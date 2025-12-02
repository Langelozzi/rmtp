#include "../include/log.h"
#include "../include/network_utils.h"
#include "../include/rmtp.h"
#include "../include/rmtp_log.h"
#include "../include/socket.h"
#include "../include/time_utils.h"
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum { DECIMAL_BASE = 10 };

enum client_arg_indices {
  PROGRAM_NAME_INDEX,
  TARGET_IP_INDEX,
  TARGET_PORT_INDEX,
  TIMEOUT_INDEX,
  MAX_RETRIES_INDEX,
  LOG_FILE_PATH,
  LOG_SERVER_IP,
  LOG_SERVER_PORT
};

typedef struct {
  char *target_ip_addr;
  int target_port;
  double timeout;
  int max_retries;
  char *log_file_path;
  char *log_server_ip;
  int log_server_port;
} client_args_t;

static volatile sig_atomic_t running = 1;
static int log_file_fd = -1;
static int log_server_fd = -1;

static void run_client(const client_args_t *args);
static int send_message_with_retry(int socket_fd, const char *message,
                                   uint32_t seq_num, const client_args_t *args,
                                   struct sockaddr *target_addr,
                                   socklen_t addr_len);
static int wait_for_ack(int socket_fd, uint32_t expected_seq_num,
                        struct sockaddr *target_addr, socklen_t *addr_len,
                        const struct timeval *timeout);
static char *read_line_stdin(char *buffer, size_t size);
static void print_packet_info(const char *str, uint32_t seq_num);
static void parse_arguments(int argc, char *argv[], client_args_t *args);
static void handle_parsing_failure(const char *prog_name);
static void print_help(const char *prog_name);
static void configure_sigint_handler(void);
static void configure_logging(const client_args_t *args);

int main(int argc, char *argv[]) {
  client_args_t args;
  parse_arguments(argc, argv, &args);

  configure_logging(&args);
  configure_sigint_handler();

  run_client(&args);

  return 0;
}

static void run_client(const client_args_t *args) {
  // Socket data
  int socket_fd;
  struct sockaddr_storage target_addr_info;
  struct sockaddr *target_addr;
  socklen_t addr_len;

  // Buffers
  char send_buffer[RMTP_MAX_PAYLOAD_SIZE_BYTES];
  char recv_buffer[RMTP_MAX_PACKET_SIZE];

  // RMTP data
  int retries_remaining = args->max_retries;
  uint32_t current_seq_num = 0;

  const char *target_ip = args->target_ip_addr;
  const in_port_t target_port = (in_port_t)args->target_port;

  convert_network_address(target_ip, &target_addr_info);
  build_address(&target_addr_info, target_port, &target_addr, &addr_len);
  socket_fd = socket_init(target_addr_info.ss_family, SOCK_DGRAM);

  while (running) {
    log_info("Waiting for user input...");
    printf("Enter a message to send to the server (CTRL+C to quit): ");

    if (read_line_stdin(send_buffer, RMTP_MAX_PAYLOAD_SIZE_BYTES) == NULL) {
      break; // EOF or error
    }

    log_info("User entered message: '%s'", send_buffer);

    if (send_message_with_retry(socket_fd, send_buffer, current_seq_num, args,
                                target_addr, addr_len) < 0) {
      // Failed after max retries
      log_warn("Maximum retry threshold reached. Failed to send packet.");
    }

    // Increment seq num in either case (success or failure)
    current_seq_num++;

    printf("\n");
  }

  close(socket_fd);
  close(log_file_fd);
  close(log_server_fd);
  log_info("Client shut down gracefully");
}

static int send_message_with_retry(int socket_fd, const char *message,
                                   uint32_t seq_num, const client_args_t *args,
                                   struct sockaddr *target_addr,
                                   socklen_t addr_len) {
  rmtp_packet_t data_packet;
  ssize_t data_packet_size;
  struct timeval timeout_tv;
  int retries_remaining = args->max_retries;

  ftotv(args->timeout, &timeout_tv);

  data_packet_size =
      rmtp_create_data_packet(&data_packet, seq_num, message, strlen(message));

  while (retries_remaining >= 0) {
    // Send the data packet
    log_info("Sending RMTP packet with message...");

    if (sendto(socket_fd, &data_packet, data_packet_size, 0, target_addr,
               addr_len) < 0) {
      perror("sendto");
      return -1;
    }

    rmtp_log(seq_num, false, LOG_INFO, "Message sent.");

    // Wait for ACK
    int ack_result =
        wait_for_ack(socket_fd, seq_num, target_addr, &addr_len, &timeout_tv);

    if (ack_result == 1) {
      // Correct ACK received
      return 0;
    } else if (ack_result < 0) {
      // Error occurred
      return -1;
    }

    // Timeout or wrong ACK - retry if possible
    if (retries_remaining == 0) {
      return -1;
    }

    retries_remaining--;
    log_info("Attempting to retransmit packet. Attempt #%d",
             (args->max_retries - retries_remaining));
  }

  return -1;
}

static int wait_for_ack(int socket_fd, uint32_t expected_seq_num,
                        struct sockaddr *target_addr, socklen_t *addr_len,
                        const struct timeval *timeout) {

  char recv_buffer[RMTP_MAX_PACKET_SIZE];
  rmtp_packet_t ack_packet;
  struct timeval remaining_time = *timeout;
  struct timeval start_time, current_time, elapsed_time;

  gettimeofday(&start_time, NULL);

  while (1) {
    // Set timeout for this iteration
    if (socket_set_timeout(socket_fd, &remaining_time) < 0) {
      perror("socket_set_timeout");
      return -1;
    }

    log_info("Waiting for ACK...");

    ssize_t recv_count = recvfrom(socket_fd, recv_buffer, RMTP_MAX_PACKET_SIZE,
                                  0, target_addr, addr_len);

    if (recv_count < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        // Timeout occurred
        rmtp_log(expected_seq_num, false, LOG_WARN,
                 "Timeout reached while waiting for ACK.");
        return 0;
      } else {
        perror("recvfrom");
        return -1;
      }
    }

    // Parse the received packet
    if (rmtp_parse_packet(recv_buffer, recv_count, &ack_packet) < 0) {
      log_warn("Received malformed response packet. Packet discarded.");
      goto update_timeout;
    }

    // Check if it's an ACK packet
    if (!rmtp_is_ack_packet(&ack_packet)) {
      log_warn("Received non-ACK response packet. Packet discarded.");
      goto update_timeout;
    }

    uint32_t ack_seq_num = ack_packet.header.seq_num;

    // Check if it's the ACK we're waiting for
    if (ack_seq_num == expected_seq_num) {
      rmtp_log(ack_seq_num, true, LOG_INFO, "ACK Received!");
      return 1; // Success!
    } else {
      log_warn("Received incorrect ACK. Expected: %u. Received: %u.",
               expected_seq_num, ack_seq_num);
      // Fall through to update timeout and keep waiting
    }

  update_timeout:
    // Calculate remaining timeout
    gettimeofday(&current_time, NULL);
    timersub(&current_time, &start_time, &elapsed_time);
    timersub(timeout, &elapsed_time, &remaining_time);

    // Check if we've run out of time
    if (remaining_time.tv_sec < 0 ||
        (remaining_time.tv_sec == 0 && remaining_time.tv_usec <= 0)) {
      rmtp_log(expected_seq_num, false, LOG_WARN,
               "Timeout reached while waiting for ACK.");
      return 0;
    }
  }
}

static char *read_line_stdin(char *buffer, size_t size) {
  if (fgets(buffer, size, stdin) == NULL) {
    return NULL;
  }

  size_t newline_index = strcspn(buffer, "\n");
  buffer[newline_index] = '\0';
  return buffer;
}

static void parse_arguments(int argc, char *argv[], client_args_t *args) {
  // Set defaults
  args->target_ip_addr = NULL;
  args->target_port = -1;
  args->timeout = -1;
  args->max_retries = -1;
  args->log_file_path = NULL;
  args->log_server_ip = NULL;
  args->log_server_port = -1;

  // Define options
  static struct option long_options[] = {
      {"target-ip", required_argument, 0, 'i'},
      {"target-port", required_argument, 0, 'p'},
      {"timeout", required_argument, 0, 't'},
      {"max-retries", required_argument, 0, 'r'},
      {"log-file-path", required_argument, 0, LOG_FILE_PATH},
      {"log-server-ip", required_argument, 0, LOG_SERVER_IP},
      {"log-server-port", required_argument, 0, LOG_SERVER_PORT},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0},
  };

  const char *prog_name = argv[PROGRAM_NAME_INDEX];

  int opt;
  int option_index;

  // Parse each option
  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) !=
         -1) {
    switch (opt) {
    case 'i':
      args->target_ip_addr = optarg;
      break;
    case 'p':
      args->target_port = atoi(optarg);
      if (args->target_port <= 0 || args->target_port > 65535) {
        fprintf(stderr, "Invalid port number: %s (must be 1-65535)\n", optarg);
        handle_parsing_failure(prog_name);
      }
      break;
    case 't':
      args->timeout = atof(optarg);
      if (args->timeout < 0) {
        fprintf(stderr, "Invalid timeout: %s (must be positive)\n", optarg);
        handle_parsing_failure(prog_name);
      }
      break;
    case 'r':
      args->max_retries = atoi(optarg);
      if (args->max_retries < 0) {
        fprintf(stderr, "Invalid max-retries: %s (must be non-negative)\n",
                optarg);
        handle_parsing_failure(prog_name);
      }
      break;
    case LOG_FILE_PATH:
      args->log_file_path = optarg;
      break;
    case LOG_SERVER_IP:
      args->log_server_ip = optarg;
      break;
    case LOG_SERVER_PORT:
      args->log_server_port = atoi(optarg);
      break;
    case 'h':
      print_help(prog_name);
      exit(EXIT_SUCCESS);
    case '?':
      fprintf(stderr, "Unknown option: -%c\n", optarg);
      handle_parsing_failure(prog_name);
    default:
      handle_parsing_failure(prog_name);
    }
  }

  // Validate that all required options are set
  if (!args->target_ip_addr) {
    fprintf(stderr, "--target-ip is required\n");
    handle_parsing_failure(prog_name);
  }

  if (args->target_port == -1) {
    fprintf(stderr, "--target-port is required\n");
    handle_parsing_failure(prog_name);
  }

  if (args->timeout == -1) {
    fprintf(stderr, "--timeout is required\n");
    handle_parsing_failure(prog_name);
  }

  if (args->max_retries == -1) {
    fprintf(stderr, "--max-retries is required\n");
    handle_parsing_failure(prog_name);
  }

  // Check for unexpected positional arguments
  if (optind < argc) {
    fprintf(stderr, "Unexpected positional argument: %s\n", argv[optind]);
    handle_parsing_failure(prog_name);
  }
}

static void handle_parsing_failure(const char *prog_name) {
  print_help(prog_name);
  exit(EXIT_FAILURE);
}

static void print_help(const char *prog_name) {
  printf(
      "Usage: %s [OPTIONS]\n"
      "\n"
      "RMTP (Reliable Message Transfer Protocol) Client - A reliability "
      "layer built on UDP.\n\nThe client sends messages from stdin to a RMTP "
      "server and automatically handles retransmission and "
      "acknowledgements.\n"
      "\n"
      "Options:\n"
      "  --target-ip IP        IP address of the server (required)\n"
      "  --target-port PORT    Port number of the server (required)\n"
      "  --timeout SECONDS     Timeout in seconds for waiting for ACKs "
      "(required)\n"
      "  --max-retries NUM     Maximum number of retries per message "
      "(required)\n"
      "  --log-file-path PATH          The path to a log file. File logging "
      "disabled if not set\n"
      "  --log-server-ip IP_ADDRESS    The IP address of the log server\n"
      "  --log-port PORT               The port of the log server\n"
      "  -h, --help            Show this help message and exit\n"
      "\n"
      "Example:\n"
      "  %s --target-ip 192.168.0.1 --target-port 9876 --timeout 2 "
      "--max-retries 5\n",
      prog_name, prog_name);
}

static void handle_sigint(int sig) { running = 0; }

static void configure_sigint_handler(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_sigint;
  sigemptyset(&sa.sa_mask);
  // Disable SA_RESTART so that accept doesn't resume and block the shut down
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    perror("sigaction");
    exit(EXIT_FAILURE);
  }
}

static void configure_logging(const client_args_t *args) {
  // Always log to stderr
  log_add_dest(STDERR_FILENO, NULL, LOG_FORMAT_PLAIN);

  // If the user specified a log file, log to that as well
  if (args->log_file_path) {
    log_file_fd =
        open(args->log_file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    log_add_dest(log_file_fd, NULL, LOG_FORMAT_PLAIN);
  }

  // If the user specified a log server, connect and log to that as well
  if (args->log_server_ip && args->log_server_port > 0) {
    log_server_fd =
        connect_to_tcp_server(args->log_server_ip, args->log_server_port);
    log_add_dest(log_server_fd, "client", LOG_FORMAT_JSON);
    log_info("Successfuly connected to log server");
    return;
  }
}
