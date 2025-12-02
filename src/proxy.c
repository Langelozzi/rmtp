#include "../include/log.h"
#include "../include/network_utils.h"
#include "../include/poll_multiplex.h"
#include "../include/rmtp.h"
#include "../include/rmtp_log.h"
#include "../include/socket.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

enum { MAX_CONNECTIONS = 2, POLL_TIMEOUT_MS = 600000, DECIMAL_BASE = 10 };

enum proxy_arg_indices {
  PROGRAM_NAME_INDEX,
  LISTEN_IP_INDEX,
  LISTEN_PORT_INDEX,
  TARGET_IP_INDEX,
  TARGET_PORT_INDEX,
  CLIENT_DROP_INDEX,
  SERVER_DROP_INDEX,
  CLIENT_DELAY_INDEX,
  SERVER_DELAY_INDEX,
  CLIENT_DELAY_TIME_MIN_INDEX,
  CLIENT_DELAY_TIME_MAX_INDEX,
  SERVER_DELAY_TIME_MIN_INDEX,
  SERVER_DELAY_TIME_MAX_INDEX,
  LOG_FILE_PATH,
  LOG_SERVER_IP,
  LOG_SERVER_PORT,
  CONTROL_PORT_INDEX
};

enum packet_action { PACKET_DROP, PACKET_DELAY, PACKET_FORWARD };

typedef struct {
  char *listen_ip_addr;
  int listen_port;
  char *target_ip_addr;
  int target_port;
  int client_drop;
  int server_drop;
  int client_delay;
  int server_delay;
  long client_delay_time_min;
  long client_delay_time_max;
  long server_delay_time_min;
  long server_delay_time_max;
  char *log_file_path;
  char *log_server_ip;
  int log_server_port;
  int control_port;
} proxy_args_t;

typedef struct {
  int drop_percent;
  int delay_percent;
  long delay_time_min_ms;
  long delay_time_max_ms;
} proxy_config_t;

static volatile sig_atomic_t running = 1;
static int log_file_fd = -1;
static int log_server_fd = -1;

static void run_proxy(const proxy_args_t *args);
static int handle_forward_packet(proxy_config_t *cfg, int source_socket_fd,
                                 struct sockaddr *source_client_addr,
                                 socklen_t *source_client_addr_len,
                                 int target_socket_fd,
                                 struct sockaddr *target_addr,
                                 socklen_t target_addr_len);
enum packet_action process_packet(const proxy_config_t *cfg, int *delay_out_ms);
static bool chance(int percent);
static void calculate_delay_time(const proxy_config_t *cfg, int *delay_out_ms);
static void delay_ms(long ms);
static void parse_arguments(int argc, char *argv[], proxy_args_t *args);
static void handle_parsing_failure(const char *prog_name);
static void print_help(const char *prog_name);
static void print_proxy_args(const proxy_args_t *args);
static void configure_sigint_handler(void);
static void configure_logging(const proxy_args_t *args);
static int setup_control_socket(const proxy_args_t *args);
static int handle_control_connection(int control_socket_fd,
                                     proxy_config_t *client_config,
                                     proxy_config_t *server_config);
static void update_config_from_json(const char *json_str,
                                    proxy_config_t *client_config,
                                    proxy_config_t *server_config);

int main(int argc, char *argv[]) {
  proxy_args_t args;
  parse_arguments(argc, argv, &args);

  configure_logging(&args);
  configure_sigint_handler();

  run_proxy(&args);

  return 0;
}

static void run_proxy(const proxy_args_t *args) {
  // Make a copy so we can revert to args as default via remote controls
  proxy_config_t client_config = {
      .delay_percent = args->client_delay,
      .drop_percent = args->client_drop,
      .delay_time_min_ms = args->client_delay_time_min,
      .delay_time_max_ms = args->client_delay_time_max,
  };

  proxy_config_t server_config = {
      .delay_percent = args->server_delay,
      .drop_percent = args->server_drop,
      .delay_time_min_ms = args->server_delay_time_min,
      .delay_time_max_ms = args->server_delay_time_max,
  };

  print_proxy_args(args);

  // Listening socket data
  int listen_socket_fd;
  struct sockaddr_storage listen_socket_addr_info;
  struct sockaddr *listen_addr, listen_client_addr;
  socklen_t listen_addr_len, listen_client_addr_len;

  // Target socket data
  int target_socket_fd;
  struct sockaddr_storage target_socket_addr_info;
  struct sockaddr *target_addr, target_client_addr;
  socklen_t target_addr_len, target_client_addr_len;

  // Polling data
  Connection
      connections[MAX_CONNECTIONS + 3]; // +3 for listen, target, and control fd
  struct pollfd fds[MAX_CONNECTIONS + 3];
  nfds_t nfds;

  // Configure listening socket
  convert_network_address(args->listen_ip_addr, &listen_socket_addr_info);
  build_address(&listen_socket_addr_info, args->listen_port, &listen_addr,
                &listen_addr_len);
  listen_socket_fd = socket_init(listen_socket_addr_info.ss_family, SOCK_DGRAM);
  socket_bind(listen_socket_fd, listen_addr, listen_addr_len);
  listen_client_addr_len = sizeof(listen_client_addr);

  // Configure target socket
  convert_network_address(args->target_ip_addr, &target_socket_addr_info);
  build_address(&target_socket_addr_info, args->target_port, &target_addr,
                &target_addr_len);
  target_socket_fd = socket_init(target_socket_addr_info.ss_family, SOCK_DGRAM);
  target_client_addr_len = sizeof(target_client_addr);

  // Configure control socket (optional)
  int control_socket_fd = setup_control_socket(args);

  // Setting up polling
  nfds = 0;
  poll_init(fds, sizeof(fds), connections, sizeof(connections));
  poll_add_init_fd(fds, &nfds, connections, listen_socket_fd, POLLIN);
  poll_add_init_fd(fds, &nfds, connections, target_socket_fd, POLLIN);
  if (control_socket_fd >= 0) {
    poll_add_init_fd(fds, &nfds, connections, control_socket_fd, POLLIN);
  }

  log_info("Proxy started. Listening on %s:%d -> forwarding to %s:%d",
           args->listen_ip_addr, args->listen_port, args->target_ip_addr,
           args->target_port);

  // Poll loop
  while (running) {
    log_info("Polling...");
    log_info("[Use CTRL-C to quit]");

    // Wait for data to come in
    int result = poll(fds, nfds, POLL_TIMEOUT_MS);
    if (result < 0) {
      if (errno == EINTR) { // ctrl-c
        break;
      }
      log_err("poll() error");
      exit(EXIT_FAILURE);
    }

    if (result == 0) {
      continue;
    }

    for (nfds_t i = 0; i < nfds; i++) {
      if (fds[i].revents & (POLLHUP | POLLERR)) {
        log_warn("[fd=%d] Detected disconnect or socket error "
                 "(revents=%d)\n",
                 fds[i].fd, fds[i].revents);
        continue;
      }

      // Client -> Proxy -> Server
      if (fds[i].fd == listen_socket_fd && (fds[i].revents & POLLIN)) {
        int status = handle_forward_packet(
            &client_config, listen_socket_fd, &listen_client_addr,
            &listen_client_addr_len, target_socket_fd, target_addr,
            target_addr_len);
        if (status < 0) {
          log_err("Error handling packet from client");
        } else {
          continue;
        }
      }

      // Server -> Proxy -> Client
      else if (fds[i].fd == target_socket_fd && (fds[i].revents & POLLIN)) {
        int status = handle_forward_packet(
            &server_config, target_socket_fd, &target_client_addr,
            &target_client_addr_len, listen_socket_fd, &listen_client_addr,
            listen_client_addr_len);
        if (status < 0) {
          log_err("Error handling packet from server");
        } else {
          continue;
        }
      }

      // Control socket for configuration updates
      else if (control_socket_fd >= 0 && fds[i].fd == control_socket_fd &&
               (fds[i].revents & POLLIN)) {
        int status = handle_control_connection(control_socket_fd,
                                               &client_config, &server_config);
        if (status < 0) {
          log_err("Error handling control connection");
        }
        continue;
      }
    }
  }

cleanup:
  close(log_file_fd);
  close(log_server_fd);
  close(listen_socket_fd);
  close(target_socket_fd);
  if (control_socket_fd >= 0) {
    close(control_socket_fd);
  }
  log_info("Proxy shut down gracefully");
}

static int handle_forward_packet(proxy_config_t *cfg, int source_socket_fd,
                                 struct sockaddr *source_client_addr,
                                 socklen_t *source_client_addr_len,
                                 int target_socket_fd,
                                 struct sockaddr *target_addr,
                                 socklen_t target_addr_len) {

  // struct sockaddr source_client_addr;
  // socklen_t source_client_addr_len;
  char buffer[RMTP_MAX_PACKET_SIZE];
  rmtp_packet_t packet;
  uint32_t seq_num;
  bool is_ack;

  // Receive the message and parse into rmtp packet
  ssize_t recv_count = recvfrom(source_socket_fd, buffer, RMTP_MAX_PACKET_SIZE,
                                0, source_client_addr, source_client_addr_len);
  if (recv_count < 0) {
    return -1;
  }

  if (rmtp_parse_packet(&buffer, (size_t)recv_count, &packet) < 0) {
    log_err("Failed to parse received RMTP packet");
    return -1;
  }
  seq_num = packet.header.seq_num;
  is_ack = (packet.header.flags & ACK_FLAG_MASK) == ACK_FLAG_MASK;

  rmtp_log(seq_num, is_ack, LOG_INFO, "Packet received.");

  // Perform drop or delay if selected
  int delay_ms_time = 0;
  enum packet_action action = process_packet(cfg, &delay_ms_time);
  if (action == PACKET_DROP) {
    rmtp_log(seq_num, is_ack, LOG_WARN, "Packet dropped.");
    return 0;
  } else if (action == PACKET_DELAY) {
    rmtp_log(seq_num, is_ack, LOG_INFO, "Delaying packet for %d ms.",
             delay_ms_time);
    delay_ms(delay_ms_time);
  }

  // Forward packet to target
  if (sendto(target_socket_fd, &buffer, recv_count, 0, target_addr,
             target_addr_len) < 0) {
    rmtp_log(seq_num, is_ack, LOG_ERROR, "Failed to forward packet to target.");
    return -1;
  }

  rmtp_log(seq_num, is_ack, LOG_INFO,
           "Packet successfully forwarded to target.");

  return 0;
}

enum packet_action process_packet(const proxy_config_t *cfg,
                                  int *delay_out_ms) {
  // Check if should drop
  if (chance(cfg->drop_percent)) {
    return PACKET_DROP;
  }
  // Check if should delay
  if (chance(cfg->delay_percent)) {
    calculate_delay_time(cfg, delay_out_ms);
    return PACKET_DELAY;
  }

  *delay_out_ms = 0;
  return PACKET_FORWARD;
}

static void calculate_delay_time(const proxy_config_t *cfg, int *delay_out_ms) {
  if (cfg->delay_time_min_ms == cfg->delay_time_max_ms) {
    *delay_out_ms = cfg->delay_time_min_ms;
  } else {
    long range = cfg->delay_time_max_ms - cfg->delay_time_min_ms;
    long random_offset = rand() % (range + 1); // +1 to include max value
    *delay_out_ms = cfg->delay_time_min_ms + random_offset;
  }
}

static void delay_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000L;

  nanosleep(&ts, NULL);
}

static bool chance(int percent) {
  if (percent <= 0) {
    return false;
  }
  if (percent >= 100) {
    return true;
  }

  int r = rand() % 100; // gives 0-99
  return r < percent;
}

static void parse_arguments(int argc, char *argv[], proxy_args_t *args) {
  // Set defaults
  args->listen_ip_addr = NULL;
  args->listen_port = -1;
  args->target_ip_addr = NULL;
  args->target_port = -1;
  args->client_drop = 0;
  args->server_drop = 0;
  args->client_delay = 0;
  args->server_delay = 0;
  args->client_delay_time_min = 0;
  args->client_delay_time_max = 0;
  args->server_delay_time_min = 0;
  args->server_delay_time_max = 0;
  args->log_file_path = NULL;
  args->log_server_ip = NULL;
  args->log_server_port = -1;
  args->control_port = -1;

  const char *prog_name = argv[PROGRAM_NAME_INDEX];

  static struct option long_options[] = {
      {"listen-ip", required_argument, 0, LISTEN_IP_INDEX},
      {"listen-port", required_argument, 0, LISTEN_PORT_INDEX},
      {"target-ip", required_argument, 0, TARGET_IP_INDEX},
      {"target-port", required_argument, 0, TARGET_PORT_INDEX},
      {"client-drop", required_argument, 0, CLIENT_DROP_INDEX},
      {"server-drop", required_argument, 0, SERVER_DROP_INDEX},
      {"client-delay", required_argument, 0, CLIENT_DELAY_INDEX},
      {"server-delay", required_argument, 0, SERVER_DELAY_INDEX},
      {"client-delay-time-min", required_argument, 0,
       CLIENT_DELAY_TIME_MIN_INDEX},
      {"client-delay-time-max", required_argument, 0,
       CLIENT_DELAY_TIME_MAX_INDEX},
      {"server-delay-time-min", required_argument, 0,
       SERVER_DELAY_TIME_MIN_INDEX},
      {"server-delay-time-max", required_argument, 0,
       SERVER_DELAY_TIME_MAX_INDEX},
      {"log-file-path", required_argument, 0, LOG_FILE_PATH},
      {"log-server-ip", required_argument, 0, LOG_SERVER_IP},
      {"log-server-port", required_argument, 0, LOG_SERVER_PORT},
      {"control-port", required_argument, 0, CONTROL_PORT_INDEX},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}};

  int opt, option_index = 0;

  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) !=
         -1) {
    switch (opt) {

    case LISTEN_IP_INDEX:
      args->listen_ip_addr = optarg;
      break;

    case LISTEN_PORT_INDEX:
      args->listen_port = atoi(optarg);
      break;

    case TARGET_IP_INDEX:
      args->target_ip_addr = optarg;
      break;

    case TARGET_PORT_INDEX:
      args->target_port = atoi(optarg);
      break;

    case CLIENT_DROP_INDEX:
      args->client_drop = atoi(optarg);
      break;

    case SERVER_DROP_INDEX:
      args->server_drop = atoi(optarg);
      break;

    case CLIENT_DELAY_INDEX:
      args->client_delay = atoi(optarg);
      break;

    case SERVER_DELAY_INDEX:
      args->server_delay = atoi(optarg);
      break;

    case CLIENT_DELAY_TIME_MIN_INDEX:
      args->client_delay_time_min = strtol(optarg, NULL, DECIMAL_BASE);
      break;

    case CLIENT_DELAY_TIME_MAX_INDEX:
      args->client_delay_time_max = strtol(optarg, NULL, DECIMAL_BASE);
      break;

    case SERVER_DELAY_TIME_MIN_INDEX:
      args->server_delay_time_min = strtol(optarg, NULL, DECIMAL_BASE);
      break;

    case SERVER_DELAY_TIME_MAX_INDEX:
      args->server_delay_time_max = strtol(optarg, NULL, DECIMAL_BASE);
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

    case CONTROL_PORT_INDEX:
      args->control_port = atoi(optarg);
      break;

    case 'h':
      print_help(prog_name);
      exit(EXIT_SUCCESS);

    case '?':
    default:
      handle_parsing_failure(prog_name);
    }
  }

  // ---------- Required argument checks ----------
  if (!args->listen_ip_addr) {
    perror("--listen-ip is required\n");
    handle_parsing_failure(prog_name);
  }
  if (args->listen_port <= 0 || args->listen_port > 65535) {
    perror("--listen-port must be 1–65535\n");
    handle_parsing_failure(prog_name);
  }
  if (!args->target_ip_addr) {
    perror("--target-ip is required\n");
    handle_parsing_failure(prog_name);
  }
  if (args->target_port <= 0 || args->target_port > 65535) {
    perror("--target-port must be 1–65535\n");
    handle_parsing_failure(prog_name);
  }
  if (args->control_port > 0 && args->control_port > 65535) {
    perror("--control-port must be 1–65535\n");
    handle_parsing_failure(prog_name);
  }

  // ---------- Range checking ----------
  if (args->client_drop < 0 || args->client_drop > 100 ||
      args->server_drop < 0 || args->server_drop > 100) {
    perror("Drop chances must be 0–100\n");
    handle_parsing_failure(prog_name);
  }

  if (args->client_delay < 0 || args->client_delay > 100 ||
      args->server_delay < 0 || args->server_delay > 100) {
    perror("Delay chances must be 0–100\n");
    handle_parsing_failure(prog_name);
  }

  if (args->client_delay_time_min < 0 || args->client_delay_time_max < 0 ||
      args->server_delay_time_min < 0 || args->server_delay_time_max < 0) {
    perror("Delay times must be >= 0\n");
    handle_parsing_failure(prog_name);
  }

  if (args->client_delay_time_min > args->client_delay_time_max) {
    perror("Client min delay cannot exceed max delay\n");
    handle_parsing_failure(prog_name);
  }
  if (args->server_delay_time_min > args->server_delay_time_max) {
    perror("Server min delay cannot exceed max delay\n");
    handle_parsing_failure(prog_name);
  }

  // ---------- No stray positional arguments ----------
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
  printf("Usage: %s [OPTIONS]\n\n"
         "Network packet manipulation proxy with configurable delay and drop "
         "simulation.\n\n"
         "Options:\n"
         "  --listen-ip IP                IP to bind for client packets "
         "(required)\n"
         "  --listen-port PORT            Port to bind for client packets "
         "(required)\n"
         "  --target-ip IP                Destination server IP (required)\n"
         "  --target-port PORT            Destination server port (required)\n"
         "\n"
         "  --client-drop PERCENT         Drop chance for packets from client "
         "(0–100)\n"
         "  --server-drop PERCENT         Drop chance for packets from server "
         "(0–100)\n"
         "  --client-delay PERCENT        Delay chance for packets from client "
         "(0–100)\n"
         "  --server-delay PERCENT        Delay chance for packets from server "
         "(0–100)\n"
         "\n"
         "  --client-delay-time-min MS    Minimum delay for client packets\n"
         "  --client-delay-time-max MS    Maximum delay for client packets\n"
         "  --server-delay-time-min MS    Minimum delay for server packets\n"
         "  --server-delay-time-max MS    Maximum delay for server packets\n"
         "  --log-file-path PATH          The path to a log file. File logging "
         "disabled if not set\n"
         "  --log-server-ip IP_ADDRESS    The IP address of the log server\n"
         "  --log-port PORT               The port of the log server\n"
         "  --control-port PORT           TCP port for receiving config "
         "updates\n"
         "\n"
         "  -h, --help                    Show this help message\n"
         "\n"
         "Example:\n"
         "  %s --listen-ip 127.0.0.1 --listen-port 9000 \\\n"
         "     --target-ip 10.0.0.5 --target-port 5000 \\\n"
         "     --client-drop 10 --client-delay 15 \\\n"
         "     --client-delay-time-min 50 --client-delay-time-max 250\n",
         prog_name, prog_name);
}

static void print_proxy_args(const proxy_args_t *args) {
  printf("Proxy configuration:\n");
  printf("  listen_ip_addr:        %s\n", args->listen_ip_addr);
  printf("  listen_port:           %d\n", args->listen_port);
  printf("  target_ip_addr:        %s\n", args->target_ip_addr);
  printf("  target_port:           %d\n", args->target_port);

  printf("  client_drop:           %d%%\n", args->client_drop);
  printf("  server_drop:           %d%%\n", args->server_drop);

  printf("  client_delay:          %d%%\n", args->client_delay);
  printf("  server_delay:          %d%%\n", args->server_delay);

  printf("  client_delay_time_min: %ld ms\n", args->client_delay_time_min);
  printf("  client_delay_time_max: %ld ms\n", args->client_delay_time_max);
  printf("  server_delay_time_min: %ld ms\n", args->server_delay_time_min);
  printf("  server_delay_time_max: %ld ms\n", args->server_delay_time_max);
  printf("  control_port:          %d\n", args->control_port);
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

static void configure_logging(const proxy_args_t *args) {
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
    log_add_dest(log_server_fd, "proxy", LOG_FORMAT_JSON);
    log_info("Successfuly connected to log server");
    return;
  }
}

static int setup_control_socket(const proxy_args_t *args) {
  if (args->control_port <= 0) {
    return -1; // Control socket disabled
  }

  struct sockaddr_storage addr_storage;
  struct sockaddr *addr;
  socklen_t addr_len;

  // Convert "127.0.0.1" to address info for control socket
  convert_network_address(args->log_server_ip, &addr_storage);
  build_address(&addr_storage, args->control_port, &addr, &addr_len);

  int control_fd = socket_init(addr_storage.ss_family, SOCK_STREAM);
  if (control_fd < 0) {
    log_err("Failed to create control socket");
    return -1;
  }

  // Set SO_REUSEADDR
  int opt = 1;
  if (setsockopt(control_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    log_warn("Failed to set SO_REUSEADDR on control socket");
  }

  if (bind(control_fd, addr, addr_len) < 0) {
    log_err("Failed to bind control socket to port %d", args->control_port);
    close(control_fd);
    return -1;
  }

  if (listen(control_fd, 5) < 0) {
    log_err("Failed to listen on control socket");
    close(control_fd);
    return -1;
  }

  log_info("Control socket listening on port %d", args->control_port);
  return control_fd;
}

static int handle_control_connection(int control_socket_fd,
                                     proxy_config_t *client_config,
                                     proxy_config_t *server_config) {
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  int client_fd = accept(control_socket_fd, (struct sockaddr *)&client_addr,
                         &client_addr_len);
  if (client_fd < 0) {
    log_err("Failed to accept control connection");
    return -1;
  }

  char buffer[4096];
  ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
  if (bytes_read <= 0) {
    close(client_fd);
    return -1;
  }

  buffer[bytes_read] = '\0';
  log_info("Received control message: %s", buffer);

  // Update configuration
  update_config_from_json(buffer, client_config, server_config);

  // Send acknowledgment
  const char *response = "OK\n";
  send(client_fd, response, strlen(response), 0);

  close(client_fd);
  return 0;
}

// Simple JSON parser for our specific config format
static void update_config_from_json(const char *json_str,
                                    proxy_config_t *client_config,
                                    proxy_config_t *server_config) {
  // Parse JSON manually for simplicity - looking for our specific fields
  // Format expected: {"client_drop": 10, "server_drop": 5, "client_delay":
  // 20, ...}

  const char *ptr = json_str;

  // Skip whitespace and opening brace
  while (*ptr && (isspace(*ptr) || *ptr == '{'))
    ptr++;

  while (*ptr && *ptr != '}') {
    // Skip whitespace and quotes
    while (*ptr && (isspace(*ptr) || *ptr == '"' || *ptr == ','))
      ptr++;

    if (*ptr == '}')
      break;

    // Extract field name
    char field[64] = {0};
    int field_idx = 0;
    while (*ptr && *ptr != '"' && *ptr != ':' &&
           field_idx < sizeof(field) - 1) {
      field[field_idx++] = *ptr++;
    }

    // Skip to value
    while (*ptr && (*ptr == '"' || *ptr == ':' || isspace(*ptr)))
      ptr++;

    // Extract value
    long value = strtol(ptr, (char **)&ptr, 10);

    // Update configuration based on field name
    if (strcmp(field, "client_drop") == 0) {
      client_config->drop_percent = (int)value;
      log_info("Updated client_drop to %d%%", client_config->drop_percent);
    } else if (strcmp(field, "server_drop") == 0) {
      server_config->drop_percent = (int)value;
      log_info("Updated server_drop to %d%%", server_config->drop_percent);
    } else if (strcmp(field, "client_delay") == 0) {
      client_config->delay_percent = (int)value;
      log_info("Updated client_delay to %d%%", client_config->delay_percent);
    } else if (strcmp(field, "server_delay") == 0) {
      server_config->delay_percent = (int)value;
      log_info("Updated server_delay to %d%%", server_config->delay_percent);
    } else if (strcmp(field, "client_delay_time_min") == 0) {
      client_config->delay_time_min_ms = value;
      log_info("Updated client_delay_time_min to %ld ms",
               client_config->delay_time_min_ms);
    } else if (strcmp(field, "client_delay_time_max") == 0) {
      client_config->delay_time_max_ms = value;
      log_info("Updated client_delay_time_max to %ld ms",
               client_config->delay_time_max_ms);
    } else if (strcmp(field, "server_delay_time_min") == 0) {
      server_config->delay_time_min_ms = value;
      log_info("Updated server_delay_time_min to %ld ms",
               server_config->delay_time_min_ms);
    } else if (strcmp(field, "server_delay_time_max") == 0) {
      server_config->delay_time_max_ms = value;
      log_info("Updated server_delay_time_max to %ld ms",
               server_config->delay_time_max_ms);
    }

    // Skip to next field
    while (*ptr && *ptr != ',' && *ptr != '}')
      ptr++;
  }

  log_info("Configuration updated successfully");
}
