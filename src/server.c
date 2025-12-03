#include "../include/log.h"
#include "../include/network_utils.h"
#include "../include/rmtp.h"
#include "../include/rmtp_log.h"
#include "../include/socket.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum { DECIMAL_BASE = 10 };

enum server_arg_indices {
    PROGRAM_NAME_INDEX,
    LISTEN_IP_INDEX,
    LISTEN_PORT_INDEX,
    LOG_FILE_PATH,
    LOG_SERVER_IP,
    LOG_SERVER_PORT
};

typedef struct {
    char *listen_ip_addr;
    int listen_port;
    char *log_file_path;
    char *log_server_ip;
    int log_server_port;
} server_args_t;

static volatile sig_atomic_t running = 1;
static int log_file_fd = -1;
static int log_server_fd = -1;

static void run_server(const server_args_t *args);
static int handle_correct_packet_received(int socket_fd, rmtp_packet_t *packet,
                                          struct sockaddr *client_addr,
                                          socklen_t client_addr_len);
static int send_ack(int socket_fd, rmtp_packet_t *packet,
                    struct sockaddr *client_addr, socklen_t client_addr_len);
static void parse_arguments(int argc, char *argv[], server_args_t *args);
static void handle_parsing_failure(const char *prog_name);
static void print_help(const char *prog_name);
static void configure_sigint_handler(void);
static void configure_logging(const server_args_t *args);

int main(int argc, char *argv[]) {
    server_args_t args;
    parse_arguments(argc, argv, &args);

    configure_logging(&args);
    configure_sigint_handler();

    run_server(&args);
    return 0;
}

static void run_server(const server_args_t *args) {
    printf("Target IP: %s\n", args->listen_ip_addr);
    printf("Target port: %d\n", args->listen_port);

    // Socket data
    int socket_fd;
    struct sockaddr_storage listen_addr_info, client_addr;
    struct sockaddr *listen_addr;
    socklen_t addr_len, client_addr_len = sizeof(client_addr);

    // Buffers
    char buffer[RMTP_MAX_PACKET_SIZE];

    // RMTP data
    rmtp_packet_t recvd_packet;
    uint32_t recvd_seq_num;
    int32_t expected_seq_num;

    const char *listen_ip = args->listen_ip_addr;
    const in_port_t listen_port = (in_port_t)args->listen_port;

    expected_seq_num = -1;

    convert_network_address(listen_ip, &listen_addr_info);
    build_address(&listen_addr_info, listen_port, &listen_addr, &addr_len);

    socket_fd = socket_init(listen_addr_info.ss_family, SOCK_DGRAM);
    socket_bind(socket_fd, listen_addr, addr_len);

    while (running) {
        printf("\n");
        log_info("RMTP server listening on port %d (CTRL+C to quit)...",
                 listen_port);

        ssize_t recv_count =
            recvfrom(socket_fd, buffer, RMTP_MAX_PACKET_SIZE, 0,
                     (struct sockaddr *)&client_addr, &client_addr_len);

        if (recv_count < 0) {
            if (errno == EINTR) { // CTRL+C
                break;
            }
            perror("recvfrom");
            break;
        }

        if (rmtp_parse_packet(&buffer, (size_t)recv_count, &recvd_packet) < 0) {
            perror("parse_packet");
            close(socket_fd);
            exit(EXIT_FAILURE);
        }

        recvd_seq_num = recvd_packet.header.seq_num;
        log_info("Packet received.");

        if (expected_seq_num < 0) {
            // First packet - set the base expected_seq_num
            expected_seq_num = recvd_seq_num;
        } else if (recvd_seq_num < expected_seq_num) {
            // Duplicate message, send same ack again
            log_warn("Duplicate message, resending ack...");
            send_ack(socket_fd, &recvd_packet, (struct sockaddr *)&client_addr,
                     client_addr_len);
            continue;
        } else if (recvd_seq_num != expected_seq_num) {
            // Incorrect packet, discard and continue waiting
            log_warn("Incorrect sequence number received. Expected: %u. "
                     "Received: %u",
                     expected_seq_num, recvd_seq_num);
            continue;
        }

        if (handle_correct_packet_received(socket_fd, &recvd_packet,
                                           (struct sockaddr *)&client_addr,
                                           client_addr_len) < 0) {
            perror("handle_packet_received");
            continue;
        }

        expected_seq_num++;
    }

    close(socket_fd);
    close(log_file_fd);
    close(log_server_fd);
    log_info("Server shut down gracefully");
}

static int handle_correct_packet_received(int socket_fd, rmtp_packet_t *packet,
                                          struct sockaddr *client_addr,
                                          socklen_t client_addr_len) {
    uint32_t seq_num = packet->header.seq_num;

    // Print payload
    rmtp_log(seq_num, false, LOG_INFO, "Message received: %s", packet->payload);

    return send_ack(socket_fd, packet, client_addr, client_addr_len);
}

static int send_ack(int socket_fd, rmtp_packet_t *packet,
                    struct sockaddr *client_addr, socklen_t client_addr_len) {
    rmtp_packet_t ack_packet;

    uint32_t seq_num = packet->header.seq_num;

    // Generate ack packet
    ssize_t packet_len =
        rmtp_create_ack_packet(&ack_packet, packet->header.seq_num);

    // Send ACK
    if (sendto(socket_fd, &ack_packet, packet_len, 0, client_addr,
               client_addr_len) < 0) {
        perror("sendto");
        return -1;
    }

    rmtp_log(seq_num, true, LOG_INFO, "ACK sent.");

    return 0;
}

static void parse_arguments(int argc, char *argv[], server_args_t *args) {
    // Set defaults
    args->listen_ip_addr = NULL;
    args->listen_port = -1;
    args->log_file_path = NULL;
    args->log_server_ip = NULL;
    args->log_server_port = -1;

    // Define options
    static struct option long_options[] = {
        {"listen-ip", required_argument, 0, 'i'},
        {"listen-port", required_argument, 0, 'p'},
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
            args->listen_ip_addr = optarg;
            break;
        case 'p':
            args->listen_port = atoi(optarg);
            if (args->listen_port <= 0 || args->listen_port > 65535) {
                fprintf(stderr, "Invalid port number: %s (must be 1-65535)\n",
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
            fprintf(stderr, "Unknown option: -%c\n", optopt);
            handle_parsing_failure(prog_name);
        default:
            handle_parsing_failure(prog_name);
        }
    }

    // Validate that all required options are set
    if (!args->listen_ip_addr) {
        fprintf(stderr, "--listen-ip is required\n");
        handle_parsing_failure(prog_name);
    }

    if (args->listen_port == -1) {
        fprintf(stderr, "--listen-port is required\n");
        handle_parsing_failure(prog_name);
    }

    // Check for unexpected positional arguments
    if (optind < argc) {
        fprintf(stderr, "Unexpected postitiional argument: %s\n", argv[optind]);
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
        "RMTP (Reliable Message Transfer Protocol) Server - A reliability "
        "layer built on UDP.\n\nThe server accepts messages from the "
        "client, prints them to stdout and sends ACKs back automatically.\n"
        "\n"
        "Options:\n"
        "  --listen-ip IP        IP address to listen on (required)\n"
        "  --listen-port PORT    Port number to listen on (required)\n"
        "  --log-file-path PATH          The path to a log file. File logging "
        "disabled if not set\n"
        "  --log-server-ip IP_ADDRESS    The IP address of the log server\n"
        "  --log-port PORT               The port of the log server\n"
        "  -h, --help            Show this help message and exit\n"
        "\n"
        "Example:\n"
        "  %s --listen-ip 192.168.0.1 --listen-port 9876\n",
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

static void configure_logging(const server_args_t *args) {
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
        log_add_dest(log_server_fd, "server", LOG_FORMAT_JSON);
        log_info("Successfuly connected to log server");
        return;
    }
}
