#include "../include/socket.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum { MAX_LISTEN_CONNECTIONS = 5 };

int socket_init(int domain, int type) {
  int socket_fd = socket(domain, type, 0);
  if (socket_fd == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }
  fcntl(socket_fd, F_SETFD, FD_CLOEXEC);
  return socket_fd;
}

void socket_bind(int fd, const struct sockaddr *addr, socklen_t addr_len) {
  if (bind(fd, addr, addr_len) == -1) {
    perror("bind");
    fprintf(stderr, "Error code: %d\n", errno);
    exit(EXIT_FAILURE);
  }
}

void socket_listen(int fd, int max_connections) {
  if (listen(fd, max_connections) == -1) {
    perror("listen");
    exit(EXIT_FAILURE);
  }
}

int socket_accept(int fd, int is_nonblocking) {
  int client_socket_fd = accept(fd, NULL, NULL);
  if (client_socket_fd < 0) {
    if (is_nonblocking && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      // If non-blocking and no client connects
      return -1;
    }
    if (errno == EINTR) {
      // Signal was caught and handler set running to 0
      // Return gracefully without an error message.
      return -1;
    } else {
      // A different, unexpected error occurred.
      perror("accept");
      exit(EXIT_FAILURE);
    }
  }
  return client_socket_fd;
}

void socket_connect(int sockfd, const struct sockaddr *addr,
                    socklen_t addr_len) {
  if (connect(sockfd, addr, addr_len) == -1) {
    perror("connect (IPv6)");
    close(sockfd);
    exit(EXIT_FAILURE);
  }
}

int socket_read(int fd, void *buf, size_t len) {
  unsigned char *ptr = buf;
  size_t total_read = 0;

  while (total_read < len) {
    ssize_t bytes = read(fd, ptr + total_read, len - total_read);

    if (bytes < 0) {
      if (errno == EINTR) {
        continue; // interrupted, retry
      }
      perror("socket_read");
      return -1;
    }

    if (bytes == 0) {
      // Connection closed
      fprintf(stderr, "socket_read: connection closed early\n");
      return -1;
    }

    total_read += (size_t)bytes;
  }

  return (int)total_read;
}

int socket_read_nonblock(int fd, void *buf, size_t len) {
  ssize_t bytes = read(fd, buf, len);
  if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
    perror("socket_read_nonblock");
    return -1;
  }
  return (int)bytes;
}

int socket_write(int fd, const void *buf, size_t len) {
  const unsigned char *ptr = buf;
  size_t total_written = 0;

  while (total_written < len) {
    ssize_t bytes = write(fd, ptr + total_written, len - total_written);

    if (bytes < 0) {
      if (errno == EINTR) {
        // Interrupted by signal, try again
        continue;
      }
      perror("socket_write");
      return -1;
    }

    if (bytes == 0) {
      // Connection closed unexpectedly
      fprintf(stderr, "socket_write: connection closed early\n");
      return -1;
    }

    total_written += (size_t)bytes;
  }

  return (int)total_written;
}

int socket_set_non_blocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl F_GETFL");
    return -1;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    perror("fcntl F_SETFL O_NONBLOCK");
    return -1;
  }
  return 0;
}

int socket_set_timeout(int fd, struct timeval *timeout_tv) {
  return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, timeout_tv,
                    sizeof(struct timeval));
}
