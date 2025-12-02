#ifndef SOCKET_H
#define SOCKET_H

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

// Initializes and returns a file descriptor for a UNIX domain socket.
int socket_init(int domain, int type);

// Binds the socket to a given path. Used by the server.
void socket_bind(int fd, const struct sockaddr *addr, socklen_t addr_len);

// Listens for incoming connections. Used by the server.
void socket_listen(int fd, int max_connections);

// Accepts a client connection. Used by the server.
int socket_accept(int fd, int is_nonblocking);

// Connects to a server socket.
void socket_connect(int sockfd, const struct sockaddr *addr,
                    socklen_t addr_len);

// Read data to buf until it has read len amount
int socket_read(int fd, void *buf, size_t len);

// Read only currently available data into buf accepting up to len bytes
int socket_read_nonblock(int fd, void *buf, size_t len);

// Write len amount of data from buf into fd
int socket_write(int fd, const void *buf, size_t len);

// Set a socket to be non-blocking
int socket_set_non_blocking(int fd);

// Set the timeout for a socket
int socket_set_timeout(int fd, struct timeval *timeout_tv);

#endif // SOCKET_H
