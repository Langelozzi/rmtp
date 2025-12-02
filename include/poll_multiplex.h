#ifndef POLL_MULTIPLEX_H
#define POLL_MULTIPLEX_H

#include <poll.h>
#include <stdio.h>

enum {
    MAX_PACKET_SIZE = 8192 // 8 KB
};

typedef struct {
    int fd;
    unsigned char buffer[MAX_PACKET_SIZE];
    size_t current_len;
    size_t expected_len;
} Connection;

// Set up the fds array with the listing file descriptor
void poll_init(struct pollfd fds[], size_t size_fds, Connection clients[],
               size_t size_clients);

void poll_add_init_fd(struct pollfd fds[], nfds_t *nfds, Connection clients[],
                      int new_fd, short events);

// Accept any new clients attempting to connect and add them to fds
void poll_accept_new_clients(int listen_fd, struct pollfd fds[],
                             nfds_t *num_fds, Connection clients[],
                             int max_client_connections);

// Remove a client from fds
void poll_remove_client(struct pollfd fds[], nfds_t *num_fds,
                        Connection clients[], nfds_t remove_index);

#endif // POLL_MULTIPLEX_H
