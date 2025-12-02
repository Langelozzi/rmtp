#include "../include/poll_multiplex.h"
#include "../include/socket.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>

void poll_init(struct pollfd fds[], size_t size_fds, Connection clients[],
               size_t size_clients) {
  memset(fds, 0, size_fds);
  memset(clients, 0, size_clients);
}

void poll_add_init_fd(struct pollfd fds[], nfds_t *nfds, Connection clients[],
                      int new_fd, short events) {
  int index = *nfds;
  fds[index].fd = new_fd;
  fds[index].events = events;
  clients[index].fd = new_fd;
  (*nfds)++;
}

// Accept all pending clients and add them to the poll array
void poll_accept_new_clients(int listen_fd, struct pollfd fds[],
                             nfds_t *num_fds, Connection clients[],
                             int max_client_connections) {
  while (1) {
    int client_fd = socket_accept(listen_fd, 1);
    if (client_fd < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break; // no more clients to accept
      }
      perror("accept");
      break;
    }

    if (*num_fds >= (unsigned int)(max_client_connections + 1)) {
      fprintf(stderr, "Max clients reached, rejecting connection\n");
      close(client_fd);
      continue;
    }

    int client_index = *num_fds;

    clients[client_index].fd = client_fd;
    clients[client_index].current_len = 0;
    clients[client_index].expected_len = 0;

    fds[client_index].fd = client_fd;
    fds[client_index].events = POLLIN;
    (*num_fds)++;

    printf("[fd=%d] Client connected\n", client_fd);
  }
}

void poll_remove_client(struct pollfd fds[], nfds_t *num_fds,
                        Connection clients[], nfds_t remove_index) {
  int fd = fds[remove_index].fd;
  close(fd);

  printf("[fd=%d] Client disconnected\n", fd);

  // Move the last entry from the back to the new empty spot to keep array
  // compact
  if (remove_index < *num_fds - 1) {
    fds[remove_index] = fds[*num_fds - 1];
    clients[remove_index] = clients[*num_fds - 1];
  }

  (*num_fds)--;
}
