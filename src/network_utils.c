#include "../include/network_utils.h"
#include "../include/socket.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void convert_network_address(const char *address,
                             struct sockaddr_storage *addr) {
  memset(addr, 0, sizeof(*addr));

  if (inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) ==
      1) {
    addr->ss_family = AF_INET;
  } else if (inet_pton(AF_INET6, address,
                       &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1) {
    addr->ss_family = AF_INET6;
  } else {
    fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
    exit(EXIT_FAILURE);
  }
}

void build_address(struct sockaddr_storage *addr_storage, in_port_t port,
                   struct sockaddr **out_addr, socklen_t *out_len) {
  if (addr_storage->ss_family == AF_INET) {
    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr_storage;
    addr4->sin_port = htons(port);

    *out_addr = (struct sockaddr *)addr4;
    *out_len = sizeof(*addr4);
  } else if (addr_storage->ss_family == AF_INET6) {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr_storage;
    addr6->sin6_port = htons(port);

    *out_addr = (struct sockaddr *)addr6;
    *out_len = sizeof(*addr6);
  } else {
    fprintf(stderr, "Unsupported address family: %d\n",
            addr_storage->ss_family);
    exit(EXIT_FAILURE);
  }
}

const char *get_ip_str(const struct sockaddr *sa, char *out,
                       socklen_t max_len) {
  if (sa->sa_family == AF_INET) {
    struct in_addr addr4;
    memcpy(&addr4, ((const char *)sa) + offsetof(struct sockaddr_in, sin_addr),
           sizeof(addr4));
    inet_ntop(AF_INET, &addr4, out, max_len);
  } else if (sa->sa_family == AF_INET6) {
    struct in6_addr addr6;
    memcpy(&addr6,
           ((const char *)sa) + offsetof(struct sockaddr_in6, sin6_addr),
           sizeof(addr6));
    inet_ntop(AF_INET6, &addr6, out, max_len);
  } else {
    strncpy(out, "Unknown AF", max_len);
    return NULL;
  }

  return out;
}

int connect_to_tcp_server(const char *server_ip, in_port_t server_port) {
  int fd;
  struct sockaddr_storage server_addr_info;
  struct sockaddr *server_addr;
  socklen_t server_addr_len;

  convert_network_address(server_ip, &server_addr_info);
  build_address(&server_addr_info, server_port, &server_addr, &server_addr_len);
  fd = socket_init(server_addr_info.ss_family, SOCK_STREAM);
  socket_connect(fd, server_addr, server_addr_len);

  return fd;
}
