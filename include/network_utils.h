#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <arpa/inet.h>

// Converts a string IP address into it's correct socket family for IPv4 or IPv6
void convert_network_address(const char *address,
                             struct sockaddr_storage *addr);

void build_address(struct sockaddr_storage *addr_storage, in_port_t port,
                   struct sockaddr **out_addr, socklen_t *out_len);

const char *get_ip_str(const struct sockaddr *sa, char *out, socklen_t max_len);

int connect_to_tcp_server(const char *server_ip, in_port_t server_port);

#endif // NETWORK_UTILS_H
