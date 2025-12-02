#include "../include/rmtp.h"
#include "../include/time_utils.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

ssize_t rmtp_create_data_packet(rmtp_packet_t *packet, uint32_t seq_num,
                                const void *payload, uint16_t payload_len) {
  if (!packet || !payload || payload_len > RMTP_MAX_PAYLOAD_SIZE_BYTES) {
    return -1;
  }

  // Clear packet
  memset(packet, 0, sizeof(rmtp_packet_t));

  // Fill header, converting values to network byte order (big-endian)
  packet->header.flags = 0;                // Not an ACK
  packet->header.seq_num = htonl(seq_num); // htonl = Host to Network Long
  packet->header.timestamp = htonl(get_current_timestamp_ms());
  packet->header.payload_len = htons(payload_len); // htons = Short

  // Copy payload
  memcpy(packet->payload, payload, payload_len);

  return RMTP_PACKET_HEADER_SIZE_BYTES + payload_len;
}

ssize_t rmtp_create_ack_packet(rmtp_packet_t *packet, uint32_t seq_num) {
  if (!packet) {
    return -1;
  }

  // Clear packet
  memset(packet, 0, sizeof(rmtp_packet_t));

  // Fill header, converting values to network byte order (big-endian)
  packet->header.flags = ACK_FLAG_MASK; // Set flag bit == 1
  packet->header.seq_num = htonl(seq_num);
  packet->header.timestamp = htonl(get_current_timestamp_ms());
  packet->header.payload_len = 0;

  return RMTP_PACKET_HEADER_SIZE_BYTES;
}

int rmtp_parse_packet(const void *raw_data, size_t data_len,
                      rmtp_packet_t *out_packet) {
  if (!raw_data || !out_packet || data_len < RMTP_PACKET_HEADER_SIZE_BYTES) {
    return -1;
  }

  // Clear packet
  memset(out_packet, 0, sizeof(rmtp_packet_t));

  // Copy raw data
  memcpy(out_packet, raw_data, data_len);

  // Convert header fields from network byte order to host (OS) byte order
  out_packet->header.seq_num = ntohl(out_packet->header.seq_num);
  out_packet->header.timestamp = ntohl(out_packet->header.timestamp);
  out_packet->header.payload_len = ntohs(out_packet->header.payload_len);

  // Validate payload length matches expected
  if (out_packet->header.payload_len > RMTP_MAX_PAYLOAD_SIZE_BYTES ||
      data_len <
          RMTP_PACKET_HEADER_SIZE_BYTES + out_packet->header.payload_len) {
    return -1;
  }

  return 0;
}

int rmtp_is_ack_packet(const rmtp_packet_t *packet) {
  return (packet->header.flags & ACK_FLAG_MASK) != 0;
}

void rmtp_print_packet_header_info(const rmtp_packet_t *packet,
                                   const char *prefix) {
  fprintf(stderr, "%s: %s | SEQ=%u | TS=%u | LEN=%u\n", prefix,
          rmtp_is_ack_packet(packet) ? "ACK" : "DATA", packet->header.seq_num,
          packet->header.timestamp, packet->header.payload_len);
}
