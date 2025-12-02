/**
 * Reliable Message Transfer Protocol (RMTP).
 * COMP 7005 - Final project
 *
 * A unified packet structure that is used for both data transfer and
 * acknowledgements. Uses network byte order (big-endian) for all multi-byte
 * fields.
 */
#ifndef RMTP_H
#define RMTP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum {
    RMTP_PACKET_HEADER_SIZE_BYTES = 11,
    RMTP_MAX_PACKET_SIZE = 1024,
    RMTP_MAX_PAYLOAD_SIZE_BYTES = 1000, // 1024 - room for header
    ACK_FLAG_MASK = 0x01
};

/**
 * Total size: 11 bytes
 *
 * Layout:
 * +--------+-------------+-------------+---------------+----------+
 * | flags  | seq_num     | timestamp   | payload_len   | payload  |
 * | 1 byte | 4 bytes     | 4 bytes     | 2 bytes       | variable |
 * +--------+-------------+-------------+---------------+----------+
 */
typedef struct {
    uint8_t flags; // Bit 0: ACK flag, Bits 1-7: Reserved (un-used)
    uint32_t seq_num;
    uint32_t timestamp;
    uint16_t payload_len;
} __attribute__((packed)) rmtp_packet_header_t;

typedef struct {
    rmtp_packet_header_t header;
    uint8_t payload[RMTP_MAX_PAYLOAD_SIZE_BYTES];
} rmtp_packet_t;

ssize_t rmtp_create_data_packet(rmtp_packet_t *packet, uint32_t seq_num,
                                const void *payload, uint16_t payload_len);

ssize_t rmtp_create_ack_packet(rmtp_packet_t *packet, uint32_t seq_num);

int rmtp_parse_packet(const void *raw_data, size_t data_len,
                      rmtp_packet_t *out_packet);

int rmtp_is_ack_packet(const rmtp_packet_t *packet);

void rmtp_print_packet_header_info(const rmtp_packet_t *packet,
                                   const char *prefix);

#endif // RMTP_H
