#include "../include/rmtp_log.h"
#include <stdarg.h>

void rmtp_log(uint32_t seq_num, bool is_ack, log_level_t level,
              const char *format, ...) {
  char user_message[512];
  char full_message[1024];

  // Format the user's message
  va_list args;
  va_start(args, format);
  vsnprintf(user_message, sizeof(user_message), format, args);
  va_end(args);

  // Extract packet information
  const char *packet_type = is_ack ? "ACK" : "DATA";

  // Build the full message with packet metadata
  snprintf(full_message, sizeof(full_message), "[SEQ#=%u] [%s] %s", seq_num,
           packet_type, user_message);

  // Log through the regular logging system
  log(level, "%s", full_message);
}
