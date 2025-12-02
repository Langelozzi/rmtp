#include "../include/log.h"
#include "../include/time_utils.h"
#include <stdarg.h>
#include <unistd.h>

static log_config_t log_config = {.nfds = 0};

static const char *log_level_str(log_level_t level);
static size_t format_log_plain(char *dst, size_t dstsize, const char *prefix,
                               const char *timestamp, log_level_t level,
                               const char *message);
static size_t format_log_json(char *dst, size_t dstsize, const char *prefix,
                              const char *timestamp, log_level_t level,
                              const char *message);

int log_add_dest(int fd, const char *prefix, log_format_t format) {
  if (log_config.nfds >= MAX_LOG_DESTS) {
    return -1; // Already at max capacity
  }

  // Check if fd already exists
  for (size_t i = 0; i < log_config.nfds; i++) {
    if (log_config.dests[i].fd == fd) {
      return -1; // Already registered
    }
  }

  log_config.dests[log_config.nfds++] = (log_destination_t){
      .fd = fd,
      .prefix = prefix, // can be NULL
      .format = format  // 0 = plain, 1 = JSON
  };

  return 0;
}

int log_remove_fd(int fd) {
  for (size_t i = 0; i < log_config.nfds; i++) {
    log_destination_t *dest = &log_config.dests[i];

    if (dest->fd == fd) {
      // Shift remaining destinations down
      for (size_t j = i; j < log_config.nfds - 1; j++) {
        log_config.dests[j] = log_config.dests[j + 1];
      }

      log_config.nfds--;
      return 0; // Success
    }
  }

  return -1;
}

int log(log_level_t level, const char *format, ...) {
  char timestamp[64];
  char message[1024];
  char full_log[1200];
  size_t message_len;

  // Get timestamp
  get_current_timestamp_str(timestamp, sizeof(timestamp));

  // Format the message with variadic arguments
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);

  // Single atomic write to file descriptors
  for (size_t i = 0; i < log_config.nfds; i++) {
    log_destination_t *dest = &log_config.dests[i];

    if (dest->format == LOG_FORMAT_PLAIN) {
      message_len = format_log_plain(full_log, sizeof(full_log), dest->prefix,
                                     timestamp, level, message);
    } else {
      message_len = format_log_json(full_log, sizeof(full_log), dest->prefix,
                                    timestamp, level, message);
    }

    write(dest->fd, full_log, message_len);
  }

  return 0;
}

static const char *log_level_str(log_level_t level) {
  switch (level) {
  case LOG_INFO:
    return "INFO";
  case LOG_WARN:
    return "WARN";
  case LOG_ERROR:
    return "ERROR";
  default:
    return "UNKNOWN";
  }
}

static size_t format_log_plain(char *dst, size_t dstsize, const char *prefix,
                               const char *timestamp, log_level_t level,
                               const char *message) {
  if (prefix) {
    return snprintf(dst, dstsize, "[%s] [%s] [%s] %s\n", timestamp,
                    log_level_str(level), prefix, message);
  } else {
    return snprintf(dst, dstsize, "[%s] [%s] %s\n", timestamp,
                    log_level_str(level), message);
  }
}

static size_t format_log_json(char *dst, size_t dstsize, const char *prefix,
                              const char *timestamp, log_level_t level,
                              const char *message) {
  if (prefix) {
    return snprintf(dst, dstsize,
                    "{\"timestamp\":\"%s\",\"level\":\"%s\",\"prefix\":\"%"
                    "s\",\"message\":\"%s\"}\n",
                    timestamp, log_level_str(level), prefix, message);
  } else {
    return snprintf(
        dst, dstsize,
        "{\"timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"%s\"}\n",
        timestamp, log_level_str(level), message);
  }
}
