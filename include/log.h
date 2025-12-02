#ifndef LOG_H
#define LOG_H

#include <stdio.h>

enum { MAX_LOG_DESTS = 10 };

typedef enum {
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
} log_level_t;

typedef enum { LOG_FORMAT_PLAIN, LOG_FORMAT_JSON } log_format_t;

typedef struct {
    int fd;
    const char *prefix;
    log_format_t format;
} log_destination_t;

typedef struct {
    log_destination_t dests[MAX_LOG_DESTS];
    size_t nfds;
} log_config_t;

int log_add_dest(int fd, const char *prefix, log_format_t format);
int log_remove_dest(int fd);
int log(log_level_t level, const char *format, ...);

// Macros for convenience
#define log_info(...) log(LOG_INFO, __VA_ARGS__)
#define log_warn(...) log(LOG_WARN, __VA_ARGS__)
#define log_err(...) log(LOG_ERROR, __VA_ARGS__)

#endif // LOG_H
