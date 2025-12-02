#ifndef TIME_UTILS_H
#define TIME_UTILS_H

#include <stdint.h>
#include <sys/time.h>
#include <stddef.h>

enum { MS_PER_S = 1000, US_PER_MS = 1000, US_PER_S = 1000000 };

uint32_t get_current_timestamp_ms(void);

void get_current_timestamp_str(char *buffer, size_t size);

struct timeval *ftotv(double raw, struct timeval *out_tv);

#endif // TIME_UTILS_H
