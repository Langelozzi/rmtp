#include "../include/time_utils.h"
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

uint32_t get_current_timestamp_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint32_t)((tv.tv_sec * MS_PER_S) + (tv.tv_usec / US_PER_MS));
}

// Float (double) to struct timeval
struct timeval *ftotv(double raw_sec, struct timeval *out_tv) {
  out_tv->tv_sec = (int)raw_sec;
  out_tv->tv_usec = (int)((raw_sec - out_tv->tv_sec) * US_PER_S);
  return out_tv;
}

void get_current_timestamp_str(char *buffer, size_t size) {
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}
