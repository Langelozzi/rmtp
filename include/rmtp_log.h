#ifndef RMTP_LOG_H
#define RMTP_LOG_H

#include "log.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

void rmtp_log(uint32_t seq_num, bool is_ack, log_level_t level,
              const char *format, ...);

#endif // RMTP_LOG_H
