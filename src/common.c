#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

static const char *log_level_strings[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

void log_message(log_level_t level, const char *format, ...) {
    time_t now;
    char time_buf[64];
    struct tm *tm_info;

    time(&now);
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "[%s] [%s] ", time_buf, log_level_strings[level]);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
}

void handle_error(const char *message) {
    log_message(LOG_ERROR, "%s", message);
    exit(EXIT_FAILURE);
}
