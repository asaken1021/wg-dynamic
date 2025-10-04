#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>

#define WG_KEY_LEN 32
#define MAX_BUFFER_SIZE 4096
#define DEFAULT_SERVER_PORT 51821

/* ログレベル */
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

/* ログ出力関数 */
void log_message(log_level_t level, const char *format, ...);

/* 設定エラー処理 */
void handle_error(const char *message);

#endif /* COMMON_H */
