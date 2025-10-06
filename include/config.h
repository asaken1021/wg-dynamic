#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_CONFIG_LINE 256
#define DEFAULT_CONFIG_FILE "server.conf"

/* サーバー設定構造体 */
typedef struct {
    char interface[32];           /* WireGuardインターフェイス名 */
    char server_ip[64];           /* サーバーIPアドレス (例: 10.0.0.1/24) */
    uint16_t wg_listen_port;      /* WireGuardリスニングポート */
    uint16_t config_server_port;  /* 設定サーバーポート */
    char client_ip_pool[64];      /* クライアントIP範囲 CIDR表記 (例: 10.0.0.0/24) */
    char allowed_ips[256];        /* クライアントに渡すAllowedIPs (例: 10.0.0.0/24) */
    char server_privkey[64];      /* サーバー秘密鍵 (Base64, 設定ファイルから読み込み) */
    bool privkey_loaded;          /* 秘密鍵が読み込まれたか */
} server_config_t;

/* デフォルト設定値 */
#define DEFAULT_INTERFACE "wg0"
#define DEFAULT_SERVER_IP "10.0.0.1/24"
#define DEFAULT_WG_LISTEN_PORT 51820
#define DEFAULT_CONFIG_SERVER_PORT 51821
#define DEFAULT_CLIENT_IP_POOL "10.0.0.0/24"
#define DEFAULT_ALLOWED_IPS "10.0.0.0/24"

/* 設定ファイルを読み込む */
int load_server_config(const char *filepath, server_config_t *config);

/* デフォルト設定で初期化 */
void init_default_config(server_config_t *config);

/* 設定を表示 */
void print_config(const server_config_t *config);

/* 設定ファイルに秘密鍵を保存 */
int save_privkey_to_config(const char *filepath, const char *privkey_b64);

/* 設定ファイルから秘密鍵を削除 */
int remove_privkey_from_config(const char *filepath);

/* CIDR表記からIPアドレス範囲を解析 */
int parse_cidr(const char *cidr, uint32_t *network, uint32_t *netmask, int *prefix_len);

/* IPアドレス文字列をuint32_tに変換 */
int ip_string_to_uint32(const char *ip_str, uint32_t *ip);

/* uint32_tをIPアドレス文字列に変換 */
void uint32_to_ip_string(uint32_t ip, char *ip_str, size_t len);

#endif /* CONFIG_H */
