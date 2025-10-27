#ifndef WG_INTERFACE_H
#define WG_INTERFACE_H

#include "common.h"
#include <stddef.h>

/* WireGuardインターフェイス設定 */
typedef struct {
    char interface_name[16];
    uint16_t listen_port;
    uint8_t private_key[WG_KEY_LEN];
} wg_config_t;

/* WireGuardピア設定 */
typedef struct {
    uint8_t public_key[WG_KEY_LEN];
    char endpoint[256];
    char allowed_ips[256];
    uint16_t persistent_keepalive;
} wg_peer_t;

/* WireGuardインターフェイスにピアを追加 */
int wg_add_peer(const char *interface, const wg_peer_t *peer);

/* WireGuardインターフェイスからピアを削除 */
int wg_remove_peer(const char *interface, const uint8_t *public_key);

/* WireGuardインターフェイスのIPアドレスを設定 */
int wg_set_interface_ip(const char *interface, const char *ip_addr, int prefix_len);

/* WireGuardインターフェイスを起動 */
int wg_interface_up(const char *interface);

/* WireGuardインターフェイスにプライベートキーを設定 */
int wg_set_private_key(const char *interface, const uint8_t *private_key);

/* WireGuardインターフェイスのリスニングポートを設定 */
int wg_set_listen_port(const char *interface, uint16_t port);

/* WireGuardインターフェイスを作成 */
int wg_create_interface(const char *interface);

/* WireGuardインターフェイスを削除 */
int wg_delete_interface(const char *interface);

/* WireGuardインターフェイスを停止 */
int wg_interface_down(const char *interface);

/* ルートを追加 */
int wg_add_route(const char *destination, const char *interface);

/* ルートを削除 */
int wg_delete_route(const char *destination, const char *interface);

/* AllowedIPsを正規化（コンマ+スペース区切りをコンマのみに変換） */
void normalize_allowed_ips(const char *input, char *output, size_t output_size);

/* AllowedIPsを分割して各CIDRに対してコールバック関数を実行 */
typedef void (*cidr_callback_t)(const char *cidr, void *user_data);
void foreach_cidr(const char *allowed_ips, cidr_callback_t callback, void *user_data);

#endif /* WG_INTERFACE_H */
