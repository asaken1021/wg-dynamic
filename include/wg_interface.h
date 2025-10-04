#ifndef WG_INTERFACE_H
#define WG_INTERFACE_H

#include "common.h"

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

/* WireGuardインターフェイスのIPアドレスを設定 */
int wg_set_interface_ip(const char *interface, const char *ip_addr, int prefix_len);

/* WireGuardインターフェイスを起動 */
int wg_interface_up(const char *interface);

/* WireGuardインターフェイスにプライベートキーを設定 */
int wg_set_private_key(const char *interface, const uint8_t *private_key);

/* WireGuardインターフェイスのリスニングポートを設定 */
int wg_set_listen_port(const char *interface, uint16_t port);

#endif /* WG_INTERFACE_H */
