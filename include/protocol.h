#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "common.h"
#include <netinet/in.h>

/* メッセージタイプ */
typedef enum {
    MSG_CLIENT_HELLO = 1,
    MSG_SERVER_CONFIG = 2,
    MSG_CONFIG_ACK = 3,
    MSG_HEARTBEAT = 4,
    MSG_ERROR = 255
} message_type_t;

/* プロトコルメッセージ構造 */
typedef struct {
    uint8_t type;
    uint16_t length;
    uint8_t data[MAX_BUFFER_SIZE];
} protocol_message_t;

/* クライアント設定情報 */
typedef struct {
    uint8_t client_pubkey[WG_KEY_LEN];
    char client_ip[INET_ADDRSTRLEN];
    char allowed_ips[256];
    uint16_t server_port;
    uint32_t heartbeat_interval;  /* ハートビート送信間隔（秒） */
} client_config_t;

/* プロトコル関数 */
int pack_client_hello(protocol_message_t *msg, const uint8_t *pubkey);
int pack_server_config(protocol_message_t *msg, const client_config_t *config);
int pack_config_ack(protocol_message_t *msg);
int pack_heartbeat(protocol_message_t *msg, const uint8_t *pubkey);
int unpack_message(const uint8_t *buffer, size_t len, protocol_message_t *msg);

#endif /* PROTOCOL_H */
