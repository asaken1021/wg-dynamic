#include "protocol.h"
#include "common.h"
#include <string.h>
#include <arpa/inet.h>

int pack_client_hello(protocol_message_t *msg, const uint8_t *pubkey) {
    if (!msg || !pubkey) {
        return -1;
    }

    msg->type = MSG_CLIENT_HELLO;
    msg->length = WG_KEY_LEN;  /* ホストバイトオーダーで保持 */
    memcpy(msg->data, pubkey, WG_KEY_LEN);

    return 0;
}

int pack_server_config(protocol_message_t *msg, const client_config_t *config) {
    if (!msg || !config) {
        return -1;
    }

    msg->type = MSG_SERVER_CONFIG;

    uint8_t *ptr = msg->data;
    size_t offset = 0;

    /* クライアント公開鍵 */
    memcpy(ptr + offset, config->client_pubkey, WG_KEY_LEN);
    offset += WG_KEY_LEN;

    /* クライアントIPアドレス */
    uint8_t ip_len = strlen(config->client_ip);
    ptr[offset++] = ip_len;
    memcpy(ptr + offset, config->client_ip, ip_len);
    offset += ip_len;

    /* AllowedIPs */
    uint8_t allowed_len = strlen(config->allowed_ips);
    ptr[offset++] = allowed_len;
    memcpy(ptr + offset, config->allowed_ips, allowed_len);
    offset += allowed_len;

    /* サーバーポート */
    uint16_t port_net = htons(config->server_port);
    memcpy(ptr + offset, &port_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    /* ハートビート間隔 */
    uint32_t interval_net = htonl(config->heartbeat_interval);
    memcpy(ptr + offset, &interval_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    msg->length = offset;  /* ホストバイトオーダーで保持 */

    return 0;
}

int pack_config_ack(protocol_message_t *msg) {
    if (!msg) {
        return -1;
    }

    msg->type = MSG_CONFIG_ACK;
    msg->length = 0;

    return 0;
}

int pack_heartbeat(protocol_message_t *msg, const uint8_t *pubkey) {
    if (!msg || !pubkey) {
        return -1;
    }

    msg->type = MSG_HEARTBEAT;
    msg->length = WG_KEY_LEN;
    memcpy(msg->data, pubkey, WG_KEY_LEN);

    return 0;
}

int unpack_message(const uint8_t *buffer, size_t len, protocol_message_t *msg) {
    if (!buffer || !msg || len < 3) {
        return -1;
    }

    msg->type = buffer[0];
    memcpy(&msg->length, buffer + 1, sizeof(uint16_t));
    msg->length = ntohs(msg->length);

    if (len < 3 + msg->length) {
        log_message(LOG_ERROR, "Incomplete message");
        return -1;
    }

    if (msg->length > 0) {
        memcpy(msg->data, buffer + 3, msg->length);
    }

    return 0;
}
