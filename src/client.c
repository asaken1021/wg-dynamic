#include "common.h"
#include "crypto.h"
#include "protocol.h"
#include "wg_interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define CLIENT_INTERFACE "wg0"
#define TIMEOUT_SEC 5

static uint8_t client_privkey[WG_KEY_LEN];
static uint8_t client_pubkey[WG_KEY_LEN];
static uint8_t server_pubkey[WG_KEY_LEN];

static int send_client_hello(int sockfd, struct sockaddr_in *server_addr) {
    protocol_message_t msg;
    pack_client_hello(&msg, client_pubkey);

    /* メッセージを平文バッファにパック */
    uint8_t plaintext[MAX_BUFFER_SIZE];
    plaintext[0] = msg.type;
    uint16_t len_net = htons(msg.length);
    memcpy(plaintext + 1, &len_net, sizeof(uint16_t));
    memcpy(plaintext + 3, msg.data, msg.length);
    size_t plaintext_len = 3 + msg.length;

    /* サーバーの公開鍵でsealed box暗号化 */
    uint8_t ciphertext[MAX_BUFFER_SIZE];
    size_t ciphertext_len;
    if (encrypt_sealed(plaintext, plaintext_len,
                      server_pubkey,
                      ciphertext, &ciphertext_len) != 0) {
        log_message(LOG_ERROR, "Failed to encrypt CLIENT_HELLO");
        return -1;
    }

    if (sendto(sockfd, ciphertext, ciphertext_len, 0,
              (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        log_message(LOG_ERROR, "Failed to send CLIENT_HELLO");
        return -1;
    }

    log_message(LOG_INFO, "Sent encrypted CLIENT_HELLO to server");
    return 0;
}

static int receive_server_config(int sockfd, client_config_t *config) {
    uint8_t recv_buffer[MAX_BUFFER_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    /* タイムアウト設定 */
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0,
                        (struct sockaddr *)&from_addr, &from_len);
    if (n < 0) {
        log_message(LOG_ERROR, "Failed to receive response from server (timeout)");
        return -1;
    }

    log_message(LOG_DEBUG, "Received %zd bytes from server", n);

    /* メッセージを復号化 */
    uint8_t plaintext[MAX_BUFFER_SIZE];
    size_t plaintext_len;

    if (decrypt_message(recv_buffer, n,
                       server_pubkey, client_privkey,
                       plaintext, &plaintext_len) != 0) {
        log_message(LOG_ERROR, "Failed to decrypt server response");
        return -1;
    }

    log_message(LOG_DEBUG, "Decrypted %zu bytes", plaintext_len);

    /* メッセージをアンパック */
    protocol_message_t msg;
    if (unpack_message(plaintext, plaintext_len, &msg) != 0) {
        log_message(LOG_ERROR, "Failed to unpack server response");
        return -1;
    }

    if (msg.type != MSG_SERVER_CONFIG) {
        log_message(LOG_ERROR, "Unexpected message type: %d", msg.type);
        return -1;
    }

    /* 設定を解析 */
    uint8_t *ptr = msg.data;
    size_t offset = 0;

    /* クライアント公開鍵 */
    memcpy(config->client_pubkey, ptr + offset, WG_KEY_LEN);
    offset += WG_KEY_LEN;

    /* クライアントIPアドレス */
    uint8_t ip_len = ptr[offset++];
    memcpy(config->client_ip, ptr + offset, ip_len);
    config->client_ip[ip_len] = '\0';
    offset += ip_len;

    /* AllowedIPs */
    uint8_t allowed_len = ptr[offset++];
    memcpy(config->allowed_ips, ptr + offset, allowed_len);
    config->allowed_ips[allowed_len] = '\0';
    offset += allowed_len;

    /* サーバーポート */
    uint16_t port_net;
    memcpy(&port_net, ptr + offset, sizeof(uint16_t));
    config->server_port = ntohs(port_net);

    log_message(LOG_INFO, "Received configuration: IP=%s, AllowedIPs=%s, Port=%u",
               config->client_ip, config->allowed_ips, config->server_port);

    return 0;
}

static int apply_configuration(const client_config_t *config, const char *server_endpoint) {
    /* WireGuardインターフェイスに秘密鍵を設定 */
    if (wg_set_private_key(CLIENT_INTERFACE, client_privkey) != 0) {
        log_message(LOG_ERROR, "Failed to set private key");
        return -1;
    }

    /* クライアントIPを設定 */
    if (wg_set_interface_ip(CLIENT_INTERFACE, config->client_ip, 24) != 0) {
        log_message(LOG_ERROR, "Failed to set interface IP");
        return -1;
    }

    /* サーバーをピアとして追加 */
    wg_peer_t server_peer;
    memcpy(server_peer.public_key, server_pubkey, WG_KEY_LEN);
    strncpy(server_peer.endpoint, server_endpoint, sizeof(server_peer.endpoint));
    strncpy(server_peer.allowed_ips, config->allowed_ips, sizeof(server_peer.allowed_ips));
    server_peer.persistent_keepalive = 25;

    if (wg_add_peer(CLIENT_INTERFACE, &server_peer) != 0) {
        log_message(LOG_ERROR, "Failed to add server as peer");
        return -1;
    }

    /* インターフェイスを起動 */
    if (wg_interface_up(CLIENT_INTERFACE) != 0) {
        log_message(LOG_ERROR, "Failed to bring interface up");
        return -1;
    }

    log_message(LOG_INFO, "WireGuard configuration applied successfully");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_address> <server_pubkey_base64>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *server_address = argv[1];
    char *server_pubkey_b64 = argv[2];

    log_message(LOG_INFO, "Starting WireGuard Dynamic Client");

    if (crypto_init() != 0) {
        handle_error("Failed to initialize crypto");
    }

    /* 鍵ペアを生成 */
    if (generate_keypair(client_pubkey, client_privkey) != 0) {
        handle_error("Failed to generate client keypair");
    }

    /* サーバーの公開鍵を読み込み */
    if (load_public_key(server_pubkey_b64, server_pubkey) != 0) {
        handle_error("Failed to load server public key");
    }
    log_message(LOG_INFO, "Loaded server public key");

    /* UDPソケットを作成 */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        handle_error("Failed to create socket");
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_SERVER_PORT);

    if (inet_pton(AF_INET, server_address, &server_addr.sin_addr) <= 0) {
        handle_error("Invalid server address");
    }

    /* CLIENT_HELLOを送信 */
    if (send_client_hello(sockfd, &server_addr) != 0) {
        handle_error("Failed to send CLIENT_HELLO");
    }

    /* サーバーからの設定を受信 */
    client_config_t config;
    if (receive_server_config(sockfd, &config) != 0) {
        handle_error("Failed to receive server configuration");
    }

    /* 設定を適用 */
    char server_endpoint[512];
    snprintf(server_endpoint, sizeof(server_endpoint), "%s:%u",
             server_address, config.server_port);

    if (apply_configuration(&config, server_endpoint) != 0) {
        handle_error("Failed to apply configuration");
    }

    log_message(LOG_INFO, "Client configured successfully!");
    log_message(LOG_INFO, "Interface: %s, IP: %s", CLIENT_INTERFACE, config.client_ip);

    close(sockfd);
    return EXIT_SUCCESS;
}
