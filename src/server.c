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

#define MAX_CLIENTS 253
#define SERVER_INTERFACE "wg0"
#define SERVER_IP_BASE "10.0.0"
#define SERVER_IP_PREFIX 24
#define SERVER_LISTEN_PORT 51820

typedef struct {
    uint8_t pubkey[WG_KEY_LEN];
    char ip_address[INET_ADDRSTRLEN];
    bool assigned;
} client_entry_t;

static client_entry_t clients[MAX_CLIENTS];
static uint8_t server_privkey[WG_KEY_LEN];
static uint8_t server_pubkey[WG_KEY_LEN];

static int find_free_ip(char *ip_out) {
    for (int i = 2; i < MAX_CLIENTS + 2; i++) {
        bool found = false;
        for (int j = 0; j < MAX_CLIENTS; j++) {
            if (clients[j].assigned) {
                char expected_ip[INET_ADDRSTRLEN];
                snprintf(expected_ip, sizeof(expected_ip), "%s.%d", SERVER_IP_BASE, i);
                if (strcmp(clients[j].ip_address, expected_ip) == 0) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            snprintf(ip_out, INET_ADDRSTRLEN, "%s.%d", SERVER_IP_BASE, i);
            return 0;
        }
    }
    return -1;
}

static int assign_client_ip(const uint8_t *client_pubkey, char *ip_out) {
    /* 既に割り当てられているか確認 */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].assigned &&
            memcmp(clients[i].pubkey, client_pubkey, WG_KEY_LEN) == 0) {
            strncpy(ip_out, clients[i].ip_address, INET_ADDRSTRLEN);
            log_message(LOG_INFO, "Client already has IP: %s", ip_out);
            return 0;
        }
    }

    /* 新しいIPを割り当て */
    if (find_free_ip(ip_out) != 0) {
        log_message(LOG_ERROR, "No free IP addresses available");
        return -1;
    }

    /* クライアント登録 */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].assigned) {
            memcpy(clients[i].pubkey, client_pubkey, WG_KEY_LEN);
            strncpy(clients[i].ip_address, ip_out, INET_ADDRSTRLEN);
            clients[i].assigned = true;
            log_message(LOG_INFO, "Assigned IP %s to new client", ip_out);
            return 0;
        }
    }

    return -1;
}

static int handle_client_hello(int sockfd, struct sockaddr_in *client_addr,
                               const protocol_message_t *msg) {
    if (msg->length != WG_KEY_LEN) {
        log_message(LOG_ERROR, "Invalid CLIENT_HELLO message length");
        return -1;
    }

    uint8_t client_pubkey[WG_KEY_LEN];
    memcpy(client_pubkey, msg->data, WG_KEY_LEN);

    /* IPアドレスを割り当て */
    char client_ip[INET_ADDRSTRLEN];
    if (assign_client_ip(client_pubkey, client_ip) != 0) {
        return -1;
    }

    /* WireGuardにピアを追加 */
    wg_peer_t peer;
    memcpy(peer.public_key, client_pubkey, WG_KEY_LEN);
    snprintf(peer.allowed_ips, sizeof(peer.allowed_ips), "%s/32", client_ip);
    peer.endpoint[0] = '\0';
    peer.persistent_keepalive = 0;

    if (wg_add_peer(SERVER_INTERFACE, &peer) != 0) {
        log_message(LOG_ERROR, "Failed to add peer to WireGuard");
        return -1;
    }

    /* 設定を返送 */
    client_config_t config;
    memcpy(config.client_pubkey, client_pubkey, WG_KEY_LEN);
    strncpy(config.client_ip, client_ip, INET_ADDRSTRLEN);
    snprintf(config.allowed_ips, sizeof(config.allowed_ips), "%s.1/32", SERVER_IP_BASE);
    config.server_port = SERVER_LISTEN_PORT;

    protocol_message_t response;
    pack_server_config(&response, &config);

    /* メッセージを暗号化して送信 */
    uint8_t send_buffer[MAX_BUFFER_SIZE];
    uint8_t plaintext[MAX_BUFFER_SIZE];

    plaintext[0] = response.type;
    uint16_t len_net = htons(response.length);
    memcpy(plaintext + 1, &len_net, sizeof(uint16_t));
    memcpy(plaintext + 3, response.data, response.length);
    size_t plaintext_len = 3 + response.length;

    size_t ciphertext_len;
    if (encrypt_message(plaintext, plaintext_len,
                       client_pubkey, server_privkey,
                       send_buffer, &ciphertext_len) != 0) {
        log_message(LOG_ERROR, "Failed to encrypt response");
        return -1;
    }

    if (sendto(sockfd, send_buffer, ciphertext_len, 0,
              (struct sockaddr *)client_addr, sizeof(*client_addr)) < 0) {
        log_message(LOG_ERROR, "Failed to send response");
        return -1;
    }

    log_message(LOG_INFO, "Sent configuration to client: %s", client_ip);
    return 0;
}

int main(int argc, char *argv[]) {
    log_message(LOG_INFO, "Starting WireGuard Dynamic Server");

    if (crypto_init() != 0) {
        handle_error("Failed to initialize crypto");
    }

    /* 鍵ペアを生成 */
    if (generate_keypair(server_pubkey, server_privkey) != 0) {
        handle_error("Failed to generate server keypair");
    }

    /* クライアントテーブルを初期化 */
    memset(clients, 0, sizeof(clients));

    /* WireGuardインターフェイスを設定 */
    log_message(LOG_INFO, "Configuring WireGuard interface %s", SERVER_INTERFACE);

    if (wg_set_private_key(SERVER_INTERFACE, server_privkey) != 0) {
        handle_error("Failed to set private key");
    }

    if (wg_set_listen_port(SERVER_INTERFACE, SERVER_LISTEN_PORT) != 0) {
        handle_error("Failed to set listen port");
    }

    char server_ip[INET_ADDRSTRLEN];
    snprintf(server_ip, sizeof(server_ip), "%s.1", SERVER_IP_BASE);
    if (wg_set_interface_ip(SERVER_INTERFACE, server_ip, SERVER_IP_PREFIX) != 0) {
        handle_error("Failed to set interface IP");
    }

    if (wg_interface_up(SERVER_INTERFACE) != 0) {
        handle_error("Failed to bring interface up");
    }

    /* UDPソケットを作成 */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        handle_error("Failed to create socket");
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DEFAULT_SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        handle_error("Failed to bind socket");
    }

    log_message(LOG_INFO, "Server listening on port %d", DEFAULT_SERVER_PORT);

    /* メインループ */
    while (1) {
        uint8_t recv_buffer[MAX_BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        ssize_t n = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0,
                            (struct sockaddr *)&client_addr, &client_len);
        if (n < 0) {
            log_message(LOG_ERROR, "recvfrom failed");
            continue;
        }

        log_message(LOG_DEBUG, "Received %zd bytes from client", n);

        /* メッセージを復号化 */
        uint8_t plaintext[MAX_BUFFER_SIZE];
        size_t plaintext_len;

        /* 暗号化なしで処理（最初のメッセージは平文） */
        protocol_message_t msg;
        if (unpack_message(recv_buffer, n, &msg) != 0) {
            log_message(LOG_ERROR, "Failed to unpack message");
            continue;
        }

        if (msg.type == MSG_CLIENT_HELLO) {
            handle_client_hello(sockfd, &client_addr, &msg);
        } else {
            log_message(LOG_WARN, "Unknown message type: %d", msg.type);
        }
    }

    close(sockfd);
    return 0;
}
