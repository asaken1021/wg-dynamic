#include "common.h"
#include "crypto.h"
#include "protocol.h"
#include "wg_interface.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sodium.h>
#include <signal.h>

typedef struct {
    uint8_t pubkey[WG_KEY_LEN];
    uint32_t ip_address;  /* ホストバイトオーダー */
    bool assigned;
} client_entry_t;

static client_entry_t *clients = NULL;
static size_t max_clients = 0;
static uint8_t server_privkey[WG_KEY_LEN];
static uint8_t server_pubkey[WG_KEY_LEN];
static server_config_t server_config;
static uint32_t pool_network;
static uint32_t pool_netmask;
static int pool_prefix_len;
static uint32_t server_ip_uint32;
static volatile sig_atomic_t running = 1;

static void cleanup_and_exit(int exit_code) {
    log_message(LOG_INFO, "Cleaning up and shutting down...");

    /* インターフェイスを削除 */
    wg_delete_interface(server_config.interface);

    /* クライアントテーブルを解放 */
    if (clients) {
        free(clients);
    }

    exit(exit_code);
}

static void signal_handler(int signum) {
    log_message(LOG_INFO, "Received signal %d, shutting down...", signum);
    running = 0;
}

static int find_free_ip(uint32_t *ip_out) {
    /* CIDR範囲内で使用可能なIPアドレスを検索 */
    uint32_t num_ips = (~pool_netmask) + 1;  /* CIDR範囲内の総IP数 */

    for (uint32_t offset = 1; offset < num_ips - 1; offset++) {
        uint32_t candidate_ip = pool_network + offset;

        /* サーバーIPと重複する場合はスキップ */
        if (candidate_ip == server_ip_uint32) {
            continue;
        }

        /* ブロードキャストアドレスとネットワークアドレスを除外 */
        if (candidate_ip == pool_network || candidate_ip == (pool_network | ~pool_netmask)) {
            continue;
        }

        /* 既に割り当て済みかチェック */
        bool found = false;
        for (size_t j = 0; j < max_clients; j++) {
            if (clients[j].assigned && clients[j].ip_address == candidate_ip) {
                found = true;
                break;
            }
        }

        if (!found) {
            *ip_out = candidate_ip;
            return 0;
        }
    }

    log_message(LOG_ERROR, "No free IP addresses in pool");
    return -1;
}

static int assign_client_ip(const uint8_t *client_pubkey, char *ip_out) {
    /* 既に割り当てられているか確認 */
    for (size_t i = 0; i < max_clients; i++) {
        if (clients[i].assigned &&
            memcmp(clients[i].pubkey, client_pubkey, WG_KEY_LEN) == 0) {
            uint32_to_ip_string(clients[i].ip_address, ip_out, INET_ADDRSTRLEN);
            log_message(LOG_INFO, "Client already has IP: %s", ip_out);
            return 0;
        }
    }

    /* 新しいIPを割り当て */
    uint32_t new_ip;
    if (find_free_ip(&new_ip) != 0) {
        log_message(LOG_ERROR, "No free IP addresses available");
        return -1;
    }

    /* クライアント登録 */
    for (size_t i = 0; i < max_clients; i++) {
        if (!clients[i].assigned) {
            memcpy(clients[i].pubkey, client_pubkey, WG_KEY_LEN);
            clients[i].ip_address = new_ip;
            clients[i].assigned = true;
            uint32_to_ip_string(new_ip, ip_out, INET_ADDRSTRLEN);
            log_message(LOG_INFO, "Assigned IP %s to new client", ip_out);
            return 0;
        }
    }

    log_message(LOG_ERROR, "Client table full");
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

    if (wg_add_peer(server_config.interface, &peer) != 0) {
        log_message(LOG_ERROR, "Failed to add peer to WireGuard");
        return -1;
    }

    /* 設定を返送 */
    client_config_t config;
    memcpy(config.client_pubkey, client_pubkey, WG_KEY_LEN);
    strncpy(config.client_ip, client_ip, INET_ADDRSTRLEN);
    strncpy(config.allowed_ips, server_config.allowed_ips, sizeof(config.allowed_ips));
    config.server_port = server_config.wg_listen_port;

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
    const char *config_file = (argc > 1) ? argv[1] : DEFAULT_CONFIG_FILE;

    log_message(LOG_INFO, "Starting WireGuard Dynamic Server");

    if (crypto_init() != 0) {
        handle_error("Failed to initialize crypto");
    }

    /* 設定ファイルを読み込み */
    if (load_server_config(config_file, &server_config) != 0) {
        handle_error("Failed to load server configuration");
    }
    print_config(&server_config);

    /* サーバーIPアドレスを解析 */
    char server_ip_only[INET_ADDRSTRLEN];
    int server_prefix_len;
    {
        char temp_ip[64];
        strncpy(temp_ip, server_config.server_ip, sizeof(temp_ip) - 1);
        char *slash = strchr(temp_ip, '/');
        if (slash) {
            *slash = '\0';
            server_prefix_len = atoi(slash + 1);
            strncpy(server_ip_only, temp_ip, INET_ADDRSTRLEN);
        } else {
            strncpy(server_ip_only, temp_ip, INET_ADDRSTRLEN);
            server_prefix_len = 24;
        }
    }

    if (ip_string_to_uint32(server_ip_only, &server_ip_uint32) != 0) {
        handle_error("Invalid server IP address");
    }

    /* クライアントIPプールを解析 */
    if (parse_cidr(server_config.client_ip_pool, &pool_network, &pool_netmask, &pool_prefix_len) != 0) {
        handle_error("Failed to parse client IP pool CIDR");
    }

    /* プール内の最大クライアント数を計算 */
    uint32_t num_ips = (~pool_netmask) + 1;
    max_clients = (size_t)(num_ips > 2 ? num_ips - 2 : 0);  /* ネットワークとブロードキャストを除外 */

    if (max_clients == 0) {
        handle_error("Invalid client IP pool: no usable addresses");
    }

    log_message(LOG_INFO, "Client pool size: %zu addresses", max_clients);

    /* クライアントテーブルを動的に割り当て */
    clients = calloc(max_clients, sizeof(client_entry_t));
    if (!clients) {
        handle_error("Failed to allocate client table");
    }

    /* 秘密鍵を読み込み、存在しなければ生成 */
    if (server_config.privkey_loaded) {
        /* server.confから秘密鍵を読み込み */
        if (load_private_key(server_config.server_privkey, server_privkey) != 0) {
            handle_error("Failed to load private key from config");
        }
        /* 秘密鍵から公開鍵を導出 */
        if (crypto_scalarmult_base(server_pubkey, server_privkey) != 0) {
            handle_error("Failed to derive public key from private key");
        }
        log_message(LOG_INFO, "Loaded server keys from configuration");
    } else {
        /* 新しい鍵ペアを生成 */
        log_message(LOG_INFO, "Generating new server keypair...");
        if (generate_keypair(server_pubkey, server_privkey) != 0) {
            handle_error("Failed to generate server keypair");
        }

        /* 秘密鍵をserver.confに保存 */
        char privkey_b64[64];
        privkey_to_base64(server_privkey, privkey_b64, sizeof(privkey_b64));
        if (save_privkey_to_config(config_file, privkey_b64) != 0) {
            log_message(LOG_WARN, "Failed to save private key to config file");
        }
    }

    /* シグナルハンドラを設定 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* 公開鍵を表示（クライアントに配布するため） */
    char pubkey_b64[64];
    pubkey_to_base64(server_pubkey, pubkey_b64, sizeof(pubkey_b64));
    log_message(LOG_INFO, "Server public key: %s", pubkey_b64);
    printf("\n===========================================\n");
    printf("Server Public Key (share with clients):\n");
    printf("%s\n", pubkey_b64);
    printf("===========================================\n\n");

    /* WireGuardインターフェイスを作成 */
    log_message(LOG_INFO, "Creating WireGuard interface %s", server_config.interface);
    if (wg_create_interface(server_config.interface) != 0) {
        log_message(LOG_WARN, "Interface may already exist, continuing...");
    }

    /* WireGuardインターフェイスを設定 */
    log_message(LOG_INFO, "Configuring WireGuard interface %s", server_config.interface);

    if (wg_set_private_key(server_config.interface, server_privkey) != 0) {
        cleanup_and_exit(EXIT_FAILURE);
    }

    if (wg_set_listen_port(server_config.interface, server_config.wg_listen_port) != 0) {
        cleanup_and_exit(EXIT_FAILURE);
    }

    if (wg_set_interface_ip(server_config.interface, server_ip_only, server_prefix_len) != 0) {
        cleanup_and_exit(EXIT_FAILURE);
    }

    if (wg_interface_up(server_config.interface) != 0) {
        cleanup_and_exit(EXIT_FAILURE);
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
    server_addr.sin_port = htons(server_config.config_server_port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        handle_error("Failed to bind socket");
    }

    log_message(LOG_INFO, "Server listening on port %d", server_config.config_server_port);

    /* メインループ */
    while (running) {
        uint8_t recv_buffer[MAX_BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        ssize_t n = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0,
                            (struct sockaddr *)&client_addr, &client_len);
        if (n < 0) {
            if (running) {
                log_message(LOG_ERROR, "recvfrom failed");
            }
            continue;
        }

        log_message(LOG_DEBUG, "Received %zd bytes from client", n);

        /* メッセージをsealed boxで復号化 */
        uint8_t plaintext[MAX_BUFFER_SIZE];
        size_t plaintext_len;

        if (decrypt_sealed(recv_buffer, n,
                          server_pubkey, server_privkey,
                          plaintext, &plaintext_len) != 0) {
            log_message(LOG_ERROR, "Failed to decrypt message");
            continue;
        }

        log_message(LOG_DEBUG, "Decrypted %zu bytes", plaintext_len);

        /* メッセージをアンパック */
        protocol_message_t msg;
        if (unpack_message(plaintext, plaintext_len, &msg) != 0) {
            log_message(LOG_ERROR, "Failed to unpack message");
            continue;
        }

        if (msg.type == MSG_CLIENT_HELLO) {
            handle_client_hello(sockfd, &client_addr, &msg);
        } else {
            log_message(LOG_WARN, "Unknown message type: %d", msg.type);
        }
    }

    /* クリーンアップ */
    close(sockfd);
    cleanup_and_exit(EXIT_SUCCESS);
}
