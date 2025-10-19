#define _POSIX_C_SOURCE 200112L
#include "config.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>

void init_default_config(server_config_t *config) {
    if (!config) {
        return;
    }

    strncpy(config->interface, DEFAULT_INTERFACE, sizeof(config->interface) - 1);
    strncpy(config->server_ip, DEFAULT_SERVER_IP, sizeof(config->server_ip) - 1);
    config->wg_listen_port = DEFAULT_WG_LISTEN_PORT;
    config->config_server_port = DEFAULT_CONFIG_SERVER_PORT;
    strncpy(config->client_ip_pool, DEFAULT_CLIENT_IP_POOL, sizeof(config->client_ip_pool) - 1);
    strncpy(config->allowed_ips, DEFAULT_ALLOWED_IPS, sizeof(config->allowed_ips) - 1);
    config->server_privkey[0] = '\0';
    config->privkey_loaded = false;
    config->hook_pre_interface[0] = '\0';
    config->hook_post_ready[0] = '\0';
    config->hook_on_connect[0] = '\0';
    config->hook_on_exit[0] = '\0';
}

int load_server_config(const char *filepath, server_config_t *config) {
    if (!filepath || !config) {
        return -1;
    }

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        log_message(LOG_WARN, "Config file not found: %s, using defaults", filepath);
        init_default_config(config);
        return 0;  /* デフォルト設定を使用 */
    }

    /* まずデフォルト設定で初期化 */
    init_default_config(config);

    char line[MAX_CONFIG_LINE];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* 改行を削除 */
        line[strcspn(line, "\r\n")] = 0;

        /* コメント行と空行をスキップ */
        if (line[0] == '#' || line[0] == '\0' || line[0] == ' ' || line[0] == '\t') {
            continue;
        }

        /* キーと値を分離（最初の=で分割、値に=を含めることを許可） */
        char *equals = strchr(line, '=');
        if (!equals) {
            log_message(LOG_WARN, "Invalid config line %d: missing '='", line_num);
            continue;
        }

        *equals = '\0';
        char *key = line;
        char *value = equals + 1;

        /* 前後の空白を削除 */
        while (*key == ' ' || *key == '\t') key++;
        while (*value == ' ' || *value == '\t') value++;

        /* valueの末尾の空白と改行を削除 */
        char *end = value + strlen(value) - 1;
        while (end > value && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
            *end = '\0';
            end--;
        }

        /* 設定を解析 */
        if (strcmp(key, "interface") == 0) {
            strncpy(config->interface, value, sizeof(config->interface) - 1);
        } else if (strcmp(key, "server_ip") == 0) {
            strncpy(config->server_ip, value, sizeof(config->server_ip) - 1);
        } else if (strcmp(key, "wg_listen_port") == 0) {
            config->wg_listen_port = (uint16_t)atoi(value);
        } else if (strcmp(key, "config_server_port") == 0) {
            config->config_server_port = (uint16_t)atoi(value);
        } else if (strcmp(key, "client_ip_pool") == 0) {
            strncpy(config->client_ip_pool, value, sizeof(config->client_ip_pool) - 1);
        } else if (strcmp(key, "allowed_ips") == 0) {
            strncpy(config->allowed_ips, value, sizeof(config->allowed_ips) - 1);
        } else if (strcmp(key, "server_privkey") == 0) {
            /* 空の値でない場合のみ読み込む */
            if (strlen(value) > 0) {
                strncpy(config->server_privkey, value, sizeof(config->server_privkey) - 1);
                config->privkey_loaded = true;
            }
        } else if (strcmp(key, "hook_pre_interface") == 0) {
            strncpy(config->hook_pre_interface, value, sizeof(config->hook_pre_interface) - 1);
        } else if (strcmp(key, "hook_post_ready") == 0) {
            strncpy(config->hook_post_ready, value, sizeof(config->hook_post_ready) - 1);
        } else if (strcmp(key, "hook_on_connect") == 0) {
            strncpy(config->hook_on_connect, value, sizeof(config->hook_on_connect) - 1);
        } else if (strcmp(key, "hook_on_exit") == 0) {
            strncpy(config->hook_on_exit, value, sizeof(config->hook_on_exit) - 1);
        } else {
            log_message(LOG_WARN, "Unknown config key at line %d: %s", line_num, key);
        }
    }

    fclose(fp);
    log_message(LOG_INFO, "Configuration loaded from %s", filepath);
    return 0;
}

void print_config(const server_config_t *config) {
    if (!config) {
        return;
    }

    log_message(LOG_INFO, "=== Server Configuration ===");
    log_message(LOG_INFO, "Interface: %s", config->interface);
    log_message(LOG_INFO, "Server IP: %s", config->server_ip);
    log_message(LOG_INFO, "WireGuard Listen Port: %u", config->wg_listen_port);
    log_message(LOG_INFO, "Config Server Port: %u", config->config_server_port);
    log_message(LOG_INFO, "Client IP Pool: %s", config->client_ip_pool);
    log_message(LOG_INFO, "Allowed IPs: %s", config->allowed_ips);
    log_message(LOG_INFO, "===========================");
}

int ip_string_to_uint32(const char *ip_str, uint32_t *ip) {
    if (!ip_str || !ip) {
        return -1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }

    *ip = ntohl(addr.s_addr);
    return 0;
}

void uint32_to_ip_string(uint32_t ip, char *ip_str, size_t len) {
    if (!ip_str || len < INET_ADDRSTRLEN) {
        return;
    }

    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, ip_str, len);
}

int parse_cidr(const char *cidr, uint32_t *network, uint32_t *netmask, int *prefix_len) {
    if (!cidr || !network || !netmask || !prefix_len) {
        return -1;
    }

    char cidr_copy[64];
    strncpy(cidr_copy, cidr, sizeof(cidr_copy) - 1);
    cidr_copy[sizeof(cidr_copy) - 1] = '\0';

    /* CIDR表記を分離 (例: 10.0.0.0/24) */
    char *slash = strchr(cidr_copy, '/');
    if (!slash) {
        log_message(LOG_ERROR, "Invalid CIDR format: %s", cidr);
        return -1;
    }

    *slash = '\0';
    char *ip_str = cidr_copy;
    char *prefix_str = slash + 1;

    /* IPアドレスを解析 */
    if (ip_string_to_uint32(ip_str, network) != 0) {
        log_message(LOG_ERROR, "Invalid IP address in CIDR: %s", ip_str);
        return -1;
    }

    /* プレフィックス長を解析 */
    *prefix_len = atoi(prefix_str);
    if (*prefix_len < 0 || *prefix_len > 32) {
        log_message(LOG_ERROR, "Invalid prefix length: %d", *prefix_len);
        return -1;
    }

    /* ネットマスクを計算 */
    if (*prefix_len == 0) {
        *netmask = 0;
    } else {
        *netmask = 0xFFFFFFFF << (32 - *prefix_len);
    }

    /* ネットワークアドレスを正規化 */
    *network = *network & *netmask;

    return 0;
}

int save_privkey_to_config(const char *filepath, const char *privkey_b64) {
    if (!filepath || !privkey_b64) {
        return -1;
    }

    /* 既存の設定ファイルを読み込み */
    FILE *fp_read = fopen(filepath, "r");
    if (!fp_read) {
        log_message(LOG_ERROR, "Config file not found: %s", filepath);
        return -1;
    }

    /* 一時ファイルに書き込み */
    char temp_file[512];
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", filepath);
    FILE *fp_write = fopen(temp_file, "w");
    if (!fp_write) {
        fclose(fp_read);
        log_message(LOG_ERROR, "Failed to create temp file: %s", temp_file);
        return -1;
    }

    char line[MAX_CONFIG_LINE];

    /* 既存の設定をコピー（server_privkey行は除外） */
    while (fgets(line, sizeof(line), fp_read)) {
        if (strncmp(line, "server_privkey=", 15) == 0) {
            continue;  /* この行はスキップ */
        }
        fputs(line, fp_write);
    }

    /* 秘密鍵を追加 */
    fprintf(fp_write, "\n# Server private key (auto-generated)\nserver_privkey=%s\n", privkey_b64);

    fclose(fp_read);
    fclose(fp_write);

    /* 一時ファイルを元のファイルに置き換え */
    if (rename(temp_file, filepath) != 0) {
        log_message(LOG_ERROR, "Failed to update config file");
        return -1;
    }

    log_message(LOG_INFO, "Server private key saved to %s", filepath);
    return 0;
}

int remove_privkey_from_config(const char *filepath) {
    if (!filepath) {
        return -1;
    }

    FILE *fp_read = fopen(filepath, "r");
    if (!fp_read) {
        return -1;
    }

    char temp_file[512];
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", filepath);
    FILE *fp_write = fopen(temp_file, "w");
    if (!fp_write) {
        fclose(fp_read);
        return -1;
    }

    char line[MAX_CONFIG_LINE];

    /* server_privkey行を除外してコピー */
    while (fgets(line, sizeof(line), fp_read)) {
        if (strncmp(line, "server_privkey=", 15) != 0) {
            fputs(line, fp_write);
        }
    }

    fclose(fp_read);
    fclose(fp_write);

    rename(temp_file, filepath);
    return 0;
}

int execute_hook(const char *script_path, const char *client_ip, const char *client_pubkey) {
    if (!script_path || strlen(script_path) == 0) {
        /* スクリプトが設定されていない場合は何もしない */
        return 0;
    }

    log_message(LOG_INFO, "Executing hook script: %s", script_path);

    pid_t pid = fork();
    if (pid < 0) {
        log_message(LOG_ERROR, "fork() failed");
        return -1;
    }

    if (pid == 0) {
        /* 子プロセス */
        /* 環境変数を設定 */
        if (client_ip) {
            setenv("WG_CLIENT_IP", client_ip, 1);
        }
        if (client_pubkey) {
            setenv("WG_CLIENT_PUBKEY", client_pubkey, 1);
        }

        /* シェル経由でスクリプトを実行 */
        char *argv[] = {"/bin/sh", "-c", (char *)script_path, NULL};
        execvp("/bin/sh", argv);
        perror("execvp failed");
        _exit(127);
    }

    /* 親プロセス: 子プロセスの終了を待つ */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        log_message(LOG_ERROR, "waitpid() failed");
        return -1;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 0) {
            log_message(LOG_WARN, "Hook script failed with exit code: %d", exit_code);
            return -1;
        }
    } else {
        log_message(LOG_ERROR, "Hook script terminated abnormally");
        return -1;
    }

    log_message(LOG_DEBUG, "Hook script completed successfully");
    return 0;
}
