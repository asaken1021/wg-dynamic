#define _GNU_SOURCE
#include "wg_interface.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

/* fork + execvp でコマンドを実行 */
static int execute_command_args(char *const argv[]) {
    if (!argv || !argv[0]) {
        return -1;
    }

    /* デバッグログ: 実行するコマンドを表示 */
    char debug_cmd[1024] = {0};
    size_t offset = 0;
    for (int i = 0; argv[i] != NULL && offset < sizeof(debug_cmd) - 1; i++) {
        offset += snprintf(debug_cmd + offset, sizeof(debug_cmd) - offset, "%s ", argv[i]);
    }
    log_message(LOG_DEBUG, "Executing: %s", debug_cmd);

    pid_t pid = fork();
    if (pid < 0) {
        log_message(LOG_ERROR, "fork() failed");
        return -1;
    }

    if (pid == 0) {
        /* 子プロセス */
        execvp(argv[0], argv);
        /* execvpが成功すると、ここには到達しない */
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
            log_message(LOG_ERROR, "Command failed with exit code: %d", exit_code);
            return -1;
        }
    } else {
        log_message(LOG_ERROR, "Command terminated abnormally");
        return -1;
    }

    return 0;
}

static void key_to_base64(const uint8_t *key, char *output, size_t output_len) {
    sodium_bin2base64(output, output_len, key, WG_KEY_LEN, sodium_base64_VARIANT_ORIGINAL);
}

int wg_add_peer(const char *interface, const wg_peer_t *peer) {
    if (!interface || !peer) {
        return -1;
    }

    char pubkey_b64[256];
    key_to_base64(peer->public_key, pubkey_b64, sizeof(pubkey_b64));

    log_message(LOG_INFO, "Adding peer to interface %s", interface);

    /* 引数配列を構築 */
    char *argv[32];
    int argc = 0;

    argv[argc++] = "wg";
    argv[argc++] = "set";
    argv[argc++] = (char *)interface;
    argv[argc++] = "peer";
    argv[argc++] = pubkey_b64;
    argv[argc++] = "allowed-ips";
    argv[argc++] = (char *)peer->allowed_ips;

    if (strlen(peer->endpoint) > 0) {
        argv[argc++] = "endpoint";
        argv[argc++] = (char *)peer->endpoint;
    }

    char keepalive_str[32];
    if (peer->persistent_keepalive > 0) {
        snprintf(keepalive_str, sizeof(keepalive_str), "%u", peer->persistent_keepalive);
        argv[argc++] = "persistent-keepalive";
        argv[argc++] = keepalive_str;
    }

    argv[argc] = NULL;

    return execute_command_args(argv);
}

int wg_remove_peer(const char *interface, const uint8_t *public_key) {
    if (!interface || !public_key) {
        return -1;
    }

    char pubkey_b64[256];
    key_to_base64(public_key, pubkey_b64, sizeof(pubkey_b64));

    log_message(LOG_INFO, "Removing peer from interface %s", interface);

    char *argv[] = {"wg", "set", (char *)interface, "peer", pubkey_b64, "remove", NULL};
    return execute_command_args(argv);
}

int wg_set_interface_ip(const char *interface, const char *ip_addr, int prefix_len) {
    if (!interface || !ip_addr) {
        return -1;
    }

    log_message(LOG_INFO, "Setting IP %s/%d on interface %s", ip_addr, prefix_len, interface);

    char ip_with_prefix[128];
    snprintf(ip_with_prefix, sizeof(ip_with_prefix), "%s/%d", ip_addr, prefix_len);

    char *argv[] = {"ip", "addr", "add", ip_with_prefix, "dev", (char *)interface, NULL};
    return execute_command_args(argv);
}

int wg_interface_up(const char *interface) {
    if (!interface) {
        return -1;
    }

    log_message(LOG_INFO, "Bringing up interface %s", interface);

    char *argv[] = {"ip", "link", "set", (char *)interface, "up", NULL};
    return execute_command_args(argv);
}

int wg_set_private_key(const char *interface, const uint8_t *private_key) {
    if (!interface || !private_key) {
        return -1;
    }

    char privkey_b64[256];
    key_to_base64(private_key, privkey_b64, sizeof(privkey_b64));

    log_message(LOG_INFO, "Setting private key on interface %s", interface);

    /* パイプを作成 */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        log_message(LOG_ERROR, "pipe() failed");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        log_message(LOG_ERROR, "fork() failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* 子プロセス: wg コマンドを実行 */
        close(pipefd[1]); /* 書き込み側を閉じる */
        dup2(pipefd[0], STDIN_FILENO); /* 標準入力をパイプに接続 */
        close(pipefd[0]);

        char *argv[] = {"wg", "set", (char *)interface, "private-key", "/dev/stdin", NULL};
        execvp("wg", argv);
        perror("execvp failed");
        _exit(127);
    }

    /* 親プロセス: 秘密鍵をパイプに書き込む */
    close(pipefd[0]); /* 読み込み側を閉じる */

    size_t key_len = strlen(privkey_b64);
    ssize_t written = write(pipefd[1], privkey_b64, key_len);
    write(pipefd[1], "\n", 1);
    close(pipefd[1]);

    if (written < 0 || (size_t)written != key_len) {
        log_message(LOG_ERROR, "Failed to write private key to pipe");
    }

    /* 子プロセスの終了を待つ */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        log_message(LOG_ERROR, "waitpid() failed");
        return -1;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 0) {
            log_message(LOG_ERROR, "wg command failed with exit code: %d", exit_code);
            return -1;
        }
    } else {
        log_message(LOG_ERROR, "wg command terminated abnormally");
        return -1;
    }

    return 0;
}

int wg_set_listen_port(const char *interface, uint16_t port) {
    if (!interface) {
        return -1;
    }

    log_message(LOG_INFO, "Setting listen port %u on interface %s", port, interface);

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    char *argv[] = {"wg", "set", (char *)interface, "listen-port", port_str, NULL};
    return execute_command_args(argv);
}

int wg_create_interface(const char *interface) {
    if (!interface) {
        return -1;
    }

    log_message(LOG_INFO, "Creating WireGuard interface %s", interface);

    char *argv[] = {"ip", "link", "add", "dev", (char *)interface, "type", "wireguard", NULL};
    return execute_command_args(argv);
}

int wg_delete_interface(const char *interface) {
    if (!interface) {
        return -1;
    }

    log_message(LOG_INFO, "Deleting interface %s", interface);

    char *argv[] = {"ip", "link", "delete", "dev", (char *)interface, NULL};
    return execute_command_args(argv);
}

int wg_interface_down(const char *interface) {
    if (!interface) {
        return -1;
    }

    log_message(LOG_INFO, "Bringing down interface %s", interface);

    char *argv[] = {"ip", "link", "set", (char *)interface, "down", NULL};
    return execute_command_args(argv);
}

int wg_add_route(const char *destination, const char *interface) {
    if (!destination || !interface) {
        return -1;
    }

    log_message(LOG_INFO, "Adding route to %s via %s", destination, interface);

    char *argv[] = {"ip", "route", "add", (char *)destination, "dev", (char *)interface, NULL};
    return execute_command_args(argv);
}

int wg_delete_route(const char *destination, const char *interface) {
    if (!destination || !interface) {
        return -1;
    }

    log_message(LOG_INFO, "Deleting route to %s via %s", destination, interface);

    /* stderrを抑制するために特別な処理が必要 */
    pid_t pid = fork();
    if (pid < 0) {
        log_message(LOG_ERROR, "fork() failed");
        return -1;
    }

    if (pid == 0) {
        /* 子プロセス: stderrを/dev/nullにリダイレクト */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        char *argv[] = {"ip", "route", "del", (char *)destination, "dev", (char *)interface, NULL};
        execvp("ip", argv);
        _exit(127);
    }

    /* 親プロセス: 子プロセスの終了を待つ */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        log_message(LOG_ERROR, "waitpid() failed");
        return -1;
    }

    /* ルート削除の失敗は許容する（既に存在しない場合など） */
    return 0;
}

void normalize_allowed_ips(const char *input, char *output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        return;
    }

    size_t in_pos = 0;
    size_t out_pos = 0;
    size_t input_len = strlen(input);

    while (in_pos < input_len && out_pos < output_size - 1) {
        char c = input[in_pos];

        if (c == ',') {
            /* コンマを出力 */
            output[out_pos++] = ',';
            in_pos++;

            /* コンマの後のスペースをスキップ */
            while (in_pos < input_len && (input[in_pos] == ' ' || input[in_pos] == '\t')) {
                in_pos++;
            }
        } else {
            /* そのまま出力 */
            output[out_pos++] = c;
            in_pos++;
        }
    }

    output[out_pos] = '\0';
}

void foreach_cidr(const char *allowed_ips, cidr_callback_t callback, void *user_data) {
    if (!allowed_ips || !callback) {
        return;
    }

    char buffer[1024];
    strncpy(buffer, allowed_ips, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *saveptr;
    char *token = strtok_r(buffer, ",", &saveptr);

    while (token != NULL) {
        /* 前後の空白を削除 */
        while (*token == ' ' || *token == '\t') {
            token++;
        }

        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        if (strlen(token) > 0) {
            callback(token, user_data);
        }

        token = strtok_r(NULL, ",", &saveptr);
    }
}
