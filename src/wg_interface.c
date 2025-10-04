#include "wg_interface.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

static int execute_command(const char *cmd) {
    log_message(LOG_DEBUG, "Executing: %s", cmd);

    int ret = system(cmd);
    if (ret != 0) {
        log_message(LOG_ERROR, "Command failed: %s (exit code: %d)", cmd, ret);
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

    char cmd[2048];
    char pubkey_b64[256];

    key_to_base64(peer->public_key, pubkey_b64, sizeof(pubkey_b64));

    snprintf(cmd, sizeof(cmd), "wg set %s peer %s allowed-ips %s",
             interface, pubkey_b64, peer->allowed_ips);

    if (strlen(peer->endpoint) > 0) {
        char endpoint_arg[512];
        snprintf(endpoint_arg, sizeof(endpoint_arg), " endpoint %s", peer->endpoint);
        strncat(cmd, endpoint_arg, sizeof(cmd) - strlen(cmd) - 1);
    }

    if (peer->persistent_keepalive > 0) {
        char keepalive_arg[64];
        snprintf(keepalive_arg, sizeof(keepalive_arg), " persistent-keepalive %u",
                 peer->persistent_keepalive);
        strncat(cmd, keepalive_arg, sizeof(cmd) - strlen(cmd) - 1);
    }

    log_message(LOG_INFO, "Adding peer to interface %s", interface);
    return execute_command(cmd);
}

int wg_set_interface_ip(const char *interface, const char *ip_addr, int prefix_len) {
    if (!interface || !ip_addr) {
        return -1;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s",
             ip_addr, prefix_len, interface);

    log_message(LOG_INFO, "Setting IP %s/%d on interface %s", ip_addr, prefix_len, interface);
    return execute_command(cmd);
}

int wg_interface_up(const char *interface) {
    if (!interface) {
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s up", interface);

    log_message(LOG_INFO, "Bringing up interface %s", interface);
    return execute_command(cmd);
}

int wg_set_private_key(const char *interface, const uint8_t *private_key) {
    if (!interface || !private_key) {
        return -1;
    }

    char privkey_b64[256];
    key_to_base64(private_key, privkey_b64, sizeof(privkey_b64));

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "echo '%s' | wg set %s private-key /dev/stdin",
             privkey_b64, interface);

    log_message(LOG_INFO, "Setting private key on interface %s", interface);
    return execute_command(cmd);
}

int wg_set_listen_port(const char *interface, uint16_t port) {
    if (!interface) {
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "wg set %s listen-port %u", interface, port);

    log_message(LOG_INFO, "Setting listen port %u on interface %s", port, interface);
    return execute_command(cmd);
}
