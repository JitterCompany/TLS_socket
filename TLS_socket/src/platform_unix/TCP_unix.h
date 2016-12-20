#ifndef TCP_UNIX_H
#define TCP_UNIX_H

#include <mbedtls/net.h>
#include <stdbool.h>

/**
 * See TCP.h for the public API.
 * This is the unix implementation: a thin wrapper around mbedtls_net_*
 * To port TCP.h to another platform, create a new header defining a custom
 * TCPImplementation struct and provide a c file implementing the functions
 * in TCP.h
 */
struct TCPImplementation {
    mbedtls_net_context net_ctx;
    bool connected;
};

void tcp_unix_init(TCP *ctx);
void tcp_unix_deinit(TCP *ctx);

#endif

