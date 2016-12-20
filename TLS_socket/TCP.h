#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct TCPImplementation;
typedef struct TCPImplementation TCP;

enum TCPResult {
    TCP_RESULT_ERROR        = -1,
    TCP_RESULT_WANT_READ    = -0x6900,
    TCP_RESULT_WANT_WRITE   = -0x6880
};

/**
 * Note: This header does not declare a generic init/deinit function,
 * but an implementation-specific init/deinit may exist. The library user
 * is responsible for initializing the TCP object before passing it to
 * TLS_socket_init() and deinitializing it after calling TLS_socket_deinit()
 */
int tcp_connect(TCP *ctx, const char *host, const char *port);
int tcp_write(TCP *ctx, const uint8_t *buffer, size_t sizeof_buffer);
int tcp_read(TCP *ctx, uint8_t *buffer, size_t sizeof_buffer);
int tcp_close(TCP *ctx);
bool tcp_is_closed(TCP *ctx);


#endif

