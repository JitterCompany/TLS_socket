#include <stdint.h>
#include <stddef.h>

#include <TLS_socket/TCP.h>
#include "TCP_unix.h"

// DEBUG
#ifndef DEBUG_MINI_CHUNK_SIZE
    #define DEBUG_MINI_CHUNK_SIZE (256)
#endif
#ifndef DEBUG_MAX_CONTINUOUS_COUNT
    #define DEBUG_MAX_CONTINUOUS_COUNT (3)
#endif

void tcp_unix_init(TCP *ctx)
{
    mbedtls_net_init(&ctx->net_ctx);
    ctx->connected = false;
}

void tcp_unix_deinit(TCP *ctx)
{
    mbedtls_net_free(&ctx->net_ctx);
    ctx->connected = false;
}

int tcp_connect(TCP *ctx, const char *host, const char *port)
{
    int result =  mbedtls_net_connect(&ctx->net_ctx,
            host, port, MBEDTLS_NET_PROTO_TCP);
    if(result != 0) {
        return result;
    }
    result = mbedtls_net_set_nonblock(&ctx->net_ctx);
    if(result == 0) {
        ctx->connected = true;
    }
    return result;
}

int tcp_close(TCP *ctx)
{
    mbedtls_net_free(&ctx->net_ctx);
    ctx->connected = false;
    return 0;
}

bool tcp_is_closed(TCP *ctx)
{
    return !ctx->connected;
}

static int debug_write_count;
static int debug_read_count;

int tcp_write(TCP *ctx, const uint8_t *buffer, size_t sizeof_buffer)
{
    if(!ctx->connected) { 
        return TCP_RESULT_ERROR;
    }

    // DEBUG: simulate non blocking / slow network: max n bytes at a time
    if(sizeof_buffer > DEBUG_MINI_CHUNK_SIZE) {
        sizeof_buffer = DEBUG_MINI_CHUNK_SIZE;
    }
    debug_write_count++;
    if(debug_write_count >= DEBUG_MAX_CONTINUOUS_COUNT) {
        debug_write_count = 0;
        return TCP_RESULT_WANT_WRITE;
    }

    int result = mbedtls_net_send(&ctx->net_ctx, buffer, sizeof_buffer);
    if(result >= 0) {
        return result;
    }
    switch(result) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            return TCP_RESULT_WANT_READ;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            return TCP_RESULT_WANT_WRITE;
        default:
             return TCP_RESULT_ERROR;
    }
}

int tcp_read(TCP *ctx, uint8_t *buffer, size_t sizeof_buffer)
{
    if(!ctx->connected) { 
        return TCP_RESULT_ERROR;
    }

    // DEBUG: simulate non blocking / slow network: max n bytes at a time
    if(sizeof_buffer > DEBUG_MINI_CHUNK_SIZE) {
        sizeof_buffer = DEBUG_MINI_CHUNK_SIZE;
    }
    debug_read_count++;
    if(debug_read_count >= DEBUG_MAX_CONTINUOUS_COUNT) {
        debug_read_count = 0;
        return TCP_RESULT_WANT_READ;
    }

    int result = mbedtls_net_recv(&ctx->net_ctx, buffer, sizeof_buffer);

    if(result >= 0) {
        return result;
    }
    switch(result) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            return TCP_RESULT_WANT_READ;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            return TCP_RESULT_WANT_WRITE;
        default:
             return TCP_RESULT_ERROR;
    }
}


