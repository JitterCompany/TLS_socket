#include "TLS_socket.h"
#include "TCP.h"
#include "platform_entropy.h"
#include "dummy_exit.h"

#include <mbedtls/platform.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/net.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// fragment_length to negotiate with the server.
// Note: make sure the server supports this, and that
// MBEDTLS_SSL_MAX_CONTENT_LEN is long enough (see TLS_cfg.h)
#define TLS_FRAGMENT_LENGTH MBEDTLS_SSL_MAX_FRAG_LEN_1024

static inline int send_cb(void *ctx,
        const unsigned char *buffer, size_t sizeof_buffer)
{
    int result = tcp_write((TCP *)ctx, buffer, sizeof_buffer);
    if(result >= 0) {
        return result;
    }
    switch(result) {
        case TCP_RESULT_WANT_READ:
            return MBEDTLS_ERR_SSL_WANT_READ;
        case TCP_RESULT_WANT_WRITE:
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        case TCP_RESULT_ERROR:
        default:
            return MBEDTLS_ERR_NET_SEND_FAILED;
    }
}
static inline int recv_cb(void *ctx,
        unsigned char *buffer, size_t sizeof_buffer)
{
    int result = tcp_read((TCP *)ctx, buffer, sizeof_buffer);
    if(result >= 0) {
        return result;
    }
    switch(result) {
        case TCP_RESULT_WANT_READ:
            return MBEDTLS_ERR_SSL_WANT_READ;
        case TCP_RESULT_WANT_WRITE:
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        case TCP_RESULT_ERROR:
        default:
            return MBEDTLS_ERR_NET_RECV_FAILED;
    }
}

static bool finish_close(TLSSocket *ctx)
{
    ctx->state = TLS_SOCKET_STATE_CLOSING;

    // reset session: this allows a new connection with
    // TLS_socket_connect()
    // TODO: save ssl session ticket? may speed up next connections
    mbedtls_ssl_session_reset(&ctx->ssl);

    tcp_close(ctx->tcp);
    if(tcp_is_closed(ctx->tcp)) {
        ctx->state = TLS_SOCKET_STATE_CLOSED;
        return true;
    }
    return false;
}

static void set_error(TLSSocket *ctx, int error_code)
{
    ctx->last_error = error_code;

    finish_close(ctx);
}

static int entropy_cb(void *void_ctx,
        uint8_t *result, size_t sizeof_result,
        size_t *result_len)
{
    PlatformEntropy *ctx = (PlatformEntropy*)void_ctx;
    if(!platform_entropy_get(ctx, result, sizeof_result, result_len)) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    return 0;
}

void TLS_socket_init(TLSSocket *ctx, TCP *tcp, PlatformEntropy *entropy)
{
    memset(ctx, 0, sizeof(TLSSocket));
    ctx->tcp = tcp;
    ctx->platform_entropy = entropy;

    // NOTE: only one 'instance' of mbedtls_memory_buffer can exist
    mbedtls_memory_buffer_alloc_init(ctx->mbedtls_buffer,
            sizeof(ctx->mbedtls_buffer));

    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->cfg);
    mbedtls_x509_crt_init(&ctx->cacert);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

    mbedtls_entropy_init(&ctx->entropy_ctx);
    ctx->entropy_strength = platform_entropy_get_strength(
            ctx->platform_entropy);

    ctx->state = TLS_SOCKET_STATE_NONE;
}

void TLS_socket_deinit(TLSSocket *ctx)
{
    mbedtls_entropy_free(&ctx->entropy_ctx);

    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_x509_crt_free(&ctx->cacert);
    mbedtls_ssl_config_free(&ctx->cfg);
    mbedtls_ssl_free(&ctx->ssl);
    mbedtls_memory_buffer_alloc_free();
}

bool TLS_socket_configure(TLSSocket *ctx,
        const char *server_hostname,
        const uint8_t *ca_cert,     size_t sizeof_ca_cert,
        const uint8_t *unique_seed, size_t sizeof_unique_seed)
{
    // set dummy exit function: our platform does not support exit()
    if(0 != mbedtls_platform_set_exit(dummy_exit)) {
        return false;
    }

    // at least one source should be strong
    bool strong_source_found = (ctx->entropy_strength
                & (PLATFORM_ENTROPY_NV_SEED_STRONG
                    | PLATFORM_ENTROPY_FUNC_STRONG));
    if(!strong_source_found) {
        return false;
    }

    if(0 != mbedtls_platform_set_nv_seed(platform_entropy_read_nv_seed,
                platform_entropy_write_nv_seed)) {
        return false;
    }

    // configure entropy sources: getter function //
    int func_strength = (ctx->entropy_strength & PLATFORM_ENTROPY_FUNC_STRONG)
        ? MBEDTLS_ENTROPY_SOURCE_STRONG : MBEDTLS_ENTROPY_SOURCE_WEAK;
    if(0 != mbedtls_entropy_add_source(&ctx->entropy_ctx,
            entropy_cb, &ctx->platform_entropy,
            BYTES_REQUIRED_TO_SEED, func_strength)) {
        return false;
    }


    // seed random number generator //
    if(!unique_seed) {
        return false;
    }
    size_t unique_seed_len = strlen((const char*)unique_seed);
    if(unique_seed_len < TLS_SOCKET_MIN_UNIQUE_SEED_LEN) {
        return false;
    }
    if(0 != mbedtls_ctr_drbg_seed(&ctx->ctr_drbg,
            mbedtls_entropy_func,
            &ctx->entropy_ctx,
            (const uint8_t*)unique_seed,
            unique_seed_len)) {
        return false;
    }

    // parse ca cert // TODO: use DER format or even save ctx->cacert in ROM
    if(0 != mbedtls_x509_crt_parse(&ctx->cacert,
            ca_cert, sizeof_ca_cert)) {
        return false;
    }

    // set default config //
    if(0 != mbedtls_ssl_config_defaults(&ctx->cfg,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT)) {
        return false;
    }

    // set config //
    mbedtls_ssl_conf_authmode(&ctx->cfg, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ctx->cfg, &ctx->cacert, NULL);
    mbedtls_ssl_conf_rng(&ctx->cfg, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

    if(0 != mbedtls_ssl_conf_max_frag_len(&ctx->cfg,
                TLS_FRAGMENT_LENGTH)) {
        return false;
    }

    if(0 != mbedtls_ssl_setup(&ctx->ssl, &ctx->cfg)) {
        return false;
    }

    // set hostname: should match hostname on server cert //
    if(0 != mbedtls_ssl_set_hostname(&ctx->ssl, server_hostname)) {
        return false;
    }

    // set network callbacks
    mbedtls_ssl_set_bio(&ctx->ssl, ctx->tcp, send_cb, recv_cb, NULL);
    
    ctx->state = TLS_SOCKET_STATE_CLOSED;
    return true;
}

bool TLS_socket_connect(TLSSocket *ctx, const char *host, const char *port)
{
    if(ctx->state == TLS_SOCKET_STATE_CLOSING) {
        finish_close(ctx);
    }

    if(ctx->state != TLS_SOCKET_STATE_CLOSED) {

        set_error(ctx, -1);
        return false;
    }
    ctx->last_error = 0;

    int result = tcp_connect(ctx->tcp, host, port);
    if(result != 0) {
        set_error(ctx, result);
        return false;
    }

    ctx->state = TLS_SOCKET_STATE_CONNECTING;
    return true;
}

static bool handle_handshake(TLSSocket *ctx)
{
    int result = mbedtls_ssl_handshake(&ctx->ssl);
   
    // handshake done 
    if(result == 0) {
        uint32_t flags = mbedtls_ssl_get_verify_result(&ctx->ssl);
        if(flags == 0) {
            ctx->state = TLS_SOCKET_STATE_OPEN;
            return true;
        }
        set_error(ctx, flags);
        return false;
    }

    // handshake in progress
    if((result == MBEDTLS_ERR_SSL_WANT_READ)
            || (result == MBEDTLS_ERR_SSL_WANT_WRITE)) {
        return true;
    }

    // handshake failed
    set_error(ctx, result);
    return false;
}

bool TLS_socket_is_ready(TLSSocket *ctx)
{
    if(ctx->state == TLS_SOCKET_STATE_CLOSING) {
        finish_close(ctx);
    }

    if(ctx->last_error) {
        return false;
    }

    if(ctx->state == TLS_SOCKET_STATE_CONNECTING) {
        ctx->state = TLS_SOCKET_STATE_HANDSHAKING;
    }
    if(ctx->state == TLS_SOCKET_STATE_HANDSHAKING) {
        if(!handle_handshake(ctx)) {
            return false;
        }
    }
    return (ctx->state == TLS_SOCKET_STATE_OPEN);
}

enum TLSSocketResult TLS_socket_send(TLSSocket *ctx,
        const void *buffer, size_t sizeof_buffer, size_t *bytes_sent)
{
    *bytes_sent = 0;

    if(ctx->state != TLS_SOCKET_STATE_OPEN) {
        set_error(ctx, -1);
        return TLS_SOCKET_RESULT_ERROR;
    }

    int result;
    const uint8_t *src = (const uint8_t*)buffer;
    size_t len = sizeof_buffer;
    while(len) {
        result = mbedtls_ssl_write(&ctx->ssl, src, len);
        if(result < 0) {
            break;
        }

        if((size_t)result > len) {
            set_error(ctx, -1);
            return TLS_SOCKET_RESULT_ERROR;
        }
        src+= result;
        len-= result;
    }
    
    size_t sent = (sizeof_buffer - len);
    *bytes_sent = sent;

    if((result >= 0)
            || (result == MBEDTLS_ERR_SSL_WANT_WRITE)
            || (result == MBEDTLS_ERR_SSL_WANT_READ))
    {
        return sent ? TLS_SOCKET_RESULT_OK : TLS_SOCKET_RESULT_TRY_LATER;
    }

    set_error(ctx, result);
    return TLS_SOCKET_RESULT_ERROR;
}


enum TLSSocketResult TLS_socket_receive(TLSSocket *ctx,
        void *buffer, size_t sizeof_buffer, size_t *bytes_received)
{
    *bytes_received = 0;

    if(ctx->state != TLS_SOCKET_STATE_OPEN) {
        set_error(ctx, -1);
        return TLS_SOCKET_RESULT_ERROR;
    }

    int result;
    uint8_t *dst = (uint8_t*)buffer;
    size_t len = sizeof_buffer;

    while(len) {
        
        result = mbedtls_ssl_read(&ctx->ssl, dst, len);
        if(result <= 0) {
            break;
        }

        if((size_t)result > len) {
            set_error(ctx, -1);
            return TLS_SOCKET_RESULT_ERROR;
        }
        dst+= result;
        len-= result;
    }

    size_t received = (sizeof_buffer - len);
    *bytes_received = received;

    if((result >= 0)
            || (result == MBEDTLS_ERR_SSL_WANT_WRITE)
            || (result == MBEDTLS_ERR_SSL_WANT_READ))
    {
        return received ? TLS_SOCKET_RESULT_OK : TLS_SOCKET_RESULT_TRY_LATER;
    }

    set_error(ctx, result);
    return TLS_SOCKET_RESULT_ERROR;
}

bool TLS_socket_try_close(TLSSocket *ctx)
{
    if(ctx->state == TLS_SOCKET_STATE_NONE) {
        return false;
    }
    if(ctx->state == TLS_SOCKET_STATE_CLOSED) {
        return true;
    }

    ctx->state = TLS_SOCKET_STATE_CLOSING;

    int result = mbedtls_ssl_close_notify(&ctx->ssl);
    if((result == MBEDTLS_ERR_SSL_WANT_WRITE)
            || (result == MBEDTLS_ERR_SSL_WANT_READ))
    {
        return false;
    }
    // if an error occurs, there is not much we can do.
    // Assume socket closed.
    if(result < 0) {
        set_error(ctx, result);
    }

    return finish_close(ctx);
}

int TLS_socket_get_last_error(TLSSocket *ctx)
{
    return ctx->last_error;
}

bool TLS_socket_is_closed(TLSSocket *ctx)
{
    return (ctx->state == TLS_SOCKET_STATE_CLOSED);
}

