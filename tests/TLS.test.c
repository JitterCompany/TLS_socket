#include <stdio.h>
#include "unity.h"
#include <string.h>
#include <stdbool.h>

#include <mbedtls/platform.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/debug.h>

#include "demo_request.h"
#include "TLS_CA.h"
#include "server_settings.h"
#include "TLS_cfg.h"

#include "TCP.h"
#include "platform_entropy.h"

// test: unix implementations of TCP and entropy_sources
#include "platform_unix/TCP_unix.h"
#include "platform_unix/platform_entropy_unix.h"


TCP tcp_ctx;
PlatformEntropy platform_entropy;

mbedtls_ssl_context ssl;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt cacert;
mbedtls_ssl_config cfg;
mbedtls_entropy_context entropy_ctx;

// extra seed: not sure if this really adds any value.
// maybe use device-id or something for this value?
const char *g_seed = "tls_test";

// HTTP path
// (equivalent to what would appear in a browsers URL-bar after the hostname)
const char *g_api_path = "/sensor-api/v2/test1";


static bool last_index_of(const char *str, const char match, size_t *result)
{
    bool success = false;
    size_t offset = 0;
    while(*str) {
        if(*str == match) {
            success = true;
            *result = offset;
        }
             
        str++;
        offset++;
    }
    return success;
}

static void _debug_cb(void *ctx, int level,
        const char *file, int line, const char *str)
{
    ((void) ctx);
    ((void) level);

    size_t offset = 0;
    last_index_of(file, '/', &offset); // strip path prefix
    printf("%s:%04d: %s", file+offset, line, str);
}

#define BYTES_REQUIRED_TO_SEED (1024)

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

// malloc buffer for mbedtls
static uint8_t tls_buffer[1024*120];

void tls_init(void)
{
    mbedtls_memory_buffer_alloc_init(tls_buffer, sizeof(tls_buffer));

    tcp_unix_init(&tcp_ctx);

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&cfg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_init(&entropy_ctx);
    platform_entropy_unix_init(&platform_entropy);
}

void tls_destroy(void)
{
    tcp_unix_deinit(&tcp_ctx);

    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&cfg);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    platform_entropy_unix_deinit(&platform_entropy);
    mbedtls_entropy_free(&entropy_ctx);
}

bool tls_setup(const char *extra_seed)
{
    enum PlatformEntropyStrength entropy_strength;
    entropy_strength = platform_entropy_get_strength(&platform_entropy);

    // at least one source should be strong
    bool strong_source_found = (entropy_strength
                & (PLATFORM_ENTROPY_NV_SEED_STRONG
                    | PLATFORM_ENTROPY_FUNC_STRONG));
    if(!strong_source_found) {
        return false;
    }

    if(0 != mbedtls_platform_set_nv_seed(platform_entropy_read_nv_seed,
                platform_entropy_write_nv_seed)) {
        return false;
    }
    
    int func_strength = (entropy_strength & PLATFORM_ENTROPY_FUNC_STRONG)
        ? MBEDTLS_ENTROPY_SOURCE_STRONG : MBEDTLS_ENTROPY_SOURCE_WEAK;
    if(0 != mbedtls_entropy_add_source(&entropy_ctx,
            entropy_cb, &platform_entropy,
            BYTES_REQUIRED_TO_SEED, func_strength)) {

        TEST_FAIL_MESSAGE("tls_setup: failed to register entropy sources!");
        return false;
    }

    size_t extra_seed_len = 0;
    if(extra_seed) {
        extra_seed_len = strlen(extra_seed);
    }
    int seed_result = mbedtls_ctr_drbg_seed(&ctr_drbg,
            mbedtls_entropy_func,
            &entropy_ctx,
            (const uint8_t*)extra_seed,
            extra_seed_len);
             
    TEST_ASSERT_EQUAL_MESSAGE(0, seed_result, "tls_setup: failed to seed rng!");
    if(seed_result != 0) {
        return false;
    }

    return true;
}

bool tls_load_ca(const uint8_t *ca, size_t sizeof_ca)
{
    int result = mbedtls_x509_crt_parse(&cacert,
            ca, sizeof_ca);
    
    return (result == 0);
}

bool tls_connect(const char *host, const char *port)
{
    int result = tcp_connect(&tcp_ctx, host, port);

    char err_str[128];
    snprintf(err_str, sizeof(err_str), "tls_connect failed: %d", result);
    TEST_ASSERT_EQUAL_MESSAGE(0, result, err_str);

    return (result == 0);
}

static inline int send_cb(void *ctx,
        const unsigned char *buffer, size_t sizeof_buffer)
{
    return tcp_write((TCP *)ctx, buffer, sizeof_buffer);
}
static inline int recv_cb(void *ctx,
        unsigned char *buffer, size_t sizeof_buffer)
{
    return tcp_read((TCP *)ctx, buffer, sizeof_buffer);
}

bool tls_config(const char *server_hostname)
{
    char err_str[128];

    // default config //
    int cfg_default_result = mbedtls_ssl_config_defaults(&cfg,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT);
    snprintf(err_str, sizeof(err_str),
            "tls_config failed to set default cfg: %d",
            cfg_default_result);
    TEST_ASSERT_EQUAL_MESSAGE(0, cfg_default_result, err_str);

    // config //
    mbedtls_ssl_conf_authmode(&cfg, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&cfg, &cacert, NULL);
    mbedtls_ssl_conf_rng(&cfg, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&cfg, _debug_cb, NULL);

    int cfg_result = mbedtls_ssl_setup(&ssl, &cfg);
    snprintf(err_str, sizeof(err_str), "tls_config failed to set cfg: %d",
            cfg_result);
    TEST_ASSERT_EQUAL_MESSAGE(0, cfg_result, err_str);

    // hostname: should match hostname on server cert //
    int hostname_result = mbedtls_ssl_set_hostname(&ssl, server_hostname);
    snprintf(err_str, sizeof(err_str), "tls_config failed to set hostname: %d",
            hostname_result);
    TEST_ASSERT_EQUAL_MESSAGE(0, hostname_result, err_str);

    mbedtls_ssl_set_bio(&ssl, &tcp_ctx,
            send_cb, recv_cb, NULL);

    return ((cfg_default_result == 0)
            && (cfg_result == 0)
            && (hostname_result == 0));
}

bool tls_handshake(void)
{
    int result;
    while((result = mbedtls_ssl_handshake(&ssl)) != 0) {

        if((result != MBEDTLS_ERR_SSL_WANT_READ)
                && (result != MBEDTLS_ERR_SSL_WANT_WRITE)) {

            // should not happen: assert always fails
            TEST_ASSERT_EQUAL(0, result);
            return false;
        }
    }
    return true;
}

bool tls_verify(void)
{
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if(flags == 0) {
        return true;
    }
    return false;
}


bool tls_request(const char *host, const char *http_path)
{
    const char *request_data = build_demo_request(host, http_path);
    size_t request_len = strlen(request_data);

    int result = 0;
    size_t written = 0;
    while(request_len) {

        while((result = mbedtls_ssl_write(&ssl,
                        (const uint8_t*)request_data + written,
                        request_len)) <= 0) {
            if((result != MBEDTLS_ERR_SSL_WANT_READ)
                    && (result != MBEDTLS_ERR_SSL_WANT_WRITE)) {

                return false;
            }
        }
        written+= result;
        if(((size_t)result) <= request_len) {
            request_len-= result;
        } else {
            request_len = 0;
        }
    }
    
    printf("tls_request: %d bytes written\n\n", result);

    char response_buffer[1024*1];
    size_t response_buff_len  = (sizeof(response_buffer) - 1);

    while(true) {
        memset(response_buffer, 0, sizeof(response_buffer));
    
        printf("calling mbedtls_ssl_read()...\n");
        result = mbedtls_ssl_read(&ssl, (uint8_t*)response_buffer, 
                response_buff_len);
        printf("DONE! result: %d\n", result);
        
        if((result == MBEDTLS_ERR_SSL_WANT_READ)
                || (result == MBEDTLS_ERR_SSL_WANT_WRITE)) {
            continue;
        }

        if(result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            printf("\n\nCLOSED by peer\n\n");
            break;
        }
        if(result < 0) {
            char err_str[1024];
            snprintf(err_str, sizeof(err_str),
                    "tls_request failed to read: error %d", result);
            TEST_ASSERT_EQUAL_MESSAGE(0, result, err_str);
            break;
        }
        if(result == 0) {
            printf("\n\nEOF\n\n");
            break;
        }

        printf("tls_request: %d bytes read\n\n", result);

        // NOTE: this is a quick hack to close the socket as soon as
        // some reply data is received, but the response may consist of multiple
        // packets...
        //
        // NOTE: this closes the socket too fast!
        if(result > 0) {
            break;
        }
    } 
    while(true) {
        int close_result = mbedtls_ssl_close_notify(&ssl);

        if((close_result != MBEDTLS_ERR_SSL_WANT_WRITE)) {
            break;
        }
    }

    return true;
}

void test_tls(void)
{
    tls_init();
#ifdef MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(2);
#endif

    TEST_ASSERT_TRUE(tls_setup(g_seed));
    // NOTE: TLS_CA should be an array for sizeof() to work correctly
    TEST_ASSERT_TRUE(tls_load_ca((const uint8_t*)TLS_CA, sizeof(TLS_CA)));
    TEST_ASSERT_TRUE(tls_config(SERVER_HOST));
    TEST_ASSERT_TRUE(tls_connect(SERVER_ADDR, SERVER_PORT));
    TEST_ASSERT_TRUE(tls_handshake());
    TEST_ASSERT_TRUE(tls_verify());
    
    TEST_ASSERT_TRUE(tls_request(SERVER_HOST, g_api_path));
    tls_destroy();
}


int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_tls);

    UNITY_END();

    return 0;
}

