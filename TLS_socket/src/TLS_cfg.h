#ifndef TLS_CFG_H
#define TLS_CFG_H

/**
 * Config for mbed tls
 * Note: after editing this file, a clean rebuild is recommended.
 */

// mbedtls: avoid implicit declaration errors for memcpy / memset
#include <string.h>

// override platform-specific dependencies such as libc/alloc
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_PLATFORM_EXIT_ALT

// no default entropy sources will work on the target platform:
// we have to roll our own seedfile-based entropy

// Don't disable all default sources: we do want to use MBEDTLS_ENTROPY_NV_SEED
//#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES

#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_NV_SEED
#define MBEDTLS_PLATFORM_NV_SEED_ALT



// System support
//#define MBEDTLS_HAVE_ASM

// TODO
// Disable time support for now
//#define MBEDTLS_HAVE_TIME

// TODO
// Disable date support for now. This disables checking if certificates
// are expired(!). This depends on gettimeofday().
//#define MBEDTLS_HAVE_TIME_DATE

// mbed_TLS features
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_SSL_PROTO_TLS1_2

// Enable the max_fragment_length SSL extension
// Note: without this the lengt passed to mbedtls_ssl_write is not checked
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

// test-only
#ifdef TEST
    // enable mbedtls TCP/IP API
    #define MBEDTLS_NET_C

    // enable mbedtls debug output
    #define MBEDTLS_DEBUG_C
#endif

// mbed_TLS modules
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SSL_CLI_C
// we dont use server APIs (but disabling seems to have no effect on RAM)
//#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C

// Certificate support
// TODO: if cert is embedded in DER format,
// PEM_PARSE_C and BASE64_C can be removed
#define MBEDTLS_BASE64_C
#define MBEDTLS_CERTS_C
#define MBEDTLS_PEM_PARSE_C

// Save RAM at the expense of ROM
#define MBEDTLS_AES_ROM_TABLES

// Save RAM: max 2048-bit RSA (/ 8 bits per byte)
#define MBEDTLS_MPI_MAX_SIZE    (2048/8)

// Save small amout of stack RAM: at the cost of performance:
// 1 is lowest performance/RAM, 6 highest performance/most RAM
#define MBEDTLS_MPI_WINDOW_SIZE 6

// we only define 2 entropy sources
#define MBEDTLS_ENTROPY_MAX_SOURCES 2

// TODO: check what size is enough (depends on cert chain / record size)
#define MBEDTLS_SSL_MAX_CONTENT_LEN   1024

// Ciphersuite list
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256


#include "mbedtls/check_config.h"

#endif

