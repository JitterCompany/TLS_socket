#ifndef TLS_SOCKET_H
#define TLS_SOCKET_H

#include <stdbool.h>
#include <stdint.h>

#include "TCP.h"
#include "platform_entropy.h"
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#define TLS_SOCKET_MIN_UNIQUE_SEED_LEN (16)

enum TLSSocketResult {
    TLS_SOCKET_RESULT_OK            =  0,
    TLS_SOCKET_RESULT_TRY_LATER     = -1,
    TLS_SOCKET_RESULT_ERROR         = -2,
};

enum TLSSocketState {
    TLS_SOCKET_STATE_NONE           = 0,
    TLS_SOCKET_STATE_CLOSED         = 1,
    TLS_SOCKET_STATE_CONNECTING     = 2,
    TLS_SOCKET_STATE_HANDSHAKING    = 3,
    TLS_SOCKET_STATE_OPEN           = 4,
    TLS_SOCKET_STATE_CLOSING        = 5,
    TLS_SOCKET_STATE_FINISH_CLOSING = 6,
};

#define BYTES_REQUIRED_TO_SEED (1024)

typedef struct {
    TCP *tcp;
    PlatformEntropy *platform_entropy;
    enum PlatformEntropyStrength entropy_strength;
    enum TLSSocketState state;
    int last_error;

    mbedtls_ssl_context ssl;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config cfg;
    mbedtls_entropy_context entropy_ctx;

    uint8_t mbedtls_buffer[14550];        // 'heap' memory for mbedtls

} TLSSocket;


/**
 * Initialize a TLS socket struct
 *
 * NOTE: CURRENTLY, ONLY ONE INSTANCE IS SUPPORTED!
 * This is because we use the mbedtls_memory_buffer_alloc function
 * for simulating heap memory.
 * mbedtls_memory_buffer_alloc can only have one instance, which for now is
 * integrated into TLS_socket.c.
 * Also, platform_entropy only supports one instance, because the
 * nv_seed_read_func/nv_seed_write_func callbacks do not have a context
 * parameter.
 *
 * This function only initializes the socket state. After initializing, you
 * should also call TLS_socket_configure() before the socket can be used.
 *
 * @param ctx                   TLSSocket object to initialize:
 *                              this will hold all relevant state for this
 *                              socket.
 *
 * @param tcp                   pointer to an initialized TCP object.
 * 
 * @param entropy               pointer to an initialized PlatformEntropy
 *                              object.
 */
void TLS_socket_init(TLSSocket *ctx, TCP *tcp, PlatformEntropy *entropy);

/**
 * Configure a TLS socket
 *
 * If succesfully configured, the socket is ready to connect.
 *
 * @param ctx                   TLSSocket, initialized with TLS_socket_init()
 *
 * @param server_hostname       Hostname of the server to connect to.
 *                              Note: this should match the server certificate!
 *
 * @param ca_cert               CA certificate in PEM or DER format.
 *                              TODO: future versions may drop PEM support
 *                              to save code size.
 * @param sizeof_ca_cert        Size of ca_cert in bytes.
 *                              Note: for PEM, this is strlen(cert)+1, because
 *                              mbedtls expects the size including '\0'.
 *
 * @param unique_seed           Value to seed the random number generator.
 *                              This value should be as unique as possible.
 *                              For example: device-specific serial number or
 *                              public key. Each instance needs a unique value.
 *                              Note: this value does not need to be secret.
 * @param sizeof_unique_seed    Size of unique_seed in bytes.
 *
 * @return                      True on success, false otherwise.
 */
bool TLS_socket_configure(TLSSocket *ctx,
        const char *server_hostname,
        const uint8_t *ca_cert,     size_t sizeof_ca_cert,
        const uint8_t *unique_seed, size_t sizeof_unique_seed);


/**
 * Connect to a server
 *
 * If succesfully connected, the socket is ready to send/receive.
 *
 * @param ctx                   TLSSocket, initialized with TLS_socket_init()
 *
 * @param host                  Address of the server to connect to (Hostname
 *                              or IP address).
 * @param port                  Port of the server to connect to (e.g. "443")
 *
 * @return                      False if an error occurs.
 */
bool TLS_socket_connect(TLSSocket *ctx, const char *host, const char *port);

/**
 * Check if the socket is ready to send / receive data.
 *
 * After connecting (@see TLS_socket_connect), A TLS handshake takes place.
 * This function advances the TLS handshake where possible, untill the socket
 * is ready to use. It is recommended to check TLS_socket_get_last_error()
 * if the socket takes longer than normal to become ready.
 *
 * @param ctx       TLSSocket, initialized with TLS_socket_init()
 *
 * @return          False if the socket not ready to use. The socket may
 *                  (still) be busy with the TLS handshake, or an error
 *                  may have occurred (@see TLS_socket_get_last_error).
 */
bool TLS_socket_is_ready(TLSSocket *ctx);

/**
 * Check if the socket is closed.
 *
 * Use this function to know if the socket is closed, which means
 * a new connection can be created. If the socket is not closed, it may be
 * busy connecting, disconnecting, or actively sending/receiving data.
 *
 * @param ctx       TLSSocket, initialized with TLS_socket_init()
 *
 * @return          True if the socket is fully closed, False if the socket
 *                  is (still) in use.
 */
bool TLS_socket_is_closed(TLSSocket *ctx);

/**
 * Try to send data over the tls socket.
 *
 * The actual amount of data sent is returned via the 'bytes_sent' pointer.
 * This may be any value from 0 to 'sizeof_buffer'.
 *
 * @param ctx               TLSSocket, initialized with TLS_socket_init()
 *
 * @param buffer            buffer with data to send over the socket
 * @param sizeof_buffer     size of the buffer (bytes): amount of data to send
 *
 * @param bytes_sent        Return value: how many bytes have actually been
 *                          sent. May be any value from 0 to 'sizeof_buffer'.
 *
 * @return                  Result of trying to send the given data:
 *                          - TLS_SOCKET_RESULT_OK: some data was succesfully
 *                              sent. See 'bytes_sent' to determine how much
 *                              was actually sent.
 *
 *                          - TLS_SOCKET_RESULT_TRY_LATER: no data was sent.
 *                              In this case the network buffer is probably
 *                              full. Try again some time later.
 *
 *                          - TLS_SOCKET_RESULT_ERROR: something went wrong,
 *                              @see TLS_socket_get_last_error() for more info.
 */
enum TLSSocketResult TLS_socket_send(TLSSocket *ctx,
        const void *buffer, size_t sizeof_buffer, size_t *bytes_sent);

/**
 * Try to receive data from the tls socket.
 *
 * The actual amount of data received is returned via the 'bytes_received'
 * pointer. This may be any value from 0 to 'sizeof_buffer'.
 *
 * @param ctx               TLSSocket, initialized with TLS_socket_init()
 *
 * @param buffer            buffer to be filled with data from the socket
 * @param sizeof_buffer     size of the buffer (bytes): maximum amount of data
 *                          to receive.
 *
 * @param bytes_received    Return value: how many bytes have actually been
 *                          received. May be any value from 0 to
 *                          'sizeof_buffer'.
 *
 * @return                  Result of trying to send the given data:
 *                          - TLS_SOCKET_RESULT_OK: some data was succesfully
 *                              received. See 'bytes_received' to determine how 
 *                              much was actually received.
 *
 *                          - TLS_SOCKET_RESULT_TRY_LATER: no data was
 *                              received. In this case the network buffer is
 *                              probably empty. Try again some time later.
 *
 *                          - TLS_SOCKET_RESULT_ERROR: something went wrong,
 *                              @see TLS_socket_get_last_error() for more info.
 */
enum TLSSocketResult TLS_socket_receive(TLSSocket *ctx,
        void *buffer, size_t sizeof_buffer, size_t *bytes_received);

/**
 * Try to close the TLS socket
 *
 * This function tries to close the socket, but it may not immediately succeed.
 * Poll this function a few times untill it returns true.
 *
 * @param ctx       TLSSocket, initialized with TLS_socket_init()
 *
 * @return          False if the socket is still open
 */
bool TLS_socket_try_close(TLSSocket *ctx);

/**
 * Get the last error code that occurred (if any).
 *
 * @param ctx       TLSSocket, initialized with TLS_socket_init()
 *
 * @return          the last error that occurred, or 0 if no errors were set 
 */
int TLS_socket_get_last_error(TLSSocket *ctx);

/**
 * De-initialize a TLS socket struct
 *
 * This function de-initializes the socket state. Make sure the passed
 * TLSSocket was initialized before with TLS_socket_init().
 *
 * @param ctx       TLSSocket, initialized with TLS_socket_init()
 */
void TLS_socket_deinit(TLSSocket *ctx);

#endif

