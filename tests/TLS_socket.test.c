#include <stdio.h>
#include "unity.h"
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "TLS_socket.h"

// test: unix implementations of TCP and entropy_sources
#include "platform_unix/TCP_unix.h"
#include "platform_unix/platform_entropy_unix.h"

// server-specific settings (see server_settings.example.h)
#include "server_settings.h"

// server CA as array (PEM or DER format)
#include "TLS_CA.h"

// build a demo HTTP request
#include "demo_request.h"

const char *g_unique_seed = "unique-device-id-123";

// HTTP path
// (equivalent to what would appear in a browsers URL-bar after the hostname)
const char *g_api_path = "/sensor-api/v2/test2";

static bool do_test_api_call(TLSSocket *socket,
        const char *host, const char *http_path)
{
    const char *request_data = build_demo_request(host, http_path);
    size_t request_len = strlen(request_data);

    size_t written = 0;
    while(request_len) {
       
        size_t bytes_sent = 0; 
        enum TLSSocketResult result = TLS_socket_send(socket,
                (const uint8_t*)request_data + written,
                request_len,
                &bytes_sent);
        
        if(result == TLS_SOCKET_RESULT_ERROR) {
            TEST_FAIL();
            return false;
        }

        written+= bytes_sent;
        if(((size_t)bytes_sent) <= request_len) {
            request_len-= bytes_sent;
        } else {
            request_len = 0;
        }
    }
    
    printf("test_request: %d bytes written\n\n", written);

    char response_buffer[1024*1];
    size_t response_buff_len  = (sizeof(response_buffer) - 1);
   
    size_t nothing_ctr = 0;
    while(true) {
        memset(response_buffer, 0, sizeof(response_buffer));

        size_t bytes_received = 0; 
        enum TLSSocketResult result = TLS_socket_receive(socket,
                (uint8_t*)response_buffer,
                response_buff_len,
                &bytes_received);

        if(result == TLS_SOCKET_RESULT_ERROR) {
            TEST_FAIL();
            return false;
        }

        if((result == TLS_SOCKET_RESULT_OK) && !bytes_received) {
            printf("\n\nEOF\n\n");
            break;
        }

        printf("tls_request: %d bytes received\n\n", bytes_received);
        printf("tls_request: response '%s' found\n\n", response_buffer);

        // NOTE: this is a quick hack to close the socket as soon as
        // some reply data is received, but the response may consist of multiple
        // packets...
        //
        // NOTE: this closes the socket too fast!
        if(bytes_received > 0) {
            break;

            nothing_ctr++;
            if(nothing_ctr > 10) {
                break;
            }
        }
    }
    
    return true;
}

void test_TLS_socket(void)
{

    TCP tcp;
    PlatformEntropy entropy;
    TLSSocket socket;
    printf("TLS SOCKET SIZE: %u\n", (unsigned int)sizeof(socket));

    tcp_unix_init(&tcp);
    platform_entropy_unix_init(&entropy);
    TLS_socket_init(&socket, &tcp, &entropy);
    TEST_ASSERT_TRUE(TLS_socket_configure(&socket,
                SERVER_HOST,
                (const uint8_t*)TLS_CA, sizeof(TLS_CA), // NOTE: tls_ca should
                                                        // be an array
                (const uint8_t*)g_unique_seed, strlen(g_unique_seed)));

    // connect
    TEST_ASSERT_TRUE(TLS_socket_connect(&socket, SERVER_ADDR, SERVER_PORT));
    while(!TLS_socket_is_ready(&socket));
    TEST_ASSERT_EQUAL(0, TLS_socket_get_last_error(&socket));
    TEST_ASSERT_EQUAL(TLS_SOCKET_STATE_OPEN, socket.state);

    // api call
    TEST_ASSERT_TRUE(do_test_api_call(&socket, SERVER_HOST, g_api_path));
    TEST_ASSERT_EQUAL(0, TLS_socket_get_last_error(&socket));
    TEST_ASSERT_EQUAL(TLS_SOCKET_STATE_OPEN, socket.state);

    // close
    while(!TLS_socket_try_close(&socket)) {
        TEST_ASSERT_EQUAL(TLS_SOCKET_STATE_CLOSING, socket.state);
    }
    TEST_ASSERT_EQUAL(0, TLS_socket_get_last_error(&socket));
    TEST_ASSERT_EQUAL(TLS_SOCKET_STATE_CLOSED, socket.state);

    // Lets try a second time //

    // connect
    TEST_ASSERT_TRUE(TLS_socket_connect(&socket, SERVER_ADDR, SERVER_PORT));
    while(!TLS_socket_is_ready(&socket));
    TEST_ASSERT_EQUAL(0, TLS_socket_get_last_error(&socket));
    TEST_ASSERT_EQUAL(TLS_SOCKET_STATE_OPEN, socket.state);

    // api call
    TEST_ASSERT_TRUE(do_test_api_call(&socket, SERVER_HOST, g_api_path));
    TEST_ASSERT_EQUAL(0, TLS_socket_get_last_error(&socket));
    TEST_ASSERT_EQUAL(TLS_SOCKET_STATE_OPEN, socket.state);

    // close
    while(!TLS_socket_try_close(&socket)) {
        TEST_ASSERT_EQUAL(TLS_SOCKET_STATE_CLOSING, socket.state);
    }
    TEST_ASSERT_EQUAL(0, TLS_socket_get_last_error(&socket));
    TEST_ASSERT_EQUAL(TLS_SOCKET_STATE_CLOSED, socket.state);


    TLS_socket_deinit(&socket);
    platform_entropy_unix_deinit(&entropy);
    tcp_unix_deinit(&tcp);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_TLS_socket);

    UNITY_END();

    return 0;
}

