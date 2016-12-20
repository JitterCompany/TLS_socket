#include "demo_request.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#if defined(TEST) && defined(__linux__)
    #include <bsd/string.h>
#endif


// request string is built up in this buffer
char g_request_buffer[1024*1024];

void build_http_header(char* result, size_t sizeof_result,
        const char *hostname, const char *path)
{
    snprintf(result, sizeof_result,
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "\r\n",
            path, hostname);
}

bool encode_http_chunk(char *result, size_t sizeof_result,
        const char *chunk)
{
    char str[1024];
    snprintf(str, sizeof(str),
            "%04X\r\n",
            (unsigned int)strlen(chunk));

    strlcat(result, str, sizeof_result);
    strlcat(result, chunk, sizeof_result);
    size_t final_len = strlcat(result, "\r\n", sizeof_result);

    return (final_len < sizeof_result);
}

bool build_http_body(char *result, size_t sizeof_result,
        const char *data, size_t chunk_size)
{
    size_t data_len = strlen(data);
    size_t offset = 0;

    while(offset < data_len) {
        char chunk[chunk_size+1];
        strncpy(chunk, (data + offset), chunk_size);
        chunk[chunk_size] = '\0';

        if(!encode_http_chunk(result, sizeof_result, chunk)) {
            return false;
        }
        offset+= chunk_size;
    }
    encode_http_chunk(result, sizeof_result, "");
    return true;
}

void print_escaped(const char *str)
{
    while(*str) {
        const unsigned char ch = (const unsigned char)*str;

        if(ch == '\n') {
            printf("\\n\n");
        } else if(ch == '\r') {
            printf("\\r");
        } else if(ch == '\t') {
            printf("\\t");
        } else if((ch < 0x20) || (ch > 0x7F)) {
            printf("\\%03o", ch);
        } else {
            printf("%c", ch);
        }
        str++;
    }
}

const char *build_demo_request(const char *hostname, const char *path)
{
    size_t chunk_size = 0x1FF;
    char data[1024*4];

    // build a blob of dummy data
    strlcpy(data, "test=", sizeof(data));
    int ctr = 0;
    while(1) {
        char str[1024];
        snprintf(str, sizeof(str), "%d,", ctr);
        if(strlcat(data, str, sizeof(data)) >= sizeof(data)) {
            break;
        }
        ctr++;
    }
    
    build_http_header(g_request_buffer, sizeof(g_request_buffer),
            hostname, path);
    build_http_body(g_request_buffer, sizeof(g_request_buffer),
            data, chunk_size);
    printf("#### BEGIN REQUEST ####\n");
    print_escaped(g_request_buffer);
    printf("#### END REQUEST ####\n");

    return g_request_buffer;
}

