#ifndef DEMO_REQUEST_H
#define DEMO_REQUEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

const char *build_demo_request(const char *hostname, const char *path);
void print_escaped(const char *str);

void build_http_header(char* result, size_t sizeof_result,
        const char *hostname, const char *path);
bool build_http_body(char *result, size_t sizeof_result,
        const char *data, size_t chunk_size);

bool encode_http_chunk(char *result, size_t sizeof_result,
        const char *chunk);

#endif

