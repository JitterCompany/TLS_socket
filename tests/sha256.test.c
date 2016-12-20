#include <stdio.h>
#include "unity.h"
#include <string.h>

#include <mbedtls/sha256.h>


void test_sha256(void)
{
    const uint8_t expected[32] = {
        0x31, 0x5f, 0x5b, 0xdb, 0x76, 0xd0, 0x78, 0xc4,
        0x3b, 0x8a, 0xc0, 0x06, 0x4e, 0x4a, 0x01, 0x64,
        0x61, 0x2b, 0x1f, 0xce, 0x77, 0xc8, 0x69, 0x34,
        0x5b, 0xfc, 0x94, 0xc7, 0x58, 0x94, 0xed, 0xd3
    };

    const char str[] = "Hello, world!";

    uint8_t digest[32];
    mbedtls_sha256((uint8_t*)str, strlen(str), digest, 0);
    
    TEST_ASSERT_EQUAL_MEMORY(expected, digest, sizeof(expected));
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_sha256);

    UNITY_END();

    return 0;
}

