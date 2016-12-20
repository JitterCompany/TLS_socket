#include "platform_entropy.h"
#include "platform_entropy_unix.h"

#include <stdbool.h>
#include <stdint.h>
#include <memory.h>
#include <stdio.h>

/**
 * Get strong entropy from /dev/urandom
 *
 * @return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on error, 0 otherwise
 */

bool platform_entropy_get(PlatformEntropy *ctx,
        uint8_t *result, size_t sizeof_result,
        size_t *result_len)
{
    *result_len = 0;

    FILE *fp = fopen("/dev/urandom", "r");
    if(!fp) {
        return false;
    }
    *result_len = fread(result, 1, sizeof_result, fp);

    printf("random: 0X");
    for(size_t i=0;i<sizeof_result;i++) {
        printf("%02X", result[i]);
    }
    printf("\n");
    fclose(fp);

    return true;
}


enum PlatformEntropyStrength platform_entropy_get_strength(
        PlatformEntropy *ctx)
{
    // this implementation offers a getter function with good entropy
    // (@see platform_entropy_get()), but no strong non-volatile seed file
    return (PLATFORM_ENTROPY_FUNC_STRONG
            | PLATFORM_ENTROPY_NV_SEED_NONE);
}

void platform_entropy_unix_init(PlatformEntropy *ctx)
{
    ctx->initialized = true;
}

void platform_entropy_unix_deinit(PlatformEntropy *ctx)
{
    ctx->initialized = false;
}

// No seed file implemented: should not be called
int platform_entropy_read_nv_seed(uint8_t *buffer, size_t sizeof_buffer)
{
    ((void)buffer);
    ((void)sizeof_buffer);

    return -1;
}
int platform_entropy_write_nv_seed(uint8_t *buffer, size_t sizeof_buffer)
{
    ((void)buffer);
    ((void)sizeof_buffer);

    return 0; // nothing to write
}

