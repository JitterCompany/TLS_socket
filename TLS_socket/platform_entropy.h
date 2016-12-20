#ifndef PLATFORM_ENTROPY_H
#define PLATFORM_ENTROPY_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

enum PlatformEntropyStrength {
    PLATFORM_ENTROPY_FUNC_STRONG        = (1 << 1),
    PLATFORM_ENTROPY_FUNC_WEAK          = 0,
    PLATFORM_ENTROPY_NV_SEED_STRONG     = (1 << 2),
    PLATFORM_ENTROPY_NV_SEED_NONE       = 0,
};

struct PlatformEntropyImplementation;
typedef struct PlatformEntropyImplementation PlatformEntropy;


/**
 * Note: This header does not declare a generic init/deinit function,
 * but an implementation-specific init/deinit may exist. The library user
 * is responsible for initializing the PlatformEntropy object
 * before passing it to TLS_socket_init() and deinitializing it
 * after calling TLS_socket_deinit()
 */

// return which sources are strong: at least one source should be strong
enum PlatformEntropyStrength platform_entropy_get_strength(
        PlatformEntropy *ctx);

/**
 * Entropy getter: called by the TLS library if it wants more entropy.
 *
 * Should return false on failure.
 */
bool platform_entropy_get(PlatformEntropy *ctx,
        uint8_t *result, size_t sizeof_result,
        size_t *result_len);

/**
 * Read a non-volatile seed: a unique and strongly random file that is kept
 * secret. Called by the TLS library when it needs entropy.
 */
int platform_entropy_read_nv_seed(uint8_t *buffer, size_t sizeof_buffer);

/**
 * Write a non-volatile seed: the unique and strongly random file is updated
 * with the latest pseudo-random state from the TLS library.
 * Called by the TLS library when the random file needs to be saved.
 */
int platform_entropy_write_nv_seed(uint8_t *buffer, size_t sizeof_buffer);

#endif

