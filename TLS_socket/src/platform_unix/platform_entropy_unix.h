#ifndef PLATFORM_ENTROPY_UNIX_H
#define PLATFORM_ENTROPY_UNIX_H

/**
 * See entropy_sources.h for the public API.
 * This is the unix implementation: a thin wrapper around mbedtls_net_*
 * To port entropy_sources.h to another platform,
 * create a new header defining a custom PlatformEntropyImplementation struct
 * and provide a c file implementing the functions in entropy_sources.h
 */
struct PlatformEntropyImplementation {
    bool initialized;
};

void platform_entropy_unix_init(PlatformEntropy *ctx);
void platform_entropy_unix_deinit(PlatformEntropy *ctx);

#endif

