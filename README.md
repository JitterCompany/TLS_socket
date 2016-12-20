# TLS\_socket: Simple TLS socket API for embedded systems

This package is aimed at embedded systems. The goal is to have as few dependencies as possible, to make it easier to port to different platforms.
The low-level TLS is handled internally by mbedTLS.

NOTE: This library by default does not verify the expiration date on the server certificate. If you do want to enable this feature, add the compile-time definitions MBEDTLS_HAVE_TIME and MBEDTLS_HAVE_TIME_DATE.
These definitions allow mbedTLS to rely on the current time, see src/TLS\_cfg.h.

The reason for this is that not all platforms support a meaningfull implementation of gettimeofday(). An alternative to certificate expiration/revocation can be emulated by using a fixed CA certificate in the firmware that is rotated/updated, depending on the use case.


You should provide your own platform-specific TCP socket implementation (see TCP.h) and find a strong entropy source for the target platform (see entropy_sources.h).

As an example, a linux/unix compatible implementation is included (see TCP\_unix.c and entropy_sources_unix.c).

To run the tests (TLS_socket.test is basically a very simple demo program), create tests/build, cd to tests/build, cmake .. && make tests.
TLS_CA.h and server_settings.h are not in this repository. Use the .example.h files as an example for you own settings.

