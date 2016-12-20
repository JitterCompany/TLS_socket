cmake_minimum_required(VERSION 3.5.0 FATAL_ERROR)

project(tests)

set(PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR}/..)

include(${PROJECT_SOURCE_DIR}/cmake/CPM_setup.cmake)

#------------------------------------------------------------------------------
# Build Settings
#------------------------------------------------------------------------------

# optimize level
set(OPT 0)

# system libraries to link, separated by ';'
set(SYSTEM_LIBRARIES m c gcc)

# linux needs libbsd
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    message(STATUS "Linux detected: linking to libbsd")
    list(APPEND SYSTEM_LIBRARIES bsd)
endif()

# compile flags
set(C_FLAGS_WARN "-Wall -Wextra -Wno-unused-parameter                   \
    -Wshadow -Wpointer-arith -Winit-self -Wstrict-overflow=5")

set(C_FLAGS "${C_FLAGS_WARN} -O${OPT} -g3 -c -fmessage-length=80        \
    -fno-builtin -ffunction-sections -fdata-sections -std=gnu99")

# linker flags
set(L_FLAGS "-fmessage-length=80 -Wl,--gc-sections")


add_definitions("${C_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${L_FLAGS}")
set(CPM_LIBRARIES "${SYSTEM_LIBRARIES}${CPM_LIBRARIES}")


# dir where the normal project sources can be found
set(TEST_NORMAL_SOURCE_DIR   "${PROJECT_SOURCE_DIR}/TLS_socket/src")

# dir where the test-related sources can be found
set(TEST_TESTS_SOURCE_DIR    "${CMAKE_CURRENT_SOURCE_DIR}")

# set specific sources: for each test <testname>,
# the sources specified by test_<testname>_src are linked in.
# Note: these are relative to TEST_NORMAL_SOURCE_DIR.

#set(test_<testname>_src              <dep1.c> <dep2.c> <depn.c>)
set(test_TLS_src
    dummy_exit.c
    platform_unix/TCP_unix.c
    platform_unix/platform_entropy_unix.c
)

set(test_TLS_socket_src
    TLS_socket.c
    dummy_exit.c
    platform_unix/TCP_unix.c
    platform_unix/platform_entropy_unix.c
)


# all 'shared' c files: these are linked against every test.
# files that also occur in TEST_MAIN_SOURCES are automatically removed
file(GLOB TEST_SHARED_SOURCES
    RELATIVE ${TEST_TESTS_SOURCE_DIR}
    "*.c"
)

# all test 'main' files: each of these should have its own main() function.
# they are compiled and run when calling 'make tests'
file(GLOB TEST_MAIN_SOURCES
    RELATIVE ${TEST_TESTS_SOURCE_DIR}
    "*.test.c"
)

include_directories("${TEST_TESTS_SOURCE_DIR}/mocks")
include_directories("${TEST_NORMAL_SOURCE_DIR}/..")

# mbed_tls: use our own src/tls_cfg.h instead of the default
set(TLS_CFG_INCLUDE "<${TEST_NORMAL_SOURCE_DIR}/TLS_cfg.h>")
add_definitions("-DMBEDTLS_CONFIG_FILE=${TLS_CFG_INCLUDE}")


CPM_AddModule("cpm_unity"
    GIT_REPOSITORY "https://github.com/JitterCompany/cpm_unity.git"
    GIT_TAG "2.3.2-9")


CPM_Finish()

