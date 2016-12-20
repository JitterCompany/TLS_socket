cmake_minimum_required(VERSION 3.5.0 FATAL_ERROR)


set(CPM_MODULE_NAME TLS_socket)

#-----------------------------------------------------------------------
# Required CPM Setup - no need to modify - See: https://github.com/iauns/cpm
#-----------------------------------------------------------------------
set(CPM_LIB_TARGET_NAME ${CPM_MODULE_NAME})

if ((DEFINED CPM_DIR) AND (DEFINED CPM_UNIQUE_ID) AND (DEFINED CPM_TARGET_NAME))
    set(CPM_LIB_TARGET_NAME ${CPM_TARGET_NAME})
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CPM_DIR})
    include(CPM)
else()
    set (CPM_DIR "${CMAKE_CURRENT_BINARY_DIR}/cpm-packages" CACHE TYPE STRING)
    find_package(Git)
    if(NOT GIT_FOUND)
        message(FATAL_ERROR "CPM requires Git.")
    endif()
    if (NOT EXISTS ${CPM_DIR}/CPM.cmake)
        message(STATUS "Cloning repo (https://github.com/iauns/cpm)")
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" clone https://github.com/iauns/cpm ${CPM_DIR}
            RESULT_VARIABLE error_code
            OUTPUT_QUIET ERROR_QUIET)
        if(error_code)
            message(FATAL_ERROR "CPM failed to get the hash for HEAD")
        endif()
    endif()
    include(${CPM_DIR}/CPM.cmake)
endif()

#------------------------------------------------------------------------------
# Dependencies
#------------------------------------------------------------------------------

# mbed_tls: use our own src/TLS_cfg.h instead of the default
set(TLS_CFG_INCLUDE "<${CMAKE_CURRENT_SOURCE_DIR}/TLS_socket/src/TLS_cfg.h>")
add_definitions("-DMBEDTLS_CONFIG_FILE=${TLS_CFG_INCLUDE}")

CPM_AddModule("cpm_mbedtls"
    GIT_REPOSITORY "https://github.com/JitterCompany/cpm_mbedtls.git"
    GIT_TAG "master")

CPM_InitModule(${CPM_MODULE_NAME})

#------------------------------------------------------------------------------
# Project sources / settings
#------------------------------------------------------------------------------

file(GLOB SOURCES
    ${CPM_MODULE_NAME}/src/*.c
    )

#TODO src? why?
include_directories("${CPM_MODULE_NAME}" 
                    "${CPM_MODULE_NAME}/src")

add_library(${CPM_LIB_TARGET_NAME} ${SOURCES})
target_link_libraries(${CPM_LIB_TARGET_NAME} ${CPM_LIBRARIES})
target_link_libraries(${CPM_LIB_TARGET_NAME} m c gcc)

