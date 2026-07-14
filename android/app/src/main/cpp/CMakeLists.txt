cmake_minimum_required(VERSION 3.22.1)

project("vault_engine")

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# libsodium paths
set(LIBSODIUM_DIR ${CMAKE_SOURCE_DIR}/libsodium)
set(LIBSODIUM_INCLUDE_DIR ${LIBSODIUM_DIR}/include)
set(LIBSODIUM_LIB_DIR ${LIBSODIUM_DIR}/lib/${ANDROID_ABI})

# Include directories
include_directories(${LIBSODIUM_INCLUDE_DIR})

# Add libsodium as imported library
add_library(sodium STATIC IMPORTED)
set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION ${LIBSODIUM_LIB_DIR}/libsodium.a
)

# Vault engine source files
add_library(vault_engine SHARED
    vault_engine.c
    vault_crypto.c
    vault_container.c
    vault_index.c
    vault_streaming.c
    vault_jni.c
    vault_streaming_jni.c
)

# Link libraries
target_link_libraries(vault_engine
    -Wl,--whole-archive
    sodium
    -Wl,--no-whole-archive
    log
    android
)

# Compiler flags for security
target_compile_options(vault_engine PRIVATE
    -Wall
    -Wextra
    -Werror
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# SECURITY: Define NDEBUG for release builds to disable logging
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_definitions(vault_engine PRIVATE NDEBUG)
endif()

# Also check for Android release build
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    # Android Gradle plugin sets this for release builds
    target_compile_definitions(vault_engine PRIVATE $<$<CONFIG:Release>:NDEBUG>)
endif()
