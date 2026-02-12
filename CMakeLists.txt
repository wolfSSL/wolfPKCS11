# CMakeLists.txt
#
# Copyright (C) 2006-2024 wolfSSL Inc.
#
# This file is part of wolfPKCS11.
#
# Usage:
# $ mkdir build
# $ cd build
# $ cmake ..
# $ cmake --build .
#
# To build with debugging use:
# $ cmake .. -DCMAKE_BUILD_TYPE=Debug

####################################################
# Project
####################################################

cmake_minimum_required(VERSION 3.16)

if(${CMAKE_VERSION} VERSION_LESS "3.22")
    message(STATUS "This project recommends using CMake version 3.22 or higher. You are using ${CMAKE_VERSION}.")
else()
    cmake_policy(SET CMP0128 NEW)
endif()

if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed.\
     Run cmake from a separate directory from where CMakeLists.txt lives.\
     NOTE: cmake will now create CMakeCache.txt and CMakeFiles/*.\
     You must delete them, or cmake will refuse to work.")
endif()

project(wolfpkcs11 VERSION 2.0.0 LANGUAGES C)

# shared library versioning
# increment if interfaces have been removed or changed
set(WOLFPKCS11_LIBRARY_VERSION_FIRST 4)

# increment if interfaces have been added
# set to zero if WOLFPKCS11_LIBRARY_VERSION_FIRST is incremented
set(WOLFPKCS11_LIBRARY_VERSION_SECOND 0)

# increment if source code has changed
# set to zero if WOLFPKCS11_LIBRARY_VERSION_FIRST is incremented or
# WOLFPKCS11_LIBRARY_VERSION_SECOND is incremented
set(WOLFPKCS11_LIBRARY_VERSION_THIRD 0)

set(LIBTOOL_FULL_VERSION ${WOLFPKCS11_LIBRARY_VERSION_FIRST}.${WOLFPKCS11_LIBRARY_VERSION_SECOND}.${WOLFPKCS11_LIBRARY_VERSION_THIRD})

set(WOLFPKCS11_DEFINITIONS)
set(WOLFPKCS11_LINK_LIBS)
set(WOLFPKCS11_INCLUDE_DIRS)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/")
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/functions.cmake)

####################################################
# Compiler
####################################################
# Let CMake choose default compiler

if(CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    # Silence ranlib warning "has no symbols"
    set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
    set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()

include(CheckFunctionExists)

# TODO: Also check if these functions are declared by the
#       expected headers. See comments around
#       AC_CHECK_FUNCS/AC_CHECK_DECLS in configure.ac.
check_function_exists("gethostbyname" HAVE_GETHOSTBYNAME)
check_function_exists("getaddrinfo" HAVE_GETADDRINFO)
check_function_exists("gettimeofday" HAVE_GETTIMEOFDAY)
check_function_exists("inet_ntoa" HAVE_INET_NTOA)
check_function_exists("memset" HAVE_MEMSET)
check_function_exists("socket" HAVE_SOCKET)

include(CheckTypeSize)

check_type_size("long long" SIZEOF_LONG_LONG)
check_type_size("long" SIZEOF_LONG)


if(CMAKE_VERSION VERSION_LESS "3.20")
    # TestBigEndian was deprecated in 3.20
    include(TestBigEndian)
    test_big_endian(IS_BIG_ENDIAN)
    set(CMAKE_C_BYTE_ORDER "LITTLE_ENDIAN")
    if(IS_BIG_ENDIAN)
        set(CMAKE_C_BYTE_ORDER "BIG_ENDIAN")
    endif()
endif()

if(DEFINED WARNING_C_FLAGS)
    set(CMAKE_C_FLAGS "${WARNING_C_FLAGS} ${CMAKE_C_FLAGS}")
elseif(WIN32)
    # Windows cl.exe does not support the -Wextra, -Wno-unused and -Werror flags.
    set(CMAKE_C_FLAGS "-Wall ${CMAKE_C_FLAGS}")
else()
    set(CMAKE_C_FLAGS "-Wall -Wextra -Wno-unused -Werror ${CMAKE_C_FLAGS}")
endif()


####################################################
# Build Options
####################################################

add_option("WOLFPKCS11_INSTALL"
    "Create install target for WolfPKCS11 project"
    "yes" "yes;no")


# Enable Debugging
add_option("WOLFPKCS11_DEBUG"
    "Enables option for debug (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_DEBUG)
    set(CMAKE_C_FLAGS "-g ${CMAKE_C_FLAGS}")
    list(APPEND WOLFPKCS11_DEFINITIONS
        "-DDEBUG"
        "-DDEBUG_WOLFPKCS11")
else()
    set(CMAKE_C_FLAGS "-O2 ${CMAKE_C_FLAGS}")
    list(APPEND WOLFPKCS11_DEFINITIONS
        "-DNDEBUG")
endif()


# Coverage
add_option("WOLFPKCS11_COVERAGE"
    "Enables option for coverage (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_COVERAGE)
    set(CMAKE_C_FLAGS "--coverage ${CMAKE_C_FLAGS}")
endif()


# Single threaded
add_option("WOLFPKCS11_SINGLE_THREADED"
    "Enable wolfPKCS11 single threaded (default: disabled)"
    "no" "yes;no")

# TODO: Logic here isn't complete, yet (see AX_PTHREAD)
if(NOT WOLFPKCS11_SINGLE_THREADED)
    if(CMAKE_USE_PTHREADS_INIT)
        list(APPEND WOLFPKCS11_LINK_LIBS Threads::Threads)
        set(HAVE_PTHREAD 1)
        list(APPEND WOLFPKCS11_DEFINITIONS
            "-DHAVE_PTHREAD"
            "-D_POSIX_THREADS")
    endif()
else()
    set(SINGLE_THREADED 1)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DSINGLE_THREADED")
endif()


# RSA
add_option("WOLFPKCS11_RSA"
    "Enable RSA (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_RSA)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DNO_RSA")
endif()


# RSA-OAEP
add_option("WOLFPKCS11_OAEP"
    "Enable RSA OAEP (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_RSA)
    override_cache(WOLFPKCS11_OAEP "no")
endif()
if(NOT WOLFPKCS11_OAEP)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWC_NO_RSA_OAEP")
endif()


# RSA-PSS
add_option("WOLFPKCS11_RSA_PSS"
    "Enable RSA-PSS (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_RSA)
    override_cache(WOLFPKCS11_RSA_PSS "no")
endif()
if(WOLFPKCS11_RSA_PSS)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWC_RSA_PSS")
endif()


# Key Gen
add_option("WOLFPKCS11_KEYGEN"
    "Enable key generation (default: enabled)])"
    "yes" "yes;no")

if(WOLFPKCS11_KEYGEN)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFSSL_KEY_GEN")
endif()


# ECC
add_option("WOLFPKCS11_ECC"
    "Enable ECC (default: enabled)"
    "yes" "yes;no")

if(WOLFPKCS11_ECC)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_ECC")
endif()


# DH
add_option("WOLFPKCS11_DH"
    "Enable DH (default: enabled)"
    "yes" "yes;no;const")

if(NOT WOLFPKCS11_DH)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DNO_DH")
endif()


# AES
add_option("WOLFPKCS11_AES"
    "Enable AES (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_AES)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DNO_AES")
endif()

# AES KEYWRAP
add_option("WOLFPKCS11_AESKEYWRAP"
    "Enable AES KEYWRAP (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_AESKEYWRAP)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_AES_KEY_WRAP")
endif()

# AES-CBC
add_option("WOLFPKCS11_AESCBC"
    "Enable wolfPKCS11 AES-CBC support (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_AESCBC OR NOT WOLFPKCS11_AES)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DNO_AES_CBC")
endif()

# AES-GCM
add_option("WOLFPKCS11_AESGCM"
    "Enable wolfPKCS11 AES-GCM support (default: enabled)"
    "yes" "yes;no")

if(WOLFPKCS11_AESGCM AND WOLFPKCS11_AES)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_AESGCM")
endif()

# AES-CTR
add_option("WOLFPKCS11_AESCTR"
    "Enable wolfPKCS11 AES-CTR support (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_AESCTR AND WOLFPKCS11_AES)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_AESCTR")
endif()

# AES-CCM
add_option("WOLFPKCS11_AESCCM"
    "Enable wolfPKCS11 AES-CCM support (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_AESCCM AND WOLFPKCS11_AES)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_AESCCM")
endif()

# AES-ECB
add_option("WOLFPKCS11_AESECB"
    "Enable wolfPKCS11 AES-ECB support (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_AESECB AND WOLFPKCS11_AES)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_AESECB")
endif()

# AES-CTS
add_option("WOLFPKCS11_AESCTS"
    "Enable wolfPKCS11 AES-CTS support (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_AESCTS AND WOLFPKCS11_AES)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_AESCTS")
endif()

# AES-CMAC
add_option("WOLFPKCS11_AESCMAC"
    "Enable wolfPKCS11 AES-CMAC support (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_AESCMAC AND WOLFPKCS11_AES)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_AESCMAC")
endif()


# HMAC
add_option("WOLFPKCS11_HMAC"
    "Enable wolfPKCS11 HMAC support (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_HMAC)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DNO_HMAC")
endif()


# HKDF
add_option("WOLFPKCS11_HKDF"
    "Enable wolfPKCS11 HKDF support (default: enabled)"
    "yes" "yes;no")

if(WOLFPKCS11_HKDF)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFPKCS11_HKDF")
endif()


# PBKDF2
add_option("WOLFPKCS11_PBKDF2"
    "Enable wolfPKCS11 PBKDF2 support (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_PBKDF2)
    set(PBKDF2_ITERATIONS 600000 CACHE STRING "Set PBKDF2 iterations (default: 600000)")
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFPKCS11_PBKDF2 -DPBKDF2_ITERATIONS=${PBKDF2_ITERATIONS}")
endif()


# MD5
add_option("WOLFPKCS11_MD5"
    "Enable MD5 (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_MD5)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DNO_MD5")
endif()


# SHA
add_option("WOLFPKCS11_SHA"
    "Enable SHA1 (default: enabled)"
    "yes" "yes;no")
add_option("WOLFPKCS11_SHA1"
    "Enable SHA1 (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_SHA OR NOT WOLFPKCS11_SHA1)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DNO_SHA")
endif()

# SHA224
add_option("WOLFPKCS11_SHA224"
    "Enable wolfPKCS11 SHA-224 support (default: enabled)"
    "yes" "yes;no")

if(WOLFPKCS11_SHA224)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFSSL_SHA224")
endif()

# SHA256
add_option("WOLFPKCS11_SHA256"
    "Enable wolfPKCS11 SHA-256 support (default: enabled)"
    "yes" "yes;no")

if(NOT WOLFPKCS11_SHA256)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DNO_SHA256")
endif()

# SHA384
add_option("WOLFPKCS11_SHA384"
    "Enable wolfPKCS11 SHA-384 support (default: enabled)"
    "yes" "yes;no")

if(WOLFPKCS11_SHA384)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFSSL_SHA384")
endif()

# SHA512
add_option("WOLFPKCS11_SHA512"
    "Enable wolfPKCS11 SHA-512 support (default: enabled)"
    "yes" "yes;no")

if(WOLFPKCS11_SHA512)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFSSL_SHA512")
endif()

# SHA3
add_option("WOLFPKCS11_SHA3"
    "Enable wolfPKCS11 SHA-3 support (default: enabled)"
    "yes" "yes;no")

if(WOLFPKCS11_SHA3)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFSSL_SHA3")
endif()


# WolfTPM
add_option("WOLFPKCS11_TPM"
    "Enable wolfTPM keystore support (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_TPM)
    list(APPEND WOLFPKCS11_LINK_LIBS "-lwolftpm")
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFPKCS11_TPM")
endif()


# NSS
add_option("WOLFPKCS11_NSS"
    "Enable NSS specific modifications (default: disabled)"
    "no" "yes;no")

if(WOLFPKCS11_NSS)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFPKCS11_NSS")
endif()


# Default token path
set(WOLFPKCS11_DEFAULT_TOKEN_PATH "" CACHE STRING "Set default token storage path (default: none)")

if(WOLFPKCS11_DEFAULT_TOKEN_PATH)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFPKCS11_DEFAULT_TOKEN_PATH=\"${WOLFPKCS11_DEFAULT_TOKEN_PATH}\"")
endif()


# PKCS#11 Version 3.0
add_option("WOLFPKCS11_PKCS11_V3_0"
    "Enable PKCS#11 Version 3.0 support (default: enabled)"
    "yes" "yes;no")

if(WOLFPKCS11_PKCS11_V3_0)
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFPKCS11_PKCS11_V3_0")
endif()


# PKCS#11 Version 3.2
add_option("WOLFPKCS11_PKCS11_V3_2"
    "Enable PKCS#11 Version 3.2 support (default: enabled)"
    "no" "yes;no")

if(WOLFPKCS11_PKCS11_V3_2)
    if(NOT WOLFPKCS11_PKCS11_V3_0)
        message(FATAL_ERROR "PKCS#11 Version 3.2 support requires PKCS#11 Version 3.0 support")
    endif()
    list(APPEND WOLFPKCS11_DEFINITIONS "-DWOLFPKCS11_PKCS11_V3_2")
endif()


# If wolfpkcs11/options.h exists, delete it to avoid
# a mixup with build/wolfpkcs11/options.h.
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wolfpkcs11/options.h")
    file(REMOVE "${CMAKE_CURRENT_SOURCE_DIR}/wolfpkcs11/options.h")
endif()

# Generate user options header
message(STATUS "Generating user options header...")
if (${CMAKE_DISABLE_SOURCE_CHANGES})
    set(WOLFPKCS11_BUILD_OUT_OF_TREE_DEFAULT "${CMAKE_DISABLE_SOURCE_CHANGES}")
else()
    set(WOLFPKCS11_BUILD_OUT_OF_TREE_DEFAULT "yes")
endif()
add_option("WOLFPKCS11_BUILD_OUT_OF_TREE"
    "Don't generate files in the source tree (default: ${WOLFPKCS11_BUILD_OUT_OF_TREE_DEFAULT})"
    "${WOLFPKCS11_BUILD_OUT_OF_TREE_DEFAULT}" "yes;no")
if (${WOLFPKCS11_BUILD_OUT_OF_TREE})
   set(WOLFPKCS11_OUTPUT_BASE ${CMAKE_CURRENT_BINARY_DIR})
else()
   set(WOLFPKCS11_OUTPUT_BASE ${CMAKE_CURRENT_SOURCE_DIR})
endif()
set(OPTION_FILE "${WOLFPKCS11_OUTPUT_BASE}/wolfpkcs11/options.h")

file(REMOVE ${OPTION_FILE})


####################################################
# Library Target
####################################################

# TODO: - Build shared/static libs based on enables. Check CMake
#         global flag BUILD_SHARED_LIBS.
option(BUILD_SHARED_LIBS
    "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)"
    ON)

set(LIB_SOURCES
    src/internal.c
    src/wolfpkcs11.c
    src/slot.c
    src/crypto.c
)
if(BUILD_SHARED_LIBS)
    message(STATUS "BUILD_SHARED_LIBS enabled: ${LIB_SOURCES}")
    add_library(wolfpkcs11 SHARED ${LIB_SOURCES})
else()
    message(STATUS "Static Libs: ${LIB_SOURCES}")
    add_library(wolfpkcs11 STATIC ${LIB_SOURCES})
    list(APPEND WOLFPKCS11_DEFINITIONS "-DHAVE_PKCS11_STATIC")
endif()

add_library(wolfpkcs11::wolfpkcs11 ALIAS wolfpkcs11)

foreach(DEF IN LISTS WOLFPKCS11_DEFINITIONS)
    string(REGEX MATCH "^(-D)?([^=]+)(=(.*))?$" DEF_MATCH ${DEF})
    if (NOT "${CMAKE_MATCH_4}" STREQUAL "")
        set(${CMAKE_MATCH_2} ${CMAKE_MATCH_4})
        # message("set(${CMAKE_MATCH_2} ${CMAKE_MATCH_4})")
    else()
        set(${CMAKE_MATCH_2} 1)
        # message("set(${CMAKE_MATCH_2} 1)")
    endif()
endforeach()

# If new build options are added please update the cmake/options.h.in
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.h.in ${OPTION_FILE})

set_target_properties(wolfpkcs11
    PROPERTIES
        SOVERSION ${WOLFPKCS11_LIBRARY_VERSION_FIRST}
        VERSION ${LIBTOOL_FULL_VERSION}
)

target_compile_definitions(wolfpkcs11 PRIVATE "BUILDING_WOLFPKCS11")
target_compile_definitions(wolfpkcs11 PRIVATE ${WOLFPKCS11_DEFINITIONS})

# Determine library filename for WOLFPKCS11_DLL_FILENAME
# This is only needed when building shared libraries
set(WOLFPKCS11_DLL_DEFINITION "")
set(WOLFPKCS11_DLL_DEFINITION_FOR_TESTS "")
set(WOLFPKCS11_DLL_DEFINITION_FOR_EXAMPLES "")
if(BUILD_SHARED_LIBS)
    # Get the library output directory
    get_target_property(LIB_OUTPUT_DIR wolfpkcs11 LIBRARY_OUTPUT_DIRECTORY)
    if(NOT LIB_OUTPUT_DIR)
        set(LIB_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR})
    endif()

    # Determine library filename based on platform
    if(APPLE)
        set(WOLFPKCS11_LIB_NAME "libwolfpkcs11.dylib")
    elseif(WIN32)
        set(WOLFPKCS11_LIB_NAME "wolfpkcs11.dll")
    else()
        set(WOLFPKCS11_LIB_NAME "libwolfpkcs11.so")
    endif()

    # Calculate relative path from source root to library for tests
    # Tests run from ${CMAKE_CURRENT_SOURCE_DIR} (source root) to use existing store/ directory
    # Library is in ${LIB_OUTPUT_DIR} (build directory)
    file(RELATIVE_PATH WOLFPKCS11_DLL_RELATIVE_PATH_FOR_TESTS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${LIB_OUTPUT_DIR})

    # Calculate relative path from examples directory to library for examples
    # Examples run from ${WOLFPKCS11_OUTPUT_BASE}/examples
    file(RELATIVE_PATH WOLFPKCS11_DLL_RELATIVE_PATH_FOR_EXAMPLES
        ${WOLFPKCS11_OUTPUT_BASE}/examples
        ${LIB_OUTPUT_DIR})

    # Construct the full relative path to the library for tests (from source root)
    # Tests run from ${CMAKE_CURRENT_SOURCE_DIR} to use existing store/ directory
    # Library is in ${LIB_OUTPUT_DIR} (build directory)
    # file(RELATIVE_PATH) returns "." when paths are the same, or empty string in some cases
    if(WOLFPKCS11_DLL_RELATIVE_PATH_FOR_TESTS STREQUAL "." OR WOLFPKCS11_DLL_RELATIVE_PATH_FOR_TESTS STREQUAL "")
        # Library is in the source root (unlikely but handle it) - use ./ prefix for relative path
        set(WOLFPKCS11_DLL_FILENAME_FOR_TESTS "./${WOLFPKCS11_LIB_NAME}")
    else()
        # Library is in build directory relative to source root - ensure it starts with ./ for relative path
        # file(RELATIVE_PATH) doesn't include ./ prefix, so we add it
        set(WOLFPKCS11_DLL_FILENAME_FOR_TESTS "./${WOLFPKCS11_DLL_RELATIVE_PATH_FOR_TESTS}/${WOLFPKCS11_LIB_NAME}")
    endif()

    # Construct the full relative path to the library for examples (from examples directory)
    # file(RELATIVE_PATH) returns "." when paths are the same, or empty string in some cases
    if(WOLFPKCS11_DLL_RELATIVE_PATH_FOR_EXAMPLES STREQUAL "." OR WOLFPKCS11_DLL_RELATIVE_PATH_FOR_EXAMPLES STREQUAL "")
        # Library is in the same directory as examples - use ./ prefix for relative path
        set(WOLFPKCS11_DLL_FILENAME_FOR_EXAMPLES "./${WOLFPKCS11_LIB_NAME}")
    else()
        # Library is in a different directory - ensure it starts with ./ for relative path
        # file(RELATIVE_PATH) doesn't include ./ prefix, so we add it
        set(WOLFPKCS11_DLL_FILENAME_FOR_EXAMPLES "./${WOLFPKCS11_DLL_RELATIVE_PATH_FOR_EXAMPLES}/${WOLFPKCS11_LIB_NAME}")
    endif()

    # Use test path for tests, example path for examples
    set(WOLFPKCS11_DLL_FILENAME "${WOLFPKCS11_DLL_FILENAME_FOR_TESTS}")

    # Add to compile definitions for examples and tests
    # We'll set different values for examples vs tests
    list(APPEND WOLFPKCS11_DLL_DEFINITION_FOR_TESTS "-DWOLFPKCS11_DLL_FILENAME=\"${WOLFPKCS11_DLL_FILENAME_FOR_TESTS}\"")
    list(APPEND WOLFPKCS11_DLL_DEFINITION_FOR_EXAMPLES "-DWOLFPKCS11_DLL_FILENAME=\"${WOLFPKCS11_DLL_FILENAME_FOR_EXAMPLES}\"")
    # message(STATUS "WOLFPKCS11_DLL_FILENAME for tests: ${WOLFPKCS11_DLL_FILENAME_FOR_TESTS}")
    # message(STATUS "WOLFPKCS11_DLL_FILENAME for examples: ${WOLFPKCS11_DLL_FILENAME_FOR_EXAMPLES}")
endif()


####################################################
# Include Directories
####################################################

target_include_directories(wolfpkcs11
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)


####################################################
# Link Libraries
####################################################

# wolfSSL
# Check if wolfSSL target already exists (e.g., from add_subdirectory)
if(TARGET wolfssl::wolfssl)
    # wolfSSL is already available as a target, use it directly
    message(STATUS "Using existing wolfSSL target")
else()
    # Try to find wolfSSL as an installed package
    find_package(wolfssl REQUIRED)
endif()
list(APPEND WOLFPKCS11_LINK_LIBS wolfssl::wolfssl)

# Other libraries
target_link_libraries(wolfpkcs11 PUBLIC ${WOLFPKCS11_LINK_LIBS})

if(WIN32)
    # For Windows link ws2_32
    target_link_libraries(wolfpkcs11 PUBLIC
        $<$<PLATFORM_ID:Windows>:ws2_32 crypt32>)
else()
    target_link_libraries(wolfpkcs11
        PUBLIC m)
endif()


####################################################
# Examples and Tests
####################################################

# Enable examples
add_option("WOLFPKCS11_EXAMPLES"
    "Enable examples (default: enabled)"
    "yes" "yes;no")

# Enable tests
add_option("WOLFPKCS11_TESTS"
    "Enable tests (default: enabled)"
    "yes" "yes;no")

enable_testing()

if(WOLFPKCS11_TESTS)
    set(WPKCS11_TEST_TARGETS
        pkcs11test
        pkcs11v3test
        pkcs11mtt
        pkcs11str
        token_path_test
        rsa_session_persistence_test
        debug_test
        object_id_uniqueness_test)

    foreach(test_target IN LISTS WPKCS11_TEST_TARGETS)
        add_wpkcs11_test(${test_target}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/${test_target}.c)
    endforeach()
endif()

if(WOLFPKCS11_EXAMPLES)
    set(WPKCS11_EXAMPLE_TARGETS
        add_aes_key
        add_cert
        add_cert_file
        add_hmac_key
        add_rsa_key
        add_rsa_key_file
        init_token
        mech_info
        obj_list
        slot_info
        token_info)

    foreach(example IN LISTS WPKCS11_EXAMPLE_TARGETS)
        add_wpkcs11_example(${example}
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/${example}.c)
    endforeach()

    # Example: nss_pkcs12_pbe_example (only build when NSS is enabled)
    if(WOLFPKCS11_NSS)
        add_wpkcs11_example(nss_pkcs12_pbe_example
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/nss_pkcs12_pbe_example.c)
    endif()

    # Add example tests in the same order as examples.test (only when tests are enabled)
    if(WOLFPKCS11_TESTS)
        # Since tests run from source root, we need to pass the library path via -lib argument
        # Use the test library path (relative to source root) for example tests
        if(BUILD_SHARED_LIBS)
            set(EXAMPLE_LIB_ARG "-lib" "${WOLFPKCS11_DLL_FILENAME_FOR_TESTS}")
        else()
            # For static builds, no library path needed
            set(EXAMPLE_LIB_ARG "")
        endif()

        # Initialize the token and setup passwords
        # Example tests run after all normal tests
        add_test(NAME init_token
                COMMAND $<TARGET_FILE:init_token>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(init_token PROPERTIES DEPENDS pkcs11test  RUN_SERIAL TRUE)

        # Get the slot information and display
        add_test(NAME slot_info
                COMMAND $<TARGET_FILE:slot_info>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(slot_info PROPERTIES DEPENDS init_token RUN_SERIAL TRUE)

        # Get the token information and display
        add_test(NAME token_info
                COMMAND $<TARGET_FILE:token_info>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(token_info PROPERTIES DEPENDS slot_info RUN_SERIAL TRUE)

        # Get information on mechanisms and display
        add_test(NAME mech_info
                COMMAND $<TARGET_FILE:mech_info>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(mech_info PROPERTIES DEPENDS token_info RUN_SERIAL TRUE)

        # Add an AES key to the session
        add_test(NAME add_aes_key
                COMMAND $<TARGET_FILE:add_aes_key>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_aes_key PROPERTIES DEPENDS mech_info RUN_SERIAL TRUE)

        # Add an AES key to the token
        add_test(NAME add_aes_key_token
                COMMAND $<TARGET_FILE:add_aes_key>
                ${EXAMPLE_LIB_ARG}
                -privId "aes-128"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_aes_key_token PROPERTIES DEPENDS add_aes_key RUN_SERIAL TRUE)

        # Add an HMAC key to the session
        add_test(NAME add_hmac_key
                COMMAND $<TARGET_FILE:add_hmac_key>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_hmac_key PROPERTIES DEPENDS add_aes_key_token RUN_SERIAL TRUE)

        # Add an HMAC key to the token
        add_test(NAME add_hmac_key_token
                COMMAND $<TARGET_FILE:add_hmac_key>
                ${EXAMPLE_LIB_ARG}
                -privId "hmac-256"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_hmac_key_token PROPERTIES DEPENDS add_hmac_key RUN_SERIAL TRUE)

        # Add an RSA key to the session
        add_test(NAME add_rsa_key
                COMMAND $<TARGET_FILE:add_rsa_key>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_rsa_key PROPERTIES DEPENDS add_hmac_key_token RUN_SERIAL TRUE)

        # Add an RSA key to the token
        add_test(NAME add_rsa_key_token
                COMMAND $<TARGET_FILE:add_rsa_key>
                ${EXAMPLE_LIB_ARG}
                -privId "rsa-2048"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_rsa_key_token PROPERTIES DEPENDS add_rsa_key RUN_SERIAL TRUE)

        # Add an RSA key from file to the session
        add_test(NAME add_rsa_key_file
                COMMAND $<TARGET_FILE:add_rsa_key_file>
                ${EXAMPLE_LIB_ARG}
                -rsa ${CMAKE_CURRENT_SOURCE_DIR}/examples/rsa-2048.der
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_rsa_key_file PROPERTIES DEPENDS add_rsa_key_token RUN_SERIAL TRUE)

        # Add an RSA key from file to the token
        add_test(NAME add_rsa_key_file_token
                COMMAND $<TARGET_FILE:add_rsa_key_file>
                ${EXAMPLE_LIB_ARG}
                -privId "rsa-2048.der"
                -rsa ${CMAKE_CURRENT_SOURCE_DIR}/examples/rsa-2048.der
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_rsa_key_file_token PROPERTIES DEPENDS add_rsa_key_file RUN_SERIAL TRUE)

        # Add a cert to the session
        add_test(NAME add_cert
                COMMAND $<TARGET_FILE:add_cert>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_cert PROPERTIES DEPENDS add_rsa_key_file_token RUN_SERIAL TRUE)

        # Add a cert to the token
        add_test(NAME add_cert_token
                COMMAND $<TARGET_FILE:add_cert>
                ${EXAMPLE_LIB_ARG}
                -privId "cert-2048"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(add_cert_token PROPERTIES DEPENDS add_cert RUN_SERIAL TRUE)

        # Show all objects on token
        add_test(NAME obj_list
                COMMAND $<TARGET_FILE:obj_list>
                ${EXAMPLE_LIB_ARG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(obj_list PROPERTIES DEPENDS add_cert_token RUN_SERIAL TRUE)
    endif()
endif()


####################################################
# Installation
####################################################

include(GNUInstallDirs)

set(HEADER_EXCLUDE
    "internal.h"
    "options.h"
    "store.h"
    "version.h"
  )

list(JOIN HEADER_EXCLUDE "|" EXCLUDED_HEADERS_REGEX)

string(PREPEND EXCLUDED_HEADERS_REGEX "(")
string(APPEND  EXCLUDED_HEADERS_REGEX ")")

if(WOLFPKCS11_INSTALL)
    # CMake config package destination (for find_package(wolfpkcs11))
    set(WOLFPKCS11_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/wolfpkcs11"
        CACHE STRING "Installation directory for CMake package config files")

    # Install the library
    install(TARGETS wolfpkcs11
            EXPORT wolfpkcs11-targets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            )

    # Install the export file (wolfpkcs11Targets.cmake) so imported targets are available
    install(EXPORT wolfpkcs11-targets
            FILE wolfpkcs11Targets.cmake
            NAMESPACE wolfpkcs11::
            DESTINATION ${WOLFPKCS11_CMAKE_INSTALL_DIR})

    # Generate and install relocatable config file (wolfpkcs11Config.cmake)
    include(CMakePackageConfigHelpers)
    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/wolfpkcs11Config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/wolfpkcs11Config.cmake
        INSTALL_DESTINATION ${WOLFPKCS11_CMAKE_INSTALL_DIR})

    # Generate and install version file for find_package version checks
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/wolfpkcs11ConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion)

    install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/wolfpkcs11Config.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/wolfpkcs11ConfigVersion.cmake
            DESTINATION ${WOLFPKCS11_CMAKE_INSTALL_DIR})

    # Install the headers
    install(DIRECTORY ${WOLFPKCS11_OUTPUT_BASE}/wolfpkcs11/
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wolfpkcs11
            FILES_MATCHING PATTERN "*.h"
            REGEX ${EXCLUDED_HEADERS_REGEX} EXCLUDE)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/wolfpkcs11/
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wolfpkcs11
            FILES_MATCHING PATTERN "*.h"
            REGEX ${EXCLUDED_HEADERS_REGEX} EXCLUDE)
endif()
