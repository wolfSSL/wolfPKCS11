/* token_path_test.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
    #include <direct.h>
    #include <windows.h>
    #define MKDIR(path) _mkdir(path)
    #define PATH_SEP "\\"
    #define ACCESS _access
    #define F_OK 0
#else
    #include <unistd.h>
    #include <sys/types.h>
    #define MKDIR(path) mkdir(path, 0755)
    #define PATH_SEP "/"
    #define ACCESS access
#endif

/* DLL Location and slot */
#ifndef WOLFPKCS11_DLL_FILENAME
    #ifdef __MACH__
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
    #else
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
    #endif
#endif
#ifndef WOLFPKCS11_DLL_SLOT
    #define WOLFPKCS11_DLL_SLOT 1
#endif

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = WOLFPKCS11_DLL_SLOT;
static const char* tokenName = "wolfpkcs11-test";

static byte* soPin = (byte*)"password123456";
static CK_ULONG soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static CK_ULONG userPinLen = 15;

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_CKR(rv, op, expected) do {                    \
    if (rv != expected) {                                   \
        fprintf(stderr, "FAIL: %s: expected %ld, got %ld\n", op, (long)expected, (long)rv); \
        test_failed++;                                      \
        return -1;                                          \
    } else {                                                \
        printf("PASS: %s\n", op);                          \
        test_passed++;                                      \
    }                                                       \
} while(0)

static int file_exists(const char* path) {
    return ACCESS(path, F_OK) == 0;
}

static void cleanup_test_files(const char* dir) {
    char filepath[512];

    char file[64] = "wp11_token_0000000000000001";

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir, file);
    remove(filepath);
}

static CK_RV pkcs11_init(const char* library)
{
    CK_RV ret = CKR_OK;
#ifndef HAVE_PKCS11_STATIC
    void* func;

    dlib = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        ret = -1;
    }

    if (ret == CKR_OK) {
        func = (void*)(CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
        if (func == NULL) {
            fprintf(stderr, "Failed to get function list function\n");
            ret = -1;
        }
    }

    if (ret == CKR_OK) {
        ret = ((CK_C_GetFunctionList)func)(&funcList);
    }

    if (ret != CKR_OK && dlib != NULL)
        dlclose(dlib);

#else
    ret = C_GetFunctionList(&funcList);
    (void)library;
#endif

    if (ret == CKR_OK) {
        ret = funcList->C_Initialize(NULL);
    }

    return ret;
}

static void pkcs11_final(void)
{
    if (funcList) {
        funcList->C_Finalize(NULL);
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib) {
        dlclose(dlib);
    }
#endif
}

static CK_RV create_test_token(const char* test_name)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    unsigned char label[32];

    printf("\n=== %s ===\n", test_name);

    /* Initialize token */
    memset(label, ' ', sizeof(label));
    memcpy(label, tokenName, strlen(tokenName));

    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "C_InitToken", CKR_OK);

    /* Open session */
    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession", CKR_OK);

    /* Login as SO to set user PIN */
    ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK) {
        ret = funcList->C_InitPIN(session, userPin, userPinLen);
        CHECK_CKR(ret, "C_InitPIN", CKR_OK);
        funcList->C_Logout(session);
    } else if (ret != CKR_USER_ALREADY_LOGGED_IN) {
        CHECK_CKR(ret, "C_Login SO", CKR_OK);
    }

    /* Login as user */
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    if (ret != CKR_OK && ret != CKR_USER_ALREADY_LOGGED_IN) {
        CHECK_CKR(ret, "C_Login User", CKR_OK);
    }

    /* Close session */
    if (session != CK_INVALID_HANDLE) {
        funcList->C_CloseSession(session);
    }

    return ret;
}

static int test_default_home_path(void)
{
    CK_RV ret;
    char expected_dir[256];
    char test_file[512];

    /* Clear environment variable to test default behavior */
#ifndef WOLFPKCS11_NO_ENV
    unsetenv("WOLFPKCS11_TOKEN_PATH");
#endif

#ifdef _WIN32
    const char* appdir = getenv("APPDATA");
    if (!appdir) {
        appdir = getenv("USERPROFILE");
        if (!appdir) {
            printf("SKIP: No APPDATA or USERPROFILE environment variable\n");
            return 0;
        }
    }
    snprintf(expected_dir, sizeof(expected_dir), "%s\\wolfPKCS11", appdir);
#else
    const char* home = getenv("HOME");
    if (!home) {
        printf("SKIP: No HOME environment variable\n");
        return 0;
    }
    snprintf(expected_dir, sizeof(expected_dir), "%s/.wolfPKCS11", home);
#endif

    /* Ensure directory exists */
    MKDIR(expected_dir);

    /* Clean up any existing test files */
    cleanup_test_files(expected_dir);

    ret = create_test_token("Testing default home directory path");
    if (ret != CKR_OK) {
        return -1;
    }

    /* Check if token files were created in expected location */
    snprintf(test_file, sizeof(test_file), "%s" PATH_SEP "wp11_token_0000000000000001", expected_dir);
    if (!file_exists(test_file)) {
        printf("FAIL: Token file not found at expected location: %s\n", test_file);
        test_failed++;
        return -1;
    }

    printf("PASS: Token file found at: %s\n", test_file);
    test_passed++;

    /* Clean up */
    cleanup_test_files(expected_dir);

    return 0;
}

static int test_env_var_path(void)
{
    CK_RV ret;
    const char* test_dir = "./test_token_storage";
    char test_file[512];

    /* Set environment variable */
#ifndef WOLFPKCS11_NO_ENV
    setenv("WOLFPKCS11_TOKEN_PATH", test_dir, 1);
#else
    printf("SKIP: Environment variables disabled\n");
    return 0;
#endif

    /* Create test directory */
    MKDIR(test_dir);

    /* Clean up any existing test files */
    cleanup_test_files(test_dir);

    ret = create_test_token("Testing WOLFPKCS11_TOKEN_PATH environment variable");
    if (ret != CKR_OK) {
        return -1;
    }

    /* Check if token files were created in expected location */
    snprintf(test_file, sizeof(test_file), "%s" PATH_SEP "wp11_token_0000000000000001", test_dir);
    if (!file_exists(test_file)) {
        printf("FAIL: Token file not found at expected location: %s\n", test_file);
        test_failed++;
        return -1;
    }

    printf("PASS: Token file found at: %s\n", test_file);
    test_passed++;

    /* Clean up */
    cleanup_test_files(test_dir);
    unsetenv("WOLFPKCS11_TOKEN_PATH");

    return 0;
}

static int test_temp_fallback_path(void)
{
    CK_RV ret;
    char expected_dir[256];
    char test_file[512];

    /* Clear environment variable and simulate no home directory */
#ifndef WOLFPKCS11_NO_ENV
    unsetenv("WOLFPKCS11_TOKEN_PATH");
    unsetenv("HOME");
    unsetenv("%APPDATA%");
#endif

#ifdef WOLFPKCS11_DEFAULT_TOKEN_PATH
    strcpy(expected_dir, WC_STRINGIFY(WOLFPKCS11_DEFAULT_TOKEN_PATH));
#else
#ifdef _WIN32
    const char* temp = getenv("TEMP");
    if (!temp) {
        strcpy(expected_dir, "C:\\Windows\\Temp");
    } else {
        strcpy(expected_dir, temp);
    }
#else
    strcpy(expected_dir, "/tmp");
#endif
#endif

    /* Clean up any existing test files */
    cleanup_test_files(expected_dir);

    ret = create_test_token("Testing directory fallback");
    if (ret != CKR_OK) {
        return -1;
    }

    /* Check if token files were created in expected location */
    snprintf(test_file, sizeof(test_file), "%s" PATH_SEP "wp11_token_0000000000000001", expected_dir);
    if (!file_exists(test_file)) {
        printf("FAIL: Token file not found at expected location: %s\n", test_file);
        test_failed++;
        return -1;
    }

    printf("PASS: Token file found at: %s\n", test_file);
    test_passed++;

    /* Clean up */
    cleanup_test_files(expected_dir);

    return 0;
}

static void print_results(void)
{
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);

    if (test_failed == 0) {
        printf("ALL TESTS PASSED!\n");
    } else {
        printf("SOME TESTS FAILED!\n");
    }
}

static void Usage(void)
{
    printf("token_path_test - Test token path storage functionality\n");
    printf("Options:\n");
    printf("  -lib <file>     PKCS#11 library to test (default: %s)\n", WOLFPKCS11_DLL_FILENAME);
    printf("  -slot <num>     Slot number to use (default: %d)\n", WOLFPKCS11_DLL_SLOT);
    printf("  -help           Show this help\n");
}

static int string_matches(const char* arg, const char* str)
{
    return strcmp(arg, str) == 0;
}

int main(int argc, char* argv[])
{
    const char* libName = WOLFPKCS11_DLL_FILENAME;
    CK_RV ret;
    int result = 0;

    #if defined(WOLFPKCS11_TPM_STORE) || defined(WOLFPKCS11_NO_STORE)
    printf("Skipped for TPM storage\n");
    return 77;
    #endif

    /* Parse command line arguments */
    argc--;
    argv++;
    while (argc > 0) {
        if (string_matches(*argv, "-help") || string_matches(*argv, "-h")) {
            Usage();
            return 0;
        }
        else if (string_matches(*argv, "-lib")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Library name not supplied\n");
                return 1;
            }
            libName = *argv;
        }
        else if (string_matches(*argv, "-slot")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Slot number not supplied\n");
                return 1;
            }
            slot = atoi(*argv);
        }
        else {
            fprintf(stderr, "Unknown argument: %s\n", *argv);
            Usage();
            return 1;
        }
        argc--;
        argv++;
    }

    printf("=== wolfPKCS11 Token Path Storage Test ===\n");
    printf("Library: %s\n", libName);
    printf("Slot: %ld\n", slot);

    /* Initialize PKCS#11 */
    ret = pkcs11_init(libName);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize PKCS#11: %ld\n", ret);
        return 1;
    }

    /* Run tests */
    printf("\nRunning token path storage tests...\n");

    if (test_env_var_path() != 0) {
        result = 1;
    }

    if (test_default_home_path() != 0) {
        result = 1;
    }

    if (test_temp_fallback_path() != 0) {
        result = 1;
    }

    /* Clean up */
    pkcs11_final();

    print_results();

    return result;
}
