/* nss_configdir_prefix_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 *
 * Test that the NSS configdir passed to C_Initialize is used as a directory
 * when NSS prefixes it with its database type ("sql:/path", "dbm:/path",
 * "extern:/path"), as NSS does for "certutil -d sql:/path" and for
 * applications such as Chromium. The prefix must not become part of the
 * token store path.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"

#if defined(WOLFPKCS11_NSS) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(WOLFPKCS11_NO_ENV)

#define TEST_DIR "./store/nss_configdir_prefix_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static int test_passed = 0;
static int test_failed = 0;

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static int check(int ok, const char* what, const char* prefix)
{
    if (ok) {
        printf("PASS: %s (prefix \"%s\")\n", what, prefix);
        test_passed++;
    }
    else {
        fprintf(stderr, "FAIL: %s (prefix \"%s\")\n", what, prefix);
        test_failed++;
    }
    return ok ? 0 : -1;
}

static int file_exists(const char* path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static void remove_dir_files(const char* dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(path);
    (void)rmdir(dir);
}

static CK_RV load_library(void)
{
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        dlib = NULL;
        return CKR_GENERAL_ERROR;
    }
    return func(&funcList);
#else
    return C_GetFunctionList(&funcList);
#endif
}

static void unload_library(void)
{
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    funcList = NULL;
}

/* Initialize with an NSS-style parameter string whose configdir has the
 * given database type prefix, set up a token and user PIN, finalize, and
 * check where the token was stored. */
static int test_prefix(const char* prefix)
{
    int result = 0;
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    unsigned char label[32];
    char params[512];
    char dir[256];
    char tokenFile[512];
    char prefixedDir[300];

    snprintf(dir, sizeof(dir), "%s/%s", TEST_DIR,
        prefix[0] == '\0' ? "none" : prefix);
    /* The directory name ends in ':' for prefixed cases; that is fine on
     * POSIX and keeps each case separate. */
    if (dir[strlen(dir) - 1] == ':')
        dir[strlen(dir) - 1] = '\0';
    remove_dir_files(dir);
    if (mkdir(dir, 0700) != 0) {
        fprintf(stderr, "mkdir %s failed\n", dir);
        return check(0, "create test directory", prefix);
    }
    snprintf(tokenFile, sizeof(tokenFile), "%s/%s", dir,
        WOLFPKCS11_TOKEN_FILENAME);
    snprintf(prefixedDir, sizeof(prefixedDir), "%s%s", prefix, dir);

    /* The parameter string NSS passes to its internal module. */
    snprintf(params, sizeof(params),
        "configdir='%s%s' certPrefix='' keyPrefix='' secmod='secmod.db' "
        "flags= updatedir='' updateCertPrefix='' updateKeyPrefix='' "
        "updateid='' updateTokenDescription='' ", prefix, dir);

    if (load_library() != CKR_OK)
        return check(0, "load library", prefix);

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    args.LibraryParameters = (CK_CHAR_PTR*)params;
    rv = funcList->C_Initialize(&args);
    if (check(rv == CKR_OK, "C_Initialize with NSS parameters", prefix) != 0) {
        unload_library();
        return -1;
    }

    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK || slotCount == 0) {
        result = check(0, "C_GetSlotList", prefix);
        goto cleanup;
    }

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "nss configdir", 13);
    rv = funcList->C_InitToken(slotList[0], soPin, soPinLen, label);
    if (check(rv == CKR_OK, "C_InitToken", prefix) != 0) {
        result = -1;
        goto cleanup;
    }

    rv = funcList->C_OpenSession(slotList[0],
        CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv == CKR_OK)
        rv = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, userPinLen);
    if (check(rv == CKR_OK, "C_InitPIN", prefix) != 0)
        result = -1;
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }

cleanup:
    funcList->C_Finalize(NULL);
    unload_library();

    if (check(file_exists(tokenFile), "token stored in the configdir", prefix)
            != 0)
        result = -1;
    if (prefix[0] != '\0' && check(!file_exists(prefixedDir),
            "no store path with the database type prefix", prefix) != 0)
        result = -1;

    remove_dir_files(dir);
    return result;
}

int main(int argc, char* argv[])
{
    static const char* prefixes[] = { "sql:", "dbm:", "extern:", "" };
    size_t i;

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 NSS configdir prefix test ===\n");

    /* WOLFPKCS11_TOKEN_PATH takes precedence over configdir and would hide
     * how the configdir is handled. */
    unsetenv("WOLFPKCS11_TOKEN_PATH");
    (void)mkdir("./store", 0700);
    (void)mkdir(TEST_DIR, 0700);

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
        (void)test_prefix(prefixes[i]);

    (void)rmdir(TEST_DIR);

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    return (test_failed == 0) ? 0 : 1;
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("NSS build with a token store not configured, skipping test\n");
    return 0;
}

#endif
