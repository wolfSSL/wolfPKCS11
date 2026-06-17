/* login_another_user_test.c
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
 * Regression test for issue F-4527. C_Login conflated the two
 * already-logged-in cases: logging in while the *same* user type is logged
 * in must return CKR_USER_ALREADY_LOGGED_IN, while logging in while a
 * *different* user type is logged in must return
 * CKR_USER_ANOTHER_ALREADY_LOGGED_IN. Pre-fix every case returned
 * CKR_USER_ALREADY_LOGGED_IN.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>

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

#define TEST_DIR "./store/login_another_user_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static byte* soPin = (byte*)"password123456";
static CK_ULONG soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static CK_ULONG userPinLen = 15;

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_RV(rv, op, expected) do {                                       \
    if ((rv) != (expected)) {                                                 \
        fprintf(stderr, "FAIL: %s: expected 0x%lx, got 0x%lx\n", op,          \
                (unsigned long)(expected), (unsigned long)(rv));              \
        test_failed++;                                                        \
    } else {                                                                  \
        printf("PASS: %s\n", op);                                             \
        test_passed++;                                                        \
    }                                                                         \
} while (0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;

static CK_RV pkcs11_load(void)
{
    CK_RV ret;
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
        return CKR_GENERAL_ERROR;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK)
        return ret;
#endif
    return CKR_OK;
}

static void pkcs11_unload(void)
{
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    funcList = NULL;
}

static void cleanup_store(void)
{
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", TEST_DIR,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

static int run_test(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = 0;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    /* 32-byte space-padded label as required by C_InitToken. */
    CK_UTF8CHAR label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "another-user-test", 17);

    cleanup_store();

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    CHECK_RV(rv, "C_GetSlotList", CKR_OK);
    if (rv != CKR_OK || slotCount == 0)
        goto out;
    slot = slotList[0];

    /* Initialize the token (sets the SO PIN) before opening a session. */
    rv = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_RV(rv, "C_InitToken", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_RV(rv, "C_OpenSession", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    /* --- SO logged in: a second SO login is the same type --- */
    rv = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
    CHECK_RV(rv, "C_Login(SO)", CKR_OK);

    rv = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
    CHECK_RV(rv, "C_Login(SO) again -> ALREADY_LOGGED_IN",
             CKR_USER_ALREADY_LOGGED_IN);

    /* USER login while SO is logged in is a *different* type. */
    rv = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_RV(rv, "C_Login(USER) while SO -> ANOTHER_ALREADY_LOGGED_IN",
             CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

    /* Set the user PIN (requires SO login) so phase B can log in as user. */
    rv = funcList->C_InitPIN(session, userPin, userPinLen);
    CHECK_RV(rv, "C_InitPIN", CKR_OK);

    rv = funcList->C_Logout(session);
    CHECK_RV(rv, "C_Logout(SO)", CKR_OK);

    /* --- USER logged in: a second USER login is the same type --- */
    rv = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_RV(rv, "C_Login(USER)", CKR_OK);

    rv = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_RV(rv, "C_Login(USER) again -> ALREADY_LOGGED_IN",
             CKR_USER_ALREADY_LOGGED_IN);

    /* SO login while USER is logged in is a *different* type. */
    rv = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
    CHECK_RV(rv, "C_Login(SO) while USER -> ANOTHER_ALREADY_LOGGED_IN",
             CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

    funcList->C_Logout(session);

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 C_Login another-user test ===\n");
    run_test();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");

    return (test_failed == 0) ? 0 : 1;
}
