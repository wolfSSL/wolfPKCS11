/* logout_token_key_zero_test.c
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
 * White-box test for token-key zeroization on user logout (bug #5524).
 *
 * WP11_Slot_Logout() scrubs the in-memory token object-encryption key with
 * wc_ForceZero() on user logout. Deleting that scrub changes no PKCS#11 return
 * value or object behaviour, so it was untestable through the public API. This
 * test uses the DEBUG_WOLFPKCS11-only hook WP11_Slot_TokenKeyIsZero() to observe
 * the key buffer directly: it must be populated after login and all-zero after
 * logout.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

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

#if defined(DEBUG_WOLFPKCS11) && !defined(WOLFPKCS11_NO_STORE)

/* DEBUG_WOLFPKCS11-only introspection hook exported by libwolfpkcs11. */
extern int WP11_Slot_TokenKeyIsZero(CK_SLOT_ID slotId);

#define LOGOUT_KEY_TEST_DIR "./store/logout_token_key_zero_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_CKR(rv, op, expected) do {                    \
    if (rv != expected) {                                   \
        fprintf(stderr, "FAIL: %s: expected %ld, got %ld\n", op, (long)expected, (long)rv); \
        test_failed++;                                      \
        result = -1;                                        \
        goto cleanup;                                       \
    } else {                                                \
        printf("PASS: %s\n", op);                           \
        test_passed++;                                      \
    }                                                       \
} while(0)

#define CHECK_COND(cond, op) do {                           \
    if (!(cond)) {                                          \
        fprintf(stderr, "FAIL: %s\n", op);                 \
        test_failed++;                                      \
        result = -1;                                        \
        goto cleanup;                                       \
    } else {                                                \
        printf("PASS: %s\n", op);                           \
        test_passed++;                                      \
    }                                                       \
} while(0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static const char* tokenName = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"someUserPin";
static int userPinLen = 11;

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return -1;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return -1;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: 0x%lx\n",
            (unsigned long)ret);
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: 0x%lx\n",
            (unsigned long)ret);
        return ret;
    }
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (ret != CKR_OK)
        return ret;

    if (slotCount > 0)
        slot = slotList[0];
    else {
        fprintf(stderr, "No slots available\n");
        return CKR_GENERAL_ERROR;
    }

    return ret;
}

static CK_RV pkcs11_final(void)
{
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
        funcList = NULL;
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    return CKR_OK;
}

static CK_RV pkcs11_init_token(void)
{
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));
    return funcList->C_InitToken(slot, soPin, soPinLen, label);
}

static CK_RV pkcs11_set_user_pin(void)
{
    CK_SESSION_HANDLE soSession;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_RV ret;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
    if (ret != CKR_OK) {
        funcList->C_CloseSession(soSession);
        return ret;
    }
    ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return ret;
}

static void cleanup_test_files(const char* dir)
{
    char filepath[512];

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

/*
 * Login as user populates the token key; logout must zeroize it. Two cycles
 * confirm the key is re-derived and re-scrubbed each time.
 */
static int logout_token_key_zero_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;
    int cycle;

    printf("\n=== Testing token key zeroization on user logout ===\n");

    cleanup_test_files(LOGOUT_KEY_TEST_DIR);

    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: pkcs11_init: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        return -1;
    }
    ret = pkcs11_init_token();
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: C_InitToken: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }
    ret = pkcs11_set_user_pin();
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: set user PIN: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession", CKR_OK);

    for (cycle = 0; cycle < 2; cycle++) {
        char msg[64];

        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        snprintf(msg, sizeof(msg), "cycle %d: C_Login user", cycle);
        CHECK_CKR(ret, msg, CKR_OK);

        snprintf(msg, sizeof(msg),
                 "cycle %d: token key populated after login", cycle);
        CHECK_COND(WP11_Slot_TokenKeyIsZero(slot) == 0, msg);

        ret = funcList->C_Logout(session);
        snprintf(msg, sizeof(msg), "cycle %d: C_Logout", cycle);
        CHECK_CKR(ret, msg, CKR_OK);

        snprintf(msg, sizeof(msg),
                 "cycle %d: token key zeroized after logout", cycle);
        CHECK_COND(WP11_Slot_TokenKeyIsZero(slot) == 1, msg);
    }

cleanup:
    if (session != 0)
        funcList->C_CloseSession(session);
    pkcs11_final();
    return result;
}

static void print_results(void)
{
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);

    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", LOGOUT_KEY_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Logout Token-Key Zeroization Test ===\n");

    (void)logout_token_key_zero_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* !DEBUG_WOLFPKCS11 || WOLFPKCS11_NO_STORE */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("Debug hook/store not available, skipping logout key zeroization "
           "test\n");
    return 0;
}

#endif /* DEBUG_WOLFPKCS11 && !WOLFPKCS11_NO_STORE */
