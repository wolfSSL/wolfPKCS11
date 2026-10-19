/* empty_pin_cache_test.c
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
 * White-box test for the empty-PIN cache in WP11_Slot_Has_Empty_Pin().
 *
 * Whether the user PIN is empty is expensive to work out, so the result is
 * cached. The check hashes with the slot lock released, so the PIN can change
 * between the check and caching its result. If the stale "empty" result were
 * cached after the PIN was changed to a non-empty one, a public session could
 * keep creating CKA_PRIVATE objects without logging in.
 *
 * This test uses the DEBUG_WOLFPKCS11-only hook
 * WP11_Test_SetEmptyPinCheckHook() to change the PIN from empty to non-empty
 * at exactly that point, then checks that a later private-object creation in
 * the public session is refused, and is allowed again after logging in.
 *
 * Needs a build that allows an empty user PIN (WP11_MIN_PIN_LEN=0, the
 * default for WOLFPKCS11_NSS builds); otherwise the test reports itself
 * skipped.
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

#if defined(DEBUG_WOLFPKCS11) && !defined(NO_AES) && \
    !defined(WOLFPKCS11_LEGACY_PRIVATE_FALSE_DEFAULT)

/* DEBUG_WOLFPKCS11-only test hook exported by libwolfpkcs11. */
#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Test_SetEmptyPinCheckHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

#define EMPTY_PIN_CACHE_TEST_DIR "./store/empty_pin_cache_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static int test_passed = 0;
static int test_failed = 0;
static int test_skipped = 0;

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
static byte* newUserPin = (byte*)"wolfpkcs11-test";
static int newUserPinLen = 15;

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

/* State for the hook, which runs inside C_CreateObject. */
static CK_SESSION_HANDLE hookSession = 0;
static int hookCalls = 0;
static CK_RV hookRv = CKR_GENERAL_ERROR;

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

/* Set an empty user PIN as the SO. */
static CK_RV pkcs11_set_empty_user_pin(void)
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
    ret = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)"", 0);
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

/* Create a CKA_PRIVATE AES session key. */
static CK_RV create_private_key(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_VALUE,    aes_128_key,     sizeof(aes_128_key)    },
        { CKA_TOKEN,    &ckFalse,        sizeof(ckFalse)        },
        { CKA_PRIVATE,  &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

/* Called by WP11_Slot_Has_Empty_Pin() after its uncached check and before it
 * caches the result: change the user PIN from empty to non-empty. */
static void change_pin_hook(void)
{
    hookCalls++;
    if (hookCalls == 1) {
        hookRv = funcList->C_SetPIN(hookSession, (CK_UTF8CHAR_PTR)"", 0,
                                    newUserPin, newUserPinLen);
    }
}

static int empty_pin_cache_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing empty-PIN cache across a PIN change ===\n");

    cleanup_test_files(EMPTY_PIN_CACHE_TEST_DIR);

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
    ret = pkcs11_set_empty_user_pin();
    if (ret == CKR_PIN_LEN_RANGE) {
        printf("Empty user PIN not allowed (WP11_MIN_PIN_LEN > 0), "
               "skipping\n");
        test_skipped = 1;
        pkcs11_final();
        return 0;
    }
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: set empty user PIN: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    /* Public (not logged in) R/W session. Nothing has cached the empty-PIN
     * result yet: setting the PIN resets the cache. */
    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession", CKR_OK);

    /* The first private-object creation runs the uncached empty-PIN check;
     * the hook changes the PIN before the result can be cached. Whether this
     * in-flight call is allowed is not what is being tested. */
    hookSession = session;
    WP11_Test_SetEmptyPinCheckHook(change_pin_hook);
    ret = create_private_key(session, &key);
    WP11_Test_SetEmptyPinCheckHook(NULL);
    printf("INFO: in-flight C_CreateObject returned 0x%lx\n",
           (unsigned long)ret);
    if (ret == CKR_OK && key != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, key);

    CHECK_COND(hookCalls >= 1, "empty-PIN check ran uncached (hook called)");
    CHECK_CKR(hookRv, "C_SetPIN from empty to non-empty in the hook", CKR_OK);

    /* The stale "empty" result must not have been cached. */
    key = CK_INVALID_HANDLE;
    ret = create_private_key(session, &key);
    CHECK_CKR(ret, "private object refused in public session after PIN change",
              CKR_USER_NOT_LOGGED_IN);

    ret = funcList->C_Login(session, CKU_USER, newUserPin, newUserPinLen);
    CHECK_CKR(ret, "C_Login with the new user PIN", CKR_OK);

    ret = create_private_key(session, &key);
    CHECK_CKR(ret, "private object allowed after login", CKR_OK);

cleanup:
    WP11_Test_SetEmptyPinCheckHook(NULL);
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", EMPTY_PIN_CACHE_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Empty-PIN Cache Test ===\n");

    (void)empty_pin_cache_test();

    print_results();

    if (test_failed != 0)
        return 1;
    if (test_skipped != 0)
        return 77;  /* automake: test skipped */
    return 0;
}

#else /* !DEBUG_WOLFPKCS11 || NO_AES || WOLFPKCS11_LEGACY_PRIVATE_FALSE_DEFAULT */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("Debug hook or AES not available, skipping empty-PIN cache "
           "test\n");
    return 77;  /* automake: test skipped */
}

#endif
