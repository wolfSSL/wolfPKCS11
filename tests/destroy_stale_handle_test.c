/* destroy_stale_handle_test.c
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
 * White-box test for address reuse (ABA) in C_DestroyObject.
 *
 * C_DestroyObject resolves the handle to an object pointer, releases the
 * lock, then removes the object by that pointer. If another thread destroys
 * the same handle in between and a third thread creates a new object that is
 * allocated at the freed address, the first caller holds a pointer that now
 * names the new object. Matching on the pointer alone would unlink and free
 * the new object and report success for the old handle.
 *
 * Address reuse cannot be forced from the public API, so this test uses the
 * DEBUG_WOLFPKCS11-only hook WP11_Test_RemoveObjectStale() to put the removal
 * directly into that state: the pointer of a live object paired with the
 * handle of an object that was already destroyed. The removal must be refused
 * and the live object must survive, for both token and session objects. A
 * control call with matching handles confirms the hook does remove otherwise.
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

#if defined(DEBUG_WOLFPKCS11) && !defined(NO_AES)

/* DEBUG_WOLFPKCS11-only test hook exported by libwolfpkcs11. */
extern int WP11_Test_RemoveObjectStale(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE liveHandle, CK_OBJECT_HANDLE staleHandle);

/* Mirrors WP11_OBJECT_ALREADY_REMOVED in wolfpkcs11/internal.h. */
#define OBJECT_ALREADY_REMOVED 1

#define STALE_HANDLE_TEST_DIR "./store/destroy_stale_handle_test"
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
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;

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

/* Create an AES secret key, on the token or in the session. */
static CK_RV create_key(CK_SESSION_HANDLE session, CK_BBOOL onToken,
                        CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_VALUE,    aes_128_key,     sizeof(aes_128_key)    },
        { CKA_TOKEN,    &onToken,        sizeof(onToken)        },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

/* Check that the object behind a handle can still be read. */
static CK_RV read_class(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_OBJECT_CLASS cls = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
    };

    return funcList->C_GetAttributeValue(session, key, tmpl, 1);
}

/*
 * Destroy one object, create another, then ask for the removal of the new
 * object's pointer under the destroyed object's handle. It must be refused and
 * leave the new object in place.
 */
static int stale_handle_case(CK_SESSION_HANDLE session, CK_BBOOL onToken)
{
    CK_RV ret;
    CK_OBJECT_HANDLE stale = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE live = CK_INVALID_HANDLE;
    const char* kind = onToken ? "token" : "session";
    char msg[96];
    int rc;
    int result = 0;

    ret = create_key(session, onToken, &stale);
    snprintf(msg, sizeof(msg), "%s: create first key", kind);
    CHECK_CKR(ret, msg, CKR_OK);

    ret = funcList->C_DestroyObject(session, stale);
    snprintf(msg, sizeof(msg), "%s: destroy first key", kind);
    CHECK_CKR(ret, msg, CKR_OK);

    ret = create_key(session, onToken, &live);
    snprintf(msg, sizeof(msg), "%s: create second key", kind);
    CHECK_CKR(ret, msg, CKR_OK);

    snprintf(msg, sizeof(msg), "%s: handles differ", kind);
    CHECK_COND(live != stale, msg);

    rc = WP11_Test_RemoveObjectStale(session, live, stale);
    snprintf(msg, sizeof(msg),
             "%s: removal by live pointer and stale handle refused", kind);
    CHECK_CKR((CK_RV)rc, msg, (CK_RV)OBJECT_ALREADY_REMOVED);

    ret = read_class(session, live);
    snprintf(msg, sizeof(msg), "%s: second key still present", kind);
    CHECK_CKR(ret, msg, CKR_OK);

    /* Control: with the matching handle the hook does remove (and free). */
    rc = WP11_Test_RemoveObjectStale(session, live, live);
    snprintf(msg, sizeof(msg), "%s: removal with matching handle succeeds",
             kind);
    CHECK_CKR((CK_RV)rc, msg, (CK_RV)0);

    ret = read_class(session, live);
    snprintf(msg, sizeof(msg), "%s: second key gone after removal", kind);
    CHECK_CKR(ret, msg, CKR_OBJECT_HANDLE_INVALID);

cleanup:
    return result;
}

static int destroy_stale_handle_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing object removal with a stale handle ===\n");

    cleanup_test_files(STALE_HANDLE_TEST_DIR);

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

    /* Secret keys default to CKA_PRIVATE, so resolving them needs a user
     * login. */
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login user", CKR_OK);

    if (stale_handle_case(session, CK_TRUE) != 0)
        result = -1;
    if (stale_handle_case(session, CK_FALSE) != 0)
        result = -1;

cleanup:
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", STALE_HANDLE_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Destroy Stale Handle Test ===\n");

    (void)destroy_stale_handle_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* !DEBUG_WOLFPKCS11 || NO_AES */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("Debug hook or AES not available, skipping destroy stale handle "
           "test\n");
    return 77;  /* automake: test skipped */
}

#endif /* DEBUG_WOLFPKCS11 && !NO_AES */
