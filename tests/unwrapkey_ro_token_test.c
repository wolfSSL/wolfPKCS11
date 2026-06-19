/* unwrapkey_ro_token_test.c
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
 * Regression test for issue F-5522: C_UnwrapKey from a read-only session must
 * reject an unwrap template requesting a token object (CKA_TOKEN=CK_TRUE) with
 * CKR_SESSION_READ_ONLY, while still allowing creation of a session object
 * (CKA_TOKEN=CK_FALSE).
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

/* NSS treats every session as read/write (WP11_Session_IsRW always returns
 * true), so the read-only token-object gate does not apply to NSS builds. */
#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP) && \
    !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_NSS)

#define UNWRAP_RO_TEST_DIR "./store/unwrapkey_ro_token_test"
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

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_INFO info;
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

    ret = funcList->C_GetInfo(&info);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (ret != CKR_OK)
        return ret;

    if (slotCount > 0) {
        slot = slotList[0];
    } else {
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

/* Open a READ-ONLY session (no CKF_RW_SESSION) and log in as user. */
static CK_RV pkcs11_open_ro_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int sessFlags = CKF_SERIAL_SESSION;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    if (ret != CKR_OK) {
        funcList->C_CloseSession(*session);
        return ret;
    }

    return CKR_OK;
}

static CK_RV pkcs11_close_session(CK_SESSION_HANDLE session)
{
    funcList->C_Logout(session);
    return funcList->C_CloseSession(session);
}

static void cleanup_test_files(const char* dir)
{
    char filepath[512];

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

/* AES-128 wrapping key (session object) with CKA_WRAP and CKA_UNWRAP. */
static CK_RV create_wrapping_key(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_TOKEN,    &ckFalse,        sizeof(ckFalse)        },
        { CKA_WRAP,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_UNWRAP,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,    aes_128_key,     sizeof(aes_128_key)    },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

/* Extractable generic secret (session object) to be wrapped. */
static CK_RV create_secret_to_wrap(CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE* key)
{
    byte keyData[32];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_TOKEN,       &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,       keyData,         sizeof(keyData)        },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    XMEMSET(keyData, 7, sizeof(keyData));
    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

static int unwrapkey_ro_token_test(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_MECHANISM mech = { CKM_AES_KEY_WRAP, NULL, 0 };
    CK_OBJECT_HANDLE wrappingKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secretKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    byte wrappedKey[64];
    CK_ULONG wrappedKeyLen = sizeof(wrappedKey);
    int result = 0;

    CK_ATTRIBUTE tokenTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_TOKEN,    &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ATTRIBUTE sessionTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_TOKEN,    &ckFalse,        sizeof(ckFalse)        },
    };

    ret = create_wrapping_key(session, &wrappingKey);
    CHECK_CKR(ret, "Create wrapping key", CKR_OK);
    ret = create_secret_to_wrap(session, &secretKey);
    CHECK_CKR(ret, "Create secret key to wrap", CKR_OK);

    ret = funcList->C_WrapKey(session, &mech, wrappingKey, secretKey,
                              wrappedKey, &wrappedKeyLen);
    CHECK_CKR(ret, "C_WrapKey", CKR_OK);

    /* Negative: R/O session must reject CKA_TOKEN=TRUE in the unwrap template */
    ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrappedKey,
                                wrappedKeyLen, tokenTmpl,
                                sizeof(tokenTmpl) / sizeof(*tokenTmpl),
                                &unwrapped);
    CHECK_CKR(ret, "C_UnwrapKey CKA_TOKEN=TRUE in R/O session rejected",
              CKR_SESSION_READ_ONLY);

    /* Positive: R/O session may create a session object (CKA_TOKEN=FALSE) */
    ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrappedKey,
                                wrappedKeyLen, sessionTmpl,
                                sizeof(sessionTmpl) / sizeof(*sessionTmpl),
                                &unwrapped);
    CHECK_CKR(ret, "C_UnwrapKey CKA_TOKEN=FALSE in R/O session allowed",
              CKR_OK);

cleanup:
    if (unwrapped != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, unwrapped);
    if (secretKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, secretKey);
    if (wrappingKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, wrappingKey);
    return result;
}

static int run_unwrapkey_ro_token_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int result = 0;

    printf("\n=== Testing C_UnwrapKey read-only token-object gate ===\n");

    cleanup_test_files(UNWRAP_RO_TEST_DIR);

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

    /* Set user PIN via SO session */
    {
        CK_SESSION_HANDLE soSession;
        int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
        if (ret != CKR_OK) {
            fprintf(stderr, "FAIL: C_OpenSession (SO): 0x%lx\n",
                    (unsigned long)ret);
            test_failed++;
            pkcs11_final();
            return -1;
        }

        ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
        if (ret != CKR_OK) {
            fprintf(stderr, "FAIL: C_Login (SO): 0x%lx\n",
                    (unsigned long)ret);
            test_failed++;
            funcList->C_CloseSession(soSession);
            pkcs11_final();
            return -1;
        }

        ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
        if (ret != CKR_OK) {
            fprintf(stderr, "FAIL: C_InitPIN: 0x%lx\n", (unsigned long)ret);
            test_failed++;
            funcList->C_Logout(soSession);
            funcList->C_CloseSession(soSession);
            pkcs11_final();
            return -1;
        }

        funcList->C_Logout(soSession);
        funcList->C_CloseSession(soSession);
    }

    ret = pkcs11_open_ro_session(&session);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: pkcs11_open_ro_session: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    if (unwrapkey_ro_token_test(session) != 0)
        result = -1;

    pkcs11_close_session(session);
    pkcs11_final();
    return result;
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

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", UNWRAP_RO_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 C_UnwrapKey Read-Only Token Gate Test ===\n");

    (void)run_unwrapkey_ro_token_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES || !HAVE_AES_KEYWRAP || WOLFPKCS11_NO_STORE || WOLFPKCS11_NSS */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES key wrap not available, skipping C_UnwrapKey R/O token test\n");
    return 0;
}

#endif /* !NO_AES && HAVE_AES_KEYWRAP && !WOLFPKCS11_NO_STORE && !WOLFPKCS11_NSS */
