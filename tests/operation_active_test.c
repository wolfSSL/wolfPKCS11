/* operation_active_test.c
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
 * Test for bug #1616: C_EncryptInit, C_DecryptInit, C_DigestInit, C_SignInit,
 * and C_VerifyInit must return CKR_OPERATION_ACTIVE when an operation of the
 * same type is already active on the session.
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

#if !defined(NO_AES) && !defined(NO_AES_CBC)

#define OP_ACTIVE_TEST_DIR "./store/operation_active_test"
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
static byte* userPin = (byte*)"someUserPin";
static int userPinLen = 11;

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_KEY_TYPE aesKeyType = CKK_AES;
#ifndef NO_HMAC
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
#endif

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

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

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

static CK_RV create_aes_128_key(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass,   sizeof(secretKeyClass)   },
        { CKA_KEY_TYPE,    &aesKeyType,       sizeof(aesKeyType)       },
        { CKA_ENCRYPT,     &ckTrue,           sizeof(ckTrue)           },
        { CKA_DECRYPT,     &ckTrue,           sizeof(ckTrue)           },
        { CKA_VALUE,       aes_128_key,       sizeof(aes_128_key)      },
        { CKA_TOKEN,       &ckTrue,           sizeof(ckTrue)           },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

#ifndef NO_HMAC
static CK_RV create_hmac_key(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass,   sizeof(secretKeyClass)   },
        { CKA_KEY_TYPE,    &genericKeyType,   sizeof(genericKeyType)   },
        { CKA_SIGN,        &ckTrue,           sizeof(ckTrue)           },
        { CKA_VERIFY,      &ckTrue,           sizeof(ckTrue)           },
        { CKA_VALUE,       (void*)hmac_key,   sizeof(hmac_key)         },
        { CKA_TOKEN,       &ckTrue,           sizeof(ckTrue)           },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}
#endif /* !NO_HMAC */

/*
 * Test 1: C_EncryptInit called twice without completing the operation.
 * Second call must return CKR_OPERATION_ACTIVE.
 */
static int test_encrypt_init_double(CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE aesKey)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte iv[16];
    byte buf[16];
    CK_ULONG bufSz;
    int result = 0;

    XMEMSET(iv, 0, sizeof(iv));

    mech.mechanism      = CKM_AES_CBC;
    mech.pParameter     = iv;
    mech.ulParameterLen = sizeof(iv);

    /* First init should succeed */
    ret = funcList->C_EncryptInit(session, &mech, aesKey);
    CHECK_CKR(ret, "EncryptInit double: first C_EncryptInit", CKR_OK);

    /* Second init should return CKR_OPERATION_ACTIVE */
    ret = funcList->C_EncryptInit(session, &mech, aesKey);
    CHECK_CKR(ret, "EncryptInit double: second C_EncryptInit",
              CKR_OPERATION_ACTIVE);

cleanup:
    /* Clean up active operation */
    bufSz = sizeof(buf);
    XMEMSET(buf, 0, sizeof(buf));
    (void)funcList->C_Encrypt(session, buf, sizeof(buf), buf, &bufSz);
    return result;
}

/*
 * Test 2: C_DecryptInit called twice without completing the operation.
 * Second call must return CKR_OPERATION_ACTIVE.
 */
static int test_decrypt_init_double(CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE aesKey)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte iv[16];
    byte buf[16];
    CK_ULONG bufSz;
    int result = 0;

    XMEMSET(iv, 0, sizeof(iv));

    mech.mechanism      = CKM_AES_CBC;
    mech.pParameter     = iv;
    mech.ulParameterLen = sizeof(iv);

    ret = funcList->C_DecryptInit(session, &mech, aesKey);
    CHECK_CKR(ret, "DecryptInit double: first C_DecryptInit", CKR_OK);

    ret = funcList->C_DecryptInit(session, &mech, aesKey);
    CHECK_CKR(ret, "DecryptInit double: second C_DecryptInit",
              CKR_OPERATION_ACTIVE);

cleanup:
    bufSz = sizeof(buf);
    XMEMSET(buf, 0, sizeof(buf));
    (void)funcList->C_Decrypt(session, buf, sizeof(buf), buf, &bufSz);
    return result;
}

/*
 * Test 3: C_DigestInit called twice without completing the operation.
 * Second call must return CKR_OPERATION_ACTIVE.
 */
static int test_digest_init_double(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte buf[32];
    CK_ULONG bufSz;
    int result = 0;

    mech.mechanism      = CKM_SHA256;
    mech.pParameter     = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_DigestInit(session, &mech);
    CHECK_CKR(ret, "DigestInit double: first C_DigestInit", CKR_OK);

    ret = funcList->C_DigestInit(session, &mech);
    CHECK_CKR(ret, "DigestInit double: second C_DigestInit",
              CKR_OPERATION_ACTIVE);

cleanup:
    bufSz = sizeof(buf);
    (void)funcList->C_Digest(session, (CK_BYTE_PTR)"abc", 3, buf, &bufSz);
    return result;
}

#ifndef NO_HMAC
/*
 * Test 4: C_SignInit called twice without completing the operation.
 * Second call must return CKR_OPERATION_ACTIVE.
 */
static int test_sign_init_double(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE hmacKey)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte buf[32];
    CK_ULONG bufSz;
    int result = 0;

    mech.mechanism      = CKM_SHA256_HMAC;
    mech.pParameter     = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_SignInit(session, &mech, hmacKey);
    CHECK_CKR(ret, "SignInit double: first C_SignInit", CKR_OK);

    ret = funcList->C_SignInit(session, &mech, hmacKey);
    CHECK_CKR(ret, "SignInit double: second C_SignInit",
              CKR_OPERATION_ACTIVE);

cleanup:
    bufSz = sizeof(buf);
    (void)funcList->C_Sign(session, (CK_BYTE_PTR)"abc", 3, buf, &bufSz);
    return result;
}

/*
 * Test 5: C_VerifyInit called twice without completing the operation.
 * Second call must return CKR_OPERATION_ACTIVE.
 */
static int test_verify_init_double(CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE hmacKey)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte buf[32];
    int result = 0;

    mech.mechanism      = CKM_SHA256_HMAC;
    mech.pParameter     = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_VerifyInit(session, &mech, hmacKey);
    CHECK_CKR(ret, "VerifyInit double: first C_VerifyInit", CKR_OK);

    ret = funcList->C_VerifyInit(session, &mech, hmacKey);
    CHECK_CKR(ret, "VerifyInit double: second C_VerifyInit",
              CKR_OPERATION_ACTIVE);

cleanup:
    XMEMSET(buf, 0, sizeof(buf));
    (void)funcList->C_Verify(session, (CK_BYTE_PTR)"abc", 3, buf, sizeof(buf));
    return result;
}
#endif /* !NO_HMAC */

static int operation_active_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE aesKey;
#ifndef NO_HMAC
    CK_OBJECT_HANDLE hmacKey;
#endif
    int result = 0;

    printf("\n=== Testing Init double-call returns CKR_OPERATION_ACTIVE ===\n");

    cleanup_test_files(OP_ACTIVE_TEST_DIR);

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

    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: pkcs11_open_session: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    /* Create keys */
    ret = create_aes_128_key(session, &aesKey);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: create_aes_128_key: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_close_session(session);
        pkcs11_final();
        return -1;
    }

#ifndef NO_HMAC
    ret = create_hmac_key(session, &hmacKey);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: create_hmac_key: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_close_session(session);
        pkcs11_final();
        return -1;
    }
#endif

    /* Run tests -- close and reopen the session between each test
     * to ensure no leftover operation state leaks between tests. */
    if (test_encrypt_init_double(session, aesKey) != 0)
        result = -1;
    pkcs11_close_session(session);
    session = CK_INVALID_HANDLE;
    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) goto done;

    if (test_decrypt_init_double(session, aesKey) != 0)
        result = -1;
    pkcs11_close_session(session);
    session = CK_INVALID_HANDLE;
    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) goto done;

    if (test_digest_init_double(session) != 0)
        result = -1;
    pkcs11_close_session(session);
    session = CK_INVALID_HANDLE;
    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) goto done;

#ifndef NO_HMAC
    if (test_sign_init_double(session, hmacKey) != 0)
        result = -1;
    pkcs11_close_session(session);
    session = CK_INVALID_HANDLE;
    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) goto done;

    if (test_verify_init_double(session, hmacKey) != 0)
        result = -1;
#endif

done:
    if (session != CK_INVALID_HANDLE)
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", OP_ACTIVE_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Operation Active Test (bug #1616) ===\n");

    (void)operation_active_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES || NO_AES_CBC */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES-CBC not available, skipping operation active test\n");
    return 0;
}

#endif /* !NO_AES && !NO_AES_CBC */
