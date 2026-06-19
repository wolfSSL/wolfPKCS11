/* aes_ctr_counterbits_test.c
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
 * Regression test for issue F-5523: AES-CTR setup must reject CK_AES_CTR_PARAMS
 * with ulCounterBits == 0 or > 128 (CKR_MECHANISM_PARAM_INVALID) in both
 * C_EncryptInit and C_DecryptInit, while accepting the valid value 128.
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

#if !defined(NO_AES) && defined(HAVE_AESCTR)

#define CTR_BITS_TEST_DIR "./store/aes_ctr_counterbits_test"
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

static void ctr_mech_init(CK_MECHANISM* mech, CK_AES_CTR_PARAMS* ctrParams,
                          CK_ULONG counterBits)
{
    XMEMSET(ctrParams->cb, 0, sizeof(ctrParams->cb));
    ctrParams->ulCounterBits = counterBits;

    mech->mechanism      = CKM_AES_CTR;
    mech->pParameter     = ctrParams;
    mech->ulParameterLen = sizeof(*ctrParams);
}

/*
 * C_EncryptInit: ulCounterBits of 0 and 129 are rejected with
 * CKR_MECHANISM_PARAM_INVALID; 128 is accepted (and a block is encrypted to
 * leave the session clean).
 */
static int test_ctr_encrypt_init(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_AES_CTR_PARAMS ctrParams;
    byte plain[16], enc[16];
    CK_ULONG encSz;
    int result = 0;

    ctr_mech_init(&mech, &ctrParams, 0);
    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "C_EncryptInit ulCounterBits=0 rejected",
              CKR_MECHANISM_PARAM_INVALID);

    ctr_mech_init(&mech, &ctrParams, 129);
    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "C_EncryptInit ulCounterBits=129 rejected",
              CKR_MECHANISM_PARAM_INVALID);

    ctr_mech_init(&mech, &ctrParams, 128);
    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "C_EncryptInit ulCounterBits=128 accepted", CKR_OK);

    XMEMSET(plain, 9, sizeof(plain));
    encSz = sizeof(enc);
    ret = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encSz);
    CHECK_CKR(ret, "C_Encrypt ulCounterBits=128", CKR_OK);

cleanup:
    return result;
}

/*
 * C_DecryptInit: ulCounterBits of 0 and 129 are rejected with
 * CKR_MECHANISM_PARAM_INVALID; 128 is accepted (and a block is decrypted to
 * leave the session clean).
 */
static int test_ctr_decrypt_init(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_AES_CTR_PARAMS ctrParams;
    byte enc[16], dec[16];
    CK_ULONG decSz;
    int result = 0;

    ctr_mech_init(&mech, &ctrParams, 0);
    ret = funcList->C_DecryptInit(session, &mech, key);
    CHECK_CKR(ret, "C_DecryptInit ulCounterBits=0 rejected",
              CKR_MECHANISM_PARAM_INVALID);

    ctr_mech_init(&mech, &ctrParams, 129);
    ret = funcList->C_DecryptInit(session, &mech, key);
    CHECK_CKR(ret, "C_DecryptInit ulCounterBits=129 rejected",
              CKR_MECHANISM_PARAM_INVALID);

    ctr_mech_init(&mech, &ctrParams, 128);
    ret = funcList->C_DecryptInit(session, &mech, key);
    CHECK_CKR(ret, "C_DecryptInit ulCounterBits=128 accepted", CKR_OK);

    XMEMSET(enc, 9, sizeof(enc));
    decSz = sizeof(dec);
    ret = funcList->C_Decrypt(session, enc, sizeof(enc), dec, &decSz);
    CHECK_CKR(ret, "C_Decrypt ulCounterBits=128", CKR_OK);

cleanup:
    return result;
}

static int run_aes_ctr_counterbits_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key;
    int result = 0;

    printf("\n=== Testing AES-CTR ulCounterBits range validation ===\n");

    cleanup_test_files(CTR_BITS_TEST_DIR);

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

    ret = create_aes_128_key(session, &key);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: create_aes_128_key: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_close_session(session);
        pkcs11_final();
        return -1;
    }

    if (test_ctr_encrypt_init(session, key) != 0)
        result = -1;
    if (test_ctr_decrypt_init(session, key) != 0)
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", CTR_BITS_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 AES-CTR Counter Bits Range Test ===\n");

    (void)run_aes_ctr_counterbits_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES || !HAVE_AESCTR */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES-CTR not available, skipping counter bits range test\n");
    return 0;
}

#endif /* !NO_AES && HAVE_AESCTR */
