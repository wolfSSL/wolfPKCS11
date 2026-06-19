/* aes_gcm_decrypt_len_test.c
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
 * Regression test for issue F-3850: C_Decrypt with CKM_AES_GCM must reject
 * ciphertext shorter than the authentication tag with
 * CKR_ENCRYPTED_DATA_LEN_RANGE. Without that guard the length subtraction
 * (decDataLen = ulEncryptedDataLen - tagBits/8) underflows.
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

#if !defined(NO_AES) && defined(HAVE_AESGCM)

#define GCM_LEN_TEST_DIR "./store/aes_gcm_decrypt_len_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

/* tagBits = 128 -> minimum ciphertext length is 16 bytes */
#define GCM_TAG_BITS    128
#define GCM_MIN_CT_LEN  (GCM_TAG_BITS / 8)

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

static void gcm_mech_init(CK_MECHANISM* mech, CK_GCM_PARAMS* gcmParams,
                          byte* iv, CK_ULONG ivLen)
{
    XMEMSET(iv, 9, ivLen);
    gcmParams->pIv       = iv;
    gcmParams->ulIvLen   = ivLen;
    gcmParams->pAAD      = NULL;
    gcmParams->ulAADLen  = 0;
    gcmParams->ulTagBits = GCM_TAG_BITS;

    mech->mechanism      = CKM_AES_GCM;
    mech->ulParameterLen = sizeof(*gcmParams);
    mech->pParameter     = gcmParams;
}

/*
 * Test 1: C_Decrypt with ciphertext shorter than the tag (0, 1, 15 bytes) must
 * be rejected with CKR_ENCRYPTED_DATA_LEN_RANGE. The operation is deinitialized
 * on rejection, so it is re-initialized before each attempt.
 */
static int test_gcm_short_ciphertext(CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_GCM_PARAMS gcmParams;
    byte iv[12];
    byte encBuf[GCM_MIN_CT_LEN];
    byte dec[32];
    CK_ULONG decSz;
    CK_ULONG shortLens[3];
    int i;
    int result = 0;

    shortLens[0] = 0;
    shortLens[1] = 1;
    shortLens[2] = GCM_MIN_CT_LEN - 1; /* 15 */
    XMEMSET(encBuf, 0, sizeof(encBuf));

    for (i = 0; i < 3; i++) {
        gcm_mech_init(&mech, &gcmParams, iv, sizeof(iv));
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "Test1: C_DecryptInit (short ciphertext)", CKR_OK);

        decSz = sizeof(dec);
        ret = funcList->C_Decrypt(session, encBuf, shortLens[i], dec, &decSz);
        CHECK_CKR(ret, "Test1: C_Decrypt short ciphertext rejected",
                  CKR_ENCRYPTED_DATA_LEN_RANGE);
    }

cleanup:
    return result;
}

/*
 * Test 2: Boundary case. Ciphertext of exactly tagBits/8 (16) bytes must NOT be
 * rejected by the length check (catches a '<' -> '<=' mutation). A size query
 * (pData == NULL) returns CKR_OK with a derived length of 0; the subsequent
 * real decrypt of a 16-byte all-zero buffer fails authentication and returns
 * CKR_ENCRYPTED_DATA_INVALID, proving the call reached actual decryption.
 */
static int test_gcm_boundary_ciphertext(CK_SESSION_HANDLE session,
                                        CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_GCM_PARAMS gcmParams;
    byte iv[12];
    byte encBuf[GCM_MIN_CT_LEN];
    byte dec[32];
    CK_ULONG decSz;
    int result = 0;

    XMEMSET(encBuf, 0, sizeof(encBuf));

    gcm_mech_init(&mech, &gcmParams, iv, sizeof(iv));
    ret = funcList->C_DecryptInit(session, &mech, key);
    CHECK_CKR(ret, "Test2: C_DecryptInit (boundary)", CKR_OK);

    decSz = 0;
    ret = funcList->C_Decrypt(session, encBuf, GCM_MIN_CT_LEN, NULL, &decSz);
    CHECK_CKR(ret, "Test2: C_Decrypt boundary len=16 not length-rejected",
              CKR_OK);

    if (decSz != 0) {
        fprintf(stderr, "FAIL: Test2: expected derived length 0, got %lu\n",
                (unsigned long)decSz);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: Test2: boundary derived length is 0\n");
    test_passed++;

    decSz = sizeof(dec);
    ret = funcList->C_Decrypt(session, encBuf, GCM_MIN_CT_LEN, dec, &decSz);
    CHECK_CKR(ret, "Test2: C_Decrypt boundary reaches authentication",
              CKR_ENCRYPTED_DATA_INVALID);

cleanup:
    return result;
}

static int aes_gcm_decrypt_len_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key;
    int result = 0;

    printf("\n=== Testing AES-GCM C_Decrypt minimum ciphertext length ===\n");

    cleanup_test_files(GCM_LEN_TEST_DIR);

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

    if (test_gcm_short_ciphertext(session, key) != 0)
        result = -1;
    if (test_gcm_boundary_ciphertext(session, key) != 0)
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", GCM_LEN_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 AES-GCM Decrypt Length Range Test ===\n");

    (void)aes_gcm_decrypt_len_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES || !HAVE_AESGCM */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES-GCM not available, skipping decrypt length range test\n");
    return 0;
}

#endif /* !NO_AES && HAVE_AESGCM */
