/* ecb_check_value_error_test.c
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
 * Test for GetEcbCheckValue error propagation (bug #496).
 *
 * GetEcbCheckValue always returns CKR_OK even when WP11_AesEcb_Encrypt fails.
 * A generic secret key with an invalid AES key length (e.g. 5 bytes) causes
 * the encrypt to fail, but C_GetAttributeValue still returns CKR_OK with
 * uninitialized output.
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

#ifdef HAVE_AESECB

#define ECB_CV_TEST_DIR "./store/ecb_check_value_error_test"
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

/*
 * Test 1 (positive control): Create a 16-byte CKK_GENERIC_SECRET key and
 * query CKA_CHECK_VALUE. Expect CKR_OK and a 3-byte result.
 */
static int test_valid_key_check_value(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    unsigned char keyData[16];
    unsigned char checkValue[3];
    CK_ULONG checkLen = sizeof(checkValue);
    int result = 0;

    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &keyType,        sizeof(keyType)        },
        { CKA_VALUE,    keyData,         sizeof(keyData)        },
        { CKA_TOKEN,    &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ULONG createTmplCnt = sizeof(createTmpl) / sizeof(*createTmpl);

    CK_ATTRIBUTE getTmpl[] = {
        { CKA_CHECK_VALUE, checkValue, checkLen },
    };

    XMEMSET(keyData, 0xAA, sizeof(keyData));
    XMEMSET(checkValue, 0, sizeof(checkValue));

    ret = funcList->C_CreateObject(session, createTmpl, createTmplCnt, &key);
    CHECK_CKR(ret, "Test1: C_CreateObject (16-byte generic secret)", CKR_OK);

    ret = funcList->C_GetAttributeValue(session, key, getTmpl, 1);
    CHECK_CKR(ret, "Test1: C_GetAttributeValue CKA_CHECK_VALUE", CKR_OK);

    if (getTmpl[0].ulValueLen != 3) {
        fprintf(stderr,
                "FAIL: Test1: expected check value length 3, got %lu\n",
                (unsigned long)getTmpl[0].ulValueLen);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: Test1: check value length is 3\n");
    test_passed++;

    /* Verify not all zeros (encrypt of zero block should produce non-zero) */
    if (checkValue[0] == 0 && checkValue[1] == 0 && checkValue[2] == 0) {
        fprintf(stderr,
                "FAIL: Test1: check value is all zeros (likely not computed)\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: Test1: check value is non-zero: %02x%02x%02x\n",
           checkValue[0], checkValue[1], checkValue[2]);
    test_passed++;

cleanup:
    return result;
}

/*
 * Test 2 (bug demonstration): Create a 5-byte CKK_GENERIC_SECRET key and
 * query CKA_CHECK_VALUE. The 5-byte key is not a valid AES key length, so
 * WP11_AesEcb_Encrypt (called by GetEcbCheckValue) fails internally.
 *
 * BUG #496: GetEcbCheckValue always returns CKR_OK regardless of whether the
 * encrypt succeeded. This test expects CKR_OK (proving the bug exists).
 * Once the bug is fixed, this test should be updated to expect
 * CKR_FUNCTION_FAILED.
 */
static int test_invalid_key_check_value(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    unsigned char keyData[5];
    unsigned char checkValue[3];
    CK_ULONG checkLen = sizeof(checkValue);
    int result = 0;

    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &keyType,        sizeof(keyType)        },
        { CKA_VALUE,    keyData,         sizeof(keyData)        },
        { CKA_TOKEN,    &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ULONG createTmplCnt = sizeof(createTmpl) / sizeof(*createTmpl);

    CK_ATTRIBUTE getTmpl[] = {
        { CKA_CHECK_VALUE, checkValue, checkLen },
    };

    XMEMSET(keyData, 0xBB, sizeof(keyData));
    XMEMSET(checkValue, 0, sizeof(checkValue));

    ret = funcList->C_CreateObject(session, createTmpl, createTmplCnt, &key);
    CHECK_CKR(ret, "Test2: C_CreateObject (5-byte generic secret)", CKR_OK);

    ret = funcList->C_GetAttributeValue(session, key, getTmpl, 1);

    /*
     * BUG #496: GetEcbCheckValue returns CKR_OK even though
     * WP11_AesEcb_Encrypt failed (5 bytes is not a valid AES key length).
     * The correct behavior is to return CKR_FUNCTION_FAILED.
     */
    CHECK_CKR(ret, "Test2: C_GetAttributeValue CKA_CHECK_VALUE (5-byte key)",
              CKR_FUNCTION_FAILED);

cleanup:
    return result;
}

static int ecb_check_value_error_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int result = 0;

    printf("\n=== Testing GetEcbCheckValue error propagation ===\n");

    cleanup_test_files(ECB_CV_TEST_DIR);

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

    /* Test 1: Valid 16-byte key — positive control */
    if (test_valid_key_check_value(session) != 0)
        result = -1;

    /* Test 2: Invalid 5-byte key — demonstrates bug #496 */
    if (test_invalid_key_check_value(session) != 0)
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", ECB_CV_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 GetEcbCheckValue Error Propagation Test ===\n");

    (void)ecb_check_value_error_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* !HAVE_AESECB */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES-ECB not available, skipping GetEcbCheckValue test\n");
    return 0;
}

#endif /* HAVE_AESECB */
