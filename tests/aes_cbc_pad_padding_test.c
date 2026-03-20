/* aes_cbc_pad_padding_test.c
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
 * Test for AES-CBC-PAD PKCS#7 padding validation (bug #821).
 *
 * WP11_AesCbcPad_DecryptFinal does not validate that all padding bytes equal
 * the pad count. Tampered ciphertext decrypts without error, silently returning
 * incorrect plaintext.
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

#define CBC_PAD_TEST_DIR "./store/cbc_pad_padding_test"
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

/*
 * Test 1: Valid encrypt/decrypt roundtrip (baseline).
 * 20-byte plaintext -> 32 bytes ciphertext (2 blocks, 12 bytes padding).
 */
static int test_valid_roundtrip(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE key,
                                unsigned char* cipherOut,
                                CK_ULONG* cipherOutLen)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte plain[20], dec[32], iv[16];
    CK_ULONG encSz, decSz;
    int result = 0;

    XMEMSET(plain, 9, sizeof(plain));
    XMEMSET(iv, 9, sizeof(iv));

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = sizeof(iv);
    mech.pParameter     = iv;

    /* Encrypt */
    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "Test1: C_EncryptInit", CKR_OK);

    encSz = *cipherOutLen;
    ret = funcList->C_Encrypt(session, plain, sizeof(plain), cipherOut, &encSz);
    CHECK_CKR(ret, "Test1: C_Encrypt", CKR_OK);

    if (encSz != 32) {
        fprintf(stderr, "FAIL: Test1: expected 32 bytes ciphertext, got %lu\n",
                (unsigned long)encSz);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: Test1: ciphertext length is 32\n");
    test_passed++;
    *cipherOutLen = encSz;

    /* Decrypt */
    ret = funcList->C_DecryptInit(session, &mech, key);
    CHECK_CKR(ret, "Test1: C_DecryptInit", CKR_OK);

    decSz = sizeof(dec);
    ret = funcList->C_Decrypt(session, cipherOut, encSz, dec, &decSz);
    CHECK_CKR(ret, "Test1: C_Decrypt", CKR_OK);

    if (decSz != sizeof(plain) || XMEMCMP(dec, plain, sizeof(plain)) != 0) {
        fprintf(stderr, "FAIL: Test1: decrypted plaintext mismatch\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: Test1: plaintext roundtrip matches\n");
    test_passed++;

cleanup:
    return result;
}

/*
 * Test 2: Tamper last byte of ciphertext, one-shot C_Decrypt.
 * Flipping a bit in the last block produces garbage padding after decryption.
 * Expected: CKR_ENCRYPTED_DATA_INVALID.
 */
static int test_tampered_last_byte_oneshot(CK_SESSION_HANDLE session,
                                           CK_OBJECT_HANDLE key,
                                           unsigned char* cipher,
                                           CK_ULONG cipherLen)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte dec[32], iv[16], tampered[32];
    CK_ULONG decSz;
    int result = 0;

    XMEMSET(iv, 9, sizeof(iv));
    XMEMCPY(tampered, cipher, cipherLen);
    tampered[cipherLen - 1] ^= 0x01; /* flip one bit in last byte */

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = sizeof(iv);
    mech.pParameter     = iv;

    ret = funcList->C_DecryptInit(session, &mech, key);
    CHECK_CKR(ret, "Test2: C_DecryptInit", CKR_OK);

    decSz = sizeof(dec);
    ret = funcList->C_Decrypt(session, tampered, cipherLen, dec, &decSz);
    CHECK_CKR(ret, "Test2: C_Decrypt tampered last byte",
              CKR_ENCRYPTED_DATA_INVALID);

cleanup:
    return result;
}

/*
 * Test 3: Tamper last byte of ciphertext, multi-part C_DecryptUpdate/Final.
 * Expected: C_DecryptFinal returns CKR_FUNCTION_FAILED.
 */
static int test_tampered_last_byte_multipart(CK_SESSION_HANDLE session,
                                              CK_OBJECT_HANDLE key,
                                              unsigned char* cipher,
                                              CK_ULONG cipherLen)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte dec[48], iv[16], tampered[32], lastPart[16];
    CK_ULONG decSz, lastPartLen;
    int result = 0;

    XMEMSET(iv, 9, sizeof(iv));
    XMEMCPY(tampered, cipher, cipherLen);
    tampered[cipherLen - 1] ^= 0x01;

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = sizeof(iv);
    mech.pParameter     = iv;

    ret = funcList->C_DecryptInit(session, &mech, key);
    CHECK_CKR(ret, "Test3: C_DecryptInit", CKR_OK);

    decSz = sizeof(dec);
    ret = funcList->C_DecryptUpdate(session, tampered, cipherLen, dec, &decSz);
    CHECK_CKR(ret, "Test3: C_DecryptUpdate", CKR_OK);

    lastPartLen = sizeof(lastPart);
    ret = funcList->C_DecryptFinal(session, lastPart, &lastPartLen);
    CHECK_CKR(ret, "Test3: C_DecryptFinal tampered last byte",
              CKR_FUNCTION_FAILED);

cleanup:
    return result;
}

/*
 * Test 4: Tamper last byte of first block, one-shot C_Decrypt.
 * Corrupting the first block changes the CBC chain for the second (padding)
 * block, producing invalid padding.
 * Expected: CKR_ENCRYPTED_DATA_INVALID.
 */
static int test_tampered_first_block_oneshot(CK_SESSION_HANDLE session,
                                             CK_OBJECT_HANDLE key,
                                             unsigned char* cipher,
                                             CK_ULONG cipherLen)
{
    CK_RV ret;
    CK_MECHANISM mech;
    byte dec[32], iv[16], tampered[32];
    CK_ULONG decSz;
    int result = 0;

    XMEMSET(iv, 9, sizeof(iv));
    XMEMCPY(tampered, cipher, cipherLen);
    tampered[15] ^= 0x01; /* flip one bit in last byte of first block */

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = sizeof(iv);
    mech.pParameter     = iv;

    ret = funcList->C_DecryptInit(session, &mech, key);
    CHECK_CKR(ret, "Test4: C_DecryptInit", CKR_OK);

    decSz = sizeof(dec);
    ret = funcList->C_Decrypt(session, tampered, cipherLen, dec, &decSz);
    CHECK_CKR(ret, "Test4: C_Decrypt tampered first block",
              CKR_ENCRYPTED_DATA_INVALID);

cleanup:
    return result;
}

static int aes_cbc_pad_padding_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key;
    unsigned char cipher[48];
    CK_ULONG cipherLen;
    int result = 0;

    printf("\n=== Testing AES-CBC-PAD padding validation ===\n");

    cleanup_test_files(CBC_PAD_TEST_DIR);

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

    /* Test 1: Valid roundtrip — also produces ciphertext for tamper tests */
    cipherLen = sizeof(cipher);
    if (test_valid_roundtrip(session, key, cipher, &cipherLen) != 0)
        result = -1;

    /* Tests 2-4 only run if test 1 produced valid ciphertext */
    if (result == 0) {
        if (test_tampered_last_byte_oneshot(session, key, cipher,
                                            cipherLen) != 0)
            result = -1;
        if (test_tampered_last_byte_multipart(session, key, cipher,
                                               cipherLen) != 0)
            result = -1;
        if (test_tampered_first_block_oneshot(session, key, cipher,
                                              cipherLen) != 0)
            result = -1;
    }

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
    XSETENV("WOLFPKCS11_TOKEN_PATH", CBC_PAD_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 AES-CBC-PAD Padding Validation Test ===\n");

    (void)aes_cbc_pad_padding_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES || NO_AES_CBC */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES-CBC not available, skipping padding validation test\n");
    return 0;
}

#endif /* !NO_AES && !NO_AES_CBC */
