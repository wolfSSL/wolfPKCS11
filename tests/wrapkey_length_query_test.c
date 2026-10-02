/* wrapkey_length_query_test.c
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
 * Test that C_WrapKey with an AES mechanism can be called first to get the
 * output length (pWrappedKey NULL) or with a buffer that is too small, and
 * then again to wrap, as PKCS #11 allows and as NSS does when exporting a
 * key to PKCS #12. The second call must not fail with CKR_OPERATION_ACTIVE.
 * The wrapped output is compared with a known answer computed by OpenSSL:
 *   openssl enc -aes-256-cbc -K <wrapKey> -iv <iv>  over <keyValue>
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

#if !defined(NO_AES) && !defined(NO_AES_CBC) && defined(WOLFSSL_AES_256) && \
    (defined(WOLFSSL_STM32U5_DHUK) || !defined(WOLFPKCS11_NO_STORE))

#define TEST_DIR "./store/wrapkey_length_query_test"

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_CKR(rv, op, expected) do {                    \
    if ((rv) != (expected)) {                               \
        fprintf(stderr, "FAIL: %s: expected 0x%lx, got 0x%lx\n", op, \
            (unsigned long)(expected), (unsigned long)(rv)); \
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
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;
static CK_BBOOL ckTrue = CK_TRUE;

static unsigned char wrapKeyValue[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char keyValue[16] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};
static unsigned char iv[16] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
};
/* openssl enc -aes-256-cbc -K 000102...1f -iv a0a1...af (PKCS#7 padding) */
static const unsigned char expected[32] = {
    0x75, 0x68, 0xef, 0xf0, 0x7a, 0x6b, 0xdd, 0x1f,
    0xde, 0x75, 0xc3, 0x89, 0x27, 0x6e, 0x41, 0x35,
    0x5f, 0xd3, 0x74, 0xec, 0x49, 0xc6, 0xdb, 0x2b,
    0x49, 0x5a, 0x28, 0xbd, 0x94, 0xf2, 0xa7, 0x9a
};

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
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        return CKR_GENERAL_ERROR;
    }
    ret = func(&funcList);
#else
    ret = C_GetFunctionList(&funcList);
#endif
    if (ret != CKR_OK)
        return ret;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (ret != CKR_OK)
        return ret;
    if (slotCount == 0)
        return CKR_GENERAL_ERROR;
    slot = slotList[0];
    return CKR_OK;
}

static void pkcs11_final(void)
{
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
        funcList = NULL;
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}

static CK_RV open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wrapkey test", 12);
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL, session);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_Login(*session, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK)
        ret = funcList->C_InitPIN(*session, userPin, userPinLen);
    if (ret == CKR_OK)
        ret = funcList->C_Logout(*session);
    if (ret == CKR_OK)
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    return ret;
}

static CK_RV create_aes_key(CK_SESSION_HANDLE session, unsigned char* value,
    CK_ULONG len, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_WRAP,        &ckTrue,         sizeof(ckTrue)         },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,       value,           len                    },
    };
    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(tmpl[0]), key);
}

static int wrapkey_length_query_test(void)
{
    int result = 0;
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE wrapKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    unsigned char out[64];
    CK_ULONG outLen;

    rv = pkcs11_init();
    CHECK_CKR(rv, "Initialize", CKR_OK);
    rv = open_session(&session);
    CHECK_CKR(rv, "Token, PIN and user login", CKR_OK);
    rv = create_aes_key(session, wrapKeyValue, sizeof(wrapKeyValue), &wrapKey);
    CHECK_CKR(rv, "Create wrapping key", CKR_OK);
    rv = create_aes_key(session, keyValue, sizeof(keyValue), &key);
    CHECK_CKR(rv, "Create key to wrap", CKR_OK);

    /* Length query, then the wrap. */
    outLen = 0;
    rv = funcList->C_WrapKey(session, &mech, wrapKey, key, NULL, &outLen);
    CHECK_CKR(rv, "C_WrapKey length query", CKR_OK);
    if (outLen != sizeof(expected)) {
        fprintf(stderr, "FAIL: length query returned %lu, want %lu\n",
            (unsigned long)outLen, (unsigned long)sizeof(expected));
        test_failed++;
        result = -1;
        goto cleanup;
    }
    outLen = sizeof(out);
    rv = funcList->C_WrapKey(session, &mech, wrapKey, key, out, &outLen);
    CHECK_CKR(rv, "C_WrapKey after length query", CKR_OK);
    if (outLen != sizeof(expected) || XMEMCMP(out, expected, outLen) != 0) {
        fprintf(stderr, "FAIL: wrapped key differs from the known answer\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: wrapped key matches the known answer\n");
    test_passed++;

    /* Too-small buffer, then the wrap. */
    outLen = 1;
    rv = funcList->C_WrapKey(session, &mech, wrapKey, key, out, &outLen);
    CHECK_CKR(rv, "C_WrapKey with a short buffer", CKR_BUFFER_TOO_SMALL);
    outLen = sizeof(out);
    rv = funcList->C_WrapKey(session, &mech, wrapKey, key, out, &outLen);
    CHECK_CKR(rv, "C_WrapKey after a short buffer", CKR_OK);
    if (outLen != sizeof(expected) || XMEMCMP(out, expected, outLen) != 0) {
        fprintf(stderr, "FAIL: wrapped key differs from the known answer\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: wrapped key after a short buffer matches the known answer\n");
    test_passed++;

cleanup:
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();
    return result;
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 C_WrapKey length query test ===\n");

    (void)wrapkey_length_query_test();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    return (test_failed == 0) ? 0 : 1;
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("AES-CBC with 256-bit keys or AES key wrapping not available, "
           "skipping test\n");
    return 77;
}

#endif
