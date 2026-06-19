/* aes_keywrap_pad_test.c
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
 * Test for CKM_AES_KEY_WRAP_PAD RFC 5649 conformance (bug #6060).
 *
 * The buggy implementation layered PKCS#7 padding over RFC 3394: it over-padded
 * block-aligned inputs by a whole block, used a length-encoding scheme that does
 * not match RFC 5649, and could not wrap 1-7 byte inputs at all. This test pins
 * the RFC 5649 6 test vectors and checks the wrap/unwrap roundtrip and output
 * length for inputs 1..40 bytes.
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

#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP)

#define KWP_TEST_DIR "./store/aes_keywrap_pad_test"
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

static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_KEY_TYPE aesKeyType = CKK_AES;

/* RFC 5649 6 KEK (AES-192). */
static const byte rfc5649_kek[24] = {
    0x58,0x40,0xdf,0x6e,0x29,0xb0,0x2a,0xf1,
    0xab,0x49,0x3b,0x70,0x5b,0xf1,0x6e,0xa1,
    0xae,0x83,0x38,0xf4,0xdc,0xc1,0x76,0xa8
};
/* Test vector 1: 20-byte plaintext -> 32-byte wrap. */
static const byte rfc5649_pt1[20] = {
    0xc3,0x7b,0x7e,0x64,0x92,0x58,0x43,0x40,
    0xbe,0xd1,0x22,0x07,0x80,0x89,0x41,0x15,
    0x50,0x68,0xf7,0x38
};
static const byte rfc5649_ct1[32] = {
    0x13,0x8b,0xde,0xaa,0x9b,0x8f,0xa7,0xfc,
    0x61,0xf9,0x77,0x42,0xe7,0x22,0x48,0xee,
    0x5a,0xe6,0xae,0x53,0x60,0xd1,0xae,0x6a,
    0x5f,0x54,0xf3,0x73,0xfa,0x54,0x3b,0x6a
};
/* Test vector 2: 7-byte plaintext -> 16-byte wrap (single semiblock). */
static const byte rfc5649_pt2[7] = {
    0x46,0x6f,0x72,0x50,0x61,0x73,0x69
};
static const byte rfc5649_ct2[16] = {
    0xaf,0xbe,0xb0,0xf0,0x7d,0xfb,0xf5,0x41,
    0x92,0x00,0xf2,0xcc,0xb5,0x0b,0xb2,0x4f
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

static CK_RV create_kek(CK_SESSION_HANDLE session, const byte* keyVal,
                        CK_ULONG keyLen, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_ENCRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_DECRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_WRAP,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_UNWRAP,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,    (CK_BYTE*)keyVal, keyLen                },
        { CKA_TOKEN,    &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

static CK_RV kwp_wrap(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE kek,
                      const byte* in, CK_ULONG inLen, byte* out,
                      CK_ULONG* outLen)
{
    CK_MECHANISM mech;
    CK_RV ret;

    mech.mechanism = CKM_AES_KEY_WRAP_PAD;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_EncryptInit(session, &mech, kek);
    if (ret != CKR_OK)
        return ret;
    return funcList->C_Encrypt(session, (CK_BYTE*)in, inLen, out, outLen);
}

static CK_RV kwp_unwrap(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE kek,
                        const byte* in, CK_ULONG inLen, byte* out,
                        CK_ULONG* outLen)
{
    CK_MECHANISM mech;
    CK_RV ret;

    mech.mechanism = CKM_AES_KEY_WRAP_PAD;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_DecryptInit(session, &mech, kek);
    if (ret != CKR_OK)
        return ret;
    return funcList->C_Decrypt(session, (CK_BYTE*)in, inLen, out, outLen);
}

/* Pin the two RFC 5649 6 test vectors (interoperability). */
static int test_rfc_vectors(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    byte wrapped[64];
    byte unwrapped[64];
    CK_ULONG wrappedLen, unwrappedLen;
    int result = 0;

    ret = create_kek(session, rfc5649_kek, sizeof(rfc5649_kek), &kek);
    CHECK_CKR(ret, "RFC: create AES-192 KEK", CKR_OK);

    /* Vector 1: 20 bytes -> 32 bytes */
    wrappedLen = sizeof(wrapped);
    ret = kwp_wrap(session, kek, rfc5649_pt1, sizeof(rfc5649_pt1), wrapped,
                   &wrappedLen);
    CHECK_CKR(ret, "RFC1: wrap", CKR_OK);
    CHECK_COND(wrappedLen == sizeof(rfc5649_ct1) &&
               XMEMCMP(wrapped, rfc5649_ct1, sizeof(rfc5649_ct1)) == 0,
               "RFC1: wrap matches published vector");

    unwrappedLen = sizeof(unwrapped);
    ret = kwp_unwrap(session, kek, rfc5649_ct1, sizeof(rfc5649_ct1), unwrapped,
                     &unwrappedLen);
    CHECK_CKR(ret, "RFC1: unwrap", CKR_OK);
    CHECK_COND(unwrappedLen == sizeof(rfc5649_pt1) &&
               XMEMCMP(unwrapped, rfc5649_pt1, sizeof(rfc5649_pt1)) == 0,
               "RFC1: unwrap recovers plaintext");

    /* Vector 2: 7 bytes -> 16 bytes (single semiblock) */
    wrappedLen = sizeof(wrapped);
    ret = kwp_wrap(session, kek, rfc5649_pt2, sizeof(rfc5649_pt2), wrapped,
                   &wrappedLen);
    CHECK_CKR(ret, "RFC2: wrap", CKR_OK);
    CHECK_COND(wrappedLen == sizeof(rfc5649_ct2) &&
               XMEMCMP(wrapped, rfc5649_ct2, sizeof(rfc5649_ct2)) == 0,
               "RFC2: wrap matches published vector");

    unwrappedLen = sizeof(unwrapped);
    ret = kwp_unwrap(session, kek, rfc5649_ct2, sizeof(rfc5649_ct2), unwrapped,
                     &unwrappedLen);
    CHECK_CKR(ret, "RFC2: unwrap", CKR_OK);
    CHECK_COND(unwrappedLen == sizeof(rfc5649_pt2) &&
               XMEMCMP(unwrapped, rfc5649_pt2, sizeof(rfc5649_pt2)) == 0,
               "RFC2: unwrap recovers plaintext");

cleanup:
    if (kek != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, kek);
    return result;
}

/* Wrap/unwrap roundtrip for every length 1..40, checking the wrapped length is
 * roundup8(len)+8 and the recovered plaintext matches. */
static int test_roundtrip_lengths(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    byte plain[40];
    byte wrapped[64];
    byte unwrapped[64];
    CK_ULONG len;
    int result = 0;
    char msg[96];

    for (len = 0; len < sizeof(plain); len++)
        plain[len] = (byte)(0x10 + len);

    ret = create_kek(session, rfc5649_kek, sizeof(rfc5649_kek), &kek);
    CHECK_CKR(ret, "Roundtrip: create AES-192 KEK", CKR_OK);

    for (len = 1; len <= sizeof(plain); len++) {
        CK_ULONG wrappedLen = sizeof(wrapped);
        CK_ULONG unwrappedLen = sizeof(unwrapped);
        CK_ULONG expWrapped = ((len + 7) & ~(CK_ULONG)7) + 8;

        ret = kwp_wrap(session, kek, plain, len, wrapped, &wrappedLen);
        snprintf(msg, sizeof(msg), "Roundtrip len=%lu: wrap",
                 (unsigned long)len);
        CHECK_CKR(ret, msg, CKR_OK);

        snprintf(msg, sizeof(msg),
                 "Roundtrip len=%lu: wrapped length is roundup8(len)+8",
                 (unsigned long)len);
        CHECK_COND(wrappedLen == expWrapped, msg);

        ret = kwp_unwrap(session, kek, wrapped, wrappedLen, unwrapped,
                         &unwrappedLen);
        snprintf(msg, sizeof(msg), "Roundtrip len=%lu: unwrap",
                 (unsigned long)len);
        CHECK_CKR(ret, msg, CKR_OK);

        snprintf(msg, sizeof(msg),
                 "Roundtrip len=%lu: recovered plaintext matches",
                 (unsigned long)len);
        CHECK_COND(unwrappedLen == len &&
                   XMEMCMP(unwrapped, plain, len) == 0, msg);
    }

cleanup:
    if (kek != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, kek);
    return result;
}

/*
 * Corrupted or wrong-length wrapped blobs must be rejected, exercising the
 * AIV/length validation paths in the unwrap (single-semiblock and multi-block).
 */
static int test_unwrap_rejects(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE kek = CK_INVALID_HANDLE;
    byte wrapped[64];
    byte out[64];
    CK_ULONG wrappedLen, outLen;
    int result = 0;

    ret = create_kek(session, rfc5649_kek, sizeof(rfc5649_kek), &kek);
    CHECK_CKR(ret, "Reject: create AES-192 KEK", CKR_OK);

    /* Multi-block blob: tampering a byte must fail the AIV/integrity check. */
    wrappedLen = sizeof(wrapped);
    ret = kwp_wrap(session, kek, rfc5649_pt1, sizeof(rfc5649_pt1), wrapped,
                   &wrappedLen);
    CHECK_CKR(ret, "Reject: wrap multi-block", CKR_OK);
    wrapped[0] ^= 0x80;
    outLen = sizeof(out);
    ret = kwp_unwrap(session, kek, wrapped, wrappedLen, out, &outLen);
    CHECK_CKR(ret, "Reject: tampered multi-block unwrap",
              CKR_ENCRYPTED_DATA_INVALID);

    /* Single-semiblock blob: tampering a byte must fail. */
    wrappedLen = sizeof(wrapped);
    ret = kwp_wrap(session, kek, rfc5649_pt2, sizeof(rfc5649_pt2), wrapped,
                   &wrappedLen);
    CHECK_CKR(ret, "Reject: wrap single-block", CKR_OK);
    wrapped[wrappedLen - 1] ^= 0x01;
    outLen = sizeof(out);
    ret = kwp_unwrap(session, kek, wrapped, wrappedLen, out, &outLen);
    CHECK_CKR(ret, "Reject: tampered single-block unwrap",
              CKR_ENCRYPTED_DATA_INVALID);

    /* Ciphertext length not a multiple of 8 must be rejected. */
    wrappedLen = sizeof(wrapped);
    ret = kwp_wrap(session, kek, rfc5649_pt1, sizeof(rfc5649_pt1), wrapped,
                   &wrappedLen);
    CHECK_CKR(ret, "Reject: wrap for length checks", CKR_OK);
    outLen = sizeof(out);
    ret = kwp_unwrap(session, kek, wrapped, wrappedLen - 1, out, &outLen);
    CHECK_CKR(ret, "Reject: non-block-aligned ciphertext",
              CKR_ENCRYPTED_DATA_LEN_RANGE);

    /* Ciphertext shorter than two semiblocks must be rejected. */
    outLen = sizeof(out);
    ret = kwp_unwrap(session, kek, wrapped, 8, out, &outLen);
    CHECK_CKR(ret, "Reject: too-short ciphertext",
              CKR_ENCRYPTED_DATA_LEN_RANGE);

cleanup:
    if (kek != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, kek);
    return result;
}

static int aes_keywrap_pad_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int result = 0;

    printf("\n=== Testing CKM_AES_KEY_WRAP_PAD (RFC 5649) ===\n");

    cleanup_test_files(KWP_TEST_DIR);

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
    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: pkcs11_open_session: 0x%lx\n",
                (unsigned long)ret);
        test_failed++;
        pkcs11_final();
        return -1;
    }

    if (test_rfc_vectors(session) != 0)
        result = -1;
    if (test_roundtrip_lengths(session) != 0)
        result = -1;
    if (test_unwrap_rejects(session) != 0)
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

    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", KWP_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 AES-KEY-WRAP-PAD RFC 5649 Test ===\n");

    (void)aes_keywrap_pad_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES || !HAVE_AES_KEYWRAP */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES key wrap not available, skipping RFC 5649 test\n");
    return 0;
}

#endif /* !NO_AES && HAVE_AES_KEYWRAP */
