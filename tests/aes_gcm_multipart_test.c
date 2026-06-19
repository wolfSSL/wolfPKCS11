/* aes_gcm_multipart_test.c
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
 * Test for CKM_AES_GCM multi-part vs single-shot equivalence (bug #4068).
 *
 * The buggy C_EncryptUpdate re-ran the one-shot wc_AesGcmEncrypt per call,
 * reusing the IV for every segment, authenticating only the last segment and
 * dropping AAD after the first segment. The multi-part ciphertext+tag therefore
 * differed from the single-shot result whenever more than one update was issued.
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

#define GCM_MP_TEST_DIR "./store/aes_gcm_multipart_test"
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

static CK_RV create_aes_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_ENCRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_DECRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,    aes_128_key,     sizeof(aes_128_key)    },
        { CKA_TOKEN,    &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, tmplCnt, key);
}

static void init_gcm_mech(CK_MECHANISM* mech, CK_GCM_PARAMS* params,
                          CK_BYTE* iv, CK_ULONG ivLen, CK_BYTE* aad,
                          CK_ULONG aadLen, CK_ULONG tagBits)
{
    params->pIv       = iv;
    params->ulIvLen   = ivLen;
    params->pAAD      = aad;
    params->ulAADLen  = aadLen;
    params->ulTagBits = tagBits;

    mech->mechanism      = CKM_AES_GCM;
    mech->ulParameterLen = sizeof(*params);
    mech->pParameter     = params;
}

/* Single-shot encrypt of the whole plaintext. */
static CK_RV gcm_single(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                        CK_BYTE* iv, CK_ULONG ivLen, CK_BYTE* aad,
                        CK_ULONG aadLen, CK_ULONG tagBits, CK_BYTE* plain,
                        CK_ULONG plainLen, CK_BYTE* out, CK_ULONG* outLen)
{
    CK_MECHANISM mech;
    CK_GCM_PARAMS params;
    CK_RV ret;

    init_gcm_mech(&mech, &params, iv, ivLen, aad, aadLen, tagBits);
    ret = funcList->C_EncryptInit(session, &mech, key);
    if (ret != CKR_OK)
        return ret;
    return funcList->C_Encrypt(session, plain, plainLen, out, outLen);
}

/*
 * Encrypt the same plaintext split into npart segments via
 * C_EncryptUpdate/C_EncryptFinal and compare the concatenated result with the
 * single-shot ciphertext+tag.
 */
static int gcm_multipart_equiv(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                               CK_BYTE* aad, CK_ULONG aadLen,
                               const CK_ULONG* parts, int nparts,
                               const char* label)
{
    CK_MECHANISM mech;
    CK_GCM_PARAMS params;
    CK_RV ret;
    CK_BYTE iv[12];
    CK_BYTE plain[64];
    CK_BYTE single[sizeof(plain) + 16];
    CK_BYTE multi[sizeof(plain) + 16];
    CK_ULONG singleLen, multiLen, off, plainLen, i;
    CK_ULONG tagBits = 128;
    int p;
    int result = 0;
    char msg[128];

    XMEMSET(iv, 7, sizeof(iv));
    for (i = 0; i < sizeof(plain); i++)
        plain[i] = (CK_BYTE)(i * 3 + 1);

    plainLen = 0;
    for (p = 0; p < nparts; p++)
        plainLen += parts[p];

    /* Single-shot reference */
    singleLen = sizeof(single);
    ret = gcm_single(session, key, iv, sizeof(iv), aad, aadLen, tagBits,
                     plain, plainLen, single, &singleLen);
    snprintf(msg, sizeof(msg), "%s: single-shot C_Encrypt", label);
    CHECK_CKR(ret, msg, CKR_OK);

    /* Multi-part */
    init_gcm_mech(&mech, &params, iv, sizeof(iv), aad, aadLen, tagBits);
    ret = funcList->C_EncryptInit(session, &mech, key);
    snprintf(msg, sizeof(msg), "%s: multi-part C_EncryptInit", label);
    CHECK_CKR(ret, msg, CKR_OK);

    off = 0;
    multiLen = 0;
    for (p = 0; p < nparts; p++) {
        CK_ULONG partOut = sizeof(multi) - multiLen;
        ret = funcList->C_EncryptUpdate(session, plain + off, parts[p],
                                        multi + multiLen, &partOut);
        snprintf(msg, sizeof(msg), "%s: C_EncryptUpdate part %d", label, p);
        CHECK_CKR(ret, msg, CKR_OK);
        off += parts[p];
        multiLen += partOut;
    }

    {
        CK_ULONG tagOut = sizeof(multi) - multiLen;
        ret = funcList->C_EncryptFinal(session, multi + multiLen, &tagOut);
        snprintf(msg, sizeof(msg), "%s: C_EncryptFinal", label);
        CHECK_CKR(ret, msg, CKR_OK);
        multiLen += tagOut;
    }

    snprintf(msg, sizeof(msg), "%s: multi-part length equals single-shot",
             label);
    CHECK_COND(multiLen == singleLen, msg);

    snprintf(msg, sizeof(msg), "%s: multi-part bytes equal single-shot", label);
    CHECK_COND(XMEMCMP(multi, single, singleLen) == 0, msg);

    /* The multi-part output must also decrypt back to the plaintext via the
     * single-shot path, proving the tag authenticates the whole message. */
    init_gcm_mech(&mech, &params, iv, sizeof(iv), aad, aadLen, tagBits);
    ret = funcList->C_DecryptInit(session, &mech, key);
    snprintf(msg, sizeof(msg), "%s: C_DecryptInit", label);
    CHECK_CKR(ret, msg, CKR_OK);

    {
        CK_BYTE dec[sizeof(plain)];
        CK_ULONG decLen = sizeof(dec);
        ret = funcList->C_Decrypt(session, multi, multiLen, dec, &decLen);
        snprintf(msg, sizeof(msg), "%s: C_Decrypt multi-part output", label);
        CHECK_CKR(ret, msg, CKR_OK);
        snprintf(msg, sizeof(msg), "%s: decrypted plaintext matches", label);
        CHECK_COND(decLen == plainLen && XMEMCMP(dec, plain, plainLen) == 0,
                   msg);
    }

cleanup:
    return result;
}

/*
 * Empty message: C_EncryptInit followed directly by C_EncryptFinal (no update)
 * must emit a tag over the empty message + AAD that authenticates on decrypt.
 * The single-shot C_Encrypt path rejects a zero-length input, so this checks a
 * self-consistent round-trip rather than comparing against single-shot.
 */
static int gcm_empty_final(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                           CK_BYTE* aad, CK_ULONG aadLen, const char* label)
{
    CK_MECHANISM mech;
    CK_GCM_PARAMS params;
    CK_RV ret;
    CK_BYTE iv[12];
    CK_BYTE tag[16];
    CK_BYTE dec[16];
    CK_ULONG tagLen = sizeof(tag);
    CK_ULONG decLen = sizeof(dec);
    int result = 0;
    char msg[128];

    XMEMSET(iv, 9, sizeof(iv));

    init_gcm_mech(&mech, &params, iv, sizeof(iv), aad, aadLen, 128);
    ret = funcList->C_EncryptInit(session, &mech, key);
    snprintf(msg, sizeof(msg), "%s: empty C_EncryptInit", label);
    CHECK_CKR(ret, msg, CKR_OK);

    ret = funcList->C_EncryptFinal(session, tag, &tagLen);
    snprintf(msg, sizeof(msg), "%s: empty C_EncryptFinal", label);
    CHECK_CKR(ret, msg, CKR_OK);

    snprintf(msg, sizeof(msg), "%s: empty final emits full tag", label);
    CHECK_COND(tagLen == sizeof(tag), msg);

    /* Decrypting just the tag (zero ciphertext) must authenticate. */
    init_gcm_mech(&mech, &params, iv, sizeof(iv), aad, aadLen, 128);
    ret = funcList->C_DecryptInit(session, &mech, key);
    snprintf(msg, sizeof(msg), "%s: empty C_DecryptInit", label);
    CHECK_CKR(ret, msg, CKR_OK);

    ret = funcList->C_Decrypt(session, tag, tagLen, dec, &decLen);
    snprintf(msg, sizeof(msg), "%s: empty C_Decrypt of tag", label);
    CHECK_CKR(ret, msg, CKR_OK);

    snprintf(msg, sizeof(msg), "%s: empty message decrypts to zero bytes",
             label);
    CHECK_COND(decLen == 0, msg);

cleanup:
    return result;
}

static int aes_gcm_multipart_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    int result = 0;
    CK_BYTE aad[20];
    CK_ULONG i;
    /* Various splits, all with >= 2 non-empty parts (the broken case). */
    CK_ULONG twoEven[2]  = { 16, 16 };
    CK_ULONG twoOdd[2]   = { 5, 27 };
    CK_ULONG three[3]    = { 8, 8, 16 };
    CK_ULONG four[4]     = { 10, 10, 10, 2 };

    printf("\n=== Testing CKM_AES_GCM multi-part equivalence ===\n");

    cleanup_test_files(GCM_MP_TEST_DIR);

    for (i = 0; i < sizeof(aad); i++)
        aad[i] = (CK_BYTE)(0x40 + i);

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

    ret = create_aes_key(session, &key);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: create_aes_key: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        pkcs11_close_session(session);
        pkcs11_final();
        return -1;
    }

    /* Without AAD */
    if (gcm_multipart_equiv(session, key, NULL, 0, twoEven, 2,
                            "no-aad 16+16") != 0)
        result = -1;
    if (gcm_multipart_equiv(session, key, NULL, 0, twoOdd, 2,
                            "no-aad 5+27") != 0)
        result = -1;
    if (gcm_multipart_equiv(session, key, NULL, 0, three, 3,
                            "no-aad 8+8+16") != 0)
        result = -1;
    /* With AAD (exercises the AAD-dropped-after-first-update bug) */
    if (gcm_multipart_equiv(session, key, aad, sizeof(aad), twoEven, 2,
                            "aad 16+16") != 0)
        result = -1;
    if (gcm_multipart_equiv(session, key, aad, sizeof(aad), four, 4,
                            "aad 10+10+10+2") != 0)
        result = -1;
    /* Empty message (no update before final) */
    if (gcm_empty_final(session, key, NULL, 0, "empty no-aad") != 0)
        result = -1;
    if (gcm_empty_final(session, key, aad, sizeof(aad), "empty aad") != 0)
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", GCM_MP_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 AES-GCM Multi-part Equivalence Test ===\n");

    (void)aes_gcm_multipart_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* NO_AES || !HAVE_AESGCM */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("AES-GCM not available, skipping multi-part equivalence test\n");
    return 0;
}

#endif /* !NO_AES && HAVE_AESGCM */
