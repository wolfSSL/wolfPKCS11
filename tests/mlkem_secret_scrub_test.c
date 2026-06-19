/* mlkem_secret_scrub_test.c
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
 * White-box test for ML-KEM shared-secret zeroization (bug #6056).
 *
 * C_EncapsulateKey/C_DecapsulateKey hold the freshly derived ML-KEM shared
 * secret in a temporary heap buffer, copy it into the new key object, then
 * wc_ForceZero() it before XFREE(). Deleting that scrub leaves the plaintext
 * shared secret in freed heap memory, which no PKCS#11-level test can observe.
 *
 * This test installs a tracking allocator that snapshots the contents of every
 * buffer freed during a C_EncapsulateKey/C_DecapsulateKey call, then asserts
 * the (extractable) shared secret never appears in any freed buffer. With the
 * scrub present the temporary buffer is zero at free; deleting the scrub makes
 * this test fail.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"

#if defined(WOLFPKCS11_MLKEM) && defined(WOLFPKCS11_PKCS11_V3_2)

#define MLKEM_SCRUB_TEST_DIR "./store/mlkem_secret_scrub_test"
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

/* ------------------------------------------------------------------ */
/* Tracking allocator: while armed, snapshots the bytes of every freed */
/* buffer that was allocated during the same window.                   */
/* ------------------------------------------------------------------ */
#define TRK_MAX  16384
#define CAP_MAX  16384
#define CAP_BYTES 64

static int    g_armed = 0;
static void*  g_trkPtr[TRK_MAX];
static size_t g_trkSz[TRK_MAX];
static int    g_trkN = 0;
static size_t g_capSz[CAP_MAX];
static unsigned char g_capBuf[CAP_MAX][CAP_BYTES];
static int    g_capN = 0;

static void track_add(void* p, size_t sz)
{
    if (g_armed && p != NULL && g_trkN < TRK_MAX) {
        g_trkPtr[g_trkN] = p;
        g_trkSz[g_trkN] = sz;
        g_trkN++;
    }
}

static int track_find(void* p)
{
    int i;
    for (i = g_trkN - 1; i >= 0; i--) {
        if (g_trkPtr[i] == p)
            return i;
    }
    return -1;
}

static void track_remove(int idx)
{
    g_trkN--;
    g_trkPtr[idx] = g_trkPtr[g_trkN];
    g_trkSz[idx] = g_trkSz[g_trkN];
}

static void* test_malloc(size_t n)
{
    void* p = malloc(n);
    track_add(p, n);
    return p;
}

static void test_free(void* p)
{
    if (g_armed && p != NULL) {
        int idx = track_find(p);
        if (idx >= 0) {
            size_t sz = g_trkSz[idx];
            if (g_capN < CAP_MAX) {
                size_t copy = sz < CAP_BYTES ? sz : CAP_BYTES;
                g_capSz[g_capN] = sz;
                memcpy(g_capBuf[g_capN], p, copy);
                g_capN++;
            }
            track_remove(idx);
        }
    }
    free(p);
}

static void* test_realloc(void* p, size_t n)
{
    void* np;
    int idx = -1;
    /* Locate the tracking entry while p is still valid. */
    if (g_armed && p != NULL)
        idx = track_find(p);
    np = realloc(p, n);
    /* Only update tracking on success; on failure p is still live and tracked. */
    if (np != NULL) {
        if (idx >= 0)
            track_remove(idx);
        track_add(np, n);
    }
    return np;
}

static void arm_capture(void)
{
    g_trkN = 0;
    g_capN = 0;
    g_armed = 1;
}

static void disarm_capture(void)
{
    g_armed = 0;
}

/* Returns 1 if the secret appears (unscrubbed) in any captured freed buffer. */
static int secret_found_in_freed(const unsigned char* secret, size_t len)
{
    int i;
    if (len > CAP_BYTES)
        len = CAP_BYTES;
    for (i = 0; i < g_capN; i++) {
        if (g_capSz[i] == len && memcmp(g_capBuf[i], secret, len) == 0)
            return 1;
    }
    return 0;
}

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

static CK_BBOOL ckTrue = CK_TRUE;

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_INTERFACE* interface = NULL;
    /* Request the PKCS#11 v3.2 interface so the function list includes
     * C_EncapsulateKey/C_DecapsulateKey. */
    CK_UTF8CHAR_PTR interfaceName = (CK_UTF8CHAR_PTR)"PKCS 11";

#ifndef HAVE_PKCS11_STATIC
    CK_C_GetInterface func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return -1;
    }
    func = (CK_C_GetInterface)dlsym(dlib, "C_GetInterface");
    if (func == NULL) {
        fprintf(stderr, "Failed to get C_GetInterface\n");
        dlclose(dlib);
        return -1;
    }
    ret = func(interfaceName, NULL, &interface, 0);
    if (ret != CKR_OK || interface == NULL) {
        fprintf(stderr, "Failed to get interface: 0x%lx\n",
            (unsigned long)ret);
        dlclose(dlib);
        return ret == CKR_OK ? CKR_GENERAL_ERROR : ret;
    }
#else
    ret = C_GetInterface(interfaceName, NULL, &interface, 0);
    if (ret != CKR_OK || interface == NULL) {
        fprintf(stderr, "Failed to get interface: 0x%lx\n",
            (unsigned long)ret);
        return ret == CKR_OK ? CKR_GENERAL_ERROR : ret;
    }
#endif
    funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;

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

static CK_RV gen_mlkem_keys(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* pub,
                            CK_OBJECT_HANDLE* priv)
{
    CK_MECHANISM mech;
    CK_ML_KEM_PARAMETER_SET_TYPE paramSet = CKP_ML_KEM_768;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
        { CKA_ENCAPSULATE,   &ckTrue,   sizeof(ckTrue)   },
        { CKA_TOKEN,         &ckTrue,   sizeof(ckTrue)   },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_DECAPSULATE,   &ckTrue,   sizeof(ckTrue)   },
        { CKA_TOKEN,         &ckTrue,   sizeof(ckTrue)   },
    };

    mech.mechanism = CKM_ML_KEM_KEY_PAIR_GEN;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    return funcList->C_GenerateKeyPair(session, &mech,
                pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
                privTmpl, sizeof(privTmpl) / sizeof(*privTmpl), pub, priv);
}

static int mlkem_secret_scrub_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE encapKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE decapKey = CK_INVALID_HANDLE;
    CK_FUNCTION_LIST_3_2* funcListExt;
    CK_MECHANISM mech;
    CK_BYTE* ciphertext = NULL;
    CK_ULONG ctLen = 0;
    CK_BYTE ss1[64], ss2[64];
    CK_ULONG ss1Len = sizeof(ss1), ss2Len = sizeof(ss2);
    int result = 0;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;
    CK_BBOOL sensitive = CK_FALSE;
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass,    sizeof(secretClass)    },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)      },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
    };
    CK_ULONG secretTmplCnt = sizeof(secretTmpl) / sizeof(*secretTmpl);
    CK_ATTRIBUTE getValueTmpl[] = { { CKA_VALUE, NULL, 0 } };

    printf("\n=== Testing ML-KEM shared-secret zeroization ===\n");

    cleanup_test_files(MLKEM_SCRUB_TEST_DIR);

    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: pkcs11_init: 0x%lx\n", (unsigned long)ret);
        test_failed++;
        return -1;
    }
    funcListExt = (CK_FUNCTION_LIST_3_2*)funcList;

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

    ret = gen_mlkem_keys(session, &pub, &priv);
    CHECK_CKR(ret, "ML-KEM key generation", CKR_OK);

    mech.mechanism = CKM_ML_KEM;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    /* Ciphertext size query (not armed: no shared secret is derived). */
    ret = funcListExt->C_EncapsulateKey(session, &mech, pub, secretTmpl,
                                        secretTmplCnt, NULL, &ctLen, &encapKey);
    CHECK_CKR(ret, "ML-KEM Encapsulate size query", CKR_OK);
    ciphertext = (CK_BYTE*)malloc(ctLen);
    CHECK_COND(ciphertext != NULL, "allocate ciphertext buffer");

    /* Real encapsulate, with freed-buffer capture armed. */
    arm_capture();
    ret = funcListExt->C_EncapsulateKey(session, &mech, pub, secretTmpl,
                                        secretTmplCnt, ciphertext, &ctLen,
                                        &encapKey);
    disarm_capture();
    CHECK_CKR(ret, "ML-KEM Encapsulate", CKR_OK);

    getValueTmpl[0].pValue = ss1;
    getValueTmpl[0].ulValueLen = ss1Len;
    ret = funcList->C_GetAttributeValue(session, encapKey, getValueTmpl, 1);
    CHECK_CKR(ret, "Get encapsulated shared secret", CKR_OK);
    ss1Len = getValueTmpl[0].ulValueLen;
    CHECK_COND(ss1Len > 0 && ss1Len <= sizeof(ss1), "shared secret length sane");

    CHECK_COND(!secret_found_in_freed(ss1, ss1Len),
               "Encapsulate: shared secret scrubbed from freed buffer");

    /* Real decapsulate, with capture armed. */
    arm_capture();
    ret = funcListExt->C_DecapsulateKey(session, &mech, priv, secretTmpl,
                                        secretTmplCnt, ciphertext, ctLen,
                                        &decapKey);
    disarm_capture();
    CHECK_CKR(ret, "ML-KEM Decapsulate", CKR_OK);

    getValueTmpl[0].pValue = ss2;
    getValueTmpl[0].ulValueLen = ss2Len;
    ret = funcList->C_GetAttributeValue(session, decapKey, getValueTmpl, 1);
    CHECK_CKR(ret, "Get decapsulated shared secret", CKR_OK);
    ss2Len = getValueTmpl[0].ulValueLen;

    CHECK_COND(ss1Len == ss2Len && XMEMCMP(ss1, ss2, ss1Len) == 0,
               "Encap/decap shared secrets match");

    CHECK_COND(!secret_found_in_freed(ss2, ss2Len),
               "Decapsulate: shared secret scrubbed from freed buffer");

cleanup:
    if (ciphertext != NULL)
        free(ciphertext);
    if (decapKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, decapKey);
    if (encapKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, encapKey);
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", MLKEM_SCRUB_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 ML-KEM Shared-Secret Scrub Test ===\n");

    /* Install the tracking allocator before any library allocation. */
    if (wolfSSL_SetAllocators(test_malloc, test_free, test_realloc) != 0) {
        fprintf(stderr, "FAIL: wolfSSL_SetAllocators\n");
        return 1;
    }

    (void)mlkem_secret_scrub_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* !WOLFPKCS11_MLKEM || !WOLFPKCS11_PKCS11_V3_2 */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("ML-KEM v3.2 not available, skipping shared-secret scrub test\n");
    return 0;
}

#endif /* WOLFPKCS11_MLKEM && WOLFPKCS11_PKCS11_V3_2 */
