/* mlkem_sensitive_attr_test.c
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
 * Regression test for issue F-4532: MlKemObject_GetAttr must not disclose an
 * ML-KEM private key's CKA_VALUE when the key is sensitive or not extractable.
 * Reading CKA_VALUE must return CKR_ATTRIBUTE_SENSITIVE with
 * ulValueLen = CK_UNAVAILABLE_INFORMATION when
 * noPriv = (SENSITIVE != 0) || (EXTRACTABLE == 0) is true, and the real key
 * bytes otherwise.
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

#ifdef WOLFPKCS11_MLKEM

#define MLKEM_SENS_TEST_DIR "./store/mlkem_sensitive_attr_test"
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
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

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

/* Generate an ML-KEM-512 key pair with the requested CKA_SENSITIVE and
 * CKA_EXTRACTABLE values on the private key. */
static CK_RV gen_mlkem_keypair(CK_SESSION_HANDLE session, CK_BBOOL* sensitive,
                               CK_BBOOL* extractable, CK_OBJECT_HANDLE* priv,
                               CK_OBJECT_HANDLE* pub)
{
    CK_MECHANISM mech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 };
    CK_ML_KEM_PARAMETER_SET_TYPE paramSet = CKP_ML_KEM_512;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
        { CKA_ENCAPSULATE,   &ckTrue,   sizeof(ckTrue)   },
        { CKA_TOKEN,         &ckFalse,  sizeof(ckFalse)  },
    };
    CK_ULONG pubCnt = sizeof(pubTmpl) / sizeof(*pubTmpl);
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_DECAPSULATE, &ckTrue,      sizeof(ckTrue)    },
        { CKA_TOKEN,       &ckFalse,     sizeof(ckFalse)   },
        { CKA_SENSITIVE,   sensitive,    sizeof(*sensitive)   },
        { CKA_EXTRACTABLE, extractable,  sizeof(*extractable) },
    };
    CK_ULONG privCnt = sizeof(privTmpl) / sizeof(*privTmpl);

    return funcList->C_GenerateKeyPair(session, &mech, pubTmpl, pubCnt,
                                       privTmpl, privCnt, pub, priv);
}

/* Read CKA_VALUE on a private key expected to be protected; assert
 * CKR_ATTRIBUTE_SENSITIVE and ulValueLen == CK_UNAVAILABLE_INFORMATION. */
static int check_value_protected(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE priv, const char* label)
{
    CK_RV ret;
    CK_BYTE buf[4096];
    CK_ATTRIBUTE getTmpl[] = { { CKA_VALUE, buf, sizeof(buf) } };
    char msg[160];
    int result = 0;

    XMEMSET(buf, 0, sizeof(buf));
    ret = funcList->C_GetAttributeValue(session, priv, getTmpl, 1);
    snprintf(msg, sizeof(msg), "%s: C_GetAttributeValue(CKA_VALUE) sensitive",
             label);
    CHECK_CKR(ret, msg, CKR_ATTRIBUTE_SENSITIVE);

    snprintf(msg, sizeof(msg), "%s: ulValueLen is CK_UNAVAILABLE_INFORMATION",
             label);
    CHECK_COND(getTmpl[0].ulValueLen == CK_UNAVAILABLE_INFORMATION, msg);

cleanup:
    return result;
}

static int mlkem_sensitive_attr_test(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE, pub = CK_INVALID_HANDLE;
    CK_BYTE buf[4096];
    CK_ATTRIBUTE getVal[] = { { CKA_VALUE, NULL, 0 } };
    int result = 0;

    /* Case 1: sensitive=TRUE, extractable=TRUE -> protected (noPriv true via
     * the SENSITIVE term). */
    ret = gen_mlkem_keypair(session, &ckTrue, &ckTrue, &priv, &pub);
    CHECK_CKR(ret, "Case1: ML-KEM keygen (sensitive=TRUE)", CKR_OK);
    if (check_value_protected(session, priv, "Case1 sensitive") != 0)
        result = -1;
    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
    priv = pub = CK_INVALID_HANDLE;

    /* Case 2: sensitive=FALSE, extractable=FALSE -> protected (noPriv true via
     * the EXTRACTABLE term). */
    ret = gen_mlkem_keypair(session, &ckFalse, &ckFalse, &priv, &pub);
    CHECK_CKR(ret, "Case2: ML-KEM keygen (extractable=FALSE)", CKR_OK);
    if (check_value_protected(session, priv, "Case2 unextractable") != 0)
        result = -1;
    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
    priv = pub = CK_INVALID_HANDLE;

    /* Case 3 (positive control): sensitive=FALSE, extractable=TRUE -> the real
     * private key bytes are returned (noPriv false). */
    ret = gen_mlkem_keypair(session, &ckFalse, &ckTrue, &priv, &pub);
    CHECK_CKR(ret, "Case3: ML-KEM keygen (sensitive=FALSE,extractable=TRUE)",
              CKR_OK);

    ret = funcList->C_GetAttributeValue(session, priv, getVal, 1);
    CHECK_CKR(ret, "Case3: C_GetAttributeValue(CKA_VALUE) size query", CKR_OK);
    CHECK_COND(getVal[0].ulValueLen != CK_UNAVAILABLE_INFORMATION &&
               getVal[0].ulValueLen > 0 &&
               getVal[0].ulValueLen <= sizeof(buf),
               "Case3: size query returns a real length");

    getVal[0].pValue = buf;
    XMEMSET(buf, 0, sizeof(buf));
    ret = funcList->C_GetAttributeValue(session, priv, getVal, 1);
    CHECK_CKR(ret, "Case3: C_GetAttributeValue(CKA_VALUE) returns key bytes",
              CKR_OK);
    CHECK_COND(getVal[0].ulValueLen != CK_UNAVAILABLE_INFORMATION &&
               getVal[0].ulValueLen > 0,
               "Case3: private key bytes available");

cleanup:
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    return result;
}

static int run_mlkem_sensitive_attr_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int result = 0;

    printf("\n=== Testing ML-KEM private key CKA_VALUE sensitivity ===\n");

    cleanup_test_files(MLKEM_SENS_TEST_DIR);

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

    if (mlkem_sensitive_attr_test(session) != 0)
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", MLKEM_SENS_TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 ML-KEM Sensitive CKA_VALUE Test ===\n");

    (void)run_mlkem_sensitive_attr_test();

    print_results();

    return (test_failed == 0) ? 0 : 1;
}

#else /* !WOLFPKCS11_MLKEM */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    printf("ML-KEM not available, skipping sensitive CKA_VALUE test\n");
    return 0;
}

#endif /* WOLFPKCS11_MLKEM */
