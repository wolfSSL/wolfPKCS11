/* rsa_private_usage_default_test.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * Test for issue F-5520: RSA private keys must not silently default to
 * multiple cryptographic uses. With a minimal template, CKA_DECRYPT,
 * CKA_SIGN and CKA_SIGN_RECOVER default to CK_FALSE; each use must be
 * requested explicitly.
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

/* The permissive multi-use defaults are expected under the legacy macro or in
 * an NSS build (which keeps the historical permissive key defaults). */
#if defined(WOLFPKCS11_LEGACY_RSA_USAGE_DEFAULT) || \
    defined(WOLFPKCS11_NSS)
    #define EXPECT_PERMISSIVE_USAGE
#endif

#define TEST_DIR "./store/rsa_private_usage_default_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static int test_passed = 0;
static int test_failed = 0;
static int test_skipped = 0;

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

#define CHECK_CKR(rv, op) do {                              \
    if (rv != CKR_OK) {                                     \
        fprintf(stderr, "FAIL: %s: got 0x%lx\n", op, (unsigned long)rv); \
        test_failed++;                                      \
        result = -1;                                        \
        goto cleanup;                                       \
    } else {                                                \
        printf("PASS: %s\n", op);                           \
        test_passed++;                                      \
    }                                                       \
} while(0)

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
static int check_bool_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                           CK_ATTRIBUTE_TYPE type, CK_BBOOL expected,
                           const char* name)
{
    CK_RV ret;
    CK_BBOOL val = 0xAA;
    CK_ATTRIBUTE tmpl[] = { { type, &val, sizeof(val) } };

    ret = funcList->C_GetAttributeValue(session, obj, tmpl, 1);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: get %s: 0x%lx\n", name, (unsigned long)ret);
        test_failed++;
        return -1;
    }
    if (val != expected) {
        fprintf(stderr, "FAIL: %s: expected %d, got %d\n", name,
                (int)expected, (int)val);
        test_failed++;
        return -1;
    }
    printf("PASS: %s is %s\n", name, expected ? "CK_TRUE" : "CK_FALSE");
    test_passed++;
    return 0;
}

static CK_RV gen_rsa(CK_SESSION_HANDLE session, CK_ATTRIBUTE* privTmpl,
                     CK_ULONG privCnt, CK_OBJECT_HANDLE* pub,
                     CK_OBJECT_HANDLE* priv)
{
    CK_MECHANISM mech;
    CK_ULONG bits = 2048;
    byte pubExp[] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_MODULUS_BITS,    &bits,  sizeof(bits)   },
        { CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp) },
    };
    CK_ULONG pubCnt = sizeof(pubTmpl) / sizeof(*pubTmpl);

    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;
    return funcList->C_GenerateKeyPair(session, &mech, pubTmpl, pubCnt,
                                       privTmpl, privCnt, pub, priv);
}

static int test_rsa_private_usage_default(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_BBOOL ckTrue = CK_TRUE;
    int result = 0;

    /* Minimal private template: no usage attributes. */
    CK_ATTRIBUTE minTmpl[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    };
    CK_ULONG minCnt = sizeof(minTmpl) / sizeof(*minTmpl);

    /* Opt-in: request signing only. */
    CK_ATTRIBUTE signTmpl[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
        { CKA_SIGN,  &ckTrue,  sizeof(ckTrue)  },
    };
    CK_ULONG signCnt = sizeof(signTmpl) / sizeof(*signTmpl);

    ret = gen_rsa(session, minTmpl, minCnt, &pub, &priv);
    CHECK_CKR(ret, "C_GenerateKeyPair (minimal private template)");

#ifdef EXPECT_PERMISSIVE_USAGE
    if (check_bool_attr(session, priv, CKA_SIGN, CK_TRUE,
                        "RSA priv CKA_SIGN (legacy)") != 0)
        result = -1;
    if (check_bool_attr(session, priv, CKA_DECRYPT, CK_TRUE,
                        "RSA priv CKA_DECRYPT (legacy)") != 0)
        result = -1;
#else
    if (check_bool_attr(session, priv, CKA_SIGN, CK_FALSE,
                        "RSA priv CKA_SIGN") != 0)
        result = -1;
    if (check_bool_attr(session, priv, CKA_DECRYPT, CK_FALSE,
                        "RSA priv CKA_DECRYPT") != 0)
        result = -1;
    if (check_bool_attr(session, priv, CKA_SIGN_RECOVER, CK_FALSE,
                        "RSA priv CKA_SIGN_RECOVER") != 0)
        result = -1;
#endif

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
    priv = pub = CK_INVALID_HANDLE;

    /* Opt-in must still produce a signing key (and only that). */
    ret = gen_rsa(session, signTmpl, signCnt, &pub, &priv);
    CHECK_CKR(ret, "C_GenerateKeyPair (CKA_SIGN=TRUE template)");

    if (check_bool_attr(session, priv, CKA_SIGN, CK_TRUE,
                        "opt-in CKA_SIGN") != 0)
        result = -1;
#ifndef EXPECT_PERMISSIVE_USAGE
    if (check_bool_attr(session, priv, CKA_DECRYPT, CK_FALSE,
                        "opt-in leaves CKA_DECRYPT") != 0)
        result = -1;
#endif

cleanup:
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    return result;
}
#endif /* !NO_RSA */

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
        dlclose(dlib);
        return -1;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK)
        return ret;
#endif

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

static CK_RV pkcs11_setup_token(void)
{
    CK_RV ret;
    unsigned char label[32];
    CK_SESSION_HANDLE soSession;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK)
        ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return ret;
}

static int rsa_private_usage_default_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing RSA private key usage defaults ===\n");

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize");

    ret = pkcs11_setup_token();
    CHECK_CKR(ret, "token setup");

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession");
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login");

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    if (test_rsa_private_usage_default(session) != 0)
        result = -1;
#else
    printf("RSA key generation not available, skipping\n");
    test_skipped = 1;
#endif

cleanup:
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();
    return result;
}

static void print_results(void)
{
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_skipped != 0)
        printf("Tests skipped: %d\n", test_skipped);
    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 RSA Private Usage Default Test ===\n");

    (void)rsa_private_usage_default_test();

    print_results();
    return (test_failed == 0) ? 0 : 1;
}
