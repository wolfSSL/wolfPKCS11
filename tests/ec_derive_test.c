/* ec_derive_test.c
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
 * Tests for C_DeriveKey with CKM_ECDH1_DERIVE: mechanism parameter
 * validation and the attributes of the derived key object.
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

#define TEST_DIR "./store/ec_derive_test"

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
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

#define CHECK_RV(rv, exp, op) do {                                        \
    if ((rv) != (exp)) {                                                  \
        fprintf(stderr, "FAIL: %s: got 0x%lx, expected 0x%lx\n", op,      \
                (unsigned long)(rv), (unsigned long)(exp));               \
        test_failed++;                                                    \
        result = -1;                                                      \
        goto cleanup;                                                     \
    }                                                                     \
    else {                                                                \
        printf("PASS: %s\n", op);                                         \
        test_passed++;                                                    \
    }                                                                     \
} while (0)

#define CHECK_CKR(rv, op) CHECK_RV(rv, CKR_OK, op)

#ifdef HAVE_ECC
static CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE eccKeyType = CKK_EC;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_ULONG secretLen = 32;

/* Session P-256 private key usable for ECDH. */
static CK_RV create_ec_base(CK_SESSION_HANDLE session, CK_BBOOL sensitive,
                            CK_BBOOL extractable, CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privKeyClass,   sizeof(privKeyClass)    },
        { CKA_KEY_TYPE,    &eccKeyType,     sizeof(eccKeyType)      },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)       },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)     },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,       ecc_p256_priv,   sizeof(ecc_p256_priv)   },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, cnt, obj);
}

/* ECDH derive of a public, extractable generic secret. */
static CK_RV ecdh_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                         CK_ECDH1_DERIVE_PARAMS* params,
                         CK_OBJECT_HANDLE* derived)
{
    CK_MECHANISM mech;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &secretLen,      sizeof(secretLen)      },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    mech.mechanism = CKM_ECDH1_DERIVE;
    mech.pParameter = params;
    mech.ulParameterLen = sizeof(*params);

    return funcList->C_DeriveKey(session, &mech, base, tmpl, cnt, derived);
}

static void ecdh_params_init(CK_ECDH1_DERIVE_PARAMS* params, byte* point,
                             CK_ULONG pointLen)
{
    XMEMSET(params, 0, sizeof(*params));
    params->kdf = CKD_NULL;
    params->pSharedData = NULL;
    params->ulSharedDataLen = 0;
    params->pPublicData = point;
    params->ulPublicDataLen = pointLen;
}

/* With CKD_NULL there is no KDF, so shared data must be absent. */
static int test_null_kdf_shared_data(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    byte sharedData[4] = { 0x01, 0x02, 0x03, 0x04 };
    int result = 0;

    ret = create_ec_base(session, CK_FALSE, CK_TRUE, &base);
    CHECK_CKR(ret, "create EC base key");

    ecdh_params_init(&params, ecc_p256_point, sizeof(ecc_p256_point));
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_CKR(ret, "CKD_NULL derive without shared data");
    funcList->C_DestroyObject(session, derived);
    derived = CK_INVALID_HANDLE;

    params.pSharedData = sharedData;
    params.ulSharedDataLen = sizeof(sharedData);
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "CKD_NULL derive rejects shared data");

    params.pSharedData = NULL;
    params.ulSharedDataLen = sizeof(sharedData);
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "CKD_NULL derive rejects shared data length");

    params.pSharedData = sharedData;
    params.ulSharedDataLen = 0;
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "CKD_NULL derive rejects shared data pointer");

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}

/* A public data length beyond any encodable EC point is a parameter error. */
static int test_public_data_length_bound(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    byte bigPoint[512];
    CK_ULONG wideLen;
    int result = 0;

    ret = create_ec_base(session, CK_FALSE, CK_TRUE, &base);
    CHECK_CKR(ret, "create EC base key");

    if (sizeof(CK_ULONG) > sizeof(word32)) {
        /* Upper bits set, low 32 bits equal to the real point length. */
        wideLen = ((CK_ULONG)2 << 16) << 16;
        wideLen += sizeof(ecc_p256_point);
        ecdh_params_init(&params, ecc_p256_point, wideLen);
        ret = ecdh_derive(session, base, &params, &derived);
        CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
                 "public data length above 32 bits rejected");
    }

    XMEMSET(bigPoint, 0, sizeof(bigPoint));
    XMEMCPY(bigPoint, ecc_p256_point, sizeof(ecc_p256_point));
    ecdh_params_init(&params, bigPoint, sizeof(bigPoint));
    ret = ecdh_derive(session, base, &params, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "oversized public data length rejected");

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}

/* An EC point wrapped with an unsupported DER length form is not accepted. */
static int test_unsupported_der_length_form(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    byte p521Params[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
    byte derPoint[2 * 66 + 4];
    byte badPoint[2 * 66 + 3];
    CK_ATTRIBUTE pointAttr = { CKA_EC_POINT, derPoint, sizeof(derPoint) };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, p521Params, sizeof(p521Params) },
        { CKA_PRIVATE,   &ckFalse,   sizeof(ckFalse)    },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_PRIVATE,   &ckFalse,   sizeof(ckFalse)    },
        { CKA_SENSITIVE, &ckFalse,   sizeof(ckFalse)    },
        { CKA_DERIVE,    &ckTrue,    sizeof(ckTrue)     },
    };
    int result = 0;

    ret = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    if (ret != CKR_OK) {
        printf("SKIP: P-521 key generation unavailable (0x%lx)\n",
               (unsigned long)ret);
        test_skipped = 1;
        goto cleanup;
    }

    ret = funcList->C_GetAttributeValue(session, pub, &pointAttr, 1);
    CHECK_CKR(ret, "read P-521 EC point");
    if (pointAttr.ulValueLen != sizeof(derPoint) || derPoint[0] != 0x04 ||
            derPoint[1] != 0x81 || derPoint[2] != sizeof(badPoint) - 2) {
        ret = CKR_GENERAL_ERROR;
    }
    CHECK_CKR(ret, "P-521 EC point is DER wrapped");

    ecdh_params_init(&params, derPoint, sizeof(derPoint));
    ret = ecdh_derive(session, priv, &params, &derived);
    CHECK_CKR(ret, "derive with DER wrapped point");
    funcList->C_DestroyObject(session, derived);
    derived = CK_INVALID_HANDLE;

    /* Same point with a long-form length byte that has no length octets. */
    badPoint[0] = 0x04;
    badPoint[1] = (byte)(sizeof(badPoint) - 2);
    XMEMCPY(badPoint + 2, derPoint + 3, sizeof(badPoint) - 2);
    ecdh_params_init(&params, badPoint, sizeof(badPoint));
    ret = ecdh_derive(session, priv, &params, &derived);
    if (ret == CKR_OK) {
        fprintf(stderr, "FAIL: malformed DER length form accepted\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: malformed DER length form rejected\n");
    test_passed++;

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    return result;
}
#endif /* HAVE_ECC */

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
        dlib = NULL;
        return -1;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        dlib = NULL;
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

static int ec_derive_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing C_DeriveKey with CKM_ECDH1_DERIVE ===\n");

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize");

    ret = pkcs11_setup_token();
    CHECK_CKR(ret, "token setup");

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession");
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login");

#ifdef HAVE_ECC
    if (test_null_kdf_shared_data(session) != 0)
        result = -1;
    if (test_public_data_length_bound(session) != 0)
        result = -1;
    if (test_unsupported_der_length_form(session) != 0)
        result = -1;
#else
    printf("ECC not available, skipping ECDH derive tests\n");
    test_skipped = 1;
#endif

cleanup:
    if (session != CK_INVALID_HANDLE) {
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

    if (ec_derive_test() != 0 && test_failed == 0)
        test_failed++;

    print_results();
#ifndef HAVE_ECC
    if (test_failed == 0)
        return 77;
#endif
    return (test_failed == 0) ? 0 : 1;
}
