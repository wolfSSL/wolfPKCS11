/* kdf_tls_derive_test.c
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
 * Tests for C_DeriveKey with the HKDF, DH, AES-CBC and TLS 1.2 mechanisms:
 * mechanism parameter validation and the attributes of the derived keys.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <limits.h>

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

#define TEST_DIR "./store/kdf_tls_derive_test"

/* CK_ULONG lengths above the 32-bit range can only be expressed on LP64. */
#if ULONG_MAX > 0xFFFFFFFFUL
    #define WIDE_CK_ULONG
    #define LEN_ABOVE_WORD32(n) ((CK_ULONG)0xFFFFFFFFUL + 1 + (CK_ULONG)(n))
#endif

#if defined(WOLFSSL_HAVE_PRF) && defined(WOLFPKCS11_NSS) && \
    defined(WIDE_CK_ULONG)
    #define NSS_EMS_WIDE_TEST
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(WIDE_CK_ULONG)
    #define AES_CBC_WIDE_TEST
#endif

#if (defined(WOLFPKCS11_HKDF) && defined(WIDE_CK_ULONG)) || \
    defined(NSS_EMS_WIDE_TEST) || defined(AES_CBC_WIDE_TEST) || \
    defined(WOLFSSL_HAVE_PRF)
    #define SECRET_BASE_TESTS
#endif

#if defined(SECRET_BASE_TESTS) || !defined(NO_DH)
    #define DERIVE_TESTS
#endif

static int test_passed = 0;
static int test_failed = 0;

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

#ifdef DERIVE_TESTS
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
#endif

#ifdef SECRET_BASE_TESTS

/* Not every SECRET_BASE_TESTS configuration uses the shared secret. */
#if defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-variable"
#endif
static byte baseSecret[32] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
#if defined(__GNUC__)
    #pragma GCC diagnostic pop
#endif

/* Session secret key of the given type usable as a derive base. */
static CK_RV create_secret_base(CK_SESSION_HANDLE session, CK_KEY_TYPE type,
                                byte* value, CK_ULONG valueLen,
                                CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &type,           sizeof(type)           },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,       value,           valueLen               },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    return funcList->C_CreateObject(session, tmpl, cnt, obj);
}
#endif /* SECRET_BASE_TESTS */

#ifdef DERIVE_TESTS
/* Derive a public, extractable generic secret of the given length. */
static CK_RV derive_generic(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                            CK_OBJECT_HANDLE base, CK_ULONG len,
                            CK_OBJECT_HANDLE* derived)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    *derived = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, mech, base, tmpl, cnt, derived);
}

static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}
#endif /* DERIVE_TESTS */

#if defined(WOLFPKCS11_HKDF) && defined(WIDE_CK_ULONG)
/* HKDF salt and info lengths must be representable without truncation. */
static int test_hkdf_lengths_fit_word32(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    byte salt[4] = { 0x00, 0x01, 0x02, 0x03 };
    byte info[4] = { 0xf0, 0xf1, 0xf2, 0xf3 };
    CK_HKDF_PARAMS params;
    CK_MECHANISM mech = { CKM_HKDF_DERIVE, &params, sizeof(params) };
    int result = 0;

    ret = create_secret_base(session, CKK_GENERIC_SECRET, baseSecret,
                             sizeof(baseSecret), &base);
    CHECK_CKR(ret, "create HKDF base key");

    XMEMSET(&params, 0, sizeof(params));
    params.bExtract = CK_TRUE;
    params.bExpand = CK_TRUE;
    params.prfHashMechanism = CKM_SHA256;
    params.ulSaltType = CKF_HKDF_SALT_DATA;
    params.pSalt = salt;
    params.ulSaltLen = sizeof(salt);
    params.pInfo = info;
    params.ulInfoLen = sizeof(info);
    ret = derive_generic(session, &mech, base, 32, &derived);
    CHECK_CKR(ret, "HKDF derive with in-range lengths");
    destroy_obj(session, &derived);

    params.ulSaltLen = LEN_ABOVE_WORD32(sizeof(salt));
    ret = derive_generic(session, &mech, base, 32, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "HKDF salt length beyond 32 bits rejected");
    params.ulSaltLen = sizeof(salt);

    params.bExtract = CK_FALSE;
    params.ulInfoLen = LEN_ABOVE_WORD32(sizeof(info));
    ret = derive_generic(session, &mech, base, 32, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "HKDF info length beyond 32 bits rejected");

cleanup:
    destroy_obj(session, &derived);
    destroy_obj(session, &base);
    return result;
}
#endif

#ifdef NSS_EMS_WIDE_TEST
/* The extended master secret session hash length must not be truncated. */
static int test_session_hash_length_fits_word32(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    byte sessionHash[32];
    CK_VERSION version = { 3, 3 };
    CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS params;
    CK_MECHANISM mech = { CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE, &params,
                          sizeof(params) };
    int result = 0;

    XMEMSET(sessionHash, 0xAA, sizeof(sessionHash));
    ret = create_secret_base(session, CKK_GENERIC_SECRET, baseSecret,
                             sizeof(baseSecret), &base);
    CHECK_CKR(ret, "create TLS base key");

    XMEMSET(&params, 0, sizeof(params));
    params.prfHashMechanism = CKM_SHA256;
    params.pSessionHash = sessionHash;
    params.ulSessionHashLen = sizeof(sessionHash);
    params.pVersion = &version;
    ret = derive_generic(session, &mech, base, 48, &derived);
    CHECK_CKR(ret, "extended master secret derive");
    destroy_obj(session, &derived);

    params.ulSessionHashLen = LEN_ABOVE_WORD32(sizeof(sessionHash));
    ret = derive_generic(session, &mech, base, 48, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "session hash length beyond 32 bits rejected");

cleanup:
    destroy_obj(session, &derived);
    destroy_obj(session, &base);
    return result;
}
#endif

#ifndef NO_DH
/* DH peer public value lengths are bounded by the largest supported prime. */
static int test_dh_public_length_bound(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE dhType = CKK_DH;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    byte padded[8192 / 8 + 1];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privClass,     sizeof(privClass)      },
        { CKA_KEY_TYPE,    &dhType,        sizeof(dhType)         },
        { CKA_PRIVATE,     &ckFalse,       sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,       sizeof(ckFalse)        },
        { CKA_DERIVE,      &ckTrue,        sizeof(ckTrue)         },
        { CKA_PRIME,       dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p) },
        { CKA_BASE,        dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g) },
        { CKA_VALUE,       dh_2048_priv,   sizeof(dh_2048_priv)   },
    };
    int result = 0;

    ret = funcList->C_CreateObject(session, tmpl,
                                   sizeof(tmpl) / sizeof(*tmpl), &base);
    CHECK_CKR(ret, "create DH base key");

    mech.mechanism = CKM_DH_PKCS_DERIVE;
    mech.pParameter = dh_2048_peer;
    mech.ulParameterLen = sizeof(dh_2048_peer);
    ret = derive_generic(session, &mech, base, 32, &derived);
    CHECK_CKR(ret, "DH derive with peer public value");
    destroy_obj(session, &derived);

    XMEMSET(padded, 0, sizeof(padded));
    XMEMCPY(padded + sizeof(padded) - sizeof(dh_2048_peer), dh_2048_peer,
            sizeof(dh_2048_peer));
    mech.pParameter = padded;
    mech.ulParameterLen = sizeof(padded);
    ret = derive_generic(session, &mech, base, 32, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "DH public value longer than any prime rejected");

#ifdef WIDE_CK_ULONG
    mech.pParameter = dh_2048_peer;
    mech.ulParameterLen = LEN_ABOVE_WORD32(sizeof(dh_2048_peer));
    ret = derive_generic(session, &mech, base, 32, &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "DH public value length beyond 32 bits rejected");
#endif

cleanup:
    destroy_obj(session, &derived);
    destroy_obj(session, &base);
    return result;
}
#endif

#ifdef AES_CBC_WIDE_TEST
/* The AES-CBC encrypt-data length must be representable in 32 bits. */
static int test_aes_cbc_data_length_fits_word32(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    byte key[sizeof(aes_cbc_key)];
    byte plain[sizeof(aes_cbc_plain)];
    CK_AES_CBC_ENCRYPT_DATA_PARAMS params;
    CK_MECHANISM mech = { CKM_AES_CBC_ENCRYPT_DATA, &params, sizeof(params) };
    int result = 0;

    XMEMCPY(key, aes_cbc_key, sizeof(key));
    XMEMCPY(plain, aes_cbc_plain, sizeof(plain));
    ret = create_secret_base(session, CKK_AES, key, sizeof(key), &base);
    CHECK_CKR(ret, "create AES base key");

    XMEMSET(&params, 0, sizeof(params));
    XMEMCPY(params.iv, aes_cbc_iv, sizeof(params.iv));
    params.pData = plain;
    params.length = sizeof(plain);
    ret = derive_generic(session, &mech, base, sizeof(plain), &derived);
    CHECK_CKR(ret, "AES-CBC encrypt-data derive");
    destroy_obj(session, &derived);

    params.length = LEN_ABOVE_WORD32(sizeof(plain));
    ret = derive_generic(session, &mech, base, sizeof(plain), &derived);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "AES-CBC data length beyond 32 bits rejected");

cleanup:
    destroy_obj(session, &derived);
    destroy_obj(session, &base);
    return result;
}
#endif

#ifdef WOLFSSL_HAVE_PRF
static byte clientRandom[32] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80
};
static byte serverRandom[32] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60
};

static void tls_key_mat_init(CK_TLS12_KEY_MAT_PARAMS* params,
                             CK_SSL3_KEY_MAT_OUT* out, CK_ULONG macBits,
                             CK_ULONG keyBits, CK_ULONG ivBits)
{
    XMEMSET(out, 0, sizeof(*out));
    out->hClientMacSecret = CK_INVALID_HANDLE;
    out->hServerMacSecret = CK_INVALID_HANDLE;
    out->hClientKey = CK_INVALID_HANDLE;
    out->hServerKey = CK_INVALID_HANDLE;
    XMEMSET(params, 0, sizeof(*params));
    params->ulMacSizeInBits = macBits;
    params->ulKeySizeInBits = keyBits;
    params->ulIVSizeInBits = ivBits;
    params->bIsExport = CK_FALSE;
    params->RandomInfo.pClientRandom = clientRandom;
    params->RandomInfo.ulClientRandomLen = sizeof(clientRandom);
    params->RandomInfo.pServerRandom = serverRandom;
    params->RandomInfo.ulServerRandomLen = sizeof(serverRandom);
    params->pReturnedKeyMaterial = out;
    params->prfHashMechanism = CKM_SHA256;
}

static CK_RV tls_key_mat_derive(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE base,
                                CK_TLS12_KEY_MAT_PARAMS* params,
                                CK_ATTRIBUTE* tmpl, CK_ULONG cnt)
{
    CK_MECHANISM mech;
    CK_ATTRIBUTE defTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
    };

    if (tmpl == NULL) {
        tmpl = defTmpl;
        cnt = sizeof(defTmpl) / sizeof(*defTmpl);
    }
    mech.mechanism = CKM_TLS12_KEY_AND_MAC_DERIVE;
    mech.pParameter = params;
    mech.ulParameterLen = sizeof(*params);

    return funcList->C_DeriveKey(session, &mech, base, tmpl, cnt, NULL);
}

static void destroy_key_mat(CK_SESSION_HANDLE session,
                            CK_SSL3_KEY_MAT_OUT* out)
{
    destroy_obj(session, &out->hClientMacSecret);
    destroy_obj(session, &out->hServerMacSecret);
    destroy_obj(session, &out->hClientKey);
    destroy_obj(session, &out->hServerKey);
}

/* Every TLS key material size must be a whole number of bytes. */
static int test_tls_key_sizes_byte_aligned(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_TLS12_KEY_MAT_PARAMS params;
    CK_SSL3_KEY_MAT_OUT out;
    byte ivClient[16];
    byte ivServer[16];
    byte master[48];
    int result = 0;

    XMEMSET(master, 0x5c, sizeof(master));
    tls_key_mat_init(&params, &out, 256, 128, 128);
    ret = create_secret_base(session, CKK_GENERIC_SECRET, master,
                             sizeof(master), &base);
    CHECK_CKR(ret, "create TLS master secret");

    out.pIVClient = ivClient;
    out.pIVServer = ivServer;
    ret = tls_key_mat_derive(session, base, &params, NULL, 0);
    CHECK_CKR(ret, "TLS key and MAC derive");
    destroy_key_mat(session, &out);

    tls_key_mat_init(&params, &out, 4, 4, 0);
    ret = tls_key_mat_derive(session, base, &params, NULL, 0);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "TLS MAC and key sizes not whole bytes rejected");

    tls_key_mat_init(&params, &out, 256, 128, 4);
    out.pIVClient = ivClient;
    out.pIVServer = ivServer;
    ret = tls_key_mat_derive(session, base, &params, NULL, 0);
    CHECK_RV(ret, CKR_MECHANISM_PARAM_INVALID,
             "TLS IV size not whole bytes rejected");

cleanup:
    destroy_key_mat(session, &out);
    destroy_obj(session, &base);
    return result;
}
#endif

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

static int kdf_tls_derive_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing C_DeriveKey with KDF and TLS mechanisms ===\n");

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize");

    ret = pkcs11_setup_token();
    CHECK_CKR(ret, "token setup");

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession");
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login");

#if defined(WOLFPKCS11_HKDF) && defined(WIDE_CK_ULONG)
    if (test_hkdf_lengths_fit_word32(session) != 0)
        result = -1;
#endif

#ifdef NSS_EMS_WIDE_TEST
    if (test_session_hash_length_fits_word32(session) != 0)
        result = -1;
#endif

#ifndef NO_DH
    if (test_dh_public_length_bound(session) != 0)
        result = -1;
#endif

#ifdef AES_CBC_WIDE_TEST
    if (test_aes_cbc_data_length_fits_word32(session) != 0)
        result = -1;
#endif

#ifdef WOLFSSL_HAVE_PRF
    if (test_tls_key_sizes_byte_aligned(session) != 0)
        result = -1;
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

    if (kdf_tls_derive_test() != 0 && test_failed == 0)
        test_failed++;

    print_results();
#ifndef DERIVE_TESTS
    if (test_failed == 0)
        return 77;
#endif
    return (test_failed == 0) ? 0 : 1;
}
