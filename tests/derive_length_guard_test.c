/* derive_length_guard_test.c
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
 * Tests that C_DeriveKey refuses sensitive or non-extractable keys shorter
 * than 16 bytes, unless built with WOLFPKCS11_NO_DERIVE_LENGTH_GUARD.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"

#define TEST_DIR "./store/derive_length_guard_test"

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    #define TEST_AES_CBC
#endif
#if defined(HAVE_ECC) || defined(WOLFPKCS11_HKDF) || !defined(NO_DH) || \
    defined(WOLFPKCS11_CONCATENATE) || defined(TEST_AES_CBC) || \
    defined(WOLFSSL_HAVE_PRF)
    #define TEST_DERIVE
#endif

/* Derived keys are not limited with the guard off, or where they do not
 * inherit the base key's protection. */
#if defined(WOLFPKCS11_NO_DERIVE_LENGTH_GUARD) || \
    defined(WOLFPKCS11_NSS) || defined(WOLFPKCS11_LEGACY_DERIVE_NO_INHERIT)
    #define GUARD_RV(rv)    CKR_OK
#else
    #define GUARD_RV(rv)    (rv)
#endif
#ifdef WOLFPKCS11_NO_DERIVE_LENGTH_GUARD
    #define CUT_RV(rv)      CKR_OK
#else
    #define CUT_RV(rv)      (rv)
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

static void check(int cond, const char* msg)
{
    if (cond) {
        printf("PASS: %s\n", msg);
        test_passed++;
    }
    else {
        fprintf(stderr, "FAIL: %s\n", msg);
        test_failed++;
    }
}

static void check_rv(CK_RV rv, CK_RV exp, const char* msg)
{
    if (rv != exp)
        fprintf(stderr, "  got 0x%lx, expected 0x%lx\n", (unsigned long)rv,
                (unsigned long)exp);
    check(rv == exp, msg);
}

#ifdef TEST_DERIVE
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;

static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}

/* Checks the result of a derive into key, then destroys any key made. */
static void check_derive(CK_SESSION_HANDLE session, CK_RV rv, CK_RV exp,
                         CK_OBJECT_HANDLE* key, const char* msg)
{
    check_rv(rv, exp, msg);
    if (exp != CKR_OK)
        check(*key == CK_INVALID_HANDLE, "no key from the refused derive");
    destroy_obj(session, key);
}
#endif

#if defined(WOLFPKCS11_HKDF) || defined(WOLFSSL_HAVE_PRF) || \
    defined(WOLFPKCS11_CONCATENATE) || defined(TEST_AES_CBC)
static CK_RV create_secret(CK_SESSION_HANDLE session, CK_KEY_TYPE keyType,
                           byte* value, CK_ULONG len, CK_BBOOL protect,
                           CK_OBJECT_HANDLE* key)
{
    CK_BBOOL extractable = !protect;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)        },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)         },
        { CKA_SENSITIVE,   &protect,        sizeof(protect)        },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
        { CKA_VALUE,       value,           len                    },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}
#endif

#ifdef HAVE_ECC
static CK_RV ecdh_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                         CK_ULONG len, CK_BBOOL sensitive,
                         CK_BBOOL extractable, CK_OBJECT_HANDLE* key)
{
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)      },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
    };

    XMEMSET(&params, 0, sizeof(params));
    params.kdf = CKD_NULL;
    params.pPublicData = ecc_p256_point;
    params.ulPublicDataLen = sizeof(ecc_p256_point);
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}

static CK_RV ecdh_derive_value(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE base, CK_OBJECT_HANDLE* key)
{
    CK_BYTE value[1] = { 0 };
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE,       value,           sizeof(value)          },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
    };

    XMEMSET(&params, 0, sizeof(params));
    params.kdf = CKD_NULL;
    params.pPublicData = ecc_p256_point;
    params.ulPublicDataLen = sizeof(ecc_p256_point);
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}

static CK_RV create_ec_key(CK_SESSION_HANDLE session, CK_BBOOL sensitive,
                           CK_BBOOL extractable, CK_OBJECT_HANDLE* key)
{
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privClass,      sizeof(privClass)       },
        { CKA_KEY_TYPE,    &ecType,         sizeof(ecType)          },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,       ecc_p256_priv,   sizeof(ecc_p256_priv)   },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)       },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)     },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}

static void test_ecdh(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE prot = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE sens = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE noExt = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE plain = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;

    printf("\n--- ECDH derive lengths ---\n");
    rv = create_ec_key(session, CK_TRUE, CK_FALSE, &prot);
    check_rv(rv, CKR_OK, "create protected EC private key");
    if (rv == CKR_OK) {
        rv = create_ec_key(session, CK_TRUE, CK_TRUE, &sens);
        check_rv(rv, CKR_OK, "create sensitive EC private key");
    }
    if (rv == CKR_OK) {
        rv = create_ec_key(session, CK_FALSE, CK_FALSE, &noExt);
        check_rv(rv, CKR_OK, "create non-extractable EC private key");
    }
    if (rv == CKR_OK) {
        rv = create_ec_key(session, CK_FALSE, CK_TRUE, &plain);
        check_rv(rv, CKR_OK, "create plain EC private key");
    }
    if (rv != CKR_OK)
        goto cleanup;

    rv = ecdh_derive(session, prot, 1, CK_TRUE, CK_FALSE, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "one byte protected ECDH key");
    rv = ecdh_derive(session, prot, 15, CK_TRUE, CK_FALSE, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "15 byte protected ECDH key");
    rv = ecdh_derive(session, prot, 16, CK_TRUE, CK_FALSE, &key);
    check_derive(session, rv, CKR_OK, &key, "16 byte protected ECDH key");
    rv = ecdh_derive_value(session, prot, &key);
    check_derive(session, rv, CKR_TEMPLATE_INCONSISTENT, &key,
                 "CKA_VALUE in an ECDH template");
    rv = ecdh_derive(session, sens, 15, CK_TRUE, CK_TRUE, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "15 byte key from a sensitive base");
    rv = ecdh_derive(session, noExt, 15, CK_FALSE, CK_FALSE, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "15 byte key from a non-extractable base");

    rv = ecdh_derive(session, plain, 1, CK_TRUE, CK_FALSE, &key);
    check_derive(session, rv, CKR_OK, &key,
                 "one byte protected ECDH key from a readable base");
    rv = ecdh_derive(session, plain, 1, CK_FALSE, CK_TRUE, &key);
    check_derive(session, rv, CKR_OK, &key, "one byte readable ECDH key");

cleanup:
    destroy_obj(session, &plain);
    destroy_obj(session, &noExt);
    destroy_obj(session, &sens);
    destroy_obj(session, &prot);
}
#endif

#ifndef NO_DH
static CK_RV dh_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                       CK_ULONG len, CK_OBJECT_HANDLE* key)
{
    CK_MECHANISM mech = { CKM_DH_PKCS_DERIVE, dh_2048_peer,
                          sizeof(dh_2048_peer) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
    };

    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}

static void test_dh(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE dhType = CKK_DH;
    CK_BBOOL extractable = CK_FALSE;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privClass,     sizeof(privClass)      },
        { CKA_KEY_TYPE,    &dhType,        sizeof(dhType)         },
        { CKA_SENSITIVE,   &ckTrue,        sizeof(ckTrue)         },
        { CKA_EXTRACTABLE, &extractable,   sizeof(extractable)    },
        { CKA_DERIVE,      &ckTrue,        sizeof(ckTrue)         },
        { CKA_PRIME,       dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p) },
        { CKA_BASE,        dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g) },
        { CKA_VALUE,       dh_2048_priv,   sizeof(dh_2048_priv)   },
    };

    printf("\n--- DH derive lengths ---\n");
    rv = funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
                                  &base);
    check_rv(rv, CKR_OK, "create protected DH private key");
    if (rv != CKR_OK)
        return;

    rv = dh_derive(session, base, 15, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "15 byte protected DH key");
    rv = dh_derive(session, base, 16, &key);
    check_derive(session, rv, CKR_OK, &key, "16 byte protected DH key");

    destroy_obj(session, &base);
}
#endif

#ifdef WOLFPKCS11_HKDF
static CK_RV hkdf_expand(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                         CK_ULONG len, CK_OBJECT_HANDLE* key)
{
    CK_BYTE info[] = { 0x01, 0x02, 0x03, 0x04 };
    CK_HKDF_PARAMS params;
    CK_MECHANISM mech = { CKM_HKDF_DERIVE, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
    };

    XMEMSET(&params, 0, sizeof(params));
    params.bExtract = CK_FALSE;
    params.bExpand = CK_TRUE;
    params.prfHashMechanism = CKM_SHA256;
    params.ulSaltType = CKF_HKDF_SALT_NULL;
    params.pInfo = info;
    params.ulInfoLen = sizeof(info);
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}

#ifdef WOLFPKCS11_NSS
static CK_RV hkdf_data(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                       CK_ULONG len, CK_BBOOL extractable,
                       CK_OBJECT_HANDLE* key)
{
    CK_BYTE info[] = { 0x01, 0x02, 0x03, 0x04 };
    CK_BBOOL sensitive = !extractable;
    CK_HKDF_PARAMS params;
    CK_MECHANISM mech = { CKM_HKDF_DATA, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)      },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
    };

    XMEMSET(&params, 0, sizeof(params));
    params.bExtract = CK_FALSE;
    params.bExpand = CK_TRUE;
    params.prfHashMechanism = CKM_SHA256;
    params.ulSaltType = CKF_HKDF_SALT_NULL;
    params.pInfo = info;
    params.ulInfoLen = sizeof(info);
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}
#endif

/* HKDF extract and expand into a sensitive key with the salt in a key. */
static CK_RV hkdf_salt_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                           CK_OBJECT_HANDLE salt, CK_ULONG len,
                           CK_OBJECT_HANDLE* key)
{
    CK_HKDF_PARAMS params;
    CK_MECHANISM mech = { CKM_HKDF_DERIVE, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
    };

    XMEMSET(&params, 0, sizeof(params));
    params.bExtract = CK_TRUE;
    params.bExpand = CK_TRUE;
    params.prfHashMechanism = CKM_SHA256;
    params.ulSaltType = CKF_HKDF_SALT_KEY;
    params.hSaltKey = salt;
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}

/* The derived key depends on the salt key's value as much as on the base
 * key's, so a protected salt key limits the length even when the base key is
 * readable. */
static void test_hkdf_salt_key(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE salt = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE readableSalt = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte ikm[32];
    byte saltValue[16];

    printf("\n--- HKDF salt key lengths ---\n");
    XMEMSET(ikm, 0x0b, sizeof(ikm));
    XMEMSET(saltValue, 0x3c, sizeof(saltValue));
    rv = create_secret(session, CKK_GENERIC_SECRET, ikm, sizeof(ikm), CK_FALSE,
                       &base);
    check_rv(rv, CKR_OK, "create readable HKDF base key");
    if (rv == CKR_OK) {
        rv = create_secret(session, CKK_GENERIC_SECRET, saltValue,
                           sizeof(saltValue), CK_TRUE, &salt);
        check_rv(rv, CKR_OK, "create protected HKDF salt key");
    }
    if (rv == CKR_OK) {
        rv = create_secret(session, CKK_GENERIC_SECRET, saltValue,
                           sizeof(saltValue), CK_FALSE, &readableSalt);
        check_rv(rv, CKR_OK, "create readable HKDF salt key");
    }
    if (rv != CKR_OK)
        goto cleanup;

    rv = hkdf_salt_key(session, base, salt, 8, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "8 byte HKDF key from a protected salt key");
    rv = hkdf_salt_key(session, base, salt, 16, &key);
    check_derive(session, rv, CKR_OK, &key,
                 "16 byte HKDF key from a protected salt key");
    rv = hkdf_salt_key(session, base, readableSalt, 8, &key);
    check_derive(session, rv, CKR_OK, &key,
                 "8 byte HKDF key from a readable salt key");

cleanup:
    destroy_obj(session, &readableSalt);
    destroy_obj(session, &salt);
    destroy_obj(session, &base);
}

static void test_hkdf(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte prk[32];
#ifdef WOLFPKCS11_NSS
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,       &dataClass,      sizeof(dataClass)      },
        { CKA_VALUE,       prk,             sizeof(prk)            },
    };
#endif

    printf("\n--- HKDF expand lengths ---\n");
    XMEMSET(prk, 0x5a, sizeof(prk));
    rv = create_secret(session, CKK_GENERIC_SECRET, prk, sizeof(prk), CK_TRUE,
                       &base);
    check_rv(rv, CKR_OK, "create protected HKDF key");
    if (rv != CKR_OK)
        return;

    rv = hkdf_expand(session, base, 1, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "one byte protected HKDF key");
    rv = hkdf_expand(session, base, 15, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "15 byte protected HKDF key");
    rv = hkdf_expand(session, base, 16, &key);
    check_derive(session, rv, CKR_OK, &key, "16 byte protected HKDF key");
    destroy_obj(session, &base);

    test_hkdf_salt_key(session);

#ifdef WOLFPKCS11_NSS
    rv = funcList->C_CreateObject(session, dataTmpl,
                                  sizeof(dataTmpl) / sizeof(*dataTmpl), &base);
    check_rv(rv, CKR_OK, "create data object");
    if (rv != CKR_OK)
        return;
    rv = hkdf_data(session, base, 8, CK_FALSE, &key);
    check_derive(session, rv, CKR_OK, &key,
                 "8 byte protected HKDF key from a data object");
    rv = hkdf_data(session, base, 8, CK_TRUE, &key);
    check_derive(session, rv, CKR_OK, &key,
                 "8 byte readable HKDF key from a data object");
    destroy_obj(session, &base);
#endif
}
#endif

#ifdef WOLFSSL_HAVE_PRF
static void destroy_key_mat(CK_SESSION_HANDLE session, CK_SSL3_KEY_MAT_OUT* out)
{
    destroy_obj(session, &out->hClientMacSecret);
    destroy_obj(session, &out->hServerMacSecret);
    destroy_obj(session, &out->hClientKey);
    destroy_obj(session, &out->hServerKey);
}

static void check_key_mat(CK_SESSION_HANDLE session, CK_RV rv, CK_RV exp,
                          CK_SSL3_KEY_MAT_OUT* out, const char* msg)
{
    check_rv(rv, exp, msg);
    if (exp != CKR_OK) {
        check(out->hClientMacSecret == CK_INVALID_HANDLE &&
              out->hServerMacSecret == CK_INVALID_HANDLE &&
              out->hClientKey == CK_INVALID_HANDLE &&
              out->hServerKey == CK_INVALID_HANDLE,
              "no keys from the refused derive");
    }
    destroy_key_mat(session, out);
}

static CK_RV tls12_key_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                              CK_ULONG macBits, CK_ULONG keyBits,
                              CK_ULONG valueLen, CK_SSL3_KEY_MAT_OUT* out)
{
    CK_BYTE clientRandom[32];
    CK_BYTE serverRandom[32];
    CK_TLS12_KEY_MAT_PARAMS params;
    CK_MECHANISM mech = { CKM_TLS12_KEY_AND_MAC_DERIVE, &params,
                          sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &valueLen,       sizeof(valueLen)       },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    if (valueLen == 0)
        cnt--;
    XMEMSET(clientRandom, 0x11, sizeof(clientRandom));
    XMEMSET(serverRandom, 0x22, sizeof(serverRandom));
    XMEMSET(&params, 0, sizeof(params));
    params.ulMacSizeInBits = macBits;
    params.ulKeySizeInBits = keyBits;
    params.ulIVSizeInBits = 0;
    params.bIsExport = CK_FALSE;
    params.RandomInfo.pClientRandom = clientRandom;
    params.RandomInfo.ulClientRandomLen = sizeof(clientRandom);
    params.RandomInfo.pServerRandom = serverRandom;
    params.RandomInfo.ulServerRandomLen = sizeof(serverRandom);
    params.pReturnedKeyMaterial = out;
    params.prfHashMechanism = CKM_SHA256;
    XMEMSET(out, 0, sizeof(*out));

    return funcList->C_DeriveKey(session, &mech, base, tmpl, cnt, NULL);
}

static CK_RV tls12_master_derive(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE base, CK_ULONG len,
                                 CK_OBJECT_HANDLE* key)
{
    CK_BYTE clientRandom[32];
    CK_BYTE serverRandom[32];
    CK_VERSION version = { 3, 3 };
    CK_TLS12_MASTER_KEY_DERIVE_PARAMS params;
    CK_MECHANISM mech = { CKM_TLS12_MASTER_KEY_DERIVE, &params,
                          sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
    };

    XMEMSET(clientRandom, 0x11, sizeof(clientRandom));
    XMEMSET(serverRandom, 0x22, sizeof(serverRandom));
    XMEMSET(&params, 0, sizeof(params));
    params.RandomInfo.pClientRandom = clientRandom;
    params.RandomInfo.ulClientRandomLen = sizeof(clientRandom);
    params.RandomInfo.pServerRandom = serverRandom;
    params.RandomInfo.ulServerRandomLen = sizeof(serverRandom);
    params.pVersion = &version;
    params.prfHashMechanism = CKM_SHA256;
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}

static void test_tls12_master(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte preMaster[48];

    printf("\n--- TLS 1.2 master secret lengths ---\n");
    XMEMSET(preMaster, 0x33, sizeof(preMaster));
    preMaster[0] = 3;
    preMaster[1] = 3;
    rv = create_secret(session, CKK_GENERIC_SECRET, preMaster,
                       sizeof(preMaster), CK_TRUE, &base);
    check_rv(rv, CKR_OK, "create protected TLS pre-master secret");
    if (rv != CKR_OK)
        return;

    rv = tls12_master_derive(session, base, 15, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "TLS master secret truncated to 15 bytes");
    rv = tls12_master_derive(session, base, 48, &key);
    check_derive(session, rv, CKR_OK, &key, "48 byte TLS master secret");

    destroy_obj(session, &base);
}

/* A protected master is tied to the sizes of its first key and MAC derive,
 * so each case uses a master of its own. */
static void tls12_key_case(CK_SESSION_HANDLE session, CK_ULONG macBits,
                           CK_ULONG keyBits, CK_ULONG valueLen, CK_RV exp,
                           const char* msg)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_SSL3_KEY_MAT_OUT out;
    byte master[48];

    XMEMSET(master, 0x77, sizeof(master));
    rv = create_secret(session, CKK_GENERIC_SECRET, master, sizeof(master),
                       CK_TRUE, &base);
    check_rv(rv, CKR_OK, "create protected TLS master secret");
    if (rv != CKR_OK)
        return;

    rv = tls12_key_derive(session, base, macBits, keyBits, valueLen, &out);
    check_key_mat(session, rv, exp, &out, msg);
    destroy_obj(session, &base);
}

static void test_tls12(CK_SESSION_HANDLE session)
{
    printf("\n--- TLS 1.2 key and MAC derive lengths ---\n");
    tls12_key_case(session, 256, 64, 0, GUARD_RV(CKR_MECHANISM_PARAM_INVALID),
                   "8 byte protected TLS keys");
    tls12_key_case(session, 64, 128, 0, GUARD_RV(CKR_MECHANISM_PARAM_INVALID),
                   "8 byte protected TLS MAC secrets");
    tls12_key_case(session, 64, 128, 4, GUARD_RV(CKR_MECHANISM_PARAM_INVALID),
                   "8 byte TLS MAC secrets truncated to 4 bytes");
    tls12_key_case(session, 256, 128, 8, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID),
                   "TLS keys truncated to 8 bytes");
    tls12_key_case(session, 256, 128, 0, CKR_OK, "16 byte protected TLS keys");
    tls12_key_case(session, 128, 128, 0, CKR_OK,
                   "16 byte protected TLS MAC secrets");
    tls12_key_case(session, 0, 128, 0, CKR_OK, "TLS keys without MAC secrets");
}
#endif

#ifdef WOLFPKCS11_CONCATENATE
static CK_RV concat_derive(CK_SESSION_HANDLE session, CK_MECHANISM_TYPE type,
                           CK_OBJECT_HANDLE base, CK_ULONG dataLen,
                           CK_ULONG len, CK_OBJECT_HANDLE* key)
{
    CK_BYTE data[16];
    CK_KEY_DERIVATION_STRING_DATA params;
    CK_MECHANISM mech = { type, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
    };
    CK_ULONG cnt = sizeof(tmpl) / sizeof(*tmpl);

    if (len == 0)
        cnt--;
    XMEMSET(data, 0x33, sizeof(data));
    params.pData = data;
    params.ulLen = dataLen;
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl, cnt, key);
}

static CK_RV concat_derive_value(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE base, CK_OBJECT_HANDLE* key)
{
    CK_BYTE data[8];
    CK_BYTE value[1] = { 0 };
    CK_KEY_DERIVATION_STRING_DATA params;
    CK_MECHANISM mech = { CKM_CONCATENATE_DATA_AND_BASE, &params,
                          sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE,       value,           sizeof(value)          },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
    };

    XMEMSET(data, 0x33, sizeof(data));
    params.pData = data;
    params.ulLen = sizeof(data);
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}

static void test_concat(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte value[32];

    printf("\n--- Concatenation lengths ---\n");
    XMEMSET(value, 0x44, sizeof(value));
    rv = create_secret(session, CKK_GENERIC_SECRET, value, sizeof(value),
                       CK_TRUE, &base);
    check_rv(rv, CKR_OK, "create protected base key");
    if (rv != CKR_OK)
        return;

    rv = concat_derive(session, CKM_CONCATENATE_BASE_AND_DATA, base, 16, 20,
                       &key);
    check_derive(session, rv, CUT_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "concatenation cutting a protected key");
    rv = concat_derive(session, CKM_CONCATENATE_BASE_AND_DATA, base, 8, 0,
                       &key);
    check_derive(session, rv, CKR_OK, &key,
                 "8 data bytes after a protected key");
    rv = concat_derive_value(session, base, &key);
    check_derive(session, rv, CKR_TEMPLATE_INCONSISTENT, &key,
                 "CKA_VALUE in a concatenation template");
    rv = concat_derive(session, CKM_CONCATENATE_DATA_AND_BASE, base, 8, 8,
                       &key);
    check_derive(session, rv, CKR_OK, &key,
                 "8 byte concatenation of data only");

    destroy_obj(session, &base);
}
#endif

#ifdef TEST_AES_CBC
static CK_RV aes_cbc_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                            CK_ULONG len, CK_OBJECT_HANDLE* key)
{
    CK_BYTE data[16];
    CK_AES_CBC_ENCRYPT_DATA_PARAMS params;
    CK_MECHANISM mech = { CKM_AES_CBC_ENCRYPT_DATA, &params, sizeof(params) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE_LEN,   &len,            sizeof(len)            },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
    };

    XMEMSET(data, 0x66, sizeof(data));
    XMEMSET(&params, 0, sizeof(params));
    params.pData = data;
    params.length = sizeof(data);
    *key = CK_INVALID_HANDLE;
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), key);
}

static void test_aes_cbc(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte value[16];

    printf("\n--- AES-CBC encrypt data lengths ---\n");
    XMEMSET(value, 0x55, sizeof(value));
    rv = create_secret(session, CKK_AES, value, sizeof(value), CK_TRUE, &base);
    check_rv(rv, CKR_OK, "create protected AES key");
    if (rv != CKR_OK)
        return;

    rv = aes_cbc_derive(session, base, 15, &key);
    check_derive(session, rv, GUARD_RV(CKR_ATTRIBUTE_VALUE_INVALID), &key,
                 "15 byte protected AES-CBC derived key");
    rv = aes_cbc_derive(session, base, 16, &key);
    check_derive(session, rv, CKR_OK, &key,
                 "16 byte protected AES-CBC derived key");

    destroy_obj(session, &base);
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

static void pkcs11_final(void)
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

int main(int argc, char* argv[])
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Derive Length Guard Test ===\n");

    rv = pkcs11_init();
    check_rv(rv, CKR_OK, "C_Initialize");
    if (rv == CKR_OK) {
        rv = pkcs11_setup_token();
        check_rv(rv, CKR_OK, "token setup");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
        check_rv(rv, CKR_OK, "C_OpenSession");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        check_rv(rv, CKR_OK, "C_Login");
    }
    if (rv == CKR_OK) {
#ifdef HAVE_ECC
        test_ecdh(session);
#endif
#ifdef WOLFPKCS11_HKDF
        test_hkdf(session);
#endif
#ifndef NO_DH
        test_dh(session);
#endif
#ifdef WOLFSSL_HAVE_PRF
        test_tls12_master(session);
        test_tls12(session);
#endif
#ifdef WOLFPKCS11_CONCATENATE
        test_concat(session);
#endif
#ifdef TEST_AES_CBC
        test_aes_cbc(session);
#endif
    }
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    return (test_failed == 0) ? 0 : 1;
}
