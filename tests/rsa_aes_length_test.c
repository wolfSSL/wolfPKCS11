/* rsa_aes_length_test.c
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
 * Length return codes of single-part RSA encrypt, decrypt and sign, the
 * RSA-PSS salt length limit, and AES lengths that do not fit a word32.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>

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
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/rsa_aes_length_test"

#if !defined(NO_AES) && (defined(HAVE_AESGCM) || defined(HAVE_AESCCM) || \
    defined(HAVE_AES_CBC) || defined(HAVE_AESECB))
    #define TEST_AES_OVER_4G
#endif

#if !defined(NO_RSA) || defined(TEST_AES_OVER_4G)
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
#endif

#ifndef NO_RSA
#define RSA_K   ((CK_ULONG)sizeof(rsa_2048_modulus))

static CK_RV create_rsa_keys(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* priv,
                             CK_OBJECT_HANDLE* pub)
{
    CK_RV rv;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_SIGN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_DECRYPT,          &ckTrue,           sizeof(ckTrue)            },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,            &pubClass,         sizeof(pubClass)          },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_VERIFY,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_ENCRYPT,          &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };

    rv = funcList->C_CreateObject(session, privTmpl,
                                  sizeof(privTmpl) / sizeof(*privTmpl), priv);
    CHECK_RV(rv, "C_CreateObject(RSA private key)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, pubTmpl,
                                      sizeof(pubTmpl) / sizeof(*pubTmpl), pub);
        CHECK_RV(rv, "C_CreateObject(RSA public key)", CKR_OK);
    }
    return rv;
}

/* C_Encrypt gives the expected code; a failure ends the operation. */
static void check_encrypt(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                          CK_OBJECT_HANDLE key, CK_BYTE* data,
                          CK_ULONG dataLen, int sizeQuery, CK_RV expected,
                          const char* what)
{
    CK_RV rv;
    CK_BYTE out[512];
    CK_ULONG outLen = sizeof(out);

    rv = funcList->C_EncryptInit(session, mech, key);
    if (rv != CKR_OK) {
        CHECK_RV(rv, "C_EncryptInit", CKR_OK);
        return;
    }
    rv = funcList->C_Encrypt(session, data, dataLen, sizeQuery ? NULL : out,
                             &outLen);
    CHECK_RV(rv, what, expected);
    if (rv == CKR_OK && sizeQuery)
        rv = funcList->C_Encrypt(session, data, dataLen, out, &outLen);
    if (expected == CKR_OK) {
        CHECK_RV(rv, what, CKR_OK);
        return;
    }
    rv = funcList->C_Encrypt(session, data, dataLen, out, &outLen);
    CHECK_RV(rv, "C_Encrypt ended the operation",
             CKR_OPERATION_NOT_INITIALIZED);
}

static void check_decrypt(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                          CK_OBJECT_HANDLE key, CK_BYTE* enc, CK_ULONG encLen,
                          CK_RV expected, const char* what)
{
    CK_RV rv;
    CK_BYTE out[512];
    CK_ULONG outLen = sizeof(out);

    rv = funcList->C_DecryptInit(session, mech, key);
    if (rv != CKR_OK) {
        CHECK_RV(rv, "C_DecryptInit", CKR_OK);
        return;
    }
    rv = funcList->C_Decrypt(session, enc, encLen, out, &outLen);
    CHECK_RV(rv, what, expected);
    if (expected == CKR_OK)
        return;
    rv = funcList->C_Decrypt(session, enc, encLen, out, &outLen);
    CHECK_RV(rv, "C_Decrypt ended the operation",
             CKR_OPERATION_NOT_INITIALIZED);
}

static void check_sign(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                       CK_OBJECT_HANDLE key, CK_BYTE* data, CK_ULONG dataLen,
                       CK_RV expected, const char* what)
{
    CK_RV rv;
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);

    rv = funcList->C_SignInit(session, mech, key);
    if (rv != CKR_OK) {
        CHECK_RV(rv, "C_SignInit", CKR_OK);
        return;
    }
    rv = funcList->C_Sign(session, data, dataLen, sig, &sigLen);
    CHECK_RV(rv, what, expected);
    if (expected == CKR_OK)
        return;
    rv = funcList->C_Sign(session, data, dataLen, sig, &sigLen);
    CHECK_RV(rv, "C_Sign ended the operation", CKR_OPERATION_NOT_INITIALIZED);
}

#ifdef WC_RSA_DIRECT
static void check_sign_size_query(CK_SESSION_HANDLE session,
                                  CK_MECHANISM* mech, CK_OBJECT_HANDLE key,
                                  CK_BYTE* data, CK_ULONG dataLen,
                                  CK_RV expected, const char* what)
{
    CK_RV rv;
    CK_BYTE sig[512];
    CK_ULONG sigLen = 0;

    rv = funcList->C_SignInit(session, mech, key);
    if (rv != CKR_OK) {
        CHECK_RV(rv, "C_SignInit", CKR_OK);
        return;
    }
    rv = funcList->C_Sign(session, data, dataLen, NULL, &sigLen);
    CHECK_RV(rv, what, expected);
    sigLen = sizeof(sig);
    rv = funcList->C_Sign(session, data, dataLen, sig, &sigLen);
    if (expected != CKR_OK) {
        CHECK_RV(rv, "C_Sign ended the operation",
                 CKR_OPERATION_NOT_INITIALIZED);
    }
}
#endif

#ifdef WC_RSA_DIRECT
static CK_RV x509_verify(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                         CK_OBJECT_HANDLE pub, CK_BYTE* data, CK_BYTE* sig)
{
    CK_RV rv;

    rv = funcList->C_VerifyInit(session, mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_Verify(session, data, RSA_K, sig, RSA_K);
    return rv;
}

/* Raw RSA input and signatures at or above the modulus. */
static void check_x509_range(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
                             CK_OBJECT_HANDLE pub)
{
    CK_RV rv = CKR_OK;
    CK_MECHANISM mech;
    CK_BYTE big[RSA_K];
    CK_BYTE data[RSA_K];
    CK_BYTE sig[RSA_K];
    CK_ULONG sigLen;
    int i;
    int carry;

    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_RSA_X_509;
    XMEMSET(big, 0xFF, sizeof(big));
    check_encrypt(session, &mech, pub, big, RSA_K, 0, CKR_DATA_INVALID,
                  "CKM_RSA_X_509 encrypt: input above the modulus");
    check_sign(session, &mech, priv, big, RSA_K, CKR_DATA_INVALID,
               "CKM_RSA_X_509 sign: input above the modulus");

    /* Find a signature s small enough that s + n still fits in k bytes. */
    XMEMSET(data, 0, sizeof(data));
    for (i = 2; i < 64; i++) {
        data[RSA_K - 1] = (CK_BYTE)i;
        sigLen = sizeof(sig);
        rv = funcList->C_SignInit(session, &mech, priv);
        if (rv == CKR_OK)
            rv = funcList->C_Sign(session, data, RSA_K, sig, &sigLen);
        if (rv != CKR_OK || sig[0] < 0xFF - rsa_2048_modulus[0])
            break;
    }
    CHECK_TRUE(rv == CKR_OK && sig[0] < 0xFF - rsa_2048_modulus[0],
               "CKM_RSA_X_509 sign: signature for s + n");
    if (rv != CKR_OK || sig[0] >= 0xFF - rsa_2048_modulus[0])
        return;
    rv = x509_verify(session, &mech, pub, data, sig);
    CHECK_RV(rv, "CKM_RSA_X_509 verify: s", CKR_OK);
    carry = 0;
    for (i = (int)RSA_K - 1; i >= 0; i--) {
        carry += sig[i] + rsa_2048_modulus[i];
        sig[i] = (CK_BYTE)carry;
        carry >>= 8;
    }
    rv = x509_verify(session, &mech, pub, data, sig);
    CHECK_RV(rv, "CKM_RSA_X_509 verify: s + n", CKR_SIGNATURE_INVALID);
}
#endif

/* k, k-1 and k+1 byte and out-of-range ciphertexts for an RSA decrypt. */
static void check_decrypt_lengths(CK_SESSION_HANDLE session,
                                  CK_MECHANISM* mech, CK_OBJECT_HANDLE priv,
                                  CK_OBJECT_HANDLE pub, CK_BYTE* data,
                                  CK_ULONG dataLen, const char* name)
{
    CK_RV rv;
    CK_BYTE enc[RSA_K + 1];
    CK_BYTE big[RSA_K];
    CK_ULONG encLen = sizeof(enc);
    char what[96];

    rv = funcList->C_EncryptInit(session, mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, data, dataLen, enc, &encLen);
    CHECK_RV(rv, "C_Encrypt for decrypt", CKR_OK);
    if (rv != CKR_OK)
        return;
    enc[RSA_K] = 0;

    snprintf(what, sizeof(what), "%s: k-byte ciphertext", name);
    check_decrypt(session, mech, priv, enc, RSA_K, CKR_OK, what);
    snprintf(what, sizeof(what), "%s: k-1 byte ciphertext", name);
    check_decrypt(session, mech, priv, enc + 1, RSA_K - 1,
                  CKR_ENCRYPTED_DATA_LEN_RANGE, what);
    snprintf(what, sizeof(what), "%s: k+1 byte ciphertext", name);
    check_decrypt(session, mech, priv, enc, RSA_K + 1,
                  CKR_ENCRYPTED_DATA_LEN_RANGE, what);
    XMEMSET(big, 0xFF, sizeof(big));
    snprintf(what, sizeof(what), "%s: ciphertext above the modulus", name);
    check_decrypt(session, mech, priv, big, RSA_K, CKR_ENCRYPTED_DATA_INVALID,
                  what);
}

static void test_rsa(CK_SESSION_HANDLE session)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_BYTE data[RSA_K + 1];
#if !defined(WC_NO_RSA_OAEP) && !defined(NO_SHA256)
    CK_RSA_PKCS_OAEP_PARAMS oaep;
#endif

    printf("--- RSA ---\n");
    if (create_rsa_keys(session, &priv, &pub) != CKR_OK)
        return;
    /* A leading zero keeps k-byte raw input below the modulus. */
    XMEMSET(data, 0x5A, sizeof(data));
    data[0] = 0;
    XMEMSET(&mech, 0, sizeof(mech));

    mech.mechanism = CKM_RSA_PKCS;
    check_encrypt(session, &mech, pub, data, RSA_K - 11, 0, CKR_OK,
                  "CKM_RSA_PKCS encrypt: k-11 bytes");
    check_encrypt(session, &mech, pub, data, RSA_K - 10, 0, CKR_DATA_LEN_RANGE,
                  "CKM_RSA_PKCS encrypt: k-10 bytes");
    check_encrypt(session, &mech, pub, data, RSA_K - 10, 1, CKR_DATA_LEN_RANGE,
                  "CKM_RSA_PKCS encrypt size query: k-10 bytes");
    check_encrypt(session, &mech, pub, data, 0, 0, CKR_DATA_LEN_RANGE,
                  "CKM_RSA_PKCS encrypt: 0 bytes");
    check_decrypt_lengths(session, &mech, priv, pub, data, 16, "CKM_RSA_PKCS");
    check_sign(session, &mech, priv, data, RSA_K - 11, CKR_OK,
               "CKM_RSA_PKCS sign: k-11 bytes");
    check_sign(session, &mech, priv, data, RSA_K - 10, CKR_DATA_LEN_RANGE,
               "CKM_RSA_PKCS sign: k-10 bytes");
    check_sign(session, &mech, priv, data, 0, CKR_DATA_LEN_RANGE,
               "CKM_RSA_PKCS sign: 0 bytes");

    mech.mechanism = CKM_RSA_X_509;
    check_encrypt(session, &mech, pub, data, RSA_K, 0, CKR_OK,
                  "CKM_RSA_X_509 encrypt: k bytes");
    check_encrypt(session, &mech, pub, data, RSA_K + 1, 0, CKR_DATA_LEN_RANGE,
                  "CKM_RSA_X_509 encrypt: k+1 bytes");
    check_encrypt(session, &mech, pub, data, 0, 0, CKR_DATA_LEN_RANGE,
                  "CKM_RSA_X_509 encrypt: 0 bytes");
    check_decrypt_lengths(session, &mech, priv, pub, data, RSA_K,
                          "CKM_RSA_X_509");
#ifdef WC_RSA_DIRECT
    check_sign(session, &mech, priv, data, RSA_K, CKR_OK,
               "CKM_RSA_X_509 sign: k bytes");
    check_sign(session, &mech, priv, data, RSA_K + 1, CKR_DATA_LEN_RANGE,
               "CKM_RSA_X_509 sign: k+1 bytes");
    check_sign(session, &mech, priv, data, 0, CKR_DATA_LEN_RANGE,
               "CKM_RSA_X_509 sign: 0 bytes");
    check_sign_size_query(session, &mech, priv, data, 0, CKR_DATA_LEN_RANGE,
                          "CKM_RSA_X_509 sign size query: 0 bytes");
    check_x509_range(session, priv, pub);
#endif

#if !defined(WC_NO_RSA_OAEP) && !defined(NO_SHA256)
    oaep.hashAlg = CKM_SHA256;
    oaep.mgf = CKG_MGF1_SHA256;
    oaep.source = CKZ_DATA_SPECIFIED;
    oaep.pSourceData = NULL;
    oaep.ulSourceDataLen = 0;
    mech.mechanism = CKM_RSA_PKCS_OAEP;
    mech.pParameter = &oaep;
    mech.ulParameterLen = sizeof(oaep);
    check_encrypt(session, &mech, pub, data, RSA_K - 66, 0, CKR_OK,
                  "CKM_RSA_PKCS_OAEP encrypt: k-66 bytes");
    check_encrypt(session, &mech, pub, data, RSA_K - 65, 0,
                  CKR_DATA_LEN_RANGE, "CKM_RSA_PKCS_OAEP encrypt: k-65 bytes");
    check_encrypt(session, &mech, pub, data, 0, 0, CKR_DATA_LEN_RANGE,
                  "CKM_RSA_PKCS_OAEP encrypt: 0 bytes");
    check_decrypt_lengths(session, &mech, priv, pub, data, 16,
                          "CKM_RSA_PKCS_OAEP");
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
#endif

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}

#if defined(WC_RSA_PSS) && !defined(NO_SHA256)
static void test_rsa_pss_salt(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_RSA_PKCS_PSS_PARAMS pss;
    CK_BYTE msg[] = "message to sign";
    CK_BYTE sig[RSA_K];
    CK_ULONG sigLen = sizeof(sig);

    printf("--- RSA-PSS salt length ---\n");
    if (create_rsa_keys(session, &priv, &pub) != CKR_OK)
        return;

    pss.hashAlg = CKM_SHA256;
    pss.mgf = CKG_MGF1_SHA256;
    pss.sLen = 33;
    mech.mechanism = CKM_SHA256_RSA_PKCS_PSS;
    mech.pParameter = &pss;
    mech.ulParameterLen = sizeof(pss);

    rv = funcList->C_SignInit(session, &mech, priv);
#if !defined(WOLFSSL_PSS_LONG_SALT) || FIPS_VERSION_GE(7,0)
    CHECK_RV(rv, "C_SignInit: salt longer than the hash",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_VerifyInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyInit: salt longer than the hash",
             CKR_MECHANISM_PARAM_INVALID);
#else
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, msg, sizeof(msg), sig, &sigLen);
    CHECK_RV(rv, "C_Sign: salt longer than the hash", CKR_OK);
    rv = funcList->C_VerifyInit(session, &mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_Verify(session, msg, sizeof(msg), sig, sigLen);
    CHECK_RV(rv, "C_Verify: salt longer than the hash", CKR_OK);
#endif
    (void)msg;
    (void)sig;
    (void)sigLen;

    /* Raw PSS signs a hash of exactly the PSS hash length. */
    pss.sLen = 32;
    mech.mechanism = CKM_RSA_PKCS_PSS;
    XMEMSET(sig, 0x3C, sizeof(sig));
    check_sign(session, &mech, priv, sig, 32, CKR_OK,
               "CKM_RSA_PKCS_PSS sign: 32-byte hash");
    check_sign(session, &mech, priv, sig, 31, CKR_DATA_LEN_RANGE,
               "CKM_RSA_PKCS_PSS sign: 31-byte hash");
    check_sign(session, &mech, priv, sig, 33, CKR_DATA_LEN_RANGE,
               "CKM_RSA_PKCS_PSS sign: 33-byte hash");
    rv = funcList->C_SignInit(session, &mech, priv);
    if (rv == CKR_OK) {
        sigLen = 0;
        rv = funcList->C_Sign(session, sig, 31, NULL, &sigLen);
    }
    CHECK_RV(rv, "CKM_RSA_PKCS_PSS sign size query: 31-byte hash",
             CKR_DATA_LEN_RANGE);
    if (rv == CKR_OK) {
        sigLen = sizeof(sig);
        funcList->C_Sign(session, sig, 32, sig, &sigLen);
    }

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif
#endif /* !NO_RSA */

#ifdef TEST_AES_OVER_4G
/* A CK_ULONG length whose low 32 bits are 16 must not be read as 16. */
static void check_decrypt_over_4g(CK_SESSION_HANDLE session,
                                  CK_MECHANISM* mech, CK_OBJECT_HANDLE key,
                                  int update, const char* what)
{
    CK_RV rv;
    CK_BYTE enc[32];
    CK_ULONG outLen = 0;
    CK_ULONG encLen = 0xFFFFFFFFUL;

    encLen += 17;
    XMEMSET(enc, 0, sizeof(enc));
    rv = funcList->C_DecryptInit(session, mech, key);
    if (rv != CKR_OK) {
        CHECK_RV(rv, "C_DecryptInit", CKR_OK);
        return;
    }
    if (update)
        rv = funcList->C_DecryptUpdate(session, enc, encLen, NULL, &outLen);
    else
        rv = funcList->C_Decrypt(session, enc, encLen, NULL, &outLen);
    CHECK_RV(rv, what, CKR_ENCRYPTED_DATA_LEN_RANGE);
    if (rv == CKR_OK)
        funcList->C_Decrypt(session, enc, 0, enc, &outLen);
}

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
/* Data length plus tag must not wrap a word32. */
static void check_encrypt_near_4g(CK_SESSION_HANDLE session,
                                  CK_MECHANISM* mech, CK_OBJECT_HANDLE key,
                                  CK_ULONG dataLen, const char* what)
{
    CK_RV rv;
    CK_BYTE data[32];
    CK_ULONG outLen = 0;

    XMEMSET(data, 0, sizeof(data));
    rv = funcList->C_EncryptInit(session, mech, key);
    if (rv != CKR_OK) {
        CHECK_RV(rv, "C_EncryptInit", CKR_OK);
        return;
    }
    rv = funcList->C_Encrypt(session, data, dataLen, NULL, &outLen);
    CHECK_RV(rv, what, CKR_DATA_LEN_RANGE);
    if (rv == CKR_OK) {
        outLen = sizeof(data);
        funcList->C_Encrypt(session, data, 0, data, &outLen);
    }
}
#endif

static void test_aes_over_4g(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_MECHANISM mech;
    CK_BYTE iv[16];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    int big = (sizeof(CK_ULONG) > 4);
#ifdef HAVE_AESGCM
    CK_GCM_PARAMS gcm;
#endif
#ifdef HAVE_AESCCM
    CK_CCM_PARAMS ccm;
#endif

    printf("--- AES lengths near and over 4 GiB ---\n");
    rv = funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
                                  &key);
    CHECK_RV(rv, "C_CreateObject(AES key)", CKR_OK);
    if (rv != CKR_OK)
        return;
    XMEMSET(iv, 9, sizeof(iv));
    XMEMSET(&mech, 0, sizeof(mech));

#ifdef HAVE_AES_CBC
    mech.mechanism = CKM_AES_CBC;
    mech.pParameter = iv;
    mech.ulParameterLen = sizeof(iv);
    if (big) {
        check_decrypt_over_4g(session, &mech, key, 0,
                              "CKM_AES_CBC over 4 GiB");
        check_decrypt_over_4g(session, &mech, key, 1,
                              "CKM_AES_CBC update over 4 GiB");
        mech.mechanism = CKM_AES_CBC_PAD;
        check_decrypt_over_4g(session, &mech, key, 0,
                              "CKM_AES_CBC_PAD over 4 GiB");
        check_decrypt_over_4g(session, &mech, key, 1,
                              "CKM_AES_CBC_PAD update over 4 GiB");
    }
#endif
#ifdef HAVE_AESECB
    mech.mechanism = CKM_AES_ECB;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    if (big) {
        check_decrypt_over_4g(session, &mech, key, 0,
                              "CKM_AES_ECB over 4 GiB");
    }
#endif
#ifdef HAVE_AESGCM
    XMEMSET(&gcm, 0, sizeof(gcm));
    gcm.pIv = iv;
    gcm.ulIvLen = 12;
    gcm.ulTagBits = 128;
    mech.mechanism = CKM_AES_GCM;
    mech.pParameter = &gcm;
    mech.ulParameterLen = sizeof(gcm);
    check_encrypt_near_4g(session, &mech, key, 0xFFFFFFF8UL,
                          "CKM_AES_GCM encrypt 0xFFFFFFF8 bytes");
    check_encrypt_near_4g(session, &mech, key, 0xFFFFFFC0UL,
                          "CKM_AES_GCM encrypt 0xFFFFFFC0 bytes");
    if (big) {
        check_decrypt_over_4g(session, &mech, key, 0,
                              "CKM_AES_GCM over 4 GiB");
    }
#endif
#ifdef HAVE_AESCCM
    XMEMSET(&ccm, 0, sizeof(ccm));
    ccm.pIv = iv;
    ccm.ulIvLen = 12;
    ccm.ulMacLen = 16;
    mech.mechanism = CKM_AES_CCM;
    mech.pParameter = &ccm;
    mech.ulParameterLen = sizeof(ccm);
    check_encrypt_near_4g(session, &mech, key, 0xFFFFFFF8UL,
                          "CKM_AES_CCM encrypt 0xFFFFFFF8 bytes");
    check_encrypt_near_4g(session, &mech, key, 0xFFFFFFC0UL,
                          "CKM_AES_CCM encrypt 0xFFFFFFC0 bytes");
    if (big) {
        check_decrypt_over_4g(session, &mech, key, 0,
                              "CKM_AES_CCM over 4 GiB");
    }
#endif

    funcList->C_DestroyObject(session, key);
}
#endif

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

#ifndef NO_RSA
    test_rsa(session);
#if defined(WC_RSA_PSS) && !defined(NO_SHA256)
    test_rsa_pss_salt(session);
#endif
#endif
#ifdef TEST_AES_OVER_4G
    test_aes_over_4g(session);
#endif

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 RSA and AES length return code test ===\n");
    run_test();
    return pkcs11_test_summary();
}
