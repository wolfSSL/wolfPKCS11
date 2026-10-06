/* encrypt_decrypt_params_test.c
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
 * Checks that encrypt/decrypt operations report output lengths correctly and
 * validate mechanism parameters and data lengths.
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

#define TEST_DIR "./store/encrypt_decrypt_params_test"

#ifndef NO_AES
static CK_RV create_aes_key(CK_SESSION_HANDLE session, unsigned char* key,
                            CK_ULONG keyLen, CK_OBJECT_HANDLE* hKey)
{
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    NULL,         0                   },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };

    tmpl[2].pValue = key;
    tmpl[2].ulValueLen = keyLen;
    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), hKey);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
/* C_EncryptFinal must report the number of bytes it wrote, not leave the
 * caller's buffer capacity in place. */
static void test_cbc_pad_encrypt_final_len(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    byte iv[16];
    byte plain[20];
    byte enc[64];
    byte dec[64];
    CK_ULONG updLen;
    CK_ULONG lastLen;
    CK_ULONG decLen;

    XMEMSET(iv, 0x11, sizeof(iv));
    XMEMSET(plain, 0x22, sizeof(plain));
    XMEMSET(enc, 0, sizeof(enc));

    rv = create_aes_key(session, aes_128_key, sizeof(aes_128_key), &key);
    CHECK_RV(rv, "CBC-PAD: create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    mech.mechanism = CKM_AES_CBC_PAD;
    mech.pParameter = iv;
    mech.ulParameterLen = sizeof(iv);

    rv = funcList->C_EncryptInit(session, &mech, key);
    CHECK_RV(rv, "CBC-PAD: C_EncryptInit", CKR_OK);
    if (rv != CKR_OK)
        return;
    updLen = sizeof(enc);
    rv = funcList->C_EncryptUpdate(session, plain, sizeof(plain), enc,
                                   &updLen);
    CHECK_RV(rv, "CBC-PAD: C_EncryptUpdate", CKR_OK);
    if (rv != CKR_OK)
        return;
    CHECK_TRUE(updLen == 16, "CBC-PAD: update emits one full block");

    lastLen = sizeof(enc) - updLen;
    rv = funcList->C_EncryptFinal(session, enc + updLen, &lastLen);
    CHECK_RV(rv, "CBC-PAD: C_EncryptFinal (large buffer)", CKR_OK);
    CHECK_TRUE(lastLen == 16,
               "CBC-PAD: C_EncryptFinal reports the bytes written");
    if (rv != CKR_OK || lastLen != 16)
        return;

    rv = funcList->C_DecryptInit(session, &mech, key);
    CHECK_RV(rv, "CBC-PAD: C_DecryptInit", CKR_OK);
    if (rv != CKR_OK)
        return;
    decLen = sizeof(dec);
    rv = funcList->C_Decrypt(session, enc, updLen + lastLen, dec, &decLen);
    CHECK_RV(rv, "CBC-PAD: C_Decrypt of multi-part output", CKR_OK);
    CHECK_TRUE(decLen == sizeof(plain) &&
               XMEMCMP(dec, plain, sizeof(plain)) == 0,
               "CBC-PAD: multi-part ciphertext round-trips");
}
#endif

#if !defined(NO_RSA) && !defined(WC_NO_RSA_OAEP)
static CK_RV create_rsa_keys(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* pub,
                             CK_OBJECT_HANDLE* priv)
{
    CK_RV rv;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,           &pubClass,        sizeof(pubClass)         },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
        { CKA_ENCRYPT,         &ckTrue,          sizeof(ckTrue)           },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_DECRYPT,          &ckTrue,           sizeof(ckTrue)            },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_SENSITIVE,        &ckFalse,          sizeof(ckFalse)           },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };

    rv = funcList->C_CreateObject(session, pubTmpl,
                                  sizeof(pubTmpl) / sizeof(*pubTmpl), pub);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, privTmpl,
                                      sizeof(privTmpl) / sizeof(*privTmpl),
                                      priv);
    }
    return rv;
}

static void oaep_params_init(CK_RSA_PKCS_OAEP_PARAMS* params,
                             CK_MECHANISM* mech)
{
    params->hashAlg = CKM_SHA256;
    params->mgf = CKG_MGF1_SHA256;
    params->source = CKZ_DATA_SPECIFIED;
    params->pSourceData = NULL;
    params->ulSourceDataLen = 0;
    mech->mechanism = CKM_RSA_PKCS_OAEP;
    mech->pParameter = params;
    mech->ulParameterLen = sizeof(*params);
}

/* An OAEP encoding parameter with no source data must have zero length. */
static void test_oaep_source_ptr_len(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_RSA_PKCS_OAEP_PARAMS params;
    CK_MECHANISM mech;
    byte plain[16];
    byte enc[256];
    byte dec[256];
    CK_ULONG encLen;
    CK_ULONG decLen;

    XMEMSET(plain, 0x33, sizeof(plain));
    rv = create_rsa_keys(session, &pub, &priv);
    CHECK_RV(rv, "OAEP: create RSA keys", CKR_OK);
    if (rv != CKR_OK)
        return;

    oaep_params_init(&params, &mech);
    params.ulSourceDataLen = 1;
    rv = funcList->C_EncryptInit(session, &mech, pub);
    CHECK_RV(rv, "OAEP: C_EncryptInit NULL source with length",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_DecryptInit(session, &mech, priv);
    CHECK_RV(rv, "OAEP: C_DecryptInit NULL source with length",
             CKR_MECHANISM_PARAM_INVALID);

    oaep_params_init(&params, &mech);
    rv = funcList->C_EncryptInit(session, &mech, pub);
    CHECK_RV(rv, "OAEP: C_EncryptInit empty source", CKR_OK);
    if (rv != CKR_OK)
        return;
    encLen = sizeof(enc);
    rv = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encLen);
    CHECK_RV(rv, "OAEP: C_Encrypt empty source", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = funcList->C_DecryptInit(session, &mech, priv);
    CHECK_RV(rv, "OAEP: C_DecryptInit empty source", CKR_OK);
    if (rv != CKR_OK)
        return;
    decLen = sizeof(dec);
    rv = funcList->C_Decrypt(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "OAEP: C_Decrypt empty source", CKR_OK);
    CHECK_TRUE(decLen == sizeof(plain) &&
               XMEMCMP(dec, plain, sizeof(plain)) == 0,
               "OAEP: empty source round-trips");
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESCCM)
static void ccm_params_init(CK_CCM_PARAMS* params, CK_MECHANISM* mech,
                            byte* iv, CK_ULONG ivLen)
{
    XMEMSET(params, 0, sizeof(*params));
    params->pIv = iv;
    params->ulIvLen = ivLen;
    params->ulMacLen = 16;
    mech->mechanism = CKM_AES_CCM;
    mech->pParameter = params;
    mech->ulParameterLen = sizeof(*params);
}

/* CCM nonces must be 7 to 13 bytes long (NIST SP 800-38C). */
static void test_ccm_nonce_len(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_CCM_PARAMS params;
    CK_MECHANISM mech;
    byte iv[16];
    byte plain[16];
    byte enc[32];
    CK_ULONG encLen;
    static const CK_ULONG badLens[] = { 1, 6, 14, 16 };
    int i;

    XMEMSET(iv, 0x44, sizeof(iv));
    XMEMSET(plain, 0x55, sizeof(plain));

    rv = create_aes_key(session, aes_128_key, sizeof(aes_128_key), &key);
    CHECK_RV(rv, "CCM: create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    for (i = 0; i < (int)(sizeof(badLens) / sizeof(*badLens)); i++) {
        ccm_params_init(&params, &mech, iv, badLens[i]);
        printf("CCM: nonce length %lu\n", (unsigned long)badLens[i]);
        rv = funcList->C_EncryptInit(session, &mech, key);
        CHECK_RV(rv, "CCM: C_EncryptInit rejects nonce length",
                 CKR_MECHANISM_PARAM_INVALID);
        rv = funcList->C_DecryptInit(session, &mech, key);
        CHECK_RV(rv, "CCM: C_DecryptInit rejects nonce length",
                 CKR_MECHANISM_PARAM_INVALID);
    }

    ccm_params_init(&params, &mech, iv, 7);
    rv = funcList->C_EncryptInit(session, &mech, key);
    CHECK_RV(rv, "CCM: C_EncryptInit nonce length 7", CKR_OK);
    if (rv != CKR_OK)
        return;
    encLen = sizeof(enc);
    rv = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encLen);
    CHECK_RV(rv, "CCM: C_Encrypt nonce length 7", CKR_OK);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESCTR)
/* A NULL output buffer to C_Decrypt is a length query that leaves the
 * operation active. */
static void test_ctr_decrypt_size_query(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_AES_CTR_PARAMS params;
    CK_MECHANISM mech;
    byte plain[32];
    byte enc[32];
    byte dec[32];
    CK_ULONG encLen;
    CK_ULONG decLen;

    XMEMSET(&params, 0, sizeof(params));
    params.ulCounterBits = 32;
    XMEMSET(params.cb, 0x66, sizeof(params.cb));
    XMEMSET(plain, 0x77, sizeof(plain));
    mech.mechanism = CKM_AES_CTR;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);

    rv = create_aes_key(session, aes_128_key, sizeof(aes_128_key), &key);
    CHECK_RV(rv, "CTR: create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_EncryptInit(session, &mech, key);
    CHECK_RV(rv, "CTR: C_EncryptInit", CKR_OK);
    if (rv != CKR_OK)
        return;
    encLen = sizeof(enc);
    rv = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encLen);
    CHECK_RV(rv, "CTR: C_Encrypt", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_DecryptInit(session, &mech, key);
    CHECK_RV(rv, "CTR: C_DecryptInit", CKR_OK);
    if (rv != CKR_OK)
        return;
    decLen = 0;
    rv = funcList->C_Decrypt(session, enc, encLen, NULL, &decLen);
    CHECK_RV(rv, "CTR: C_Decrypt length query", CKR_OK);
    CHECK_TRUE(decLen == encLen, "CTR: length query reports plaintext size");

    decLen = sizeof(dec);
    rv = funcList->C_Decrypt(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "CTR: C_Decrypt after length query", CKR_OK);
    CHECK_TRUE(decLen == sizeof(plain) &&
               XMEMCMP(dec, plain, sizeof(plain)) == 0,
               "CTR: decrypt after length query round-trips");
}
#endif

#if !defined(NO_AES) && (defined(HAVE_AES_CBC) || defined(HAVE_AESECB))
/* Unpadded block modes reject data that is not a whole number of blocks with
 * the PKCS#11 length-range codes, and the failed call ends the operation. */
static void check_block_alignment(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key, CK_MECHANISM* mech)
{
    CK_RV rv;
    byte data[32];
    byte out[32];
    CK_ULONG outLen;

    XMEMSET(data, 0x5A, sizeof(data));

    rv = funcList->C_EncryptInit(session, mech, key);
    CHECK_RV(rv, "block align: C_EncryptInit", CKR_OK);
    if (rv != CKR_OK)
        return;
    outLen = sizeof(out);
    rv = funcList->C_Encrypt(session, data, 17, out, &outLen);
    CHECK_RV(rv, "block align: C_Encrypt of 17 bytes", CKR_DATA_LEN_RANGE);
    outLen = sizeof(out);
    rv = funcList->C_Encrypt(session, data, 16, out, &outLen);
    CHECK_RV(rv, "block align: encrypt operation ended after length error",
             CKR_OPERATION_NOT_INITIALIZED);

    rv = funcList->C_DecryptInit(session, mech, key);
    CHECK_RV(rv, "block align: C_DecryptInit", CKR_OK);
    if (rv != CKR_OK)
        return;
    outLen = sizeof(out);
    rv = funcList->C_Decrypt(session, data, 15, out, &outLen);
    CHECK_RV(rv, "block align: C_Decrypt of 15 bytes",
             CKR_ENCRYPTED_DATA_LEN_RANGE);
    outLen = sizeof(out);
    rv = funcList->C_Decrypt(session, data, 16, out, &outLen);
    CHECK_RV(rv, "block align: decrypt operation ended after length error",
             CKR_OPERATION_NOT_INITIALIZED);
}

static void test_block_mode_alignment(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
#ifdef HAVE_AES_CBC
    byte iv[16];
#endif

    rv = create_aes_key(session, aes_128_key, sizeof(aes_128_key), &key);
    CHECK_RV(rv, "block align: create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

#ifdef HAVE_AES_CBC
    XMEMSET(iv, 0x12, sizeof(iv));
    mech.mechanism = CKM_AES_CBC;
    mech.pParameter = iv;
    mech.ulParameterLen = sizeof(iv);
    printf("AES-CBC\n");
    check_block_alignment(session, key, &mech);
#endif
#ifdef HAVE_AESECB
    mech.mechanism = CKM_AES_ECB;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    printf("AES-ECB\n");
    check_block_alignment(session, key, &mech);
#endif
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESECB)
/* CKA_CHECK_VALUE of an AES key is the first three bytes of one zero block
 * encrypted under the key, for every AES key size. */
static void test_aes_check_value_key_sizes(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key;
    CK_MECHANISM mech;
    byte keyData[32];
    byte zero[16];
    byte enc[16];
    byte kcv[3];
    CK_ULONG encLen;
    CK_ATTRIBUTE attr;
    static const CK_ULONG keyLens[] = { 16, 24, 32 };
    int i;

    for (i = 0; i < (int)sizeof(keyData); i++)
        keyData[i] = (byte)(0xA0 + i);
    XMEMSET(zero, 0, sizeof(zero));
    mech.mechanism = CKM_AES_ECB;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    for (i = 0; i < (int)(sizeof(keyLens) / sizeof(*keyLens)); i++) {
        printf("check value: AES key length %lu\n", (unsigned long)keyLens[i]);
        key = CK_INVALID_HANDLE;
        rv = create_aes_key(session, keyData, keyLens[i], &key);
        CHECK_RV(rv, "check value: create AES key", CKR_OK);
        if (rv != CKR_OK)
            continue;

        rv = funcList->C_EncryptInit(session, &mech, key);
        CHECK_RV(rv, "check value: C_EncryptInit", CKR_OK);
        if (rv != CKR_OK)
            continue;
        encLen = sizeof(enc);
        rv = funcList->C_Encrypt(session, zero, sizeof(zero), enc, &encLen);
        CHECK_RV(rv, "check value: C_Encrypt zero block", CKR_OK);
        if (rv != CKR_OK)
            continue;

        XMEMSET(kcv, 0, sizeof(kcv));
        attr.type = CKA_CHECK_VALUE;
        attr.pValue = kcv;
        attr.ulValueLen = sizeof(kcv);
        rv = funcList->C_GetAttributeValue(session, key, &attr, 1);
        CHECK_RV(rv, "check value: C_GetAttributeValue", CKR_OK);
        CHECK_TRUE(rv == CKR_OK && attr.ulValueLen == sizeof(kcv) &&
                   XMEMCMP(kcv, enc, sizeof(kcv)) == 0,
                   "check value matches encrypted zero block");
    }
}
#endif

typedef void (*test_fn)(CK_SESSION_HANDLE session);

/* Each check runs in its own session so session objects and operation state
 * do not carry over between checks. */
static void run_in_session(CK_SLOT_ID slot, test_fn fn)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    CHECK_RV(rv, "open test session", CKR_OK);
    if (rv == CKR_OK) {
        fn(session);
        funcList->C_CloseSession(session);
    }
}

#if !defined(NO_AES) && defined(HAVE_AESGCM)
static void gcm_params_init(CK_GCM_PARAMS* params, CK_MECHANISM* mech,
                            byte* iv, byte* aad)
{
    XMEMSET(params, 0, sizeof(*params));
    params->pIv = iv;
    params->ulIvLen = 12;
    params->pAAD = aad;
    params->ulAADLen = 16;
    params->ulTagBits = 128;
    mech->mechanism = CKM_AES_GCM;
    mech->pParameter = params;
    mech->ulParameterLen = sizeof(*params);
}

static void check_gcm_params_rejected(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE key, CK_MECHANISM* mech)
{
    CK_RV rv;

    rv = funcList->C_EncryptInit(session, mech, key);
    CHECK_RV(rv, "GCM: C_EncryptInit rejects parameter",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_DecryptInit(session, mech, key);
    CHECK_RV(rv, "GCM: C_DecryptInit rejects parameter",
             CKR_MECHANISM_PARAM_INVALID);
}

/* CK_GCM_PARAMS lengths outside what the token supports are rejected rather
 * than narrowed. */
static void test_gcm_param_ranges(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_GCM_PARAMS params;
    CK_MECHANISM mech;
    byte iv[12];
    byte aad[16];
    byte plain[16];
    byte enc[32];
    CK_ULONG encLen;
    CK_ULONG wrap = ((CK_ULONG)1 << 16) << 16;

    XMEMSET(iv, 0x21, sizeof(iv));
    XMEMSET(aad, 0x43, sizeof(aad));
    XMEMSET(plain, 0x65, sizeof(plain));

    rv = create_aes_key(session, aes_128_key, sizeof(aes_128_key), &key);
    CHECK_RV(rv, "GCM: create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    printf("GCM: tag bits 0xFFFFFFFF\n");
    gcm_params_init(&params, &mech, iv, aad);
    params.ulTagBits = 0xFFFFFFFFUL;
    check_gcm_params_rejected(session, key, &mech);

    printf("GCM: tag bits 0x80000000\n");
    gcm_params_init(&params, &mech, iv, aad);
    params.ulTagBits = 0x80000000UL;
    check_gcm_params_rejected(session, key, &mech);

    printf("GCM: AAD length 0x80000000\n");
    gcm_params_init(&params, &mech, iv, aad);
    params.ulAADLen = 0x80000000UL;
    check_gcm_params_rejected(session, key, &mech);

    if (wrap != 0) {
        printf("GCM: tag bits 2^32 + 128\n");
        gcm_params_init(&params, &mech, iv, aad);
        params.ulTagBits = wrap + 128;
        check_gcm_params_rejected(session, key, &mech);

        printf("GCM: IV length 2^32 + 12\n");
        gcm_params_init(&params, &mech, iv, aad);
        params.ulIvLen = wrap + sizeof(iv);
        check_gcm_params_rejected(session, key, &mech);

        printf("GCM: AAD length 2^32 + 16\n");
        gcm_params_init(&params, &mech, iv, aad);
        params.ulAADLen = wrap + sizeof(aad);
        check_gcm_params_rejected(session, key, &mech);
    }

    gcm_params_init(&params, &mech, iv, aad);
    rv = funcList->C_EncryptInit(session, &mech, key);
    CHECK_RV(rv, "GCM: C_EncryptInit valid parameters", CKR_OK);
    if (rv != CKR_OK)
        return;
    encLen = sizeof(enc);
    rv = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encLen);
    CHECK_RV(rv, "GCM: C_Encrypt valid parameters", CKR_OK);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESCCM)
static void check_ccm_params_rejected(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE key, CK_MECHANISM* mech)
{
    CK_RV rv;

    rv = funcList->C_EncryptInit(session, mech, key);
    CHECK_RV(rv, "CCM: C_EncryptInit rejects parameter",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_DecryptInit(session, mech, key);
    CHECK_RV(rv, "CCM: C_DecryptInit rejects parameter",
             CKR_MECHANISM_PARAM_INVALID);
}

/* CK_CCM_PARAMS lengths must be in range for CCM and are rejected rather than
 * narrowed. */
static void test_ccm_param_ranges(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_CCM_PARAMS params;
    CK_MECHANISM mech;
    byte iv[13];
    byte aad[16];
    byte plain[16];
    byte enc[32];
    CK_ULONG encLen;
    CK_ULONG wrap = ((CK_ULONG)1 << 16) << 16;
    static const CK_ULONG badMacLens[] = { 0, 2, 5, 15, 18 };
    int i;

    XMEMSET(iv, 0x31, sizeof(iv));
    XMEMSET(aad, 0x53, sizeof(aad));
    XMEMSET(plain, 0x75, sizeof(plain));

    rv = create_aes_key(session, aes_128_key, sizeof(aes_128_key), &key);
    CHECK_RV(rv, "CCM: create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    for (i = 0; i < (int)(sizeof(badMacLens) / sizeof(*badMacLens)); i++) {
        printf("CCM: MAC length %lu\n", (unsigned long)badMacLens[i]);
        ccm_params_init(&params, &mech, iv, sizeof(iv));
        params.ulMacLen = badMacLens[i];
        check_ccm_params_rejected(session, key, &mech);
    }

    printf("CCM: AAD length 0x80000000\n");
    ccm_params_init(&params, &mech, iv, sizeof(iv));
    params.pAAD = aad;
    params.ulAADLen = 0x80000000UL;
    check_ccm_params_rejected(session, key, &mech);

    printf("CCM: data length 0x80000000\n");
    ccm_params_init(&params, &mech, iv, sizeof(iv));
    params.ulDataLen = 0x80000000UL;
    check_ccm_params_rejected(session, key, &mech);

    if (wrap != 0) {
        printf("CCM: MAC length 2^32 + 4\n");
        ccm_params_init(&params, &mech, iv, sizeof(iv));
        params.ulMacLen = wrap + 4;
        check_ccm_params_rejected(session, key, &mech);

        printf("CCM: AAD length 2^32 + 16\n");
        ccm_params_init(&params, &mech, iv, sizeof(iv));
        params.pAAD = aad;
        params.ulAADLen = wrap + sizeof(aad);
        check_ccm_params_rejected(session, key, &mech);

        printf("CCM: nonce length 2^32 + 13\n");
        ccm_params_init(&params, &mech, iv, wrap + sizeof(iv));
        check_ccm_params_rejected(session, key, &mech);
    }

    ccm_params_init(&params, &mech, iv, sizeof(iv));
    params.pAAD = aad;
    params.ulAADLen = sizeof(aad);
    params.ulMacLen = 8;
    rv = funcList->C_EncryptInit(session, &mech, key);
    CHECK_RV(rv, "CCM: C_EncryptInit valid parameters", CKR_OK);
    if (rv != CKR_OK)
        return;
    encLen = sizeof(enc);
    rv = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encLen);
    CHECK_RV(rv, "CCM: C_Encrypt valid parameters", CKR_OK);
    CHECK_TRUE(encLen == sizeof(plain) + 8, "CCM: output carries 8-byte MAC");
}
#endif

#if !defined(NO_RSA) && !defined(WC_NO_RSA_OAEP)
static void check_oaep_params_rejected(CK_SESSION_HANDLE session,
                                       CK_OBJECT_HANDLE pub,
                                       CK_OBJECT_HANDLE priv,
                                       CK_MECHANISM* mech)
{
    CK_RV rv;

    rv = funcList->C_EncryptInit(session, mech, pub);
    CHECK_RV(rv, "OAEP: C_EncryptInit rejects source length",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_DecryptInit(session, mech, priv);
    CHECK_RV(rv, "OAEP: C_DecryptInit rejects source length",
             CKR_MECHANISM_PARAM_INVALID);
}

/* An OAEP source length the token cannot represent is rejected rather than
 * narrowed to a different label. */
static void test_oaep_source_len_range(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_RSA_PKCS_OAEP_PARAMS params;
    CK_MECHANISM mech;
    byte label[16];
    byte plain[16];
    byte enc[256];
    byte dec[256];
    CK_ULONG encLen;
    CK_ULONG decLen;
    CK_ULONG wrap = ((CK_ULONG)1 << 16) << 16;

    XMEMSET(label, 0x4C, sizeof(label));
    XMEMSET(plain, 0x50, sizeof(plain));

    rv = create_rsa_keys(session, &pub, &priv);
    CHECK_RV(rv, "OAEP: create RSA keys", CKR_OK);
    if (rv != CKR_OK)
        return;

    printf("OAEP: source length 0x80000000\n");
    oaep_params_init(&params, &mech);
    params.pSourceData = label;
    params.ulSourceDataLen = 0x80000000UL;
    check_oaep_params_rejected(session, pub, priv, &mech);

    if (wrap != 0) {
        printf("OAEP: source length 2^32 + 16\n");
        oaep_params_init(&params, &mech);
        params.pSourceData = label;
        params.ulSourceDataLen = wrap + sizeof(label);
        check_oaep_params_rejected(session, pub, priv, &mech);

        printf("OAEP: source length 2^32\n");
        oaep_params_init(&params, &mech);
        params.pSourceData = label;
        params.ulSourceDataLen = wrap;
        check_oaep_params_rejected(session, pub, priv, &mech);
    }

    oaep_params_init(&params, &mech);
    params.pSourceData = label;
    params.ulSourceDataLen = sizeof(label);
    rv = funcList->C_EncryptInit(session, &mech, pub);
    CHECK_RV(rv, "OAEP: C_EncryptInit with label", CKR_OK);
    if (rv != CKR_OK)
        return;
    encLen = sizeof(enc);
    rv = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encLen);
    CHECK_RV(rv, "OAEP: C_Encrypt with label", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = funcList->C_DecryptInit(session, &mech, priv);
    CHECK_RV(rv, "OAEP: C_DecryptInit with label", CKR_OK);
    if (rv != CKR_OK)
        return;
    decLen = sizeof(dec);
    rv = funcList->C_Decrypt(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "OAEP: C_Decrypt with label", CKR_OK);
    CHECK_TRUE(decLen == sizeof(plain) &&
               XMEMCMP(dec, plain, sizeof(plain)) == 0,
               "OAEP: labelled ciphertext round-trips");
}
#endif

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_SESSION_INFO info;
    CK_SLOT_ID slot = 0;

    (void)run_in_session;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_GetSessionInfo(session, &info);
        CHECK_RV(rv, "C_GetSessionInfo", CKR_OK);
    }
    if (rv == CKR_OK) {
        slot = info.slotID;
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
        run_in_session(slot, test_cbc_pad_encrypt_final_len);
#endif
#if !defined(NO_RSA) && !defined(WC_NO_RSA_OAEP)
        run_in_session(slot, test_oaep_source_ptr_len);
#endif
#if !defined(NO_AES) && defined(HAVE_AESCCM)
        run_in_session(slot, test_ccm_nonce_len);
#endif
#if !defined(NO_AES) && defined(HAVE_AESCTR)
        run_in_session(slot, test_ctr_decrypt_size_query);
#endif
#if !defined(NO_AES) && (defined(HAVE_AES_CBC) || defined(HAVE_AESECB))
        run_in_session(slot, test_block_mode_alignment);
#endif
#if !defined(NO_AES) && defined(HAVE_AESECB)
        run_in_session(slot, test_aes_check_value_key_sizes);
#endif
#if !defined(NO_AES) && defined(HAVE_AESGCM)
        run_in_session(slot, test_gcm_param_ranges);
#endif
#if !defined(NO_AES) && defined(HAVE_AESCCM)
        run_in_session(slot, test_ccm_param_ranges);
#endif
#if !defined(NO_RSA) && !defined(WC_NO_RSA_OAEP)
        run_in_session(slot, test_oaep_source_len_range);
#endif
    }

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

    printf("=== wolfPKCS11 encrypt/decrypt parameter and length test ===\n");
    run_test();
    return pkcs11_test_summary();
}
