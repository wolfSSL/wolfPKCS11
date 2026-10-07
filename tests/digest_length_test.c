/* digest_length_test.c
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
 * Digest, sign, verify, encrypt and decrypt must honour the PKCS#11 length
 * conventions: input lengths are taken in full, output buffer lengths are
 * compared in full and a short buffer reports the length that is needed.
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
#include <wolfssl/wolfcrypt/hash.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/digest_length_test"

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "digest-length";

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

#if !defined(NO_SHA256) || !defined(NO_RSA) || \
    (!defined(NO_AES) && defined(HAVE_AESCMAC))
/* A length above the 32-bit range whose low 32 bits equal small. */
static CK_ULONG big_len(CK_ULONG small)
{
    return (((CK_ULONG)1 << 16) << 16) | small;
}
#endif

#ifndef NO_RSA
static CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
static CK_KEY_TYPE rsaKeyType = CKK_RSA;

static CK_RV create_rsa_keys(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* priv,
                             CK_OBJECT_HANDLE* pub)
{
    CK_RV rv;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,         &rsaKeyType,       sizeof(rsaKeyType)        },
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
        { CKA_CLASS,           &pubKeyClass,     sizeof(pubKeyClass)      },
        { CKA_KEY_TYPE,        &rsaKeyType,      sizeof(rsaKeyType)       },
        { CKA_VERIFY,          &ckTrue,          sizeof(ckTrue)           },
        { CKA_ENCRYPT,         &ckTrue,          sizeof(ckTrue)           },
        { CKA_PRIVATE,         &ckFalse,         sizeof(ckFalse)          },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };

    rv = funcList->C_CreateObject(session, privTmpl,
                                  sizeof(privTmpl) / sizeof(*privTmpl), priv);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, pubTmpl,
                                      sizeof(pubTmpl) / sizeof(*pubTmpl), pub);
    }
    return rv;
}
#endif

#ifndef NO_SHA256
static CK_MECHANISM sha256Mech = { CKM_SHA256, NULL, 0 };

#if !defined(NO_HMAC)
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;

static CK_RV create_hmac_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    static byte keyData[32] = { 0x0b };
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType) },
        { CKA_SIGN,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_VERIFY,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    keyData,         sizeof(keyData)        },
    };

    return funcList->C_CreateObject(session, keyTmpl,
                                    sizeof(keyTmpl) / sizeof(*keyTmpl), key);
}
#endif

/* C_Digest only runs inside an operation started by C_DigestInit. */
static void digest_requires_init_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    byte data[16];
    byte hash[32];
    CK_ULONG hashLen = sizeof(hash);
#if !defined(NO_HMAC)
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, NULL, 0 };
    byte mac[32];
    CK_ULONG macLen = sizeof(mac);
#endif

    XMEMSET(data, 0x61, sizeof(data));
    rv = funcList->C_Digest(session, data, sizeof(data), hash, &hashLen);
    CHECK_RV(rv, "C_Digest without C_DigestInit",
             CKR_OPERATION_NOT_INITIALIZED);

    rv = funcList->C_DigestInit(session, &sha256Mech);
    CHECK_RV(rv, "C_DigestInit(SHA256)", CKR_OK);
    hashLen = sizeof(hash);
    rv = funcList->C_Digest(session, data, sizeof(data), hash, &hashLen);
    CHECK_RV(rv, "C_Digest(SHA256)", CKR_OK);
    hashLen = sizeof(hash);
    rv = funcList->C_Digest(session, data, sizeof(data), hash, &hashLen);
    CHECK_RV(rv, "C_Digest after the digest operation finished",
             CKR_OPERATION_NOT_INITIALIZED);

#if !defined(NO_HMAC)
    rv = create_hmac_key(session, &key);
    CHECK_RV(rv, "create HMAC key", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = funcList->C_SignInit(session, &hmacMech, key);
    CHECK_RV(rv, "C_SignInit(SHA256 HMAC)", CKR_OK);
    hashLen = sizeof(hash);
    rv = funcList->C_Digest(session, data, sizeof(data), hash, &hashLen);
    CHECK_RV(rv, "C_Digest during a sign operation",
             CKR_OPERATION_NOT_INITIALIZED);
    rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "sign operation still active after C_Digest", CKR_OK);
    funcList->C_DestroyObject(session, key);
#endif
}

/* A short C_Digest buffer reports the digest length and leaves the operation
 * active. */
static void digest_single_too_small_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    byte data[16];
    byte hash[32];
    CK_ULONG hashLen = sizeof(hash) - 1;

    XMEMSET(data, 0x6e, sizeof(data));
    rv = funcList->C_DigestInit(session, &sha256Mech);
    CHECK_RV(rv, "C_DigestInit(SHA256)", CKR_OK);
    rv = funcList->C_Digest(session, data, sizeof(data), hash, &hashLen);
    CHECK_RV(rv, "C_Digest short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(hashLen == sizeof(hash),
               "C_Digest short buffer reports the digest length");
    rv = funcList->C_Digest(session, data, sizeof(data), hash, &hashLen);
    CHECK_RV(rv, "C_Digest retry with the reported length", CKR_OK);
}

/* A short C_DigestFinal buffer reports the digest length and leaves the
 * operation active. */
static void digest_final_too_small_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    byte data[16];
    byte hash[32];
    byte single[32];
    CK_ULONG hashLen = 1;
    CK_ULONG singleLen = sizeof(single);

    XMEMSET(data, 0x6f, sizeof(data));
    rv = funcList->C_DigestInit(session, &sha256Mech);
    if (rv == CKR_OK)
        rv = funcList->C_Digest(session, data, sizeof(data), single,
                                &singleLen);
    CHECK_RV(rv, "C_Digest(SHA256) reference", CKR_OK);

    rv = funcList->C_DigestInit(session, &sha256Mech);
    CHECK_RV(rv, "C_DigestInit(SHA256)", CKR_OK);
    rv = funcList->C_DigestUpdate(session, data, sizeof(data));
    CHECK_RV(rv, "C_DigestUpdate(SHA256)", CKR_OK);
    rv = funcList->C_DigestFinal(session, hash, &hashLen);
    CHECK_RV(rv, "C_DigestFinal short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(hashLen == sizeof(hash),
               "C_DigestFinal short buffer reports the digest length");
    rv = funcList->C_DigestFinal(session, hash, &hashLen);
    CHECK_RV(rv, "C_DigestFinal retry with the reported length", CKR_OK);
    CHECK_TRUE(hashLen == singleLen && XMEMCMP(hash, single, hashLen) == 0,
               "C_DigestFinal retry gives the full digest");
}

/* Digest input lengths that do not fit in 32 bits are rejected. */
static void digest_input_len_range_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    byte data[16];
    byte hash[32];
    CK_ULONG hashLen = sizeof(hash);

    XMEMSET(data, 0x62, sizeof(data));
    rv = funcList->C_DigestInit(session, &sha256Mech);
    CHECK_RV(rv, "C_DigestInit(SHA256)", CKR_OK);
    rv = funcList->C_Digest(session, data, big_len(sizeof(data)), hash,
                            &hashLen);
    CHECK_RV(rv, "C_Digest rejects a length above 32 bits",
             CKR_DATA_LEN_RANGE);
    hashLen = sizeof(hash);
    rv = funcList->C_Digest(session, data, sizeof(data), hash, &hashLen);
    CHECK_RV(rv, "C_Digest length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    rv = funcList->C_DigestInit(session, &sha256Mech);
    CHECK_RV(rv, "C_DigestInit(SHA256) for update", CKR_OK);
    rv = funcList->C_DigestUpdate(session, data, big_len(sizeof(data)));
    CHECK_RV(rv, "C_DigestUpdate rejects a length above 32 bits",
             CKR_DATA_LEN_RANGE);
    hashLen = sizeof(hash);
    rv = funcList->C_DigestFinal(session, hash, &hashLen);
    CHECK_RV(rv, "C_DigestUpdate length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);
}

#if !defined(NO_HMAC)
/* MAC input and signature lengths that do not fit in 32 bits are rejected. */
static void hmac_input_len_range_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    byte data[16];
    byte mac[32];
    CK_ULONG macLen = sizeof(mac);

    XMEMSET(data, 0x63, sizeof(data));
    rv = create_hmac_key(session, &key);
    CHECK_RV(rv, "create HMAC key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(SHA256 HMAC)", CKR_OK);
    rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(SHA256 HMAC)", CKR_OK);

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(SHA256 HMAC) for long data", CKR_OK);
    macLen = sizeof(mac);
    rv = funcList->C_Sign(session, data, big_len(sizeof(data)), mac, &macLen);
    CHECK_RV(rv, "C_Sign rejects a length above 32 bits", CKR_DATA_LEN_RANGE);
    macLen = sizeof(mac);
    rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(SHA256 HMAC) for update", CKR_OK);
    rv = funcList->C_SignUpdate(session, data, big_len(sizeof(data)));
    CHECK_RV(rv, "C_SignUpdate rejects a length above 32 bits",
             CKR_DATA_LEN_RANGE);
    macLen = sizeof(mac);
    rv = funcList->C_SignFinal(session, mac, &macLen);
    CHECK_RV(rv, "C_SignUpdate length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    macLen = sizeof(mac);
    rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(SHA256 HMAC) reference MAC", CKR_OK);

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(SHA256 HMAC)", CKR_OK);
    rv = funcList->C_Verify(session, data, big_len(sizeof(data)), mac, macLen);
    CHECK_RV(rv, "C_Verify rejects a data length above 32 bits",
             CKR_DATA_LEN_RANGE);
    rv = funcList->C_Verify(session, data, sizeof(data), mac, macLen);
    CHECK_RV(rv, "C_Verify length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(SHA256 HMAC) for long signature", CKR_OK);
    rv = funcList->C_Verify(session, data, sizeof(data), mac, big_len(macLen));
    CHECK_RV(rv, "C_Verify rejects a signature length above 32 bits",
             CKR_SIGNATURE_LEN_RANGE);

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(SHA256 HMAC) for update", CKR_OK);
    rv = funcList->C_VerifyUpdate(session, data, big_len(sizeof(data)));
    CHECK_RV(rv, "C_VerifyUpdate rejects a length above 32 bits",
             CKR_DATA_LEN_RANGE);
    rv = funcList->C_VerifyFinal(session, mac, macLen);
    CHECK_RV(rv, "C_VerifyUpdate length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    funcList->C_DestroyObject(session, key);
}

/* A multi-part MAC verify takes the signature length in full. */
static void verify_final_sig_len_range_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    byte data[16];
    byte mac[32];
    CK_ULONG macLen = sizeof(mac);

    XMEMSET(data, 0x65, sizeof(data));
    rv = create_hmac_key(session, &key);
    CHECK_RV(rv, "create HMAC key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(SHA256 HMAC) reference MAC", CKR_OK);

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(SHA256 HMAC)", CKR_OK);
    rv = funcList->C_VerifyUpdate(session, data, sizeof(data));
    CHECK_RV(rv, "C_VerifyUpdate(SHA256 HMAC)", CKR_OK);
    rv = funcList->C_VerifyFinal(session, mac, big_len(macLen));
    CHECK_RV(rv, "C_VerifyFinal(HMAC) rejects a length above 32 bits",
             CKR_SIGNATURE_LEN_RANGE);
    rv = funcList->C_VerifyFinal(session, mac, macLen);
    CHECK_RV(rv, "C_VerifyFinal(HMAC) length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    funcList->C_DestroyObject(session, key);
}

/* A short signature buffer reports the length that is needed and leaves the
 * operation active. */
static void sign_buffer_too_small_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    byte data[16];
    byte mac[32];
    CK_ULONG macLen;

    XMEMSET(data, 0x6b, sizeof(data));
    rv = create_hmac_key(session, &key);
    CHECK_RV(rv, "create HMAC key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(HMAC)", CKR_OK);
    macLen = sizeof(mac) - 1;
    rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(HMAC) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(macLen == sizeof(mac),
               "C_Sign(HMAC) short buffer reports the length");
    rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(HMAC) retry with the reported length", CKR_OK);

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(HMAC) multi-part", CKR_OK);
    rv = funcList->C_SignUpdate(session, data, sizeof(data));
    CHECK_RV(rv, "C_SignUpdate(HMAC)", CKR_OK);
    macLen = 1;
    rv = funcList->C_SignFinal(session, mac, &macLen);
    CHECK_RV(rv, "C_SignFinal(HMAC) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(macLen == sizeof(mac),
               "C_SignFinal(HMAC) short buffer reports the length");
    rv = funcList->C_SignFinal(session, mac, &macLen);
    CHECK_RV(rv, "C_SignFinal(HMAC) retry with the reported length", CKR_OK);

    funcList->C_DestroyObject(session, key);
}

/* Signing accepts an output buffer length above 32 bits. */
static void sign_output_capacity_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    byte data[16];
    byte mac[32];
    CK_ULONG macLen;

    XMEMSET(data, 0x68, sizeof(data));
    rv = create_hmac_key(session, &key);
    CHECK_RV(rv, "create HMAC key", CKR_OK);
    if (rv != CKR_OK)
        return;

    macLen = big_len(0);
    rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(HMAC) with a buffer length above 32 bits", CKR_OK);
    CHECK_TRUE(macLen == sizeof(mac), "C_Sign(HMAC) reports the MAC length");

    macLen = big_len(0);
    rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_SignUpdate(session, data, sizeof(data));
    if (rv == CKR_OK)
        rv = funcList->C_SignFinal(session, mac, &macLen);
    CHECK_RV(rv, "C_SignFinal(HMAC) with a buffer length above 32 bits",
             CKR_OK);
    CHECK_TRUE(macLen == sizeof(mac),
               "C_SignFinal(HMAC) reports the MAC length");

    funcList->C_DestroyObject(session, key);
}
#endif
#endif /* !NO_SHA256 */

#ifndef NO_RSA
/* RSA encrypt and decrypt input lengths that do not fit in 32 bits are
 * rejected. */
static void rsa_input_len_range_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    byte data[16];
    byte enc[2048 / 8];
    byte dec[2048 / 8];
    CK_ULONG encLen = sizeof(enc);
    CK_ULONG decLen = sizeof(dec);

    XMEMSET(data, 0x64, sizeof(data));
    rv = create_rsa_keys(session, &priv, &pub);
    CHECK_RV(rv, "create RSA key pair", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_EncryptInit(session, &mech, pub);
    CHECK_RV(rv, "C_EncryptInit(RSA PKCS)", CKR_OK);
    rv = funcList->C_Encrypt(session, data, big_len(sizeof(data)), enc,
                             &encLen);
    CHECK_RV(rv, "C_Encrypt(RSA PKCS) rejects a length above 32 bits",
             CKR_DATA_LEN_RANGE);
    encLen = sizeof(enc);
    rv = funcList->C_Encrypt(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_Encrypt(RSA PKCS) length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    encLen = sizeof(enc);
    rv = funcList->C_EncryptInit(session, &mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_Encrypt(RSA PKCS)", CKR_OK);

    rv = funcList->C_DecryptInit(session, &mech, priv);
    CHECK_RV(rv, "C_DecryptInit(RSA PKCS)", CKR_OK);
    rv = funcList->C_Decrypt(session, enc, big_len(encLen), dec, &decLen);
    CHECK_RV(rv, "C_Decrypt(RSA PKCS) rejects a length above 32 bits",
             CKR_ENCRYPTED_DATA_LEN_RANGE);
    decLen = sizeof(dec);
    rv = funcList->C_Decrypt(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "C_Decrypt(RSA PKCS) length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif

#ifndef NO_RSA
/* A short RSA output buffer reports the length that is needed. */
static void rsa_buffer_too_small_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    byte data[16];
    byte out[2048 / 8];
    byte dec[2048 / 8];
    CK_ULONG outLen;
    CK_ULONG decLen;

    XMEMSET(data, 0x6c, sizeof(data));
    rv = create_rsa_keys(session, &priv, &pub);
    CHECK_RV(rv, "create RSA key pair", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, priv);
    CHECK_RV(rv, "C_SignInit(RSA PKCS)", CKR_OK);
    outLen = sizeof(out) - 1;
    rv = funcList->C_Sign(session, data, sizeof(data), out, &outLen);
    CHECK_RV(rv, "C_Sign(RSA PKCS) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(outLen == sizeof(out),
               "C_Sign(RSA PKCS) short buffer reports the length");
    rv = funcList->C_Sign(session, data, sizeof(data), out, &outLen);
    CHECK_RV(rv, "C_Sign(RSA PKCS) retry with the reported length", CKR_OK);

    rv = funcList->C_EncryptInit(session, &mech, pub);
    CHECK_RV(rv, "C_EncryptInit(RSA PKCS)", CKR_OK);
    outLen = sizeof(out) - 1;
    rv = funcList->C_Encrypt(session, data, sizeof(data), out, &outLen);
    CHECK_RV(rv, "C_Encrypt(RSA PKCS) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(outLen == sizeof(out),
               "C_Encrypt(RSA PKCS) short buffer reports the length");
    rv = funcList->C_Encrypt(session, data, sizeof(data), out, &outLen);
    CHECK_RV(rv, "C_Encrypt(RSA PKCS) retry with the reported length",
             CKR_OK);

    rv = funcList->C_DecryptInit(session, &mech, priv);
    CHECK_RV(rv, "C_DecryptInit(RSA PKCS)", CKR_OK);
    decLen = sizeof(data);
    rv = funcList->C_Decrypt(session, out, outLen, dec, &decLen);
    CHECK_RV(rv, "C_Decrypt(RSA PKCS) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(decLen == sizeof(dec),
               "C_Decrypt(RSA PKCS) short buffer reports the length");
    rv = funcList->C_Decrypt(session, out, outLen, dec, &decLen);
    CHECK_RV(rv, "C_Decrypt(RSA PKCS) retry with the reported length",
             CKR_OK);
    CHECK_TRUE(decLen == sizeof(data) && XMEMCMP(dec, data, decLen) == 0,
               "C_Decrypt(RSA PKCS) recovers the data");

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif

#ifndef NO_RSA
/* An RSA sign accepts an output buffer length above 32 bits. */
static void rsa_sign_output_capacity_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    byte data[16];
    byte sig[2048 / 8];
    CK_ULONG sigLen = big_len(0);

    XMEMSET(data, 0x69, sizeof(data));
    rv = create_rsa_keys(session, &priv, &pub);
    CHECK_RV(rv, "create RSA key pair", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, priv);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, data, sizeof(data), sig, &sigLen);
    CHECK_RV(rv, "C_Sign(RSA) with a buffer length above 32 bits", CKR_OK);
    CHECK_TRUE(sigLen == sizeof(sig), "C_Sign(RSA) reports the length");

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESCMAC)
static CK_OBJECT_CLASS aesKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;

static CK_RV create_cmac_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &aesKeyClass, sizeof(aesKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,  sizeof(aesKeyType)  },
        { CKA_SIGN,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_VERIFY,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
    };

    return funcList->C_CreateObject(session, keyTmpl,
                                    sizeof(keyTmpl) / sizeof(*keyTmpl), key);
}

/* A multi-part CMAC verify takes the signature length in full. */
static void cmac_verify_final_sig_len_range_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_AES_CMAC, NULL, 0 };
    byte data[16];
    byte mac[16];
    CK_ULONG macLen = sizeof(mac);

    XMEMSET(data, 0x66, sizeof(data));
    rv = create_cmac_key(session, &key);
    CHECK_RV(rv, "create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(AES CMAC) reference MAC", CKR_OK);

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(AES CMAC)", CKR_OK);
    rv = funcList->C_VerifyUpdate(session, data, sizeof(data));
    CHECK_RV(rv, "C_VerifyUpdate(AES CMAC)", CKR_OK);
    rv = funcList->C_VerifyFinal(session, mac, big_len(macLen));
    CHECK_RV(rv, "C_VerifyFinal(CMAC) rejects a length above 32 bits",
             CKR_SIGNATURE_LEN_RANGE);
    rv = funcList->C_VerifyFinal(session, mac, macLen);
    CHECK_RV(rv, "C_VerifyFinal(CMAC) length error ends the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    funcList->C_DestroyObject(session, key);
}

/* A short CMAC buffer reports the length that is needed. */
static void cmac_buffer_too_small_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_AES_CMAC, NULL, 0 };
    byte data[16];
    byte mac[16];
    CK_ULONG macLen;

    XMEMSET(data, 0x6d, sizeof(data));
    rv = create_cmac_key(session, &key);
    CHECK_RV(rv, "create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(CMAC)", CKR_OK);
    macLen = sizeof(mac) - 1;
    rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(CMAC) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(macLen == sizeof(mac),
               "C_Sign(CMAC) short buffer reports the length");
    rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(CMAC) retry with the reported length", CKR_OK);

    funcList->C_DestroyObject(session, key);
}

/* A CMAC sign accepts an output buffer length above 32 bits. */
static void cmac_sign_output_capacity_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_AES_CMAC, NULL, 0 };
    byte data[16];
    byte mac[16];
    CK_ULONG macLen;

    XMEMSET(data, 0x67, sizeof(data));
    rv = create_cmac_key(session, &key);
    CHECK_RV(rv, "create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    macLen = big_len(0);
    rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
    CHECK_RV(rv, "C_Sign(CMAC) with a buffer length above 32 bits", CKR_OK);
    CHECK_TRUE(macLen == sizeof(mac), "C_Sign(CMAC) reports the MAC length");

    macLen = big_len(0);
    rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_SignUpdate(session, data, sizeof(data));
    if (rv == CKR_OK)
        rv = funcList->C_SignFinal(session, mac, &macLen);
    CHECK_RV(rv, "C_SignFinal(CMAC) with a buffer length above 32 bits",
             CKR_OK);
    CHECK_TRUE(macLen == sizeof(mac),
               "C_SignFinal(CMAC) reports the MAC length");

    funcList->C_DestroyObject(session, key);
}
#endif

#if !defined(NO_AES) && (defined(HAVE_AES_CBC) || defined(HAVE_AESGCM))
static CK_OBJECT_CLASS aesEncKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesEncKeyType = CKK_AES;

static CK_RV create_aes_enc_key(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &aesEncKeyClass, sizeof(aesEncKeyClass) },
        { CKA_KEY_TYPE, &aesEncKeyType,  sizeof(aesEncKeyType)  },
        { CKA_ENCRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_DECRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    aes_128_key,     sizeof(aes_128_key)    },
    };

    return funcList->C_CreateObject(session, keyTmpl,
                                    sizeof(keyTmpl) / sizeof(*keyTmpl), key);
}

/* A short encrypt or decrypt buffer reports the length that is needed and
 * leaves the operation active. */
static void aes_buffer_too_small_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte iv[16];
    byte data[32];
    byte enc[48];
    byte dec[48];
    CK_ULONG encLen;
    CK_ULONG decLen;
#ifdef HAVE_AES_CBC
    CK_MECHANISM cbcMech;
#endif
#ifdef HAVE_AESGCM
    CK_GCM_PARAMS gcmParams;
    CK_MECHANISM gcmMech;
#endif

    XMEMSET(iv, 0x01, sizeof(iv));
    XMEMSET(data, 0x6a, sizeof(data));
    rv = create_aes_enc_key(session, &key);
    CHECK_RV(rv, "create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

#ifdef HAVE_AES_CBC
    cbcMech.mechanism = CKM_AES_CBC;
    cbcMech.pParameter = iv;
    cbcMech.ulParameterLen = sizeof(iv);

    rv = funcList->C_EncryptInit(session, &cbcMech, key);
    CHECK_RV(rv, "C_EncryptInit(AES CBC)", CKR_OK);
    encLen = sizeof(data) - 1;
    rv = funcList->C_Encrypt(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_Encrypt(AES CBC) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(encLen == sizeof(data),
               "C_Encrypt(AES CBC) short buffer reports the length");
    rv = funcList->C_Encrypt(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_Encrypt(AES CBC) retry with the reported length", CKR_OK);

    rv = funcList->C_DecryptInit(session, &cbcMech, key);
    CHECK_RV(rv, "C_DecryptInit(AES CBC)", CKR_OK);
    decLen = 1;
    rv = funcList->C_Decrypt(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "C_Decrypt(AES CBC) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(decLen == encLen,
               "C_Decrypt(AES CBC) short buffer reports the length");
    rv = funcList->C_Decrypt(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "C_Decrypt(AES CBC) retry with the reported length", CKR_OK);

    rv = funcList->C_EncryptInit(session, &cbcMech, key);
    CHECK_RV(rv, "C_EncryptInit(AES CBC) multi-part", CKR_OK);
    encLen = 16;
    rv = funcList->C_EncryptUpdate(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_EncryptUpdate(AES CBC) short buffer",
             CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(encLen == sizeof(data),
               "C_EncryptUpdate(AES CBC) short buffer reports the length");
    rv = funcList->C_EncryptUpdate(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_EncryptUpdate(AES CBC) retry", CKR_OK);
    decLen = sizeof(dec);
    rv = funcList->C_EncryptFinal(session, dec, &decLen);
    CHECK_RV(rv, "C_EncryptFinal(AES CBC)", CKR_OK);

    rv = funcList->C_DecryptInit(session, &cbcMech, key);
    CHECK_RV(rv, "C_DecryptInit(AES CBC) multi-part", CKR_OK);
    decLen = 16;
    rv = funcList->C_DecryptUpdate(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "C_DecryptUpdate(AES CBC) short buffer",
             CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(decLen == encLen,
               "C_DecryptUpdate(AES CBC) short buffer reports the length");
    rv = funcList->C_DecryptUpdate(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "C_DecryptUpdate(AES CBC) retry", CKR_OK);
    encLen = sizeof(enc);
    rv = funcList->C_DecryptFinal(session, enc, &encLen);
    CHECK_RV(rv, "C_DecryptFinal(AES CBC)", CKR_OK);
#endif

#ifdef HAVE_AESGCM
    XMEMSET(&gcmParams, 0, sizeof(gcmParams));
    gcmParams.pIv = iv;
    gcmParams.ulIvLen = 12;
    gcmParams.ulIvBits = 96;
    gcmParams.ulTagBits = 128;
    gcmMech.mechanism = CKM_AES_GCM;
    gcmMech.pParameter = &gcmParams;
    gcmMech.ulParameterLen = sizeof(gcmParams);

    rv = funcList->C_EncryptInit(session, &gcmMech, key);
    CHECK_RV(rv, "C_EncryptInit(AES GCM)", CKR_OK);
    encLen = sizeof(data);
    rv = funcList->C_Encrypt(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_Encrypt(AES GCM) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(encLen == sizeof(data) + 16,
               "C_Encrypt(AES GCM) short buffer reports the length");
    rv = funcList->C_Encrypt(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_Encrypt(AES GCM) retry with the reported length", CKR_OK);

    rv = funcList->C_DecryptInit(session, &gcmMech, key);
    CHECK_RV(rv, "C_DecryptInit(AES GCM)", CKR_OK);
    decLen = 1;
    rv = funcList->C_Decrypt(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "C_Decrypt(AES GCM) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(decLen == sizeof(data),
               "C_Decrypt(AES GCM) short buffer reports the length");
    rv = funcList->C_Decrypt(session, enc, encLen, dec, &decLen);
    CHECK_RV(rv, "C_Decrypt(AES GCM) retry with the reported length", CKR_OK);

    rv = funcList->C_EncryptInit(session, &gcmMech, key);
    CHECK_RV(rv, "C_EncryptInit(AES GCM) multi-part", CKR_OK);
    encLen = sizeof(enc);
    rv = funcList->C_EncryptUpdate(session, data, sizeof(data), enc, &encLen);
    CHECK_RV(rv, "C_EncryptUpdate(AES GCM)", CKR_OK);
    decLen = 15;
    rv = funcList->C_EncryptFinal(session, dec, &decLen);
    CHECK_RV(rv, "C_EncryptFinal(AES GCM) short buffer", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(decLen == 16,
               "C_EncryptFinal(AES GCM) short buffer reports the length");
    rv = funcList->C_EncryptFinal(session, dec, &decLen);
    CHECK_RV(rv, "C_EncryptFinal(AES GCM) retry", CKR_OK);
#endif

    funcList->C_DestroyObject(session, key);
}
#endif

static CK_RV token_init(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE soSession = 0;
    unsigned char label[32];

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv != CKR_OK)
        return rv;
    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK)
        return rv;
    if (slotCount == 0)
        return CKR_TOKEN_NOT_PRESENT;
    *slot = slotList[0];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    rv = funcList->C_InitToken(*slot, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin), label);
    if (rv != CKR_OK)
        return rv;

    rv = funcList->C_OpenSession(*slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &soSession);
    if (rv != CKR_OK)
        return rv;
    rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                           (CK_ULONG)XSTRLEN(soPin));
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
    }
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return rv;
}

static int run_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = 0;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = token_init(&slot);
    CHECK_RV(rv, "token init", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
        CHECK_RV(rv, "open session", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
        CHECK_RV(rv, "user login", CKR_OK);
    }
    if (rv == CKR_OK) {
#ifndef NO_SHA256
        digest_requires_init_test(session);
        digest_single_too_small_len_test(session);
        digest_final_too_small_len_test(session);
#endif
#if !defined(NO_SHA256) && !defined(NO_HMAC)
        sign_buffer_too_small_len_test(session);
#endif
#ifndef NO_RSA
        rsa_buffer_too_small_len_test(session);
#endif
#if !defined(NO_AES) && (defined(HAVE_AES_CBC) || defined(HAVE_AESGCM))
        aes_buffer_too_small_len_test(session);
#endif
#if !defined(NO_AES) && defined(HAVE_AESCMAC)
        cmac_buffer_too_small_len_test(session);
#endif
        if (sizeof(CK_ULONG) > sizeof(word32)) {
#ifndef NO_SHA256
            digest_input_len_range_test(session);
#if !defined(NO_HMAC)
            hmac_input_len_range_test(session);
            verify_final_sig_len_range_test(session);
            sign_output_capacity_test(session);
#endif
#endif
#ifndef NO_RSA
            rsa_input_len_range_test(session);
            rsa_sign_output_capacity_test(session);
#endif
#if !defined(NO_AES) && defined(HAVE_AESCMAC)
            cmac_verify_final_sig_len_range_test(session);
            cmac_sign_output_capacity_test(session);
#endif
        }
    }

    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    (void)ckTrue;
    (void)ckFalse;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 digest and length convention test ===\n");
    run_test();
    return pkcs11_test_summary();
}
