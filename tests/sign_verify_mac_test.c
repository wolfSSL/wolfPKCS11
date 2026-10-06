/* sign_verify_mac_test.c
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
 * Sign, verify and MAC operations must honour the mechanism definitions:
 * parameters are validated against the mechanism, output lengths match the
 * mechanism and verification compares the whole value.
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
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/sign_verify_mac_test"

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "sign-verify-mac";

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

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

#if !defined(NO_RSA) && defined(WC_RSA_DIRECT)
/* A raw RSA verify compares the whole recovered block with the data. */
static void rsa_x509_verify_block_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_RSA_X_509, NULL, 0 };
    byte data[32];
    byte sig[2048 / 8];
    CK_ULONG sigLen = sizeof(sig);

    XMEMSET(data, 0x5a, sizeof(data));
    rv = create_rsa_keys(session, &priv, &pub);
    CHECK_RV(rv, "create RSA key pair", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, priv);
    CHECK_RV(rv, "C_SignInit(RSA X.509)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, data, sizeof(data), sig, &sigLen);
        CHECK_RV(rv, "C_Sign(RSA X.509)", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_RV(rv, "C_VerifyInit(RSA X.509)", CKR_OK);
        rv = funcList->C_Verify(session, data, sizeof(data), sig, sigLen);
        CHECK_RV(rv, "C_Verify(RSA X.509, signed data)", CKR_OK);

        rv = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_RV(rv, "C_VerifyInit(RSA X.509, shorter data)", CKR_OK);
        rv = funcList->C_Verify(session, data + 1, sizeof(data) - 1, sig,
                                sigLen);
        CHECK_RV(rv, "C_Verify(RSA X.509, trailing part of signed data)",
                 CKR_SIGNATURE_INVALID);
    }

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}

/* Larger than the maximum RSA modulus wolfCrypt is built for. */
#define BIG_MOD_SZ  ((RSA_MAX_SIZE / 8) + 64)
static byte bigMod[BIG_MOD_SZ];
static byte bigHalf[BIG_MOD_SZ / 2];
static byte bigSig[BIG_MOD_SZ];
/* Just over the maximum, so the math library can still use the key. */
#define BIG_VERIFY_MOD_SZ  ((RSA_MAX_SIZE / 8) + 8)

/* Raw RSA fails cleanly for a key larger than the supported modulus size. */
static void rsa_x509_big_modulus_sign_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_RSA_X_509, NULL, 0 };
    byte data[32];
    CK_ULONG sigLen = sizeof(bigSig);
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privKeyClass,    sizeof(privKeyClass)     },
        { CKA_KEY_TYPE,         &rsaKeyType,      sizeof(rsaKeyType)       },
        { CKA_SIGN,             &ckTrue,          sizeof(ckTrue)           },
        { CKA_PRIVATE,          &ckFalse,         sizeof(ckFalse)          },
        { CKA_MODULUS,          bigMod,           sizeof(bigMod)           },
        { CKA_PRIVATE_EXPONENT, bigMod,           sizeof(bigMod)           },
        { CKA_PRIME_1,          bigHalf,          sizeof(bigHalf)          },
        { CKA_PRIME_2,          bigHalf,          sizeof(bigHalf)          },
        { CKA_EXPONENT_1,       bigHalf,          sizeof(bigHalf)          },
        { CKA_EXPONENT_2,       bigHalf,          sizeof(bigHalf)          },
        { CKA_COEFFICIENT,      bigHalf,          sizeof(bigHalf)          },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };

    XMEMSET(bigMod, 0xa5, sizeof(bigMod));
    XMEMSET(bigHalf, 0xc3, sizeof(bigHalf));
    XMEMSET(data, 0x11, sizeof(data));
    rv = funcList->C_CreateObject(session, privTmpl,
                                  sizeof(privTmpl) / sizeof(*privTmpl), &priv);
    if (rv != CKR_OK) {
        CHECK_TRUE(1, "oversized RSA private key rejected at import");
        return;
    }

    rv = funcList->C_SignInit(session, &mech, priv);
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, data, sizeof(data), bigSig, &sigLen);
        CHECK_TRUE(rv != CKR_OK, "C_Sign(RSA X.509) fails for oversized key");
    }
    else {
        CHECK_TRUE(1, "C_SignInit(RSA X.509) rejects oversized key");
    }
    funcList->C_DestroyObject(session, priv);
}

/* Raw RSA verify fails cleanly for a key larger than the supported size. */
static void rsa_x509_big_modulus_verify_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_RSA_X_509, NULL, 0 };
    byte data[32];
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,           &pubKeyClass,     sizeof(pubKeyClass)      },
        { CKA_KEY_TYPE,        &rsaKeyType,      sizeof(rsaKeyType)       },
        { CKA_VERIFY,          &ckTrue,          sizeof(ckTrue)           },
        { CKA_PRIVATE,         &ckFalse,         sizeof(ckFalse)          },
        { CKA_MODULUS,         bigMod,           BIG_VERIFY_MOD_SZ        },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };

    XMEMSET(bigMod, 0xa5, sizeof(bigMod));
    XMEMSET(bigSig, 0x01, sizeof(bigSig));
    XMEMSET(data, 0x11, sizeof(data));
    rv = funcList->C_CreateObject(session, pubTmpl,
                                  sizeof(pubTmpl) / sizeof(*pubTmpl), &pub);
    if (rv != CKR_OK) {
        CHECK_TRUE(1, "oversized RSA public key rejected at import");
        return;
    }

    rv = funcList->C_VerifyInit(session, &mech, pub);
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, data, sizeof(data), bigSig,
                                BIG_VERIFY_MOD_SZ);
        CHECK_TRUE(rv != CKR_OK,
                   "C_Verify(RSA X.509) fails for oversized key");
    }
    else {
        CHECK_TRUE(1, "C_VerifyInit(RSA X.509) rejects oversized key");
    }
    funcList->C_DestroyObject(session, pub);
}
#endif

#if !defined(NO_RSA) && !defined(WC_RSA_DIRECT)
/* Without raw RSA support, raw RSA sign and verify are refused at init. */
static void rsa_x509_unsupported_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_RSA_X_509, NULL, 0 };
    CK_MECHANISM_INFO info;
    CK_SESSION_INFO sessInfo;

    rv = create_rsa_keys(session, &priv, &pub);
    CHECK_RV(rv, "create RSA key pair", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, priv);
    CHECK_RV(rv, "C_SignInit(RSA X.509) without raw RSA",
             CKR_MECHANISM_INVALID);
    rv = funcList->C_VerifyInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyInit(RSA X.509) without raw RSA",
             CKR_MECHANISM_INVALID);
    rv = funcList->C_VerifyRecoverInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyRecoverInit(RSA X.509) without raw RSA",
             CKR_MECHANISM_INVALID);

    rv = funcList->C_GetSessionInfo(session, &sessInfo);
    CHECK_RV(rv, "C_GetSessionInfo", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_GetMechanismInfo(sessInfo.slotID, CKM_RSA_X_509,
                                          &info);
        CHECK_RV(rv, "C_GetMechanismInfo(RSA X.509)", CKR_OK);
        CHECK_TRUE(rv == CKR_OK && (info.flags & (CKF_SIGN | CKF_VERIFY |
                   CKF_VERIFY_RECOVER)) == 0,
                   "RSA X.509 does not advertise sign or verify");
    }

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif

#if !defined(NO_RSA) && defined(WC_RSA_PSS) && !defined(NO_SHA256)
/* A hashed RSA-PSS mechanism fixes the PSS hash to its own digest; any valid
 * MGF1 hash is accepted. */
static void pss_hash_binding_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_RSA_PKCS_PSS_PARAMS params;
    CK_MECHANISM mech;
    byte data[32];
    byte sig[2048 / 8];
    CK_ULONG sigLen = sizeof(sig);

    XMEMSET(data, 0x5a, sizeof(data));
    rv = create_rsa_keys(session, &priv, &pub);
    CHECK_RV(rv, "create RSA key pair", CKR_OK);
    if (rv != CKR_OK)
        return;

    mech.mechanism = CKM_SHA256_RSA_PKCS_PSS;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);

    params.hashAlg = CKM_SHA1;
    params.mgf = CKG_MGF1_SHA256;
    params.sLen = 32;
    rv = funcList->C_SignInit(session, &mech, priv);
    CHECK_RV(rv, "C_SignInit(SHA256 PSS, different hashAlg)",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_VerifyInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyInit(SHA256 PSS, different hashAlg)",
             CKR_MECHANISM_PARAM_INVALID);

    params.hashAlg = CKM_SHA256;
    params.mgf = (CK_RSA_PKCS_MGF_TYPE)0x7FFFFFFFUL;
    rv = funcList->C_SignInit(session, &mech, priv);
    CHECK_RV(rv, "C_SignInit(SHA256 PSS, unknown MGF)",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_VerifyInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyInit(SHA256 PSS, unknown MGF)",
             CKR_MECHANISM_PARAM_INVALID);

    params.mgf = CKG_MGF1_SHA1;
    rv = funcList->C_SignInit(session, &mech, priv);
    CHECK_RV(rv, "C_SignInit(SHA256 PSS, different MGF)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, data, sizeof(data), sig, &sigLen);
        CHECK_RV(rv, "C_Sign(SHA256 PSS, different MGF)", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_RV(rv, "C_VerifyInit(SHA256 PSS, different MGF)", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, data, sizeof(data), sig, sigLen);
        CHECK_RV(rv, "C_Verify(SHA256 PSS, different MGF)", CKR_OK);
    }

    sigLen = sizeof(sig);
    params.mgf = CKG_MGF1_SHA256;
    rv = funcList->C_SignInit(session, &mech, priv);
    CHECK_RV(rv, "C_SignInit(SHA256 PSS, matching params)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, data, sizeof(data), sig, &sigLen);
        CHECK_RV(rv, "C_Sign(SHA256 PSS)", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_RV(rv, "C_VerifyInit(SHA256 PSS, matching params)", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, data, sizeof(data), sig, sigLen);
        CHECK_RV(rv, "C_Verify(SHA256 PSS)", CKR_OK);
    }

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}

/* A PSS salt length larger than any RSA modulus is rejected, not remapped. */
static void pss_salt_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_RSA_PKCS_PSS_PARAMS params;
    CK_MECHANISM mech;
    CK_ULONG badLen[2];
    int i;

    badLen[0] = (CK_ULONG)0xFFFFFFFFUL;
    badLen[1] = (CK_ULONG)0xFFFFFFFEUL;
    rv = create_rsa_keys(session, &priv, &pub);
    CHECK_RV(rv, "create RSA key pair", CKR_OK);
    if (rv != CKR_OK)
        return;

    mech.mechanism = CKM_RSA_PKCS_PSS;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);
    params.hashAlg = CKM_SHA256;
    params.mgf = CKG_MGF1_SHA256;
    for (i = 0; i < 2; i++) {
        params.sLen = badLen[i];
        rv = funcList->C_SignInit(session, &mech, priv);
        CHECK_RV(rv, "C_SignInit(RSA PSS, oversized salt length)",
                 CKR_MECHANISM_PARAM_INVALID);
        rv = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_RV(rv, "C_VerifyInit(RSA PSS, oversized salt length)",
                 CKR_MECHANISM_PARAM_INVALID);
    }

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESCMAC)
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;

/* RFC 4493 AES-CMAC example 2. */
static byte cmacKey[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static byte cmacMsg[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
static byte cmacTag[16] = {
    0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
    0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
};

/* CKM_AES_CMAC produces and checks the full AES block as its MAC. */
static void aes_cmac_full_block_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_AES_CMAC, NULL, 0 };
    byte mac[32];
    CK_ULONG macLen;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_SIGN,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_VERIFY,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    cmacKey,         sizeof(cmacKey)        },
    };

    rv = funcList->C_CreateObject(session, keyTmpl,
                                  sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    CHECK_RV(rv, "create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(AES-CMAC)", CKR_OK);
    if (rv == CKR_OK) {
        macLen = 0;
        rv = funcList->C_Sign(session, cmacMsg, sizeof(cmacMsg), NULL, &macLen);
        CHECK_RV(rv, "C_Sign(AES-CMAC, length query)", CKR_OK);
        CHECK_TRUE(macLen == sizeof(cmacTag), "AES-CMAC length is one block");
        macLen = sizeof(mac);
        rv = funcList->C_Sign(session, cmacMsg, sizeof(cmacMsg), mac, &macLen);
        CHECK_RV(rv, "C_Sign(AES-CMAC)", CKR_OK);
        CHECK_TRUE(macLen == sizeof(cmacTag) &&
                   XMEMCMP(mac, cmacTag, sizeof(cmacTag)) == 0,
                   "AES-CMAC matches the full known-answer tag");
    }

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(AES-CMAC multi-part)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SignUpdate(session, cmacMsg, sizeof(cmacMsg));
        CHECK_RV(rv, "C_SignUpdate(AES-CMAC)", CKR_OK);
        macLen = sizeof(mac);
        rv = funcList->C_SignFinal(session, mac, &macLen);
        CHECK_RV(rv, "C_SignFinal(AES-CMAC)", CKR_OK);
        CHECK_TRUE(macLen == sizeof(cmacTag) &&
                   XMEMCMP(mac, cmacTag, sizeof(cmacTag)) == 0,
                   "multi-part AES-CMAC matches the full known-answer tag");
    }

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(AES-CMAC)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, cmacMsg, sizeof(cmacMsg), cmacTag,
                                sizeof(cmacTag));
        CHECK_RV(rv, "C_Verify(AES-CMAC, full tag)", CKR_OK);
    }

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(AES-CMAC, half tag)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, cmacMsg, sizeof(cmacMsg), cmacTag,
                                sizeof(cmacTag) / 2);
        CHECK_TRUE(rv != CKR_OK, "C_Verify(AES-CMAC) rejects a half-block tag");
    }

    funcList->C_DestroyObject(session, key);
}

/* The CKM_AES_CMAC_GENERAL length is validated as the full CK_ULONG value. */
static void aes_cmac_general_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MAC_GENERAL_PARAMS macLen = 16;
    CK_MECHANISM mech = { CKM_AES_CMAC_GENERAL, &macLen, sizeof(macLen) };
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_SIGN,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_VERIFY,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    cmacKey,         sizeof(cmacKey)        },
    };

    if (sizeof(CK_ULONG) <= sizeof(word32))
        return;
    /* Out of range, but equal to a valid length in the low 32 bits. */
    macLen |= ((CK_ULONG)1 << 16) << 16;

    rv = funcList->C_CreateObject(session, keyTmpl,
                                  sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    CHECK_RV(rv, "create AES key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(AES-CMAC-GENERAL, out of range length)",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(AES-CMAC-GENERAL, out of range length)",
             CKR_MECHANISM_PARAM_INVALID);

    funcList->C_DestroyObject(session, key);
}
#endif

#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_SHA256)
static CK_OBJECT_CLASS tlsKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static byte tlsSecret[48] = { 0x42 };
static byte tlsHandshakeHash[32] = { 0x17 };

static CK_RV create_generic_key(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &tlsKeyClass,    sizeof(tlsKeyClass)    },
        { CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType) },
        { CKA_SIGN,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_VERIFY,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_PRIVATE,  &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    tlsSecret,       sizeof(tlsSecret)      },
    };

    return funcList->C_CreateObject(session, keyTmpl,
                                    sizeof(keyTmpl) / sizeof(*keyTmpl), key);
}

static void tls_mac_params(CK_TLS_MAC_PARAMS* params, CK_MECHANISM* mech)
{
    params->prfHashMechanism = CKM_SHA256;
    params->ulMacLength = 12;
    params->ulServerOrClient = 1;
    mech->mechanism = CKM_TLS_MAC;
    mech->pParameter = params;
    mech->ulParameterLen = sizeof(*params);
}

/* A short output buffer leaves a multi-part TLS MAC active for a retry. */
static void tls_mac_sign_final_retry_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_TLS_MAC_PARAMS params;
    CK_MECHANISM mech;
    byte expMac[12];
    byte mac[12];
    CK_ULONG macLen;

    rv = create_generic_key(session, &key);
    CHECK_RV(rv, "create TLS secret", CKR_OK);
    if (rv != CKR_OK)
        return;
    tls_mac_params(&params, &mech);

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(TLS MAC single-part)", CKR_OK);
    if (rv == CKR_OK) {
        macLen = sizeof(expMac);
        rv = funcList->C_Sign(session, tlsHandshakeHash,
                              sizeof(tlsHandshakeHash), expMac, &macLen);
        CHECK_RV(rv, "C_Sign(TLS MAC)", CKR_OK);
    }

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(TLS MAC multi-part)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SignUpdate(session, tlsHandshakeHash,
                                    sizeof(tlsHandshakeHash));
        CHECK_RV(rv, "C_SignUpdate(TLS MAC)", CKR_OK);
        macLen = 4;
        rv = funcList->C_SignFinal(session, mac, &macLen);
        CHECK_RV(rv, "C_SignFinal(TLS MAC, short buffer)",
                 CKR_BUFFER_TOO_SMALL);
        macLen = sizeof(mac);
        rv = funcList->C_SignFinal(session, mac, &macLen);
        CHECK_RV(rv, "C_SignFinal(TLS MAC, retry)", CKR_OK);
        CHECK_TRUE(rv == CKR_OK && macLen == sizeof(expMac) &&
                   XMEMCMP(mac, expMac, sizeof(expMac)) == 0,
                   "retried TLS MAC matches the single-part result");
    }

    funcList->C_DestroyObject(session, key);
}

/* A TLS MAC verify supports the multi-part update and final calls. */
static void tls_mac_verify_multipart_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_TLS_MAC_PARAMS params;
    CK_MECHANISM mech;
    byte mac[12];
    CK_ULONG macLen = sizeof(mac);
    CK_ULONG half = sizeof(tlsHandshakeHash) / 2;

    rv = create_generic_key(session, &key);
    CHECK_RV(rv, "create TLS secret", CKR_OK);
    if (rv != CKR_OK)
        return;
    tls_mac_params(&params, &mech);

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(TLS MAC)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, tlsHandshakeHash,
                              sizeof(tlsHandshakeHash), mac, &macLen);
        CHECK_RV(rv, "C_Sign(TLS MAC)", CKR_OK);
    }

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(TLS MAC multi-part)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_VerifyUpdate(session, tlsHandshakeHash, half);
        CHECK_RV(rv, "C_VerifyUpdate(TLS MAC, first part)", CKR_OK);
        rv = funcList->C_VerifyUpdate(session, tlsHandshakeHash + half,
                                      sizeof(tlsHandshakeHash) - half);
        CHECK_RV(rv, "C_VerifyUpdate(TLS MAC, second part)", CKR_OK);
        rv = funcList->C_VerifyFinal(session, mac, macLen);
        CHECK_RV(rv, "C_VerifyFinal(TLS MAC)", CKR_OK);
    }

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(TLS MAC, other data)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_VerifyUpdate(session, tlsHandshakeHash, half);
        CHECK_RV(rv, "C_VerifyUpdate(TLS MAC, partial data)", CKR_OK);
        rv = funcList->C_VerifyFinal(session, mac, macLen);
        CHECK_RV(rv, "C_VerifyFinal(TLS MAC, other data)",
                 CKR_SIGNATURE_INVALID);
    }

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(TLS MAC, mixed calls)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_VerifyUpdate(session, tlsHandshakeHash, half);
        CHECK_RV(rv, "C_VerifyUpdate(TLS MAC, before single-part)", CKR_OK);
        rv = funcList->C_Verify(session, tlsHandshakeHash,
                                sizeof(tlsHandshakeHash), mac, macLen);
        CHECK_TRUE(rv != CKR_OK,
                   "C_Verify(TLS MAC) does not finish a multi-part verify");
    }

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(TLS MAC, mixed calls)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SignUpdate(session, tlsHandshakeHash, half);
        CHECK_RV(rv, "C_SignUpdate(TLS MAC, before single-part)", CKR_OK);
        macLen = sizeof(mac);
        rv = funcList->C_Sign(session, tlsHandshakeHash,
                              sizeof(tlsHandshakeHash), mac, &macLen);
        CHECK_RV(rv, "C_Sign(TLS MAC, after update)", CKR_OK);
    }
    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(TLS MAC, after sign)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_VerifyUpdate(session, tlsHandshakeHash,
                                      sizeof(tlsHandshakeHash));
        CHECK_RV(rv, "C_VerifyUpdate(TLS MAC, after sign)", CKR_OK);
        rv = funcList->C_VerifyFinal(session, mac, macLen);
        CHECK_RV(rv, "C_VerifyFinal(TLS MAC, after sign)", CKR_OK);
    }

    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(TLS MAC, after mixed calls)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, tlsHandshakeHash,
                                sizeof(tlsHandshakeHash), mac, macLen);
        CHECK_RV(rv, "C_Verify(TLS MAC, after mixed calls)", CKR_OK);
    }

    funcList->C_DestroyObject(session, key);
}

/* The TLS MAC length is validated as the full CK_ULONG value. */
static void tls_mac_len_param_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_TLS_MAC_PARAMS params;
    CK_MECHANISM mech;
    CK_ULONG high;

    if (sizeof(CK_ULONG) <= sizeof(word32))
        return;
    high = ((CK_ULONG)1 << 16) << 16;

    rv = create_generic_key(session, &key);
    CHECK_RV(rv, "create TLS secret", CKR_OK);
    if (rv != CKR_OK)
        return;
    tls_mac_params(&params, &mech);

    params.ulMacLength = high;
    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(TLS MAC, length above 32 bits)",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(TLS MAC, length above 32 bits)",
             CKR_MECHANISM_PARAM_INVALID);

    params.ulMacLength = high | 12;
    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(TLS MAC, length above 32 bits plus 12)",
             CKR_MECHANISM_PARAM_INVALID);
    rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "C_VerifyInit(TLS MAC, length above 32 bits plus 12)",
             CKR_MECHANISM_PARAM_INVALID);

    funcList->C_DestroyObject(session, key);
}

/* Closing a session discards any multi-part TLS MAC data it held. */
static void tls_mac_verify_session_close_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_TLS_MAC_PARAMS params;
    CK_MECHANISM mech;
    byte mac[12];
    CK_ULONG macLen = sizeof(mac);
    int i;

    tls_mac_params(&params, &mech);
    for (i = 0; i < 2; i++) {
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
        CHECK_RV(rv, "C_OpenSession(TLS MAC close)", CKR_OK);
        if (rv != CKR_OK)
            return;
        rv = create_generic_key(session, &key);
        CHECK_RV(rv, "create TLS secret (TLS MAC close)", CKR_OK);
        if (rv == CKR_OK && i == 0) {
            rv = funcList->C_VerifyInit(session, &mech, key);
            CHECK_RV(rv, "C_VerifyInit(TLS MAC, abandoned)", CKR_OK);
            rv = funcList->C_VerifyUpdate(session, tlsHandshakeHash, 8);
            CHECK_RV(rv, "C_VerifyUpdate(TLS MAC, abandoned)", CKR_OK);
        }
        else if (rv == CKR_OK) {
            rv = funcList->C_SignInit(session, &mech, key);
            CHECK_RV(rv, "C_SignInit(TLS MAC, new session)", CKR_OK);
            rv = funcList->C_Sign(session, tlsHandshakeHash,
                                  sizeof(tlsHandshakeHash), mac, &macLen);
            CHECK_RV(rv, "C_Sign(TLS MAC, new session)", CKR_OK);
            rv = funcList->C_VerifyInit(session, &mech, key);
            CHECK_RV(rv, "C_VerifyInit(TLS MAC, new session)", CKR_OK);
            rv = funcList->C_VerifyUpdate(session, tlsHandshakeHash,
                                          sizeof(tlsHandshakeHash));
            CHECK_RV(rv, "C_VerifyUpdate(TLS MAC, new session)", CKR_OK);
            rv = funcList->C_VerifyFinal(session, mac, macLen);
            CHECK_RV(rv, "C_VerifyFinal(TLS MAC, new session)", CKR_OK);
        }
        funcList->C_CloseSession(session);
    }
}
#endif

#if !defined(NO_HMAC) && !defined(NO_SHA256)
static CK_OBJECT_CLASS hmacKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE hmacKeyType = CKK_GENERIC_SECRET;

/* The HMAC output length parameter is compared as the full CK_ULONG value. */
static void hmac_len_param_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG digestLen = 32;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, &digestLen, sizeof(digestLen) };
    byte keyData[32];
    byte data[16];
    byte mac[32];
    CK_ULONG macLen = sizeof(mac);
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &hmacKeyClass, sizeof(hmacKeyClass) },
        { CKA_KEY_TYPE, &hmacKeyType,  sizeof(hmacKeyType)  },
        { CKA_SIGN,     &ckTrue,       sizeof(ckTrue)       },
        { CKA_PRIVATE,  &ckFalse,      sizeof(ckFalse)      },
        { CKA_VALUE,    keyData,       sizeof(keyData)      },
    };

    XMEMSET(keyData, 0x0b, sizeof(keyData));
    XMEMSET(data, 0x61, sizeof(data));
    rv = funcList->C_CreateObject(session, keyTmpl,
                                  sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    CHECK_RV(rv, "create HMAC key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, &mech, key);
    CHECK_RV(rv, "C_SignInit(SHA256 HMAC, matching length)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, data, sizeof(data), mac, &macLen);
        CHECK_RV(rv, "C_Sign(SHA256 HMAC)", CKR_OK);
    }

    if (sizeof(CK_ULONG) > sizeof(word32)) {
        /* Out of range, but equal to the digest size in the low 32 bits. */
        digestLen |= ((CK_ULONG)1 << 16) << 16;
        rv = funcList->C_SignInit(session, &mech, key);
        CHECK_RV(rv, "C_SignInit(SHA256 HMAC, length above 32 bits)",
                 CKR_MECHANISM_PARAM_INVALID);
    }

    funcList->C_DestroyObject(session, key);
}
#endif

#ifdef HAVE_ECC
static CK_OBJECT_CLASS ecPubClass = CKO_PUBLIC_KEY;
static CK_KEY_TYPE ecKeyType = CKK_EC;

/* An ECDSA signature whose length is not 2 * order size is out of range. */
static void ecdsa_sig_len_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
    byte hash[32];
    byte sig[65];
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,     &ecPubClass,     sizeof(ecPubClass)      },
        { CKA_KEY_TYPE,  &ecKeyType,      sizeof(ecKeyType)       },
        { CKA_VERIFY,    &ckTrue,         sizeof(ckTrue)          },
        { CKA_PRIVATE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_EC_POINT,  ecc_p256_pub,    sizeof(ecc_p256_pub)    },
    };

    XMEMSET(hash, 0x3c, sizeof(hash));
    XMEMSET(sig, 0x01, sizeof(sig));
    rv = funcList->C_CreateObject(session, pubTmpl,
                                  sizeof(pubTmpl) / sizeof(*pubTmpl), &pub);
    CHECK_RV(rv, "create EC public key", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_VerifyInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyInit(ECDSA, short signature)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, hash, sizeof(hash), sig, 63);
        CHECK_RV(rv, "C_Verify(ECDSA, short signature)",
                 CKR_SIGNATURE_LEN_RANGE);
    }

    rv = funcList->C_VerifyInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyInit(ECDSA, long signature)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, hash, sizeof(hash), sig, 65);
        CHECK_RV(rv, "C_Verify(ECDSA, long signature)",
                 CKR_SIGNATURE_LEN_RANGE);
    }

    rv = funcList->C_VerifyInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyInit(ECDSA, wrong signature)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, hash, sizeof(hash), sig, 64);
        CHECK_RV(rv, "C_Verify(ECDSA, wrong signature)",
                 CKR_SIGNATURE_INVALID);
    }

    funcList->C_DestroyObject(session, pub);
}
#endif

#ifdef WOLFSSL_MAXQ10XX_CRYPTO
/* Signing with the pre-provisioned device key requires a user login. */
static void maxq_device_key_login_test(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };

    rv = funcList->C_Logout(session);
    CHECK_RV(rv, "C_Logout", CKR_OK);
    rv = funcList->C_SignInit(session, &mech, 0);
    CHECK_RV(rv, "C_SignInit(device key, no login)", CKR_USER_NOT_LOGGED_IN);
    rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                           (CK_ULONG)XSTRLEN(userPin));
    CHECK_RV(rv, "user login again", CKR_OK);
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
#if !defined(NO_RSA) && defined(WC_RSA_PSS) && !defined(NO_SHA256)
        pss_hash_binding_test(session);
        pss_salt_len_test(session);
#endif
#if !defined(NO_RSA) && defined(WC_RSA_DIRECT)
        rsa_x509_verify_block_test(session);
        rsa_x509_big_modulus_sign_test(session);
        rsa_x509_big_modulus_verify_test(session);
#endif
#if !defined(NO_RSA) && !defined(WC_RSA_DIRECT)
        rsa_x509_unsupported_test(session);
#endif
#if !defined(NO_AES) && defined(HAVE_AESCMAC)
        aes_cmac_full_block_test(session);
        aes_cmac_general_len_test(session);
#endif
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_SHA256)
        tls_mac_sign_final_retry_test(session);
        tls_mac_verify_multipart_test(session);
        tls_mac_verify_session_close_test(slot);
        tls_mac_len_param_test(session);
#endif
#ifdef HAVE_ECC
        ecdsa_sig_len_test(session);
#endif
#if !defined(NO_HMAC) && !defined(NO_SHA256)
        hmac_len_param_test(session);
#endif
#ifdef WOLFSSL_MAXQ10XX_CRYPTO
        maxq_device_key_login_test(session);
#endif
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

    printf("=== wolfPKCS11 sign, verify and MAC test ===\n");
    run_test();
    return pkcs11_test_summary();
}
