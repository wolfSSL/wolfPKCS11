/* verify_return_codes_test.c
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
 * Return codes of C_Verify, C_VerifyFinal and C_VerifyRecover for invalid
 * signatures and signatures of the wrong length.
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

#define TEST_DIR "./store/verify_return_codes_test"

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_BYTE msg[] = "message to sign";

static CK_RV do_sign(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                     CK_OBJECT_HANDLE priv, CK_BYTE* data, CK_ULONG dataLen,
                     CK_BYTE* sig, CK_ULONG* sigLen, const char* what)
{
    CK_RV rv;

    rv = funcList->C_SignInit(session, mech, priv);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, data, dataLen, sig, sigLen);
    CHECK_RV(rv, what, CKR_OK);
    return rv;
}

/* C_Verify gives the expected code and leaves no operation behind. */
static void check_verify(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                         CK_OBJECT_HANDLE pub, CK_BYTE* data, CK_ULONG dataLen,
                         CK_BYTE* sig, CK_ULONG sigLen, CK_RV expected,
                         const char* what)
{
    CK_RV rv;

    rv = funcList->C_VerifyInit(session, mech, pub);
    if (rv != CKR_OK) {
        CHECK_RV(rv, "C_VerifyInit", CKR_OK);
        return;
    }
    rv = funcList->C_Verify(session, data, dataLen, sig, sigLen);
    CHECK_RV(rv, what, expected);
    rv = funcList->C_Verify(session, data, dataLen, sig, sigLen);
    CHECK_RV(rv, "C_Verify ended the operation", CKR_OPERATION_NOT_INITIALIZED);
}

#if (!defined(NO_HMAC) && !defined(NO_SHA256)) || \
    (!defined(NO_AES) && defined(HAVE_AESCMAC))
static void check_verify_final(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                               CK_OBJECT_HANDLE pub, CK_BYTE* sig,
                               CK_ULONG sigLen, CK_RV expected,
                               const char* what)
{
    CK_RV rv;

    rv = funcList->C_VerifyInit(session, mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_VerifyUpdate(session, msg, sizeof(msg));
    if (rv != CKR_OK) {
        CHECK_RV(rv, "C_VerifyInit and C_VerifyUpdate", CKR_OK);
        return;
    }
    rv = funcList->C_VerifyFinal(session, sig, sigLen);
    CHECK_RV(rv, what, expected);
    rv = funcList->C_VerifyFinal(session, sig, sigLen);
    CHECK_RV(rv, "C_VerifyFinal ended the operation",
             CKR_OPERATION_NOT_INITIALIZED);
}
#endif

#ifndef NO_RSA
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
        { CKA_VERIFY_RECOVER,   &ckTrue,           sizeof(ckTrue)            },
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

/* Checks shared by the RSA signature mechanisms. */
static void check_rsa_sig(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                          CK_OBJECT_HANDLE pub, CK_BYTE* data,
                          CK_ULONG dataLen, CK_BYTE* sig, const char* name)
{
    CK_BYTE bad[512];
    CK_ULONG k = sizeof(rsa_2048_modulus);
    CK_ULONG lens[] = { 1, 255, 257, 512 };
    char what[96];
    size_t i;

    check_verify(session, mech, pub, data, dataLen, sig, k, CKR_OK, name);

    XMEMCPY(bad, sig, k);
    bad[128] ^= 0x01;
    snprintf(what, sizeof(what), "%s: bit flipped", name);
    check_verify(session, mech, pub, data, dataLen, bad, k,
                 CKR_SIGNATURE_INVALID, what);

    XMEMSET(bad, 0xFF, sizeof(bad));
    snprintf(what, sizeof(what), "%s: signature above the modulus", name);
    check_verify(session, mech, pub, data, dataLen, bad, k,
                 CKR_SIGNATURE_INVALID, what);

    XMEMSET(bad, 0, sizeof(bad));
    XMEMCPY(bad, sig, k);
    for (i = 0; i < sizeof(lens) / sizeof(*lens); i++) {
        snprintf(what, sizeof(what), "%s: %lu-byte signature", name,
                 (unsigned long)lens[i]);
        check_verify(session, mech, pub, data, dataLen, bad, lens[i],
                     CKR_SIGNATURE_LEN_RANGE, what);
    }
}

static void test_rsa(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_BYTE sig[256];
    CK_ULONG sigLen;
    CK_BYTE info[51];
#ifdef WC_RSA_PSS
    CK_RSA_PKCS_PSS_PARAMS pss;
#endif
    CK_BYTE raw[257];

    printf("--- RSA ---\n");
    XMEMSET(raw, 0x5A, sizeof(raw));
    if (create_rsa_keys(session, &priv, &pub) != CKR_OK)
        return;
    XMEMSET(&mech, 0, sizeof(mech));

#ifndef NO_SHA256
    mech.mechanism = CKM_SHA256_RSA_PKCS;
    sigLen = sizeof(sig);
    rv = do_sign(session, &mech, priv, msg, sizeof(msg), sig, &sigLen,
                 "C_Sign(CKM_SHA256_RSA_PKCS)");
    if (rv == CKR_OK) {
        check_rsa_sig(session, &mech, pub, msg, sizeof(msg), sig,
                      "CKM_SHA256_RSA_PKCS");
    }
#endif

    mech.mechanism = CKM_RSA_PKCS;
    XMEMSET(info, 0x3C, sizeof(info));
    sigLen = sizeof(sig);
    rv = do_sign(session, &mech, priv, info, sizeof(info), sig, &sigLen,
                 "C_Sign(CKM_RSA_PKCS)");
    if (rv == CKR_OK) {
        check_rsa_sig(session, &mech, pub, info, sizeof(info), sig,
                      "CKM_RSA_PKCS");
        check_verify(session, &mech, pub, raw, sizeof(rsa_2048_modulus) - 10,
                     sig, sigLen, CKR_DATA_LEN_RANGE,
                     "CKM_RSA_PKCS: data longer than k - 11");
    }

#if defined(WC_RSA_PSS) && !defined(NO_SHA256)
    pss.hashAlg = CKM_SHA256;
    pss.mgf = CKG_MGF1_SHA256;
    pss.sLen = 32;
    mech.mechanism = CKM_SHA256_RSA_PKCS_PSS;
    mech.pParameter = &pss;
    mech.ulParameterLen = sizeof(pss);
    sigLen = sizeof(sig);
    rv = do_sign(session, &mech, priv, msg, sizeof(msg), sig, &sigLen,
                 "C_Sign(CKM_SHA256_RSA_PKCS_PSS)");
    if (rv == CKR_OK) {
        check_rsa_sig(session, &mech, pub, msg, sizeof(msg), sig,
                      "CKM_SHA256_RSA_PKCS_PSS");
    }

    mech.mechanism = CKM_RSA_PKCS_PSS;
    sigLen = sizeof(sig);
    rv = do_sign(session, &mech, priv, info, 32, sig, &sigLen,
                 "C_Sign(CKM_RSA_PKCS_PSS)");
    if (rv == CKR_OK) {
        check_verify(session, &mech, pub, info, 32, sig, sigLen, CKR_OK,
                     "CKM_RSA_PKCS_PSS valid signature");
        check_verify(session, &mech, pub, info, 20, sig, sigLen,
                     CKR_DATA_LEN_RANGE,
                     "CKM_RSA_PKCS_PSS: hash shorter than the PSS hash");
    }
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
#endif

#ifdef WC_RSA_DIRECT
    mech.mechanism = CKM_RSA_X_509;
    XMEMSET(raw, 0x5A, sizeof(raw));
    raw[0] = 0x01;
    raw[256] = 0x00;
    sigLen = sizeof(sig);
    rv = do_sign(session, &mech, priv, raw, 256, sig, &sigLen,
                 "C_Sign(CKM_RSA_X_509)");
    if (rv == CKR_OK) {
        check_rsa_sig(session, &mech, pub, raw, 256, sig, "CKM_RSA_X_509");
        check_verify(session, &mech, pub, raw, sizeof(raw), sig, sigLen,
                     CKR_DATA_LEN_RANGE,
                     "CKM_RSA_X_509: data longer than the modulus");
    }
#endif

    funcList->C_DestroyObject(session, pub);
    funcList->C_DestroyObject(session, priv);
}

#ifdef WC_RSA_DIRECT
static void test_rsa_verify_recover(CK_SESSION_HANDLE session,
                                    CK_MECHANISM_TYPE mechType)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_BYTE block[256];
    CK_BYTE* data = msg;
    CK_ULONG dataLen = sizeof(msg);
    CK_BYTE* expect = msg;
    CK_ULONG expectLen = sizeof(msg);
    CK_BYTE sig[256];
    CK_BYTE bad[256];
    CK_ULONG sigLen = sizeof(sig);
    CK_BYTE out[256];
    CK_ULONG outLen;

    printf("--- RSA verify recover (%s) ---\n",
           mechType == CKM_RSA_PKCS ? "CKM_RSA_PKCS" : "CKM_RSA_X_509");
    if (create_rsa_keys(session, &priv, &pub) != CKR_OK)
        return;
    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = mechType;
    if (mechType == CKM_RSA_X_509) {
        /* The recovered block loses its 200 leading zero bytes. */
        XMEMSET(block, 0, 200);
        block[200] = 0x01;
        XMEMSET(block + 201, 0x5A, sizeof(block) - 201);
        data = block;
        dataLen = sizeof(block);
        expect = block + 200;
        expectLen = sizeof(block) - 200;
    }

    rv = do_sign(session, &mech, priv, data, dataLen, sig, &sigLen,
                 "C_Sign for recover");
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_VerifyRecoverInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyRecoverInit", CKR_OK);
    outLen = 0;
    rv = funcList->C_VerifyRecover(session, sig, sigLen, NULL, &outLen);
    CHECK_RV(rv, "C_VerifyRecover length query", CKR_OK);
    CHECK_TRUE(outLen >= expectLen, "length query covers the message");
    outLen = expectLen - 1;
    rv = funcList->C_VerifyRecover(session, sig, sigLen, out, &outLen);
    CHECK_RV(rv, "C_VerifyRecover one byte short", CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(outLen == expectLen, "short buffer reports the exact length");
    outLen = expectLen;
    rv = funcList->C_VerifyRecover(session, sig, sigLen, out, &outLen);
    CHECK_RV(rv, "C_VerifyRecover message-sized buffer", CKR_OK);
    CHECK_TRUE(outLen == expectLen && XMEMCMP(out, expect, expectLen) == 0,
               "recovered message matches");

    if (mechType == CKM_RSA_PKCS) {
        XMEMCPY(bad, sig, sizeof(bad));
        bad[128] ^= 0x01;
        rv = funcList->C_VerifyRecoverInit(session, &mech, pub);
        CHECK_RV(rv, "C_VerifyRecoverInit", CKR_OK);
        outLen = sizeof(out);
        rv = funcList->C_VerifyRecover(session, bad, sigLen, out, &outLen);
        CHECK_RV(rv, "C_VerifyRecover bit flipped", CKR_SIGNATURE_INVALID);
    }

    XMEMSET(bad, 0xFF, sizeof(bad));
    rv = funcList->C_VerifyRecoverInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyRecoverInit", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_VerifyRecover(session, bad, sigLen, out, &outLen);
    CHECK_RV(rv, "C_VerifyRecover signature above the modulus",
             CKR_SIGNATURE_INVALID);

    rv = funcList->C_VerifyRecoverInit(session, &mech, pub);
    CHECK_RV(rv, "C_VerifyRecoverInit", CKR_OK);
    outLen = 0;
    rv = funcList->C_VerifyRecover(session, sig, sigLen - 1, NULL, &outLen);
    CHECK_RV(rv, "C_VerifyRecover length query, 255-byte signature", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_VerifyRecover(session, sig, sigLen - 1, out, &outLen);
    CHECK_RV(rv, "C_VerifyRecover 255-byte signature",
             CKR_SIGNATURE_LEN_RANGE);
    rv = funcList->C_VerifyRecover(session, sig, sigLen, out, &outLen);
    CHECK_RV(rv, "C_VerifyRecover ended the operation",
             CKR_OPERATION_NOT_INITIALIZED);

out:
    funcList->C_DestroyObject(session, pub);
    funcList->C_DestroyObject(session, priv);
}
#endif /* WC_RSA_DIRECT */
#endif /* !NO_RSA */

#if defined(HAVE_ECC) && !defined(NO_SHA256) && \
    (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES))
static void test_ecdsa_p521(CK_SESSION_HANDLE session)
{
    static CK_BYTE p521Params[] = {
        0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23
    };
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_BYTE sig[132];
    CK_BYTE bad[132];
    CK_ULONG sigLen = sizeof(sig);
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, p521Params, sizeof(p521Params) },
        { CKA_VERIFY,    &ckTrue,    sizeof(ckTrue)     },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_SIGN,      &ckTrue,    sizeof(ckTrue)     },
        { CKA_PRIVATE,   &ckFalse,   sizeof(ckFalse)    },
    };

    printf("--- ECDSA P-521 ---\n");
    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_EC_KEY_PAIR_GEN;
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
                                     sizeof(pubTmpl) / sizeof(*pubTmpl),
                                     privTmpl,
                                     sizeof(privTmpl) / sizeof(*privTmpl),
                                     &pub, &priv);
    CHECK_RV(rv, "C_GenerateKeyPair(P-521)", CKR_OK);
    if (rv != CKR_OK)
        return;

    mech.mechanism = CKM_ECDSA_SHA256;
    rv = do_sign(session, &mech, priv, msg, sizeof(msg), sig, &sigLen,
                 "C_Sign(CKM_ECDSA_SHA256)");
    if (rv == CKR_OK) {
        CHECK_TRUE(sigLen == sizeof(sig), "P-521 signature is 132 bytes");
    }
    if (rv == CKR_OK && sigLen == sizeof(sig)) {
        check_verify(session, &mech, pub, msg, sizeof(msg), sig, sigLen,
                     CKR_OK, "P-521 valid signature");

        XMEMCPY(bad, sig, sizeof(bad));
        bad[0] |= 0x80;
        check_verify(session, &mech, pub, msg, sizeof(msg), bad, sigLen,
                     CKR_SIGNATURE_INVALID, "P-521 r above the order");

        XMEMCPY(bad, sig, sizeof(bad));
        bad[66] |= 0x02;
        check_verify(session, &mech, pub, msg, sizeof(msg), bad, sigLen,
                     CKR_SIGNATURE_INVALID, "P-521 s above the order");

        XMEMSET(bad, 0, sizeof(bad));
        check_verify(session, &mech, pub, msg, sizeof(msg), bad, sigLen,
                     CKR_SIGNATURE_INVALID, "P-521 r and s zero");
    }

    funcList->C_DestroyObject(session, pub);
    funcList->C_DestroyObject(session, priv);
}
#endif

#ifdef WOLFPKCS11_MLDSA
static void test_mldsa(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = CKP_ML_DSA_44;
    CK_BYTE sig[2420];
    CK_BYTE bad[2420];
    CK_ULONG sigLen = sizeof(sig);
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
        { CKA_VERIFY,        &ckTrue,   sizeof(ckTrue)   },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_SIGN,          &ckTrue,   sizeof(ckTrue)   },
        { CKA_PRIVATE,       &ckFalse,  sizeof(ckFalse)  },
    };

    printf("--- ML-DSA-44 ---\n");
    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_ML_DSA_KEY_PAIR_GEN;
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
                                     sizeof(pubTmpl) / sizeof(*pubTmpl),
                                     privTmpl,
                                     sizeof(privTmpl) / sizeof(*privTmpl),
                                     &pub, &priv);
    CHECK_RV(rv, "C_GenerateKeyPair(ML-DSA-44)", CKR_OK);
    if (rv != CKR_OK)
        return;

    mech.mechanism = CKM_ML_DSA;
    rv = do_sign(session, &mech, priv, msg, sizeof(msg), sig, &sigLen,
                 "C_Sign(CKM_ML_DSA)");
    if (rv == CKR_OK) {
        CHECK_TRUE(sigLen == sizeof(sig), "ML-DSA-44 signature is 2420 bytes");
    }
    if (rv == CKR_OK && sigLen == sizeof(sig)) {
        check_verify(session, &mech, pub, msg, sizeof(msg), sig, sigLen,
                     CKR_OK, "ML-DSA valid signature");

        /* The last byte is the hint count of the last row, at most omega. */
        XMEMCPY(bad, sig, sizeof(bad));
        bad[sizeof(bad) - 1] = 81;
        check_verify(session, &mech, pub, msg, sizeof(msg), bad, sigLen,
                     CKR_SIGNATURE_INVALID, "ML-DSA hint count above omega");

        check_verify(session, &mech, pub, msg, sizeof(msg), sig, sigLen - 1,
                     CKR_SIGNATURE_LEN_RANGE, "ML-DSA short signature");
    }

    funcList->C_DestroyObject(session, pub);
    funcList->C_DestroyObject(session, priv);
}
#endif

#if (!defined(NO_HMAC) && !defined(NO_SHA256)) || \
    (!defined(NO_AES) && defined(HAVE_AESCMAC))
/* Sign msg with a MAC mechanism, then check wrong-length MACs. */
static void check_mac_lengths(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                              CK_OBJECT_HANDLE key, const char* name)
{
    CK_RV rv;
    CK_BYTE sig[80];
    CK_ULONG sigLen = sizeof(sig);
    char what[96];

    snprintf(what, sizeof(what), "C_Sign(%s)", name);
    XMEMSET(sig, 0, sizeof(sig));
    rv = do_sign(session, mech, key, msg, sizeof(msg), sig, &sigLen, what);
    if (rv != CKR_OK)
        return;

    snprintf(what, sizeof(what), "%s: C_Verify valid MAC", name);
    check_verify(session, mech, key, msg, sizeof(msg), sig, sigLen, CKR_OK,
                 what);
    snprintf(what, sizeof(what), "%s: C_Verify short MAC", name);
    check_verify(session, mech, key, msg, sizeof(msg), sig, sigLen - 1,
                 CKR_SIGNATURE_LEN_RANGE, what);
    snprintf(what, sizeof(what), "%s: C_Verify long MAC", name);
    check_verify(session, mech, key, msg, sizeof(msg), sig, sigLen + 1,
                 CKR_SIGNATURE_LEN_RANGE, what);
    snprintf(what, sizeof(what), "%s: C_VerifyFinal valid MAC", name);
    check_verify_final(session, mech, key, sig, sigLen, CKR_OK, what);
    snprintf(what, sizeof(what), "%s: C_VerifyFinal short MAC", name);
    check_verify_final(session, mech, key, sig, sigLen - 1,
                       CKR_SIGNATURE_LEN_RANGE, what);
    snprintf(what, sizeof(what), "%s: C_VerifyFinal long MAC", name);
    check_verify_final(session, mech, key, sig, sigLen + 1,
                       CKR_SIGNATURE_LEN_RANGE, what);
}
#endif

#if !defined(NO_HMAC) && !defined(NO_SHA256)
static void test_hmac(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_BYTE keyData[32];
    CK_MECHANISM mech;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_VALUE,    keyData,      sizeof(keyData)     },
        { CKA_SIGN,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_VERIFY,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };

    printf("--- HMAC ---\n");
    XMEMSET(keyData, 0x42, sizeof(keyData));
    rv = funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
                                  &key);
    CHECK_RV(rv, "C_CreateObject(HMAC key)", CKR_OK);
    if (rv != CKR_OK)
        return;

    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_SHA256_HMAC;
    check_mac_lengths(session, &mech, key, "CKM_SHA256_HMAC");

    funcList->C_DestroyObject(session, key);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESCMAC)
static void test_cmac(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_MECHANISM mech;
    CK_MAC_GENERAL_PARAMS macLen = 10;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
        { CKA_SIGN,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_VERIFY,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };

    printf("--- AES-CMAC ---\n");
    rv = funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
                                  &key);
    CHECK_RV(rv, "C_CreateObject(AES key)", CKR_OK);
    if (rv != CKR_OK)
        return;

    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_AES_CMAC;
    check_mac_lengths(session, &mech, key, "CKM_AES_CMAC");

    mech.mechanism = CKM_AES_CMAC_GENERAL;
    mech.pParameter = &macLen;
    mech.ulParameterLen = sizeof(macLen);
    check_mac_lengths(session, &mech, key, "CKM_AES_CMAC_GENERAL");

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
#ifdef WC_RSA_DIRECT
    test_rsa_verify_recover(session, CKM_RSA_PKCS);
    test_rsa_verify_recover(session, CKM_RSA_X_509);
#endif
#endif
#if defined(HAVE_ECC) && !defined(NO_SHA256) && \
    (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES))
    test_ecdsa_p521(session);
#endif
#ifdef WOLFPKCS11_MLDSA
    test_mldsa(session);
#endif
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    test_hmac(session);
#endif
#if !defined(NO_AES) && defined(HAVE_AESCMAC)
    test_cmac(session);
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

    printf("=== wolfPKCS11 verify return code test ===\n");
    run_test();
    return pkcs11_test_summary();
}
