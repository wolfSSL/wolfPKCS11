/* multi_part_sign_test.c
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
 * Multi-part hash-and-sign (RSA PKCS #1 v1.5, RSA-PSS, ECDSA), AES-ECB and
 * in-place AES-CBC operations against their single-part results.
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

#define TEST_DIR "./store/multi_part_sign_test"

#define MSG_LEN     100
#define MAX_SIG_LEN 512

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_BYTE msg[MSG_LEN];

#if !defined(NO_RSA) || defined(HAVE_ECC)
/* Update sizes; 0 is Init then Final with no update, of the empty message. */
static const CK_ULONG splits[] = { 0, 1, 15, 16, 17, MSG_LEN };

#define SPLIT_CNT (sizeof(splits) / sizeof(*splits))

static CK_ULONG msg_len(CK_ULONG split)
{
    return split == 0 ? 0 : MSG_LEN;
}

/* Sign with C_SignUpdate in split-sized parts, querying the length first. */
static CK_RV sign_multi(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                        CK_OBJECT_HANDLE priv, CK_ULONG split, CK_BYTE* sig,
                        CK_ULONG* sigLen)
{
    CK_RV rv;
    CK_ULONG off;
    CK_ULONG len = msg_len(split);
    CK_ULONG need = 0;

    rv = funcList->C_SignInit(session, mech, priv);
    for (off = 0; rv == CKR_OK && off < len; off += split) {
        rv = funcList->C_SignUpdate(session, msg + off,
                                    (len - off < split) ? len - off : split);
    }
    if (rv == CKR_OK)
        rv = funcList->C_SignFinal(session, NULL, &need);
    if (rv == CKR_OK && need > *sigLen)
        rv = CKR_BUFFER_TOO_SMALL;
    if (rv == CKR_OK)
        rv = funcList->C_SignFinal(session, sig, sigLen);
    return rv;
}

static CK_RV verify_multi(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                          CK_OBJECT_HANDLE pub, CK_ULONG split, CK_BYTE* sig,
                          CK_ULONG sigLen)
{
    CK_RV rv;
    CK_ULONG off;
    CK_ULONG len = msg_len(split);

    rv = funcList->C_VerifyInit(session, mech, pub);
    for (off = 0; rv == CKR_OK && off < len; off += split) {
        rv = funcList->C_VerifyUpdate(session, msg + off,
                                      (len - off < split) ? len - off : split);
    }
    if (rv == CKR_OK)
        rv = funcList->C_VerifyFinal(session, sig, sigLen);
    return rv;
}

static CK_RV sign_single(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                         CK_OBJECT_HANDLE priv, CK_ULONG len, CK_BYTE* sig,
                         CK_ULONG* sigLen)
{
    CK_RV rv;

    rv = funcList->C_SignInit(session, mech, priv);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, msg, len, sig, sigLen);
    return rv;
}

static CK_RV verify_single(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                           CK_OBJECT_HANDLE pub, CK_ULONG len, CK_BYTE* sig,
                           CK_ULONG sigLen)
{
    CK_RV rv;

    rv = funcList->C_VerifyInit(session, mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_Verify(session, msg, len, sig, sigLen);
    return rv;
}

/* Multi-part results match single-part ones for every split. */
static void check_mech(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                       CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub,
                       int deterministic, const char* name)
{
    CK_RV rv;
    CK_BYTE sigM[MAX_SIG_LEN];
    CK_BYTE sigS[MAX_SIG_LEN];
    CK_ULONG sigMLen;
    CK_ULONG sigSLen;
    CK_ULONG short_len;
    char what[128];
    size_t i;

    for (i = 0; i < SPLIT_CNT; i++) {
        sigMLen = sizeof(sigM);
        rv = sign_multi(session, mech, priv, splits[i], sigM, &sigMLen);
        snprintf(what, sizeof(what), "%s: sign in %lu-byte parts", name,
                 (unsigned long)splits[i]);
        CHECK_RV(rv, what, CKR_OK);
        if (rv != CKR_OK)
            continue;

        rv = verify_single(session, mech, pub, msg_len(splits[i]), sigM,
                           sigMLen);
        snprintf(what, sizeof(what), "%s: C_Verify of %lu-byte part signature",
                 name, (unsigned long)splits[i]);
        CHECK_RV(rv, what, CKR_OK);

        rv = verify_multi(session, mech, pub, splits[i], sigM, sigMLen);
        snprintf(what, sizeof(what), "%s: verify in %lu-byte parts", name,
                 (unsigned long)splits[i]);
        CHECK_RV(rv, what, CKR_OK);

        sigSLen = sizeof(sigS);
        rv = sign_single(session, mech, priv, msg_len(splits[i]), sigS,
                         &sigSLen);
        snprintf(what, sizeof(what), "%s: C_Sign of %lu bytes", name,
                 (unsigned long)msg_len(splits[i]));
        CHECK_RV(rv, what, CKR_OK);
        if (rv != CKR_OK)
            continue;

        rv = verify_multi(session, mech, pub, splits[i], sigS, sigSLen);
        snprintf(what, sizeof(what), "%s: verify C_Sign output in %lu-byte "
                 "parts", name, (unsigned long)splits[i]);
        CHECK_RV(rv, what, CKR_OK);

        if (deterministic) {
            snprintf(what, sizeof(what), "%s: %lu-byte parts give the C_Sign "
                     "signature", name, (unsigned long)splits[i]);
            CHECK_TRUE(sigMLen == sigSLen &&
                       XMEMCMP(sigM, sigS, sigSLen) == 0, what);
        }
    }

    sigMLen = sizeof(sigM);
    rv = sign_multi(session, mech, priv, 16, sigM, &sigMLen);
    if (rv != CKR_OK)
        return;

    sigM[sigMLen / 2] ^= 0x01;
    rv = verify_multi(session, mech, pub, 16, sigM, sigMLen);
    snprintf(what, sizeof(what), "%s: C_VerifyFinal of a changed signature",
             name);
    CHECK_RV(rv, what, CKR_SIGNATURE_INVALID);
    rv = funcList->C_VerifyFinal(session, sigM, sigMLen);
    snprintf(what, sizeof(what), "%s: C_VerifyFinal ended the operation", name);
    CHECK_RV(rv, what, CKR_OPERATION_NOT_INITIALIZED);
    sigM[sigMLen / 2] ^= 0x01;

    rv = verify_multi(session, mech, pub, 16, sigM, sigMLen - 1);
    snprintf(what, sizeof(what), "%s: C_VerifyFinal of a short signature",
             name);
    CHECK_RV(rv, what, CKR_SIGNATURE_LEN_RANGE);
    rv = funcList->C_VerifyFinal(session, sigM, sigMLen);
    snprintf(what, sizeof(what), "%s: short signature ended the operation",
             name);
    CHECK_RV(rv, what, CKR_OPERATION_NOT_INITIALIZED);

    /* A short buffer leaves the hash running for the retry. */
    rv = funcList->C_SignInit(session, mech, priv);
    if (rv == CKR_OK)
        rv = funcList->C_SignUpdate(session, msg, MSG_LEN);
    if (rv == CKR_OK) {
        short_len = 1;
        rv = funcList->C_SignFinal(session, sigS, &short_len);
        snprintf(what, sizeof(what), "%s: C_SignFinal into a 1-byte buffer",
                 name);
        CHECK_RV(rv, what, CKR_BUFFER_TOO_SMALL);
        snprintf(what, sizeof(what), "%s: C_SignFinal reports the length",
                 name);
        CHECK_TRUE(short_len >= sigMLen, what);
    }
    if (rv == CKR_BUFFER_TOO_SMALL) {
        sigSLen = sizeof(sigS);
        rv = funcList->C_SignFinal(session, sigS, &sigSLen);
        snprintf(what, sizeof(what), "%s: C_SignFinal retry", name);
        CHECK_RV(rv, what, CKR_OK);
        if (rv == CKR_OK) {
            rv = verify_single(session, mech, pub, MSG_LEN, sigS, sigSLen);
            snprintf(what, sizeof(what), "%s: retried signature verifies",
                     name);
            CHECK_RV(rv, what, CKR_OK);
        }
    }

    rv = funcList->C_SignInit(session, mech, priv);
    if (rv == CKR_OK)
        rv = funcList->C_SignUpdate(session, msg, MSG_LEN);
    if (rv == CKR_OK) {
        sigSLen = sizeof(sigS);
        rv = funcList->C_Sign(session, msg, MSG_LEN, sigS, &sigSLen);
        snprintf(what, sizeof(what), "%s: C_Sign after C_SignUpdate", name);
        CHECK_RV(rv, what, CKR_FUNCTION_FAILED);
        rv = funcList->C_SignFinal(session, sigS, &sigSLen);
        snprintf(what, sizeof(what), "%s: C_Sign ended the operation", name);
        CHECK_RV(rv, what, CKR_OPERATION_NOT_INITIALIZED);
    }

    rv = funcList->C_VerifyInit(session, mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_VerifyUpdate(session, msg, MSG_LEN);
    if (rv == CKR_OK) {
        rv = funcList->C_Verify(session, msg, MSG_LEN, sigM, sigMLen);
        snprintf(what, sizeof(what), "%s: C_Verify after C_VerifyUpdate",
                 name);
        CHECK_RV(rv, what, CKR_FUNCTION_FAILED);
        rv = funcList->C_VerifyFinal(session, sigM, sigMLen);
        snprintf(what, sizeof(what), "%s: C_Verify ended the operation", name);
        CHECK_RV(rv, what, CKR_OPERATION_NOT_INITIALIZED);
    }
}

/* The single-part-only raw mechanisms refuse the update calls. */
static void check_raw(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                      CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub,
                      const char* name)
{
    CK_RV rv;
    CK_BYTE sig[MAX_SIG_LEN];
    CK_ULONG sigLen = sizeof(sig);
    char what[128];

    XMEMSET(sig, 0, sizeof(sig));
    rv = funcList->C_SignInit(session, mech, priv);
    if (rv == CKR_OK)
        rv = funcList->C_SignUpdate(session, msg, 32);
    snprintf(what, sizeof(what), "%s: C_SignUpdate", name);
    CHECK_RV(rv, what, CKR_MECHANISM_INVALID);
    rv = funcList->C_SignFinal(session, sig, &sigLen);
    snprintf(what, sizeof(what), "%s: C_SignUpdate ended the operation", name);
    CHECK_RV(rv, what, CKR_OPERATION_NOT_INITIALIZED);

    rv = funcList->C_VerifyInit(session, mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_VerifyUpdate(session, msg, 32);
    snprintf(what, sizeof(what), "%s: C_VerifyUpdate", name);
    CHECK_RV(rv, what, CKR_MECHANISM_INVALID);
    rv = funcList->C_VerifyFinal(session, sig, sizeof(sig));
    snprintf(what, sizeof(what), "%s: C_VerifyUpdate ended the operation",
             name);
    CHECK_RV(rv, what, CKR_OPERATION_NOT_INITIALIZED);
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

/* An abandoned multi-part sign leaves nothing behind for the next one. */
static void check_abandoned(CK_SESSION_HANDLE session, CK_MECHANISM* first,
                            CK_MECHANISM* second, CK_OBJECT_HANDLE priv,
                            CK_OBJECT_HANDLE pub)
{
    CK_RV rv;
    CK_BYTE sigM[MAX_SIG_LEN];
    CK_BYTE sigS[MAX_SIG_LEN];
    CK_ULONG sigMLen = sizeof(sigM);
    CK_ULONG sigSLen = sizeof(sigS);

    rv = sign_single(session, second, priv, MSG_LEN, sigS, &sigSLen);
    CHECK_RV(rv, "C_Sign reference signature", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_SignInit(session, first, priv);
    if (rv == CKR_OK)
        rv = funcList->C_SignUpdate(session, msg, 10);
    CHECK_RV(rv, "C_SignUpdate left running", CKR_OK);
    rv = verify_single(session, second, pub, MSG_LEN, sigS, sigSLen);
    CHECK_RV(rv, "C_Verify after an abandoned C_SignUpdate", CKR_OK);
    rv = sign_multi(session, second, priv, 16, sigM, &sigMLen);
    CHECK_RV(rv, "multi-part sign after an abandoned C_SignUpdate", CKR_OK);
    CHECK_TRUE(sigMLen == sigSLen && XMEMCMP(sigM, sigS, sigSLen) == 0,
               "multi-part sign after an abandoned one gives the C_Sign "
               "signature");

    rv = funcList->C_VerifyInit(session, first, pub);
    if (rv == CKR_OK)
        rv = funcList->C_VerifyUpdate(session, msg, 10);
    CHECK_RV(rv, "C_VerifyUpdate left running", CKR_OK);
    sigMLen = sizeof(sigM);
    rv = sign_single(session, second, priv, MSG_LEN, sigM, &sigMLen);
    CHECK_RV(rv, "C_Sign after an abandoned C_VerifyUpdate", CKR_OK);
    rv = verify_multi(session, second, pub, 16, sigS, sigSLen);
    CHECK_RV(rv, "multi-part verify after an abandoned one", CKR_OK);

#ifdef WOLFPKCS11_PKCS11_V3_0
    rv = funcList->C_VerifyInit(session, first, pub);
    if (rv == CKR_OK)
        rv = funcList->C_VerifyUpdate(session, msg, 10);
    if (rv == CKR_OK)
        rv = funcList->C_VerifyInit(session, NULL, pub);
    CHECK_RV(rv, "C_VerifyInit(NULL) after C_VerifyUpdate", CKR_OK);
    rv = verify_multi(session, second, pub, 16, sigS, sigSLen);
    CHECK_RV(rv, "multi-part verify after a cancelled one", CKR_OK);

    rv = funcList->C_SignInit(session, first, priv);
    if (rv == CKR_OK)
        rv = funcList->C_SignUpdate(session, msg, 10);
    if (rv == CKR_OK)
        rv = funcList->C_SignInit(session, NULL, priv);
    CHECK_RV(rv, "C_SignInit(NULL) after C_SignUpdate", CKR_OK);
    sigMLen = sizeof(sigM);
    rv = sign_multi(session, second, priv, 16, sigM, &sigMLen);
    CHECK_RV(rv, "multi-part sign after a cancelled one", CKR_OK);
    CHECK_TRUE(sigMLen == sigSLen && XMEMCMP(sigM, sigS, sigSLen) == 0,
               "multi-part sign after a cancelled one gives the C_Sign "
               "signature");
#endif
}

static void test_rsa(CK_SESSION_HANDLE session)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_MECHANISM first;
    static const struct {
        CK_MECHANISM_TYPE mech;
        const char* name;
    } pkcs[] = {
#ifndef NO_SHA
        { CKM_SHA1_RSA_PKCS,   "CKM_SHA1_RSA_PKCS"   },
#endif
#ifdef WOLFSSL_SHA224
        { CKM_SHA224_RSA_PKCS, "CKM_SHA224_RSA_PKCS" },
#endif
#ifndef NO_SHA256
        { CKM_SHA256_RSA_PKCS, "CKM_SHA256_RSA_PKCS" },
#endif
#ifdef WOLFSSL_SHA384
        { CKM_SHA384_RSA_PKCS, "CKM_SHA384_RSA_PKCS" },
#endif
#ifdef WOLFSSL_SHA512
        { CKM_SHA512_RSA_PKCS, "CKM_SHA512_RSA_PKCS" },
#endif
    };
#ifdef WC_RSA_PSS
    static const struct {
        CK_MECHANISM_TYPE mech;
        CK_MECHANISM_TYPE hash;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_ULONG sLen;
        const char* name;
    } pss[] = {
#ifndef NO_SHA
        { CKM_SHA1_RSA_PKCS_PSS,   CKM_SHA1,   CKG_MGF1_SHA1,   20,
          "CKM_SHA1_RSA_PKCS_PSS"   },
#endif
#ifdef WOLFSSL_SHA224
        { CKM_SHA224_RSA_PKCS_PSS, CKM_SHA224, CKG_MGF1_SHA224, 28,
          "CKM_SHA224_RSA_PKCS_PSS" },
#endif
#ifndef NO_SHA256
        { CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, CKG_MGF1_SHA256, 32,
          "CKM_SHA256_RSA_PKCS_PSS" },
#endif
#ifdef WOLFSSL_SHA384
        { CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384, CKG_MGF1_SHA384, 48,
          "CKM_SHA384_RSA_PKCS_PSS" },
#endif
#ifdef WOLFSSL_SHA512
        { CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512, CKG_MGF1_SHA512, 64,
          "CKM_SHA512_RSA_PKCS_PSS" },
#endif
    };
    CK_RSA_PKCS_PSS_PARAMS params;
#endif
    size_t i;

    printf("--- RSA ---\n");
    if (create_rsa_keys(session, &priv, &pub) != CKR_OK)
        return;

    XMEMSET(&mech, 0, sizeof(mech));
    for (i = 0; i < sizeof(pkcs) / sizeof(*pkcs); i++) {
        mech.mechanism = pkcs[i].mech;
        check_mech(session, &mech, priv, pub, 1, pkcs[i].name);
    }
    first = mech;
    first.mechanism = pkcs[0].mech;
    check_abandoned(session, &first, &mech, priv, pub);

    first.mechanism = CKM_RSA_PKCS;
    check_raw(session, &first, priv, pub, "CKM_RSA_PKCS");
#if defined(WC_RSA_PSS) && !defined(NO_SHA256)
    params.hashAlg = CKM_SHA256;
    params.mgf = CKG_MGF1_SHA256;
    params.sLen = 32;
    first.mechanism = CKM_RSA_PKCS_PSS;
    first.pParameter = &params;
    first.ulParameterLen = sizeof(params);
    check_raw(session, &first, priv, pub, "CKM_RSA_PKCS_PSS");
#endif
#ifdef WC_RSA_PSS
    for (i = 0; i < sizeof(pss) / sizeof(*pss); i++) {
        params.hashAlg = pss[i].hash;
        params.mgf = pss[i].mgf;
        params.sLen = pss[i].sLen;
        mech.mechanism = pss[i].mech;
        mech.pParameter = &params;
        mech.ulParameterLen = sizeof(params);
        check_mech(session, &mech, priv, pub, 0, pss[i].name);
    }
#endif

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif

#ifdef HAVE_ECC
static void test_ecdsa(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE ecType = CKK_EC;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,     &privClass,      sizeof(privClass)       },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_SIGN,      &ckTrue,         sizeof(ckTrue)          },
        { CKA_PRIVATE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,     ecc_p256_priv,   sizeof(ecc_p256_priv)   },
    };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_CLASS,     &pubClass,       sizeof(pubClass)        },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)          },
        { CKA_VERIFY,    &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_EC_POINT,  ecc_p256_pub,    sizeof(ecc_p256_pub)    },
    };
    CK_MECHANISM mech;
    static const struct {
        CK_MECHANISM_TYPE mech;
        const char* name;
    } mechs[] = {
#ifndef NO_SHA
        { CKM_ECDSA_SHA1,   "CKM_ECDSA_SHA1"   },
#endif
#ifdef WOLFSSL_SHA224
        { CKM_ECDSA_SHA224, "CKM_ECDSA_SHA224" },
#endif
#ifndef NO_SHA256
        { CKM_ECDSA_SHA256, "CKM_ECDSA_SHA256" },
#endif
#ifdef WOLFSSL_SHA384
        { CKM_ECDSA_SHA384, "CKM_ECDSA_SHA384" },
#endif
#ifdef WOLFSSL_SHA512
        { CKM_ECDSA_SHA512, "CKM_ECDSA_SHA512" },
#endif
    };
    size_t i;

    printf("--- ECDSA ---\n");
    rv = funcList->C_CreateObject(session, privTmpl,
                                  sizeof(privTmpl) / sizeof(*privTmpl), &priv);
    CHECK_RV(rv, "C_CreateObject(EC private key)", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, pubTmpl,
                                      sizeof(pubTmpl) / sizeof(*pubTmpl), &pub);
        CHECK_RV(rv, "C_CreateObject(EC public key)", CKR_OK);
    }
    if (rv != CKR_OK)
        return;

    XMEMSET(&mech, 0, sizeof(mech));
    for (i = 0; i < sizeof(mechs) / sizeof(*mechs); i++) {
        mech.mechanism = mechs[i].mech;
        check_mech(session, &mech, priv, pub, 0, mechs[i].name);
    }
    mech.mechanism = CKM_ECDSA;
    check_raw(session, &mech, priv, pub, "CKM_ECDSA");

    funcList->C_DestroyObject(session, priv);
    funcList->C_DestroyObject(session, pub);
}
#endif

#if !defined(NO_AES) && (defined(HAVE_AESECB) || defined(HAVE_AES_CBC))
/* In place, with a block cached from the part before. */
static void check_in_place(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                           CK_OBJECT_HANDLE key, int enc, CK_BYTE* in,
                           const CK_ULONG* parts, size_t partCnt,
                           CK_BYTE* expected, CK_ULONG expectedLen,
                           const char* name)
{
    CK_RV rv;
    CK_BYTE work[MSG_LEN];
    CK_BYTE out[MSG_LEN];
    CK_ULONG workLen;
    CK_ULONG total = 0;
    CK_ULONG off = 0;
    char what[96];
    size_t i;

    if (enc)
        rv = funcList->C_EncryptInit(session, mech, key);
    else
        rv = funcList->C_DecryptInit(session, mech, key);
    for (i = 0; rv == CKR_OK && i < partCnt; i++) {
        XMEMCPY(work, in + off, parts[i]);
        workLen = sizeof(work);
        if (enc)
            rv = funcList->C_EncryptUpdate(session, work, parts[i], work,
                                           &workLen);
        else
            rv = funcList->C_DecryptUpdate(session, work, parts[i], work,
                                           &workLen);
        if (rv == CKR_OK) {
            XMEMCPY(out + total, work, workLen);
            total += workLen;
            off += parts[i];
        }
    }
    if (rv == CKR_OK) {
        workLen = sizeof(work);
        if (enc)
            rv = funcList->C_EncryptFinal(session, work, &workLen);
        else
            rv = funcList->C_DecryptFinal(session, work, &workLen);
        if (rv == CKR_OK) {
            XMEMCPY(out + total, work, workLen);
            total += workLen;
        }
    }
    snprintf(what, sizeof(what), "%s: %s in place", name,
             enc ? "encrypt" : "decrypt");
    CHECK_RV(rv, what, CKR_OK);
    snprintf(what, sizeof(what), "%s: %s in place gives the one-shot result",
             name, enc ? "encrypt" : "decrypt");
    CHECK_TRUE(total == expectedLen &&
               XMEMCMP(out, expected, expectedLen) == 0, what);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESECB)
#define ECB_LEN 64
#define ECB_PARTS 3

/* Run C_EncryptUpdate or C_DecryptUpdate over in, split-sized parts. */
static CK_RV ecb_multi(CK_SESSION_HANDLE session, int enc, CK_BYTE* in,
                       CK_ULONG inLen, CK_ULONG split, CK_BYTE* out,
                       CK_ULONG* outLen)
{
    CK_RV rv = CKR_OK;
    CK_ULONG off;
    CK_ULONG part;
    CK_ULONG need;
    CK_ULONG got;
    CK_ULONG total = 0;

    for (off = 0; rv == CKR_OK && off < inLen; off += part) {
        part = (inLen - off < split) ? inLen - off : split;
        need = 0;
        if (enc)
            rv = funcList->C_EncryptUpdate(session, in + off, part, NULL,
                                           &need);
        else
            rv = funcList->C_DecryptUpdate(session, in + off, part, NULL,
                                           &need);
        if (rv == CKR_OK && need > *outLen - total)
            rv = CKR_BUFFER_TOO_SMALL;
        got = *outLen - total;
        if (rv == CKR_OK && enc)
            rv = funcList->C_EncryptUpdate(session, in + off, part,
                                           out + total, &got);
        else if (rv == CKR_OK)
            rv = funcList->C_DecryptUpdate(session, in + off, part,
                                           out + total, &got);
        if (rv == CKR_OK && got != need)
            rv = CKR_GENERAL_ERROR;
        if (rv == CKR_OK)
            total += got;
    }
    if (rv == CKR_OK) {
        got = 0;
        if (enc)
            rv = funcList->C_EncryptFinal(session, out + total, &got);
        else
            rv = funcList->C_DecryptFinal(session, out + total, &got);
        total += got;
    }
    *outLen = total;
    return rv;
}

static void test_aes_ecb(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_MECHANISM mech = { CKM_AES_ECB, NULL, 0 };
    static const CK_ULONG ecbSplits[] = { 1, 7, 15, 16, 17, ECB_LEN };
    static const CK_ULONG ecbParts[] = { 5, 30, 29 };
    CK_BYTE ref[ECB_LEN];
    CK_BYTE out[ECB_LEN];
    CK_ULONG refLen = sizeof(ref);
    CK_ULONG outLen;
    char what[96];
    size_t i;

    printf("--- AES-ECB ---\n");
    rv = funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
                                  &key);
    CHECK_RV(rv, "C_CreateObject(AES key)", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = funcList->C_EncryptInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, msg, ECB_LEN, ref, &refLen);
    CHECK_RV(rv, "C_Encrypt", CKR_OK);
    if (rv != CKR_OK)
        goto done;

    for (i = 0; i < sizeof(ecbSplits) / sizeof(*ecbSplits); i++) {
        outLen = sizeof(out);
        rv = funcList->C_EncryptInit(session, &mech, key);
        if (rv == CKR_OK)
            rv = ecb_multi(session, 1, msg, ECB_LEN, ecbSplits[i], out,
                           &outLen);
        snprintf(what, sizeof(what), "encrypt in %lu-byte parts",
                 (unsigned long)ecbSplits[i]);
        CHECK_RV(rv, what, CKR_OK);
        snprintf(what, sizeof(what), "%lu-byte parts give the C_Encrypt "
                 "output", (unsigned long)ecbSplits[i]);
        CHECK_TRUE(outLen == refLen && XMEMCMP(out, ref, refLen) == 0, what);

        outLen = sizeof(out);
        rv = funcList->C_DecryptInit(session, &mech, key);
        if (rv == CKR_OK)
            rv = ecb_multi(session, 0, ref, refLen, ecbSplits[i], out,
                           &outLen);
        snprintf(what, sizeof(what), "decrypt in %lu-byte parts",
                 (unsigned long)ecbSplits[i]);
        CHECK_RV(rv, what, CKR_OK);
        snprintf(what, sizeof(what), "%lu-byte parts give the plaintext",
                 (unsigned long)ecbSplits[i]);
        CHECK_TRUE(outLen == ECB_LEN && XMEMCMP(out, msg, ECB_LEN) == 0, what);
    }

    outLen = sizeof(out);
    rv = funcList->C_EncryptInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = ecb_multi(session, 1, msg, 20, 7, out, &outLen);
    CHECK_RV(rv, "C_EncryptFinal with 4 bytes left", CKR_DATA_LEN_RANGE);
    rv = funcList->C_EncryptFinal(session, out, &outLen);
    CHECK_RV(rv, "C_EncryptFinal ended the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    outLen = sizeof(out);
    rv = funcList->C_DecryptInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = ecb_multi(session, 0, ref, 20, 7, out, &outLen);
    CHECK_RV(rv, "C_DecryptFinal with 4 bytes left",
             CKR_ENCRYPTED_DATA_LEN_RANGE);
    rv = funcList->C_DecryptFinal(session, out, &outLen);
    CHECK_RV(rv, "C_DecryptFinal ended the operation",
             CKR_OPERATION_NOT_INITIALIZED);

    /* A short buffer leaves the cached data in place for the retry. */
    rv = funcList->C_EncryptInit(session, &mech, key);
    CHECK_RV(rv, "C_EncryptInit", CKR_OK);
    if (rv == CKR_OK) {
        outLen = 16;
        rv = funcList->C_EncryptUpdate(session, msg, 5, out, &outLen);
        CHECK_RV(rv, "C_EncryptUpdate of 5 bytes", CKR_OK);
        CHECK_TRUE(outLen == 0, "5 bytes are cached");
        outLen = 16;
        rv = funcList->C_EncryptUpdate(session, msg + 5, 30, out, &outLen);
        CHECK_RV(rv, "C_EncryptUpdate into a short buffer",
                 CKR_BUFFER_TOO_SMALL);
        CHECK_TRUE(outLen == 32, "C_EncryptUpdate reports 32 bytes");
        outLen = sizeof(out);
        rv = funcList->C_EncryptUpdate(session, msg + 5, 30, out, &outLen);
        CHECK_RV(rv, "C_EncryptUpdate retry", CKR_OK);
        CHECK_TRUE(outLen == 32 && XMEMCMP(out, ref, 32) == 0,
                   "retry gives the C_Encrypt output");
        outLen = sizeof(out);
        rv = funcList->C_EncryptUpdate(session, msg + 35, 29, out, &outLen);
        CHECK_RV(rv, "C_EncryptUpdate of the rest", CKR_OK);
        CHECK_TRUE(outLen == 32 && XMEMCMP(out, ref + 32, 32) == 0,
                   "rest gives the C_Encrypt output");
        outLen = sizeof(out);
        rv = funcList->C_EncryptFinal(session, out, &outLen);
        CHECK_RV(rv, "C_EncryptFinal", CKR_OK);
        CHECK_TRUE(outLen == 0, "C_EncryptFinal returns no data");
    }

    check_in_place(session, &mech, key, 1, msg, ecbParts, ECB_PARTS, ref,
                   refLen, "CKM_AES_ECB");
    check_in_place(session, &mech, key, 0, ref, ecbParts, ECB_PARTS, msg,
                   ECB_LEN, "CKM_AES_ECB");

done:
    funcList->C_DestroyObject(session, key);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
static void test_aes_cbc_in_place(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_BYTE iv[16];
    CK_MECHANISM mech;
    static const CK_ULONG encParts[] = { 5, 30, 29 };
    static const CK_ULONG padDecParts[] = { 5, 30, 45 };
    CK_BYTE ref[96];
    CK_ULONG refLen;
    size_t i;

    printf("--- AES-CBC in place ---\n");
    rv = funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
                                  &key);
    CHECK_RV(rv, "C_CreateObject(AES key)", CKR_OK);
    if (rv != CKR_OK)
        return;

    XMEMSET(iv, 0x3C, sizeof(iv));
    mech.pParameter = iv;
    mech.ulParameterLen = sizeof(iv);
    for (i = 0; i < 2; i++) {
        mech.mechanism = (i == 0) ? CKM_AES_CBC : CKM_AES_CBC_PAD;
        refLen = sizeof(ref);
        rv = funcList->C_EncryptInit(session, &mech, key);
        if (rv == CKR_OK)
            rv = funcList->C_Encrypt(session, msg, 64, ref, &refLen);
        CHECK_RV(rv, "C_Encrypt", CKR_OK);
        if (rv != CKR_OK)
            break;

        check_in_place(session, &mech, key, 1, msg, encParts, 3, ref, refLen,
                       i == 0 ? "CKM_AES_CBC" : "CKM_AES_CBC_PAD");
        check_in_place(session, &mech, key, 0, ref,
                       i == 0 ? encParts : padDecParts, 3, msg, 64,
                       i == 0 ? "CKM_AES_CBC" : "CKM_AES_CBC_PAD");
    }

    funcList->C_DestroyObject(session, key);
}
#endif

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    size_t i;

    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (CK_BYTE)i;

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
#endif
#ifdef HAVE_ECC
    test_ecdsa(session);
#endif
#if !defined(NO_AES) && defined(HAVE_AESECB)
    test_aes_ecb(session);
#endif
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    test_aes_cbc_in_place(session);
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

    printf("=== wolfPKCS11 multi-part sign and AES-ECB test ===\n");
    run_test();
    return pkcs11_test_summary();
}
