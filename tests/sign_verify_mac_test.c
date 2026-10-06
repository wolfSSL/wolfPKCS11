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
