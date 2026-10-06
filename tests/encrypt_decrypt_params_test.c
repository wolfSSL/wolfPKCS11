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
    if (rv == CKR_OK) {
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
        test_cbc_pad_encrypt_final_len(session);
#endif
#if !defined(NO_RSA) && !defined(WC_NO_RSA_OAEP)
        test_oaep_source_ptr_len(session);
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
