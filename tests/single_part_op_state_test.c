/* single_part_op_state_test.c
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
 * A call refused for a missing operation must leave the active operation
 * alone, and a single-part call must not finish a multi-part operation.
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

#define TEST_DIR "./store/single_part_op_state_test"

#if !defined(NO_AES) && !defined(NO_AES_CBC) && !defined(NO_HMAC) && \
    !defined(NO_SHA256)

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static byte iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static byte hmacKeyData[32] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static CK_RV create_aes_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &cls,        sizeof(cls)         },
        { CKA_KEY_TYPE, &type,       sizeof(type)        },
        { CKA_VALUE,    aes_128_key, sizeof(aes_128_key) },
        { CKA_ENCRYPT,  &ckTrue,     sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,     sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,    sizeof(ckFalse)     },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}

static CK_RV create_hmac_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &cls,        sizeof(cls)         },
        { CKA_KEY_TYPE, &type,       sizeof(type)        },
        { CKA_VALUE,    hmacKeyData, sizeof(hmacKeyData) },
        { CKA_SIGN,     &ckTrue,     sizeof(ckTrue)      },
        { CKA_VERIFY,   &ckTrue,     sizeof(ckTrue)      },
        { CKA_EXTRACTABLE, &ckTrue,  sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,    sizeof(ckFalse)     },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}

static void set_mech(CK_MECHANISM* mech, CK_MECHANISM_TYPE type)
{
    XMEMSET(mech, 0, sizeof(*mech));
    mech->mechanism = type;
    if (type == CKM_AES_CBC || type == CKM_AES_CBC_PAD) {
        mech->pParameter = iv;
        mech->ulParameterLen = sizeof(iv);
    }
}

static void check_no_other_op(CK_SESSION_HANDLE session, int notEncrypt,
                              int notDecrypt, int notSign, const char* desc)
{
    CK_RV rv;
    byte data[16];
    byte out[64];
    CK_ULONG outSz;

    XMEMSET(data, 0x5a, sizeof(data));
    printf("  %s\n", desc);
    if (notEncrypt) {
        outSz = sizeof(out);
        rv = funcList->C_Encrypt(session, data, sizeof(data), out, &outSz);
        CHECK_RV(rv, "C_Encrypt", CKR_OPERATION_NOT_INITIALIZED);
        outSz = sizeof(out);
        rv = funcList->C_EncryptUpdate(session, data, sizeof(data), out,
                                       &outSz);
        CHECK_RV(rv, "C_EncryptUpdate", CKR_OPERATION_NOT_INITIALIZED);
        outSz = sizeof(out);
        rv = funcList->C_EncryptFinal(session, out, &outSz);
        CHECK_RV(rv, "C_EncryptFinal", CKR_OPERATION_NOT_INITIALIZED);
    }
    if (notDecrypt) {
        outSz = sizeof(out);
        rv = funcList->C_Decrypt(session, data, sizeof(data), out, &outSz);
        CHECK_RV(rv, "C_Decrypt", CKR_OPERATION_NOT_INITIALIZED);
        outSz = sizeof(out);
        rv = funcList->C_DecryptUpdate(session, data, sizeof(data), out,
                                       &outSz);
        CHECK_RV(rv, "C_DecryptUpdate", CKR_OPERATION_NOT_INITIALIZED);
        outSz = sizeof(out);
        rv = funcList->C_DecryptFinal(session, out, &outSz);
        CHECK_RV(rv, "C_DecryptFinal", CKR_OPERATION_NOT_INITIALIZED);
    }
    if (notSign) {
        outSz = sizeof(out);
        rv = funcList->C_Sign(session, data, sizeof(data), out, &outSz);
        CHECK_RV(rv, "C_Sign", CKR_OPERATION_NOT_INITIALIZED);
        rv = funcList->C_SignUpdate(session, data, sizeof(data));
        CHECK_RV(rv, "C_SignUpdate", CKR_OPERATION_NOT_INITIALIZED);
        outSz = sizeof(out);
        rv = funcList->C_SignFinal(session, out, &outSz);
        CHECK_RV(rv, "C_SignFinal", CKR_OPERATION_NOT_INITIALIZED);
    }
    rv = funcList->C_Verify(session, data, sizeof(data), out, 32);
    CHECK_RV(rv, "C_Verify", CKR_OPERATION_NOT_INITIALIZED);
    rv = funcList->C_VerifyUpdate(session, data, sizeof(data));
    CHECK_RV(rv, "C_VerifyUpdate", CKR_OPERATION_NOT_INITIALIZED);
    rv = funcList->C_VerifyFinal(session, out, 32);
    CHECK_RV(rv, "C_VerifyFinal", CKR_OPERATION_NOT_INITIALIZED);
#if !defined(NO_RSA) && defined(WC_RSA_DIRECT)
    outSz = sizeof(out);
    rv = funcList->C_VerifyRecover(session, out, 32, data, &outSz);
    CHECK_RV(rv, "C_VerifyRecover", CKR_OPERATION_NOT_INITIALIZED);
#endif
}

#if !defined(NO_RSA) && defined(WC_RSA_DIRECT)
static void test_stray_calls_verify_recover(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
    CK_KEY_TYPE type = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,           &cls,             sizeof(cls)              },
        { CKA_KEY_TYPE,        &type,            sizeof(type)             },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
        { CKA_VERIFY_RECOVER,  &ckTrue,          sizeof(ckTrue)           },
    };
    CK_OBJECT_HANDLE rsaKey = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    byte sig[256];
    byte out[256];
    CK_ULONG outSz;

    XMEMSET(sig, 0x5a, sizeof(sig));
    sig[0] = 0x00;
    rv = funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
                                  &rsaKey);
    CHECK_RV(rv, "C_CreateObject(RSA public key)", CKR_OK);
    if (rv != CKR_OK)
        return;

    set_mech(&mech, CKM_RSA_X_509);
    rv = funcList->C_VerifyRecoverInit(session, &mech, rsaKey);
    CHECK_RV(rv, "C_VerifyRecoverInit(RSA_X_509)", CKR_OK);
    rv = funcList->C_Verify(session, sig, sizeof(sig), sig, sizeof(sig));
    CHECK_RV(rv, "C_Verify during verify-recover",
             CKR_OPERATION_NOT_INITIALIZED);
    rv = funcList->C_VerifyUpdate(session, sig, sizeof(sig));
    CHECK_RV(rv, "C_VerifyUpdate during verify-recover",
             CKR_OPERATION_NOT_INITIALIZED);
    rv = funcList->C_VerifyFinal(session, sig, sizeof(sig));
    CHECK_RV(rv, "C_VerifyFinal during verify-recover",
             CKR_OPERATION_NOT_INITIALIZED);
    outSz = sizeof(out);
    rv = funcList->C_VerifyRecover(session, sig, sizeof(sig), out, &outSz);
    CHECK_RV(rv, "C_VerifyRecover after stray calls", CKR_OK);

    funcList->C_DestroyObject(session, rsaKey);
}
#endif

static void test_stray_calls(CK_SESSION_HANDLE session,
                             CK_OBJECT_HANDLE aesKey, CK_OBJECT_HANDLE hmacKey)
{
    CK_RV rv;
    CK_MECHANISM cbc;
    CK_MECHANISM hmac;
    byte data[16];
    byte out[64];
    CK_ULONG outSz;

    XMEMSET(data, 0x5a, sizeof(data));
    set_mech(&cbc, CKM_AES_CBC);
    set_mech(&hmac, CKM_SHA256_HMAC);

    rv = funcList->C_EncryptInit(session, &cbc, aesKey);
    CHECK_RV(rv, "C_EncryptInit(CBC)", CKR_OK);
    check_no_other_op(session, 0, 1, 1, "active encrypt");
    outSz = sizeof(out);
    rv = funcList->C_Encrypt(session, data, sizeof(data), out, &outSz);
    CHECK_RV(rv, "C_Encrypt after stray calls", CKR_OK);
    CHECK_TRUE(outSz == sizeof(data), "encrypt output is one block");

    rv = funcList->C_SignInit(session, &hmac, hmacKey);
    CHECK_RV(rv, "C_SignInit(HMAC)", CKR_OK);
    check_no_other_op(session, 1, 1, 0, "active sign");
    outSz = sizeof(out);
    rv = funcList->C_Sign(session, data, sizeof(data), out, &outSz);
    CHECK_RV(rv, "C_Sign after stray calls", CKR_OK);
    CHECK_TRUE(outSz == 32, "HMAC-SHA256 is 32 bytes");

    check_no_other_op(session, 1, 1, 1, "finished sign");
#if !defined(NO_RSA) && defined(WC_RSA_DIRECT)
    test_stray_calls_verify_recover(session);
#endif
}

static void test_restored_digest(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech;
    byte abc[] = { 'a', 'b', 'c' };
    byte def[] = { 'd', 'e', 'f' };
    byte abcdef[] = { 'a', 'b', 'c', 'd', 'e', 'f' };
    byte state[1024];
    byte want[32];
    byte out[64];
    CK_ULONG stateSz = sizeof(state);
    CK_ULONG outSz;

    set_mech(&mech, CKM_SHA256);
    rv = funcList->C_DigestInit(session, &mech);
    CHECK_RV(rv, "C_DigestInit(reference)", CKR_OK);
    outSz = sizeof(want);
    rv = funcList->C_Digest(session, abcdef, sizeof(abcdef), want, &outSz);
    CHECK_RV(rv, "C_Digest(reference)", CKR_OK);

    rv = funcList->C_DigestInit(session, &mech);
    CHECK_RV(rv, "C_DigestInit to save", CKR_OK);
    rv = funcList->C_DigestUpdate(session, abc, sizeof(abc));
    CHECK_RV(rv, "C_DigestUpdate before save", CKR_OK);
    rv = funcList->C_GetOperationState(session, state, &stateSz);
    CHECK_RV(rv, "C_GetOperationState", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_DigestFinal(session, out, &outSz);
    CHECK_RV(rv, "C_DigestFinal of saved operation", CKR_OK);

    rv = funcList->C_SetOperationState(session, state, stateSz, 0, 0);
    CHECK_RV(rv, "C_SetOperationState", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_Digest(session, def, sizeof(def), out, &outSz);
    CHECK_RV(rv, "C_Digest of restored state", CKR_FUNCTION_FAILED);

    rv = funcList->C_SetOperationState(session, state, stateSz - 1, 0, 0);
    CHECK_RV(rv, "C_SetOperationState without the update byte", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_Digest(session, def, sizeof(def), out, &outSz);
    CHECK_RV(rv, "C_Digest of state without the update byte",
             CKR_FUNCTION_FAILED);

    rv = funcList->C_SetOperationState(session, state, stateSz, 0, 0);
    CHECK_RV(rv, "C_SetOperationState again", CKR_OK);
    rv = funcList->C_DigestUpdate(session, def, sizeof(def));
    CHECK_RV(rv, "C_DigestUpdate of restored state", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_DigestFinal(session, out, &outSz);
    CHECK_RV(rv, "C_DigestFinal of restored state", CKR_OK);
    CHECK_TRUE(outSz == sizeof(want) && XMEMCMP(out, want, sizeof(want)) == 0,
               "restored state continues the saved digest");

    rv = funcList->C_DigestInit(session, &mech);
    CHECK_RV(rv, "C_DigestInit to save without update", CKR_OK);
    stateSz = sizeof(state);
    rv = funcList->C_GetOperationState(session, state, &stateSz);
    CHECK_RV(rv, "C_GetOperationState without update", CKR_OK);
    rv = funcList->C_SetOperationState(session, state, stateSz, 0, 0);
    CHECK_RV(rv, "C_SetOperationState without update", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_Digest(session, abcdef, sizeof(abcdef), out, &outSz);
    CHECK_RV(rv, "C_Digest of state saved without update", CKR_OK);
    CHECK_TRUE(outSz == sizeof(want) && XMEMCMP(out, want, sizeof(want)) == 0,
               "C_Digest of state saved without update is correct");
}

static void test_single_part_after_update(CK_SESSION_HANDLE session,
                                          CK_OBJECT_HANDLE aesKey,
                                          CK_OBJECT_HANDLE hmacKey)
{
    CK_RV rv;
    CK_MECHANISM mech;
    byte abc[] = { 'a', 'b', 'c' };
    byte def[] = { 'd', 'e', 'f' };
    byte block[16];
    byte out[64];
    byte mac[32];
    CK_ULONG outSz;

    XMEMSET(block, 0x5a, sizeof(block));

    set_mech(&mech, CKM_SHA256);
    rv = funcList->C_DigestInit(session, &mech);
    CHECK_RV(rv, "C_DigestInit", CKR_OK);
    rv = funcList->C_DigestUpdate(session, abc, sizeof(abc));
    CHECK_RV(rv, "C_DigestUpdate", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_Digest(session, def, sizeof(def), out, &outSz);
    CHECK_RV(rv, "C_Digest after update", CKR_FUNCTION_FAILED);
    outSz = sizeof(out);
    rv = funcList->C_DigestFinal(session, out, &outSz);
    CHECK_RV(rv, "C_DigestFinal after refused C_Digest",
             CKR_OPERATION_NOT_INITIALIZED);
    rv = funcList->C_DigestInit(session, &mech);
    CHECK_RV(rv, "C_DigestInit again", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_Digest(session, def, sizeof(def), out, &outSz);
    CHECK_RV(rv, "C_Digest without update", CKR_OK);

#ifndef WOLFPKCS11_NO_STORE
    rv = funcList->C_DigestInit(session, &mech);
    CHECK_RV(rv, "C_DigestInit for C_DigestKey", CKR_OK);
    rv = funcList->C_DigestKey(session, hmacKey);
    CHECK_RV(rv, "C_DigestKey", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_Digest(session, def, sizeof(def), out, &outSz);
    CHECK_RV(rv, "C_Digest after C_DigestKey", CKR_FUNCTION_FAILED);
    outSz = sizeof(out);
    rv = funcList->C_DigestFinal(session, out, &outSz);
    CHECK_RV(rv, "C_DigestFinal after refused C_Digest",
             CKR_OPERATION_NOT_INITIALIZED);
#endif

    test_restored_digest(session);

    set_mech(&mech, CKM_SHA256_HMAC);
    rv = funcList->C_SignInit(session, &mech, hmacKey);
    CHECK_RV(rv, "C_SignInit(HMAC)", CKR_OK);
    rv = funcList->C_SignUpdate(session, abc, sizeof(abc));
    CHECK_RV(rv, "C_SignUpdate", CKR_OK);
    outSz = sizeof(mac);
    rv = funcList->C_Sign(session, def, sizeof(def), mac, &outSz);
    CHECK_RV(rv, "C_Sign after update", CKR_FUNCTION_FAILED);
    outSz = sizeof(mac);
    rv = funcList->C_SignFinal(session, mac, &outSz);
    CHECK_RV(rv, "C_SignFinal after refused C_Sign",
             CKR_OPERATION_NOT_INITIALIZED);

    rv = funcList->C_SignInit(session, &mech, hmacKey);
    CHECK_RV(rv, "C_SignInit(HMAC) for MAC", CKR_OK);
    outSz = sizeof(mac);
    rv = funcList->C_Sign(session, def, sizeof(def), mac, &outSz);
    CHECK_RV(rv, "C_Sign without update", CKR_OK);
    rv = funcList->C_VerifyInit(session, &mech, hmacKey);
    CHECK_RV(rv, "C_VerifyInit(HMAC)", CKR_OK);
    rv = funcList->C_VerifyUpdate(session, abc, sizeof(abc));
    CHECK_RV(rv, "C_VerifyUpdate", CKR_OK);
    rv = funcList->C_Verify(session, def, sizeof(def), mac, sizeof(mac));
    CHECK_RV(rv, "C_Verify after update", CKR_FUNCTION_FAILED);
    rv = funcList->C_VerifyFinal(session, mac, sizeof(mac));
    CHECK_RV(rv, "C_VerifyFinal after refused C_Verify",
             CKR_OPERATION_NOT_INITIALIZED);

    set_mech(&mech, CKM_AES_CBC);
    rv = funcList->C_EncryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(CBC)", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_EncryptUpdate(session, block, sizeof(block), out, &outSz);
    CHECK_RV(rv, "C_EncryptUpdate", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_Encrypt(session, block, sizeof(block), out, &outSz);
    CHECK_RV(rv, "C_Encrypt after update", CKR_FUNCTION_FAILED);
    outSz = sizeof(out);
    rv = funcList->C_EncryptFinal(session, out, &outSz);
    CHECK_RV(rv, "C_EncryptFinal after refused C_Encrypt",
             CKR_OPERATION_NOT_INITIALIZED);

    rv = funcList->C_DecryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_DecryptInit(CBC)", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_DecryptUpdate(session, block, sizeof(block), out, &outSz);
    CHECK_RV(rv, "C_DecryptUpdate", CKR_OK);
    outSz = sizeof(out);
    rv = funcList->C_Decrypt(session, block, sizeof(block), out, &outSz);
    CHECK_RV(rv, "C_Decrypt after update", CKR_FUNCTION_FAILED);
    outSz = sizeof(out);
    rv = funcList->C_DecryptFinal(session, out, &outSz);
    CHECK_RV(rv, "C_DecryptFinal after refused C_Decrypt",
             CKR_OPERATION_NOT_INITIALIZED);
}

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hmacKey = CK_INVALID_HANDLE;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv == CKR_OK) {
        rv = create_aes_key(session, &aesKey);
        CHECK_RV(rv, "C_CreateObject(AES key)", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = create_hmac_key(session, &hmacKey);
        CHECK_RV(rv, "C_CreateObject(HMAC key)", CKR_OK);
    }
    if (rv == CKR_OK) {
        test_stray_calls(session, aesKey, hmacKey);
        test_single_part_after_update(session, aesKey, hmacKey);
    }

    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}
#endif

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 single-part operation state test ===\n");
#if !defined(NO_AES) && !defined(NO_AES_CBC) && !defined(NO_HMAC) && \
    !defined(NO_SHA256)
    run_test();
#else
    printf("AES-CBC, HMAC or SHA-256 not available, skipping\n");
#endif
    return pkcs11_test_summary();
}
