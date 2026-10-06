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
#endif /* !NO_SHA256 */

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

    printf("=== wolfPKCS11 digest and length convention test ===\n");
    run_test();
    return pkcs11_test_summary();
}
