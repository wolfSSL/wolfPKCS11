/* session_op_lifecycle_test.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Every way a session operation ends (completion, error, replacement or
 * session close) must release and scrub the state the operation owned.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/session_op_lifecycle_test"

#if defined(USE_WOLFSSL_MEMORY) && !defined(NO_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
    #define TRACK_ALLOCS
#endif

/* Fixtures and helpers are shared by tests that compile in different builds. */
#if defined(_MSC_VER)
    #pragma warning(push)
    #pragma warning(disable: 4101 4189 4505)
#elif defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-variable"
    #pragma GCC diagnostic ignored "-Wunused-function"
#endif

static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesType = CKK_AES;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

/* Uniform key bytes so the value is recognisable in any key schedule. */
static byte aesKeyValue[16] = {
    0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
    0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3
};
static byte macKeyValue[32] = {
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C
};
static byte gcmIv[12] = { 0 };
static byte gcmAad[48] = { 0 };
static byte plainMarker[32] = {
    0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B,
    0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B,
    0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B,
    0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B, 0x6B
};

#ifdef TRACK_ALLOCS
/* Allocation hooks: count live blocks and look for a watched byte pattern in
 * every block handed back to the allocator. */
#define ALLOC_HDR_SZ 16

static long liveBlocks = 0;
static long allocCount = 0;
static const byte* watchData = NULL;
static size_t watchLen = 0;
static int watchHit = 0;

static void track_scan(const byte* p, size_t sz)
{
    size_t i;

    if (watchData == NULL || watchLen == 0 || sz < watchLen)
        return;
    for (i = 0; i + watchLen <= sz; i++) {
        if (XMEMCMP(p + i, watchData, watchLen) == 0) {
            watchHit = 1;
            return;
        }
    }
}

static void* track_malloc(size_t sz)
{
    byte* p = (byte*)malloc(sz + ALLOC_HDR_SZ);

    if (p == NULL)
        return NULL;
    /* Zeroed so a scan only sees bytes the library wrote. */
    XMEMSET(p, 0, sz + ALLOC_HDR_SZ);
    XMEMCPY(p, &sz, sizeof(sz));
    liveBlocks++;
    allocCount++;
    return p + ALLOC_HDR_SZ;
}

static void track_free(void* ptr)
{
    byte* p;
    size_t sz;

    if (ptr == NULL)
        return;
    p = (byte*)ptr - ALLOC_HDR_SZ;
    XMEMCPY(&sz, p, sizeof(sz));
    track_scan((byte*)ptr, sz);
    liveBlocks--;
    free(p);
}

static void* track_realloc(void* ptr, size_t sz)
{
    void* n;
    size_t oldSz;

    if (ptr == NULL)
        return track_malloc(sz);
    if (sz == 0) {
        track_free(ptr);
        return NULL;
    }
    n = track_malloc(sz);
    if (n == NULL)
        return NULL;
    XMEMCPY(&oldSz, (byte*)ptr - ALLOC_HDR_SZ, sizeof(oldSz));
    XMEMCPY(n, ptr, (oldSz < sz) ? oldSz : sz);
    track_free(ptr);
    return n;
}

static void watch_start(const byte* data, size_t len)
{
    watchData = data;
    watchLen = len;
    watchHit = 0;
}

static int watch_stop(void)
{
    watchData = NULL;
    watchLen = 0;
    return watchHit;
}
#endif /* TRACK_ALLOCS */

static CK_RV create_secret(CK_SESSION_HANDLE session, CK_KEY_TYPE* type,
                           byte* value, CK_ULONG valueLen,
                           CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, type,         sizeof(*type)       },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_SIGN,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_VERIFY,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE,    value,        valueLen            },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}

#if !defined(NO_RSA) && (!defined(WC_NO_RSA_OAEP) || defined(WC_RSA_PSS))
static CK_RV create_rsa_public(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE* key)
{
    static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    static CK_KEY_TYPE rsaType = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,           &pubClass,        sizeof(pubClass)        },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)         },
        { CKA_ENCRYPT,         &ckTrue,          sizeof(ckTrue)          },
        { CKA_VERIFY,          &ckTrue,          sizeof(ckTrue)          },
        { CKA_TOKEN,           &ckFalse,         sizeof(ckFalse)         },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}
#endif

#ifdef HAVE_ECC
static CK_RV create_ec_public(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    static CK_KEY_TYPE ecType = CKK_EC;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &pubClass,       sizeof(pubClass)       },
        { CKA_KEY_TYPE,  &ecType,         sizeof(ecType)         },
        { CKA_VERIFY,    &ckTrue,         sizeof(ckTrue)         },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_EC_POINT,  ecc_p256_pub,    sizeof(ecc_p256_pub)    },
    };

    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}
#endif

static CK_RV init_library(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_ULONG slotCount = 1;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slot, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    return rv;
}

static CK_RV open_with_keys(CK_SLOT_ID slot, CK_SESSION_HANDLE* session,
                            CK_OBJECT_HANDLE* aesKey,
                            CK_OBJECT_HANDLE* macKey)
{
    CK_RV rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
#ifndef NO_AES
    if (rv == CKR_OK) {
        rv = create_secret(*session, &aesType, aesKeyValue,
                           sizeof(aesKeyValue), aesKey);
    }
#else
    (void)aesKey;
#endif
    if (rv == CKR_OK) {
        rv = create_secret(*session, &genericType, macKeyValue,
                           sizeof(macKeyValue), macKey);
    }
    return rv;
}

#if defined(_MSC_VER)
    #pragma warning(pop)
#elif defined(__GNUC__)
    #pragma GCC diagnostic pop
#endif

#if defined(TRACK_ALLOCS) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(NO_HMAC) && !defined(NO_SHA256)
/* Starting an operation of another category must release the resources held
 * by the operation it replaces. */
static void test_cross_category_init_releases_state(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    CK_GCM_PARAMS gcmParams;
    CK_MECHANISM gcmMech = { CKM_AES_GCM, &gcmParams, sizeof(gcmParams) };
    CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, NULL, 0 };
    CK_MECHANISM sha256Mech = { CKM_SHA256, NULL, 0 };
#if !defined(NO_RSA) && !defined(WC_NO_RSA_OAEP)
    CK_OBJECT_HANDLE rsaKey = CK_INVALID_HANDLE;
    byte label[24] = { 0 };
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = {
        CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, label, sizeof(label)
    };
    CK_MECHANISM oaepMech = { CKM_RSA_PKCS_OAEP, &oaepParams,
                              sizeof(oaepParams) };
#endif
#ifdef HAVE_ECC
    CK_OBJECT_HANDLE ecKey = CK_INVALID_HANDLE;
    CK_MECHANISM ecdsaMech = { CKM_ECDSA, NULL, 0 };
#endif
    byte out[64];
    CK_ULONG outLen;
    CK_SLOT_ID slot;
    long before;

    printf("\n--- replacing an operation releases its state ---\n");
    XMEMSET(&gcmParams, 0, sizeof(gcmParams));
    gcmParams.pIv = gcmIv;
    gcmParams.ulIvLen = sizeof(gcmIv);
    gcmParams.ulIvBits = sizeof(gcmIv) * 8;
    gcmParams.pAAD = gcmAad;
    gcmParams.ulAADLen = sizeof(gcmAad);
    gcmParams.ulTagBits = 128;

    rv = init_library(&slot);
    CHECK_RV(rv, "initialize library", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    before = liveBlocks;
    rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_EncryptInit(session, &gcmMech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(AES-GCM with AAD)", CKR_OK);
    rv = funcList->C_VerifyInit(session, &hmacMech, macKey);
    CHECK_RV(rv, "C_VerifyInit(HMAC) over active encrypt", CKR_OK);

    rv = funcList->C_DecryptInit(session, &gcmMech, aesKey);
    CHECK_RV(rv, "C_DecryptInit(AES-GCM with AAD)", CKR_OK);
    rv = funcList->C_DigestInit(session, &sha256Mech);
    CHECK_RV(rv, "C_DigestInit over active decrypt", CKR_OK);

    rv = funcList->C_SignInit(session, &hmacMech, macKey);
    CHECK_RV(rv, "C_SignInit(HMAC) over active digest", CKR_OK);
    rv = funcList->C_EncryptInit(session, &gcmMech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(AES-GCM) over active sign", CKR_OK);
    rv = funcList->C_SignInit(session, &hmacMech, macKey);
    CHECK_RV(rv, "C_SignInit(HMAC) over active encrypt", CKR_OK);

    rv = funcList->C_EncryptInit(session, &gcmMech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(AES-GCM) over active sign", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_EncryptUpdate(session, plainMarker, sizeof(plainMarker),
                                   out, &outLen);
    CHECK_RV(rv, "C_EncryptUpdate(AES-GCM)", CKR_OK);
    watch_start(plainMarker, sizeof(plainMarker));
    rv = funcList->C_SignInit(session, &hmacMech, macKey);
    CHECK_RV(rv, "C_SignInit(HMAC) over multi-part encrypt", CKR_OK);
    CHECK_TRUE(!watch_stop(),
               "replaced operation scrubs buffered input before release");

#ifdef HAVE_ECC
    rv = create_ec_public(session, &ecKey);
    CHECK_RV(rv, "C_CreateObject(EC public)", CKR_OK);
    rv = funcList->C_EncryptInit(session, &gcmMech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(AES-GCM) over active sign", CKR_OK);
    rv = funcList->C_VerifyInit(session, &ecdsaMech, ecKey);
    CHECK_RV(rv, "C_VerifyInit(ECDSA) over active encrypt", CKR_OK);
    rv = funcList->C_DestroyObject(session, ecKey);
    CHECK_RV(rv, "C_DestroyObject(EC)", CKR_OK);
#endif

#if !defined(NO_RSA) && !defined(WC_NO_RSA_OAEP)
    rv = create_rsa_public(session, &rsaKey);
    CHECK_RV(rv, "C_CreateObject(RSA public)", CKR_OK);
    rv = funcList->C_EncryptInit(session, &oaepMech, rsaKey);
    CHECK_RV(rv, "C_EncryptInit(RSA-OAEP with label)", CKR_OK);
    rv = funcList->C_DecryptInit(session, &gcmMech, aesKey);
    CHECK_RV(rv, "C_DecryptInit(AES-GCM) over active encrypt", CKR_OK);
    rv = funcList->C_SignInit(session, &hmacMech, macKey);
    CHECK_RV(rv, "C_SignInit(HMAC) over active decrypt", CKR_OK);
    rv = funcList->C_DestroyObject(session, rsaKey);
    CHECK_RV(rv, "C_DestroyObject(RSA)", CKR_OK);
#endif

    rv = funcList->C_DestroyObject(session, aesKey);
    CHECK_RV(rv, "C_DestroyObject(AES)", CKR_OK);
    rv = funcList->C_DestroyObject(session, macKey);
    CHECK_RV(rv, "C_DestroyObject(HMAC)", CKR_OK);
    funcList->C_CloseSession(session);
    session = CK_INVALID_HANDLE;
    CHECK_TRUE(liveBlocks == before,
               "replaced operations leave no allocation behind");

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(HAVE_ECC)
/* A request that is rejected before it can start must leave the operation
 * already active on the session untouched. */
static void test_rejected_init_keeps_active_operation(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    CK_MECHANISM cbcMech = { CKM_AES_CBC, NULL, 0 };
    CK_MECHANISM ecdsaMech = { CKM_ECDSA, NULL, 0 };
    CK_MECHANISM badMech = { CKM_VENDOR_DEFINED, NULL, 0 };
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    CK_ULONG badMacLen = 5;
    CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, &badMacLen,
                              sizeof(badMacLen) };
#endif
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    CK_OBJECT_HANDLE rsaKey = CK_INVALID_HANDLE;
    CK_RSA_PKCS_PSS_PARAMS pssParams = { CKM_VENDOR_DEFINED, CKG_MGF1_SHA256,
                                         32 };
    CK_MECHANISM pssMech = { CKM_RSA_PKCS_PSS, &pssParams,
                             sizeof(pssParams) };
#endif
    byte iv[16] = { 0 };
    byte out[32];
    CK_ULONG outLen;
    CK_SLOT_ID slot;

    printf("\n--- a rejected Init keeps the active operation ---\n");
    cbcMech.pParameter = iv;
    cbcMech.ulParameterLen = sizeof(iv);

    rv = init_library(&slot);
    CHECK_RV(rv, "initialize library", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_EncryptInit(session, &cbcMech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(AES-CBC)", CKR_OK);
    rv = funcList->C_VerifyInit(session, &ecdsaMech, macKey);
    CHECK_RV(rv, "C_VerifyInit(ECDSA) with a secret key",
             CKR_KEY_TYPE_INCONSISTENT);
    rv = funcList->C_SignInit(session, &badMech, macKey);
    CHECK_RV(rv, "C_SignInit(unknown mechanism)", CKR_MECHANISM_INVALID);
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    rv = funcList->C_SignInit(session, &hmacMech, macKey);
    CHECK_RV(rv, "C_SignInit(HMAC with bad output length)",
             CKR_MECHANISM_PARAM_INVALID);
#endif
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    rv = create_rsa_public(session, &rsaKey);
    CHECK_RV(rv, "C_CreateObject(RSA public)", CKR_OK);
    rv = funcList->C_VerifyInit(session, &pssMech, rsaKey);
    CHECK_RV(rv, "C_VerifyInit(RSA-PSS with bad hash)",
             CKR_MECHANISM_PARAM_INVALID);
#endif

    outLen = sizeof(out);
    rv = funcList->C_EncryptUpdate(session, plainMarker, sizeof(plainMarker),
                                   out, &outLen);
    CHECK_RV(rv, "C_EncryptUpdate after rejected Inits", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_EncryptFinal(session, out, &outLen);
    CHECK_RV(rv, "C_EncryptFinal after rejected Inits", CKR_OK);

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if defined(TRACK_ALLOCS) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    !defined(NO_SHA256)
static int finalize_watched(CK_SESSION_HANDLE session)
{
    funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    return watch_stop();
}

/* An operation that ends on an error must release and scrub its keyed and
 * buffered state, just as a completed operation does. */
static void test_failed_operation_scrubs_state(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    byte iv[16] = { 0 };
    CK_MECHANISM cbcMech = { CKM_AES_CBC, NULL, 0 };
    CK_MECHANISM sha256Mech = { CKM_SHA256, NULL, 0 };
    CK_ULONG bigLen = (CK_ULONG)0xFFFFFFFFUL;
    byte out[64];
    CK_ULONG outLen;
    CK_SLOT_ID slot;
    int i;

    printf("\n--- an operation ending on error scrubs its state ---\n");
    cbcMech.pParameter = iv;
    cbcMech.ulParameterLen = sizeof(iv);
    if (sizeof(CK_ULONG) <= sizeof(word32)) {
        printf("SKIP: lengths beyond 32 bits need a 64-bit CK_ULONG\n");
        return;
    }
    bigLen += 16;

    for (i = 0; i < 2; i++) {
        rv = init_library(&slot);
        if (rv == CKR_OK)
            rv = open_with_keys(slot, &session, &aesKey, &macKey);
        CHECK_RV(rv, "open session with keys", CKR_OK);
        if (rv != CKR_OK)
            goto out;
        rv = funcList->C_EncryptInit(session, &cbcMech, aesKey);
        CHECK_RV(rv, "C_EncryptInit(AES-CBC)", CKR_OK);
        outLen = sizeof(out);
        /* Watch from the failing call: it may free the state itself. */
        watch_start(aesKeyValue, sizeof(aesKeyValue));
        if (i == 0) {
            rv = funcList->C_EncryptUpdate(session, out, bigLen, out, &outLen);
            CHECK_RV(rv, "C_EncryptUpdate(oversized)", CKR_DATA_LEN_RANGE);
        }
        else {
            rv = funcList->C_Encrypt(session, out, bigLen, out, &outLen);
            CHECK_RV(rv, "C_Encrypt(oversized)", CKR_DATA_LEN_RANGE);
        }
        CHECK_TRUE(!finalize_watched(session),
                   "failed AES operation leaves no key schedule behind");
        session = CK_INVALID_HANDLE;
    }

    rv = init_library(&slot);
    if (rv == CKR_OK)
        rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = funcList->C_DigestInit(session, &sha256Mech);
    CHECK_RV(rv, "C_DigestInit(SHA-256)", CKR_OK);
    rv = funcList->C_DigestUpdate(session, plainMarker, sizeof(plainMarker));
    CHECK_RV(rv, "C_DigestUpdate", CKR_OK);
    watch_start(plainMarker, sizeof(plainMarker));
    rv = funcList->C_DigestKey(session, CK_INVALID_HANDLE);
    CHECK_RV(rv, "C_DigestKey(invalid handle)", CKR_OBJECT_HANDLE_INVALID);
    CHECK_TRUE(!finalize_watched(session),
               "failed digest leaves no buffered input behind");
    session = CK_INVALID_HANDLE;

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if defined(TRACK_ALLOCS) && !defined(NO_AES) && defined(HAVE_AESGCM)
/* Re-initializing AES-GCM must release, scrubbed, any data a previous GCM
 * operation left buffered on the session. */
static void test_gcm_reinit_releases_buffer(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    CK_GCM_PARAMS gcmParams;
    CK_MECHANISM gcmMech = { CKM_AES_GCM, &gcmParams, sizeof(gcmParams) };
    byte out[64];
    CK_ULONG outLen;
    CK_SLOT_ID slot;
    long before;
    int hit;

    printf("\n--- GCM re-init releases buffered data ---\n");
    XMEMSET(&gcmParams, 0, sizeof(gcmParams));
    gcmParams.pIv = gcmIv;
    gcmParams.ulIvLen = sizeof(gcmIv);
    gcmParams.ulIvBits = sizeof(gcmIv) * 8;
    gcmParams.ulTagBits = 128;

    rv = init_library(&slot);
    CHECK_RV(rv, "initialize library", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    before = liveBlocks;
    rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_EncryptInit(session, &gcmMech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(AES-GCM)", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_EncryptUpdate(session, plainMarker, sizeof(plainMarker),
                                   out, &outLen);
    CHECK_RV(rv, "C_EncryptUpdate(AES-GCM)", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_Encrypt(session, gcmIv, sizeof(gcmIv), out, &outLen);
    CHECK_RV(rv, "C_Encrypt(AES-GCM) ends the operation", CKR_OK);

    watch_start(plainMarker, sizeof(plainMarker));
    rv = funcList->C_EncryptInit(session, &gcmMech, aesKey);
    hit = watch_stop();
    CHECK_RV(rv, "C_EncryptInit(AES-GCM) again", CKR_OK);
    CHECK_TRUE(!hit, "GCM re-init scrubs buffered data before release");

    rv = funcList->C_DestroyObject(session, aesKey);
    CHECK_RV(rv, "C_DestroyObject(AES)", CKR_OK);
    rv = funcList->C_DestroyObject(session, macKey);
    CHECK_RV(rv, "C_DestroyObject(HMAC)", CKR_OK);
    funcList->C_CloseSession(session);
    session = CK_INVALID_HANDLE;
    CHECK_TRUE(liveBlocks == before,
               "GCM re-init leaves no allocation behind");

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
/* A key that the cipher rejects during setup must not leave a half-built
 * context behind, and the session must stay usable. */
static void test_failed_key_setup_keeps_session_usable(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE oddKey = CK_INVALID_HANDLE;
    byte oddValue[20];
    byte iv[16] = { 0 };
    CK_MECHANISM cbcMech = { CKM_AES_CBC, NULL, 0 };
    byte out[32];
    CK_ULONG outLen;
    CK_SLOT_ID slot;
#ifdef TRACK_ALLOCS
    long before = 0;
#endif

    printf("\n--- a failed key setup leaves the session usable ---\n");
    cbcMech.pParameter = iv;
    cbcMech.ulParameterLen = sizeof(iv);
    XMEMSET(oddValue, 0x5A, sizeof(oddValue));

    rv = init_library(&slot);
    CHECK_RV(rv, "initialize library", CKR_OK);
    if (rv != CKR_OK)
        goto out;
#ifdef TRACK_ALLOCS
    before = liveBlocks;
#endif
    rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = create_secret(session, &aesType, oddValue, sizeof(oddValue), &oddKey);
    if (rv != CKR_OK) {
        printf("SKIP: token rejects AES keys of invalid length\n");
    }
    else {
        rv = funcList->C_EncryptInit(session, &cbcMech, oddKey);
        CHECK_TRUE(rv != CKR_OK, "C_EncryptInit with an unusable key fails");
        rv = funcList->C_EncryptInit(session, &cbcMech, aesKey);
        CHECK_RV(rv, "C_EncryptInit(AES-CBC) after failed setup", CKR_OK);
        outLen = sizeof(out);
        rv = funcList->C_Encrypt(session, iv, sizeof(iv), out, &outLen);
        CHECK_RV(rv, "C_Encrypt(AES-CBC) after failed setup", CKR_OK);
        funcList->C_DestroyObject(session, oddKey);
    }

    funcList->C_DestroyObject(session, aesKey);
    funcList->C_DestroyObject(session, macKey);
    funcList->C_CloseSession(session);
    session = CK_INVALID_HANDLE;
#ifdef TRACK_ALLOCS
    CHECK_TRUE(liveBlocks == before,
               "failed key setup leaves no allocation behind");
#endif

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if !defined(NO_AES) && (defined(HAVE_AESGCM) || defined(HAVE_AESECB) || \
    defined(HAVE_AESCCM))
/* Destroying a key must end the operations that still read it, while
 * operations that copied the key at Init time may finish. */
static void test_destroyed_key_ends_dependent_operation(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE tmpKey = CK_INVALID_HANDLE;
#ifdef HAVE_AESGCM
    CK_GCM_PARAMS gcmParams;
    CK_MECHANISM gcmMech = { CKM_AES_GCM, &gcmParams, sizeof(gcmParams) };
#endif
#ifdef HAVE_AESECB
    CK_MECHANISM ecbMech = { CKM_AES_ECB, NULL, 0 };
#endif
#ifdef HAVE_AESCCM
    CK_CCM_PARAMS ccmParams;
    CK_MECHANISM ccmMech = { CKM_AES_CCM, &ccmParams, sizeof(ccmParams) };
#endif
#ifdef HAVE_AES_CBC
    byte iv[16] = { 0 };
    CK_MECHANISM cbcMech = { CKM_AES_CBC, NULL, 0 };
#endif
    byte out[64];
    CK_ULONG outLen;
    CK_SLOT_ID slot;

    printf("\n--- destroying a key ends operations that read it ---\n");
#ifdef HAVE_AESGCM
    XMEMSET(&gcmParams, 0, sizeof(gcmParams));
    gcmParams.pIv = gcmIv;
    gcmParams.ulIvLen = sizeof(gcmIv);
    gcmParams.ulIvBits = sizeof(gcmIv) * 8;
    gcmParams.ulTagBits = 128;
#endif
#ifdef HAVE_AESCCM
    XMEMSET(&ccmParams, 0, sizeof(ccmParams));
    ccmParams.ulDataLen = 16;
    ccmParams.pIv = gcmIv;
    ccmParams.ulIvLen = sizeof(gcmIv);
    ccmParams.pAAD = gcmAad;
    ccmParams.ulAADLen = sizeof(gcmAad);
    ccmParams.ulMacLen = 16;
#endif
#ifdef HAVE_AES_CBC
    cbcMech.pParameter = iv;
    cbcMech.ulParameterLen = sizeof(iv);
#endif

    rv = init_library(&slot);
    if (rv == CKR_OK)
        rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

#ifdef HAVE_AESGCM
    rv = create_secret(session, &aesType, aesKeyValue, sizeof(aesKeyValue),
                       &tmpKey);
    CHECK_RV(rv, "C_CreateObject(AES)", CKR_OK);
    rv = funcList->C_EncryptInit(session, &gcmMech, tmpKey);
    CHECK_RV(rv, "C_EncryptInit(AES-GCM)", CKR_OK);
    rv = funcList->C_DestroyObject(session, tmpKey);
    CHECK_RV(rv, "C_DestroyObject(active AES-GCM key)", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_Encrypt(session, plainMarker, 16, out, &outLen);
    CHECK_RV(rv, "C_Encrypt(AES-GCM) after key destroyed",
             CKR_OPERATION_NOT_INITIALIZED);
    rv = funcList->C_EncryptInit(session, &gcmMech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(AES-GCM) with another key", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_Encrypt(session, plainMarker, 16, out, &outLen);
    CHECK_RV(rv, "C_Encrypt(AES-GCM) with another key", CKR_OK);
#endif
#ifdef HAVE_AESCCM
    rv = create_secret(session, &aesType, aesKeyValue, sizeof(aesKeyValue),
                       &tmpKey);
    CHECK_RV(rv, "C_CreateObject(AES)", CKR_OK);
    rv = funcList->C_EncryptInit(session, &ccmMech, tmpKey);
    CHECK_RV(rv, "C_EncryptInit(AES-CCM)", CKR_OK);
    rv = funcList->C_DestroyObject(session, tmpKey);
    CHECK_RV(rv, "C_DestroyObject(active AES-CCM key)", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_Encrypt(session, plainMarker, 16, out, &outLen);
    CHECK_RV(rv, "C_Encrypt(AES-CCM) after key destroyed",
             CKR_OPERATION_NOT_INITIALIZED);
    rv = funcList->C_EncryptInit(session, &ccmMech, aesKey);
    CHECK_RV(rv, "C_EncryptInit(AES-CCM) with another key", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_Encrypt(session, plainMarker, 16, out, &outLen);
    CHECK_RV(rv, "C_Encrypt(AES-CCM) with another key", CKR_OK);
#endif
#ifdef HAVE_AESECB
    rv = create_secret(session, &aesType, aesKeyValue, sizeof(aesKeyValue),
                       &tmpKey);
    CHECK_RV(rv, "C_CreateObject(AES)", CKR_OK);
    rv = funcList->C_DecryptInit(session, &ecbMech, tmpKey);
    CHECK_RV(rv, "C_DecryptInit(AES-ECB)", CKR_OK);
    rv = funcList->C_DestroyObject(session, tmpKey);
    CHECK_RV(rv, "C_DestroyObject(active AES-ECB key)", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_Decrypt(session, plainMarker, 16, out, &outLen);
    CHECK_RV(rv, "C_Decrypt(AES-ECB) after key destroyed",
             CKR_OPERATION_NOT_INITIALIZED);
#endif
#ifdef HAVE_AES_CBC
    rv = create_secret(session, &aesType, aesKeyValue, sizeof(aesKeyValue),
                       &tmpKey);
    CHECK_RV(rv, "C_CreateObject(AES)", CKR_OK);
    rv = funcList->C_EncryptInit(session, &cbcMech, tmpKey);
    CHECK_RV(rv, "C_EncryptInit(AES-CBC)", CKR_OK);
    rv = funcList->C_DestroyObject(session, tmpKey);
    CHECK_RV(rv, "C_DestroyObject(active AES-CBC key)", CKR_OK);
    outLen = sizeof(out);
    rv = funcList->C_Encrypt(session, plainMarker, 16, out, &outLen);
    CHECK_RV(rv, "C_Encrypt(AES-CBC) with key copied at Init", CKR_OK);
#endif

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if defined(TRACK_ALLOCS) && defined(WOLFSSL_HAVE_PRF) && !defined(NO_SHA256)
static CK_RV tls_mac_sign_init(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_TLS_MAC_PARAMS params;
    CK_MECHANISM mech = { CKM_TLS_MAC, &params, sizeof(params) };

    params.prfHashMechanism = CKM_SHA256;
    params.ulMacLength = 12;
    params.ulServerOrClient = 1;
    return funcList->C_SignInit(session, &mech, key);
}

/* Input accumulated for a one-shot MAC must be scrubbed whenever its buffer
 * is grown or released. */
static void test_mac_input_scrubbed_on_release(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    byte sig[64];
    CK_ULONG sigLen;
    CK_SLOT_ID slot;
    int hit;

    printf("\n--- accumulated MAC input is scrubbed ---\n");
    rv = init_library(&slot);
    if (rv == CKR_OK)
        rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = tls_mac_sign_init(session, macKey);
    CHECK_RV(rv, "C_SignInit(TLS MAC)", CKR_OK);
    rv = funcList->C_SignUpdate(session, plainMarker, sizeof(plainMarker));
    CHECK_RV(rv, "C_SignUpdate(TLS MAC)", CKR_OK);
    watch_start(plainMarker, sizeof(plainMarker));
    rv = funcList->C_SignUpdate(session, plainMarker, sizeof(plainMarker));
    CHECK_RV(rv, "C_SignUpdate(TLS MAC) again", CKR_OK);
    sigLen = sizeof(sig);
    rv = funcList->C_SignFinal(session, sig, &sigLen);
    hit = watch_stop();
    CHECK_RV(rv, "C_SignFinal(TLS MAC)", CKR_OK);
    CHECK_TRUE(!hit, "MAC input is scrubbed when its buffer is released");

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

#define MAC_SMALL_PARTS 1024

/* Many one-byte MAC parts must not reallocate the buffered input each time. */
static void test_mac_input_grows_linearly(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    byte part = 0x5a;
    CK_SLOT_ID slot;
    long allocs;
    int i;

    printf("\n--- many small MAC parts grow the input buffer linearly ---\n");
    rv = init_library(&slot);
    if (rv == CKR_OK)
        rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = tls_mac_sign_init(session, macKey);
    CHECK_RV(rv, "C_SignInit(TLS MAC)", CKR_OK);
    allocs = allocCount;
    for (i = 0; rv == CKR_OK && i < MAC_SMALL_PARTS; i++)
        rv = funcList->C_SignUpdate(session, &part, 1);
    allocs = allocCount - allocs;
    CHECK_RV(rv, "one-byte C_SignUpdate(TLS MAC) parts", CKR_OK);
    if (allocs > 64)
        fprintf(stderr, "  %ld allocations for %d parts\n", allocs, i);
    CHECK_TRUE(allocs <= 64, "buffered MAC input is not reallocated per part");

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if defined(TRACK_ALLOCS) && defined(WOLFSSL_HAVE_PRF) && !defined(NO_SHA256)
/* Closing a session in the middle of a one-shot MAC must release, scrubbed,
 * the input accumulated so far. */
static void test_mac_input_released_on_close(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    CK_SLOT_ID slot;
    long before;
    int hit;

    printf("\n--- closing a session releases accumulated MAC input ---\n");
    rv = init_library(&slot);
    CHECK_RV(rv, "initialize library", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    before = liveBlocks;
    rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = tls_mac_sign_init(session, macKey);
    CHECK_RV(rv, "C_SignInit(TLS MAC)", CKR_OK);
    rv = funcList->C_SignUpdate(session, plainMarker, sizeof(plainMarker));
    CHECK_RV(rv, "C_SignUpdate(TLS MAC)", CKR_OK);

    watch_start(plainMarker, sizeof(plainMarker));
    funcList->C_CloseSession(session);
    hit = watch_stop();
    session = CK_INVALID_HANDLE;
    CHECK_TRUE(!hit, "closed session scrubs accumulated MAC input");
    CHECK_TRUE(liveBlocks == before,
               "closed session leaves no allocation behind");

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#ifndef NO_SHA256
/* Operation state is only available while a digest is in progress, and a
 * refused request leaves the caller's length untouched. */
static void test_operation_state_requires_active_digest(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    CK_MECHANISM sha256Mech = { CKM_SHA256, NULL, 0 };
#ifndef NO_HMAC
    CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, NULL, 0 };
#endif
    byte digest[32];
    CK_ULONG digestLen;
    CK_ULONG stateLen;
    CK_SLOT_ID slot;

    printf("\n--- operation state needs an active digest ---\n");
    rv = init_library(&slot);
    if (rv == CKR_OK)
        rv = open_with_keys(slot, &session, &aesKey, &macKey);
    CHECK_RV(rv, "open session with keys", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_DigestInit(session, &sha256Mech);
    CHECK_RV(rv, "C_DigestInit(SHA-256)", CKR_OK);
    digestLen = sizeof(digest);
    rv = funcList->C_Digest(session, plainMarker, sizeof(plainMarker), digest,
                            &digestLen);
    CHECK_RV(rv, "C_Digest completes the operation", CKR_OK);
    stateLen = 0;
    rv = funcList->C_GetOperationState(session, NULL, &stateLen);
    CHECK_RV(rv, "C_GetOperationState after digest completed",
             CKR_OPERATION_NOT_INITIALIZED);

#ifndef NO_HMAC
    rv = funcList->C_SignInit(session, &hmacMech, macKey);
    CHECK_RV(rv, "C_SignInit(HMAC)", CKR_OK);
    stateLen = 1234;
    rv = funcList->C_GetOperationState(session, NULL, &stateLen);
    CHECK_RV(rv, "C_GetOperationState during HMAC", CKR_STATE_UNSAVEABLE);
    CHECK_TRUE(stateLen == 1234,
               "refused C_GetOperationState leaves the length untouched");
#endif

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if defined(TRACK_ALLOCS) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(WOLFSSL_AESGCM_STREAM)
/* Destroying the key of a multi-part AES-GCM operation must release the
 * plaintext it buffered once the operation is next used. */
static void test_destroyed_gcm_key_releases_input(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE macKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE tmpKey = CK_INVALID_HANDLE;
    CK_GCM_PARAMS gcmParams;
    CK_MECHANISM gcmMech = { CKM_AES_GCM, &gcmParams, sizeof(gcmParams) };
    byte out[64];
    CK_ULONG outLen;
    CK_SLOT_ID slot;
    long before;
    int hit;

    printf("\n--- destroying an AES-GCM key releases buffered input ---\n");
    XMEMSET(&gcmParams, 0, sizeof(gcmParams));
    gcmParams.pIv = gcmIv;
    gcmParams.ulIvLen = sizeof(gcmIv);
    gcmParams.ulIvBits = sizeof(gcmIv) * 8;
    gcmParams.ulTagBits = 128;

    rv = init_library(&slot);
    if (rv == CKR_OK)
        rv = open_with_keys(slot, &session, &aesKey, &macKey);
    if (rv == CKR_OK) {
        rv = create_secret(session, &aesType, aesKeyValue, sizeof(aesKeyValue),
                           &tmpKey);
    }
    if (rv == CKR_OK)
        rv = funcList->C_EncryptInit(session, &gcmMech, tmpKey);
    if (rv == CKR_OK) {
        outLen = sizeof(out);
        rv = funcList->C_EncryptUpdate(session, plainMarker,
                                       sizeof(plainMarker), out, &outLen);
    }
    if (rv == CKR_OK)
        rv = funcList->C_DestroyObject(session, tmpKey);
    CHECK_RV(rv, "buffer AES-GCM input and destroy its key", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    before = liveBlocks;
    watch_start(plainMarker, sizeof(plainMarker));
    outLen = sizeof(out);
    rv = funcList->C_EncryptFinal(session, out, &outLen);
    hit = watch_stop();
    CHECK_RV(rv, "C_EncryptFinal(AES-GCM) after key destroyed",
             CKR_OPERATION_NOT_INITIALIZED);
    CHECK_TRUE(liveBlocks < before, "buffered AES-GCM input is released");
    CHECK_TRUE(!hit, "buffered AES-GCM input is scrubbed");

out:
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

static int run_test(void)
{
    CK_RV rv;

#ifdef TRACK_ALLOCS
    if (wolfSSL_SetAllocators(track_malloc, track_free, track_realloc) != 0) {
        CHECK_TRUE(0, "install allocation hooks");
        return -1;
    }
#endif

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

#if defined(TRACK_ALLOCS) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(NO_HMAC) && !defined(NO_SHA256)
    test_cross_category_init_releases_state();
#endif
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && defined(HAVE_ECC)
    test_rejected_init_keeps_active_operation();
#endif
#if defined(TRACK_ALLOCS) && !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    !defined(NO_SHA256)
    test_failed_operation_scrubs_state();
#endif
#if defined(TRACK_ALLOCS) && !defined(NO_AES) && defined(HAVE_AESGCM)
    test_gcm_reinit_releases_buffer();
#endif
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    test_failed_key_setup_keeps_session_usable();
#endif
#if !defined(NO_AES) && (defined(HAVE_AESGCM) || defined(HAVE_AESECB) || \
    defined(HAVE_AESCCM))
    test_destroyed_key_ends_dependent_operation();
#endif
#if defined(TRACK_ALLOCS) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    !defined(WOLFSSL_AESGCM_STREAM)
    test_destroyed_gcm_key_releases_input();
#endif
#if defined(TRACK_ALLOCS) && defined(WOLFSSL_HAVE_PRF) && !defined(NO_SHA256)
    test_mac_input_scrubbed_on_release();
    test_mac_input_grows_linearly();
    test_mac_input_released_on_close();
#endif
#ifndef NO_SHA256
    test_operation_state_requires_active_digest();
#endif

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

    printf("=== wolfPKCS11 session operation lifecycle test ===\n");
    run_test();
    return pkcs11_test_summary();
}
