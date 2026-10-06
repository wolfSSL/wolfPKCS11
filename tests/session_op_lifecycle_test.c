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
    if (rv == CKR_OK) {
        rv = create_secret(*session, &aesType, aesKeyValue,
                           sizeof(aesKeyValue), aesKey);
    }
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
