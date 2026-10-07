/* secret_scrub_test.c
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
 * Checks that transient secret data is wiped before its memory is released
 * back to the allocator.
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

#if (!defined(NO_AES) && (defined(HAVE_AES_CBC) || \
    (defined(HAVE_AESGCM) && !defined(WOLFSSL_AESGCM_STREAM)))) || \
    (defined(WOLFSSL_HAVE_PRF) && !defined(NO_SHA256))
    #define SCRUB_SESSION_TESTS
#endif

#define TEST_DIR "./store/secret_scrub_test"

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "secret-scrub";

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

/* The allocator hooks below report any released block that still holds the
 * watched bytes. A size header lets free() see the whole block. */
#define SCRUB_HDR_SZ 16

static const unsigned char* watchData = NULL;
static size_t watchLen = 0;
static int watchHits = 0;
static int watchFrees = 0;

static int block_holds_watch(const unsigned char* buf, size_t sz)
{
    size_t i;

    if (watchData == NULL || watchLen == 0 || sz < watchLen)
        return 0;
    for (i = 0; i + watchLen <= sz; i++) {
        if (memcmp(buf + i, watchData, watchLen) == 0)
            return 1;
    }
    return 0;
}

static void* scrub_malloc(size_t n)
{
    unsigned char* p = (unsigned char*)malloc(n + SCRUB_HDR_SZ);

    if (p == NULL)
        return NULL;
    /* Zeroed so a scan only sees bytes the library wrote. */
    memset(p, 0, n + SCRUB_HDR_SZ);
    memcpy(p, &n, sizeof(n));
    return p + SCRUB_HDR_SZ;
}

static void scrub_free(void* ptr)
{
    unsigned char* p;
    size_t n;

    if (ptr == NULL)
        return;
    p = (unsigned char*)ptr - SCRUB_HDR_SZ;
    memcpy(&n, p, sizeof(n));
    if (watchData != NULL) {
        watchFrees++;
        if (block_holds_watch((unsigned char*)ptr, n))
            watchHits++;
    }
    free(p);
}

/* Always moves, so the block given up by a resize is inspected too. */
static void* scrub_realloc(void* ptr, size_t n)
{
    void* np;
    size_t old;

    if (ptr == NULL)
        return scrub_malloc(n);
    np = scrub_malloc(n);
    if (np == NULL)
        return NULL;
    memcpy(&old, (unsigned char*)ptr - SCRUB_HDR_SZ, sizeof(old));
    memcpy(np, ptr, old < n ? old : n);
    scrub_free(ptr);
    return np;
}

#ifdef SCRUB_SESSION_TESTS
static void watch_start(const unsigned char* data, size_t len)
{
    watchData = data;
    watchLen = len;
    watchHits = 0;
    watchFrees = 0;
}

/* Returns 1 when memory was released while watching and none held the data. */
static int watch_stop_clean(void)
{
    watchData = NULL;
    watchLen = 0;
    return watchFrees > 0 && watchHits == 0;
}
#endif

static CK_RV token_setup(CK_SLOT_ID* slot)
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
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK) {
        *slot = slotList[0];
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(*slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(*slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &soSession);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
        if (rv == CKR_OK) {
            rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                     (CK_ULONG)XSTRLEN(userPin));
            funcList->C_Logout(soSession);
        }
        funcList->C_CloseSession(soSession);
    }
    funcList->C_Finalize(NULL);
    return rv;
}

#ifdef SCRUB_SESSION_TESTS
/* C_Initialize, then open a user session on the first slot. */
static CK_RV user_session_open(CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    rv = pkcs11_open_session(session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(*session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    return rv;
}
#endif

#if !defined(NO_AES) && (defined(HAVE_AES_CBC) || \
    (defined(HAVE_AESGCM) && !defined(WOLFSSL_AESGCM_STREAM)))
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;
static unsigned char aesKeyData[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static CK_RV create_aes_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_ENCRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_DECRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_TOKEN,    &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    aesKeyData,      sizeof(aesKeyData)     },
    };

    return funcList->C_CreateObject(session, keyTmpl,
                                    sizeof(keyTmpl) / sizeof(*keyTmpl), key);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
static unsigned char cbcIv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
/* Shorter than one block, so it stays buffered in the session. */
static const unsigned char cbcPlain[15] = {
    0xc3, 0x5a, 0x91, 0x0e, 0x7d, 0x44, 0xb8, 0x26,
    0xe1, 0x9f, 0x30, 0x6b, 0xd2, 0x58, 0xa7
};

/* Buffered CBC input must be wiped before the session memory is freed. */
static void cbc_buffered_scrub_test(CK_MECHANISM_TYPE mechType, int decrypt,
                                    int callFinal, CK_RV finalRv,
                                    const char* op)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_BYTE block[16];
    CK_BYTE out[32];
    CK_ULONG outLen;
    const unsigned char* in = cbcPlain;
    CK_ULONG inLen = sizeof(cbcPlain);
    int clean;

    mech.mechanism = mechType;
    mech.pParameter = cbcIv;
    mech.ulParameterLen = sizeof(cbcIv);

    rv = user_session_open(&session);
    if (rv == CKR_OK)
        rv = create_aes_key(session, &key);
    if (rv == CKR_OK && decrypt && mechType == CKM_AES_CBC_PAD) {
        /* Padded decrypt holds back a whole block, so buffer a real one. */
        rv = funcList->C_EncryptInit(session, &mech, key);
        if (rv == CKR_OK) {
            outLen = sizeof(block);
            rv = funcList->C_Encrypt(session, (CK_BYTE_PTR)cbcPlain,
                                     sizeof(cbcPlain), block, &outLen);
        }
        in = block;
        inLen = sizeof(block);
    }
    if (rv == CKR_OK && decrypt) {
        rv = funcList->C_DecryptInit(session, &mech, key);
        if (rv == CKR_OK) {
            outLen = sizeof(out);
            rv = funcList->C_DecryptUpdate(session, (CK_BYTE_PTR)in, inLen,
                                           out, &outLen);
        }
    }
    else if (rv == CKR_OK) {
        rv = funcList->C_EncryptInit(session, &mech, key);
        if (rv == CKR_OK) {
            outLen = sizeof(out);
            rv = funcList->C_EncryptUpdate(session, (CK_BYTE_PTR)in, inLen,
                                           out, &outLen);
        }
    }
    CHECK_RV(rv, "CBC operation with a buffered block", CKR_OK);
    if (rv == CKR_OK && callFinal) {
        outLen = sizeof(out);
        if (decrypt)
            rv = funcList->C_DecryptFinal(session, out, &outLen);
        else
            rv = funcList->C_EncryptFinal(session, out, &outLen);
        CHECK_RV(rv, "CBC final", finalRv);
    }

    /* C_Finalize frees every session. */
    watch_start(in, inLen);
    funcList->C_Finalize(NULL);
    clean = watch_stop_clean();
    CHECK_TRUE(clean, op);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESGCM) && !defined(WOLFSSL_AESGCM_STREAM)
static unsigned char gcmIv[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
};
static const unsigned char gcmPlain1[24] = {
    0x5e, 0x17, 0xa2, 0x9c, 0x04, 0xd3, 0x6f, 0xb1,
    0x88, 0x2a, 0xe5, 0x71, 0x3d, 0xc6, 0x90, 0x4b,
    0xf2, 0x1e, 0x67, 0xad, 0x39, 0x85, 0xcb, 0x12
};
static const unsigned char gcmPlain2[24] = {
    0x93, 0x4e, 0xd7, 0x0b, 0x61, 0xfa, 0x28, 0xc5,
    0x7e, 0xb3, 0x16, 0x8d, 0x42, 0xe9, 0x5c, 0xa0,
    0x0f, 0x74, 0xbe, 0x23, 0xd8, 0x69, 0x31, 0xe6
};

/* Plaintext buffered by a multi-part GCM encrypt must be wiped whenever its
 * buffer is replaced or released. */
static void gcm_buffered_plaintext_scrub_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_GCM_PARAMS params;
    CK_BYTE out[32];
    CK_ULONG outLen;
    int clean;

    XMEMSET(&params, 0, sizeof(params));
    params.pIv = gcmIv;
    params.ulIvLen = sizeof(gcmIv);
    params.ulIvBits = sizeof(gcmIv) * 8;
    params.ulTagBits = 128;
    mech.mechanism = CKM_AES_GCM;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);

    rv = user_session_open(&session);
    if (rv == CKR_OK)
        rv = create_aes_key(session, &key);
    if (rv == CKR_OK)
        rv = funcList->C_EncryptInit(session, &mech, key);
    CHECK_RV(rv, "GCM C_EncryptInit", CKR_OK);

    if (rv == CKR_OK) {
        watch_start(gcmPlain1, sizeof(gcmPlain1));
        outLen = sizeof(out);
        rv = funcList->C_EncryptUpdate(session, (CK_BYTE_PTR)gcmPlain1,
                                       sizeof(gcmPlain1), out, &outLen);
        if (rv == CKR_OK) {
            outLen = sizeof(out);
            rv = funcList->C_EncryptUpdate(session, (CK_BYTE_PTR)gcmPlain2,
                                           sizeof(gcmPlain2), out, &outLen);
        }
        clean = watch_stop_clean();
        CHECK_RV(rv, "GCM C_EncryptUpdate twice", CKR_OK);
        CHECK_TRUE(clean, "GCM plaintext wiped when its buffer grows");
    }
    if (rv == CKR_OK) {
        watch_start(gcmPlain1, sizeof(gcmPlain1));
        outLen = sizeof(out);
        rv = funcList->C_EncryptFinal(session, out, &outLen);
        clean = watch_stop_clean();
        CHECK_RV(rv, "GCM C_EncryptFinal", CKR_OK);
        CHECK_TRUE(clean, "GCM plaintext wiped after C_EncryptFinal");
    }

    funcList->C_Finalize(NULL);
}
#endif

#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_SHA256)
static CK_OBJECT_CLASS tlsKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static unsigned char tlsSecret[48] = {
    0x6d, 0x21, 0xb4, 0x0f, 0x93, 0xce, 0x57, 0x1a,
    0xe8, 0x3c, 0x75, 0xa9, 0x02, 0xdf, 0x46, 0xbb
};
static unsigned char tlsHandshakeHash[32] = {
    0x1f, 0x8e, 0x34, 0xc7, 0x5a, 0x09, 0xd6, 0x72,
    0xab, 0x40, 0xe5, 0x18, 0x9d, 0x63, 0xf0, 0x2c
};

/* A rejected TLS MAC verify must not leave the expected MAC in memory that
 * has been released. */
static void tls_mac_verify_scrub_test(int multiPart, const char* op)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_TLS_MAC_PARAMS params;
    CK_MECHANISM mech;
    CK_BYTE mac[12];
    CK_BYTE badMac[12];
    CK_ULONG macLen = sizeof(mac);
    int clean = 0;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &tlsKeyClass,    sizeof(tlsKeyClass)    },
        { CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType) },
        { CKA_SIGN,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_VERIFY,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_TOKEN,    &ckFalse,        sizeof(ckFalse)        },
        { CKA_VALUE,    tlsSecret,       sizeof(tlsSecret)      },
    };

    params.prfHashMechanism = CKM_SHA256;
    params.ulMacLength = sizeof(mac);
    params.ulServerOrClient = 1;
    mech.mechanism = CKM_TLS_MAC;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);

    rv = user_session_open(&session);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
                                      sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    }
    if (rv == CKR_OK)
        rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, tlsHandshakeHash,
                              sizeof(tlsHandshakeHash), mac, &macLen);
    }
    if (rv == CKR_OK && macLen != sizeof(mac))
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        rv = funcList->C_VerifyInit(session, &mech, key);
    CHECK_RV(rv, "TLS MAC sign and verify init", CKR_OK);

    if (rv == CKR_OK) {
        XMEMCPY(badMac, mac, sizeof(mac));
        badMac[0] ^= 0x01;
        watch_start(mac, sizeof(mac));
        if (multiPart) {
            rv = funcList->C_VerifyUpdate(session, tlsHandshakeHash,
                                          sizeof(tlsHandshakeHash));
            if (rv == CKR_OK)
                rv = funcList->C_VerifyFinal(session, badMac, sizeof(badMac));
        }
        else {
            rv = funcList->C_Verify(session, tlsHandshakeHash,
                                    sizeof(tlsHandshakeHash), badMac,
                                    sizeof(badMac));
        }
        clean = watch_stop_clean();
        CHECK_RV(rv, "TLS MAC verify rejects a wrong tag",
                 CKR_SIGNATURE_INVALID);
        CHECK_TRUE(clean, op);
    }

    funcList->C_Finalize(NULL);
}
#endif

int main(int argc, char* argv[])
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;

    (void)argc;
    (void)argv;
    (void)ckTrue;
    (void)ckFalse;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 secret scrub test ===\n");
#ifdef WOLFPKCS11_NO_STORE
    /* The user PIN set by token_setup does not survive C_Finalize. */
    printf("Skipped: needs the key store\n");
    return 77;
#endif

    /* Installed before the first library allocation. */
    if (wolfSSL_SetAllocators(scrub_malloc, scrub_free, scrub_realloc) != 0) {
        fprintf(stderr, "FAIL: wolfSSL_SetAllocators\n");
        return 1;
    }

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv == CKR_OK) {
        rv = token_setup(&slot);
        CHECK_RV(rv, "token setup", CKR_OK);
    }
    if (rv == CKR_OK) {
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
        cbc_buffered_scrub_test(CKM_AES_CBC_PAD, 0, 1, CKR_OK,
            "CBC-PAD buffered plaintext wiped after C_EncryptFinal");
        cbc_buffered_scrub_test(CKM_AES_CBC, 0, 1, CKR_DATA_LEN_RANGE,
            "CBC buffered plaintext wiped after a rejected C_EncryptFinal");
        cbc_buffered_scrub_test(CKM_AES_CBC_PAD, 0, 0, CKR_OK,
            "CBC-PAD buffered plaintext wiped when the session is freed");
        cbc_buffered_scrub_test(CKM_AES_CBC, 1, 1, CKR_DATA_LEN_RANGE,
            "CBC buffered input wiped after a rejected C_DecryptFinal");
        cbc_buffered_scrub_test(CKM_AES_CBC_PAD, 1, 1, CKR_OK,
            "CBC-PAD buffered block wiped after C_DecryptFinal");
#endif
#if !defined(NO_AES) && defined(HAVE_AESGCM) && !defined(WOLFSSL_AESGCM_STREAM)
        gcm_buffered_plaintext_scrub_test();
#endif
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_SHA256)
        tls_mac_verify_scrub_test(0,
            "TLS MAC expected value wiped after C_Verify");
        tls_mac_verify_scrub_test(1,
            "TLS MAC expected value wiped after C_VerifyFinal");
#endif
    }
    pkcs11_unload();

    return pkcs11_test_summary();
}
