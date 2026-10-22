/* legacy_class_load_test.c
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
 * Older releases stored secret keys derived from a template without CKA_CLASS
 * with no object class. A token holding such keys must load them as secret
 * keys that still work, and keep them loadable if they cannot be rebound to
 * the secret key class straight away. The DEBUG_WOLFPKCS11-only hooks build
 * those stored keys and check that an unknown store type gets no file name.
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
#include <wolfpkcs11/store.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/legacy_class_load_test"

#if defined(DEBUG_WOLFPKCS11) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(NO_AES) && defined(HAVE_AES_CBC)

/* DEBUG_WOLFPKCS11-only test hooks exported by libwolfpkcs11, with C linkage
 * as in wolfpkcs11/internal.h. */
#ifdef __cplusplus
extern "C" {
#endif
extern int WP11_Test_SetObjectClass(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_OBJECT_CLASS objClass);
#if !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_TPM_STORE)
extern int WP11_Test_StoreName(int type);
#endif
#ifdef __cplusplus
}
#endif

#if defined(USE_WOLFSSL_MEMORY) && !defined(NO_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
    #define ALLOC_HOOKS
#endif

/* The generic key re-encodes into a buffer of this length plus a tag, a size
 * nothing else allocates while logging in. */
#define ODD_KEY_LEN 91

#ifdef ALLOC_HOOKS
static size_t failSize = 0;

static void* hook_malloc(size_t sz)
{
    if (failSize != 0 && sz == failSize) {
        failSize = 0;
        return NULL;
    }
    return malloc(sz);
}

static void hook_free(void* ptr)
{
    free(ptr);
}

static void* hook_realloc(void* ptr, size_t sz)
{
    return realloc(ptr, sz);
}
#endif

static CK_SLOT_ID slot = 0;
static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "legacy-class-load";
static const char aesLabel[] = "legacy-aes";
static const char genLabel[] = "legacy-generic";

static CK_RV lib_init(void)
{
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_RV rv;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK)
        slot = slotList[0];
    return rv;
}

static CK_RV token_setup(void)
{
    CK_SESSION_HANDLE soSession = 0;
    unsigned char label[32];
    CK_RV rv;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin), label);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &soSession);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
        funcList->C_Logout(soSession);
    }
    if (soSession != 0)
        funcList->C_CloseSession(soSession);
    return rv;
}

static CK_RV user_login(CK_SESSION_HANDLE session)
{
    return funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                             (CK_ULONG)XSTRLEN(userPin));
}

static CK_RV open_user_session(CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
    if (rv == CKR_OK)
        rv = user_login(*session);
    return rv;
}

static CK_RV create_token_key(CK_SESSION_HANDLE session, CK_KEY_TYPE keyType,
                              const unsigned char* value, CK_ULONG len,
                              const char* label, CK_OBJECT_HANDLE* key)
{
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass,  sizeof(secretClass)        },
        { CKA_KEY_TYPE, &keyType,      sizeof(keyType)            },
        { CKA_VALUE,    (void*)value,  len                        },
        { CKA_TOKEN,    &ckTrue,       sizeof(ckTrue)             },
        { CKA_ENCRYPT,  &ckTrue,       sizeof(ckTrue)             },
        { CKA_LABEL,    (void*)label,  (CK_ULONG)XSTRLEN(label)   },
    };

    *key = CK_INVALID_HANDLE;
    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), key);
}

static CK_OBJECT_HANDLE find_key(CK_SESSION_HANDLE session, const char* label)
{
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_LABEL, (void*)label, (CK_ULONG)XSTRLEN(label) },
    };

    if (funcList->C_FindObjectsInit(session, tmpl, 1) == CKR_OK) {
        if (funcList->C_FindObjects(session, &key, 1, &count) != CKR_OK ||
                count != 1) {
            key = CK_INVALID_HANDLE;
        }
        funcList->C_FindObjectsFinal(session);
    }
    return key;
}

static CK_OBJECT_CLASS key_class(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE key)
{
    CK_OBJECT_CLASS objClass = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &objClass, sizeof(objClass) },
    };

    if (funcList->C_GetAttributeValue(session, key, tmpl, 1) != CKR_OK)
        objClass = CKO_DATA;
    return objClass;
}

static CK_RV encrypt_block(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                           unsigned char* out)
{
    unsigned char iv[16];
    unsigned char plain[16];
    CK_ULONG outLen = 16;
    CK_MECHANISM mech = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_RV rv;

    XMEMSET(iv, 0, sizeof(iv));
    XMEMSET(plain, 0x42, sizeof(plain));
    rv = funcList->C_EncryptInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, plain, sizeof(plain), out, &outLen);
    return rv;
}

static void run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE genKey = CK_INVALID_HANDLE;
    unsigned char aesValue[16];
    unsigned char genValue[ODD_KEY_LEN];
    unsigned char expect[16];
    unsigned char got[16];

    XMEMSET(aesValue, 0x5a, sizeof(aesValue));
    XMEMSET(genValue, 0x3c, sizeof(genValue));

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return;

    /* Store an AES and a generic secret key with no class. */
    rv = lib_init();
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv == CKR_OK) {
        rv = token_setup();
        CHECK_RV(rv, "token setup", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = open_user_session(&session);
        CHECK_RV(rv, "user session", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = create_token_key(session, CKK_AES, aesValue, sizeof(aesValue),
                              aesLabel, &aesKey);
        CHECK_RV(rv, "create AES token key", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = create_token_key(session, CKK_GENERIC_SECRET, genValue,
                              sizeof(genValue), genLabel, &genKey);
        CHECK_RV(rv, "create generic token key", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = encrypt_block(session, aesKey, expect);
        CHECK_RV(rv, "encrypt with AES key", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(WP11_Test_SetObjectClass(session, aesKey,
                       (CK_OBJECT_CLASS)-1) == 0, "store AES key with no class");
        CHECK_TRUE(WP11_Test_SetObjectClass(session, genKey,
                       (CK_OBJECT_CLASS)-1) == 0,
                   "store generic key with no class");
        CHECK_TRUE(key_class(session, aesKey) == (CK_OBJECT_CLASS)-1,
                   "AES key has no class");
        CHECK_TRUE(WP11_Test_SetObjectClass(session, CK_INVALID_HANDLE,
                       (CK_OBJECT_CLASS)-1) != 0, "no class for a bad handle");
    }
    funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);

    /* Load the token, failing the generic key's rebind once. */
    rv = lib_init();
    CHECK_RV(rv, "C_Initialize to load keys with no class", CKR_OK);
#ifdef ALLOC_HOOKS
    failSize = ODD_KEY_LEN + 16;
#endif
    if (rv == CKR_OK) {
        rv = open_user_session(&session);
        CHECK_RV(rv, "user session with keys with no class", CKR_OK);
    }
#ifdef ALLOC_HOOKS
    CHECK_TRUE(failSize == 0, "generic key rebind was attempted");
    failSize = 0;
#endif
    if (rv == CKR_OK) {
        aesKey = find_key(session, aesLabel);
        genKey = find_key(session, genLabel);
        CHECK_TRUE(key_class(session, aesKey) == CKO_SECRET_KEY,
                   "AES key loads as a secret key");
#ifdef ALLOC_HOOKS
        CHECK_TRUE(key_class(session, genKey) == (CK_OBJECT_CLASS)-1,
                   "generic key keeps its stored class when not rebound");
#endif
        XMEMSET(got, 0, sizeof(got));
        rv = encrypt_block(session, aesKey, got);
        CHECK_RV(rv, "encrypt with loaded AES key", CKR_OK);
        CHECK_TRUE(XMEMCMP(got, expect, sizeof(got)) == 0,
                   "loaded AES key gives the same ciphertext");
    }
    if (rv == CKR_OK) {
        funcList->C_Logout(session);
        rv = user_login(session);
        CHECK_RV(rv, "log in again", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(key_class(session, genKey) == CKO_SECRET_KEY,
                   "generic key is a secret key after logging in again");
    }
    funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);

    /* The secret key class was stored with the keys. */
    rv = lib_init();
    CHECK_RV(rv, "C_Initialize to load rebound keys", CKR_OK);
    if (rv == CKR_OK) {
        rv = open_user_session(&session);
        CHECK_RV(rv, "user session with rebound keys", CKR_OK);
    }
    if (rv == CKR_OK) {
        aesKey = find_key(session, aesLabel);
        genKey = find_key(session, genLabel);
        CHECK_TRUE(key_class(session, aesKey) == CKO_SECRET_KEY &&
                   key_class(session, genKey) == CKO_SECRET_KEY,
                   "rebound keys load as secret keys");
        XMEMSET(got, 0, sizeof(got));
        rv = encrypt_block(session, aesKey, got);
        CHECK_RV(rv, "encrypt with rebound AES key", CKR_OK);
        CHECK_TRUE(XMEMCMP(got, expect, sizeof(got)) == 0,
                   "rebound AES key gives the same ciphertext");
    }
#if !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_TPM_STORE)
    CHECK_TRUE(WP11_Test_StoreName(WOLFPKCS11_STORE_TOKEN) > 0,
               "token store file name");
    CHECK_TRUE(WP11_Test_StoreName(0x7f) == -1,
               "no store file name for an unknown type");
#endif
    funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);

    pkcs11_unload();
}

#endif

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#if !defined(DEBUG_WOLFPKCS11) || defined(WOLFPKCS11_NO_STORE) || \
    defined(NO_AES) || !defined(HAVE_AES_CBC)
    printf("Debug hooks or stored AES keys not available, skipping\n");
    return 77;  /* automake: test skipped */
#else
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
#ifdef ALLOC_HOOKS
    if (wolfSSL_SetAllocators(hook_malloc, hook_free, hook_realloc) != 0) {
        printf("FAIL: wolfSSL_SetAllocators\n");
        return 1;
    }
#endif

    printf("=== wolfPKCS11 legacy class load test ===\n");
    run_test();
    return pkcs11_test_summary();
#endif
}
