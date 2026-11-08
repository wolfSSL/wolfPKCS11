/* session_object_visibility_test.c
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
 * Session objects belong to the application: every session of it finds and
 * uses them, and they go away when the session that created them closes.
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
#include <wolfpkcs11/internal.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/session_object_visibility_test"

#if !defined(SINGLE_THREADED) && !defined(WOLFPKCS11_SINGLE_THREADED)
    #define VIS_TEST_THREADS
    #include <pthread.h>
#endif

#define RW_SESSION (CKF_SERIAL_SESSION | CKF_RW_SESSION)
#define THREAD_ROUNDS 200

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "session-visibility";
static CK_SLOT_ID slot = 0;
static CK_BBOOL ckFalse = CK_FALSE;
static CK_OBJECT_CLASS dataClass = CKO_DATA;
static char dataLabel[] = "probe-visibility";

static CK_RV token_setup(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE so = CK_INVALID_HANDLE;
    unsigned char label[32];

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK) {
        slot = slotList[0];
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, RW_SESSION, NULL, NULL, &so);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(so, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(so, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
        funcList->C_Logout(so);
    }
    if (so != CK_INVALID_HANDLE)
        funcList->C_CloseSession(so);
    return rv;
}

static CK_RV open_sessions(CK_SESSION_HANDLE* a, CK_SESSION_HANDLE* b)
{
    CK_RV rv;

    *a = CK_INVALID_HANDLE;
    *b = CK_INVALID_HANDLE;
    rv = funcList->C_OpenSession(slot, RW_SESSION, NULL, NULL, a);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, RW_SESSION, NULL, NULL, b);
    return rv;
}

static void close_session(CK_SESSION_HANDLE* session)
{
    if (*session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(*session);
    *session = CK_INVALID_HANDLE;
}

static CK_RV create_data(CK_SESSION_HANDLE session, CK_BBOOL priv,
                         CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass)     },
        { CKA_TOKEN,   &ckFalse,   sizeof(ckFalse)       },
        { CKA_PRIVATE, &priv,      sizeof(priv)          },
        { CKA_LABEL,   dataLabel,  sizeof(dataLabel) - 1 },
    };

    return funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), obj);
}

/* Find the data objects with the probe label; first gets the first match. */
static CK_RV find_first(CK_SESSION_HANDLE session, CK_ULONG* count,
                        CK_OBJECT_HANDLE* first)
{
    CK_RV rv;
    CK_OBJECT_HANDLE found[4];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass)     },
        { CKA_LABEL, dataLabel,  sizeof(dataLabel) - 1 },
    };

    *count = 0;
    rv = funcList->C_FindObjectsInit(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl));
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, found,
                sizeof(found) / sizeof(*found), count);
        funcList->C_FindObjectsFinal(session);
    }
    *first = (rv == CKR_OK && *count > 0) ? found[0] : CK_INVALID_HANDLE;
    return rv;
}

static CK_RV find_count(CK_SESSION_HANDLE session, CK_ULONG* count)
{
    CK_OBJECT_HANDLE first;

    return find_first(session, count, &first);
}

static CK_RV get_label(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                       char* label, CK_ULONG* len)
{
    CK_RV rv;
    CK_ATTRIBUTE attr;

    attr.type = CKA_LABEL;
    attr.pValue = label;
    attr.ulValueLen = *len;
    rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    *len = (rv == CKR_OK) ? attr.ulValueLen : 0;
    return rv;
}

/* Session B finds, reads, changes and copies an object session A created. */
static void other_session_uses_object_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    char label[32];
    CK_ULONG len = sizeof(label);
    char newLabel[] = "renamed";
    CK_ATTRIBUTE set = { CKA_LABEL, newLabel, sizeof(newLabel) - 1 };

    printf("--- another session uses a session object ---\n");
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK)
        rv = create_data(a, CK_FALSE, &obj);
    CHECK_RV(rv, "open sessions and create session object in A", CKR_OK);
    if (rv == CKR_OK) {
        rv = find_count(b, &count);
        CHECK_RV(rv, "find from B", CKR_OK);
        CHECK_TRUE(count == 1, "B finds A's session object");
        rv = get_label(b, obj, label, &len);
        CHECK_RV(rv, "B reads A's session object", CKR_OK);
        CHECK_TRUE(len == sizeof(dataLabel) - 1 &&
                   XMEMCMP(label, dataLabel, len) == 0, "B reads the label");
        rv = funcList->C_CopyObject(b, obj, NULL, 0, &copy);
        CHECK_RV(rv, "B copies A's session object", CKR_OK);
        rv = funcList->C_SetAttributeValue(b, obj, &set, 1);
        CHECK_RV(rv, "B changes A's session object", CKR_OK);
        len = sizeof(label);
        rv = get_label(a, obj, label, &len);
        CHECK_TRUE(rv == CKR_OK && len == sizeof(newLabel) - 1 &&
                   XMEMCMP(label, newLabel, len) == 0,
                   "A reads the label B set");
    }
    close_session(&a);
    if (copy != CK_INVALID_HANDLE) {
        len = sizeof(label);
        rv = get_label(b, copy, label, &len);
        CHECK_RV(rv, "B's copy outlives A", CKR_OK);
        rv = funcList->C_DestroyObject(b, copy);
        CHECK_RV(rv, "destroy B's copy", CKR_OK);
    }
    if (obj != CK_INVALID_HANDLE) {
        len = sizeof(label);
        rv = get_label(b, obj, label, &len);
        CHECK_RV(rv, "A's object handle after A closed",
                 CKR_OBJECT_HANDLE_INVALID);
        rv = find_count(b, &count);
        CHECK_TRUE(rv == CKR_OK && count == 0,
                   "B no longer finds A's object");
    }
    close_session(&b);
}

/* A read-only session destroys another session's session object. */
static void read_only_destroy_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE ro = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG count = 1;

    printf("--- read-only session destroys another session's object ---\n");
    rv = funcList->C_OpenSession(slot, RW_SESSION, NULL, NULL, &a);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
                                     &ro);
    if (rv == CKR_OK)
        rv = create_data(a, CK_FALSE, &obj);
    CHECK_RV(rv, "open sessions and create session object", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_DestroyObject(ro, obj);
        CHECK_RV(rv, "read-only session destroys it", CKR_OK);
        rv = find_count(a, &count);
        CHECK_TRUE(rv == CKR_OK && count == 0, "creator no longer finds it");
    }
    close_session(&ro);
    close_session(&a);
}

/* A session freed on close takes its objects with it. */
static void dynamic_session_close_test(void)
{
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE held[WP11_SESSION_CNT_MIN];
    CK_SESSION_HANDLE c = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG count = 1;
    char label[32];
    CK_ULONG len = sizeof(label);
    int i;

    printf("--- objects of a freed session go with it ---\n");
    if (WP11_SESSION_CNT_MIN + 1 > WP11_SESSION_CNT_MAX) {
        printf("No session beyond the minimum allowed, skipping\n");
        return;
    }
    /* Sessions past the minimum are freed when closed. */
    for (i = 0; i < WP11_SESSION_CNT_MIN; i++) {
        held[i] = CK_INVALID_HANDLE;
        if (rv == CKR_OK) {
            rv = funcList->C_OpenSession(slot, RW_SESSION, NULL, NULL,
                                         &held[i]);
        }
    }
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, RW_SESSION, NULL, NULL, &c);
    if (rv == CKR_OK)
        rv = create_data(c, CK_FALSE, &obj);
    CHECK_RV(rv, "open sessions and create object in the last", CKR_OK);
    if (rv == CKR_OK) {
        close_session(&c);
        rv = get_label(held[WP11_SESSION_CNT_MIN - 1], obj, label, &len);
        CHECK_RV(rv, "handle after its session closed",
                 CKR_OBJECT_HANDLE_INVALID);
        rv = funcList->C_DestroyObject(held[WP11_SESSION_CNT_MIN - 1], obj);
        CHECK_RV(rv, "destroy after its session closed",
                 CKR_OBJECT_HANDLE_INVALID);
        rv = find_count(held[0], &count);
        CHECK_TRUE(rv == CKR_OK && count == 0, "object no longer found");
    }
    close_session(&c);
    for (i = 0; i < WP11_SESSION_CNT_MIN; i++)
        close_session(&held[i]);
}

/* Each session finds its own matching objects before other sessions'. */
static void find_order_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_OBJECT_HANDLE objA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE objB = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE first = CK_INVALID_HANDLE;
    CK_ULONG count = 0;

    printf("--- own session objects are found first ---\n");
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK)
        rv = create_data(a, CK_FALSE, &objA);
    if (rv == CKR_OK)
        rv = create_data(b, CK_FALSE, &objB);
    CHECK_RV(rv, "create one object in each session", CKR_OK);
    if (rv == CKR_OK) {
        rv = find_first(a, &count, &first);
        CHECK_TRUE(rv == CKR_OK && count == 2 && first == objA,
                   "A finds both, its own first");
        rv = find_first(b, &count, &first);
        CHECK_TRUE(rv == CKR_OK && count == 2 && first == objB,
                   "B finds both, its own first");
    }
    close_session(&b);
    close_session(&a);
}

#ifndef WOLFPKCS11_NSS
/* Private session objects follow the application's login state. */
static void private_object_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    char label[32];
    CK_ULONG len = sizeof(label);

    printf("--- private session objects ---\n");
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(a, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    if (rv == CKR_OK)
        rv = create_data(a, CK_TRUE, &obj);
    CHECK_RV(rv, "log in and create private session object", CKR_OK);
    if (rv == CKR_OK) {
        rv = find_count(b, &count);
        CHECK_TRUE(rv == CKR_OK && count == 1,
                   "B finds the private object while logged in");
        rv = funcList->C_Logout(b);
        CHECK_RV(rv, "log out from B", CKR_OK);
        rv = find_count(a, &count);
        CHECK_TRUE(rv == CKR_OK && count == 0,
                   "A no longer finds it after logout");
        rv = get_label(b, obj, label, &len);
        CHECK_RV(rv, "B's handle after logout", CKR_OBJECT_HANDLE_INVALID);
    }
    close_session(&b);
    close_session(&a);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AESGCM)
static CK_BBOOL ckTrue = CK_TRUE;
static CK_KEY_TYPE aesKeyType = CKK_AES;
static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;

static CK_RV create_aes_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesKeyType,  sizeof(aesKeyType)  },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
    };

    return funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), key);
}

static void gcm_mech(CK_MECHANISM* mech, CK_GCM_PARAMS* gcm, byte* iv)
{
    XMEMSET(iv, 0x42, 12);
    XMEMSET(gcm, 0, sizeof(*gcm));
    gcm->pIv = iv;
    gcm->ulIvLen = 12;
    gcm->ulIvBits = 96;
    gcm->ulTagBits = 128;
    mech->mechanism = CKM_AES_GCM;
    mech->pParameter = gcm;
    mech->ulParameterLen = sizeof(*gcm);
}

/* B encrypts with A's key; closing A ends B's operation on that key. */
static void other_session_key_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_GCM_PARAMS gcm;
    byte iv[12];
    byte plain[32];
    byte enc[64];
    CK_ULONG encLen = sizeof(enc);

    printf("--- another session uses a session key ---\n");
    XMEMSET(plain, 0x11, sizeof(plain));
    gcm_mech(&mech, &gcm, iv);
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK)
        rv = create_aes_key(a, &key);
    CHECK_RV(rv, "create AES session key in A", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_EncryptInit(b, &mech, key);
        if (rv == CKR_OK) {
            rv = funcList->C_Encrypt(b, plain, sizeof(plain), enc, &encLen);
        }
        CHECK_RV(rv, "B encrypts with A's key", CKR_OK);
        rv = funcList->C_EncryptInit(b, &mech, key);
        CHECK_RV(rv, "B starts another encryption", CKR_OK);
        close_session(&a);
        encLen = sizeof(enc);
        rv = funcList->C_Encrypt(b, plain, sizeof(plain), enc, &encLen);
        CHECK_RV(rv, "B's operation after A closed",
                 CKR_OPERATION_NOT_INITIALIZED);
    }
    close_session(&b);
    close_session(&a);
}

/* Closing all sessions while one's operation uses another's key. */
static void close_all_with_shared_key_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_GCM_PARAMS gcm;
    byte iv[12];
    byte plain[32];
    byte enc[64];
    CK_ULONG encLen = sizeof(enc);

    printf("--- close all sessions while a shared key is in use ---\n");
    XMEMSET(plain, 0x11, sizeof(plain));
    gcm_mech(&mech, &gcm, iv);
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK)
        rv = create_aes_key(a, &key);
    if (rv == CKR_OK)
        rv = funcList->C_EncryptInit(b, &mech, key);
    CHECK_RV(rv, "B starts encrypting with A's key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_CloseAllSessions(slot);
        CHECK_RV(rv, "close all sessions", CKR_OK);
        rv = funcList->C_Encrypt(b, plain, sizeof(plain), enc, &encLen);
        CHECK_RV(rv, "B's operation after close all",
                 CKR_SESSION_HANDLE_INVALID);
        a = CK_INVALID_HANDLE;
        b = CK_INVALID_HANDLE;
    }
    close_session(&b);
    close_session(&a);
}
#endif

#ifdef DEBUG_WOLFPKCS11
static CK_SESSION_HANDLE hookSession = CK_INVALID_HANDLE;
static CK_RV hookRv = CKR_GENERAL_ERROR;

/* Runs inside another session's call once it has found the object. */
static void hook_close(void)
{
    WP11_Object_SetFindHook(NULL);
    hookRv = funcList->C_CloseSession(hookSession);
}

static CK_SESSION_HANDLE hookDestroySession = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE hookObject = CK_INVALID_HANDLE;
static CK_RV hookDestroyRv = CKR_GENERAL_ERROR;

/* Runs inside a destroy once it has found the object. */
static void hook_destroy_close(void)
{
    WP11_Object_SetFindHook(NULL);
    hookDestroyRv = funcList->C_DestroyObject(hookDestroySession, hookObject);
    hookRv = funcList->C_CloseSession(hookSession);
}

/* A destroy that found the object before another session destroyed it, and
 * before its creator closed, finds it gone. */
static void destroy_after_close_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_SESSION_HANDLE c = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;

    printf("--- destroy races another destroy and the creator's close ---\n");
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, RW_SESSION, NULL, NULL, &c);
    if (rv == CKR_OK)
        rv = create_data(c, CK_FALSE, &obj);
    CHECK_RV(rv, "open sessions and create object", CKR_OK);
    if (rv == CKR_OK) {
        hookSession = c;
        hookDestroySession = a;
        hookObject = obj;
        hookRv = CKR_GENERAL_ERROR;
        hookDestroyRv = CKR_GENERAL_ERROR;
        WP11_Object_SetFindHook(hook_destroy_close);
        rv = funcList->C_DestroyObject(b, obj);
        WP11_Object_SetFindHook(NULL);
        c = CK_INVALID_HANDLE;
        CHECK_RV(hookDestroyRv, "other destroy inside the call", CKR_OK);
        CHECK_RV(hookRv, "C_CloseSession inside the call", CKR_OK);
        CHECK_RV(rv, "first destroy completes", CKR_OBJECT_HANDLE_INVALID);
    }
    close_session(&c);
    close_session(&b);
    close_session(&a);
}

/* Closing the creating session while another session's call uses its object
 * keeps the object until the call ends. */
static void close_during_call_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_SESSION_HANDLE c = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    char label[32];
    CK_ULONG len = sizeof(label);

    printf("--- creator closes during another session's call ---\n");
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, RW_SESSION, NULL, NULL, &c);
    if (rv == CKR_OK)
        rv = create_data(c, CK_FALSE, &obj);
    CHECK_RV(rv, "open sessions and create object", CKR_OK);
    if (rv == CKR_OK) {
        hookSession = c;
        hookRv = CKR_GENERAL_ERROR;
        WP11_Object_SetFindHook(hook_close);
        rv = get_label(b, obj, label, &len);
        WP11_Object_SetFindHook(NULL);
        c = CK_INVALID_HANDLE;
        CHECK_RV(hookRv, "C_CloseSession inside the call", CKR_OK);
        CHECK_RV(rv, "call completes", CKR_OK);
        CHECK_TRUE(len == sizeof(dataLabel) - 1 &&
                   XMEMCMP(label, dataLabel, len) == 0,
                   "call reads the object it found");
        len = sizeof(label);
        rv = get_label(b, obj, label, &len);
        CHECK_RV(rv, "handle after the call", CKR_OBJECT_HANDLE_INVALID);
    }
    close_session(&c);
    close_session(&b);
    close_session(&a);
}
#endif

#if defined(DEBUG_WOLFPKCS11) && defined(HAVE_ECC) && !defined(WOLFPKCS11_NSS)
static char pubLabel[] = "rollback-pub";
static int hookAddCalls = 0;

/* Before the private key is added, another session destroys the public key
 * and logs out, so the private key add fails. */
static void hook_add_destroy(void)
{
    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl = { CKA_LABEL, pubLabel, sizeof(pubLabel) - 1 };

    if (++hookAddCalls != 2)
        return;
    WP11_Session_SetAddObjectHook(NULL);
    hookDestroyRv = funcList->C_FindObjectsInit(hookDestroySession, &tmpl, 1);
    if (hookDestroyRv == CKR_OK) {
        hookDestroyRv = funcList->C_FindObjects(hookDestroySession, &found, 1,
                                                &count);
        funcList->C_FindObjectsFinal(hookDestroySession);
    }
    if (hookDestroyRv == CKR_OK && count != 1)
        hookDestroyRv = CKR_GENERAL_ERROR;
    if (hookDestroyRv == CKR_OK)
        hookDestroyRv = funcList->C_DestroyObject(hookDestroySession, found);
    hookRv = funcList->C_Logout(hookDestroySession);
}

/* A key pair whose second add fails takes back only the key still there. */
static void keypair_rollback_after_destroy_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_PRIVATE,   &ckFalse,        sizeof(ckFalse)         },
        { CKA_VERIFY,    &yes,            sizeof(yes)             },
        { CKA_LABEL,     pubLabel,        sizeof(pubLabel) - 1    },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &ckFalse, sizeof(ckFalse) },
        { CKA_PRIVATE, &yes,     sizeof(yes)     },
        { CKA_SIGN,    &yes,     sizeof(yes)     },
    };

    printf("--- key pair rollback after another session destroyed a key ---\n");
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(a, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    CHECK_RV(rv, "open sessions and log in", CKR_OK);
    if (rv == CKR_OK) {
        hookDestroySession = b;
        hookDestroyRv = CKR_GENERAL_ERROR;
        hookRv = CKR_GENERAL_ERROR;
        hookAddCalls = 0;
        WP11_Session_SetAddObjectHook(hook_add_destroy);
        rv = funcList->C_GenerateKeyPair(a, &mech, pubTmpl,
                sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
                sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
        WP11_Session_SetAddObjectHook(NULL);
        CHECK_RV(hookDestroyRv, "B destroys the public key", CKR_OK);
        CHECK_RV(hookRv, "B logs out", CKR_OK);
        CHECK_RV(rv, "C_GenerateKeyPair", CKR_USER_NOT_LOGGED_IN);
        CHECK_TRUE(pub == CK_INVALID_HANDLE && priv == CK_INVALID_HANDLE,
                   "no handles returned");
    }
    close_session(&b);
    close_session(&a);
}
#endif

#ifdef VIS_TEST_THREADS
typedef struct ShareArg {
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE obj;
    CK_RV rv;
} ShareArg;

/* Read the label over and over. */
static void* read_thread(void* p)
{
    ShareArg* arg = (ShareArg*)p;
    char label[64];
    CK_ULONG len;
    int i;

    for (i = 0; i < THREAD_ROUNDS && arg->rv == CKR_OK; i++) {
        len = sizeof(label);
        arg->rv = get_label(arg->session, arg->obj, label, &len);
    }
    return NULL;
}

/* Change the label to a new length each round. */
static void* write_thread(void* p)
{
    ShareArg* arg = (ShareArg*)p;
    char label[40];
    CK_ATTRIBUTE attr;
    int i;

    XMEMSET(label, 'w', sizeof(label));
    attr.type = CKA_LABEL;
    attr.pValue = label;
    for (i = 0; i < THREAD_ROUNDS && arg->rv == CKR_OK; i++) {
        attr.ulValueLen = 1 + (CK_ULONG)(i % (int)sizeof(label));
        arg->rv = funcList->C_SetAttributeValue(arg->session, arg->obj, &attr,
                                                1);
    }
    return NULL;
}

/* Two threads on two sessions read and change one session object. */
static void shared_object_threads_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a;
    CK_SESSION_HANDLE b;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    pthread_t reader;
    pthread_t writer;
    ShareArg readArg;
    ShareArg writeArg;

    printf("--- threads share a session object ---\n");
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK)
        rv = create_data(a, CK_FALSE, &obj);
    CHECK_RV(rv, "open sessions and create object", CKR_OK);
    if (rv == CKR_OK) {
        readArg.session = b;
        readArg.obj = obj;
        readArg.rv = CKR_OK;
        writeArg.session = a;
        writeArg.obj = obj;
        writeArg.rv = CKR_OK;
        if (pthread_create(&reader, NULL, read_thread, &readArg) != 0) {
            rv = CKR_GENERAL_ERROR;
        }
        else {
            if (pthread_create(&writer, NULL, write_thread, &writeArg) != 0)
                writeArg.rv = CKR_GENERAL_ERROR;
            else
                pthread_join(writer, NULL);
            pthread_join(reader, NULL);
        }
        CHECK_RV(rv, "start threads", CKR_OK);
        CHECK_RV(readArg.rv, "reader on B", CKR_OK);
        CHECK_RV(writeArg.rv, "writer on A", CKR_OK);
    }
    close_session(&b);
    close_session(&a);
}
#endif

#if defined(VIS_TEST_THREADS) && !defined(NO_RSA)
#define RSA_ROUNDS 20
#define CHURN_ROUNDS 50

typedef struct DecArg {
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    byte* enc;
    CK_ULONG encLen;
    byte* plain;
    CK_ULONG plainLen;
    CK_RV rv;
} DecArg;

/* Decrypt with the shared key, which takes its lock for writing. */
static void* decrypt_thread(void* p)
{
    DecArg* arg = (DecArg*)p;
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    byte dec[256];
    CK_ULONG decLen;
    int i;

    for (i = 0; i < RSA_ROUNDS && arg->rv == CKR_OK; i++) {
        decLen = sizeof(dec);
        arg->rv = funcList->C_DecryptInit(arg->session, &mech, arg->key);
        if (arg->rv == CKR_OK) {
            arg->rv = funcList->C_Decrypt(arg->session, arg->enc, arg->encLen,
                                          dec, &decLen);
        }
        if (arg->rv == CKR_OK && (decLen != arg->plainLen ||
                XMEMCMP(dec, arg->plain, decLen) != 0)) {
            arg->rv = CKR_GENERAL_ERROR;
        }
    }
    return NULL;
}

/* Create, find and destroy session objects while the keys are in use. */
static void* churn_thread(void* p)
{
    ShareArg* arg = (ShareArg*)p;
    CK_OBJECT_HANDLE obj;
    CK_ULONG count;
    int i;

    for (i = 0; i < CHURN_ROUNDS && arg->rv == CKR_OK; i++) {
        arg->rv = create_data(arg->session, CK_FALSE, &obj);
        if (arg->rv == CKR_OK)
            arg->rv = find_count(arg->session, &count);
        if (arg->rv == CKR_OK)
            arg->rv = funcList->C_DestroyObject(arg->session, obj);
    }
    return NULL;
}

/* Two sessions decrypt with a third's RSA key while a fourth changes the
 * object lists. */
static void shared_key_threads_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE a = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE b = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE c = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE d = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_DECRYPT,          &yes,              sizeof(yes)               },
        { CKA_TOKEN,            &ckFalse,          sizeof(ckFalse)           },
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
        { CKA_CLASS,           &pubClass,        sizeof(pubClass)         },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
        { CKA_ENCRYPT,         &yes,             sizeof(yes)              },
        { CKA_TOKEN,           &ckFalse,         sizeof(ckFalse)          },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
    byte plain[32];
    byte enc[256];
    CK_ULONG encLen = sizeof(enc);
    pthread_t th[3];
    DecArg dec[2];
    ShareArg churn;
    int started = 0;
    int i;

    printf("--- threads decrypt with a shared RSA key during churn ---\n");
    XMEMSET(plain, 0x5a, sizeof(plain));
    rv = open_sessions(&a, &b);
    if (rv == CKR_OK)
        rv = open_sessions(&c, &d);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(a, privTmpl,
                sizeof(privTmpl) / sizeof(*privTmpl), &priv);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(a, pubTmpl,
                sizeof(pubTmpl) / sizeof(*pubTmpl), &pub);
    }
    if (rv == CKR_OK)
        rv = funcList->C_EncryptInit(a, &mech, pub);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(a, plain, sizeof(plain), enc, &encLen);
    CHECK_RV(rv, "create RSA keys in A and encrypt", CKR_OK);
    if (rv == CKR_OK) {
        for (i = 0; i < 2; i++) {
            dec[i].session = (i == 0) ? b : c;
            dec[i].key = priv;
            dec[i].enc = enc;
            dec[i].encLen = encLen;
            dec[i].plain = plain;
            dec[i].plainLen = sizeof(plain);
            dec[i].rv = CKR_OK;
        }
        churn.session = d;
        churn.obj = CK_INVALID_HANDLE;
        churn.rv = CKR_OK;
        for (i = 0; i < 2 && rv == CKR_OK; i++) {
            if (pthread_create(&th[i], NULL, decrypt_thread, &dec[i]) != 0)
                rv = CKR_GENERAL_ERROR;
            else
                started++;
        }
        if (rv == CKR_OK) {
            if (pthread_create(&th[2], NULL, churn_thread, &churn) != 0)
                rv = CKR_GENERAL_ERROR;
            else
                pthread_join(th[2], NULL);
        }
        for (i = 0; i < started; i++)
            pthread_join(th[i], NULL);
        CHECK_RV(rv, "start threads", CKR_OK);
        CHECK_RV(dec[0].rv, "decrypt on B", CKR_OK);
        CHECK_RV(dec[1].rv, "decrypt on C", CKR_OK);
        CHECK_RV(churn.rv, "object churn on D", CKR_OK);
    }
    close_session(&d);
    close_session(&c);
    close_session(&b);
    close_session(&a);
}
#endif

int main(int argc, char* argv[])
{
    CK_RV rv;

    (void)argc;
    (void)argv;

    if (WP11_SESSION_CNT_MAX < 4) {
        printf("Fewer than four sessions allowed, skipping test\n");
        return 77;
    }

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 session object visibility test ===\n");
    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv == CKR_OK) {
        rv = token_setup();
        CHECK_RV(rv, "token setup", CKR_OK);
    }
    if (rv == CKR_OK) {
        other_session_uses_object_test();
        read_only_destroy_test();
        dynamic_session_close_test();
        find_order_test();
#ifndef WOLFPKCS11_NSS
        private_object_test();
#endif
#if !defined(NO_AES) && defined(HAVE_AESGCM)
        other_session_key_test();
        close_all_with_shared_key_test();
#endif
#ifdef DEBUG_WOLFPKCS11
        close_during_call_test();
        destroy_after_close_test();
#endif
#if defined(DEBUG_WOLFPKCS11) && defined(HAVE_ECC) && !defined(WOLFPKCS11_NSS)
        keypair_rollback_after_destroy_test();
#endif
#ifdef VIS_TEST_THREADS
        shared_object_threads_test();
#ifndef NO_RSA
        shared_key_threads_test();
#endif
#endif
    }
    if (funcList != NULL)
        funcList->C_Finalize(NULL);
    pkcs11_unload();
    return pkcs11_test_summary();
}
