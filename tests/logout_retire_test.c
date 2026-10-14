/* logout_retire_test.c
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
 * Checks that logging out clears the key material of private session objects
 * and that the objects it retires do not pile up across login cycles.
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

#define TEST_DIR "./store/logout_retire_test"

#if defined(DEBUG_WOLFPKCS11) && !defined(SINGLE_THREADED) && \
    !defined(WOLFPKCS11_SINGLE_THREADED)
    #define RETIRE_TEST_THREADS
    #include <pthread.h>
#endif

#ifndef WOLFPKCS11_NSS

#define RETIRE_CYCLES 40
#define RETIRE_SETTLE 5

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "logout-retire";
static unsigned char keyValue[32] = "logout-retire-secret-key-012345";

/* Every live block is linked through its header so it can be scanned. */
typedef struct TrackHdr {
    struct TrackHdr* prev;
    struct TrackHdr* next;
    size_t sz;
} TrackHdr;

#define TRACK_HDR_SZ 32

static TrackHdr* liveHead = NULL;
static long liveBlocks = 0;
#ifdef RETIRE_TEST_THREADS
static pthread_mutex_t trackMutex = PTHREAD_MUTEX_INITIALIZER;
#define TRACK_LOCK()   pthread_mutex_lock(&trackMutex)
#define TRACK_UNLOCK() pthread_mutex_unlock(&trackMutex)
#else
#define TRACK_LOCK()
#define TRACK_UNLOCK()
#endif

static void* track_malloc(size_t sz)
{
    unsigned char* p = (unsigned char*)malloc(sz + TRACK_HDR_SZ);
    TrackHdr* hdr;

    if (p == NULL)
        return NULL;
    memset(p, 0, sz + TRACK_HDR_SZ);
    hdr = (TrackHdr*)p;
    hdr->sz = sz;
    TRACK_LOCK();
    hdr->next = liveHead;
    if (liveHead != NULL)
        liveHead->prev = hdr;
    liveHead = hdr;
    liveBlocks++;
    TRACK_UNLOCK();
    return p + TRACK_HDR_SZ;
}

static void track_free(void* ptr)
{
    TrackHdr* hdr;

    if (ptr == NULL)
        return;
    hdr = (TrackHdr*)((unsigned char*)ptr - TRACK_HDR_SZ);
    TRACK_LOCK();
    if (hdr->prev != NULL)
        hdr->prev->next = hdr->next;
    else
        liveHead = hdr->next;
    if (hdr->next != NULL)
        hdr->next->prev = hdr->prev;
    liveBlocks--;
    TRACK_UNLOCK();
    /* Poison so a use after free reads garbage, not the old key. */
    memset(ptr, 0xA5, hdr->sz);
    free(hdr);
}

static void* track_realloc(void* ptr, size_t sz)
{
    void* np;
    size_t old;

    if (ptr == NULL)
        return track_malloc(sz);
    np = track_malloc(sz);
    if (np == NULL)
        return NULL;
    old = ((TrackHdr*)((unsigned char*)ptr - TRACK_HDR_SZ))->sz;
    memcpy(np, ptr, old < sz ? old : sz);
    track_free(ptr);
    return np;
}

static int live_holds_key(void)
{
    TrackHdr* hdr;
    unsigned char* buf;
    size_t i;
    int found = 0;

    TRACK_LOCK();
    for (hdr = liveHead; hdr != NULL; hdr = hdr->next) {
        buf = (unsigned char*)hdr + TRACK_HDR_SZ;
        for (i = 0; hdr->sz >= sizeof(keyValue) &&
                i <= hdr->sz - sizeof(keyValue); i++) {
            if (memcmp(buf + i, keyValue, sizeof(keyValue)) == 0)
                found = 1;
        }
    }
    TRACK_UNLOCK();
    return found;
}

static CK_RV token_setup(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE soSession = CK_INVALID_HANDLE;
    unsigned char label[32];

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
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
    if (soSession != CK_INVALID_HANDLE)
        funcList->C_CloseSession(soSession);
    return rv;
}

static CK_RV create_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType,  sizeof(keyType)  },
        { CKA_TOKEN,    &no,       sizeof(no)       },
        { CKA_PRIVATE,  &yes,      sizeof(yes)      },
        { CKA_SENSITIVE, &no,      sizeof(no)       },
        { CKA_EXTRACTABLE, &yes,   sizeof(yes)      },
        { CKA_VALUE,    keyValue,  sizeof(keyValue) },
    };

    return funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), key);
}

static CK_RV login_create_key(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE* key)
{
    CK_RV rv;

    rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                           (CK_ULONG)XSTRLEN(userPin));
    if (rv == CKR_OK)
        rv = create_key(session, key);
    return rv;
}

/* A private session key's bytes must not stay in memory after C_Logout. */
static void logout_clears_retired_key_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;

    printf("--- logout clears retired session key material ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK)
        rv = login_create_key(session, &key);
    CHECK_RV(rv, "log in and create private session key", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(live_holds_key(), "key bytes held while logged in");
        rv = funcList->C_Logout(session);
        CHECK_RV(rv, "C_Logout", CKR_OK);
        CHECK_TRUE(!live_holds_key(), "no key bytes left after logout");
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

/* Login, create and logout cycles on one session keep memory use flat. */
static void retired_objects_bounded_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    long settled = 0;
    int i;

    printf("--- retired session objects stay bounded ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    for (i = 0; rv == CKR_OK && i < RETIRE_CYCLES; i++) {
        rv = login_create_key(session, &key);
        if (rv == CKR_OK)
            rv = funcList->C_Logout(session);
        if (i == RETIRE_SETTLE)
            settled = liveBlocks;
    }
    CHECK_RV(rv, "login, create and logout cycles", CKR_OK);
    if (rv == CKR_OK) {
        if (liveBlocks > settled) {
            fprintf(stderr, "  live blocks grew from %ld to %ld\n", settled,
                    liveBlocks);
        }
        CHECK_TRUE(liveBlocks <= settled, "retired objects do not accumulate");
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

#ifdef DEBUG_WOLFPKCS11
extern void WP11_Object_SetFindHook(void (*hook)(void));
extern void WP11_Session_SetAddObjectHook(void (*hook)(void));

static CK_SESSION_HANDLE hookLogoutSession = CK_INVALID_HANDLE;
static CK_RV hookLogoutRv = CKR_GENERAL_ERROR;

/* Runs inside C_GetAttributeValue once it holds the object pointer. */
static void hook_logout(void)
{
    WP11_Object_SetFindHook(NULL);
    hookLogoutRv = funcList->C_Logout(hookLogoutSession);
}

static CK_SESSION_HANDLE hookDestroySession = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE hookDestroyObject = CK_INVALID_HANDLE;
static CK_RV hookDestroyRv = CKR_GENERAL_ERROR;

/* Runs inside C_GetAttributeValue once it holds the object pointer. */
static void hook_destroy(void)
{
    WP11_Object_SetFindHook(NULL);
    hookDestroyRv = funcList->C_DestroyObject(hookDestroySession,
                                              hookDestroyObject);
}

/* Destroying a key while a call uses it must not free it under that call. */
static void destroy_during_call_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    unsigned char value[sizeof(keyValue)];
    CK_ATTRIBUTE valAttr = { CKA_VALUE, value, sizeof(value) };

    printf("--- destroy during a call keeps the key until the call ends ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK)
        rv = login_create_key(session, &key);
    CHECK_RV(rv, "log in and create session key", CKR_OK);
    if (rv == CKR_OK) {
        hookDestroySession = session;
        hookDestroyObject = key;
        hookDestroyRv = CKR_GENERAL_ERROR;
        XMEMSET(value, 0, sizeof(value));
        WP11_Object_SetFindHook(hook_destroy);
        rv = funcList->C_GetAttributeValue(session, key, &valAttr, 1);
        WP11_Object_SetFindHook(NULL);
        CHECK_RV(hookDestroyRv, "C_DestroyObject inside the call", CKR_OK);
        CHECK_RV(rv, "C_GetAttributeValue", CKR_OK);
        CHECK_TRUE(rv == CKR_OK && valAttr.ulValueLen == sizeof(keyValue) &&
                   XMEMCMP(value, keyValue, sizeof(keyValue)) == 0,
                   "call reads the intact key");
        CHECK_TRUE(!live_holds_key(), "key freed once the call ends");
        funcList->C_Logout(session);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

/* A logout while a call uses a private session key must not free the key. */
static void logout_during_call_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    unsigned char value[sizeof(keyValue)];
    CK_ATTRIBUTE valAttr = { CKA_VALUE, value, sizeof(value) };

    printf("--- logout during a call keeps the key until the call ends ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &other);
    }
    if (rv == CKR_OK)
        rv = login_create_key(session, &key);
    CHECK_RV(rv, "log in and create private session key", CKR_OK);
    if (rv == CKR_OK) {
        hookLogoutSession = other;
        hookLogoutRv = CKR_GENERAL_ERROR;
        XMEMSET(value, 0, sizeof(value));
        WP11_Object_SetFindHook(hook_logout);
        rv = funcList->C_GetAttributeValue(session, key, &valAttr, 1);
        WP11_Object_SetFindHook(NULL);
        CHECK_RV(hookLogoutRv, "C_Logout inside the call", CKR_OK);
        CHECK_RV(rv, "C_GetAttributeValue", CKR_OK);
        CHECK_TRUE(rv == CKR_OK && valAttr.ulValueLen == sizeof(keyValue) &&
                   XMEMCMP(value, keyValue, sizeof(keyValue)) == 0,
                   "call reads the intact key");
        CHECK_TRUE(!live_holds_key(), "key freed once the call ends");
    }
    if (other != CK_INVALID_HANDLE)
        funcList->C_CloseSession(other);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

/* A logout while C_DestroyObject holds the key leaves one owner of the key. */
static void logout_during_destroy_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;

    printf("--- logout during destroy frees the key once ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &other);
    }
    if (rv == CKR_OK)
        rv = login_create_key(session, &key);
    CHECK_RV(rv, "log in and create private session key", CKR_OK);
    if (rv == CKR_OK) {
        hookLogoutSession = other;
        hookLogoutRv = CKR_GENERAL_ERROR;
        WP11_Object_SetFindHook(hook_logout);
        rv = funcList->C_DestroyObject(session, key);
        WP11_Object_SetFindHook(NULL);
        CHECK_RV(hookLogoutRv, "C_Logout inside C_DestroyObject", CKR_OK);
        CHECK_RV(rv, "C_DestroyObject of the retired key",
                 CKR_OBJECT_HANDLE_INVALID);
        CHECK_TRUE(!live_holds_key(), "key freed once the call ends");
    }
    if (other != CK_INVALID_HANDLE)
        funcList->C_CloseSession(other);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

static CK_SESSION_HANDLE hookCloseSession = CK_INVALID_HANDLE;
static CK_RV hookCloseRv = CKR_GENERAL_ERROR;
static int hookCloseKeyLive = 0;

/* Runs inside C_GetAttributeValue on another session's object. */
static void hook_logout_close(void)
{
    WP11_Object_SetFindHook(NULL);
    hookLogoutRv = funcList->C_Logout(hookLogoutSession);
    hookCloseRv = funcList->C_CloseSession(hookCloseSession);
    hookCloseKeyLive = live_holds_key();
}

/* Closing a session with a retired key keeps it until the running call ends. */
static void close_with_retired_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_OBJECT_CLASS cls;
    CK_BBOOL no = CK_FALSE;
    unsigned char dataValue[] = "hold";
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &no,        sizeof(no)        },
        { CKA_PRIVATE, &no,        sizeof(no)        },
        { CKA_VALUE,   dataValue,  sizeof(dataValue) },
    };
    CK_ATTRIBUTE clsAttr = { CKA_CLASS, &cls, sizeof(cls) };

    printf("--- close session with retired key during a call ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &other);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(other, dataTmpl,
                sizeof(dataTmpl) / sizeof(*dataTmpl), &data);
    }
    if (rv == CKR_OK)
        rv = login_create_key(session, &key);
    CHECK_RV(rv, "log in and create private session key", CKR_OK);
    if (rv == CKR_OK) {
        hookLogoutSession = other;
        hookCloseSession = session;
        hookLogoutRv = CKR_GENERAL_ERROR;
        hookCloseRv = CKR_GENERAL_ERROR;
        hookCloseKeyLive = 0;
        WP11_Object_SetFindHook(hook_logout_close);
        rv = funcList->C_GetAttributeValue(other, data, &clsAttr, 1);
        WP11_Object_SetFindHook(NULL);
        session = CK_INVALID_HANDLE;
        CHECK_RV(hookLogoutRv, "C_Logout inside the call", CKR_OK);
        CHECK_RV(hookCloseRv, "C_CloseSession inside the call", CKR_OK);
        CHECK_TRUE(hookCloseKeyLive, "retired key kept while the call runs");
        CHECK_RV(rv, "C_GetAttributeValue", CKR_OK);
        CHECK_TRUE(!live_holds_key(), "key freed once the call ends");
    }
    if (other != CK_INVALID_HANDLE)
        funcList->C_CloseSession(other);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}

#ifdef HAVE_ECC
static int hookAddCalls = 0;

/* Runs at the start of each object add; logs out before the second one. */
static void hook_add_logout(void)
{
    hookAddCalls++;
    if (hookAddCalls == 2) {
        WP11_Session_SetAddObjectHook(NULL);
        hookLogoutRv = funcList->C_Logout(hookLogoutSession);
    }
}

/* A logout between the two adds of a key pair retires the first key; the
 * rollback must get it back and free it exactly once. */
static void keypair_rollback_after_logout_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_TOKEN,     &no,             sizeof(no)              },
        { CKA_PRIVATE,   &yes,            sizeof(yes)             },
        { CKA_VERIFY,    &yes,            sizeof(yes)             },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &no,  sizeof(no)  },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_SIGN,    &yes, sizeof(yes) },
    };
    long before;

    printf("--- key pair rollback after a logout between the adds ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &other);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    CHECK_RV(rv, "open sessions and log in", CKR_OK);
    if (rv == CKR_OK) {
        hookLogoutSession = other;
        hookLogoutRv = CKR_GENERAL_ERROR;
        hookAddCalls = 0;
        before = liveBlocks;
        WP11_Session_SetAddObjectHook(hook_add_logout);
        rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
                sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
                sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
        WP11_Session_SetAddObjectHook(NULL);
        CHECK_RV(hookLogoutRv, "C_Logout between the two adds", CKR_OK);
        CHECK_RV(rv, "C_GenerateKeyPair after the logout",
                 CKR_USER_NOT_LOGGED_IN);
        if (liveBlocks != before) {
            fprintf(stderr, "  live blocks went from %ld to %ld\n", before,
                    liveBlocks);
        }
        CHECK_TRUE(liveBlocks == before, "rolled back key pair freed");
    }
    if (other != CK_INVALID_HANDLE)
        funcList->C_CloseSession(other);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}
#endif

#ifdef RETIRE_TEST_THREADS
#define OVERLAP_STEPS 5
#define KEY_TAG_IDX   (sizeof(keyValue) - 2)

typedef struct HoldArg {
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE object;
    CK_RV rv;
} HoldArg;

static pthread_mutex_t holdMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t holdCond = PTHREAD_COND_INITIALIZER;
static int holdArmed = 0;
static int holdEntered[OVERLAP_STEPS];
static int holdRelease[OVERLAP_STEPS];

/* The armed holder's call waits here, inside its object call. */
static void hook_hold(void)
{
    int idx;

    pthread_mutex_lock(&holdMutex);
    idx = holdArmed - 1;
    holdArmed = 0;
    if (idx >= 0) {
        holdEntered[idx] = 1;
        pthread_cond_broadcast(&holdCond);
        while (!holdRelease[idx])
            pthread_cond_wait(&holdCond, &holdMutex);
    }
    pthread_mutex_unlock(&holdMutex);
}

static void* hold_thread(void* p)
{
    HoldArg* arg = (HoldArg*)p;
    CK_OBJECT_CLASS cls;
    CK_ATTRIBUTE attr = { CKA_CLASS, &cls, sizeof(cls) };

    arg->rv = funcList->C_GetAttributeValue(arg->session, arg->object, &attr,
                                            1);
    return NULL;
}

static int hold_start(pthread_t* th, HoldArg* arg, int idx)
{
    int ret;

    pthread_mutex_lock(&holdMutex);
    holdArmed = idx + 1;
    holdEntered[idx] = 0;
    holdRelease[idx] = 0;
    pthread_mutex_unlock(&holdMutex);
    ret = pthread_create(th, NULL, hold_thread, arg);
    if (ret == 0) {
        pthread_mutex_lock(&holdMutex);
        while (!holdEntered[idx])
            pthread_cond_wait(&holdCond, &holdMutex);
        pthread_mutex_unlock(&holdMutex);
    }
    return ret;
}

static void hold_end(pthread_t th, int idx)
{
    pthread_mutex_lock(&holdMutex);
    holdRelease[idx] = 1;
    pthread_cond_broadcast(&holdCond);
    pthread_mutex_unlock(&holdMutex);
    pthread_join(th, NULL);
}

static int live_holds_tagged_key(int idx)
{
    unsigned char saved = keyValue[KEY_TAG_IDX];
    int found;

    keyValue[KEY_TAG_IDX] = (unsigned char)('a' + idx);
    found = live_holds_key();
    keyValue[KEY_TAG_IDX] = saved;
    return found;
}

/* Overlapping calls that never all end at once must not hold destroyed keys:
 * each one is freed once the calls that began before its destroy end. */
static void destroy_while_calls_overlap_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL no = CK_FALSE;
    unsigned char dataValue[] = "hold";
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &no,        sizeof(no)        },
        { CKA_PRIVATE, &no,        sizeof(no)        },
        { CKA_VALUE,   dataValue,  sizeof(dataValue) },
    };
    pthread_t th[OVERLAP_STEPS];
    HoldArg arg[OVERLAP_STEPS];
    unsigned char saved = keyValue[KEY_TAG_IDX];
    int started = 0;
    int i;

    printf("--- destroyed keys are freed while calls keep overlapping ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &other);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(other, dataTmpl,
                sizeof(dataTmpl) / sizeof(*dataTmpl), &data);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    CHECK_RV(rv, "open sessions, create data object and log in", CKR_OK);
    if (rv == CKR_OK)
        WP11_Object_SetFindHook(hook_hold);
    for (i = 0; rv == CKR_OK && i < OVERLAP_STEPS; i++) {
        arg[i].session = other;
        arg[i].object = data;
        arg[i].rv = CKR_GENERAL_ERROR;
        if (hold_start(&th[i], &arg[i], i) != 0) {
            rv = CKR_GENERAL_ERROR;
            break;
        }
        started = i + 1;
        if (i > 0)
            hold_end(th[i - 1], i - 1);
        if (i > 1) {
            CHECK_TRUE(!live_holds_tagged_key(i - 2),
                       "key destroyed before two calls ended is freed");
        }
        keyValue[KEY_TAG_IDX] = (unsigned char)('a' + i);
        rv = create_key(session, &key);
        keyValue[KEY_TAG_IDX] = saved;
        if (rv == CKR_OK)
            rv = funcList->C_DestroyObject(session, key);
    }
    CHECK_RV(rv, "create and destroy keys while calls overlap", CKR_OK);
    if (started > 0)
        hold_end(th[started - 1], started - 1);
    WP11_Object_SetFindHook(NULL);
    for (i = 0; i < started; i++) {
        CHECK_RV(arg[i].rv, "held C_GetAttributeValue", CKR_OK);
        CHECK_TRUE(!live_holds_tagged_key(i), "destroyed key freed at end");
    }
    funcList->C_Logout(session);
    if (other != CK_INVALID_HANDLE)
        funcList->C_CloseSession(other);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}
#endif
#ifndef NO_HMAC
/* A destroyed key an operation still used is freed after the operation ends,
 * even though a new call always starts before the previous one ends. */
static void destroyed_key_freed_after_op_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL no = CK_FALSE;
    unsigned char dataValue[] = "hold";
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &no,        sizeof(no)        },
        { CKA_PRIVATE, &no,        sizeof(no)        },
        { CKA_VALUE,   dataValue,  sizeof(dataValue) },
    };
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType,  sizeof(keyType)  },
        { CKA_TOKEN,    &no,       sizeof(no)       },
        { CKA_PRIVATE,  &yes,      sizeof(yes)      },
        { CKA_SIGN,     &yes,      sizeof(yes)      },
        { CKA_VALUE,    keyValue,  sizeof(keyValue) },
    };
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    unsigned char msg[] = "message";
    unsigned char mac[64];
    CK_ULONG macLen = sizeof(mac);
    pthread_t th[2];
    HoldArg arg[2];
    unsigned char saved = keyValue[KEY_TAG_IDX];
    int started = 0;

    printf("--- destroyed key in use is freed once its operation ends ---\n");
    keyValue[KEY_TAG_IDX] = 'z';
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &other);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(other, dataTmpl,
                sizeof(dataTmpl) / sizeof(*dataTmpl), &data);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
                sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    }
    if (rv == CKR_OK)
        rv = funcList->C_SignInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_DestroyObject(session, key);
    keyValue[KEY_TAG_IDX] = saved;
    CHECK_RV(rv, "destroy a key used by an active sign operation", CKR_OK);
    if (rv == CKR_OK) {
        WP11_Object_SetFindHook(hook_hold);
        arg[0].session = other;
        arg[0].object = data;
        arg[0].rv = CKR_GENERAL_ERROR;
        if (hold_start(&th[0], &arg[0], 0) != 0)
            rv = CKR_GENERAL_ERROR;
        else
            started = 1;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, msg, sizeof(msg), mac, &macLen);
        CHECK_RV(rv, "C_Sign ends the operation", CKR_OK);
        arg[1].session = other;
        arg[1].object = data;
        arg[1].rv = CKR_GENERAL_ERROR;
        if (hold_start(&th[1], &arg[1], 1) == 0)
            started = 2;
        hold_end(th[0], 0);
        CHECK_TRUE(!live_holds_tagged_key('z' - 'a'),
                   "key freed while a later call still runs");
    }
    if (started == 2)
        hold_end(th[1], 1);
    else if (started == 1)
        hold_end(th[0], 0);
    WP11_Object_SetFindHook(NULL);
    funcList->C_Logout(session);
    if (other != CK_INVALID_HANDLE)
        funcList->C_CloseSession(other);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}
#endif
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
/* Right after C_InitPIN("") the empty PIN verdict is not cached yet; deriving
 * a private session key without a login must still be allowed. */
static void empty_pin_derive_test(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    unsigned char aesKey[16] = "empty-pin-base";
    unsigned char plain[32] = "empty-pin-derive-data-012345678";
    CK_ULONG len = sizeof(plain);
    CK_AES_CBC_ENCRYPT_DATA_PARAMS params;
    CK_MECHANISM mech = { CKM_AES_CBC_ENCRYPT_DATA, &params, sizeof(params) };
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS,    &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &aesType,  sizeof(aesType)  },
        { CKA_TOKEN,    &no,       sizeof(no)       },
        { CKA_PRIVATE,  &no,       sizeof(no)       },
        { CKA_DERIVE,   &yes,      sizeof(yes)      },
        { CKA_VALUE,    aesKey,    sizeof(aesKey)   },
    };
    CK_ATTRIBUTE derivedTmpl[] = {
        { CKA_CLASS,     &keyClass,    sizeof(keyClass)    },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_TOKEN,     &no,          sizeof(no)          },
        { CKA_VALUE_LEN, &len,         sizeof(len)         },
    };

    printf("--- derive a private session key right after an empty PIN ---\n");
    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)"", 0);
        if (rv == CKR_PIN_LEN_RANGE) {
            printf("  empty PIN not allowed by this build, skipping\n");
            funcList->C_Logout(session);
            funcList->C_CloseSession(session);
            return;
        }
    }
    CHECK_RV(rv, "log in as SO and set an empty user PIN", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_Logout(session);
        if (rv == CKR_OK) {
            rv = funcList->C_CreateObject(session, baseTmpl,
                    sizeof(baseTmpl) / sizeof(*baseTmpl), &base);
        }
        if (rv == CKR_OK) {
            XMEMSET(&params, 0, sizeof(params));
            params.pData = plain;
            params.length = sizeof(plain);
            rv = funcList->C_DeriveKey(session, &mech, base, derivedTmpl,
                    sizeof(derivedTmpl) / sizeof(*derivedTmpl), &derived);
        }
        CHECK_RV(rv, "derive a private session key without login", CKR_OK);
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
        if (rv == CKR_OK) {
            rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)userPin,
                                     (CK_ULONG)XSTRLEN(userPin));
            funcList->C_Logout(session);
        }
        CHECK_RV(rv, "restore the user PIN", CKR_OK);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
}
#endif

int main(int argc, char* argv[])
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;

    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
    if (wolfSSL_SetAllocators(track_malloc, track_free, track_realloc) != 0) {
        printf("Allocator hooks not available, skipping test\n");
        return 77;
    }

    printf("=== wolfPKCS11 logout retire test ===\n");
    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv == CKR_OK) {
        rv = token_setup(&slot);
        CHECK_RV(rv, "token setup", CKR_OK);
    }
    if (rv == CKR_OK) {
        logout_clears_retired_key_test(slot);
        retired_objects_bounded_test(slot);
#ifdef DEBUG_WOLFPKCS11
        logout_during_call_test(slot);
        destroy_during_call_test(slot);
        logout_during_destroy_test(slot);
        close_with_retired_test(slot);
#ifdef HAVE_ECC
        keypair_rollback_after_logout_test(slot);
#endif
#endif
#ifdef RETIRE_TEST_THREADS
        destroy_while_calls_overlap_test(slot);
#ifndef NO_HMAC
        destroyed_key_freed_after_op_test(slot);
#endif
#endif
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
        empty_pin_derive_test(slot);
#endif
    }
    if (funcList != NULL)
        funcList->C_Finalize(NULL);
    pkcs11_unload();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("NSS keeps private session objects across logout, skipping test\n");
    return 77;
}

#endif
