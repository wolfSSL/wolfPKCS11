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
#endif
#ifdef RETIRE_TEST_THREADS
        destroy_while_calls_overlap_test(slot);
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
