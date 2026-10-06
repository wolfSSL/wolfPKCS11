/* login_pin_state_test.c
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
 * Login, PIN and session state invariants of the token.
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

#include <wolfpkcs11/internal.h>

#include "testdata.h"
#include "pkcs11_test_util.h"

#ifndef SINGLE_THREADED
#include <pthread.h>
#include <unistd.h>
#endif

#define TEST_DIR "./store/login_pin_state_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

/* These debug tests damage the default file store under TEST_DIR. */
#if defined(DEBUG_WOLFPKCS11) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(WOLFPKCS11_TPM_STORE) && !defined(WOLFPKCS11_CUSTOM_STORE) && \
    !defined(WOLFPKCS11_NO_ENV) && !defined(NO_AES)
    #define LOGIN_TEST_FILE_STORE
#endif

/* Not every helper is used in every build configuration. */
#if defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-variable"
    #pragma GCC diagnostic ignored "-Wunused-function"
#endif

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "login-pin-state";
#ifndef WOLFPKCS11_NO_TIME
static const char* wrongOldPin = "wrong-old-pin";
#endif

/* Start from an unprovisioned token so earlier runs cannot affect this one. */
static void cleanup_test_files(void)
{
    char filepath[512];

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", TEST_DIR,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

static CK_RV lib_init(void)
{
    CK_C_INITIALIZE_ARGS args;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    return funcList->C_Initialize(&args);
}

/* Initialize the library, re-initialize the token and set the user PIN. */
static CK_RV token_setup(CK_SLOT_ID* slot, const char* pin)
{
    CK_RV rv;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE soSession = CK_INVALID_HANDLE;
    unsigned char label[32];

    rv = lib_init();
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
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)pin,
                                 (CK_ULONG)XSTRLEN(pin));
        funcList->C_Logout(soSession);
    }
    if (soSession != CK_INVALID_HANDLE)
        funcList->C_CloseSession(soSession);
    return rv;
}

static CK_RV open_rw(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    return funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                   NULL, NULL, session);
}

static CK_RV user_login(CK_SESSION_HANDLE session, const char* pin)
{
    return funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin,
                             (CK_ULONG)XSTRLEN(pin));
}

#if !defined(WOLFPKCS11_NO_STORE) && !defined(NO_AES)
static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesType = CKK_AES;
static CK_BBOOL ckTrue = CK_TRUE;
static byte aesValue[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
#endif

#if defined(__GNUC__)
    #pragma GCC diagnostic pop
#endif

#ifdef LOGIN_TEST_FILE_STORE
/* DEBUG_WOLFPKCS11-only introspection hooks exported by libwolfpkcs11. */
extern int WP11_Slot_TokenKeyIsZero(CK_SLOT_ID slotId);
extern int WP11_Slot_TokenDecodedObjectCount(CK_SLOT_ID slotId);

#define SYMMKEY_FILENAME "wp11_symmkey_0000000000000001_0000000000000000"

/* Replace the oldest stored secret key with a record too short to decrypt. */
static int truncate_stored_key(void)
{
    FILE* f;
    char filepath[512];
    static const byte shortRecord[12] = { 0x00, 0x00, 0x00, 0x08 };
    int ret = -1;

    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", TEST_DIR,
             SYMMKEY_FILENAME);
    f = fopen(filepath, "wb");
    if (f != NULL) {
        if (fwrite(shortRecord, 1, sizeof(shortRecord), f) ==
                sizeof(shortRecord)) {
            ret = 0;
        }
        if (fclose(f) != 0)
            ret = -1;
    }
    return ret;
}

/* A login that fails after the PIN is verified must not leave the key derived
 * from the PIN, or any key decoded before the failure, resident in memory. */
static void failed_login_leaves_no_token_key_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aesValue,     sizeof(aesValue)    },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckTrue,      sizeof(ckTrue)      },
    };

    printf("--- failed login leaves no token key ---\n");
    rv = token_setup(&slot, userPin);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK)
        rv = user_login(session, userPin);
    /* Objects decode newest first, so the second key decodes before the
     * damaged first one. */
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
                sizeof(keyTmpl) / sizeof(*keyTmpl), &obj);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
                sizeof(keyTmpl) / sizeof(*keyTmpl), &obj);
    }
    CHECK_RV(rv, "create private token keys", CKR_OK);
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
    }
    funcList->C_Finalize(NULL);
    if (rv != CKR_OK)
        return;

    CHECK_TRUE(truncate_stored_key() == 0, "replace stored key record");
    rv = lib_init();
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    CHECK_RV(rv, "reload token", CKR_OK);
    if (rv == CKR_OK) {
        rv = user_login(session, userPin);
        CHECK_TRUE(rv != CKR_OK, "login fails on undecodable token object");
        CHECK_TRUE(WP11_Slot_TokenKeyIsZero(slot) == 1,
                   "token key is clear after failed login");
        CHECK_TRUE(WP11_Slot_TokenDecodedObjectCount(slot) == 0,
                   "no decoded keys left after failed login");
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);
    cleanup_test_files();
}
#endif

#if defined(LOGIN_TEST_FILE_STORE) && defined(HAVE_ECC)
static char ecLabel[] = "pin-state-ec-key";
static CK_BYTE ecP256Params[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

static CK_RV create_ec_key(CK_SESSION_HANDLE session)
{
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, ecP256Params, sizeof(ecP256Params) },
        { CKA_VERIFY,    &ckTrue,      sizeof(ckTrue)       },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,   &ckTrue, sizeof(ckTrue)        },
        { CKA_PRIVATE, &ckTrue, sizeof(ckTrue)        },
        { CKA_SIGN,    &ckTrue, sizeof(ckTrue)        },
        { CKA_LABEL,   ecLabel, sizeof(ecLabel) - 1   },
    };

    return funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
}

/* Flip a byte of the stored EC private key so it no longer authenticates. */
static int damage_stored_ec_key(void)
{
    FILE* f;
    char filepath[512];
    int id;
    int ret = -1;
    int c;

    for (id = 0; id < 3 && ret != 0; id++) {
        snprintf(filepath, sizeof(filepath), "%s" PATH_SEP
                 "wp11_ecckey_priv_0000000000000001_%016x", TEST_DIR, id);
        f = fopen(filepath, "r+b");
        if (f == NULL)
            continue;
        if (fseek(f, -1, SEEK_END) == 0 && (c = fgetc(f)) != EOF &&
                fseek(f, -1, SEEK_END) == 0 && fputc(c ^ 0xff, f) != EOF) {
            ret = 0;
        }
        if (fclose(f) != 0)
            ret = -1;
    }
    return ret;
}

/* Logout protects every decoded token object even when one cannot be. */
static void logout_protects_all_objects_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aesValue,     sizeof(aesValue)    },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckTrue,      sizeof(ckTrue)      },
    };

    printf("--- logout protects all token objects ---\n");
    rv = token_setup(&slot, userPin);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK)
        rv = user_login(session, userPin);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
                sizeof(keyTmpl) / sizeof(*keyTmpl), &obj);
    }
    if (rv == CKR_OK)
        rv = create_ec_key(session);
    CHECK_RV(rv, "create private token keys", CKR_OK);
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
    }
    funcList->C_Finalize(NULL);
    if (rv != CKR_OK)
        return;

    CHECK_TRUE(damage_stored_ec_key() == 0, "damage stored EC key");
    rv = lib_init();
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK)
        rv = user_login(session, userPin);
    CHECK_RV(rv, "login with one undecodable object", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(WP11_Slot_TokenDecodedObjectCount(slot) > 0,
                   "objects decoded while logged in");
        funcList->C_Logout(session);
        CHECK_TRUE(WP11_Slot_TokenDecodedObjectCount(slot) == 0,
                   "no decoded objects left after logout");
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    cleanup_test_files();
}
#endif

#ifndef SINGLE_THREADED
#define EMPTY_PIN_ROUNDS 8

static pthread_mutex_t infoMutex = PTHREAD_MUTEX_INITIALIZER;
static int infoStop = 0;
static CK_SLOT_ID infoSlot = 0;

static int info_should_stop(void)
{
    int stop;

    pthread_mutex_lock(&infoMutex);
    stop = infoStop;
    pthread_mutex_unlock(&infoMutex);
    return stop;
}

static void info_set_stop(int stop)
{
    pthread_mutex_lock(&infoMutex);
    infoStop = stop;
    pthread_mutex_unlock(&infoMutex);
}

static void* token_info_loop(void* arg)
{
    CK_TOKEN_INFO info;

    (void)arg;
    while (!info_should_stop())
        (void)funcList->C_GetTokenInfo(infoSlot, &info);
    return NULL;
}

/* Once a non-empty user PIN is set, the token requires login and private
 * objects cannot be created without one, even with concurrent token queries. */
static void empty_pin_change_requires_login_test(void)
{
    CK_RV rv;
    int i;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_TOKEN_INFO info;
    pthread_t thread;
    const char* newPin = "non-empty-pin";
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL privTrue = CK_TRUE;
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_PRIVATE, &privTrue,  sizeof(privTrue)  },
    };
    int loginRequired = 1;
    int privateDenied = 1;

    printf("--- empty PIN replaced by a non-empty PIN ---\n");
    for (i = 0; i < EMPTY_PIN_ROUNDS; i++) {
        rv = token_setup(&slot, "");
        if (i == 0 && rv == CKR_PIN_LEN_RANGE) {
            printf("SKIP: empty user PIN not supported by this build\n");
            funcList->C_Finalize(NULL);
            return;
        }
        if (rv == CKR_OK)
            rv = open_rw(slot, &session);
        CHECK_RV(rv, "token setup with empty user PIN", CKR_OK);
        if (rv != CKR_OK) {
            funcList->C_Finalize(NULL);
            return;
        }

        infoSlot = slot;
        info_set_stop(0);
        if (pthread_create(&thread, NULL, token_info_loop, NULL) != 0) {
            CHECK_TRUE(0, "create token info thread");
            funcList->C_CloseSession(session);
            funcList->C_Finalize(NULL);
            return;
        }
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)"", 0,
                                (CK_UTF8CHAR_PTR)newPin,
                                (CK_ULONG)XSTRLEN(newPin));
        info_set_stop(1);
        pthread_join(thread, NULL);
        CHECK_RV(rv, "C_SetPIN from empty to non-empty PIN", CKR_OK);

        if (funcList->C_GetTokenInfo(slot, &info) != CKR_OK ||
                (info.flags & CKF_LOGIN_REQUIRED) == 0) {
            loginRequired = 0;
        }
        obj = CK_INVALID_HANDLE;
        rv = funcList->C_CreateObject(session, privTmpl,
                sizeof(privTmpl) / sizeof(*privTmpl), &obj);
        if (rv != CKR_USER_NOT_LOGGED_IN)
            privateDenied = 0;

        funcList->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
        funcList->C_Finalize(NULL);
    }
    CHECK_TRUE(loginRequired, "token reports login required after PIN set");
    CHECK_TRUE(privateDenied,
               "private object creation needs login after PIN set");
}
#endif

#ifndef WOLFPKCS11_NO_TIME
/* Changing a PIN counts wrong old PINs toward the login lockout. */
static void set_pin_lockout(CK_USER_TYPE type, const char* pin, int maxFails,
                            const char* what)
{
    CK_RV rv;
    int i;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    const char* newPin = "replacement-pin";

    rv = token_setup(&slot, userPin);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK && type == CKU_SO) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv != CKR_OK) {
        funcList->C_Finalize(NULL);
        return;
    }
    for (i = 0; i < maxFails; i++) {
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)wrongOldPin,
                                (CK_ULONG)XSTRLEN(wrongOldPin),
                                (CK_UTF8CHAR_PTR)newPin,
                                (CK_ULONG)XSTRLEN(newPin));
        CHECK_RV(rv, "C_SetPIN with wrong old PIN", CKR_PIN_INCORRECT);
    }
    rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)pin,
                            (CK_ULONG)XSTRLEN(pin), (CK_UTF8CHAR_PTR)newPin,
                            (CK_ULONG)XSTRLEN(newPin));
    CHECK_TRUE(rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED, what);
    if (type == CKU_SO)
        funcList->C_Logout(session);
    funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    /* The lockout is persisted; start later tests from a fresh token. */
    cleanup_test_files();
}
#endif

#if !defined(SINGLE_THREADED) && !defined(WOLFPKCS11_NO_TIME)
#define LOCKOUT_THREADS 6
#define LOCKOUT_ROUNDS 4

static const char* wrongPin = "not-the-right-pin";

typedef struct login_ctx {
    CK_SESSION_HANDLE session;
    CK_USER_TYPE type;
    CK_RV rv;
} login_ctx;

static pthread_mutex_t goMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t goCond = PTHREAD_COND_INITIALIZER;
static int goFlag = 0;

static void* wrong_login(void* arg)
{
    login_ctx* ctx = (login_ctx*)arg;

    pthread_mutex_lock(&goMutex);
    while (!goFlag)
        pthread_cond_wait(&goCond, &goMutex);
    pthread_mutex_unlock(&goMutex);

    ctx->rv = funcList->C_Login(ctx->session, ctx->type,
                                (CK_UTF8CHAR_PTR)wrongPin,
                                (CK_ULONG)XSTRLEN(wrongPin));
    return NULL;
}

/* Run simultaneous wrong-PIN logins, one per session. Returns 1 when every
 * one of them was rejected as an incorrect PIN. */
static int concurrent_wrong_logins(CK_SLOT_ID slot, CK_USER_TYPE type)
{
    int i;
    int started = 0;
    int rejected = 1;
    pthread_t threads[LOCKOUT_THREADS];
    login_ctx ctx[LOCKOUT_THREADS];

    goFlag = 0;
    for (i = 0; i < LOCKOUT_THREADS; i++) {
        ctx[i].session = CK_INVALID_HANDLE;
        ctx[i].type = type;
        ctx[i].rv = CKR_OK;
        if (open_rw(slot, &ctx[i].session) != CKR_OK)
            break;
        if (pthread_create(&threads[i], NULL, wrong_login, &ctx[i]) != 0) {
            funcList->C_CloseSession(ctx[i].session);
            break;
        }
        started++;
    }
    pthread_mutex_lock(&goMutex);
    goFlag = 1;
    pthread_cond_broadcast(&goCond);
    pthread_mutex_unlock(&goMutex);
    for (i = 0; i < started; i++) {
        pthread_join(threads[i], NULL);
        funcList->C_CloseSession(ctx[i].session);
        if (ctx[i].rv != CKR_PIN_INCORRECT)
            rejected = 0;
    }
    CHECK_TRUE(started == LOCKOUT_THREADS, "start concurrent logins");
    return rejected;
}

/* Failed logins that race each other still lock out the correct PIN. */
static void lockout_after_concurrent_failures(CK_USER_TYPE type,
                                              const char* pin, int maxFails,
                                              const char* what)
{
    CK_RV rv = CKR_OK;
    int i;
    int round;
    int locked = 1;
    int rejected = 1;
    CK_RV final;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    for (round = 0; rv == CKR_OK && round < LOCKOUT_ROUNDS; round++) {
        rv = token_setup(&slot, userPin);
        if (rv == CKR_OK)
            rv = open_rw(slot, &session);
        for (i = 0; rv == CKR_OK && i < maxFails - 1; i++) {
            rv = funcList->C_Login(session, type, (CK_UTF8CHAR_PTR)wrongPin,
                                   (CK_ULONG)XSTRLEN(wrongPin));
            if (rv == CKR_PIN_INCORRECT)
                rv = CKR_OK;
        }
        if (rv == CKR_OK) {
            if (!concurrent_wrong_logins(slot, type))
                rejected = 0;
            final = funcList->C_Login(session, type, (CK_UTF8CHAR_PTR)pin,
                                      (CK_ULONG)XSTRLEN(pin));
            if (final != CKR_PIN_INCORRECT && final != CKR_PIN_LOCKED)
                locked = 0;
            if (final == CKR_OK)
                funcList->C_Logout(session);
        }
        if (session != CK_INVALID_HANDLE) {
            funcList->C_CloseSession(session);
            session = CK_INVALID_HANDLE;
        }
        funcList->C_Finalize(NULL);
        /* The lockout is persisted; start each round from a fresh token. */
        cleanup_test_files();
    }
    CHECK_RV(rv, "set up failed logins", CKR_OK);
    CHECK_TRUE(rejected, "concurrent wrong PINs rejected");
    CHECK_TRUE(locked, what);
}

static void concurrent_login_lockout_test(void)
{
    printf("--- concurrent failed logins lock out the PIN ---\n");
    lockout_after_concurrent_failures(CKU_USER, userPin,
                                      WP11_MAX_LOGIN_FAILS_USER,
                                      "user PIN locked after racing failures");
    lockout_after_concurrent_failures(CKU_SO, soPin, WP11_MAX_LOGIN_FAILS_SO,
                                      "SO PIN locked after racing failures");
}
#endif

#ifndef SINGLE_THREADED
#define CLOSE_OPEN_ROUNDS 10

static pthread_mutex_t openMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t openCond = PTHREAD_COND_INITIALIZER;
static int openFlag = 0;

typedef struct open_ctx {
    CK_SLOT_ID slot;
    CK_SESSION_HANDLE session;
    CK_STATE firstState;
    CK_STATE lastState;
    CK_RV rv;
} open_ctx;

static void* open_during_close(void* arg)
{
    open_ctx* ctx = (open_ctx*)arg;
    CK_SESSION_INFO info;

    pthread_mutex_lock(&openMutex);
    while (!openFlag)
        pthread_cond_wait(&openCond, &openMutex);
    pthread_mutex_unlock(&openMutex);

    ctx->rv = open_rw(ctx->slot, &ctx->session);
    if (ctx->rv == CKR_OK)
        ctx->rv = funcList->C_GetSessionInfo(ctx->session, &info);
    if (ctx->rv == CKR_OK)
        ctx->firstState = info.state;
    return NULL;
}

/* A session opened while another one closes is never logged out after
 * C_OpenSession reported it as logged in. */
static void close_last_session_race_test(void)
{
    CK_RV rv;
    int i;
    int consistent = 1;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_INFO info;
    pthread_t thread;
    open_ctx ctx;

    printf("--- closing the last session races an open ---\n");
    rv = token_setup(&slot, userPin);
    CHECK_RV(rv, "token setup", CKR_OK);
    for (i = 0; rv == CKR_OK && i < CLOSE_OPEN_ROUNDS; i++) {
        rv = open_rw(slot, &session);
        if (rv == CKR_OK)
            rv = user_login(session, userPin);
        if (rv != CKR_OK)
            break;

        XMEMSET(&ctx, 0, sizeof(ctx));
        XMEMSET(&info, 0, sizeof(info));
        ctx.slot = slot;
        ctx.session = CK_INVALID_HANDLE;
        openFlag = 0;
        if (pthread_create(&thread, NULL, open_during_close, &ctx) != 0) {
            rv = CKR_GENERAL_ERROR;
            break;
        }
        pthread_mutex_lock(&openMutex);
        openFlag = 1;
        pthread_cond_broadcast(&openCond);
        pthread_mutex_unlock(&openMutex);
        rv = funcList->C_CloseSession(session);
        pthread_join(thread, NULL);
        if (rv == CKR_OK)
            rv = ctx.rv;
        if (rv == CKR_OK)
            rv = funcList->C_GetSessionInfo(ctx.session, &info);
        if (rv == CKR_OK && ctx.firstState == CKS_RW_USER_FUNCTIONS &&
                info.state != CKS_RW_USER_FUNCTIONS) {
            consistent = 0;
        }
        if (ctx.session != CK_INVALID_HANDLE) {
            if (info.state == CKS_RW_USER_FUNCTIONS)
                funcList->C_Logout(ctx.session);
            funcList->C_CloseSession(ctx.session);
        }
    }
    CHECK_RV(rv, "open and close sessions concurrently", CKR_OK);
    CHECK_TRUE(consistent, "opened session keeps its reported login state");
    funcList->C_Finalize(NULL);
}
#endif

#ifndef SINGLE_THREADED
#define CHURN_ROUNDS 200

typedef struct churn_ctx {
    CK_SESSION_HANDLE session;
    CK_RV rv;
} churn_ctx;

static void* churn_session_objects(void* arg)
{
    churn_ctx* ctx = (churn_ctx*)arg;
    int i;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL no = CK_FALSE;
    byte value[4] = { 5, 6, 7, 8 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, &no,        sizeof(no)        },
        { CKA_VALUE, value,      sizeof(value)     },
    };

    for (i = 0; ctx->rv == CKR_OK && i < CHURN_ROUNDS; i++) {
        ctx->rv = funcList->C_CreateObject(ctx->session, tmpl,
                sizeof(tmpl) / sizeof(*tmpl), &obj);
        if (ctx->rv == CKR_OK)
            ctx->rv = funcList->C_DestroyObject(ctx->session, obj);
    }
    return NULL;
}

/* Finding session objects is safe while session objects come and go. */
static void find_during_object_churn_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found[8];
    CK_ULONG cnt;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, &no,        sizeof(no)        },
    };
    pthread_t thread;
    churn_ctx ctx;
    int i;

    printf("--- find session objects while they change ---\n");
    rv = token_setup(&slot, userPin);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv != CKR_OK) {
        funcList->C_Finalize(NULL);
        return;
    }
    ctx.session = session;
    ctx.rv = CKR_OK;
    if (pthread_create(&thread, NULL, churn_session_objects, &ctx) != 0) {
        CHECK_TRUE(0, "create object churn thread");
        funcList->C_Finalize(NULL);
        return;
    }
    for (i = 0; rv == CKR_OK && i < CHURN_ROUNDS; i++) {
        rv = funcList->C_FindObjectsInit(session, findTmpl, 2);
        if (rv == CKR_OK) {
            rv = funcList->C_FindObjects(session, found, 8, &cnt);
            funcList->C_FindObjectsFinal(session);
        }
    }
    pthread_join(thread, NULL);
    CHECK_RV(rv, "find session objects concurrently", CKR_OK);
    CHECK_RV(ctx.rv, "create and destroy session objects concurrently",
             CKR_OK);
    funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#if !defined(SINGLE_THREADED) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(NO_AES)
#define FIND_LOGIN_ROUNDS 3

static pthread_mutex_t findMutex = PTHREAD_MUTEX_INITIALIZER;
static int findStop = 0;

typedef struct find_ctx {
    CK_SESSION_HANDLE session;
    CK_RV rv;
} find_ctx;

static int find_should_stop(void)
{
    int stop;

    pthread_mutex_lock(&findMutex);
    stop = findStop;
    pthread_mutex_unlock(&findMutex);
    return stop;
}

static void find_set_stop(int stop)
{
    pthread_mutex_lock(&findMutex);
    findStop = stop;
    pthread_mutex_unlock(&findMutex);
}

static void* find_loop(void* arg)
{
    find_ctx* ctx = (find_ctx*)arg;
    CK_OBJECT_HANDLE found[8];
    CK_ULONG cnt;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secretClass, sizeof(secretClass) },
    };

    while (ctx->rv == CKR_OK && !find_should_stop()) {
        ctx->rv = funcList->C_FindObjectsInit(ctx->session, tmpl, 1);
        if (ctx->rv == CKR_OK) {
            ctx->rv = funcList->C_FindObjects(ctx->session, found, 8, &cnt);
            funcList->C_FindObjectsFinal(ctx->session);
        }
    }
    return NULL;
}

/* Finding objects stays well behaved while the user logs in and out, and
 * private objects are not listed once logged out. */
static void find_during_login_changes_test(void)
{
    CK_RV rv;
    int i;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE findSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found[8];
    CK_ULONG cnt = 0;
    pthread_t thread;
    find_ctx ctx;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aesValue,     sizeof(aesValue)    },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckTrue,      sizeof(ckTrue)      },
    };
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &secretClass, sizeof(secretClass) },
    };

    printf("--- find objects while logging in and out ---\n");
    rv = token_setup(&slot, userPin);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK)
        rv = open_rw(slot, &findSession);
    if (rv == CKR_OK)
        rv = user_login(session, userPin);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
                sizeof(keyTmpl) / sizeof(*keyTmpl), &obj);
    }
    CHECK_RV(rv, "create private token key", CKR_OK);
    if (rv != CKR_OK) {
        funcList->C_Finalize(NULL);
        return;
    }

    ctx.session = findSession;
    ctx.rv = CKR_OK;
    find_set_stop(0);
    if (pthread_create(&thread, NULL, find_loop, &ctx) != 0) {
        CHECK_TRUE(0, "create find thread");
        funcList->C_Finalize(NULL);
        return;
    }
    for (i = 0; rv == CKR_OK && i < FIND_LOGIN_ROUNDS; i++) {
        rv = funcList->C_Logout(session);
        if (rv == CKR_OK)
            rv = user_login(session, userPin);
    }
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    find_set_stop(1);
    pthread_join(thread, NULL);
    CHECK_RV(rv, "log in and out while finding", CKR_OK);
    CHECK_RV(ctx.rv, "find objects concurrently", CKR_OK);

    rv = funcList->C_FindObjectsInit(findSession, findTmpl, 1);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(findSession, found, 8, &cnt);
        funcList->C_FindObjectsFinal(findSession);
    }
    CHECK_TRUE(rv == CKR_OK && cnt == 0,
               "private object not listed after logout");
    funcList->C_Finalize(NULL);
}
#endif

#if defined(DEBUG_WOLFPKCS11) && !defined(SINGLE_THREADED) && \
    !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_NSS)
#define FIND_HOOK_WAIT_MS 200

static pthread_mutex_t hookMutex = PTHREAD_MUTEX_INITIALIZER;
static CK_SESSION_HANDLE hookSession = CK_INVALID_HANDLE;
static pthread_t hookThread;
static int hookStarted = 0;
static int hookLogoutDone = 0;
static int hookLogoutBeforeWalk = 0;

static int hook_logout_done(void)
{
    int done;

    pthread_mutex_lock(&hookMutex);
    done = hookLogoutDone;
    pthread_mutex_unlock(&hookMutex);
    return done;
}

static void* hook_logout(void* arg)
{
    (void)arg;
    (void)funcList->C_Logout(hookSession);
    pthread_mutex_lock(&hookMutex);
    hookLogoutDone = 1;
    pthread_mutex_unlock(&hookMutex);
    return NULL;
}

/* Runs in C_FindObjectsInit between the login state read and the walk. */
static void find_hook_logout(void)
{
    int i;

    if (hookStarted)
        return;
    hookStarted = (pthread_create(&hookThread, NULL, hook_logout, NULL) == 0);
    for (i = 0; hookStarted && i < FIND_HOOK_WAIT_MS && !hook_logout_done();
            i++) {
        usleep(1000);
    }
    hookLogoutBeforeWalk = hook_logout_done();
}

/* A logout racing a find must not let the walk list private objects. */
static void find_with_racing_logout_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE findSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found[4];
    CK_ULONG cnt = 0;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL isTrue = CK_TRUE;
    static byte privData[] = "private data value";
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass)    },
        { CKA_TOKEN,   &isTrue,    sizeof(isTrue)       },
        { CKA_PRIVATE, &isTrue,    sizeof(isTrue)       },
        { CKA_VALUE,   privData,   sizeof(privData) - 1 },
    };
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
    };

    printf("--- find with a logout racing the object walk ---\n");
    rv = token_setup(&slot, userPin);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK)
        rv = open_rw(slot, &findSession);
    if (rv == CKR_OK)
        rv = user_login(session, userPin);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
                sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
    }
    CHECK_RV(rv, "create private token data object", CKR_OK);
    if (rv == CKR_OK) {
        hookSession = session;
        hookStarted = 0;
        hookLogoutBeforeWalk = 0;
        pthread_mutex_lock(&hookMutex);
        hookLogoutDone = 0;
        pthread_mutex_unlock(&hookMutex);
        WP11_Session_SetFindHook(find_hook_logout);
        rv = funcList->C_FindObjectsInit(findSession, findTmpl, 1);
        WP11_Session_SetFindHook(NULL);
        if (hookStarted)
            pthread_join(hookThread, NULL);
        if (rv == CKR_OK) {
            rv = funcList->C_FindObjects(findSession, found, 4, &cnt);
            funcList->C_FindObjectsFinal(findSession);
        }
        CHECK_RV(rv, "find objects with a racing logout", CKR_OK);
        CHECK_TRUE(hookStarted && hook_logout_done(), "racing logout ran");
        CHECK_TRUE(!(hookLogoutBeforeWalk && cnt > 0),
                   "walk after logout lists no private object");
    }
    funcList->C_Finalize(NULL);
    cleanup_test_files();
}
#endif

static int run_test(void)
{
    CK_RV rv;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

#ifndef SINGLE_THREADED
    empty_pin_change_requires_login_test();
#endif
#ifdef LOGIN_TEST_FILE_STORE
    failed_login_leaves_no_token_key_test();
#endif
#ifndef SINGLE_THREADED
    close_last_session_race_test();
#endif
#if !defined(SINGLE_THREADED) && !defined(WOLFPKCS11_NO_TIME)
    concurrent_login_lockout_test();
#endif
#ifndef SINGLE_THREADED
    find_during_object_churn_test();
#endif
#if !defined(SINGLE_THREADED) && !defined(WOLFPKCS11_NO_STORE) && \
    !defined(NO_AES)
    find_during_login_changes_test();
#endif
#if defined(DEBUG_WOLFPKCS11) && !defined(SINGLE_THREADED) && \
    !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_NSS)
    find_with_racing_logout_test();
#endif
#if defined(LOGIN_TEST_FILE_STORE) && defined(HAVE_ECC)
    logout_protects_all_objects_test();
#endif
#ifndef WOLFPKCS11_NO_TIME
    printf("--- C_SetPIN counts failed SO PIN checks ---\n");
    set_pin_lockout(CKU_SO, soPin, WP11_MAX_LOGIN_FAILS_SO,
                    "SO C_SetPIN locked after failures");
    printf("--- C_SetPIN counts failed user PIN checks ---\n");
    set_pin_lockout(CKU_USER, userPin, WP11_MAX_LOGIN_FAILS_USER,
                    "user C_SetPIN locked after failures");
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

    printf("=== wolfPKCS11 login and PIN state test ===\n");
    cleanup_test_files();
    run_test();
    return pkcs11_test_summary();
}
