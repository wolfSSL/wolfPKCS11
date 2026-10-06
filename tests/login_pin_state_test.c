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

#include "testdata.h"
#include "pkcs11_test_util.h"

#ifndef SINGLE_THREADED
#include <pthread.h>
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
