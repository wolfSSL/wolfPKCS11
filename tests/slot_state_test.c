/* slot_state_test.c
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
 * Slot login state: close-all logout, SO PIN changes during a PIN check and
 * lockout counts kept across processes.
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

#define TEST_DIR "./store/slot_state_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_NO_TIME) && \
    !defined(WOLFPKCS11_TPM_STORE) && !defined(WOLFPKCS11_CUSTOM_STORE) && \
    !defined(WOLFPKCS11_NO_ENV) && !defined(_WIN32)
    #define SLOT_TEST_PROCESSES
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/stat.h>
    #include <unistd.h>

    #define CHILD_PASS      0
    #define CHILD_FAIL      1
    #define CHILD_SETUP     2
#endif

#if defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-variable"
    #pragma GCC diagnostic ignored "-Wunused-function"
#endif

/* Non-empty PINs are at least 14 bytes, the FIPS HMAC minimum key length. */
static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char* wrongPin = "not-the-right-pin";
static const char tokenLabel[] = "slot-state";

static void cleanup_test_files(void)
{
    char filepath[512];

#ifdef SLOT_TEST_PROCESSES
    (void)chmod(TEST_DIR, 0700);
#endif
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

static CK_RV first_slot(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK)
        *slot = slotList[0];
    return rv;
}

static CK_RV open_rw(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    return funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                   NULL, NULL, session);
}

static CK_RV login(CK_SESSION_HANDLE session, CK_USER_TYPE type,
                   const char* pin)
{
    return funcList->C_Login(session, type, (CK_UTF8CHAR_PTR)pin,
                             (CK_ULONG)XSTRLEN(pin));
}

/* Initialize the library, re-initialize the token and set the user PIN. */
static CK_RV token_setup(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE soSession = CK_INVALID_HANDLE;
    unsigned char label[32];

    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(slot);
    if (rv == CKR_OK) {
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(*slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK)
        rv = open_rw(*slot, &soSession);
    if (rv == CKR_OK)
        rv = login(soSession, CKU_SO, soPin);
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
        funcList->C_Logout(soSession);
    }
    if (soSession != CK_INVALID_HANDLE)
        funcList->C_CloseSession(soSession);
    return rv;
}

static CK_FLAGS token_flags(CK_SLOT_ID slot)
{
    CK_TOKEN_INFO info;

    XMEMSET(&info, 0, sizeof(info));
    if (funcList->C_GetTokenInfo(slot, &info) != CKR_OK)
        return 0;
    return info.flags;
}

static CK_RV find_count(CK_SESSION_HANDLE session, CK_ATTRIBUTE* tmpl,
                        CK_ULONG cnt, CK_ULONG* found)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj[2];

    *found = 0;
    rv = funcList->C_FindObjectsInit(session, tmpl, cnt);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, obj, 2, found);
        (void)funcList->C_FindObjectsFinal(session);
    }
    return rv;
}

#if defined(DEBUG_WOLFPKCS11) && !defined(WOLFPKCS11_NO_STORE)
#ifdef __cplusplus
extern "C" {
#endif
extern int WP11_Slot_TokenKeyIsZero(CK_SLOT_ID slotId);
#ifdef __cplusplus
}
#endif
#endif

/* C_CloseAllSessions closes the application's last session, so it logs out
 * whoever was logged in. */
static void close_all_sessions_logs_out_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_INFO info;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL yes = CK_TRUE;
    byte label[] = "close-all-private";
    byte value[4] = { 1, 2, 3, 4 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &yes,       sizeof(yes)       },
        { CKA_PRIVATE, &yes,       sizeof(yes)       },
        { CKA_LABEL,   label,      sizeof(label) - 1 },
        { CKA_VALUE,   value,      sizeof(value)     },
    };
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_LABEL, label,      sizeof(label) - 1 },
    };
    CK_ULONG found = 0;

    printf("--- C_CloseAllSessions logs out the user ---\n");
    rv = token_setup(&slot);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, tmpl,
                sizeof(tmpl) / sizeof(*tmpl), &obj);
    }
    CHECK_RV(rv, "log in and create a private token object", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_CloseAllSessions(slot);
        CHECK_RV(rv, "close all sessions while logged in", CKR_OK);
        session = CK_INVALID_HANDLE;
    }
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK)
        rv = funcList->C_GetSessionInfo(session, &info);
    if (rv == CKR_OK) {
        CHECK_TRUE(info.state == CKS_RW_PUBLIC_SESSION,
                   "new session after close-all is public");
    #ifndef WOLFPKCS11_NSS
        /* NSS mode lists private objects in public sessions. */
        rv = find_count(session, findTmpl, 2, &found);
        CHECK_TRUE(rv == CKR_OK && found == 0,
                   "private object not found after close-all");
    #endif
    #if defined(DEBUG_WOLFPKCS11) && !defined(WOLFPKCS11_NO_STORE)
        CHECK_TRUE(WP11_Slot_TokenKeyIsZero(slot) == 1,
                   "token key cleared by close-all");
    #endif
        rv = login(session, CKU_USER, userPin);
        CHECK_RV(rv, "user logs in again after close-all", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = find_count(session, findTmpl, 2, &found);
        CHECK_TRUE(rv == CKR_OK && found == 1,
                   "private object found after logging in again");
        funcList->C_Logout(session);
    }

    printf("--- C_CloseAllSessions logs out the SO ---\n");
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = funcList->C_CloseAllSessions(slot);
    CHECK_RV(rv, "SO login and close all sessions", CKR_OK);
    session = CK_INVALID_HANDLE;
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
                                     &session);
        CHECK_RV(rv, "read-only session opens after SO close-all", CKR_OK);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

#if defined(DEBUG_WOLFPKCS11) && !defined(WOLFPKCS11_NO_TIME)
#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Slot_SetPinCheckHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

static const char* newSoPin = "new-so-password-1";
static const char* otherSoPin = "other-so-password";
static CK_SESSION_HANDLE hookSession = CK_INVALID_HANDLE;
static CK_RV hookRv = CKR_GENERAL_ERROR;

/* Changes the SO PIN while an SO PIN check hashes outside the lock. */
static void change_so_pin_hook(void)
{
    WP11_Slot_SetPinCheckHook(NULL);
    hookRv = funcList->C_SetPIN(hookSession, (CK_UTF8CHAR_PTR)soPin,
                                (CK_ULONG)XSTRLEN(soPin),
                                (CK_UTF8CHAR_PTR)newSoPin,
                                (CK_ULONG)XSTRLEN(newSoPin));
}

/* An SO PIN check overtaken by an SO PIN change is refused without counting
 * toward the lockout. */
static void so_pin_change_during_check_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    printf("--- SO PIN changed during an SO PIN check ---\n");
    rv = token_setup(&slot);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    CHECK_RV(rv, "SO login", CKR_OK);
    if (rv == CKR_OK) {
        hookSession = session;
        hookRv = CKR_GENERAL_ERROR;
        WP11_Slot_SetPinCheckHook(change_so_pin_hook);
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)soPin,
                                (CK_ULONG)XSTRLEN(soPin),
                                (CK_UTF8CHAR_PTR)otherSoPin,
                                (CK_ULONG)XSTRLEN(otherSoPin));
        WP11_Slot_SetPinCheckHook(NULL);
        CHECK_RV(hookRv, "SO PIN changed during the check", CKR_OK);
        CHECK_RV(rv, "overtaken SO PIN check refused", CKR_FUNCTION_FAILED);
        CHECK_TRUE((token_flags(slot) & CKF_SO_PIN_COUNT_LOW) == 0,
                   "overtaken SO PIN check not counted as a failure");
        funcList->C_Logout(session);
        rv = login(session, CKU_SO, newSoPin);
        CHECK_RV(rv, "SO logs in with the changed PIN", CKR_OK);
        if (rv == CKR_OK)
            funcList->C_Logout(session);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#ifdef DEBUG_WOLFPKCS11
#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Test_FailSeedRandom(int fail);
#ifdef __cplusplus
}
#endif

/* A failed C_SeedRandom leaves the slot with a working generator. */
static void seed_random_failure_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    byte seed[16] = { 1, 2, 3, 4 };
    byte data[32];
    byte acc = 0;
    size_t i;

    printf("--- C_GenerateRandom after a failed C_SeedRandom ---\n");
    rv = token_setup(&slot);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv == CKR_OK) {
        WP11_Test_FailSeedRandom(1);
        rv = funcList->C_SeedRandom(session, seed, sizeof(seed));
        WP11_Test_FailSeedRandom(0);
        CHECK_RV(rv, "seeding fails", CKR_FUNCTION_FAILED);
        XMEMSET(data, 0, sizeof(data));
        rv = funcList->C_GenerateRandom(session, data, sizeof(data));
        for (i = 0; i < sizeof(data); i++)
            acc |= data[i];
        CHECK_TRUE(rv == CKR_OK && acc != 0, "random generation still works");
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#ifdef SLOT_TEST_PROCESSES
typedef int (*child_fn)(void);

/* Run fn in a child that loads the library itself and exits without
 * C_Finalize. */
static int run_in_child(child_fn fn)
{
    pid_t pid;
    int status = 0;

    fflush(stdout);
    fflush(stderr);
    pid = fork();
    if (pid < 0)
        return CHILD_SETUP;
    if (pid == 0) {
        int res = CHILD_SETUP;

        if (pkcs11_load() == CKR_OK)
            res = fn();
        fflush(stdout);
        fflush(stderr);
        _exit(res);
    }
    if (waitpid(pid, &status, 0) != pid)
        return CHILD_SETUP;
    if (!WIFEXITED(status))
        return CHILD_FAIL;
    return WEXITSTATUS(status);
}

static int child_setup(void)
{
    CK_SLOT_ID slot = 0;
    CK_RV rv = token_setup(&slot);

    funcList->C_Finalize(NULL);
    return rv == CKR_OK ? CHILD_PASS : CHILD_SETUP;
}

/* Fail all but the last allowed login for both users, then exit. */
static int child_fail_logins(void)
{
    CK_RV rv;
    int i;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    for (i = 0; rv == CKR_OK && i < WP11_MAX_LOGIN_FAILS_USER - 1; i++) {
        rv = login(session, CKU_USER, wrongPin);
        rv = (rv == CKR_PIN_INCORRECT) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    for (i = 0; rv == CKR_OK && i < WP11_MAX_LOGIN_FAILS_SO - 1; i++) {
        rv = login(session, CKU_SO, wrongPin);
        rv = (rv == CKR_PIN_INCORRECT) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    return rv == CKR_OK ? CHILD_PASS : CHILD_SETUP;
}

/* The failures of the previous process are counted. */
static int child_check_final_try(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_FLAGS flags;
    int res = CHILD_FAIL;

    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    if (rv != CKR_OK)
        return CHILD_SETUP;
    flags = token_flags(slot);
    if ((flags & CKF_USER_PIN_FINAL_TRY) && (flags & CKF_SO_PIN_FINAL_TRY))
        res = CHILD_PASS;
    else
        printf("  token flags 0x%lx\n", (unsigned long)flags);
    rv = open_rw(slot, &session);
    if (rv != CKR_OK)
        res = CHILD_SETUP;
    if (res == CHILD_PASS &&
            login(session, CKU_USER, wrongPin) != CKR_PIN_INCORRECT) {
        res = CHILD_FAIL;
    }
    if (res == CHILD_PASS &&
            login(session, CKU_USER, userPin) != CKR_PIN_LOCKED) {
        printf("  user not locked after the last failure\n");
        res = CHILD_FAIL;
    }
    funcList->C_Finalize(NULL);
    return res;
}

/* A failure followed by a successful login, then exit. */
static int child_fail_then_login(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    if (rv == CKR_OK)
        rv = open_rw(slot, &session);
    if (rv == CKR_OK) {
        rv = login(session, CKU_USER, wrongPin);
        rv = (rv == CKR_PIN_INCORRECT) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    return rv == CKR_OK ? CHILD_PASS : CHILD_SETUP;
}

static int child_check_no_failures(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_FLAGS flags;

    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    if (rv != CKR_OK)
        return CHILD_SETUP;
    flags = token_flags(slot);
    funcList->C_Finalize(NULL);
    if (flags & CKF_USER_PIN_COUNT_LOW) {
        printf("  token flags 0x%lx\n", (unsigned long)flags);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static void lockout_survives_exit_test(void)
{
    int res;

    printf("--- failed logins are counted across processes ---\n");
    cleanup_test_files();
    res = run_in_child(child_setup);
    CHECK_TRUE(res == CHILD_PASS, "set up token");
    if (res == CHILD_PASS) {
        res = run_in_child(child_fail_logins);
        CHECK_TRUE(res == CHILD_PASS,
                   "fail logins and exit without C_Finalize");
    }
    if (res == CHILD_PASS) {
        res = run_in_child(child_check_final_try);
        CHECK_TRUE(res == CHILD_PASS,
                   "next process sees the failures and locks the user");
    }

    printf("--- a successful login clears the stored failures ---\n");
    cleanup_test_files();
    res = run_in_child(child_setup);
    if (res == CHILD_PASS)
        res = run_in_child(child_fail_then_login);
    CHECK_TRUE(res == CHILD_PASS,
               "fail, log in and exit without C_Finalize");
    if (res == CHILD_PASS) {
        res = run_in_child(child_check_no_failures);
        CHECK_TRUE(res == CHILD_PASS,
                   "next process sees no failed logins");
    }
    cleanup_test_files();
}

static const char p2Label[] = "other-process-object";
static int pauseToParent = -1;
static int pauseFromParent = -1;
static int expectFails = 0;
static int expectObject = 0;

#define CHILD_SKIP      3

/* Wait in the first process while the parent runs the other one. */
static int pause_for_parent(void)
{
    char c = 'p';

    if (write(pauseToParent, &c, 1) != 1 || read(pauseFromParent, &c, 1) != 1)
        return -1;
    return 0;
}

/* Run first in a child that pauses once, run other in a second child while
 * it waits, then let first finish. Returns first's exit code. */
static int run_with_other(child_fn first, child_fn other, int* otherRes)
{
    int toParent[2];
    int fromParent[2];
    pid_t pid;
    int status = 0;
    int paused;
    int res = CHILD_FAIL;
    char c = 0;

    *otherRes = CHILD_SETUP;
    if (pipe(toParent) != 0)
        return CHILD_SETUP;
    if (pipe(fromParent) != 0) {
        close(toParent[0]);
        close(toParent[1]);
        return CHILD_SETUP;
    }
    fflush(stdout);
    fflush(stderr);
    pid = fork();
    if (pid == 0) {
        res = CHILD_SETUP;
        close(toParent[0]);
        close(fromParent[1]);
        pauseToParent = toParent[1];
        pauseFromParent = fromParent[0];
        if (pkcs11_load() == CKR_OK)
            res = first();
        fflush(stdout);
        _exit(res);
    }
    close(toParent[1]);
    close(fromParent[0]);
    paused = (pid > 0 && read(toParent[0], &c, 1) == 1);
    if (paused) {
        *otherRes = run_in_child(other);
        c = 'g';
        if (write(fromParent[1], &c, 1) != 1)
            *otherRes = CHILD_SETUP;
    }
    close(fromParent[1]);
    close(toParent[0]);
    if (pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status))
        res = WEXITSTATUS(status);
    (void)chmod(TEST_DIR, 0700);
    return res;
}

static CK_RV create_public_object(CK_SESSION_HANDLE session)
{
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    byte value[4] = { 5, 6, 7, 8 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass,     sizeof(dataClass)   },
        { CKA_TOKEN,   &yes,           sizeof(yes)         },
        { CKA_PRIVATE, &no,            sizeof(no)          },
        { CKA_LABEL,   (void*)p2Label, sizeof(p2Label) - 1 },
        { CKA_VALUE,   value,          sizeof(value)       },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
}

static CK_RV wrong_user_login(CK_SESSION_HANDLE session)
{
    CK_RV rv = login(session, CKU_USER, wrongPin);

    return (rv == CKR_PIN_INCORRECT) ? CKR_OK : CKR_GENERAL_ERROR;
}

static CK_RV child_session(CK_SLOT_ID* slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(slot);
    if (rv == CKR_OK)
        rv = open_rw(*slot, session);
    return rv;
}

/* Stores a public object without logging in. */
static int child_add_object(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = child_session(&slot, &session);
    if (rv == CKR_OK)
        rv = create_public_object(session);
    funcList->C_Finalize(NULL);
    return rv == CKR_OK ? CHILD_PASS : CHILD_SETUP;
}

/* Pass when exactly expectFails failed user logins are stored. */
static int child_check_fails(void)
{
    CK_RV rv;
    int i;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &dataClass,     sizeof(dataClass)   },
        { CKA_LABEL, (void*)p2Label, sizeof(p2Label) - 1 },
    };
    CK_ULONG found = 0;
    int res = CHILD_PASS;

    rv = child_session(&slot, &session);
    if (rv != CKR_OK)
        return CHILD_SETUP;
    if (expectObject &&
            (find_count(session, findTmpl, 2, &found) != CKR_OK ||
             found != 1)) {
        printf("  other process's object found %lu times\n",
               (unsigned long)found);
        res = CHILD_FAIL;
    }
    for (i = expectFails; i < WP11_MAX_LOGIN_FAILS_USER; i++) {
        if (wrong_user_login(session) != CKR_OK) {
            printf("  locked after %d more failures\n", i - expectFails);
            res = CHILD_FAIL;
            break;
        }
    }
    if (res == CHILD_PASS &&
            login(session, CKU_USER, userPin) != CKR_PIN_LOCKED) {
        printf("  fewer than %d failed logins stored\n", expectFails);
        res = CHILD_FAIL;
    }
    funcList->C_Finalize(NULL);
    return res;
}

static void check_stored(int fails, int object, const char* what)
{
    expectFails = fails;
    expectObject = object;
    CHECK_TRUE(run_in_child(child_check_fails) == CHILD_PASS, what);
}

static int setup_token(void)
{
    int res;

    cleanup_test_files();
    res = run_in_child(child_setup);
    CHECK_TRUE(res == CHILD_PASS, "set up token");
    return res;
}

static int check_pair(int res, int otherRes, const char* first,
                      const char* other)
{
    CHECK_TRUE(otherRes == CHILD_PASS, other);
    CHECK_TRUE(res == CHILD_PASS, first);
    return res == CHILD_PASS && otherRes == CHILD_PASS;
}

/* Fail all but the last allowed user login and exit. */
static int child_fail_user_logins(void)
{
    CK_RV rv;
    int i;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = child_session(&slot, &session);
    for (i = 0; rv == CKR_OK && i < WP11_MAX_LOGIN_FAILS_USER - 1; i++)
        rv = wrong_user_login(session);
    funcList->C_Finalize(NULL);
    return rv == CKR_OK ? CHILD_PASS : CHILD_SETUP;
}

static int child_lock_user(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = child_session(&slot, &session);
    if (rv == CKR_OK)
        rv = wrong_user_login(session);
    funcList->C_Finalize(NULL);
    return rv == CKR_OK ? CHILD_PASS : CHILD_SETUP;
}

/* Make the token directory unwritable. CHILD_SKIP when it stays writable, as
 * for root. */
static int store_dir_read_only(void)
{
    FILE* f;
    char probe[512];

    if (chmod(TEST_DIR, 0500) != 0)
        return CHILD_SETUP;
    snprintf(probe, sizeof(probe), "%s" PATH_SEP "probe", TEST_DIR);
    f = fopen(probe, "wb");
    if (f != NULL) {
        fclose(f);
        (void)remove(probe);
        (void)chmod(TEST_DIR, 0700);
        return CHILD_SKIP;
    }
    return CHILD_PASS;
}

/* Log in, failing or not, while the token directory is unwritable, then
 * pause. */
static int child_unwritten(CK_SESSION_HANDLE* session, CK_SLOT_ID* slot,
                           int reset)
{
    CK_RV rv;
    int res;

    if (child_session(slot, session) != CKR_OK)
        return CHILD_SETUP;
    res = store_dir_read_only();
    if (res != CHILD_PASS)
        return res;
    if (reset)
        rv = login(*session, CKU_USER, userPin);
    else
        rv = wrong_user_login(*session);
    if (chmod(TEST_DIR, 0700) != 0 || rv != CKR_OK)
        return CHILD_SETUP;
    return pause_for_parent() == 0 ? CHILD_PASS : CHILD_SETUP;
}

static int child_unwritten_then_fail(void)
{
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int res = child_unwritten(&session, &slot, 0);

    if (res == CHILD_PASS && wrong_user_login(session) != CKR_OK)
        res = CHILD_FAIL;
    return res;
}

static int child_unwritten_then_finalize(void)
{
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int res = child_unwritten(&session, &slot, 0);

    if (res == CHILD_PASS && funcList->C_Finalize(NULL) != CKR_OK)
        res = CHILD_FAIL;
    return res;
}

static int child_unwritten_reset(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int res = child_unwritten(&session, &slot, 1);

    if (res != CHILD_PASS)
        return res;
    rv = create_public_object(session);
    if (rv != CKR_OK || !(token_flags(slot) & CKF_USER_PIN_LOCKED)) {
        printf("  create 0x%lx, token flags 0x%lx\n", (unsigned long)rv,
               (unsigned long)token_flags(slot));
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

/* A failed login while WOLFPKCS11_NO_STORE pauses storage, then another
 * process stores and a second failed login follows. */
static int child_paused_then_fail(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    if (child_session(&slot, &session) != CKR_OK)
        return CHILD_SETUP;
    XSETENV("WOLFPKCS11_NO_STORE", "1", 1);
    rv = wrong_user_login(session);
    (void)unsetenv("WOLFPKCS11_NO_STORE");
    if (rv != CKR_OK || pause_for_parent() != 0)
        return CHILD_SETUP;
    return wrong_user_login(session) == CKR_OK ? CHILD_PASS : CHILD_FAIL;
}

/* Failed logins whose store failed are stored by a later login or by
 * C_Finalize, merged with what another process stored meanwhile. */
static void unwritten_lockout_test(void)
{
    int res;
    int otherRes = CHILD_SETUP;

    printf("--- a failed login while storage is paused ---\n");
    if (setup_token() != CHILD_PASS)
        return;
    res = run_with_other(child_paused_then_fail, child_add_object, &otherRes);
    if (check_pair(res, otherRes, "next login loads the token again",
                   "other process stores an object")) {
        check_stored(2, 1, "both failures stored with the other object");
    }

    printf("--- a failed lockout store is retried by a later login ---\n");
    if (setup_token() != CHILD_PASS)
        return;
    res = run_with_other(child_unwritten_then_fail, child_add_object,
                         &otherRes);
    if (res == CHILD_SKIP) {
        printf("  store directory stays writable, skipped\n");
        cleanup_test_files();
        return;
    }
    if (check_pair(res, otherRes, "next login loads the token again",
                   "other process stores an object")) {
        check_stored(2, 1, "both failures stored with the other object");
    }

    printf("--- a stale C_Finalize stores an unstored failure ---\n");
    if (setup_token() != CHILD_PASS)
        return;
    res = run_with_other(child_unwritten_then_finalize, child_add_object,
                         &otherRes);
    if (check_pair(res, otherRes, "finalize after the other process stored",
                   "other process stores an object")) {
        check_stored(1, 1, "failure stored with the other object");
    }

    printf("--- a stored lockout survives an unstored login reset ---\n");
    if (setup_token() != CHILD_PASS)
        return;
    res = run_in_child(child_fail_user_logins);
    CHECK_TRUE(res == CHILD_PASS, "fail all but the last login");
    if (res == CHILD_PASS) {
        res = run_with_other(child_unwritten_reset, child_lock_user,
                             &otherRes);
        if (check_pair(res, otherRes, "PIN locked after loading again",
                       "other process locks the PIN")) {
            check_stored(WP11_MAX_LOGIN_FAILS_USER, 0, "lockout stays stored");
        }
    }
    cleanup_test_files();
}

#ifdef DEBUG_WOLFPKCS11
static const char* otherUserPin = "other-user-pin-1234";

static void pause_hook(void)
{
    WP11_Slot_SetPinCheckHook(NULL);
    if (pause_for_parent() != 0)
        printf("  pipe to the test process failed\n");
}

static int child_fail_while_other_stores(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    if (child_session(&slot, &session) != CKR_OK)
        return CHILD_SETUP;
    WP11_Slot_SetPinCheckHook(pause_hook);
    rv = wrong_user_login(session);
    WP11_Slot_SetPinCheckHook(NULL);
    return rv == CKR_OK ? CHILD_PASS : CHILD_FAIL;
}

/* Adds a token object and a failed login, stored before the other exits. */
static int child_object_and_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = child_session(&slot, &session);
    if (rv == CKR_OK)
        rv = create_public_object(session);
    if (rv == CKR_OK)
        rv = wrong_user_login(session);
    funcList->C_Finalize(NULL);
    return rv == CKR_OK ? CHILD_PASS : CHILD_SETUP;
}

/* C_Login's result matches the session state when another process changes
 * the PIN while it is checked. */
static int child_login_while_pin_changes(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_INFO info;

    rv = child_session(&slot, &session);
    if (rv == CKR_OK)
        rv = wrong_user_login(session);
    if (rv != CKR_OK)
        return CHILD_SETUP;
    WP11_Slot_SetPinCheckHook(pause_hook);
    rv = login(session, CKU_USER, userPin);
    WP11_Slot_SetPinCheckHook(NULL);
    if (funcList->C_GetSessionInfo(session, &info) != CKR_OK)
        return CHILD_SETUP;
    if ((rv == CKR_OK) != (info.state == CKS_RW_USER_FUNCTIONS)) {
        printf("  login 0x%lx, session state %lu\n", (unsigned long)rv,
               (unsigned long)info.state);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static int child_change_user_pin(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = child_session(&slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)userPin,
                                (CK_ULONG)XSTRLEN(userPin),
                                (CK_UTF8CHAR_PTR)otherUserPin,
                                (CK_ULONG)XSTRLEN(otherUserPin));
    }
    funcList->C_Finalize(NULL);
    return rv == CKR_OK ? CHILD_PASS : CHILD_SETUP;
}

/* Lockout stores that meet a store by another process during the check. */
static void stale_lockout_store_test(void)
{
    int res;
    int otherRes = CHILD_SETUP;

    printf("--- failed login stored after another process stored ---\n");
    if (setup_token() != CHILD_PASS)
        return;
    res = run_with_other(child_fail_while_other_stores,
                         child_object_and_failure, &otherRes);
    if (check_pair(res, otherRes, "first process fails its login and exits",
                   "other process adds an object and a failed login")) {
        check_stored(2, 1, "both failures counted and the other object kept");
    }

    printf("--- login while another process changes the PIN ---\n");
    if (setup_token() != CHILD_PASS)
        return;
    res = run_with_other(child_login_while_pin_changes, child_change_user_pin,
                         &otherRes);
    (void)check_pair(res, otherRes, "login result matches the session state",
                     "other process changes the user PIN");
    cleanup_test_files();
}
#endif
#endif

#if defined(__GNUC__)
    #pragma GCC diagnostic pop
#endif

static int run_test(void)
{
    CK_RV rv;

#ifdef SLOT_TEST_PROCESSES
    lockout_survives_exit_test();
    unwritten_lockout_test();
#ifdef DEBUG_WOLFPKCS11
    stale_lockout_store_test();
#endif
#endif

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    close_all_sessions_logs_out_test();
#ifdef DEBUG_WOLFPKCS11
    seed_random_failure_test();
#endif
#if defined(DEBUG_WOLFPKCS11) && !defined(WOLFPKCS11_NO_TIME)
    so_pin_change_during_check_test();
#endif

    pkcs11_unload();
    cleanup_test_files();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 slot state test ===\n");
    cleanup_test_files();
    run_test();
    return pkcs11_test_summary();
}
