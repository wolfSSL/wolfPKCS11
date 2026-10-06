/* token_store_test.c
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
 * Token persistence must stay consistent with the in-memory token: every
 * token object is persisted and reloaded, and a failure to persist token
 * state is reported to the caller instead of being reported as success.
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

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_TPM_STORE) && \
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_NO_ENV) && \
    !defined(WOLFPKCS11_USER_ENV) && !defined(_WIN32)

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_DIR "./store/token_store_test"

static const char* soPin = "password123456";
static const char* userPin = "wolfpkcs11-test";
static const char tokenLabel[] = "token-store-test";
static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;
static byte keyData[16] = { 0 };

static void clear_store_dir(void)
{
    DIR* dir;
    struct dirent* ent;
    char path[512];

    (void)mkdir("./store", 0700);
    (void)chmod(TEST_DIR, 0700);
    dir = opendir(TEST_DIR);
    if (dir == NULL) {
        (void)mkdir(TEST_DIR, 0700);
        return;
    }
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        snprintf(path, sizeof(path), "%s/%s", TEST_DIR, ent->d_name);
        if (remove(path) != 0)
            (void)rmdir(path);
    }
    closedir(dir);
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

/* Initialize the library and provision a fresh token with a user PIN. */
static CK_RV token_setup(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE soSession = CK_INVALID_HANDLE;
    unsigned char label[32];

    clear_store_dir();
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(slot);
    if (rv == CKR_OK) {
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
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
    }
    if (soSession != CK_INVALID_HANDLE) {
        funcList->C_Logout(soSession);
        funcList->C_CloseSession(soSession);
    }
    return rv;
}

static CK_RV user_session(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(*session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
    }
    return rv;
}

static void close_session(CK_SESSION_HANDLE session)
{
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
}

static CK_RV create_token_secret(CK_SESSION_HANDLE session, const char* label,
                                 CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_VALUE,    keyData,      sizeof(keyData)     },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_LABEL,    NULL,         0                   },
    };

    tmpl[5].pValue = (CK_VOID_PTR)label;
    tmpl[5].ulValueLen = (CK_ULONG)XSTRLEN(label);
    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), obj);
}

static CK_ULONG count_label(CK_SESSION_HANDLE session, const char* label)
{
    CK_RV rv;
    CK_OBJECT_HANDLE found[8];
    CK_ULONG foundCnt = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_LABEL, NULL, 0 },
    };

    tmpl[0].pValue = (CK_VOID_PTR)label;
    tmpl[0].ulValueLen = (CK_ULONG)XSTRLEN(label);
    rv = funcList->C_FindObjectsInit(session, tmpl, 1);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, found, 8, &foundCnt);
        funcList->C_FindObjectsFinal(session);
    }
    return (rv == CKR_OK) ? foundCnt : 0;
}

/* Path of the stored record of a token object. */
static void object_record_path(CK_SLOT_ID slot, int objId, char* path,
                               size_t pathSz)
{
    snprintf(path, pathSz, "%s/wp11_obj_%016lx_%016lx", TEST_DIR,
             (unsigned long)slot, (unsigned long)objId);
}

/* Read a stored file into buf, returning its length or -1 on error. */
static long read_store_file(const char* path, byte* buf, size_t bufSz)
{
    FILE* f;
    long len;

    f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    len = (long)fread(buf, 1, bufSz, f);
    fclose(f);
    return len;
}

/* Reload the token from storage and open a user session on it. */
static CK_RV reload(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    funcList->C_Finalize(NULL);
    rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, session);
    return rv;
}

/* Token objects keep being persisted after storage is paused and resumed. */
static void test_objects_persist_across_storage_pause(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;

    printf("\n--- token objects persist across a storage pause ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "pause-first", &obj);
        CHECK_RV(rv, "create first token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        XSETENV("WOLFPKCS11_NO_STORE", "1", 1);
        rv = create_token_secret(session, "pause-second", &obj);
        unsetenv("WOLFPKCS11_NO_STORE");
        CHECK_RV(rv, "create token object while storage is paused", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "pause-third", &obj);
        CHECK_RV(rv, "create token object after storage resumes", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;

    if (rv == CKR_OK) {
        rv = reload(slot, &session);
        CHECK_RV(rv, "reload token", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "pause-first") == 1,
                   "object stored before the pause is reloaded");
        CHECK_TRUE(count_label(session, "pause-second") == 1,
                   "object created during the pause is reloaded");
        CHECK_TRUE(count_label(session, "pause-third") == 1,
                   "object created after the pause is reloaded");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A token object whose record cannot be committed is not reported created. */
static void test_create_reports_commit_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    char path[512];
    int blocked = 0;

    printf("\n--- token object creation reports a commit failure ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "commit-first", &obj);
        CHECK_RV(rv, "create first token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        object_record_path(slot, 1, path, sizeof(path));
        blocked = (mkdir(path, 0700) == 0);
        CHECK_TRUE(blocked, "occupy the next object record path");
    }
    if (blocked) {
        rv = create_token_secret(session, "commit-second", &obj);
        CHECK_TRUE(rv != CKR_OK,
                   "create fails when the object cannot be committed");
        CHECK_TRUE(count_label(session, "commit-second") == 0,
                   "uncommitted object is not in the token");
        CHECK_TRUE(count_label(session, "commit-first") == 1,
                   "committed object is still in the token");
        (void)rmdir(path);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A failed token object store leaves the stored token record unchanged. */
static void test_token_record_kept_on_failed_store(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    char path[512];
    char tokenPath[512];
    byte before[1024];
    byte after[1024];
    long beforeLen = -1;
    long afterLen = -1;
    int blocked = 0;

    printf("\n--- token record is kept when an object store fails ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "record-first", &obj);
        CHECK_RV(rv, "create first token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        snprintf(tokenPath, sizeof(tokenPath), "%s/wp11_token_%016lx",
                 TEST_DIR, (unsigned long)slot);
        beforeLen = read_store_file(tokenPath, before, sizeof(before));
        CHECK_TRUE(beforeLen > 0 && beforeLen < (long)sizeof(before),
                   "token record is stored");
        object_record_path(slot, 1, path, sizeof(path));
        blocked = (beforeLen > 0) && (mkdir(path, 0700) == 0);
    }
    if (blocked) {
        rv = create_token_secret(session, "record-second", &obj);
        CHECK_TRUE(rv != CKR_OK,
                   "create fails when the object cannot be committed");
        afterLen = read_store_file(tokenPath, after, sizeof(after));
        CHECK_TRUE(afterLen == beforeLen &&
                   XMEMCMP(before, after, (size_t)beforeLen) == 0,
                   "token record is unchanged by the failed store");
        (void)rmdir(path);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A PIN change that cannot be stored leaves the stored PIN in effect. */
static void test_pin_change_store_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    static const char* newPin = "wolfpkcs11-next";

    if (geteuid() == 0) {
        printf("\nSkipping PIN store failure test when run as root\n");
        return;
    }
    printf("\n--- PIN change that cannot be stored is not applied ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK && chmod(TEST_DIR, 0500) == 0) {
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)userPin,
                                (CK_ULONG)XSTRLEN(userPin),
                                (CK_UTF8CHAR_PTR)newPin,
                                (CK_ULONG)XSTRLEN(newPin));
        (void)chmod(TEST_DIR, 0700);
        CHECK_TRUE(rv != CKR_OK, "PIN change reports the store failure");
        funcList->C_Logout(session);
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
        CHECK_RV(rv, "stored PIN still logs in", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A first user PIN that cannot be stored does not log in. */
static void test_init_pin_store_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE soSession = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    unsigned char label[32];

    if (geteuid() == 0) {
        printf("\nSkipping user PIN store failure test when run as root\n");
        return;
    }
    printf("\n--- user PIN that cannot be stored is not applied ---\n");
    clear_store_dir();
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    if (rv == CKR_OK) {
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &soSession);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(soSession, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK && chmod(TEST_DIR, 0500) == 0) {
        rv = funcList->C_InitPIN(soSession, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
        (void)chmod(TEST_DIR, 0700);
        CHECK_TRUE(rv != CKR_OK, "user PIN set reports the store failure");
        close_session(soSession);
        soSession = CK_INVALID_HANDLE;
        rv = user_session(slot, &session);
        CHECK_TRUE(rv != CKR_OK, "unstored user PIN does not log in");
    }
    close_session(soSession);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* A token reset that cannot be stored leaves the stored token in effect. */
static void test_token_reset_store_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    unsigned char label[32];
    static const char* wrongPin = "not-the-so-pin";

    if (geteuid() == 0) {
        printf("\nSkipping token reset store failure test when run as root\n");
        return;
    }
    printf("\n--- token reset that cannot be stored is not applied ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "reset-keep", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK && chmod(TEST_DIR, 0500) == 0) {
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        (void)chmod(TEST_DIR, 0700);
        CHECK_TRUE(rv != CKR_OK, "token reset reports the store failure");
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)wrongPin,
                                   (CK_ULONG)XSTRLEN(wrongPin), label);
        CHECK_TRUE(rv != CKR_OK, "token reset still requires the SO PIN");
        rv = user_session(slot, &session);
        CHECK_RV(rv, "stored user PIN still logs in", CKR_OK);
        if (rv == CKR_OK) {
            CHECK_TRUE(count_label(session, "reset-keep") == 1,
                       "stored token object is still present");
        }
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

static int run_tests(void)
{
    CK_RV rv;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    test_objects_persist_across_storage_pause();
    test_create_reports_commit_failure();
    test_token_record_kept_on_failed_store();
    test_pin_change_store_failure();
    test_init_pin_store_failure();
    test_token_reset_store_failure();

    clear_store_dir();
    pkcs11_unload();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
    unsetenv("WOLFPKCS11_NO_STORE");

    printf("=== wolfPKCS11 token store test ===\n");
    run_tests();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("Token store test requires the file-backed store, skipping\n");
    return 77;
}

#endif
