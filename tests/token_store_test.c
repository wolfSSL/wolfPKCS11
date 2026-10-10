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
    #define TOKEN_STORE_FILE_TEST
#elif defined(WOLFPKCS11_TPM_STORE) && defined(DEBUG_WOLFPKCS11) && \
    !defined(WOLFPKCS11_NO_ENV) && !defined(WOLFPKCS11_USER_ENV) && \
    !defined(_WIN32)
    #define TOKEN_STORE_TPM_TEST
#endif

#if defined(TOKEN_STORE_FILE_TEST) || defined(TOKEN_STORE_TPM_TEST)

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

#if defined(TOKEN_STORE_FILE_TEST) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY) && !defined(NO_WOLFSSL_MEMORY)
#define TEST_ALLOC_FAILURE
static int failAllocs = 0;

static void* test_malloc(size_t n)
{
    if (failAllocs)
        return NULL;
    return malloc(n);
}

static void test_free(void* p)
{
    free(p);
}

static void* test_realloc(void* p, size_t n)
{
    if (failAllocs)
        return NULL;
    return realloc(p, n);
}
#endif

#ifdef TOKEN_STORE_FILE_TEST
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
#endif

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

#ifdef TOKEN_STORE_FILE_TEST
    clear_store_dir();
#endif
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

#ifdef TOKEN_STORE_FILE_TEST
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

/* Replace a stored file with len bytes from buf. */
static int write_store_file(const char* path, const byte* buf, size_t len)
{
    FILE* f;
    size_t written;

    f = fopen(path, "wb");
    if (f == NULL)
        return -1;
    written = fwrite(buf, 1, len, f);
    if (fclose(f) != 0 || written != len)
        return -1;
    return 0;
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

/* C_Finalize reports a token that could not be stored. */
static void test_finalize_reports_store_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;

    if (geteuid() == 0) {
        printf("\nSkipping finalize store failure test when run as root\n");
        return;
    }
    printf("\n--- finalize reports a token store failure ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "final-first", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (rv == CKR_OK && chmod(TEST_DIR, 0500) == 0) {
        rv = funcList->C_Finalize(NULL);
        (void)chmod(TEST_DIR, 0700);
        CHECK_RV(rv, "finalize reports the store failure",
                 CKR_FUNCTION_FAILED);
        rv = lib_init();
        CHECK_RV(rv, "library initializes after the failed finalize", CKR_OK);
        if (rv == CKR_OK)
            rv = user_session(slot, &session);
        if (rv == CKR_OK) {
            CHECK_TRUE(count_label(session, "final-first") == 1,
                       "previously stored object is still present");
        }
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* The library initializes once an unreadable token record is repaired. */
static void test_init_retry_after_load_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    char tokenPath[512];
    byte record[1024];
    long recordLen = -1;

    printf("\n--- library initializes after a failed initialization ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "retry-keep", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);

    if (rv == CKR_OK) {
        snprintf(tokenPath, sizeof(tokenPath), "%s/wp11_token_%016lx",
                 TEST_DIR, (unsigned long)slot);
        recordLen = read_store_file(tokenPath, record, sizeof(record));
        CHECK_TRUE(recordLen > 0 && recordLen < (long)sizeof(record),
                   "token record is stored");
    }
    if (recordLen > 0) {
        CHECK_TRUE(write_store_file(tokenPath, record, 4) == 0,
                   "truncate the token record");
        rv = lib_init();
        CHECK_TRUE(rv != CKR_OK, "initialize fails on a truncated record");
        if (rv == CKR_OK)
            funcList->C_Finalize(NULL);
        rv = write_store_file(tokenPath, record, (size_t)recordLen) == 0 ?
             CKR_OK : CKR_GENERAL_ERROR;
        if (rv == CKR_OK)
            rv = lib_init();
        CHECK_RV(rv, "initialize succeeds once the record is restored",
                 CKR_OK);
        if (rv == CKR_OK) {
            rv = user_session(slot, &session);
            CHECK_RV(rv, "user logs in after the retry", CKR_OK);
        }
        if (rv == CKR_OK) {
            CHECK_TRUE(count_label(session, "retry-keep") == 1,
                       "stored object is loaded after the retry");
        }
        close_session(session);
        funcList->C_Finalize(NULL);
    }
}

/* Destroying a token object reports stored data that cannot be removed. */
static void test_destroy_reports_unstore_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE first;
    CK_OBJECT_HANDLE second;
    char keyPath[512];
    char innerPath[600];
    int blocked = 0;

    printf("\n--- destroy reports stored data that cannot be removed ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "destroy-first", &first);
        CHECK_RV(rv, "create first token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "destroy-second", &second);
        CHECK_RV(rv, "create second token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        snprintf(keyPath, sizeof(keyPath), "%s/wp11_symmkey_%016lx_%016lx",
                 TEST_DIR, (unsigned long)slot, 1UL);
        snprintf(innerPath, sizeof(innerPath), "%s/keep", keyPath);
        blocked = remove(keyPath) == 0 && mkdir(keyPath, 0700) == 0 &&
                  write_store_file(innerPath, keyData, sizeof(keyData)) == 0;
        CHECK_TRUE(blocked, "make the stored key data unremovable");
    }
    if (blocked) {
        rv = funcList->C_DestroyObject(session, second);
        CHECK_TRUE(rv != CKR_OK,
                   "destroy reports stored data that was not removed");
        CHECK_TRUE(count_label(session, "destroy-first") == 1,
                   "other token object is still present");
        (void)remove(innerPath);
        (void)rmdir(keyPath);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A token object never written to storage can still be destroyed. */
static void test_destroy_unstored_object(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;

    printf("\n--- destroy of an object created while paused ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        XSETENV("WOLFPKCS11_NO_STORE", "1", 1);
        rv = create_token_secret(session, "paused-destroy", &obj);
        unsetenv("WOLFPKCS11_NO_STORE");
        CHECK_RV(rv, "create token object while storage is paused", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_DestroyObject(session, obj);
        CHECK_RV(rv, "destroy the never stored object", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifdef TEST_ALLOC_FAILURE
/* Object creation fails cleanly when memory cannot be allocated. */
static void test_create_object_out_of_memory(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_VALUE,    keyData,      sizeof(keyData)     },
        { CKA_TOKEN,    &ckFalse,     sizeof(ckFalse)     },
    };

    printf("\n--- object creation fails cleanly without memory ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        failAllocs = 1;
        rv = funcList->C_CreateObject(session, tmpl,
                                      sizeof(tmpl) / sizeof(*tmpl), &obj);
        failAllocs = 0;
        CHECK_TRUE(rv != CKR_OK, "create fails when allocation fails");
        rv = funcList->C_CreateObject(session, tmpl,
                                      sizeof(tmpl) / sizeof(*tmpl), &obj);
        CHECK_RV(rv, "create succeeds once memory is available", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

/* A token record from before the trailing fields were added still loads. */
static void test_load_record_without_trailing_fields(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    char tokenPath[512];
    byte record[1024];
    long recordLen = -1;
    long dropLen;

    printf("\n--- token record without trailing fields loads ---\n");
    for (dropLen = 4; dropLen <= 8; dropLen += 4) {
        rv = token_setup(&slot);
        CHECK_RV(rv, "token setup", CKR_OK);
        if (rv == CKR_OK)
            rv = user_session(slot, &session);
        if (rv == CKR_OK) {
            rv = create_token_secret(session, "legacy-keep", &obj);
            CHECK_RV(rv, "create token object", CKR_OK);
        }
        close_session(session);
        session = CK_INVALID_HANDLE;
        funcList->C_Finalize(NULL);
        if (rv == CKR_OK) {
            snprintf(tokenPath, sizeof(tokenPath), "%s/wp11_token_%016lx",
                     TEST_DIR, (unsigned long)slot);
            recordLen = read_store_file(tokenPath, record, sizeof(record));
            CHECK_TRUE(recordLen > dropLen && recordLen < (long)sizeof(record),
                       "token record is stored");
        }
        if (rv == CKR_OK && recordLen > dropLen) {
            CHECK_TRUE(write_store_file(tokenPath, record,
                                        (size_t)(recordLen - dropLen)) == 0,
                       "drop trailing token record fields");
            rv = lib_init();
            CHECK_RV(rv, "initialize with the shorter record", CKR_OK);
            if (rv == CKR_OK) {
                rv = user_session(slot, &session);
                CHECK_RV(rv, "user logs in", CKR_OK);
            }
            if (rv == CKR_OK) {
                CHECK_TRUE(count_label(session, "legacy-keep") == 1,
                           "stored object is loaded");
            }
            close_session(session);
            session = CK_INVALID_HANDLE;
            funcList->C_Finalize(NULL);
        }
    }
}
#endif /* TOKEN_STORE_FILE_TEST */

#ifdef TOKEN_STORE_TPM_TEST
/* Debug-only hook exported by libwolfpkcs11. */
extern int WP11_Test_StoreWriteFailAfter(int writes);

#define MAX_STORE_WRITES 500

/* Reload the token from what storage holds after storing was made to fail. */
static CK_RV reload_stored(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    (void)funcList->C_Finalize(NULL);
    (void)WP11_Test_StoreWriteFailAfter(-1);
    rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, session);
    return rv;
}

/* An object create that fails at any storage write keeps the stored token. */
static void test_interrupted_create_keeps_stored_token(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    int writes;
    int intact = 1;

    printf("\n--- interrupted object create keeps the stored token ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "tpm-keep", &obj);
        CHECK_RV(rv, "create stored token object", CKR_OK);
    }
    for (writes = 0; intact && rv == CKR_OK && writes < MAX_STORE_WRITES;
         writes++) {
        (void)WP11_Test_StoreWriteFailAfter(writes);
        rv = create_token_secret(session, "tpm-new", &obj);
        if (rv == CKR_OK) {
            (void)WP11_Test_StoreWriteFailAfter(-1);
            break;
        }
        close_session(session);
        session = CK_INVALID_HANDLE;
        rv = reload_stored(slot, &session);
        if (rv != CKR_OK || count_label(session, "tpm-keep") != 1 ||
                count_label(session, "tpm-new") != 0) {
            printf("Stored token changed by a store failing after %d "
                   "writes\n", writes);
            intact = 0;
        }
    }
    CHECK_TRUE(intact, "stored token is intact after each failed create");
    CHECK_TRUE(rv == CKR_OK && writes < MAX_STORE_WRITES,
               "create succeeds once storing works");
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A PIN change that fails at any storage write keeps the stored PIN. */
static void test_interrupted_pin_change_keeps_stored_pin(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    int writes;
    int intact = 1;
    static const char* newPin = "wolfpkcs11-next";

    printf("\n--- interrupted PIN change keeps the stored PIN ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "tpm-pin-keep", &obj);
        CHECK_RV(rv, "create stored token object", CKR_OK);
    }
    for (writes = 0; intact && rv == CKR_OK && writes < MAX_STORE_WRITES;
         writes++) {
        (void)WP11_Test_StoreWriteFailAfter(writes);
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)userPin,
                                (CK_ULONG)XSTRLEN(userPin),
                                (CK_UTF8CHAR_PTR)newPin,
                                (CK_ULONG)XSTRLEN(newPin));
        if (rv == CKR_OK) {
            (void)WP11_Test_StoreWriteFailAfter(-1);
            break;
        }
        close_session(session);
        session = CK_INVALID_HANDLE;
        rv = reload_stored(slot, &session);
        if (rv != CKR_OK || count_label(session, "tpm-pin-keep") != 1) {
            printf("Stored token changed by a store failing after %d "
                   "writes\n", writes);
            intact = 0;
        }
    }
    CHECK_TRUE(intact, "stored PIN logs in after each failed PIN change");
    CHECK_TRUE(rv == CKR_OK && writes < MAX_STORE_WRITES,
               "PIN change succeeds once storing works");
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif /* TOKEN_STORE_TPM_TEST */

static int run_tests(void)
{
    CK_RV rv;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

#ifdef TOKEN_STORE_FILE_TEST
    test_objects_persist_across_storage_pause();
    test_create_reports_commit_failure();
    test_token_record_kept_on_failed_store();
    test_pin_change_store_failure();
    test_init_pin_store_failure();
    test_token_reset_store_failure();
    test_finalize_reports_store_failure();
    test_init_retry_after_load_failure();
    test_destroy_reports_unstore_failure();
    test_destroy_unstored_object();
    test_load_record_without_trailing_fields();
#ifdef TEST_ALLOC_FAILURE
    test_create_object_out_of_memory();
#endif

    clear_store_dir();
#else
    test_interrupted_create_keeps_stored_token();
    test_interrupted_pin_change_keeps_stored_pin();
#endif
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
#ifdef TEST_ALLOC_FAILURE
    if (wolfSSL_SetAllocators(test_malloc, test_free, test_realloc) != 0) {
        fprintf(stderr, "FAIL: wolfSSL_SetAllocators\n");
        return 1;
    }
#endif
    run_tests();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("Token store test requires the file-backed store or a debug "
           "TPM store, skipping\n");
    return 77;
}

#endif
