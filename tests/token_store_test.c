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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_DIR "./store/token_store_test"
/* SO key seed, public-object key copies and PIN seeds end the token record. */
#define PUB_EXT_LEN (16 + 2 * 60 + 2 * 16)

/* A FIPS PBKDF2 does not hash a PIN shorter than 14 bytes. */
#ifdef HAVE_FIPS
    #define EMPTY_PIN_REFUSED(rv) ((rv) != CKR_OK)
#else
    #define EMPTY_PIN_REFUSED(rv) ((rv) == CKR_PIN_LEN_RANGE)
#endif

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
/* Allocations left before they fail, or -1 for no limit. */
static int allocsLeft = -1;
/* Allocation that fails alone, counted by allocCnt, or -1 for none. */
static int failOnceAt = -1;
static int allocCnt = 0;

static int test_alloc_fails(void)
{
    if (failOnceAt >= 0 && allocCnt++ == failOnceAt)
        return 1;
    if (allocsLeft == 0)
        return 1;
    if (allocsLeft > 0)
        allocsLeft--;
    return failAllocs;
}

static void* test_malloc(size_t n)
{
    if (test_alloc_fails())
        return NULL;
    return malloc(n);
}

static void test_free(void* p)
{
    free(p);
}

static void* test_realloc(void* p, size_t n)
{
    if (test_alloc_fails())
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

static CK_RV create_token_secret_ex(CK_SESSION_HANDLE session,
                                    const char* label, CK_BBOOL priv,
                                    CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_VALUE,    keyData,      sizeof(keyData)     },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &priv,        sizeof(priv)        },
        { CKA_LABEL,    NULL,         0                   },
    };

    tmpl[5].pValue = (CK_VOID_PTR)label;
    tmpl[5].ulValueLen = (CK_ULONG)XSTRLEN(label);
    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), obj);
}

static CK_RV create_token_secret(CK_SESSION_HANDLE session, const char* label,
                                 CK_OBJECT_HANDLE* obj)
{
    return create_token_secret_ex(session, label, CK_FALSE, obj);
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

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
static CK_KEY_TYPE aesType = CKK_AES;
static byte deriveBaseKey[16] = {
    0x4b, 0x1d, 0x8e, 0x3f, 0xa2, 0x57, 0xc0, 0x69,
    0x9d, 0x24, 0x6b, 0xf8, 0x13, 0xe5, 0x70, 0xac
};
static byte deriveData[16] = { 0 };

/* Derive a token key from an AES base key with CKM_AES_CBC_ENCRYPT_DATA. */
static CK_RV derive_token_secret(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE base, const char* label,
                                 CK_OBJECT_HANDLE* obj)
{
    CK_MECHANISM mech;
    CK_AES_CBC_ENCRYPT_DATA_PARAMS params;
    CK_ULONG valueLen = sizeof(deriveData);
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_VALUE_LEN, &valueLen,    sizeof(valueLen)    },
        { CKA_TOKEN,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_LABEL,     NULL,         0                   },
    };

    XMEMSET(&params, 0, sizeof(params));
    params.pData = deriveData;
    params.length = sizeof(deriveData);
    mech.mechanism = CKM_AES_CBC_ENCRYPT_DATA;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);
    tmpl[5].pValue = (CK_VOID_PTR)label;
    tmpl[5].ulValueLen = (CK_ULONG)XSTRLEN(label);
    return funcList->C_DeriveKey(session, &mech, base, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), obj);
}

/* A derived token key whose record cannot be committed is not reported
 * created, and deriving works again once it can be. */
static void test_derive_reports_commit_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    char path[512];
    int blocked = 0;
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS,    &secretClass,  sizeof(secretClass)   },
        { CKA_KEY_TYPE, &aesType,      sizeof(aesType)       },
        { CKA_VALUE,    deriveBaseKey, sizeof(deriveBaseKey) },
        { CKA_TOKEN,    &ckTrue,       sizeof(ckTrue)        },
        { CKA_DERIVE,   &ckTrue,       sizeof(ckTrue)        },
        { CKA_LABEL,    (CK_VOID_PTR)"derive-base", 11       },
    };

    printf("\n--- derived token key reports a commit failure ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, baseTmpl,
                                      sizeof(baseTmpl) / sizeof(*baseTmpl),
                                      &base);
        CHECK_RV(rv, "create base token key", CKR_OK);
    }
    if (rv == CKR_OK) {
        object_record_path(slot, 1, path, sizeof(path));
        blocked = (mkdir(path, 0700) == 0);
        CHECK_TRUE(blocked, "occupy the next object record path");
    }
    if (blocked) {
        rv = derive_token_secret(session, base, "derive-token", &derived);
        CHECK_TRUE(rv != CKR_OK,
                   "derive fails when the key cannot be committed");
        CHECK_TRUE(count_label(session, "derive-token") == 0,
                   "uncommitted derived key is not in the token");
        CHECK_TRUE(count_label(session, "derive-base") == 1,
                   "base key is still in the token");
        (void)rmdir(path);
        rv = derive_token_secret(session, base, "derive-token", &derived);
        CHECK_RV(rv, "derive succeeds once the key can be committed", CKR_OK);
        CHECK_TRUE(count_label(session, "derive-token") == 1,
                   "committed derived key is in the token");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

#ifdef DEBUG_WOLFPKCS11
/* Debug-only hook exported by libwolfpkcs11. */
#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Test_StoreCloseFailAfter(int closes);
#ifdef __cplusplus
}
#endif

/* A token object whose record cannot be closed is not reported created. */
static void test_create_reports_close_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;

    printf("\n--- token object creation reports a close failure ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "close-first", &obj);
        CHECK_RV(rv, "create first token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(0);
        rv = create_token_secret(session, "close-second", &obj);
        WP11_Test_StoreCloseFailAfter(-1);
        CHECK_TRUE(rv != CKR_OK,
                   "create fails when the record cannot be closed");
        CHECK_TRUE(count_label(session, "close-second") == 0,
                   "unclosed object is not in the token");
        close_session(session);
        session = CK_INVALID_HANDLE;
        rv = reload(slot, &session);
        CHECK_RV(rv, "reload token", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "close-first") == 1,
                   "stored object is reloaded");
        CHECK_TRUE(count_label(session, "close-second") == 0,
                   "unclosed object was not stored");
        rv = create_token_secret(session, "close-third", &obj);
        CHECK_RV(rv, "create succeeds once records close", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

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

/* Some platforms, such as MSYS2, ignore a read-only mode on a directory. */
static int block_store_dir(void)
{
    FILE* probe;
    char path[256];

    if (chmod(TEST_DIR, 0500) != 0)
        return 0;
    (void)snprintf(path, sizeof(path), "%s/wp11_probe", TEST_DIR);
    probe = fopen(path, "wb");
    if (probe != NULL) {
        fclose(probe);
        (void)remove(path);
        (void)chmod(TEST_DIR, 0700);
        printf("Skipping: store directory cannot be made read-only\n");
        return 0;
    }
    return 1;
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
    if (rv == CKR_OK && block_store_dir()) {
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
    if (rv == CKR_OK && block_store_dir()) {
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
    if (rv == CKR_OK && block_store_dir()) {
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
    if (rv == CKR_OK && block_store_dir()) {
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
/* A library initialization that fails part way is undone and retried. */
static void test_init_out_of_memory(void)
{
#ifdef HAVE_FIPS
    /* The failed initialization runs the FIPS self-tests without memory. A
     * failed self-test disables its algorithm until the process exits, so the
     * retry cannot succeed in a FIPS build. */
    printf("\nSkipping initialization out of memory test in a FIPS build\n");
#else
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;

    printf("\n--- library initializes after running out of memory ---\n");
    clear_store_dir();
    failAllocs = 1;
    rv = lib_init();
    failAllocs = 0;
    CHECK_TRUE(rv != CKR_OK, "initialize fails when allocation fails");
    if (rv == CKR_OK)
        funcList->C_Finalize(NULL);
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup once memory is available", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "init-retry", &obj);
        CHECK_RV(rv, "create token object after the retry", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
#endif
}

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
            rv = create_token_secret_ex(session, "legacy-keep", CK_TRUE, &obj);
            CHECK_RV(rv, "create token object", CKR_OK);
        }
        close_session(session);
        session = CK_INVALID_HANDLE;
        funcList->C_Finalize(NULL);
        if (rv == CKR_OK) {
            snprintf(tokenPath, sizeof(tokenPath), "%s/wp11_token_%016lx",
                     TEST_DIR, (unsigned long)slot);
            recordLen = read_store_file(tokenPath, record, sizeof(record));
            CHECK_TRUE(recordLen > dropLen + PUB_EXT_LEN &&
                       recordLen < (long)sizeof(record),
                       "token record is stored");
        }
        if (rv == CKR_OK && recordLen > dropLen + PUB_EXT_LEN) {
            CHECK_TRUE(write_store_file(tokenPath, record,
                (size_t)(recordLen - PUB_EXT_LEN - dropLen)) == 0,
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

/* An object record cut inside its issuer fails to load. */
static void test_record_cut_in_issuer(void)
{
    static const char label[] = "cut-issuer";
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    char path[512];
    byte record[2048];
    long recordLen = 0;
    long pos = -1;
    long i;
    int objId;

    printf("\n--- object record cut inside the issuer ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, label, &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);

    /* The issuer length follows the label in the object record. */
    for (objId = 0; rv == CKR_OK && pos < 0 && objId < 4; objId++) {
        object_record_path(slot, objId, path, sizeof(path));
        recordLen = read_store_file(path, record, sizeof(record));
        for (i = 0; i + (long)sizeof(label) + 13 <= recordLen; i++) {
            if (XMEMCMP(record + i, label, sizeof(label) - 1) == 0) {
                pos = i + (long)sizeof(label) - 1;
                break;
            }
        }
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(pos > 0, "label found in the object record");
        if (pos < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK) {
        record[pos] = 0;
        record[pos + 1] = 0;
        record[pos + 2] = 0;
        record[pos + 3] = 100;
        CHECK_TRUE(write_store_file(path, record, (size_t)pos + 4 + 10) == 0,
                   "cut the record inside a 100 byte issuer");
        rv = lib_init();
        CHECK_TRUE(rv != CKR_OK, "initialize fails on the cut record");
        if (rv == CKR_OK)
            funcList->C_Finalize(NULL);
        record[pos + 3] = 0;
        rv = write_store_file(path, record, (size_t)recordLen) == 0 ?
             CKR_OK : CKR_GENERAL_ERROR;
        if (rv == CKR_OK)
            rv = reload(slot, &session);
        CHECK_RV(rv, "initialize once the record is whole", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, label) == 1,
                   "stored object is loaded");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif /* TOKEN_STORE_FILE_TEST */

#ifdef TOKEN_STORE_TPM_TEST
#include <time.h>
#include <wolftpm/tpm2.h>

/* Debug-only hooks exported by libwolfpkcs11. */
#ifdef __cplusplus
extern "C" {
#endif
extern int WP11_Test_StoreWriteFailAfter(int writes);
extern int WP11_Test_StoreWriteFailOnce(int writes);
extern void WP11_Test_TpmStoreShortBy(int bytes);
extern void WP11_Test_TpmStoreOpenRc(int rc);
#ifdef __cplusplus
}
#endif

#define MAX_STORE_WRITES 500

static byte privateValue[16] = {
    0x5a, 0x0c, 0xe7, 0x31, 0x9b, 0x46, 0xd8, 0x2f,
    0x74, 0xa1, 0x1e, 0xc3, 0x68, 0xf5, 0x0d, 0xb2
};

/* Create a private, readable token secret encrypted under the token key. */
static CK_RV create_private_token_secret(CK_SESSION_HANDLE session,
                                         const char* label,
                                         CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass)  },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType)  },
        { CKA_VALUE,       privateValue, sizeof(privateValue) },
        { CKA_TOKEN,       &ckTrue,      sizeof(ckTrue)       },
        { CKA_PRIVATE,     &ckTrue,      sizeof(ckTrue)       },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)      },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)       },
        { CKA_LABEL,       NULL,         0                    },
    };

    tmpl[7].pValue = (CK_VOID_PTR)label;
    tmpl[7].ulValueLen = (CK_ULONG)XSTRLEN(label);
    return funcList->C_CreateObject(session, tmpl,
                                    sizeof(tmpl) / sizeof(*tmpl), obj);
}

/* The private secret with the label is found and its value decrypts. */
static int private_secret_usable(CK_SESSION_HANDLE session, const char* label)
{
    CK_RV rv;
    CK_OBJECT_HANDLE found[8];
    CK_ULONG foundCnt = 0;
    byte value[sizeof(privateValue)];
    CK_ATTRIBUTE valueAttr = { CKA_VALUE, value, sizeof(value) };
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
    if (rv == CKR_OK && foundCnt != 1)
        rv = CKR_OBJECT_HANDLE_INVALID;
    if (rv == CKR_OK)
        rv = funcList->C_GetAttributeValue(session, found[0], &valueAttr, 1);
    return rv == CKR_OK && valueAttr.ulValueLen == sizeof(privateValue) &&
           XMEMCMP(value, privateValue, sizeof(privateValue)) == 0;
}

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

/* A PIN change that fails at any one storage write keeps the stored PIN.
 * TPM records commit one at a time, so the old records are written back. */
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
    if (rv == CKR_OK) {
        rv = create_private_token_secret(session, "tpm-pin-private", &obj);
        CHECK_RV(rv, "create stored private token object", CKR_OK);
    }
    for (writes = 0; intact && rv == CKR_OK && writes < MAX_STORE_WRITES;
         writes++) {
        (void)WP11_Test_StoreWriteFailOnce(writes);
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
        /* Records under the token key must still open with the stored PIN. */
        if (rv != CKR_OK || count_label(session, "tpm-pin-keep") != 1 ||
                !private_secret_usable(session, "tpm-pin-private")) {
            printf("Stored token changed by a store failing after %d "
                   "writes\n", writes);
            intact = 0;
        }
    }
    CHECK_TRUE(intact, "stored PIN and private key work after each failed "
               "PIN change");
    CHECK_TRUE(rv == CKR_OK && writes < MAX_STORE_WRITES,
               "PIN change succeeds once storing works");
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A record that outgrows its NV index is moved to a larger one with its
 * data and reloads from there. */
static void test_grown_record_reloads(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    char longLabel[200];
    CK_ATTRIBUTE labelAttr = { CKA_LABEL, longLabel, sizeof(longLabel) - 1 };

    printf("\n--- record that outgrows its NV index reloads ---\n");
    XMEMSET(longLabel, 'g', sizeof(longLabel) - 1);
    longLabel[sizeof(longLabel) - 1] = '\0';
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "tpm-grow", &obj);
        CHECK_RV(rv, "create stored token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, obj, &labelAttr, 1);
        CHECK_RV(rv, "grow the object record past its NV index", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (rv == CKR_OK) {
        rv = reload_stored(slot, &session);
        CHECK_RV(rv, "reload token", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, longLabel) == 1,
                   "grown record reloads with its new data");
        CHECK_TRUE(count_label(session, "tpm-grow") == 0,
                   "old record is gone");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A token record whose NV index cannot be read stops the load, while a
 * missing NV index reads as an uninitialized token. */
static void test_tpm_unreadable_token_record(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_TOKEN_INFO info;

    printf("\n--- an unreadable TPM token record stops the load ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        /* TPM_RC_FAILURE */
        WP11_Test_TpmStoreOpenRc(0x101);
        XMEMSET(&info, 0, sizeof(info));
        rv = lib_init();
        if (rv == CKR_OK)
            rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_TRUE(rv != CKR_OK || (info.flags & CKF_TOKEN_INITIALIZED) != 0,
                   "unreadable token record is not reported uninitialized");
        funcList->C_Finalize(NULL);

        /* TPM_RC_HANDLE for handle 1 */
        WP11_Test_TpmStoreOpenRc(0x18B);
        XMEMSET(&info, 0, sizeof(info));
        rv = lib_init();
        if (rv == CKR_OK)
            rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_RV(rv, "load without NV indices", CKR_OK);
        CHECK_TRUE((info.flags & CKF_TOKEN_INITIALIZED) == 0,
                   "missing token record reads as uninitialized");
        funcList->C_Finalize(NULL);
        WP11_Test_TpmStoreOpenRc(0);

        XMEMSET(&info, 0, sizeof(info));
        rv = lib_init();
        if (rv == CKR_OK)
            rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_RV(rv, "load once the record is readable", CKR_OK);
        CHECK_TRUE((info.flags & CKF_TOKEN_INITIALIZED) != 0,
                   "token initialized once readable");
        if (rv == CKR_OK) {
            CHECK_RV(user_session(slot, &session),
                     "login once the record is readable", CKR_OK);
            close_session(session);
        }
        funcList->C_Finalize(NULL);
    }
}

/* A record written past its staging buffer is reported, not committed. */
static void test_record_overflow_reports_failure(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;

    printf("\n--- record overflowing its staging buffer is reported ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "tpm-fit", &obj);
        CHECK_RV(rv, "create stored token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        WP11_Test_TpmStoreShortBy(1);
        rv = create_token_secret(session, "tpm-overflow", &obj);
        WP11_Test_TpmStoreShortBy(0);
        CHECK_TRUE(rv != CKR_OK, "create fails when a record overflows");
        close_session(session);
        session = CK_INVALID_HANDLE;
        rv = reload_stored(slot, &session);
        CHECK_RV(rv, "reload token", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "tpm-fit") == 1,
                   "stored object is still present");
        CHECK_TRUE(count_label(session, "tpm-overflow") == 0,
                   "overflowing object was not stored");
        rv = create_token_secret(session, "tpm-overflow", &obj);
        CHECK_RV(rv, "create succeeds once records fit", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#ifndef WOLFPKCS11_TPM_NV_BASE
    #if !defined(WOLFPKCS11_TPM_AUTH_TYPE) || WOLFPKCS11_TPM_AUTH_TYPE == 1
        #define WOLFPKCS11_TPM_NV_BASE TPM_20_OWNER_NV_SPACE
    #else
        #define WOLFPKCS11_TPM_NV_BASE TPM_20_PLATFORM_MFG_NV_SPACE
    #endif
#endif

/* Count the NV indices of the token's object and key records. */
static int count_token_nv(CK_SLOT_ID slot)
{
    GetCapability_In in;
    static GetCapability_Out out;
    TPM_HANDLE base = WOLFPKCS11_TPM_NV_BASE;
    TPM_HANDLE start = base;
    TPM_HANDLE last = base + (0x20 << 16) - 1;
    TPM_HANDLE h;
    word32 i;
    int cnt = 0;
    int more = 1;

    while (more) {
        XMEMSET(&in, 0, sizeof(in));
        in.capability = TPM_CAP_HANDLES;
        in.property = start;
        in.propertyCount = MAX_CAP_HANDLES;
        if (TPM2_GetCapability(&in, &out) != TPM_RC_SUCCESS)
            return -1;
        more = out.moreData && out.capabilityData.data.handles.count > 0;
        for (i = 0; i < out.capabilityData.data.handles.count; i++) {
            h = out.capabilityData.data.handles.handle[i];
            if (h > last) {
                more = 0;
                break;
            }
            start = h + 1;
            if (((h >> 8) & 0xFF) == (slot & 0xFF) && h - base >= 0x10000)
                cnt++;
        }
    }
    return cnt;
}

/* C_InitToken removes the NV indices of the records it discards. */
static void test_tpm_init_token_removes_records(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    unsigned char label[32];
    struct timespec t0, t1;

    printf("\n--- C_InitToken removes the NV records it discards ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_private_token_secret(session, "nv-first", &obj);
    if (rv == CKR_OK)
        rv = create_private_token_secret(session, "nv-second", &obj);
    CHECK_RV(rv, "create token objects", CKR_OK);
    close_session(session);
    if (rv == CKR_OK)
        CHECK_TRUE(count_token_nv(slot) > 0, "objects have NV records");
    if (rv == CKR_OK) {
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        clock_gettime(CLOCK_MONOTONIC, &t0);
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        CHECK_RV(rv, "C_InitToken", CKR_OK);
        printf("C_InitToken took %.1f ms\n",
               (t1.tv_sec - t0.tv_sec) * 1000.0 +
               (t1.tv_nsec - t0.tv_nsec) / 1e6);
    }
    if (rv == CKR_OK)
        CHECK_TRUE(count_token_nv(slot) == 0, "no object NV records are left");
    funcList->C_Finalize(NULL);
}

#endif /* TOKEN_STORE_TPM_TEST */

#ifdef DEBUG_WOLFPKCS11
/* Debug-only hook exported by libwolfpkcs11. */
#ifdef __cplusplus
extern "C" {
#endif
extern int WP11_Test_StoreReadFailAfter(int reads);
#ifdef __cplusplus
}
#endif

/* A store read error fails the load instead of reading as an older format. */
static void test_load_fails_on_read_error(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    int reads;
    int failed = 1;
    int ignored = 0;

    printf("\n--- a store read error fails the token load ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "read-error", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);

    for (reads = 0; rv == CKR_OK && failed; reads++) {
        (void)WP11_Test_StoreReadFailAfter(reads);
        rv = lib_init();
        failed = WP11_Test_StoreReadFailAfter(-1) == -1;
        if (rv == CKR_OK) {
            funcList->C_Finalize(NULL);
            if (failed) {
                printf("read error after %d reads ignored\n", reads);
                ignored++;
            }
        }
        else if (failed) {
            rv = CKR_OK;
        }
    }
    CHECK_RV(rv, "initialize fails only on the read error", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(reads > 1, "loading the token reads the store");
        CHECK_TRUE(ignored == 0, "every read error fails initialization");
        rv = lib_init();
        if (rv == CKR_OK)
            rv = user_session(slot, &session);
        CHECK_RV(rv, "initialize without a read error", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "read-error") == 1,
                   "stored object is loaded");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

#ifdef TOKEN_STORE_FILE_TEST
/* Count the object and key records left in the store directory. */
static int count_object_records(void)
{
    DIR* dir;
    struct dirent* ent;
    int cnt = 0;

    dir = opendir(TEST_DIR);
    if (dir == NULL)
        return -1;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "wp11_", 5) == 0 &&
                strncmp(ent->d_name, "wp11_token_", 11) != 0 &&
                strncmp(ent->d_name, "wp11_txn_", 9) != 0) {
            cnt++;
        }
    }
    closedir(dir);
    return cnt;
}

/* C_InitToken also removes the records of objects another process stored
 * after this one loaded the token. */
static void test_init_token_removes_newer_records(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    unsigned char label[32];
    pid_t pid;
    int status = 0;

    printf("\n--- C_InitToken removes records another process stored ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "init-first", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        pid = fork();
        if (pid == 0) {
            funcList->C_Finalize(NULL);
            if (lib_init() != CKR_OK ||
                    user_session(slot, &session) != CKR_OK ||
                    create_token_secret(session, "init-second", &obj) !=
                        CKR_OK ||
                    create_token_secret(session, "init-third", &obj) !=
                        CKR_OK) {
                _exit(1);
            }
            close_session(session);
            funcList->C_Finalize(NULL);
            _exit(0);
        }
        if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0) {
            rv = CKR_GENERAL_ERROR;
        }
        CHECK_RV(rv, "other process stores two objects", CKR_OK);
    }
    if (rv == CKR_OK) {
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        CHECK_RV(rv, "C_InitToken", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_object_records() == 0,
                   "no object records are left");
    }
    funcList->C_Finalize(NULL);
}
#endif

#ifdef TOKEN_STORE_FILE_TEST
/* C_InitToken removes a record whose type another process changed at an id
 * this process knows. */
static void test_init_token_removes_changed_type(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    static byte dataValue[4] = { 1, 2, 3, 4 };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
        { CKA_VALUE,   dataValue,  sizeof(dataValue) },
    };
    unsigned char label[32];
    pid_t pid;
    int status = 0;

    printf("\n--- C_InitToken removes a record of a changed type ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "changed-secret", &secret);
        CHECK_RV(rv, "create secret key", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &data);
        CHECK_RV(rv, "create data object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK)
        rv = lib_init();
    /* The other process destroys the secret, so the data object moves into
     * its id. */
    if (rv == CKR_OK) {
        pid = fork();
        if (pid == 0) {
            CK_OBJECT_HANDLE found[2];
            CK_ULONG cnt = 0;
            CK_ATTRIBUTE byClass = { CKA_CLASS, &secretClass,
                sizeof(secretClass) };

            funcList->C_Finalize(NULL);
            if (lib_init() != CKR_OK ||
                    user_session(slot, &session) != CKR_OK ||
                    funcList->C_FindObjectsInit(session, &byClass, 1) !=
                        CKR_OK ||
                    funcList->C_FindObjects(session, found, 2, &cnt) !=
                        CKR_OK || cnt != 1 ||
                    funcList->C_FindObjectsFinal(session) != CKR_OK ||
                    funcList->C_DestroyObject(session, found[0]) != CKR_OK) {
                _exit(1);
            }
            close_session(session);
            funcList->C_Finalize(NULL);
            _exit(0);
        }
        if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0) {
            rv = CKR_GENERAL_ERROR;
        }
        CHECK_RV(rv, "other process destroys the secret", CKR_OK);
    }
    if (rv == CKR_OK) {
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        CHECK_RV(rv, "C_InitToken", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_object_records() == 0,
                   "no object records are left");
    }
    funcList->C_Finalize(NULL);
}
#endif

#ifdef TOKEN_STORE_FILE_TEST
/* Close a pipe end once and mark it closed. */
static void close_fd(int* fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

/* A process that loaded the token before another one changed it loads the
 * token again before changing it, so it does not write its older token back
 * and its own changes are kept. */
static void test_stale_process_reloads(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE first = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    int toChild[2] = { -1, -1 };
    int fromChild[2] = { -1, -1 };
    pid_t pid = -1;
    int status = 0;
    char c = 0;

    printf("\n--- a stale process loads the token again ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "stale-first", &first);
        CHECK_RV(rv, "create first token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "stale-second", &obj);
        CHECK_RV(rv, "create second token object", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "stale-third", &obj);
        CHECK_RV(rv, "create third token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK && (pipe(toChild) != 0 || pipe(fromChild) != 0))
        rv = CKR_GENERAL_ERROR;

    /* The child finds its objects, waits for the parent's destroy, then
     * renames, destroys and creates through the handles it already has. */
    if (rv == CKR_OK)
        pid = fork();
    if (pid == 0) {
        CK_OBJECT_HANDLE second = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE third = CK_INVALID_HANDLE;
        CK_ULONG n = 0;
        CK_ATTRIBUTE find2 = { CKA_LABEL, (CK_VOID_PTR)"stale-second", 12 };
        CK_ATTRIBUTE find3 = { CKA_LABEL, (CK_VOID_PTR)"stale-third", 11 };
        CK_ATTRIBUTE rename = { CKA_LABEL, (CK_VOID_PTR)"stale-renamed", 13 };
        int code = 0;

        close_fd(&toChild[1]);
        close_fd(&fromChild[0]);
        if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK)
            _exit(10);
        if (funcList->C_FindObjectsInit(session, &find2, 1) != CKR_OK ||
                funcList->C_FindObjects(session, &second, 1, &n) != CKR_OK ||
                funcList->C_FindObjectsFinal(session) != CKR_OK || n != 1 ||
                funcList->C_FindObjectsInit(session, &find3, 1) != CKR_OK ||
                funcList->C_FindObjects(session, &third, 1, &n) != CKR_OK ||
                funcList->C_FindObjectsFinal(session) != CKR_OK || n != 1) {
            _exit(11);
        }
        if (write(fromChild[1], &c, 1) != 1 || read(toChild[0], &c, 1) != 1)
            _exit(12);
        if (funcList->C_SetAttributeValue(session, second, &rename, 1) !=
                CKR_OK) {
            code |= 1;
        }
        if (funcList->C_DestroyObject(session, third) != CKR_OK)
            code |= 2;
        if (create_token_secret(session, "stale-child", &obj) != CKR_OK)
            code |= 4;
        if (count_label(session, "stale-first") != 0)
            code |= 8;
        close_session(session);
        if (funcList->C_Finalize(NULL) != CKR_OK)
            code |= 16;
        _exit(code);
    }
    close_fd(&toChild[0]);
    close_fd(&fromChild[1]);
    if (rv == CKR_OK && (pid < 0 || read(fromChild[0], &c, 1) != 1))
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        rv = reload(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_DestroyObject(session, first);
        CHECK_RV(rv, "destroy in the other process", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (pid > 0) {
        if (rv == CKR_OK && write(toChild[1], &c, 1) != 1)
            rv = CKR_GENERAL_ERROR;
        close_fd(&toChild[1]);
        if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
            status = -1;
        CHECK_TRUE(status == 0, "stale process changed the current token");
    }
    if (rv == CKR_OK)
        rv = reload(slot, &session);
    CHECK_RV(rv, "reload", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "stale-first") == 0,
                   "destroyed object stays destroyed");
        CHECK_TRUE(count_label(session, "stale-renamed") == 1,
                   "stale process's rename is stored");
        CHECK_TRUE(count_label(session, "stale-third") == 0,
                   "stale process's destroy is stored");
        CHECK_TRUE(count_label(session, "stale-child") == 1,
                   "stale process's object is stored");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
    close_fd(&toChild[0]);
    close_fd(&toChild[1]);
    close_fd(&fromChild[0]);
    close_fd(&fromChild[1]);
}

static const char reloadPin[] = "reload-new-pin";
static byte reloadKey[16] = {
    0x52, 0x45, 0x4c, 0x4f, 0x41, 0x44, 0x2d, 0x4b,
    0x45, 0x59, 0x2d, 0x56, 0x41, 0x4c, 0x55, 0x45
};

/* Fork a child that waits for a byte on *go, then makes its change with its
 * own library instance and exits with the change's result. */
static pid_t fork_changer(int (*change)(CK_SLOT_ID slot), CK_SLOT_ID slot,
                          int* go)
{
    int fds[2];
    pid_t pid;
    char c;

    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid == 0) {
        close(fds[1]);
        if (read(fds[0], &c, 1) != 1)
            _exit(10);
        _exit(change(slot));
    }
    close(fds[0]);
    if (pid < 0) {
        close(fds[1]);
        return -1;
    }
    *go = fds[1];
    return pid;
}

/* Let the child of fork_changer make its change and wait for it.
 * Returns its exit code, or -1 when it did not exit normally. */
static int run_changer(pid_t pid, int go)
{
    char c = 0;
    int status = 0;

    if (write(go, &c, 1) != 1)
        status = -1;
    close(go);
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int change_pin(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int code = 0;

    if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK)
        return 20;
    if (funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)userPin,
            (CK_ULONG)XSTRLEN(userPin), (CK_UTF8CHAR_PTR)reloadPin,
            (CK_ULONG)XSTRLEN(reloadPin)) != CKR_OK) {
        code |= 1;
    }
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* Store a public object without logging in, so the failed logins stay. */
static int change_add_public(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    int code = 0;

    if (lib_init() != CKR_OK)
        return 20;
    if (funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &session) != CKR_OK ||
            funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj) != CKR_OK) {
        code |= 1;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* A PIN change that cannot be stored leaves no change to store, so the
 * token loads again after another process stores. */
static void test_failed_pin_change_reloads(int so)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    const char* pin = so ? soPin : userPin;
    static const char newPin[] = "unstored-new-pin";
    pid_t pid = -1;
    int go = -1;

    if (geteuid() == 0) {
        printf("\nSkipping failed PIN change reload test when run as root\n");
        return;
    }
    printf("\n--- %s PIN change that cannot be stored keeps reloading ---\n",
           so ? "SO" : "user");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add_public, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, so ? CKU_SO : CKU_USER,
                               (CK_UTF8CHAR_PTR)pin, (CK_ULONG)XSTRLEN(pin));
        CHECK_RV(rv, "login", CKR_OK);
    }
    if (rv == CKR_OK && block_store_dir()) {
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)pin,
                                (CK_ULONG)XSTRLEN(pin),
                                (CK_UTF8CHAR_PTR)newPin,
                                (CK_ULONG)XSTRLEN(newPin));
        (void)chmod(TEST_DIR, 0700);
        CHECK_TRUE(rv != CKR_OK, "PIN change reports the store failure");
        if (pid > 0) {
            CHECK_TRUE(run_changer(pid, go) == 0, "other process stores");
            pid = -1;
        }
        rv = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj);
        CHECK_RV(rv, "token loads again and stores", CKR_OK);
    }
    if (pid > 0)
        (void)run_changer(pid, go);
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* Log in as the user in a new session and close it. */
static CK_RV login_user(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = user_session(slot, &session);
    close_session(session);
    return rv;
}

#define GEN_FILE_SZ 9

static int read_gen_file(const char* path, byte* gen)
{
    FILE* f;
    size_t got = 0;

    f = fopen(path, "rb");
    if (f != NULL) {
        got = fread(gen, 1, GEN_FILE_SZ, f);
        fclose(f);
    }
    return (got == GEN_FILE_SZ) ? 0 : -1;
}

static int write_gen_file(const char* path, const byte* gen, size_t len)
{
    FILE* f;
    size_t put = 0;

    f = fopen(path, "wb");
    if (f != NULL) {
        put = fwrite(gen, 1, len, f);
        fclose(f);
    }
    return (put == len) ? 0 : -1;
}

/* A store whose freshness cannot be checked refuses a login. */
static void test_unchecked_store_refuses_login(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    char path[256];
    byte gen[GEN_FILE_SZ + 1] = { 0 };
    FILE* f;
    int fd;

    printf("\n--- a store that cannot be checked refuses a login ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK) {
        /* A commit marker naming a cut-short line cannot be finished. */
        (void)snprintf(path, sizeof(path), "%s/wp11_txn_%016lx_commit",
                       TEST_DIR, (unsigned long)slot);
        f = fopen(path, "wb");
        if (f != NULL) {
            (void)fputs("wp11_cut", f);
            fclose(f);
        }
        CHECK_TRUE(login_user(slot) != CKR_OK,
                   "unfinished pass refuses login");
        if (chmod(path, 0) == 0) {
            fd = open(path, O_RDONLY);
            if (fd >= 0) {
                close(fd);
                printf("Skipping: commit marker cannot be made unreadable\n");
            }
            else {
                CHECK_TRUE(login_user(slot) != CKR_OK,
                           "unreadable commit marker refuses login");
            }
        }
        (void)remove(path);
        CHECK_RV(login_user(slot), "login once the pass is gone", CKR_OK);
    }
    (void)snprintf(path, sizeof(path), "%s/wp11_txn_%016lx_lock", TEST_DIR,
                   (unsigned long)slot);
    if (rv == CKR_OK && geteuid() != 0 && chmod(path, 0) == 0) {
        fd = open(path, O_RDWR);
        if (fd >= 0) {
            close(fd);
            printf("Skipping: lock file cannot be made unreadable\n");
        }
        else {
            CHECK_TRUE(login_user(slot) != CKR_OK,
                       "unreadable lock file refuses login");
        }
        (void)chmod(path, 0600);
        CHECK_RV(login_user(slot), "login once the lock is readable", CKR_OK);
    }
    (void)snprintf(path, sizeof(path), "%s/wp11_txn_%016lx_gen", TEST_DIR,
                   (unsigned long)slot);
    if (rv == CKR_OK) {
        CHECK_TRUE(read_gen_file(path, gen) == 0, "pass count read");
        CHECK_TRUE(write_gen_file(path, gen, 4) == 0, "pass count cut");
        CHECK_TRUE(login_user(slot) != CKR_OK, "cut pass count refuses login");
        CHECK_TRUE(write_gen_file(path, gen, sizeof(gen)) == 0,
                   "pass count lengthened");
        CHECK_TRUE(login_user(slot) != CKR_OK,
                   "long pass count refuses login");
        CHECK_TRUE(write_gen_file(path, gen, GEN_FILE_SZ) == 0,
                   "pass count restored");
        CHECK_RV(login_user(slot), "login once the count is whole", CKR_OK);
    }
    if (rv == CKR_OK && geteuid() != 0 && chmod(path, 0) == 0) {
        f = fopen(path, "rb");
        if (f != NULL) {
            fclose(f);
            printf("Skipping: pass count cannot be made unreadable\n");
        }
        else {
            CHECK_TRUE(login_user(slot) != CKR_OK,
                       "unreadable pass count refuses login");
        }
        (void)chmod(path, 0600);
        CHECK_RV(login_user(slot), "login once the count is readable",
                 CKR_OK);
    }
    funcList->C_Finalize(NULL);
}

/* A token record that exists but cannot be read stops the load instead of
 * reporting an uninitialized token that could be initialized over it. */
static void test_unreadable_token_record(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_TOKEN_INFO info;
    char path[256];
    FILE* f;

    printf("\n--- an unreadable token record stops the load ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    snprintf(path, sizeof(path), "%s/wp11_token_%016lx", TEST_DIR,
             (unsigned long)slot);
    if (rv == CKR_OK && geteuid() != 0 && chmod(path, 0) == 0) {
        f = fopen(path, "rb");
        if (f != NULL) {
            fclose(f);
            printf("Skipping: token record cannot be made unreadable\n");
        }
        else {
            XMEMSET(&info, 0, sizeof(info));
            rv = lib_init();
            if (rv == CKR_OK)
                rv = funcList->C_GetTokenInfo(slot, &info);
            CHECK_TRUE(rv != CKR_OK ||
                       (info.flags & CKF_TOKEN_INITIALIZED) != 0,
                       "unreadable token record is not reported uninitialized");
            funcList->C_Finalize(NULL);
        }
        (void)chmod(path, 0600);
        XMEMSET(&info, 0, sizeof(info));
        rv = lib_init();
        if (rv == CKR_OK)
            rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_RV(rv, "load once the record is readable", CKR_OK);
        CHECK_TRUE((info.flags & CKF_TOKEN_INITIALIZED) != 0,
                   "token initialized once readable");
        CHECK_RV(login_user(slot), "login once the record is readable",
                 CKR_OK);
        funcList->C_Finalize(NULL);
    }
}

static int change_user_pin_empty(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int code = 0;

    if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK)
        return 20;
    rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)userPin,
                            (CK_ULONG)XSTRLEN(userPin), (CK_UTF8CHAR_PTR)"", 0);
    if (EMPTY_PIN_REFUSED(rv))
        code = 30;
    else if (rv != CKR_OK)
        code |= 1;
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* A user PIN emptied by another process leaves the token key usable. */
static void test_reload_to_empty_pin_keeps_key(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG cnt = 0;
    byte value[sizeof(keyData)];
    CK_ATTRIBUTE label = { CKA_LABEL, (CK_VOID_PTR)"emptied-pin-key", 15 };
    CK_ATTRIBUTE get = { CKA_VALUE, value, sizeof(value) };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_VALUE,     keyData,      sizeof(keyData)     },
        { CKA_TOKEN,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_SENSITIVE,   &ckFalse,   sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,    sizeof(ckTrue)      },
        { CKA_LABEL,     (CK_VOID_PTR)"emptied-pin-key", 15 },
    };
    pid_t pid = -1;
    int go = -1;
    int code = -1;

    printf("\n--- a user PIN emptied by another process ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_user_pin_empty, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (pid > 0)
        code = run_changer(pid, go);
    if (code == 30) {
        printf("Skipping: empty PINs are not allowed\n");
        rv = CKR_GENERAL_ERROR;
    }
    else {
        CHECK_TRUE(code == 0, "other process empties the PIN");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj);
        CHECK_RV(rv, "login ended by the PIN change", CKR_USER_NOT_LOGGED_IN);
        rv = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj);
        CHECK_RV(rv, "key created after the reload", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
                                     &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)"", 0);
        CHECK_RV(rv, "login with the empty PIN", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjectsInit(session, &label, 1);
        if (rv == CKR_OK) {
            rv = funcList->C_FindObjects(session, &found, 1, &cnt);
            funcList->C_FindObjectsFinal(session);
        }
        CHECK_TRUE(rv == CKR_OK && cnt == 1, "key found after reloading");
        if (cnt == 1) {
            XMEMSET(value, 0xff, sizeof(value));
            rv = funcList->C_GetAttributeValue(session, found, &get, 1);
            CHECK_TRUE(rv == CKR_OK &&
                       XMEMCMP(value, keyData, sizeof(value)) == 0,
                       "key value readable after reloading");
        }
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifdef WOLFPKCS11_NSS
/* NSS sets the first user PIN in a SO session with an empty PIN. */
static void test_nss_init_pin_without_store_dir(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    printf("\n--- NSS sets the first PIN before the store exists ---\n");
    clear_store_dir();
    (void)rmdir(TEST_DIR);
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)"", 0);
        CHECK_RV(rv, "empty SO PIN login", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
        CHECK_RV(rv, "first user PIN set", CKR_OK);
        funcList->C_Logout(session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
        CHECK_RV(rv, "login with the first user PIN", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
    (void)mkdir(TEST_DIR, 0700);
}
#endif

static int change_add(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretClass,   sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType,   sizeof(genericType) },
        { CKA_VALUE,       reloadKey,      sizeof(reloadKey)   },
        { CKA_TOKEN,       &ckTrue,        sizeof(ckTrue)      },
        { CKA_SENSITIVE,   &ckFalse,       sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,        sizeof(ckTrue)      },
        { CKA_LABEL,       (CK_VOID_PTR)"reload-child", 12     },
    };
    int code = 0;

    if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK)
        return 20;
    if (funcList->C_CreateObject(session, tmpl, sizeof(tmpl) / sizeof(*tmpl),
            &obj) != CKR_OK) {
        code |= 1;
    }
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* C_Login checks the PIN another process stored after this one loaded the
 * token. */
static void test_stale_login_sees_new_pin(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    pid_t pid = -1;
    int go = -1;

    printf("\n--- login checks a PIN another process changed ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process changes the PIN");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
        CHECK_RV(rv, "old PIN is refused", CKR_PIN_INCORRECT);
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)reloadPin,
                               (CK_ULONG)XSTRLEN(reloadPin));
        CHECK_RV(rv, "new PIN logs in", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* Loading the token again keeps the login when the PIN is unchanged, and the
 * objects it loads are usable. */
static void test_reload_keeps_login(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_SESSION_INFO info;
    pid_t pid = -1;
    int go = -1;

    printf("\n--- loading the token again keeps the login ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process stores an object");
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "reload-parent", &obj);
        CHECK_RV(rv, "create after the other process stored", CKR_OK);
    }
    if (rv == CKR_OK) {
        CK_ULONG n = 0;
        CK_ATTRIBUTE find = { CKA_LABEL, (CK_VOID_PTR)"reload-child", 12 };
        byte value[sizeof(reloadKey)];
        CK_ATTRIBUTE get = { CKA_VALUE, value, sizeof(value) };

        XMEMSET(value, 0xff, sizeof(value));
        rv = funcList->C_FindObjectsInit(session, &find, 1);
        if (rv == CKR_OK)
            rv = funcList->C_FindObjects(session, &obj, 1, &n);
        (void)funcList->C_FindObjectsFinal(session);
        if (rv == CKR_OK && n != 1)
            rv = CKR_GENERAL_ERROR;
        if (rv == CKR_OK)
            rv = funcList->C_GetAttributeValue(session, obj, &get, 1);
        CHECK_TRUE(rv == CKR_OK && get.ulValueLen == sizeof(reloadKey) &&
                   XMEMCMP(value, reloadKey, sizeof(reloadKey)) == 0,
                   "other process's key is usable");
        rv = funcList->C_GetSessionInfo(session, &info);
        CHECK_TRUE(rv == CKR_OK && info.state == CKS_RW_USER_FUNCTIONS,
                   "session is still logged in");
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK)
        rv = reload(slot, &session);
    CHECK_RV(rv, "reload", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "reload-child") == 1,
                   "other process's object is stored");
        CHECK_TRUE(count_label(session, "reload-parent") == 1,
                   "this process's object is stored");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* Loading the token again after another process changed the PIN ends the
 * login, and the private object being created is not added. */
static void test_reload_ends_login_on_pin_change(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_SESSION_INFO info;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    static byte dataValue[4] = { 1, 2, 3, 4 };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckTrue,    sizeof(ckTrue)    },
        { CKA_VALUE,   dataValue,  sizeof(dataValue) },
    };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- a PIN changed by another process ends the login ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process changes the PIN");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "private object is not added", CKR_USER_NOT_LOGGED_IN);
        rv = (rv == CKR_USER_NOT_LOGGED_IN) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_GetSessionInfo(session, &info);
        CHECK_TRUE(rv == CKR_OK && info.state == CKS_RW_PUBLIC_SESSION,
                   "session is logged out");
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)reloadPin,
                               (CK_ULONG)XSTRLEN(reloadPin));
        CHECK_RV(rv, "login with the new PIN", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

static const char reloadSoPin[] = "reload-new-so-pin";

static int change_so_pin(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int code = 0;

    if (lib_init() != CKR_OK)
        return 20;
    if (funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &session) != CKR_OK ||
            funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
            (CK_ULONG)XSTRLEN(soPin)) != CKR_OK) {
        code |= 1;
    }
    else if (funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)soPin,
            (CK_ULONG)XSTRLEN(soPin), (CK_UTF8CHAR_PTR)reloadSoPin,
            (CK_ULONG)XSTRLEN(reloadSoPin)) != CKR_OK) {
        code |= 2;
    }
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 4;
    return code;
}

/* C_InitPIN does not set the user PIN once loading the token again ended the
 * SO login. */
static void test_init_pin_after_so_pin_change(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    static const char newPin[] = "init-pin-stale";
    pid_t pid = -1;
    int go = -1;

    printf("\n--- C_InitPIN after another process changed the SO PIN ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_so_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
        CHECK_RV(rv, "SO login", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process changes the SO PIN");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)newPin,
                                 (CK_ULONG)XSTRLEN(newPin));
        CHECK_RV(rv, "user PIN is not set", CKR_USER_NOT_LOGGED_IN);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* C_SetPIN does not change the user PIN once loading the token again ended
 * the SO login. */
static void test_set_pin_after_so_pin_change(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    static const char newPin[] = "set-pin-stale";
    pid_t pid = -1;
    int go = -1;

    printf("\n--- C_SetPIN after another process changed the SO PIN ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_so_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
        CHECK_RV(rv, "SO login", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process changes the SO PIN");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)soPin,
                                (CK_ULONG)XSTRLEN(soPin),
                                (CK_UTF8CHAR_PTR)newPin,
                                (CK_ULONG)XSTRLEN(newPin));
        CHECK_RV(rv, "no PIN is changed", CKR_USER_NOT_LOGGED_IN);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifdef HAVE_ECC
static CK_OBJECT_HANDLE endKey = CK_INVALID_HANDLE;

/* Destroy the key whose operation this process runs. */
static int change_destroy_key(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int code = 0;

    if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK)
        return 20;
    if (funcList->C_DestroyObject(session, endKey) != CKR_OK)
        code |= 1;
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* Destroying a key ends an operation that runs on the copy a reload
 * replaced, whether this process or another one destroys it. */
static void test_op_ends_on_destroyed_key(int elsewhere)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_MECHANISM genMech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM mech = { CKM_ECDSA_SHA256, NULL, 0 };
    static CK_BYTE p256[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };
    static CK_BYTE msg[] = "message";
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, p256,    sizeof(p256)   },
        { CKA_TOKEN,     &ckTrue, sizeof(ckTrue) },
        { CKA_VERIFY,    &ckTrue, sizeof(ckTrue) },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,     &ckTrue, sizeof(ckTrue) },
        { CKA_SIGN,      &ckTrue, sizeof(ckTrue) },
    };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- destroying a key %s ends its operation ---\n",
           elsewhere ? "in another process" : "after a reload");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_GenerateKeyPair(session, &genMech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &endKey);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(elsewhere ? change_destroy_key : change_add, slot,
                           &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &other);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_SignInit(session, &mech, endKey);
        if (rv == CKR_OK)
            rv = funcList->C_SignUpdate(session, msg, sizeof(msg) - 1);
        CHECK_RV(rv, "sign started", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process stores");
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(other, "end-reload", &obj);
        CHECK_RV(rv, "token loaded again", CKR_OK);
    }
    if (rv == CKR_OK && !elsewhere) {
        rv = funcList->C_DestroyObject(other, endKey);
        CHECK_RV(rv, "key destroyed", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_SignUpdate(session, msg, sizeof(msg) - 1);
        CHECK_TRUE(rv != CKR_OK, "operation on the destroyed key ended");
    }
    close_session(other);
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
/* A derive from a token key another process stored after this one loaded
 * the token takes the key's handle as valid. */
static void test_derive_after_other_store(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS,    &secretClass,  sizeof(secretClass)   },
        { CKA_KEY_TYPE, &aesType,      sizeof(aesType)       },
        { CKA_VALUE,    deriveBaseKey, sizeof(deriveBaseKey) },
        { CKA_TOKEN,    &ckTrue,       sizeof(ckTrue)        },
        { CKA_DERIVE,   &ckTrue,       sizeof(ckTrue)        },
        { CKA_LABEL,    (CK_VOID_PTR)"stale-base", 10        },
    };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- derive after another process stored ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, baseTmpl,
                                      sizeof(baseTmpl) / sizeof(*baseTmpl),
                                      &base);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process stores");
    }
    if (rv == CKR_OK) {
        rv = derive_token_secret(session, base, "stale-derived", &derived);
        CHECK_RV(rv, "derive from the stored key", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

/* C_InitToken checks the SO PIN another process stored. */
static void test_init_token_sees_new_so_pin(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    unsigned char label[32];
    pid_t pid = -1;
    int go = -1;

    printf("\n--- C_InitToken checks an SO PIN another process changed ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_so_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process changes the SO PIN");
    }
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        CHECK_RV(rv, "old SO PIN is refused", CKR_PIN_INCORRECT);
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)reloadSoPin,
                                   (CK_ULONG)XSTRLEN(reloadSoPin), label);
        CHECK_RV(rv, "new SO PIN resets the token", CKR_OK);
    }
    funcList->C_Finalize(NULL);
}

#ifdef TEST_ALLOC_FAILURE
/* A template that fails after changing an attribute is undone. */
static void test_partial_set_attr_undone(void)
{
    CK_RV rv;
    CK_RV setRv = CKR_GENERAL_ERROR;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte newId[32] = { 2 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_LABEL, (CK_VOID_PTR)"undo-renamed", 12            },
        { CKA_ID,    newId,                       sizeof(newId) },
    };
    int at;
    int partial = 0;

    printf("\n--- a partly applied attribute change is undone ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "undo-first", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    /* Fail each allocation in turn until the template is set. */
    for (at = 0; rv == CKR_OK && setRv != CKR_OK && at < 32; at++) {
        allocCnt = 0;
        failOnceAt = at;
        setRv = funcList->C_SetAttributeValue(session, obj, tmpl,
            sizeof(tmpl) / sizeof(*tmpl));
        failOnceAt = -1;
        if (setRv != CKR_OK && count_label(session, "undo-renamed") != 0)
            partial = 1;
    }
    CHECK_TRUE(setRv == CKR_OK, "template is set once memory is available");
    CHECK_TRUE(!partial, "a failed template leaves the label unchanged");
    if (rv == CKR_OK) {
        CK_SESSION_INFO info;

        rv = funcList->C_GetSessionInfo(session, &info);
        CHECK_TRUE(rv == CKR_OK && info.state == CKS_RW_USER_FUNCTIONS,
                   "failed allocations leave the login");
    }
    close_session(session);
    rv = funcList->C_Finalize(NULL);
    CHECK_RV(rv, "finalize", CKR_OK);
}
#endif

static int change_empty_pin(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int code = 0;

    if (lib_init() != CKR_OK)
        return 20;
    if (funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &session) != CKR_OK ||
            funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)"", 0,
            (CK_UTF8CHAR_PTR)reloadPin, (CK_ULONG)XSTRLEN(reloadPin)) !=
            CKR_OK) {
        code |= 1;
    }
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* A token with an empty user PIN that another process gives a PIN does not
 * get keys encrypted under the empty PIN's key. */
static void test_reload_drops_empty_pin_key(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    unsigned char label[32];
    pid_t pid = -1;
    int go = -1;

    printf("\n--- an empty user PIN set by another process ---\n");
#ifdef TOKEN_STORE_FILE_TEST
    clear_store_dir();
#endif
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)"", 0);
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (EMPTY_PIN_REFUSED(rv)) {
        printf("Skipping: empty PINs are not allowed\n");
        return;
    }
    CHECK_RV(rv, "token with an empty user PIN", CKR_OK);
    if (rv == CKR_OK) {
        pid = fork_changer(change_empty_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process sets a PIN");
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "empty-pin-key", &obj);
        CHECK_RV(rv, "key needs a login", CKR_USER_NOT_LOGGED_IN);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifndef WOLFPKCS11_NO_TIME
/* Log in with a wrong PIN in a new session and close it. */
static CK_RV wrong_login(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER,
            (CK_UTF8CHAR_PTR)"wrong-user-pin-1234", 19);
        rv = (rv == CKR_PIN_INCORRECT) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    return rv;
}

/* Check whether the stored token reports failed user logins. */
static int stored_user_fails(CK_SLOT_ID slot)
{
    CK_TOKEN_INFO info;
    int fails = -1;

    if (lib_init() == CKR_OK &&
            funcList->C_GetTokenInfo(slot, &info) == CKR_OK) {
        fails = (info.flags & CKF_USER_PIN_COUNT_LOW) != 0;
    }
    funcList->C_Finalize(NULL);
    return fails;
}

/* A failed login stays stored when another process stores the token later. */
static void test_failed_login_survives_later_store(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    pid_t pid = -1;
    int go = -1;

    printf("\n--- a failed login survives a later store ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add_public, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = wrong_login(slot);
        CHECK_RV(rv, "login with a wrong PIN", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process stores an object");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Finalize(NULL);
        CHECK_RV(rv, "finalize", CKR_OK);
        CHECK_TRUE(stored_user_fails(slot) == 1, "failed login is stored");
    }
    else {
        funcList->C_Finalize(NULL);
    }
}

/* A successful login that reset the failed logins is not undone when the
 * token is loaded again. */
static void test_reload_keeps_login_reset(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    pid_t pid = -1;
    int go = -1;

    printf("\n--- loading the token again keeps a login's reset ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK) {
        rv = wrong_login(slot);
        CHECK_RV(rv, "login with a wrong PIN", CKR_OK);
    }
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add_public, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = user_session(slot, &session);
        CHECK_RV(rv, "login resets the failed logins", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process stores an object");
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "reset-parent", &obj);
        CHECK_RV(rv, "create after the other process stored", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        CHECK_TRUE(stored_user_fails(slot) == 0,
                   "reset of the failed logins is stored");
    }
}
#endif

static void record_path(const char* kind, CK_SLOT_ID slot, int objId,
                        char* path, size_t pathSz);

/* Provision the token as token_setup does, without clearing the store. */
static int change_setup(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    unsigned char label[32];
    int code = 0;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (lib_init() != CKR_OK)
        return 20;
    if (funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
            (CK_ULONG)XSTRLEN(soPin), label) != CKR_OK ||
            funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &session) != CKR_OK ||
            funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
            (CK_ULONG)XSTRLEN(soPin)) != CKR_OK ||
            funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)userPin,
            (CK_ULONG)XSTRLEN(userPin)) != CKR_OK) {
        code |= 1;
    }
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* A process that started before another one set up the token checks the SO
 * PIN of that token at C_InitToken. */
static void test_init_token_after_other_setup(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    unsigned char label[32];
    static const char wrongSoPin[] = "wrong-so-pin-1234";
    pid_t pid = -1;
    int go = -1;

    printf("\n--- C_InitToken after another process set up the token ---\n");
    clear_store_dir();
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_setup, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process sets up the token");
    }
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)wrongSoPin,
                                   (CK_ULONG)XSTRLEN(wrongSoPin), label);
        CHECK_RV(rv, "wrong SO PIN is refused", CKR_PIN_INCORRECT);
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        CHECK_RV(rv, "SO PIN resets the token", CKR_OK);
    }
    funcList->C_Finalize(NULL);
}

static int change_uncopyable(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG n = 0;
    CK_ATTRIBUTE find = { CKA_LABEL, (CK_VOID_PTR)"copy-src", 8 };
    CK_ATTRIBUTE noCopy = { CKA_COPYABLE, &ckFalse, sizeof(ckFalse) };
    int code = 0;

    if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK)
        return 20;
    if (funcList->C_FindObjectsInit(session, &find, 1) != CKR_OK ||
            funcList->C_FindObjects(session, &obj, 1, &n) != CKR_OK ||
            funcList->C_FindObjectsFinal(session) != CKR_OK || n != 1 ||
            funcList->C_SetAttributeValue(session, obj, &noCopy, 1) !=
            CKR_OK) {
        code |= 1;
    }
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* C_CopyObject checks the source as another process stored it. */
static void test_copy_sees_other_change(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE src = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_ATTRIBUTE label = { CKA_LABEL, (CK_VOID_PTR)"copy-dst", 8 };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- C_CopyObject after another process changed the source ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_token_secret(session, "copy-src", &src);
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_uncopyable, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process makes the source not copyable");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CopyObject(session, src, &label, 1, &copy);
        CHECK_RV(rv, "copy is refused", CKR_ACTION_PROHIBITED);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A reload that cannot read what another process stored leaves the token in
 * memory as it was. */
static void test_reload_failure_keeps_token(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_SESSION_INFO info;
    char path[512];
    static const byte junk[2] = { 0xff, 0xff };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- a failed reload leaves the token as it was ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_token_secret(session, "rf-first", &obj);
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process stores an object");
    }
    record_path("obj", slot, 1, path, sizeof(path));
    if (rv == CKR_OK) {
        CHECK_TRUE(write_store_file(path, junk, sizeof(junk)) == 0,
                   "damage the stored object record");
        CHECK_TRUE(create_token_secret(session, "rf-second", &obj) != CKR_OK,
                   "create fails when the token cannot be read");
        CHECK_TRUE(count_label(session, "rf-first") == 1,
                   "loaded object is kept");
        rv = funcList->C_GetSessionInfo(session, &info);
        CHECK_TRUE(rv == CKR_OK && info.state == CKS_RW_USER_FUNCTIONS,
                   "login is kept");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifndef WOLFPKCS11_NO_TIME
static int change_wrong_login(CK_SLOT_ID slot)
{
    int code = 0;

    if (lib_init() != CKR_OK)
        return 20;
    if (wrong_login(slot) != CKR_OK)
        code |= 1;
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* Failed logins of two processes that reach the limit together lock the
 * PIN. */
static void test_merged_failed_logins_lock(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_TOKEN_INFO info;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- failed logins of two processes lock the PIN ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_wrong_login, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = wrong_login(slot);
    if (rv == CKR_OK)
        rv = wrong_login(slot);
    CHECK_RV(rv, "two wrong logins", CKR_OK);
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process stores a wrong login");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "store pass", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_TRUE(rv == CKR_OK && (info.flags & CKF_USER_PIN_LOCKED),
                   "PIN is locked");
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                               (CK_ULONG)XSTRLEN(userPin));
        CHECK_RV(rv, "correct PIN is refused while locked", CKR_PIN_LOCKED);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

#ifndef NO_HMAC
/* Dropping the empty PIN's key ends the operations on keys decoded under it.
 */
static void test_dropped_key_ends_ops(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass,             sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType,             sizeof(genericType) },
        { CKA_VALUE,    reloadKey,                sizeof(reloadKey)   },
        { CKA_TOKEN,    &ckTrue,                  sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,                 sizeof(ckFalse)     },
        { CKA_SIGN,     &ckTrue,                  sizeof(ckTrue)      },
        { CKA_LABEL,    (CK_VOID_PTR)"drop-key",  8                   },
    };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    static CK_BYTE msg[] = "message";
    CK_BYTE sig[64];
    CK_ULONG sigLen = sizeof(sig);
    unsigned char label[32];
    pid_t pid = -1;
    int go = -1;

    printf("\n--- dropping the empty PIN's key ends its operations ---\n");
    clear_store_dir();
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)"", 0);
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (EMPTY_PIN_REFUSED(rv)) {
        funcList->C_Finalize(NULL);
        printf("Skipping: empty PINs are not allowed\n");
        return;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
            sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    CHECK_RV(rv, "token with an empty user PIN and a key", CKR_OK);
    if (rv == CKR_OK) {
        pid = fork_changer(change_empty_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_SignInit(session, &mech, key);
        CHECK_RV(rv, "sign with the empty PIN's key", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process sets a PIN");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "load the token again", CKR_OK);
        CHECK_TRUE(funcList->C_Sign(session, msg, sizeof(msg) - 1, sig,
                   &sigLen) != CKR_OK, "operation is ended");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

static int change_reset(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass,              sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,                 sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,                sizeof(ckFalse)   },
        { CKA_LABEL,   (CK_VOID_PTR)"reset-new", 9                },
    };
    unsigned char label[32];
    int code = 0;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (lib_init() != CKR_OK)
        return 20;
    if (funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
            (CK_ULONG)XSTRLEN(soPin), label) != CKR_OK ||
            funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &session) != CKR_OK ||
            funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj) != CKR_OK) {
        code |= 1;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* After another process reset the token, handles this process holds do not
 * name the new token's objects. */
static void test_handles_after_other_reset(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE old = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    byte buf[32];
    CK_ATTRIBUTE get = { CKA_LABEL, buf, sizeof(buf) };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- handles after another process reset the token ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &old);
        CHECK_RV(rv, "create a public object", CKR_OK);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_reset, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process resets the token");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "load the token again", CKR_OK);
        rv = funcList->C_GetAttributeValue(session, old, &get, 1);
        CHECK_RV(rv, "old handle names no object",
                 CKR_OBJECT_HANDLE_INVALID);
        rv = CKR_OK;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* Keys loaded again by a reload that ends the login decrypt with the new
 * PIN, also after the library is initialized again. */
static void test_reload_logout_keeps_keys(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,       &secretClass,            sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType,            sizeof(genericType) },
        { CKA_VALUE,       reloadKey,               sizeof(reloadKey)   },
        { CKA_TOKEN,       &ckTrue,                 sizeof(ckTrue)      },
        { CKA_SENSITIVE,   &ckFalse,                sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,                 sizeof(ckTrue)      },
        { CKA_LABEL,       (CK_VOID_PTR)"keep-key", 8                   },
    };
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    int pass;
    pid_t pid = -1;
    int go = -1;

    printf("\n--- keys survive a reload that ends the login ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
            sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
        CHECK_RV(rv, "create a token key", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process changes the PIN");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "reload ends the login", CKR_OK);
    }
    for (pass = 0; rv == CKR_OK && pass < 2; pass++) {
        byte value[sizeof(reloadKey)];
        CK_ATTRIBUTE get = { CKA_VALUE, value, sizeof(value) };

        if (pass == 1) {
            close_session(session);
            session = CK_INVALID_HANDLE;
            funcList->C_Finalize(NULL);
            rv = lib_init();
            if (rv == CKR_OK) {
                rv = funcList->C_OpenSession(slot,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
            }
        }
        if (rv == CKR_OK) {
            rv = funcList->C_Login(session, CKU_USER,
                (CK_UTF8CHAR_PTR)reloadPin, (CK_ULONG)XSTRLEN(reloadPin));
            CHECK_RV(rv, "login with the new PIN", CKR_OK);
        }
        if (rv == CKR_OK) {
            XMEMSET(value, 0, sizeof(value));
            rv = funcList->C_GetAttributeValue(session, key, &get, 1);
            CHECK_TRUE(rv == CKR_OK &&
                       XMEMCMP(value, reloadKey, sizeof(reloadKey)) == 0,
                       pass == 0 ? "key decrypts after the reload" :
                       "key decrypts after initializing again");
        }
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifndef WOLFPKCS11_NO_TIME
#ifdef DEBUG_WOLFPKCS11
static int change_lock_user(CK_SLOT_ID slot)
{
    int code = 0;

    if (lib_init() != CKR_OK)
        return 20;
    if (wrong_login(slot) != CKR_OK)
        code |= 1;
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Slot_SetPinCheckHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

static pid_t lockPid = -1;
static int lockGo = -1;
static int lockResult = -1;

/* Let the other process lock the PIN while this one checks it. */
static void lock_during_login_hook(void)
{
    if (lockPid > 0) {
        lockResult = run_changer(lockPid, lockGo);
        lockPid = -1;
    }
}

/* A lockout another process stored while this process's login was checked
 * stays, though the login reset the failed logins. */
static void test_merge_keeps_stored_lockout(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_TOKEN_INFO info;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- a stored lockout survives a login's reset ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = wrong_login(slot);
    if (rv == CKR_OK)
        rv = wrong_login(slot);
    CHECK_RV(rv, "two wrong logins", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_lock_user, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        lockPid = pid;
        lockGo = go;
        WP11_Slot_SetPinCheckHook(lock_during_login_hook);
        rv = user_session(slot, &session);
        WP11_Slot_SetPinCheckHook(NULL);
        CHECK_RV(rv, "login resets the failed logins", CKR_OK);
        CHECK_TRUE(lockResult == 0, "other process locks the PIN");
        pid = lockPid;
    }
    if (pid > 0)
        (void)run_changer(pid, go);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "store pass", CKR_OK);
        rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_TRUE(rv == CKR_OK && (info.flags & CKF_USER_PIN_LOCKED),
                   "PIN stays locked");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

static word32 stored_be32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16) |
           ((word32)p[2] << 8) | (word32)p[3];
}

/* Move the stored time of the last failed user login into the past. */
static int expire_user_lockout(CK_SLOT_ID slot)
{
    static byte data[4096];
    char path[512];
    long len;
    long off = 32;

    snprintf(path, sizeof(path), "%s/wp11_token_%016lx", TEST_DIR,
             (unsigned long)slot);
    len = read_store_file(path, data, sizeof(data));
    if (len <= 0 || len >= (long)sizeof(data))
        return -1;
    /* Label, SO PIN, seed, failed logins and times, then the user's. */
    if (len < off + 4)
        return -1;
    off += 4 + (long)stored_be32(data + off) + 16 + 4 +
           2 * (long)sizeof(time_t);
    if (len < off + 4)
        return -1;
    off += 4 + (long)stored_be32(data + off) + 16 + 4;
    if (len < off + (long)sizeof(time_t))
        return -1;
    XMEMSET(data + off, 0, sizeof(time_t));
    return write_store_file(path, data, (size_t)len);
}

/* Failed logins of two processes after a lockout expired are both kept. */
static void test_merge_after_lockout_expires(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_TOKEN_INFO info;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    pid_t pid = -1;
    int go = -1;
    int i;

    printf("\n--- failed logins after an expired lockout are merged ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    for (i = 0; rv == CKR_OK && i < 3; i++)
        rv = wrong_login(slot);
    CHECK_RV(rv, "lock the user PIN", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        CHECK_TRUE(expire_user_lockout(slot) == 0, "lockout expires");
        pid = fork_changer(change_wrong_login, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = wrong_login(slot);
    CHECK_RV(rv, "wrong login after the lockout", CKR_OK);
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process stores a wrong login");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "store pass", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_TRUE(rv == CKR_OK && (info.flags & CKF_USER_PIN_FINAL_TRY),
                   "both failed logins are kept");
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

/* Load the token again through an SO login, which stores nothing. */
static CK_RV so_login_refresh(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    close_session(session);
    return rv;
}

/* Failed logins after an expired lockout are kept across two reloads. */
static void test_merge_after_lockout_two_reloads(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_TOKEN_INFO info;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    pid_t addPid = -1;
    pid_t failPid = -1;
    int addGo = -1;
    int failGo = -1;
    int i;

    printf("\n--- failed logins after an expired lockout, two reloads ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    for (i = 0; rv == CKR_OK && i < 3; i++)
        rv = wrong_login(slot);
    CHECK_RV(rv, "lock the user PIN", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        CHECK_TRUE(expire_user_lockout(slot) == 0, "lockout expires");
        addPid = fork_changer(change_add_public, slot, &addGo);
        failPid = fork_changer(change_wrong_login, slot, &failGo);
        if (addPid < 0 || failPid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = wrong_login(slot);
    CHECK_RV(rv, "wrong login after the lockout", CKR_OK);
    if (addPid > 0) {
        CHECK_TRUE(run_changer(addPid, addGo) == 0,
                   "other process stores an object");
        addPid = -1;
    }
    if (rv == CKR_OK) {
        rv = so_login_refresh(slot);
        CHECK_RV(rv, "first reload", CKR_OK);
    }
    if (failPid > 0) {
        CHECK_TRUE(run_changer(failPid, failGo) == 0,
                   "other process stores a wrong login");
        failPid = -1;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "second reload and store pass", CKR_OK);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_TRUE(rv == CKR_OK && (info.flags & CKF_USER_PIN_FINAL_TRY),
                   "both failed logins are kept");
    }
    if (addPid > 0)
        (void)run_changer(addPid, addGo);
    if (failPid > 0)
        (void)run_changer(failPid, failGo);
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

/* A token with an empty user PIN loads again after a login and logout. */
static void test_empty_pin_reload_after_logout(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
#ifndef NO_HMAC
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    static CK_BYTE msg[] = "message";
    CK_BYTE sig[64];
    CK_ULONG sigLen = sizeof(sig);
#endif
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass,             sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType,             sizeof(genericType) },
        { CKA_VALUE,    reloadKey,                sizeof(reloadKey)   },
        { CKA_TOKEN,    &ckTrue,                  sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,                 sizeof(ckFalse)     },
        { CKA_SIGN,     &ckTrue,                  sizeof(ckTrue)      },
        { CKA_LABEL,    (CK_VOID_PTR)"empty-key", 9                   },
    };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    unsigned char label[32];
    pid_t pid = -1;
    int go = -1;

    printf("\n--- an empty PIN token loads again after a logout ---\n");
    clear_store_dir();
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)"", 0);
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (EMPTY_PIN_REFUSED(rv)) {
        funcList->C_Finalize(NULL);
        printf("Skipping: empty PINs are not allowed\n");
        return;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
            sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    CHECK_RV(rv, "token with an empty user PIN and a key", CKR_OK);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add_public, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)"", 0);
        CHECK_RV(rv, "login with the empty PIN", CKR_OK);
        rv = funcList->C_Logout(session);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process stores an object");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "create after the reload", CKR_OK);
    #ifndef NO_HMAC
        rv = funcList->C_SignInit(session, &mech, key);
        if (rv == CKR_OK)
            rv = funcList->C_Sign(session, msg, sizeof(msg) - 1, sig, &sigLen);
        CHECK_RV(rv, "key loaded again is usable", CKR_OK);
    #endif
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)"", 0);
        CHECK_RV(rv, "login after the reload", CKR_OK);
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}

#ifndef NO_HMAC
/* A reload that ends an SO login leaves the keys of an empty PIN token
 * usable. */
static void test_empty_pin_reload_ends_so_login(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    static CK_BYTE msg[] = "message";
    CK_BYTE sig[64];
    CK_ULONG sigLen = sizeof(sig);
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass,             sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType,             sizeof(genericType) },
        { CKA_VALUE,    reloadKey,                sizeof(reloadKey)   },
        { CKA_TOKEN,    &ckTrue,                  sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,                 sizeof(ckFalse)     },
        { CKA_SIGN,     &ckTrue,                  sizeof(ckTrue)      },
        { CKA_LABEL,    (CK_VOID_PTR)"empty-key", 9                   },
    };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    unsigned char label[32];
    pid_t pid = -1;
    int go = -1;

    printf("\n--- an empty PIN token after a reload ends the SO login ---\n");
    clear_store_dir();
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)"", 0);
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (EMPTY_PIN_REFUSED(rv)) {
        funcList->C_Finalize(NULL);
        printf("Skipping: empty PINs are not allowed\n");
        return;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
            sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    CHECK_RV(rv, "token with an empty user PIN and a key", CKR_OK);
    if (rv == CKR_OK) {
        pid = fork_changer(change_so_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
        CHECK_RV(rv, "SO login", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process changes the SO PIN");
    }
    if (rv == CKR_OK) {
        (void)funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        rv = funcList->C_SignInit(session, &mech, key);
        if (rv == CKR_OK)
            rv = funcList->C_Sign(session, msg, sizeof(msg) - 1, sig, &sigLen);
        CHECK_RV(rv, "key loaded again is usable", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

#ifndef NO_HMAC
/* An SO logout ends an operation on a public key copy a reload replaced, as
 * it ends those on the current objects. */
static void test_so_logout_ends_replaced_op(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    static CK_BYTE msg[] = "message";
    CK_BYTE sig[64];
    CK_ULONG sigLen = sizeof(sig);
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType, sizeof(genericType) },
        { CKA_VALUE,    reloadKey,    sizeof(reloadKey)   },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_SIGN,     &ckTrue,      sizeof(ckTrue)      },
    };
    pid_t pid = -1;
    int go = -1;

    printf("\n--- an SO logout after a reload ends a running sign ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &other);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
            sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_SignInit(session, &mech, key);
        if (rv == CKR_OK)
            rv = funcList->C_SignUpdate(session, msg, sizeof(msg) - 1);
        CHECK_RV(rv, "sign started", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process stores");
    }
    if (rv == CKR_OK) {
        rv = create_token_secret(other, "so-reload", &obj);
        CHECK_RV(rv, "token loaded again", CKR_OK);
    }
    if (rv == CKR_OK)
        rv = funcList->C_Logout(other);
    if (rv == CKR_OK) {
        rv = funcList->C_SignFinal(session, sig, &sigLen);
        CHECK_RV(rv, "sign ended by the SO logout",
                 CKR_OPERATION_NOT_INITIALIZED);
    }
    close_session(other);
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

#ifndef WOLFPKCS11_NSS
/* Dropping the empty PIN's key retires private session objects. */
static void test_dropped_key_retires_session_objects(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    static byte value[4] = { 9, 8, 7, 6 };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckFalse,   sizeof(ckFalse)   },
        { CKA_PRIVATE, &ckTrue,    sizeof(ckTrue)    },
        { CKA_VALUE,   value,      sizeof(value)     },
    };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    byte buf[4];
    CK_ATTRIBUTE get = { CKA_VALUE, buf, sizeof(buf) };
    unsigned char label[32];
    pid_t pid = -1;
    int go = -1;

    printf("\n--- dropping the empty PIN's key retires session objects ---\n");
    clear_store_dir();
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&slot);
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)"", 0);
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (EMPTY_PIN_REFUSED(rv)) {
        printf("Skipping: empty PINs are not allowed\n");
        return;
    }
    CHECK_RV(rv, "token with an empty user PIN", CKR_OK);
    if (rv == CKR_OK) {
        pid = fork_changer(change_empty_pin, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &priv);
        CHECK_RV(rv, "private session object without a login", CKR_OK);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0, "other process sets a PIN");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, dataTmpl,
            sizeof(dataTmpl) / sizeof(*dataTmpl), &obj);
        CHECK_RV(rv, "load the token again", CKR_OK);
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)reloadPin,
                               (CK_ULONG)XSTRLEN(reloadPin));
        CHECK_RV(rv, "login with the new PIN", CKR_OK);
        rv = funcList->C_GetAttributeValue(session, priv, &get, 1);
        CHECK_RV(rv, "private session object is retired",
                 CKR_OBJECT_HANDLE_INVALID);
        rv = CKR_OK;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
}
#endif

/* A create whose store pass failed leaves nothing to store, so the process
 * can load the token again after another process stored. */
static void test_failed_create_not_pending(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    int blocked = 0;
    pid_t pid = -1;
    int go = -1;

    if (geteuid() == 0) {
        printf("\nSkipping failed create test when run as root\n");
        return;
    }
    printf("\n--- a failed create leaves nothing to store ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        pid = fork_changer(change_add, slot, &go);
        if (pid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK && block_store_dir()) {
        blocked = 1;
        CHECK_TRUE(create_token_secret(session, "failed-create", &obj) !=
                   CKR_OK, "create fails while the store is blocked");
        (void)chmod(TEST_DIR, 0700);
    }
    if (pid > 0) {
        CHECK_TRUE(run_changer(pid, go) == 0,
                   "other process stores an object");
    }
    if (rv == CKR_OK && blocked) {
        rv = create_token_secret(session, "after-failed", &obj);
        CHECK_RV(rv, "token can still be changed", CKR_OK);
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifdef DEBUG_WOLFPKCS11
#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Session_SetAddObjectHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

static pid_t racePid = -1;
static int raceGo = -1;
static int raceResult = -1;

/* Let the other process store between the check and the store pass. */
static void race_add_hook(void)
{
    if (racePid > 0) {
        raceResult = run_changer(racePid, raceGo);
        racePid = -1;
    }
}

/* A store pass refused because another process stored first loads the token
 * again and adds the object to the current token. */
static void test_refused_add_retries(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;

    printf("\n--- a refused create loads the token again ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_add, slot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        WP11_Session_SetAddObjectHook(race_add_hook);
        rv = create_token_secret(session, "race-parent", &obj);
        WP11_Session_SetAddObjectHook(NULL);
        CHECK_RV(rv, "create while another process stores", CKR_OK);
        CHECK_TRUE(raceResult == 0, "other process stored first");
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK)
        rv = reload(slot, &session);
    CHECK_RV(rv, "reload", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "reload-child") == 1,
                   "other process's object is stored");
        CHECK_TRUE(count_label(session, "race-parent") == 1,
                   "this process's object is stored");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Object_SetFindHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

static CK_SLOT_ID raceSlot = 0;
static CK_SESSION_HANDLE raceSession = CK_INVALID_HANDLE;

/* Let the other process store after the object was looked up. */
static void race_find_hook(void)
{
    race_add_hook();
}

/* Let the other process store after the lookup, then load the token again in
 * this process through another session. */
static void race_find_reload_hook(void)
{
    CK_OBJECT_HANDLE obj;

    if (racePid > 0) {
        race_add_hook();
        (void)create_token_secret(raceSession, "race-reload", &obj);
    }
}

/* A change to an object that a reload replaced after the lookup is made to
 * the object loaded since. */
static void test_set_attr_after_reload(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE rename = { CKA_LABEL, (CK_VOID_PTR)"race-renamed", 12 };

    printf("\n--- an attribute change after a reload of the token ---\n");
    rv = token_setup(&raceSlot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK)
        rv = create_token_secret(session, "race-first", &obj);
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_add, raceSlot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &raceSession);
    }
    if (rv == CKR_OK) {
        WP11_Object_SetFindHook(race_find_reload_hook);
        rv = funcList->C_SetAttributeValue(session, obj, &rename, 1);
        WP11_Object_SetFindHook(NULL);
        CHECK_RV(rv, "rename while the token is loaded again", CKR_OK);
        CHECK_TRUE(raceResult == 0, "other process stored first");
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    close_session(raceSession);
    raceSession = CK_INVALID_HANDLE;
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK)
        rv = reload(raceSlot, &session);
    CHECK_RV(rv, "reload", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "race-renamed") == 1,
                   "rename is stored");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A destroy whose store pass is refused because another process stored first
 * loads the token again and destroys the object then. */
static void test_refused_destroy_retries(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;

    printf("\n--- a refused destroy loads the token again ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_token_secret(session, "race-doomed", &obj);
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_add, slot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        WP11_Object_SetFindHook(race_find_hook);
        rv = funcList->C_DestroyObject(session, obj);
        WP11_Object_SetFindHook(NULL);
        CHECK_RV(rv, "destroy while another process stores", CKR_OK);
        CHECK_TRUE(raceResult == 0, "other process stored first");
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK)
        rv = reload(slot, &session);
    CHECK_RV(rv, "reload", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "race-doomed") == 0,
                   "object is destroyed");
        CHECK_TRUE(count_label(session, "reload-child") == 1,
                   "other process's object is stored");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

static pid_t racePid2 = -1;
static int raceGo2 = -1;
static int raceFinds = 0;
static int raceSecondReload = 1;

/* After each lookup another process stores and this one loads the token
 * again, except after the second when raceSecondReload is 0. */
static void race_find_twice_hook(void)
{
    CK_OBJECT_HANDLE obj;
    int n = ++raceFinds;

    if (n == 1 && racePid > 0) {
        race_add_hook();
        (void)create_token_secret(raceSession, "race-reload-1", &obj);
    }
    else if (n == 2 && racePid2 > 0) {
        (void)run_changer(racePid2, raceGo2);
        racePid2 = -1;
        if (raceSecondReload)
            (void)create_token_secret(raceSession, "race-reload-2", &obj);
    }
}

static int change_add_second(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    int code = 0;

    if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK)
        return 20;
    if (create_token_secret(session, "reload-child-2", &obj) != CKR_OK)
        code |= 1;
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* An attribute change refused twice, by reloads or by another process's
 * stores, reports a failure a retry can get past and is not kept. */
static void test_set_attr_after_two_reloads(int secondReload)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE rename = { CKA_LABEL, (CK_VOID_PTR)"race-twice", 10 };

    printf("\n--- an attribute change after two %s of the token ---\n",
           secondReload ? "reloads" : "changes");
    rv = token_setup(&raceSlot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK)
        rv = create_token_secret(session, "race-first", &obj);
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_add, raceSlot, &raceGo);
        racePid2 = fork_changer(change_add_second, raceSlot, &raceGo2);
        if (racePid < 0 || racePid2 < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &raceSession);
    }
    if (rv == CKR_OK) {
        raceFinds = 0;
        raceSecondReload = secondReload;
        WP11_Object_SetFindHook(race_find_twice_hook);
        rv = funcList->C_SetAttributeValue(session, obj, &rename, 1);
        WP11_Object_SetFindHook(NULL);
        CHECK_RV(rv, "rename reports a retryable failure",
                 CKR_FUNCTION_FAILED);
        CHECK_TRUE(count_label(session, "race-twice") == 0,
                   "failed rename is not kept");
        rv = funcList->C_SetAttributeValue(session, obj, &rename, 1);
        CHECK_RV(rv, "retry succeeds", CKR_OK);
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    if (racePid2 > 0)
        (void)run_changer(racePid2, raceGo2);
    racePid = -1;
    racePid2 = -1;
    close_session(raceSession);
    raceSession = CK_INVALID_HANDLE;
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifndef NO_HMAC
/* An operation init on a key that a reload replaced after the lookup still
 * starts. */
static void test_op_init_after_reload(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass,             sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType,             sizeof(genericType) },
        { CKA_VALUE,    reloadKey,                sizeof(reloadKey)   },
        { CKA_TOKEN,    &ckTrue,                  sizeof(ckTrue)      },
        { CKA_SIGN,     &ckTrue,                  sizeof(ckTrue)      },
        { CKA_LABEL,    (CK_VOID_PTR)"init-key",  8                   },
    };
    static CK_BYTE msg[] = "message";
    CK_BYTE sig[64];
    CK_ULONG sigLen = sizeof(sig);

    printf("\n--- an operation init after a reload of the token ---\n");
    rv = token_setup(&raceSlot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
            sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_add, raceSlot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &raceSession);
    }
    if (rv == CKR_OK) {
        WP11_Object_SetFindHook(race_find_reload_hook);
        rv = funcList->C_SignInit(session, &mech, key);
        WP11_Object_SetFindHook(NULL);
        CHECK_RV(rv, "sign init while the token is loaded again", CKR_OK);
        CHECK_TRUE(raceResult == 0, "other process stored first");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Sign(session, msg, sizeof(msg) - 1, sig, &sigLen);
        CHECK_RV(rv, "sign", CKR_OK);
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    close_session(raceSession);
    raceSession = CK_INVALID_HANDLE;
    close_session(session);
    funcList->C_Finalize(NULL);
}

static CK_OBJECT_HANDLE raceKey = CK_INVALID_HANDLE;

/* Destroy the object this process looks up. */
static int change_destroy(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int code = 0;

    if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK)
        return 20;
    if (funcList->C_DestroyObject(session, raceKey) != CKR_OK)
        code |= 1;
    close_session(session);
    if (funcList->C_Finalize(NULL) != CKR_OK)
        code |= 2;
    return code;
}

/* Load the token again after the lookup and then log out. */
static void race_find_reload_logout_hook(void)
{
    if (racePid > 0) {
        race_find_reload_hook();
        (void)funcList->C_Logout(raceSession);
    }
}

/* An operation does not start with a key that is gone by the time it is
 * set: destroyed by another process, or ended by a logout after a reload. */
static void test_op_init_on_ended_key(int destroy)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_SHA256_HMAC, NULL, 0 };
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,    &secretClass,             sizeof(secretClass) },
        { CKA_KEY_TYPE, &genericType,             sizeof(genericType) },
        { CKA_VALUE,    reloadKey,                sizeof(reloadKey)   },
        { CKA_TOKEN,    &ckTrue,                  sizeof(ckTrue)      },
        { CKA_SIGN,     &ckTrue,                  sizeof(ckTrue)      },
        { CKA_LABEL,    (CK_VOID_PTR)"ended-key", 9                   },
    };

    printf("\n--- an operation init on a key %s after the lookup ---\n",
           destroy ? "destroyed elsewhere" : "ended by a logout");
    rv = token_setup(&raceSlot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
            sizeof(keyTmpl) / sizeof(*keyTmpl), &raceKey);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(destroy ? change_destroy : change_add,
                               raceSlot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &raceSession);
    }
    if (rv == CKR_OK) {
        WP11_Object_SetFindHook(destroy ? race_find_reload_hook :
                                race_find_reload_logout_hook);
        rv = funcList->C_SignInit(session, &mech, raceKey);
        WP11_Object_SetFindHook(NULL);
        CHECK_TRUE(raceResult == 0, "other process stored first");
        CHECK_TRUE(rv != CKR_OK, "sign init is refused");
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    close_session(raceSession);
    raceSession = CK_INVALID_HANDLE;
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif

/* Log out after the object was looked up. */
static void race_find_logout_hook(void)
{
    (void)funcList->C_Logout(raceSession);
}

/* A copy of a private object is not added once a logout came after the
 * source was looked up. */
static void test_copy_private_after_logout(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    static CK_BYTE value[] = { 0x01, 0x02, 0x03 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckTrue,    sizeof(ckTrue)    },
        { CKA_VALUE,   value,      sizeof(value)     },
    };
    CK_ATTRIBUTE copyTmpl[] = {
        { CKA_LABEL, (CK_VOID_PTR)"private-copy", 12 },
    };

    printf("\n--- a private copy when a logout comes after the lookup ---\n");
    rv = token_setup(&raceSlot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(raceSlot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &raceSession);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj);
    }
    if (rv == CKR_OK) {
        WP11_Object_SetFindHook(race_find_logout_hook);
        rv = funcList->C_CopyObject(session, obj, copyTmpl,
            sizeof(copyTmpl) / sizeof(*copyTmpl), &copy);
        WP11_Object_SetFindHook(NULL);
        CHECK_TRUE(rv != CKR_OK, "copy is not added");
    }
    close_session(raceSession);
    raceSession = CK_INVALID_HANDLE;
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Slot_SetPinCheckHook(void (*hook)(void));
#ifdef __cplusplus
}
#endif

/* Let the other process change the SO PIN while this one checks it. */
static void race_pin_hook(void)
{
    race_add_hook();
}

/* C_InitToken does not reset a token whose SO PIN another process changed
 * while this one checked the old one. */
static void test_init_token_race(void)
{
    CK_RV rv;
    unsigned char label[32];

    printf("\n--- C_InitToken while another process changes the SO PIN ---\n");
    rv = token_setup(&raceSlot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_so_pin, raceSlot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        WP11_Slot_SetPinCheckHook(race_pin_hook);
        rv = funcList->C_InitToken(raceSlot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        WP11_Slot_SetPinCheckHook(NULL);
        CHECK_TRUE(rv != CKR_OK, "reset with the old SO PIN fails");
        CHECK_TRUE(raceResult == 0, "other process changed the SO PIN");
        rv = funcList->C_InitToken(raceSlot, (CK_UTF8CHAR_PTR)reloadSoPin,
                                   (CK_ULONG)XSTRLEN(reloadSoPin), label);
        CHECK_RV(rv, "reset with the new SO PIN", CKR_OK);
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    funcList->C_Finalize(NULL);
}

/* Make the store directory, then let the other process set up the token. */
static void race_setup_hook(void)
{
    (void)mkdir(TEST_DIR, 0700);
    race_add_hook();
}

/* C_InitToken of a token loaded before its store directory existed does not
 * overwrite the token another process set up during the reset. */
static void test_init_token_new_store_race(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    unsigned char label[32];

    printf("\n--- C_InitToken while another process sets up a new store ---\n");
    clear_store_dir();
    (void)rmdir(TEST_DIR);
    rv = lib_init();
    if (rv == CKR_OK)
        rv = first_slot(&raceSlot);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_setup, raceSlot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
    if (rv == CKR_OK) {
        raceResult = -1;
        WP11_Slot_SetPinCheckHook(race_setup_hook);
        rv = funcList->C_InitToken(raceSlot, (CK_UTF8CHAR_PTR)reloadSoPin,
                                   (CK_ULONG)XSTRLEN(reloadSoPin), label);
        WP11_Slot_SetPinCheckHook(NULL);
        CHECK_TRUE(rv != CKR_OK, "reset over the other token fails");
        CHECK_TRUE(raceResult == 0, "other process sets up the token");
        rv = funcList->C_InitToken(raceSlot, (CK_UTF8CHAR_PTR)reloadSoPin,
                                   (CK_ULONG)XSTRLEN(reloadSoPin), label);
        CHECK_RV(rv, "its SO PIN is checked", CKR_PIN_INCORRECT);
        rv = user_session(raceSlot, &session);
        CHECK_RV(rv, "its user PIN is kept", CKR_OK);
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* Let the other process store while the SO PIN is checked, then load the
 * token again in this process. */
static void race_pin_reload_hook(void)
{
    CK_OBJECT_HANDLE obj;

    if (racePid > 0) {
        race_add_hook();
        (void)create_token_secret(raceSession, "race-pin-reload", &obj);
    }
}

/* C_SetPIN changes the SO PIN when a reload during the old PIN check did not
 * change it. */
static void test_so_set_pin_survives_reload(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    printf("\n--- SO C_SetPIN while the token is loaded again ---\n");
    rv = token_setup(&raceSlot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_add, raceSlot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &raceSession);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        WP11_Slot_SetPinCheckHook(race_pin_reload_hook);
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)soPin,
                                (CK_ULONG)XSTRLEN(soPin),
                                (CK_UTF8CHAR_PTR)reloadSoPin,
                                (CK_ULONG)XSTRLEN(reloadSoPin));
        WP11_Slot_SetPinCheckHook(NULL);
        CHECK_TRUE(raceResult == 0, "other process stored an object");
        CHECK_RV(rv, "SO PIN is changed", CKR_OK);
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    close_session(raceSession);
    raceSession = CK_INVALID_HANDLE;
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* Log the SO out while this process adds an object. */
static void race_add_logout_hook(void)
{
    if (raceSession != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(raceSession);
        raceSession = CK_INVALID_HANDLE;
    }
}

/* An SO logout during an add drops the key a public token key needs once a
 * user PIN is set. */
static void test_add_refused_by_so_logout(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;

    printf("\n--- an add while the SO logs out ---\n");
    rv = token_setup(&raceSlot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(raceSlot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &other);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        raceSession = other;
        WP11_Session_SetAddObjectHook(race_add_logout_hook);
        rv = create_token_secret(session, "so-logout-add", &obj);
        WP11_Session_SetAddObjectHook(NULL);
        raceSession = CK_INVALID_HANDLE;
        CHECK_RV(rv, "key is refused", CKR_USER_NOT_LOGGED_IN);
    }
    close_session(other);
    close_session(session);
    funcList->C_Finalize(NULL);
}

#ifdef HAVE_ECC
static int raceAdds = 0;

/* Let the other process change the PIN before the second key is added. */
static void race_second_add_hook(void)
{
    if (++raceAdds == 2)
        race_add_hook();
}

/* A key pair whose private key cannot be added after a reload leaves no
 * public key on the token. */
static void test_keypair_cleanup_after_reload(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    static CK_BYTE p256[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, p256,                  sizeof(p256)   },
        { CKA_TOKEN,     &ckTrue,               sizeof(ckTrue) },
        { CKA_PRIVATE,   &ckTrue,               sizeof(ckTrue) },
        { CKA_VERIFY,    &ckTrue,               sizeof(ckTrue) },
        { CKA_LABEL,     (CK_VOID_PTR)"kp-pub", 6              },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,     &ckTrue,                sizeof(ckTrue) },
        { CKA_SIGN,      &ckTrue,                sizeof(ckTrue) },
        { CKA_LABEL,     (CK_VOID_PTR)"kp-priv", 7              },
    };

    printf("\n--- a key pair that fails after a reload leaves nothing ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        racePid = fork_changer(change_pin, slot, &raceGo);
        if (racePid < 0)
            rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        raceAdds = 0;
        WP11_Session_SetAddObjectHook(race_second_add_hook);
        rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
            sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
            sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
        WP11_Session_SetAddObjectHook(NULL);
        CHECK_TRUE(rv != CKR_OK, "key pair fails after the PIN changed");
        CHECK_TRUE(raceResult == 0, "other process changed the PIN");
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)reloadPin,
                               (CK_ULONG)XSTRLEN(reloadPin));
        CHECK_RV(rv, "login with the new PIN", CKR_OK);
        CHECK_TRUE(count_label(session, "kp-pub") == 0,
                   "private public key is removed");
        rv = CKR_OK;
    }
    if (racePid > 0)
        (void)run_changer(racePid, raceGo);
    racePid = -1;
    close_session(session);
    funcList->C_Finalize(NULL);
}
#endif
#endif

/* A stale process whose change is still waiting to be stored reports the
 * loss at C_Finalize. */
static void test_stale_finalize_reports_pending(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE rename = { CKA_LABEL, (CK_VOID_PTR)"pending-renamed", 15 };
    int toChild[2] = { -1, -1 };
    pid_t pid = -1;
    int status = 0;
    int blocked = 0;
    char c = 0;

    if (geteuid() == 0) {
        printf("\nSkipping stale pending finalize test when run as root\n");
        return;
    }
    printf("\n--- a stale C_Finalize reports a pending change ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "pending-first", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK && pipe(toChild) != 0)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        pid = fork();
    if (pid == 0) {
        close_fd(&toChild[1]);
        if (read(toChild[0], &c, 1) != 1 || lib_init() != CKR_OK ||
                user_session(slot, &session) != CKR_OK ||
                create_token_secret(session, "pending-child", &obj) !=
                    CKR_OK) {
            _exit(1);
        }
        close_session(session);
        _exit(funcList->C_Finalize(NULL) == CKR_OK ? 0 : 2);
    }
    close_fd(&toChild[0]);
    if (rv == CKR_OK && pid < 0)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        CK_ULONG n = 0;
        CK_ATTRIBUTE find = { CKA_LABEL, (CK_VOID_PTR)"pending-first", 13 };

        rv = funcList->C_FindObjectsInit(session, &find, 1);
        if (rv == CKR_OK)
            rv = funcList->C_FindObjects(session, &obj, 1, &n);
        (void)funcList->C_FindObjectsFinal(session);
        if (rv == CKR_OK && n != 1)
            rv = CKR_GENERAL_ERROR;
    }
    /* The change is kept in memory and left for a later pass. */
    if (rv == CKR_OK && block_store_dir()) {
        blocked = 1;
        rv = funcList->C_SetAttributeValue(session, obj, &rename, 1);
        (void)chmod(TEST_DIR, 0700);
        CHECK_RV(rv, "rename while the store is blocked", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (pid > 0) {
        if (rv == CKR_OK && write(toChild[1], &c, 1) != 1)
            rv = CKR_GENERAL_ERROR;
        close_fd(&toChild[1]);
        if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
            status = -1;
        CHECK_TRUE(status == 0, "other process stores an object");
    }
    /* The pending change keeps the token from being loaded again. */
    if (rv == CKR_OK && blocked) {
        CK_TOKEN_INFO info;

        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
        if (rv == CKR_OK) {
            rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                                   (CK_ULONG)XSTRLEN(userPin));
            CHECK_RV(rv, "login uses the token as loaded", CKR_OK);
            rv = create_token_secret(session, "pending-second", &obj);
            CHECK_RV(rv, "create while a change is pending",
                     CKR_TOKEN_WRITE_PROTECTED);
            rv = funcList->C_GetTokenInfo(slot, &info);
            CHECK_TRUE(rv == CKR_OK && (info.flags & CKF_WRITE_PROTECTED),
                       "token reports write protection");
            rv = CKR_OK;
        }
        if (session != CK_INVALID_HANDLE)
            funcList->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
    }
    if (rv == CKR_OK && blocked) {
        rv = funcList->C_Finalize(NULL);
        CHECK_RV(rv, "stale finalize with a pending change",
                 CKR_FUNCTION_FAILED);
    }
    else {
        funcList->C_Finalize(NULL);
    }
    close_fd(&toChild[1]);
}

#ifdef TEST_ALLOC_FAILURE
/* A C_SetAttributeValue that fails after changing an attribute leaves other
 * processes out of date, so they do not write the old attribute back. */
static void test_partial_set_attr_advances(void)
{
    CK_RV rv;
    CK_RV setRv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte newId[32] = { 1 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_LABEL, (CK_VOID_PTR)"partial-renamed", 15            },
        { CKA_ID,    newId,                          sizeof(newId) },
    };
    int toChild[2] = { -1, -1 };
    int fromChild[2] = { -1, -1 };
    pid_t pid = -1;
    int status = 0;
    int changed = 0;
    int left;
    char c = 0;

    printf("\n--- a partly applied attribute change advances the count ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "partial-first", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK && (pipe(toChild) != 0 || pipe(fromChild) != 0))
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        pid = fork();
    if (pid == 0) {
        CK_ULONG n = 0;
        CK_ATTRIBUTE find = { CKA_LABEL, (CK_VOID_PTR)"partial-first", 13 };
        CK_ATTRIBUTE childId = { CKA_ID, (CK_VOID_PTR)"child", 5 };
        int code = 0;

        close_fd(&toChild[1]);
        close_fd(&fromChild[0]);
        if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK ||
                funcList->C_FindObjectsInit(session, &find, 1) != CKR_OK ||
                funcList->C_FindObjects(session, &obj, 1, &n) != CKR_OK ||
                funcList->C_FindObjectsFinal(session) != CKR_OK || n != 1 ||
                write(fromChild[1], &c, 1) != 1 ||
                read(toChild[0], &c, 1) != 1) {
            _exit(10);
        }
        /* Rewrites the object's record with the label this process holds. */
        if (funcList->C_SetAttributeValue(session, obj, &childId, 1) != CKR_OK)
            code = 1;
        close_session(session);
        funcList->C_Finalize(NULL);
        _exit(code);
    }
    close_fd(&toChild[0]);
    close_fd(&fromChild[1]);
    if (rv == CKR_OK && pid < 0)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK && read(fromChild[0], &c, 1) != 1)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        CK_ULONG n = 0;
        CK_ATTRIBUTE find = { CKA_LABEL, (CK_VOID_PTR)"partial-first", 13 };

        rv = funcList->C_FindObjectsInit(session, &find, 1);
        if (rv == CKR_OK)
            rv = funcList->C_FindObjects(session, &obj, 1, &n);
        (void)funcList->C_FindObjectsFinal(session);
        if (rv == CKR_OK && n != 1)
            rv = CKR_GENERAL_ERROR;
    }
    /* Fail one more allocation each time until the label is set first. */
    for (left = 0; rv == CKR_OK && !changed && left < 16; left++) {
        allocsLeft = left;
        setRv = funcList->C_SetAttributeValue(session, obj, tmpl,
                                              sizeof(tmpl) / sizeof(*tmpl));
        allocsLeft = -1;
        if (setRv == CKR_OK)
            break;
        changed = count_label(session, "partial-renamed") == 1;
    }
    CHECK_TRUE(changed, "set fails after changing the label");
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (rv == CKR_OK) {
        rv = funcList->C_Finalize(NULL);
        CHECK_RV(rv, "finalize stores the changed label", CKR_OK);
    }
    else {
        funcList->C_Finalize(NULL);
    }
    if (pid > 0) {
        if (write(toChild[1], &c, 1) != 1)
            rv = CKR_GENERAL_ERROR;
        close_fd(&toChild[1]);
        if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
            status = -1;
        CHECK_TRUE(status == 0, "other process changes the object");
    }
    if (rv == CKR_OK)
        rv = reload(slot, &session);
    CHECK_RV(rv, "reload", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "partial-renamed") == 1,
                   "changed label is kept");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
    close_fd(&toChild[1]);
    close_fd(&fromChild[0]);
}
#endif

/* A process that finalizes with nothing to store leaves other processes able
 * to change the token. */
static void test_clean_finalize_keeps_others_current(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    int toChild[2] = { -1, -1 };
    int fromChild[2] = { -1, -1 };
    pid_t pid = -1;
    int status = 0;
    char c = 0;

    printf("\n--- a clean C_Finalize keeps other processes current ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        rv = create_token_secret(session, "clean-first", &obj);
        CHECK_RV(rv, "create token object", CKR_OK);
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK && (pipe(toChild) != 0 || pipe(fromChild) != 0))
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        pid = fork();
    if (pid == 0) {
        int code = 0;

        close_fd(&toChild[1]);
        close_fd(&fromChild[0]);
        if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK ||
                write(fromChild[1], &c, 1) != 1 ||
                read(toChild[0], &c, 1) != 1) {
            _exit(10);
        }
        if (create_token_secret(session, "clean-child", &obj) != CKR_OK)
            code |= 1;
        close_session(session);
        if (funcList->C_Finalize(NULL) != CKR_OK)
            code |= 2;
        _exit(code);
    }
    close_fd(&toChild[0]);
    close_fd(&fromChild[1]);
    if (rv == CKR_OK && pid < 0)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK && read(fromChild[0], &c, 1) != 1)
        rv = CKR_GENERAL_ERROR;
    /* A rejected template changes nothing, so leaves nothing to store. */
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK) {
        CK_ULONG n = 0;
        CK_ATTRIBUTE find = { CKA_LABEL, (CK_VOID_PTR)"clean-first", 11 };
        CK_ATTRIBUTE uniqueId = { CKA_UNIQUE_ID, (CK_VOID_PTR)"x", 1 };

        rv = funcList->C_FindObjectsInit(session, &find, 1);
        if (rv == CKR_OK)
            rv = funcList->C_FindObjects(session, &obj, 1, &n);
        (void)funcList->C_FindObjectsFinal(session);
        if (rv == CKR_OK && n != 1)
            rv = CKR_GENERAL_ERROR;
        if (rv == CKR_OK) {
            rv = funcList->C_SetAttributeValue(session, obj, &uniqueId, 1);
            CHECK_RV(rv, "rejected attribute change",
                     CKR_ATTRIBUTE_READ_ONLY);
            rv = CKR_OK;
        }
    }
    close_session(session);
    session = CK_INVALID_HANDLE;
    if (rv == CKR_OK) {
        rv = funcList->C_Finalize(NULL);
        CHECK_RV(rv, "finalize with nothing to store", CKR_OK);
    }
    if (pid > 0) {
        if (rv == CKR_OK && write(toChild[1], &c, 1) != 1)
            rv = CKR_GENERAL_ERROR;
        close_fd(&toChild[1]);
        if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
            status = -1;
        CHECK_TRUE(status == 0, "other process can still create an object");
    }
    if (rv == CKR_OK)
        rv = reload(slot, &session);
    CHECK_RV(rv, "reload", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(count_label(session, "clean-child") == 1,
                   "other process's object is stored");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
    close_fd(&toChild[1]);
    close_fd(&fromChild[0]);
}
#endif

#if defined(TOKEN_STORE_FILE_TEST) && !defined(WOLFPKCS11_NO_TIME)
/* A C_Finalize that stores a changed failed login count leaves other
 * processes out of date, so they do not write the old count back. */
static void test_failed_login_finalize_advances(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    int toChild[2] = { -1, -1 };
    int fromChild[2] = { -1, -1 };
    pid_t pid = -1;
    int status = 0;
    char c = 0;
    static const char wrongPin[] = "wrong-user-pin-1234";

    printf("\n--- C_Finalize storing a failed login advances the count ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK && (pipe(toChild) != 0 || pipe(fromChild) != 0))
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        pid = fork();
    if (pid == 0) {
        int code = 0;

        close_fd(&toChild[1]);
        close_fd(&fromChild[0]);
        if (lib_init() != CKR_OK || user_session(slot, &session) != CKR_OK ||
                write(fromChild[1], &c, 1) != 1 ||
                read(toChild[0], &c, 1) != 1) {
            _exit(10);
        }
        if (create_token_secret(session, "login-child", &obj) != CKR_OK)
            code |= 1;
        close_session(session);
        funcList->C_Finalize(NULL);
        _exit(code);
    }
    close_fd(&toChild[0]);
    close_fd(&fromChild[1]);
    if (rv == CKR_OK && pid < 0)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK && read(fromChild[0], &c, 1) != 1)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)wrongPin,
                               (CK_ULONG)XSTRLEN(wrongPin));
        CHECK_RV(rv, "login with a wrong PIN", CKR_PIN_INCORRECT);
        rv = (rv == CKR_PIN_INCORRECT) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    session = CK_INVALID_HANDLE;
    if (rv == CKR_OK) {
        rv = funcList->C_Finalize(NULL);
        CHECK_RV(rv, "finalize stores the failed login", CKR_OK);
    }
    if (pid > 0) {
        if (rv == CKR_OK && write(toChild[1], &c, 1) != 1)
            rv = CKR_GENERAL_ERROR;
        close_fd(&toChild[1]);
        if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
            status = -1;
        CHECK_TRUE(status == 0, "other process stores an object");
    }
    if (rv == CKR_OK)
        rv = lib_init();
    if (rv == CKR_OK) {
        CK_TOKEN_INFO info;

        rv = funcList->C_GetTokenInfo(slot, &info);
        CHECK_RV(rv, "token info", CKR_OK);
        if (rv == CKR_OK) {
            CHECK_TRUE((info.flags & CKF_USER_PIN_COUNT_LOW) != 0,
                       "failed login count is kept");
        }
    }
    funcList->C_Finalize(NULL);
    close_fd(&toChild[1]);
    close_fd(&fromChild[0]);
}
#endif

#ifdef TOKEN_STORE_FILE_TEST
/* Path of a stored record of the given kind at an object id. */
static void record_path(const char* kind, CK_SLOT_ID slot, int objId,
                        char* path, size_t pathSz)
{
    snprintf(path, pathSz, "%s/wp11_%s_%016lx_%016lx", TEST_DIR, kind,
             (unsigned long)slot, (unsigned long)objId);
}

/* A destroy whose store pass fails leaves its records to the next pass
 * that commits. */
static void test_failed_destroy_pass_purges(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE first = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    CK_OBJECT_HANDLE last = CK_INVALID_HANDLE;
    CK_ATTRIBUTE rename = { CKA_LABEL, (CK_VOID_PTR)"purge-renamed", 13 };
    char objPath[512];
    char keyPath[512];
    int blocked = 0;

    if (geteuid() == 0) {
        printf("\nSkipping failed destroy pass test when run as root\n");
        return;
    }
    printf("\n--- a failed destroy pass leaves its records to a purge ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK)
        rv = user_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_token_secret(session, "purge-first", &first);
    if (rv == CKR_OK)
        rv = create_token_secret(session, "purge-second", &obj);
    if (rv == CKR_OK)
        rv = create_token_secret(session, "purge-last", &last);
    CHECK_RV(rv, "three token objects", CKR_OK);
    if (rv == CKR_OK && block_store_dir()) {
        blocked = 1;
        (void)funcList->C_DestroyObject(session, last);
        (void)chmod(TEST_DIR, 0700);
    }
    if (blocked) {
        rv = funcList->C_SetAttributeValue(session, first, &rename, 1);
        CHECK_RV(rv, "next change commits", CKR_OK);
        record_path("obj", slot, 2, objPath, sizeof(objPath));
        record_path("symmkey", slot, 2, keyPath, sizeof(keyPath));
        CHECK_TRUE(count_label(session, "purge-last") != 0 ||
                   (access(objPath, F_OK) != 0 && access(keyPath, F_OK) != 0),
                   "destroyed object's records are removed");
    }
    close_session(session);
    funcList->C_Finalize(NULL);
}

/* A record kind this build does not write. */
#if !defined(WOLFPKCS11_MLKEM)
    #define UNWRITTEN_KIND "mlkemkey_priv"
#elif !defined(WOLFPKCS11_XMSS)
    #define UNWRITTEN_KIND "xmsskey_pub"
#elif !defined(WOLFPKCS11_LMS)
    #define UNWRITTEN_KIND "hsskey_pub"
#endif

/* C_InitToken removes key records at ids that have no object record, as left
 * by an interrupted reset. */
static void test_init_token_removes_orphan_records(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    unsigned char label[32];
    char path[512];
#ifdef UNWRITTEN_KIND
    char unwritten[512];
#endif
    static const byte junk[4] = { 1, 2, 3, 4 };

    printf("\n--- C_InitToken removes records without an object record ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    if (rv == CKR_OK) {
        record_path("symmkey", slot, 0, path, sizeof(path));
        CHECK_TRUE(write_store_file(path, junk, sizeof(junk)) == 0,
                   "write key record 0");
        record_path("obj", slot, 1, path, sizeof(path));
        CHECK_TRUE(write_store_file(path, junk, sizeof(junk)) == 0,
                   "write object record 1");
        record_path("data", slot, 1, path, sizeof(path));
        CHECK_TRUE(write_store_file(path, junk, sizeof(junk)) == 0,
                   "write key record 1");
    #ifdef UNWRITTEN_KIND
        record_path(UNWRITTEN_KIND, slot, 2, unwritten, sizeof(unwritten));
        CHECK_TRUE(write_store_file(unwritten, junk, sizeof(junk)) == 0,
                   "write a record of a type this build does not write");
    #endif
    }
    if (rv == CKR_OK) {
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        CHECK_RV(rv, "C_InitToken", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(count_object_records() == 0,
                   "no object records are left");
    #ifdef UNWRITTEN_KIND
        CHECK_TRUE(access(unwritten, F_OK) != 0,
                   "record of a type this build does not write is removed");
    #endif
    }
    funcList->C_Finalize(NULL);
}

/* C_InitToken reports a record it cannot remove, and the next store pass
 * removes it. */
static void test_init_token_reports_failed_removal(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    unsigned char label[32];
    char path[512];
    char inner[600];
    static const byte junk[4] = { 1, 2, 3, 4 };
    struct stat st;

    printf("\n--- C_InitToken reports a record it cannot remove ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    record_path("symmkey", slot, 3, path, sizeof(path));
    snprintf(inner, sizeof(inner), "%s/x", path);
    if (rv == CKR_OK) {
        CHECK_TRUE(mkdir(path, 0700) == 0 &&
                   write_store_file(inner, junk, sizeof(junk)) == 0,
                   "make an unremovable key record");
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        CHECK_RV(rv, "C_InitToken", CKR_FUNCTION_FAILED);
        rv = (rv == CKR_FUNCTION_FAILED) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    (void)remove(inner);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)XSTRLEN(soPin));
    }
    if (rv == CKR_OK) {
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)userPin,
                                 (CK_ULONG)XSTRLEN(userPin));
        CHECK_RV(rv, "C_InitPIN stores the token", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(stat(path, &st) != 0,
                   "the next store pass removes the record");
    }
    close_session(session);
    (void)rmdir(path);
    funcList->C_Finalize(NULL);
}

/* Set or clear the failed purge flag in the token's pass count file. */
static int set_purge_failed(CK_SLOT_ID slot, int failed)
{
    char path[512];
    FILE* f;
    byte buf[GEN_FILE_SZ];
    int ret = -1;

    snprintf(path, sizeof(path), "%s/wp11_txn_%016lx_gen", TEST_DIR,
             (unsigned long)slot);
    f = fopen(path, "r+b");
    if (f == NULL)
        return -1;
    if (fread(buf, 1, sizeof(buf), f) == sizeof(buf)) {
        buf[GEN_FILE_SZ - 1] = failed ? (byte)(buf[GEN_FILE_SZ - 1] | 0x02) :
            (byte)(buf[GEN_FILE_SZ - 1] & ~0x02);
        if (fseek(f, 0, SEEK_SET) == 0 &&
                fwrite(buf, 1, sizeof(buf), f) == sizeof(buf)) {
            ret = 0;
        }
    }
    fclose(f);
    return ret;
}

/* A purge that C_InitToken could not finish is retried by store passes, not
 * by every load; one that never ran, as when its process stopped, is
 * finished by the next process that loads the token, and only once. */
static void test_init_token_purge_survives_exit(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj;
    unsigned char label[32];
    char path[512];
    char inner[600];
    char later[512];
    static const byte junk[4] = { 1, 2, 3, 4 };
    struct stat st;

    printf("\n--- a later process finishes a pending purge ---\n");
    rv = token_setup(&slot);
    CHECK_RV(rv, "token setup", CKR_OK);
    record_path("symmkey", slot, 3, path, sizeof(path));
    record_path("symmkey", slot, 4, later, sizeof(later));
    snprintf(inner, sizeof(inner), "%s/x", path);
    if (rv == CKR_OK) {
        CHECK_TRUE(mkdir(path, 0700) == 0 &&
                   write_store_file(inner, junk, sizeof(junk)) == 0,
                   "make an unremovable key record");
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        CHECK_RV(rv, "C_InitToken", CKR_FUNCTION_FAILED);
        rv = (rv == CKR_FUNCTION_FAILED) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    funcList->C_Finalize(NULL);
    /* Leave an ordinary record that only the pending purge removes. */
    (void)remove(inner);
    (void)rmdir(path);
    if (rv == CKR_OK) {
        CHECK_TRUE(write_store_file(path, junk, sizeof(junk)) == 0,
                   "leave an old key record");
        rv = lib_init();
        CHECK_RV(rv, "initialize in a later process", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(stat(path, &st) == 0, "loading does not retry it");
        rv = funcList->C_OpenSession(slot,
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        CK_OBJECT_CLASS dataClass = CKO_DATA;
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,   &dataClass, sizeof(dataClass) },
            { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
            { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
        };

        rv = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj);
        CHECK_RV(rv, "a store pass", CKR_OK);
        CHECK_TRUE(stat(path, &st) != 0, "the store pass removes it");
    }
    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);

    /* A purge that never ran is finished at load. */
    if (rv == CKR_OK) {
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, tokenLabel, XSTRLEN(tokenLabel));
        rv = lib_init();
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(mkdir(path, 0700) == 0 &&
                   write_store_file(inner, junk, sizeof(junk)) == 0,
                   "make the key record unremovable again");
        rv = funcList->C_InitToken(slot, (CK_UTF8CHAR_PTR)soPin,
                                   (CK_ULONG)XSTRLEN(soPin), label);
        CHECK_RV(rv, "C_InitToken", CKR_FUNCTION_FAILED);
        rv = (rv == CKR_FUNCTION_FAILED) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    funcList->C_Finalize(NULL);
    (void)remove(inner);
    (void)rmdir(path);
    if (rv == CKR_OK) {
        CHECK_TRUE(write_store_file(path, junk, sizeof(junk)) == 0 &&
                   set_purge_failed(slot, 0) == 0,
                   "leave a purge that never ran");
        rv = lib_init();
        CHECK_RV(rv, "initialize in a later process", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(stat(path, &st) != 0, "the later process removes it");
    }
    funcList->C_Finalize(NULL);
    if (rv == CKR_OK) {
        CHECK_TRUE(write_store_file(later, junk, sizeof(junk)) == 0,
                   "leave a record after the purge");
        rv = lib_init();
        CHECK_RV(rv, "initialize again", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(stat(later, &st) == 0, "the finished purge does not rerun");
    }
    funcList->C_Finalize(NULL);
    (void)remove(path);
    (void)remove(later);
}
#endif

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
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    test_derive_reports_commit_failure();
#endif
#ifdef DEBUG_WOLFPKCS11
    test_create_reports_close_failure();
    test_load_fails_on_read_error();
#endif
    test_token_record_kept_on_failed_store();
    test_pin_change_store_failure();
    test_init_pin_store_failure();
    test_token_reset_store_failure();
    test_finalize_reports_store_failure();
    test_init_retry_after_load_failure();
    test_init_token_removes_newer_records();
    test_init_token_removes_changed_type();
    test_init_token_removes_orphan_records();
    test_init_token_reports_failed_removal();
    test_init_token_purge_survives_exit();
    test_destroy_reports_unstore_failure();
    test_failed_destroy_pass_purges();
    test_destroy_unstored_object();
    test_load_record_without_trailing_fields();
    test_record_cut_in_issuer();
    test_stale_process_reloads();
    test_stale_login_sees_new_pin();
    test_reload_keeps_login();
    test_reload_ends_login_on_pin_change();
    test_init_pin_after_so_pin_change();
    test_init_token_after_other_setup();
    test_failed_create_not_pending();
    test_handles_after_other_reset();
    test_reload_logout_keeps_keys();
    test_empty_pin_reload_after_logout();
#ifndef NO_HMAC
    test_empty_pin_reload_ends_so_login();
    test_so_logout_ends_replaced_op();
#endif
#ifndef WOLFPKCS11_NSS
    test_dropped_key_retires_session_objects();
#endif
    test_copy_sees_other_change();
    test_reload_failure_keeps_token();
    test_failed_pin_change_reloads(0);
    test_failed_pin_change_reloads(1);
    test_unchecked_store_refuses_login();
    test_unreadable_token_record();
#ifndef NO_HMAC
    test_dropped_key_ends_ops();
#endif
    test_init_token_sees_new_so_pin();
    test_set_pin_after_so_pin_change();
#ifdef HAVE_ECC
    test_op_ends_on_destroyed_key(0);
    test_op_ends_on_destroyed_key(1);
#endif
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    test_derive_after_other_store();
#endif
#ifdef TEST_ALLOC_FAILURE
    test_partial_set_attr_undone();
#endif
    test_reload_drops_empty_pin_key();
    test_reload_to_empty_pin_keeps_key();
#ifdef WOLFPKCS11_NSS
    test_nss_init_pin_without_store_dir();
#endif
#ifndef WOLFPKCS11_NO_TIME
    test_failed_login_survives_later_store();
    test_reload_keeps_login_reset();
    test_merged_failed_logins_lock();
#ifdef DEBUG_WOLFPKCS11
    test_merge_keeps_stored_lockout();
#endif
    test_merge_after_lockout_expires();
    test_merge_after_lockout_two_reloads();
#endif
#ifdef DEBUG_WOLFPKCS11
    test_refused_add_retries();
    test_set_attr_after_reload();
    test_refused_destroy_retries();
    test_set_attr_after_two_reloads(1);
    test_set_attr_after_two_reloads(0);
#ifndef NO_HMAC
    test_op_init_after_reload();
    test_op_init_on_ended_key(1);
    test_op_init_on_ended_key(0);
#endif
    test_copy_private_after_logout();
    test_init_token_race();
    test_init_token_new_store_race();
    test_so_set_pin_survives_reload();
    test_add_refused_by_so_logout();
#ifdef HAVE_ECC
    test_keypair_cleanup_after_reload();
#endif
#endif
    test_clean_finalize_keeps_others_current();
#ifndef WOLFPKCS11_NO_TIME
    test_failed_login_finalize_advances();
#endif
    test_stale_finalize_reports_pending();
#ifdef TEST_ALLOC_FAILURE
    test_init_out_of_memory();
    test_create_object_out_of_memory();
    test_partial_set_attr_advances();
#endif

    clear_store_dir();
#else
    test_interrupted_create_keeps_stored_token();
    test_interrupted_pin_change_keeps_stored_pin();
    test_grown_record_reloads();
    test_record_overflow_reports_failure();
    test_tpm_unreadable_token_record();
    test_tpm_init_token_removes_records();
    test_load_fails_on_read_error();
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
