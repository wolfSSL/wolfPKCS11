/* custom_store_test.c
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
 * The library sources are built into this test with WOLFPKCS11_CUSTOM_STORE,
 * and the test implements the store in memory. It is built twice:
 *  - custom_store_test, with WOLFPKCS11_CUSTOM_STORE_CLOSE_COMMIT, checks that
 *    a record whose commit fails, with any code, or whose write fails, fails
 *    the create, that a failed write closes the record with commit set to 0,
 *    that a failed commit fails a destroy, and that the next store writes the
 *    records of every object again,
 *  - custom_store_legacy_test, without it, checks that a store implementing
 *    only wolfPKCS11_Store_Close() still builds and keeps token objects.
 * Both check that a record that fails to open for writing fails the create
 * with CKR_FUNCTION_FAILED, whatever code the store returns, that a failed
 * remove fails the destroy, that any failed read or open for reading fails
 * loading the token, and that a record that fails to open, for writing or
 * reading, is not closed.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>
#include <wolfpkcs11/store.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The library turns storage off without AES (wolfpkcs11/internal.h). */
#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_TPM_STORE) && \
    !defined(NO_AES)
#define RUN_TEST
#endif

/* Store status codes, as in wolfpkcs11/internal.h. */
#define NOT_AVAILABLE_E     -4
/* Failure code of the store. The same value as PIN_INVALID_E, so a failed
 * create only reports CKR_FUNCTION_FAILED when the code is not passed on. */
#define STORE_FAIL_E        -1

/* ---- Store kept in memory ---- */

#define STORE_RECORDS       64

typedef struct StoreRecord {
    int used;
    int type;
    CK_ULONG id1;
    CK_ULONG id2;
    unsigned char* data;
    int len;
    int commits;                /* Times the record was committed */
} StoreRecord;

typedef struct StoreHandle {
    int read;
    int type;
    CK_ULONG id1;
    CK_ULONG id2;
    unsigned char* data;        /* Record read, or data written */
    int len;
    int pos;                    /* Read position */
} StoreHandle;

static StoreRecord records[STORE_RECORDS];
static int commitCnt;           /* Commits tried */
static int openCnt;             /* Opens for writing tried */
static int writeCnt;            /* Writes tried */
static int readOpenCnt;         /* Opens for reading tried */
static int readCnt;             /* Reads tried */
static int removeCnt;           /* Removes tried */
static int discardCnt;          /* Written records closed without commit */
static int nullCloseCnt;        /* Closes of a store that was not opened */
static int injectCnt;           /* Failures injected */
static int failCommitAt = -1;   /* Commit to fail, counted by commitCnt */
static int failOpenAt = -1;     /* Open to fail, counted by openCnt */
static int failWriteAt = -1;    /* Write to fail, counted by writeCnt */
static int failReadOpenAt = -1; /* Open to fail, counted by readOpenCnt */
static int failReadAt = -1;     /* Read to fail, counted by readCnt */
static int failRemoveAt = -1;   /* Remove to fail, counted by removeCnt */
static int failCommitCode = STORE_FAIL_E;   /* Code of a failed commit */
static int failOpenCode = STORE_FAIL_E;     /* Code of a failed write open */

static StoreRecord* store_find(int type, CK_ULONG id1, CK_ULONG id2)
{
    int i;

    for (i = 0; i < STORE_RECORDS; i++) {
        if (records[i].used && records[i].type == type &&
                records[i].id1 == id1 && records[i].id2 == id2) {
            return &records[i];
        }
    }
    return NULL;
}

static int store_commit(StoreHandle* handle)
{
    StoreRecord* rec = store_find(handle->type, handle->id1, handle->id2);
    int i;

    for (i = 0; rec == NULL && i < STORE_RECORDS; i++) {
        if (!records[i].used) {
            rec = &records[i];
            XMEMSET(rec, 0, sizeof(*rec));
            rec->used = 1;
            rec->type = handle->type;
            rec->id1 = handle->id1;
            rec->id2 = handle->id2;
        }
    }
    if (rec == NULL)
        return STORE_FAIL_E;

    free(rec->data);
    rec->data = handle->data;
    rec->len = handle->len;
    rec->commits++;
    handle->data = NULL;
    return 0;
}

static int store_close(void* store, int commit)
{
    StoreHandle* handle = (StoreHandle*)store;
    int ret = 0;

    if (handle == NULL) {
        nullCloseCnt++;
        return 0;
    }
    if (!handle->read) {
        if (!commit) {
            discardCnt++;
        }
        else if (commitCnt++ == failCommitAt) {
            /* As a failed flash commit: the record keeps its old data. */
            injectCnt++;
            ret = failCommitCode;
        }
        else {
            ret = store_commit(handle);
        }
        free(handle->data);
    }
    free(handle);
    return ret;
}

int wolfPKCS11_Store_Open(int type, CK_ULONG id1, CK_ULONG id2, int read,
    void** store)
{
    StoreRecord* rec = store_find(type, id1, id2);
    StoreHandle* handle;

    *store = NULL;
    if (read && readOpenCnt++ == failReadOpenAt) {
        injectCnt++;
        return STORE_FAIL_E;
    }
    if (read && rec == NULL)
        return NOT_AVAILABLE_E;
    if (!read && openCnt++ == failOpenAt) {
        injectCnt++;
        return failOpenCode;
    }
    handle = (StoreHandle*)calloc(1, sizeof(*handle));
    if (handle == NULL)
        return STORE_FAIL_E;
    handle->read = read;
    handle->type = type;
    handle->id1 = id1;
    handle->id2 = id2;
    if (read) {
        /* Reads use the record's data, which no write changes while open. */
        handle->data = rec->data;
        handle->len = rec->len;
    }
    *store = handle;
    return 0;
}

int wolfPKCS11_Store_Remove(int type, CK_ULONG id1, CK_ULONG id2)
{
    StoreRecord* rec = store_find(type, id1, id2);

    if (removeCnt++ == failRemoveAt) {
        injectCnt++;
        return STORE_FAIL_E;
    }
    if (rec == NULL)
        return NOT_AVAILABLE_E;
    free(rec->data);
    XMEMSET(rec, 0, sizeof(*rec));
    return 0;
}

void wolfPKCS11_Store_Close(void* store)
{
    (void)store_close(store, 1);
}

#ifdef WOLFPKCS11_CUSTOM_STORE_CLOSE_COMMIT
int wolfPKCS11_Store_CloseCommit(void* store, int commit)
{
    return store_close(store, commit);
}
#endif

int wolfPKCS11_Store_Read(void* store, unsigned char* buffer, int len)
{
    StoreHandle* handle = (StoreHandle*)store;

    if (handle == NULL || !handle->read || len < 0)
        return STORE_FAIL_E;
    if (readCnt++ == failReadAt) {
        injectCnt++;
        return STORE_FAIL_E;
    }
    if (len > handle->len - handle->pos)
        len = handle->len - handle->pos;
    if (len > 0)
        XMEMCPY(buffer, handle->data + handle->pos, len);
    handle->pos += len;
    return len;
}

int wolfPKCS11_Store_Write(void* store, unsigned char* buffer, int len)
{
    StoreHandle* handle = (StoreHandle*)store;
    unsigned char* data;

    if (handle == NULL || handle->read || len < 0)
        return STORE_FAIL_E;
    if (writeCnt++ == failWriteAt) {
        injectCnt++;
        return STORE_FAIL_E;
    }
    data = (unsigned char*)realloc(handle->data, handle->len + len + 1);
    if (data == NULL)
        return STORE_FAIL_E;
    if (len > 0)
        XMEMCPY(data + handle->len, buffer, len);
    handle->data = data;
    handle->len += len;
    return len;
}

#ifdef RUN_TEST

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d - %s - FAIL\n", __FILE__, __LINE__,     \
                    msg);                                                  \
            return -1;                                                     \
        }                                                                  \
    }                                                                      \
    while (0)
#define CHECK_RV(rv, msg)                                                  \
    do {                                                                   \
        if ((rv) != CKR_OK) {                                              \
            fprintf(stderr, "%s:%d - %s: 0x%lx - FAIL\n", __FILE__,        \
                    __LINE__, msg, (unsigned long)(rv));                   \
            return -1;                                                     \
        }                                                                  \
    }                                                                      \
    while (0)

static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot;
static unsigned char tokenName[32] = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static void store_free(void)
{
    int i;

    for (i = 0; i < STORE_RECORDS; i++)
        free(records[i].data);
    XMEMSET(records, 0, sizeof(records));
}

/* Remove the record of the given type for the object with the given store id.
 * Returns 1 when removed. */
static int store_drop(int type, CK_ULONG id)
{
    int i;

    for (i = 0; i < STORE_RECORDS; i++) {
        if (records[i].used && records[i].type == type &&
                records[i].id2 == id) {
            free(records[i].data);
            XMEMSET(&records[i], 0, sizeof(records[i]));
            return 1;
        }
    }
    return 0;
}

/* Commits of the records of the object with the given store id. */
static int object_commits(CK_ULONG id)
{
    int i;
    int cnt = 0;

    for (i = 0; i < STORE_RECORDS; i++) {
        if (records[i].used && records[i].type != WOLFPKCS11_STORE_TOKEN &&
                records[i].id2 == id) {
            cnt += records[i].commits;
        }
    }
    return cnt;
}

static CK_RV pkcs11_init(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

    rv = C_GetFunctionList(&funcList);
    if (rv != CKR_OK)
        return rv;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_OK && slotCount == 0)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        slot = slotList[0];
    return rv;
}

static CK_RV provision(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;

    rv = funcList->C_InitToken(slot, soPin, soPinLen, tokenName);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        if (rv == CKR_OK)
            rv = funcList->C_InitPIN(session, userPin, userPinLen);
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }
    return rv;
}

static CK_RV open_user_session(CK_SESSION_HANDLE* session)
{
    CK_RV rv;

    rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 NULL, NULL, session);
    if (rv == CKR_OK)
        rv = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    return rv;
}

/* Create a token data object whose label and value are the name. */
static CK_RV create_obj(CK_SESSION_HANDLE session, const char* name)
{
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &dataClass,      sizeof(dataClass)   },
        { CKA_TOKEN,       &ckTrue,         sizeof(ckTrue)      },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)     },
        { CKA_LABEL,       (void*)name,     strlen(name)        },
        { CKA_VALUE,       (void*)name,     strlen(name)        },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(tmpl[0]), &obj);
}

/* Destroy the token object with the name as label. */
static CK_RV destroy_obj(CK_SESSION_HANDLE session, const char* name)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &ckTrue,      sizeof(ckTrue) },
        { CKA_LABEL, (void*)name,  strlen(name)   },
    };
    CK_OBJECT_HANDLE obj;
    CK_ULONG cnt = 0;
    CK_RV rv;

    rv = funcList->C_FindObjectsInit(session, tmpl, 2);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, &obj, 1, &cnt);
        (void)funcList->C_FindObjectsFinal(session);
    }
    if (rv == CKR_OK && cnt != 1)
        rv = CKR_OBJECT_HANDLE_INVALID;
    if (rv == CKR_OK)
        rv = funcList->C_DestroyObject(session, obj);
    return rv;
}

/* Find the token object with the name as label, and check its value.
 * Returns the number found, or -1 on a wrong value. */
static int find_obj(CK_SESSION_HANDLE session, const char* name)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &ckTrue,      sizeof(ckTrue) },
        { CKA_LABEL, (void*)name,  strlen(name)   },
    };
    CK_OBJECT_HANDLE found[4];
    CK_ULONG cnt = 0;
    byte value[32];
    CK_ATTRIBUTE attr = { CKA_VALUE, value, sizeof(value) };

    if (funcList->C_FindObjectsInit(session, tmpl, 2) != CKR_OK)
        return -1;
    if (funcList->C_FindObjects(session, found, 4, &cnt) != CKR_OK)
        cnt = 0;
    (void)funcList->C_FindObjectsFinal(session);
    if (cnt > 0) {
        if (funcList->C_GetAttributeValue(session, found[0], &attr, 1) !=
                CKR_OK) {
            return -1;
        }
        if (attr.ulValueLen != strlen(name) ||
                XMEMCMP(value, name, attr.ulValueLen) != 0) {
            return -1;
        }
    }
    return (int)cnt;
}

static int count_token_objects(CK_SESSION_HANDLE session)
{
    CK_ATTRIBUTE tmpl[] = { { CKA_TOKEN, &ckTrue, sizeof(ckTrue) } };
    CK_OBJECT_HANDLE found[16];
    CK_ULONG cnt = 0;

    if (funcList->C_FindObjectsInit(session, tmpl, 1) != CKR_OK)
        return -1;
    if (funcList->C_FindObjects(session, found, 16, &cnt) != CKR_OK)
        cnt = 0;
    (void)funcList->C_FindObjectsFinal(session);
    return (int)cnt;
}

/* Load the token and check that exactly the kept objects load back. Returns
 * the number of reads and of opens for reading that loading took. */
static int load_kept(const char** kept, int keptCnt, int* reads, int* opens)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    int startReads = readCnt;
    int startOpens = readOpenCnt;
    int i;

    rv = pkcs11_init();
    CHECK_RV(rv, "Initialize again");
    *reads = readCnt - startReads;
    *opens = readOpenCnt - startOpens;
    rv = open_user_session(&session);
    CHECK_RV(rv, "Open user session again");
    CHECK(count_token_objects(session) == keptCnt, "Object count");
    for (i = 0; i < keptCnt; i++)
        CHECK(find_obj(session, kept[i]) == 1, "Object loaded");
    (void)funcList->C_Logout(session);
    (void)funcList->C_CloseSession(session);
    (void)funcList->C_Finalize(NULL);
    return 0;
}

/* Fail each of the store calls that loading the token makes, one per load,
 * and check that every load fails. */
static int load_fails(int* failAt, const int* callCnt, int calls,
    const char* msg)
{
    CK_RV rv;
    int i;

    for (i = 0; i < calls; i++) {
        injectCnt = 0;
        *failAt = *callCnt + i;
        rv = pkcs11_init();
        *failAt = -1;
        if (rv == CKR_OK)
            (void)funcList->C_Finalize(NULL);
        CHECK(injectCnt == 1, "Failure injected while loading");
        if (rv == CKR_OK)
            fprintf(stderr, "Store call %d of %d while loading\n", i, calls);
        CHECK(rv != CKR_OK, msg);
    }
    return 0;
}

static int custom_store_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    /* Objects that exist at the end. */
    const char* kept[] = { "objA", "objB", "objD", "objG" };
    int keptCnt;
    int commits;
    int discards = 0;
    int reads;
    int opens;

    rv = pkcs11_init();
    CHECK_RV(rv, "Initialize");
    rv = provision();
    CHECK_RV(rv, "Provision token");
    rv = open_user_session(&session);
    CHECK_RV(rv, "Open user session");

    /* objA takes store id 0. Creating objB writes only objB and the token. */
    rv = create_obj(session, "objA");
    CHECK_RV(rv, "Create objA");
    commits = object_commits(0);
    CHECK(commits > 0, "objA stored");
    rv = create_obj(session, "objB");
    CHECK_RV(rv, "Create objB");
    CHECK(object_commits(0) == commits, "Create leaves objA's records");
    keptCnt = 2;

    /* objX's first record does not open for writing, so the create fails. */
    failOpenAt = openCnt;
    rv = create_obj(session, "objX");
    failOpenAt = -1;
    CHECK(rv == CKR_FUNCTION_FAILED, "Failed open fails the create");
    CHECK(find_obj(session, "objX") == 0, "Failed create not added");

    /* objY's object record is written, then its data record does not open. */
    failOpenAt = openCnt + 1;
    rv = create_obj(session, "objY");
    failOpenAt = -1;
    CHECK(rv == CKR_FUNCTION_FAILED, "Failed open fails the create");
    CHECK(find_obj(session, "objY") == 0, "Failed create not added");
    CHECK(nullCloseCnt == 0, "Record that did not open not closed");

    /* NOT_AVAILABLE_E from an open for writing fails the create too, rather
     * than reading as storage turned off. */
    failOpenAt = openCnt;
    failOpenCode = NOT_AVAILABLE_E;
    rv = create_obj(session, "objZ");
    failOpenAt = -1;
    failOpenCode = STORE_FAIL_E;
    CHECK(rv == CKR_FUNCTION_FAILED, "Unavailable open fails the create");
    CHECK(find_obj(session, "objZ") == 0, "Failed create not added");

    /* objR's records fail to be removed when it is destroyed. */
    rv = create_obj(session, "objR");
    CHECK_RV(rv, "Create objR");
    failRemoveAt = removeCnt;
    rv = destroy_obj(session, "objR");
    failRemoveAt = -1;
    CHECK(rv == CKR_FUNCTION_FAILED, "Failed remove fails the destroy");
    CHECK(find_obj(session, "objR") == 0, "Destroyed object removed");
    /* Creating objR wrote every object, after the failures above. */
    commits = object_commits(0);

#ifdef WOLFPKCS11_CUSTOM_STORE_CLOSE_COMMIT
    /* The first record of objC does not commit, so the create fails. */
    failCommitAt = commitCnt;
    rv = create_obj(session, "objC");
    failCommitAt = -1;
    CHECK(rv == CKR_FUNCTION_FAILED, "Failed commit fails the create");

    /* The next create writes every object again, then only its own. */
    rv = create_obj(session, "objD");
    CHECK_RV(rv, "Create objD");
    CHECK(object_commits(0) > commits, "objA rewritten after failure");
    commits = object_commits(0);
    rv = create_obj(session, "objE");
    CHECK_RV(rv, "Create objE");
    CHECK(object_commits(0) == commits, "objA not rewritten again");

    /* A failed write fails the create, and the record is not committed. */
    failWriteAt = writeCnt;
    rv = create_obj(session, "objF");
    failWriteAt = -1;
    CHECK(rv == CKR_FUNCTION_FAILED, "Failed write fails the create");
    discards++;
    CHECK(discardCnt == discards, "Record closed with commit of 0");

    rv = create_obj(session, "objG");
    CHECK_RV(rv, "Create objG");
    CHECK(object_commits(0) > commits, "objA rewritten after failure");
    keptCnt = (int)(sizeof(kept) / sizeof(kept[0]));

    CHECK(find_obj(session, "objC") == 0, "Failed create not added");
    CHECK(find_obj(session, "objF") == 0, "Failed create not added");

    /* A destroy whose commit fails reports it. The object is gone, and the
     * token is written in full when finalized. */
    failCommitAt = commitCnt;
    rv = destroy_obj(session, "objE");
    failCommitAt = -1;
    CHECK(rv == CKR_FUNCTION_FAILED, "Failed commit fails the destroy");
    CHECK(find_obj(session, "objE") == 0, "Destroyed object removed");

    /* NOT_AVAILABLE_E from a commit fails the create too, rather than
     * reading as storage turned off. */
    failCommitAt = commitCnt;
    failCommitCode = NOT_AVAILABLE_E;
    rv = create_obj(session, "objH");
    failCommitAt = -1;
    failCommitCode = STORE_FAIL_E;
    CHECK(rv == CKR_FUNCTION_FAILED, "Unavailable commit fails the create");
    CHECK(find_obj(session, "objH") == 0, "Failed create not added");
#endif
    /* Records written without a failure are closed with commit of 1. */
    CHECK(discardCnt == discards, "No other record discarded");

    (void)funcList->C_Logout(session);
    (void)funcList->C_CloseSession(session);
    (void)funcList->C_Finalize(NULL);

    /* The objects load back from the store. */
    if (load_kept(kept, keptCnt, &reads, &opens) != 0)
        return -1;

    /* Any read, or open for reading, that fails while loading fails the
     * load. A failed read must not read as the end of a record in an older
     * format, which would load it without the fields after that point. */
    if (load_fails(&failReadAt, &readCnt, reads,
            "Failed read fails the load") != 0) {
        return -1;
    }
    if (load_fails(&failReadOpenAt, &readOpenCnt, opens,
            "Failed open fails the load") != 0) {
        return -1;
    }
    CHECK(nullCloseCnt == 0, "Record that did not open not closed");
    /* The failed loads left the store as it was. */
    if (load_kept(kept, keptCnt, &reads, &opens) != 0)
        return -1;

    /* A data record that is missing does not open for reading. Loading the
     * token fails, and the record is not closed. */
    CHECK(store_drop(WOLFPKCS11_STORE_DATA, 0), "Data record removed");
    rv = pkcs11_init();
    if (rv == CKR_OK)
        (void)funcList->C_Finalize(NULL);
    CHECK(rv != CKR_OK, "Missing record fails the load");
    CHECK(nullCloseCnt == 0, "Record that did not open not closed");

    return 0;
}

#endif /* RUN_TEST */

int main(int argc, char* argv[])
{
#ifdef RUN_TEST
    int ret;

    (void)argc;
    (void)argv;

#ifdef WOLFPKCS11_CUSTOM_STORE_CLOSE_COMMIT
    printf("Custom store test (close with commit status)\n");
#else
    printf("Custom store test (close only)\n");
#endif
    ret = custom_store_test();
    store_free();
    if (ret == 0)
        printf("All tests passed!\n");
    return (ret == 0) ? 0 : 1;
#else
    (void)argc;
    (void)argv;
    printf("Test not built for this configuration\n");
    return 77;
#endif
}
