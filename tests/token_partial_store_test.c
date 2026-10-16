/* token_partial_store_test.c
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
 * Token objects are written to storage only when they are created, changed
 * or moved. This test checks that:
 *  - creating an object does not rewrite the records of the other objects,
 *  - after creates, destroys and an attribute change, the records written so
 *    far load back as the right objects without relying on the full store
 *    done by C_Finalize,
 *  - no records are left behind for destroyed objects,
 *  - changes made while storage is turned off (WOLFPKCS11_NO_STORE) are all
 *    written once it is turned back on.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#include <stdio.h>
#include <string.h>

#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_CUSTOM_STORE) && \
    !defined(WOLFPKCS11_TPM_STORE) && !defined(WOLFPKCS11_NO_ENV) && \
    !defined(NO_AES) && !defined(_WIN32)
#define RUN_TEST
#endif

#ifdef RUN_TEST

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"

#define STORE_DIR   "./store/partial"
#define SNAP_DIR    "./store/partial-snap"

#define MAX_FILES   64
#define NAME_LEN    128
#define PATH_LEN    256

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

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot;
static unsigned char tokenName[32] = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static const byte aesKey[32] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

/* Objects made by the test. Index is used in the label and value. */
#define OBJ_CNT     7
#define OBJ_AES     5

struct file_ent {
    char name[NAME_LEN];
    ino_t ino;
};

/* ---- Store directory helpers ---- */

static int is_object_record(const char* name)
{
    /* Object records are named "wp11_<kind>_<tokenId>_<objId>". */
    const char* p = strrchr(name, '_');

    if (strncmp(name, "wp11_", 5) != 0 || strncmp(name, "wp11_token_", 11) == 0)
        return 0;
    return p != NULL && strlen(p + 1) == 16 && strchr(name, '.') == NULL;
}

static long record_id(const char* name)
{
    return strtol(strrchr(name, '_') + 1, NULL, 16);
}

/* Join a directory and file name. Returns -1 when it does not fit. */
static int join_path(char* path, size_t len, const char* dir, const char* name)
{
    int n = snprintf(path, len, "%s/%s", dir, name);

    return (n < 0 || (size_t)n >= len) ? -1 : 0;
}

static int list_records(const char* dir, struct file_ent* ents, int* cnt)
{
    DIR* d;
    struct dirent* e;
    struct stat st;
    char path[PATH_LEN];

    *cnt = 0;
    d = opendir(dir);
    if (d == NULL)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (!is_object_record(e->d_name) || *cnt >= MAX_FILES ||
                strlen(e->d_name) >= NAME_LEN) {
            continue;
        }
        if (join_path(path, sizeof(path), dir, e->d_name) != 0 ||
                stat(path, &st) != 0) {
            continue;
        }
        memcpy(ents[*cnt].name, e->d_name, strlen(e->d_name) + 1);
        ents[*cnt].ino = st.st_ino;
        (*cnt)++;
    }
    closedir(d);
    return 0;
}

static int clear_dir(const char* dir)
{
    DIR* d;
    struct dirent* e;
    char path[PATH_LEN];

    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return -1;
    d = opendir(dir);
    if (d == NULL)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        if (join_path(path, sizeof(path), dir, e->d_name) == 0)
            (void)unlink(path);
    }
    closedir(d);
    return 0;
}

static int copy_dir(const char* from, const char* to)
{
    DIR* d;
    struct dirent* e;
    char src[PATH_LEN];
    char dst[PATH_LEN];
    char buf[4096];
    size_t n;
    FILE* in;
    FILE* out;

    if (clear_dir(to) != 0)
        return -1;
    d = opendir(from);
    if (d == NULL)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        if (join_path(src, sizeof(src), from, e->d_name) != 0 ||
                join_path(dst, sizeof(dst), to, e->d_name) != 0) {
            closedir(d);
            return -1;
        }
        in = fopen(src, "rb");
        out = fopen(dst, "wb");
        if (in == NULL || out == NULL) {
            if (in != NULL)
                fclose(in);
            if (out != NULL)
                fclose(out);
            closedir(d);
            return -1;
        }
        while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
            (void)fwrite(buf, 1, n, out);
        fclose(in);
        fclose(out);
    }
    closedir(d);
    return 0;
}

/* ---- PKCS#11 helpers ---- */

static CK_RV pkcs11_init(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL)
        return CKR_GENERAL_ERROR;
    rv = func(&funcList);
#else
    rv = C_GetFunctionList(&funcList);
#endif
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

static void pkcs11_final(void)
{
    (void)funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
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

static void obj_label(int idx, char* label, size_t len)
{
    snprintf(label, len, "obj%d", idx);
}

static CK_RV create_obj(CK_SESSION_HANDLE session, int idx,
    CK_OBJECT_HANDLE* obj)
{
    char label[16];
    char value[32];
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;

    obj_label(idx, label, sizeof(label));
    snprintf(value, sizeof(value), "value of object %d", idx);
    if (idx == OBJ_AES) {
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,       &keyClass,       sizeof(keyClass)    },
            { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)     },
            { CKA_TOKEN,       &ckTrue,         sizeof(ckTrue)      },
            { CKA_PRIVATE,     &ckTrue,         sizeof(ckTrue)      },
            { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)     },
            { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)      },
            { CKA_ENCRYPT,     &ckTrue,         sizeof(ckTrue)      },
            { CKA_LABEL,       label,           strlen(label)       },
            { CKA_VALUE,       (void*)aesKey,   sizeof(aesKey)      },
        };
        return funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(tmpl[0]), obj);
    }
    else {
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,       &dataClass,      sizeof(dataClass)   },
            { CKA_TOKEN,       &ckTrue,         sizeof(ckTrue)      },
            { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)     },
            { CKA_MODIFIABLE,  &ckTrue,         sizeof(ckTrue)      },
            { CKA_LABEL,       label,           strlen(label)       },
            { CKA_VALUE,       value,           strlen(value)       },
        };
        return funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(tmpl[0]), obj);
    }
}

/* Find the object with the given label. Returns the number found. */
static int find_label(CK_SESSION_HANDLE session, const char* label,
    CK_OBJECT_HANDLE* obj)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &ckTrue,      sizeof(ckTrue) },
        { CKA_LABEL, (void*)label, strlen(label)  },
    };
    CK_OBJECT_HANDLE found[4];
    CK_ULONG cnt = 0;

    if (funcList->C_FindObjectsInit(session, tmpl, 2) != CKR_OK)
        return -1;
    if (funcList->C_FindObjects(session, found, 4, &cnt) != CKR_OK)
        cnt = 0;
    (void)funcList->C_FindObjectsFinal(session);
    if (cnt > 0)
        *obj = found[0];
    return (int)cnt;
}

static int count_token_objects(CK_SESSION_HANDLE session)
{
    CK_ATTRIBUTE tmpl[] = { { CKA_TOKEN, &ckTrue, sizeof(ckTrue) } };
    CK_OBJECT_HANDLE found[32];
    CK_ULONG cnt = 0;

    if (funcList->C_FindObjectsInit(session, tmpl, 1) != CKR_OK)
        return -1;
    if (funcList->C_FindObjects(session, found, 32, &cnt) != CKR_OK)
        cnt = 0;
    (void)funcList->C_FindObjectsFinal(session);
    return (int)cnt;
}

static int check_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
    const void* exp, CK_ULONG expLen)
{
    byte buf[64];
    CK_ATTRIBUTE attr = { CKA_VALUE, buf, sizeof(buf) };

    if (funcList->C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
        return -1;
    if (attr.ulValueLen != expLen || memcmp(buf, exp, expLen) != 0)
        return -1;
    return 0;
}

/* Create an object and check no other object record was rewritten. */
static int create_checked(CK_SESSION_HANDLE session, int idx,
    CK_OBJECT_HANDLE* obj)
{
    struct file_ent before[MAX_FILES];
    struct file_ent after[MAX_FILES];
    int beforeCnt, afterCnt;
    int i, j;

    CHECK(list_records(STORE_DIR, before, &beforeCnt) == 0, "List records");
    CHECK_RV(create_obj(session, idx, obj), "Create object");
    CHECK(list_records(STORE_DIR, after, &afterCnt) == 0, "List records");
    CHECK(afterCnt > beforeCnt, "Records written for new object");
    for (i = 0; i < beforeCnt; i++) {
        for (j = 0; j < afterCnt; j++) {
            if (strcmp(before[i].name, after[j].name) == 0)
                break;
        }
        CHECK(j < afterCnt, "Record of other object still present");
        CHECK(before[i].ino == after[j].ino,
              "Record of other object not rewritten");
    }
    return 0;
}

/* Reload from what is in storage now, as if power was lost here, and check
 * only records for ids below cnt exist. */
static int reload_from_storage(CK_SESSION_HANDLE session, int cnt)
{
    struct file_ent recs[MAX_FILES];
    int recCnt;
    int i;

    CHECK(copy_dir(STORE_DIR, SNAP_DIR) == 0, "Snapshot store");
    (void)funcList->C_Logout(session);
    (void)funcList->C_CloseSession(session);
    pkcs11_final();
    CHECK(copy_dir(SNAP_DIR, STORE_DIR) == 0, "Restore store");

    CHECK(list_records(STORE_DIR, recs, &recCnt) == 0, "List records");
    for (i = 0; i < recCnt; i++) {
        if (record_id(recs[i].name) >= cnt) {
            fprintf(stderr, "Record left behind: %s\n", recs[i].name);
            CHECK(0, "No records for removed ids");
        }
    }
    CHECK_RV(pkcs11_init(), "Initialize after restore");
    return 0;
}

static int check_data_obj(CK_SESSION_HANDLE session, const char* label,
    int idx)
{
    CK_OBJECT_HANDLE h;
    char value[32];

    CHECK(find_label(session, label, &h) == 1, "Object loaded");
    snprintf(value, sizeof(value), "value of object %d", idx);
    CHECK(check_value(session, h, value, strlen(value)) == 0,
          "Object value loaded");
    return 0;
}

static int partial_store_test(void)
{
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE obj[OBJ_CNT];
    CK_OBJECT_HANDLE h;
    char label[16];
    static const char renamed[] = "obj2-renamed";
    CK_ATTRIBUTE labelAttr = { CKA_LABEL, (void*)renamed,
                               sizeof(renamed) - 1 };
    int i;
    int survivors[] = { 1, 4, OBJ_AES };

    (void)mkdir("./store", 0700);
    CHECK(clear_dir(STORE_DIR) == 0, "Clear store directory");
    CHECK_RV(pkcs11_init(), "Initialize");
    CHECK_RV(provision(), "Provision token");
    CHECK_RV(open_user_session(&session), "Open user session");

    /* Objects 0 to 5, with the AES key (5) newest. */
    for (i = 0; i <= OBJ_AES; i++)
        CHECK(create_checked(session, i, &obj[i]) == 0, "Create object");

    /* Not the newest object: the newest (the AES key) takes its place. */
    CHECK_RV(funcList->C_DestroyObject(session, obj[0]), "Destroy oldest");
    /* Object 4 is now the newest and moves into the place of object 3. */
    CHECK_RV(funcList->C_DestroyObject(session, obj[3]), "Destroy middle");
    /* Newest object: nothing moves. */
    CHECK(create_checked(session, 6, &obj[6]) == 0, "Create object");
    CHECK_RV(funcList->C_DestroyObject(session, obj[6]), "Destroy newest");

    CHECK_RV(funcList->C_SetAttributeValue(session, obj[2], &labelAttr, 1),
             "Rename object");

    /* Only records of the four objects left may exist. */
    CHECK(reload_from_storage(session, 4) == 0, "Reload");
    CHECK_RV(open_user_session(&session), "Open user session");
    CHECK(count_token_objects(session) == 4, "Four objects loaded");

    for (i = 0; i < (int)(sizeof(survivors) / sizeof(survivors[0])); i++) {
        obj_label(survivors[i], label, sizeof(label));
        CHECK(find_label(session, label, &h) == 1, "Object loaded");
        if (survivors[i] == OBJ_AES) {
            CHECK(check_value(session, h, aesKey, sizeof(aesKey)) == 0,
                  "Key value loaded");
        }
        else {
            CHECK(check_data_obj(session, label, survivors[i]) == 0,
                  "Object value loaded");
        }
    }
    CHECK(check_data_obj(session, renamed, 2) == 0, "Renamed object loaded");
    CHECK(find_label(session, "obj2", &h) == 0, "Old label gone");
    for (i = 0; i < OBJ_CNT; i++) {
        if (i == 0 || i == 3 || i == 6) {
            obj_label(i, label, sizeof(label));
            CHECK(find_label(session, label, &h) == 0,
                  "Destroyed object not loaded");
        }
    }

    (void)funcList->C_Logout(session);
    (void)funcList->C_CloseSession(session);
    pkcs11_final();
    return 0;
}

static int pause_resume_test(void)
{
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE obj[5];
    CK_OBJECT_HANDLE h;
    static const char renamed[] = "obj1-renamed";
    CK_ATTRIBUTE labelAttr = { CKA_LABEL, (void*)renamed,
                               sizeof(renamed) - 1 };
    int i;

    CHECK(clear_dir(STORE_DIR) == 0, "Clear store directory");
    CHECK_RV(pkcs11_init(), "Initialize");
    CHECK_RV(provision(), "Provision token");
    CHECK_RV(open_user_session(&session), "Open user session");
    for (i = 0; i <= 2; i++)
        CHECK_RV(create_obj(session, i, &obj[i]), "Create object");

    /* Storage off: these changes are only in memory. */
    CHECK(setenv("WOLFPKCS11_NO_STORE", "1", 1) == 0, "Turn storage off");
    CHECK_RV(funcList->C_DestroyObject(session, obj[0]), "Destroy oldest");
    CHECK_RV(funcList->C_SetAttributeValue(session, obj[1], &labelAttr, 1),
             "Rename object");
    CHECK(find_label(session, renamed, &h) == 1, "Rename is live");
    CHECK_RV(create_obj(session, 3, &obj[3]), "Create object");
    CHECK(unsetenv("WOLFPKCS11_NO_STORE") == 0, "Turn storage on");

    /* The next write catches up with every change made while off. */
    CHECK_RV(create_obj(session, 4, &obj[4]), "Create object");

    CHECK(reload_from_storage(session, 4) == 0, "Reload");
    CHECK_RV(open_user_session(&session), "Open user session");
    CHECK(count_token_objects(session) == 4, "Four objects loaded");
    CHECK(check_data_obj(session, renamed, 1) == 0, "Renamed object");
    CHECK(check_data_obj(session, "obj2", 2) == 0, "Moved object");
    CHECK(check_data_obj(session, "obj3", 3) == 0, "Object made while off");
    CHECK(check_data_obj(session, "obj4", 4) == 0, "Object made after");
    CHECK(find_label(session, "obj0", &h) == 0, "Destroyed object gone");
    CHECK(find_label(session, "obj1", &h) == 0, "Old label gone");

    (void)funcList->C_Logout(session);
    (void)funcList->C_CloseSession(session);
    pkcs11_final();
    return 0;
}

#endif /* RUN_TEST */

int main(int argc, char* argv[])
{
#ifdef RUN_TEST
    int ret;

    (void)argc;
    (void)argv;
    /* The test empties the store directory, so always use its own. */
    XSETENV("WOLFPKCS11_TOKEN_PATH", STORE_DIR, 1);

    printf("Token partial store test\n");
    ret = partial_store_test();
    if (ret == 0) {
        printf("Token pause and resume test\n");
        ret = pause_resume_test();
    }
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
