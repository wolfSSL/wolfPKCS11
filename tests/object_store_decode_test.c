/* object_store_decode_test.c
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
 * Stored token objects whose recorded lengths do not describe valid data must
 * be rejected cleanly when the token is loaded or logged into. Each reload runs
 * in a child process so a failure is reported instead of ending the test.
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
    !defined(_WIN32)

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_DIR        "./store/object_store_decode_test"
#define MAX_OBJ_ID      8
#define MAX_FILE_SZ     16384

/* Offset of the first variable-length attribute in a stored object record. */
#define OBJ_ID_LEN_OFF  (12 + 3 * sizeof(CK_ULONG) + 1 + 1 + 4 + 4 + 8 + 8)
#define OBJ_LABEL_LEN_OFF (OBJ_ID_LEN_OFF + 4)
#define OBJ_ISSUER_LEN_OFF (OBJ_LABEL_LEN_OFF + 4)

#define CHILD_PASS      0
#define CHILD_FAIL      1
#define CHILD_SETUP     2

static byte soPin[] = "password123456";
static byte userPin[] = "wolfpkcs11-test";
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static const char* storeKinds[] = {
    "obj", "data", "symmkey", "rsakey_priv", "rsakey_pub", "ecckey_priv",
    "ecckey_pub", "dhkey_priv", "dhkey_pub", "cert", "trust"
};

static void store_path(char* path, size_t sz, const char* kind, int objId)
{
    if (objId < 0) {
        (void)snprintf(path, sz, "%s/wp11_%s_%016lx", TEST_DIR, kind, 1UL);
    }
    else {
        (void)snprintf(path, sz, "%s/wp11_%s_%016lx_%016lx", TEST_DIR, kind,
                       1UL, (unsigned long)objId);
    }
}

static void cleanup_test_files(void)
{
    char path[256];
    size_t k;
    int i;

    for (k = 0; k < sizeof(storeKinds) / sizeof(*storeKinds); k++) {
        for (i = 0; i < MAX_OBJ_ID; i++) {
            store_path(path, sizeof(path), storeKinds[k], i);
            (void)remove(path);
        }
    }
    store_path(path, sizeof(path), "token", -1);
    (void)remove(path);
}

/* Locate the stored file of the given kind for the single object of that kind. */
static int find_store_file(const char* kind, char* path, size_t sz)
{
    FILE* f;
    int i;

    for (i = 0; i < MAX_OBJ_ID; i++) {
        store_path(path, sz, kind, i);
        f = fopen(path, "rb");
        if (f != NULL) {
            fclose(f);
            return 0;
        }
    }
    return -1;
}

static int read_file(const char* path, byte* data, size_t sz, size_t* readSz)
{
    FILE* f = fopen(path, "rb");

    if (f == NULL)
        return -1;
    *readSz = fread(data, 1, sz, f);
    if (ferror(f) || !feof(f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int write_file(const char* path, const byte* data, size_t sz)
{
    FILE* f = fopen(path, "wb");
    size_t written;

    if (f == NULL)
        return -1;
    written = fwrite(data, 1, sz, f);
    if (fclose(f) != 0 || written != sz)
        return -1;
    return 0;
}

static word32 get_be32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16) |
           ((word32)p[2] << 8) | (word32)p[3];
}

static void put_be32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)v;
}

/* Overwrite a 4-byte length field that is expected to hold 'expect'. */
static int patch_length(const char* path, size_t off, word32 expect,
                        word32 value)
{
    static byte data[MAX_FILE_SZ];
    size_t sz = 0;

    if (read_file(path, data, sizeof(data), &sz) != 0 || sz < off + 4)
        return -1;
    if (get_be32(data + off) != expect)
        return -1;
    put_be32(data + off, value);
    return write_file(path, data, sz);
}

static CK_RV init_slot(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slots[16];
    CK_ULONG count = sizeof(slots) / sizeof(*slots);

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slots, &count);
    if (rv == CKR_OK && count == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK)
        *slot = slots[0];
    return rv;
}

static CK_RV provision_token(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_UTF8CHAR label[32];
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    if (rv == CKR_OK)
        rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }
    return rv;
}

static CK_RV open_session(CK_SLOT_ID slot, int login,
                          CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    rv = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    if (rv == CKR_OK && login) {
        rv = funcList->C_Login(*session, CKU_USER, userPin,
                               sizeof(userPin) - 1);
    }
    return rv;
}

typedef CK_RV (*create_fn)(CK_SESSION_HANDLE session);

/* Provision a fresh token, create objects with 'create' and persist them. */
static CK_RV store_objects(create_fn create)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    cleanup_test_files();
    rv = pkcs11_load();
    if (rv != CKR_OK)
        return rv;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = provision_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = create(session);
    if (session != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(session);
    (void)funcList->C_Finalize(NULL);
    pkcs11_unload();
    return rv;
}

typedef int (*child_fn)(void);

/* Run fn in a child process. Returns CHILD_PASS only when it exits normally
 * reporting that the invariant held. */
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
        int res = fn();
        fflush(stdout);
        fflush(stderr);
        _exit(res);
    }
    if (waitpid(pid, &status, 0) != pid)
        return CHILD_SETUP;
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "  reload terminated by signal %d\n",
                WTERMSIG(status));
        return CHILD_FAIL;
    }
    if (!WIFEXITED(status))
        return CHILD_FAIL;
    return WEXITSTATUS(status);
}

static CK_RV create_data_object(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte app[] = "wolfpkcs11";
    static byte value[] = "stored data object value";
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,       &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE,     &ckFalse,   sizeof(ckFalse)   },
        { CKA_APPLICATION, app,        sizeof(app) - 1   },
        { CKA_VALUE,       value,      sizeof(value) - 1 },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
}

/* Either the token refuses to load or the data object reports a real label
 * length. */
static int child_data_label_length(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
    };
    CK_ATTRIBUTE label = { CKA_LABEL, NULL, 0 };
    int res = CHILD_SETUP;

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv != CKR_OK)
        return CHILD_PASS;

    rv = open_session(slot, 0, &session);
    if (rv == CKR_OK)
        rv = funcList->C_FindObjectsInit(session, findTmpl, 1);
    if (rv == CKR_OK)
        rv = funcList->C_FindObjects(session, &obj, 1, &count);
    if (rv == CKR_OK)
        rv = funcList->C_FindObjectsFinal(session);
    if (rv == CKR_OK && count == 1)
        rv = funcList->C_GetAttributeValue(session, obj, &label, 1);
    if (rv == CKR_OK && count == 1) {
        res = (label.ulValueLen == CK_UNAVAILABLE_INFORMATION ||
               label.ulValueLen > 64) ? CHILD_FAIL : CHILD_PASS;
        if (res != CHILD_PASS) {
            fprintf(stderr, "  loaded label length 0x%lx\n",
                    (unsigned long)label.ulValueLen);
        }
    }
    (void)funcList->C_Finalize(NULL);
    return res;
}

/* A negative length must not pass as the end of an older record format. */
static int child_token_not_loaded(void)
{
    CK_SLOT_ID slot = 0;
    int res;

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    res = (init_slot(&slot) != CKR_OK) ? CHILD_PASS : CHILD_FAIL;
    (void)funcList->C_Finalize(NULL);
    return res;
}

static void test_negative_optional_length(void)
{
    CK_RV rv;
    char path[256];
    int res = CHILD_SETUP;

    printf("\n--- stored issuer length must not be negative ---\n");
    rv = store_objects(create_data_object);
    CHECK_RV(rv, "store data object", CKR_OK);
    if (rv != CKR_OK)
        return;
    if (find_store_file("obj", path, sizeof(path)) == 0 &&
            patch_length(path, OBJ_ISSUER_LEN_OFF, 0, 0xFFFFFFFFUL) == 0) {
        res = run_in_child(child_token_not_loaded);
    }
    CHECK_TRUE(res == CHILD_PASS,
               "negative stored issuer length is not loaded");
    cleanup_test_files();
}

static void test_negative_attribute_length(void)
{
    CK_RV rv;
    char path[256];
    int res = CHILD_SETUP;

    printf("\n--- stored attribute length must not be negative ---\n");
    rv = store_objects(create_data_object);
    CHECK_RV(rv, "store data object", CKR_OK);
    if (rv != CKR_OK)
        return;
    if (find_store_file("obj", path, sizeof(path)) == 0 &&
            patch_length(path, OBJ_LABEL_LEN_OFF, 0, 0xFFFFFFFFUL) == 0) {
        res = run_in_child(child_data_label_length);
    }
    CHECK_TRUE(res == CHILD_PASS,
               "negative stored attribute length is not loaded");
    cleanup_test_files();
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);

    printf("=== wolfPKCS11 stored object decode test ===\n");
    test_negative_optional_length();
    test_negative_attribute_length();

    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("File-backed token storage not available, skipping test\n");
    return 77;
}

#endif
