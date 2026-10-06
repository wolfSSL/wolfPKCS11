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
static byte dataValue[] = "stored data object value";

static const char* storeKinds[] = {
    "obj", "data", "symmkey", "rsakey_priv", "rsakey_pub", "ecckey_priv",
    "ecckey_pub", "dhkey_priv", "dhkey_pub", "cert", "trust"
};

#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
#define HAVE_ALLOC_TRACKING
#define ALLOC_REFUSE_SZ ((size_t)64 * 1024 * 1024)

#define TRACK_HDR_SZ    16

static size_t largestAlloc = 0;
/* Live bytes in blocks no larger than peakCap, and their peak. */
static size_t peakCap = 0;
static size_t liveBytes = 0;
static size_t peakLive = 0;

static void* track_malloc(size_t sz)
{
    unsigned char* p;

    if (sz > largestAlloc)
        largestAlloc = sz;
    if (sz >= ALLOC_REFUSE_SZ)
        return NULL;
    p = (unsigned char*)malloc(sz + TRACK_HDR_SZ);
    if (p == NULL)
        return NULL;
    XMEMCPY(p, &sz, sizeof(sz));
    if (sz <= peakCap) {
        liveBytes += sz;
        if (liveBytes > peakLive)
            peakLive = liveBytes;
    }
    return p + TRACK_HDR_SZ;
}

static void track_free(void* ptr)
{
    unsigned char* p;
    size_t sz;

    if (ptr == NULL)
        return;
    p = (unsigned char*)ptr - TRACK_HDR_SZ;
    XMEMCPY(&sz, p, sizeof(sz));
    if (sz <= peakCap)
        liveBytes -= sz;
    free(p);
}

static void* track_realloc(void* ptr, size_t sz)
{
    void* n;
    size_t old;

    if (ptr == NULL)
        return track_malloc(sz);
    if (sz == 0) {
        track_free(ptr);
        return NULL;
    }
    n = track_malloc(sz);
    if (n == NULL)
        return NULL;
    XMEMCPY(&old, (unsigned char*)ptr - TRACK_HDR_SZ, sizeof(old));
    XMEMCPY(n, ptr, (old < sz) ? old : sz);
    track_free(ptr);
    return n;
}
#endif

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
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,       &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE,     &ckFalse,   sizeof(ckFalse)   },
        { CKA_APPLICATION, app,        sizeof(app) - 1   },
        { CKA_VALUE,       dataValue,  sizeof(dataValue) - 1 },
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

static int truncate_file(const char* path, size_t keep)
{
    static byte data[MAX_FILE_SZ];
    size_t sz = 0;

    if (read_file(path, data, sizeof(data), &sz) != 0 || sz <= keep)
        return -1;
    return write_file(path, data, keep);
}

/* Either the token refuses to load or the data object reads back its full
 * stored value. */
static int child_data_value_intact(void)
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
    byte value[64];
    CK_ATTRIBUTE attr = { CKA_VALUE, value, sizeof(value) };
    int res = CHILD_FAIL;

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
        rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    if (rv == CKR_OK && count == 1 &&
            attr.ulValueLen == sizeof(dataValue) - 1 &&
            XMEMCMP(value, dataValue, sizeof(dataValue) - 1) == 0) {
        res = CHILD_PASS;
    }
    (void)funcList->C_Finalize(NULL);
    return res;
}

static void test_truncated_data_record(void)
{
    CK_RV rv;
    char path[256];
    int res = CHILD_SETUP;

    printf("\n--- truncated data object record is not loaded ---\n");
    rv = store_objects(create_data_object);
    CHECK_RV(rv, "store data object", CKR_OK);
    if (rv != CKR_OK)
        return;
    if (find_store_file("data", path, sizeof(path)) == 0 &&
            truncate_file(path, 2) == 0) {
        res = run_in_child(child_data_value_intact);
    }
    CHECK_TRUE(res == CHILD_PASS, "truncated data object record is rejected");
    cleanup_test_files();
}

#define LARGE_VALUE_SZ  300001
static byte largeValue[LARGE_VALUE_SZ];
static byte largeRead[LARGE_VALUE_SZ];

static CK_RV create_large_data_object(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
        { CKA_VALUE,   largeValue, sizeof(largeValue) },
    };
    size_t i;

    for (i = 0; i < sizeof(largeValue); i++)
        largeValue[i] = (byte)(i * 7 + (i >> 8));
    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
}

static void test_large_stored_value_round_trip(void)
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
    CK_ATTRIBUTE value = { CKA_VALUE, largeRead, sizeof(largeRead) };

    printf("\n--- large stored value reloads intact ---\n");
    rv = store_objects(create_large_data_object);
    CHECK_RV(rv, "store large data object", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = pkcs11_load();
    if (rv == CKR_OK) {
        rv = init_slot(&slot);
        if (rv == CKR_OK)
            rv = open_session(slot, 0, &session);
        if (rv == CKR_OK)
            rv = funcList->C_FindObjectsInit(session, findTmpl, 1);
        if (rv == CKR_OK)
            rv = funcList->C_FindObjects(session, &obj, 1, &count);
        if (rv == CKR_OK)
            rv = funcList->C_FindObjectsFinal(session);
        if (rv == CKR_OK && count != 1)
            rv = CKR_GENERAL_ERROR;
        if (rv == CKR_OK)
            rv = funcList->C_GetAttributeValue(session, obj, &value, 1);
        (void)funcList->C_Finalize(NULL);
        pkcs11_unload();
    }
    CHECK_RV(rv, "reload large data object", CKR_OK);
    CHECK_TRUE(rv == CKR_OK && value.ulValueLen == sizeof(largeValue) &&
               XMEMCMP(largeRead, largeValue, sizeof(largeValue)) == 0,
               "large stored value is unchanged after reload");
    cleanup_test_files();
}

#ifdef HAVE_ALLOC_TRACKING
/* Loading must not size an allocation from a length the data cannot back. */
static int child_load_allocation_bound(void)
{
    CK_SLOT_ID slot = 0;

    if (wolfSSL_SetAllocators(track_malloc, track_free, track_realloc) != 0)
        return CHILD_SETUP;
    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    if (init_slot(&slot) == CKR_OK)
        (void)funcList->C_Finalize(NULL);
    if (largestAlloc >= ALLOC_REFUSE_SZ) {
        fprintf(stderr, "  largest allocation while loading: %lu\n",
                (unsigned long)largestAlloc);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static void test_oversized_attribute_length(void)
{
    CK_RV rv;
    char path[256];
    int res = CHILD_SETUP;

    printf("\n--- stored attribute length must be bounded ---\n");
    rv = store_objects(create_data_object);
    CHECK_RV(rv, "store data object", CKR_OK);
    if (rv != CKR_OK)
        return;
    if (find_store_file("obj", path, sizeof(path)) == 0 &&
            patch_length(path, OBJ_LABEL_LEN_OFF, 0, 0x7FFFFFF8UL) == 0) {
        res = run_in_child(child_load_allocation_bound);
    }
    CHECK_TRUE(res == CHILD_PASS,
               "oversized stored attribute length is not allocated");
    cleanup_test_files();
}

/* Loading a large stored value holds about one copy of it, not two. Larger
 * blocks cannot be partial copies of it, so they are not counted. */
static int child_large_value_peak(void)
{
    CK_SLOT_ID slot = 0;

    peakCap = LARGE_VALUE_SZ;
    if (wolfSSL_SetAllocators(track_malloc, track_free, track_realloc) != 0)
        return CHILD_SETUP;
    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    if (init_slot(&slot) == CKR_OK)
        (void)funcList->C_Finalize(NULL);
    if (peakLive >= (size_t)LARGE_VALUE_SZ + LARGE_VALUE_SZ / 2) {
        fprintf(stderr, "  peak live bytes while loading: %lu\n",
                (unsigned long)peakLive);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static void test_large_stored_value_peak(void)
{
    CK_RV rv;
    int res;

    printf("\n--- large stored value loads without a second copy ---\n");
    rv = store_objects(create_large_data_object);
    CHECK_RV(rv, "store large data object", CKR_OK);
    if (rv != CKR_OK)
        return;
    res = run_in_child(child_large_value_peak);
    CHECK_TRUE(res == CHILD_PASS,
               "peak memory while loading stays near one copy");
    cleanup_test_files();
}
#endif

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);

    printf("=== wolfPKCS11 stored object decode test ===\n");
    test_negative_optional_length();
    test_negative_attribute_length();
#ifdef HAVE_ALLOC_TRACKING
    test_oversized_attribute_length();
#endif
    test_large_stored_value_round_trip();
#ifdef HAVE_ALLOC_TRACKING
    test_large_stored_value_peak();
#endif
    test_truncated_data_record();

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
