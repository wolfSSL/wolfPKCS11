/* token_pub_key_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * Tests that token keys with CKA_PRIVATE false are usable by the user and the
 * SO, across PIN changes and from token stores of older releases.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <time.h>

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

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && !defined(WOLFPKCS11_NO_STORE)

#define TEST_DIR "." PATH_SEP "store" PATH_SEP "token_pub_key_test"
#define MAX_TEST_OBJS 16

#if defined(DEBUG_WOLFPKCS11) && !defined(_WIN32) && \
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_TPM_STORE)
    #define TEST_LEGACY_STORE
#ifdef __cplusplus
extern "C" {
#endif
extern void WP11_Test_StoreLegacyFormat(int on);
extern void WP11_Test_StoreCloseFailAfter(int closes);
#ifdef __cplusplus
}
#endif
#endif

static byte soPin[] = "password123456";
static byte soPin2[] = "so-rotated-5678";
static byte userPin[] = "wolfpkcs11-test";
static byte userPin2[] = "user-reset-1234";
static byte userPin3[] = "user-rotated-90";
static byte pubId[] = "pub-aes";
static byte privId[] = "priv-aes";

static byte aesValue[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
};

static void cleanup_test_files(void)
{
    static const char* prefixes[] = { "wp11_obj", "wp11_symmkey" };
    char name[160];
    size_t p;
    int i;

    for (p = 0; p < sizeof(prefixes) / sizeof(*prefixes); p++) {
        for (i = 0; i < MAX_TEST_OBJS; i++) {
            XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "%s_%016lx_%016lx",
                      TEST_DIR, prefixes[p], 1UL, (unsigned long)i);
            (void)remove(name);
        }
    }
    XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "wp11_token_%016lx",
              TEST_DIR, 1UL);
    (void)remove(name);
}

/* Load library and initialize, simulating a fresh process. */
static CK_RV restart(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slots[16];
    CK_ULONG count = sizeof(slots) / sizeof(*slots);

    rv = pkcs11_load();
    if (rv == CKR_OK) {
        XMEMSET(&args, 0, sizeof(args));
        args.flags = CKF_OS_LOCKING_OK;
        rv = funcList->C_Initialize(&args);
    }
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slots, &count);
    if (rv == CKR_OK && count == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK)
        *slot = slots[0];
    return rv;
}

static void shutdown_lib(CK_SESSION_HANDLE session)
{
    if (session != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(session);
    (void)funcList->C_Finalize(NULL);
    pkcs11_unload();
}

static CK_RV open_session(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    return funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                   NULL, NULL, session);
}

static CK_RV login(CK_SESSION_HANDLE session, CK_USER_TYPE type, byte* pin)
{
    return funcList->C_Login(session, type, pin, (CK_ULONG)XSTRLEN((char*)pin));
}

static CK_RV provision(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_UTF8CHAR label[32];
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }
    return rv;
}

static CK_RV create_aes_key(CK_SESSION_HANDLE session, CK_BBOOL isPrivate,
                            byte* id, CK_OBJECT_HANDLE* key)
{
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,       &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,     &isPrivate,   sizeof(isPrivate)   },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_ENCRYPT,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,       aesValue,     sizeof(aesValue)    },
        { CKA_ID,          id,           0                   },
    };

    tmpl[8].ulValueLen = (CK_ULONG)XSTRLEN((char*)id);
    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), key);
}

static CK_RV find_key(CK_SESSION_HANDLE session, byte* id,
                      CK_OBJECT_HANDLE* key)
{
    CK_RV rv;
    CK_ULONG count = 0;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_ID, id, 0 },
    };

    findTmpl[0].ulValueLen = (CK_ULONG)XSTRLEN((char*)id);
    rv = funcList->C_FindObjectsInit(session, findTmpl, 1);
    if (rv == CKR_OK)
        rv = funcList->C_FindObjects(session, key, 1, &count);
    if (rv == CKR_OK)
        rv = funcList->C_FindObjectsFinal(session);
    if (rv == CKR_OK && count != 1)
        rv = CKR_GENERAL_ERROR;
    return rv;
}

/* The key is found and its value reads back. */
static CK_RV check_aes_key(CK_SESSION_HANDLE session, byte* id)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte value[sizeof(aesValue)];
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_VALUE, value, sizeof(value) },
    };

    rv = find_key(session, id, &key);
    if (rv == CKR_OK)
        rv = funcList->C_GetAttributeValue(session, key, getTmpl, 1);
    if (rv == CKR_OK && (getTmpl[0].ulValueLen != sizeof(aesValue) ||
            XMEMCMP(value, aesValue, sizeof(aesValue)) != 0)) {
        rv = CKR_GENERAL_ERROR;
    }
    return rv;
}

/* The SO creates and uses public token keys; the user uses them too. */
static void test_so_public_keys(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- SO creates public token keys ---\n");
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    CHECK_RV(rv, "provision token", CKR_OK);
    shutdown_lib(CK_INVALID_HANDLE);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    CHECK_RV(rv, "SO login", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_RV(create_aes_key(session, CK_FALSE, pubId, &key),
                 "SO creates public token key", CKR_OK);
        CHECK_RV(create_aes_key(session, CK_TRUE, privId, &key),
                 "SO creates private token key", CKR_USER_NOT_LOGGED_IN);
        CHECK_RV(check_aes_key(session, pubId), "SO uses public key", CKR_OK);
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "user uses public key the SO created", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "SO uses public key after restart", CKR_OK);
    shutdown_lib(session);
}

/* Public keys stay usable when the SO resets the user PIN, the SO changes
 * its PIN and the user changes the PIN. */
static void test_public_keys_survive_pin_changes(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- public keys survive PIN changes ---\n");
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "user creates public token key", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin2, sizeof(userPin2) - 1);
    CHECK_RV(rv, "SO resets the user PIN", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, soPin, sizeof(soPin) - 1, soPin2,
                                sizeof(soPin2) - 1);
        CHECK_RV(rv, "SO changes its PIN", CKR_OK);
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin2);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "public key usable with the reset user PIN", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, userPin2, sizeof(userPin2) - 1,
                                userPin3, sizeof(userPin3) - 1);
        CHECK_RV(rv, "user changes the PIN", CKR_OK);
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin3);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "public key usable with the changed user PIN", CKR_OK);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin2);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "public key usable with the changed SO PIN", CKR_OK);
    shutdown_lib(session);
}

/* An SO logout ends operations on public keys when no user key is loaded. */
static void test_so_logout_ends_ops(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE opSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte iv[16];
    byte in[16];
    byte out[32];
    CK_ULONG outLen = sizeof(out);
    CK_MECHANISM mech = { CKM_AES_CBC, NULL, 0 };

    printf("--- SO logout ends operations on public keys ---\n");
    XMEMSET(iv, 0, sizeof(iv));
    XMEMSET(in, 0x5a, sizeof(in));
    mech.pParameter = iv;
    mech.ulParameterLen = sizeof(iv);
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    CHECK_RV(rv, "provision token", CKR_OK);
    shutdown_lib(CK_INVALID_HANDLE);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = open_session(slot, &opSession);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    if (rv == CKR_OK)
        rv = funcList->C_EncryptInit(opSession, &mech, key);
    if (rv == CKR_OK) {
        rv = funcList->C_EncryptUpdate(opSession, in, sizeof(in), out,
                                       &outLen);
    }
    CHECK_RV(rv, "encryption started under the SO", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_RV(funcList->C_Logout(session), "SO logout", CKR_OK);
        outLen = sizeof(out);
        CHECK_RV(funcList->C_EncryptUpdate(opSession, in, sizeof(in), out,
                                           &outLen),
                 "encryption ended by the SO logout",
                 CKR_OPERATION_NOT_INITIALIZED);
    }
    if (opSession != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(opSession);
    shutdown_lib(session);
}

#ifdef TEST_LEGACY_STORE
static long read_file(const char* name, byte* buf, size_t bufSz)
{
    FILE* f;
    long len;

    f = fopen(name, "rb");
    if (f == NULL)
        return -1;
    len = (long)fread(buf, 1, bufSz, f);
    fclose(f);
    return len;
}

static long get_be32(const byte* p)
{
    return ((long)p[0] << 24) | ((long)p[1] << 16) | ((long)p[2] << 8) |
        (long)p[3];
}

/* Public-object key bits of the token flags in the token record. */
static int token_pub_flags(void)
{
    char name[160];
    byte rec[1024];
    long len;
    long off = 32;
    int i;

    XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "wp11_token_%016lx",
              TEST_DIR, 1UL);
    len = read_file(name, rec, sizeof(rec));
    /* Label, then PIN hash, seed, failure count and times of SO and user. */
    for (i = 0; i < 2; i++) {
        if (off + 4 > len)
            return -1;
        off += 4 + get_be32(rec + off) + 16 + 4 + 2 * (long)sizeof(time_t);
    }
    /* Token key seed, then the object types. */
    off += 16;
    if (off + 4 > len)
        return -1;
    off += 4 + get_be32(rec + off) * (long)sizeof(CK_ULONG);
    if (off + 4 > len)
        return -1;
    return rec[off + 3] & 0x1c;
}

/* Record flag word bit marking key data under the public-object key. */
static int object_pub_bit(int objId)
{
    char name[160];
    byte rec[256];
    long len;
    long off = 12 + 3 * (long)sizeof(CK_ULONG) + 2;

    XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "wp11_obj_%016lx_%016lx",
              TEST_DIR, 1UL, (unsigned long)objId);
    len = read_file(name, rec, sizeof(rec));
    if (len < off + 4)
        return -1;
    return (rec[off] & 0x40) != 0;
}

/* A store from before the public-object key loads, and its public keys move
 * to the public-object key at the user's login, the token record first. */
static void test_legacy_store_migrates(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- store from an older release migrates ---\n");
    cleanup_test_files();
    WP11_Test_StoreLegacyFormat(1);
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "store public key in the old format", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    WP11_Test_StoreLegacyFormat(0);
    if (rv != CKR_OK)
        return;
    CHECK_TRUE(token_pub_flags() == 0, "token record has no key copies");
    CHECK_TRUE(object_pub_bit(0) == 0, "key record is under the token key");

    rv = restart(&slot);
    CHECK_RV(rv, "old format token record loads", CKR_OK);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    CHECK_RV(rv, "SO login on old format token", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(check_aes_key(session, pubId) != CKR_OK,
                   "SO has no public-object key before the user migrates");
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    /* Fail the migration's second store pass; the first makes two closes. */
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(2);
        rv = login(session, CKU_USER, userPin);
        WP11_Test_StoreCloseFailAfter(-1);
    }
    CHECK_RV(rv, "user login with the key move failing", CKR_OK);
    CHECK_TRUE(token_pub_flags() == 0x0c,
               "token record with the user copy stored first");
    CHECK_TRUE(object_pub_bit(0) == 0, "key record not moved yet");
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "public key usable after the next login", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    CHECK_TRUE(object_pub_bit(0) == 1, "key record moved");

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "moved public key usable after restart", CKR_OK);
    shutdown_lib(session);
}
#endif

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 public-object key test ===\n");
    test_so_public_keys();
    test_public_keys_survive_pin_changes();
    test_so_logout_ends_ops();
#ifdef TEST_LEGACY_STORE
    test_legacy_store_migrates();
#endif
    cleanup_test_files();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("AES-CBC or token store not available, skipping test\n");
    return 77;
}

#endif
