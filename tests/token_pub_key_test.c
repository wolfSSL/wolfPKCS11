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

#if !defined(NO_AES) && !defined(WOLFPKCS11_NO_STORE)

#define TEST_DIR "." PATH_SEP "store" PATH_SEP "token_pub_key_test"
#define MAX_TEST_OBJS 16

#if !defined(_WIN32) && !defined(WOLFPKCS11_CUSTOM_STORE) && \
    !defined(WOLFPKCS11_TPM_STORE) && !defined(WOLFPKCS11_NO_ENV)
    #define TEST_FILE_STORE
    #include <unistd.h>
    #include <sys/wait.h>
#endif

#if defined(DEBUG_WOLFPKCS11) && defined(TEST_FILE_STORE)
    #define TEST_LEGACY_STORE
#endif
#ifdef DEBUG_WOLFPKCS11
#ifdef __cplusplus
extern "C" {
#endif
#ifdef TEST_LEGACY_STORE
extern void WP11_Test_StoreLegacyFormat(int on);
extern void WP11_Test_StoreCloseFailAfter(int closes);
#endif
extern void WP11_Slot_SetPinCheckHook(void (*hook)(void));
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
    static const char* prefixes[] = { "wp11_obj", "wp11_symmkey", "wp11_data" };
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

static CK_RV init_token(CK_SLOT_ID slot)
{
    CK_UTF8CHAR label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    return funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
}

static CK_RV provision(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = init_token(slot);
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

#if defined(TEST_LEGACY_STORE) || \
    (defined(TEST_FILE_STORE) && defined(HAVE_AES_CBC))
static CK_RV create_data_object(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)    },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
        { CKA_VALUE,   pubId,      sizeof(pubId) - 1 },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
}
#endif

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
    /* A TPM store keeps the token, and C_InitToken needs the SO PIN. */
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, soPin2, sizeof(soPin2) - 1, soPin,
                                sizeof(soPin) - 1);
        CHECK_RV(rv, "SO changes its PIN back", CKR_OK);
    }
    shutdown_lib(session);
}

#ifdef HAVE_AES_CBC
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
#endif

#ifdef HAVE_AES_CBC
static byte newPin[] = "newpin1234567890";

/* Initialize the token with an empty user PIN. */
static CK_RV empty_pin_token(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = init_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)"", 0);
    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }
    return rv;
}

static CK_RV encrypt_start(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_RV rv;
    static byte iv[16];
    byte in[16];
    byte out[32];
    CK_ULONG outLen = sizeof(out);
    CK_MECHANISM mech = { CKM_AES_CBC, iv, sizeof(iv) };

    XMEMSET(in, 0x5a, sizeof(in));
    rv = funcList->C_EncryptInit(session, &mech, key);
    if (rv == CKR_OK)
        rv = funcList->C_EncryptUpdate(session, in, sizeof(in), out, &outLen);
    return rv;
}

static CK_RV encrypt_more(CK_SESSION_HANDLE session)
{
    byte in[16];
    byte out[32];
    CK_ULONG outLen = sizeof(out);

    XMEMSET(in, 0x5a, sizeof(in));
    return funcList->C_EncryptUpdate(session, in, sizeof(in), out, &outLen);
}

/* A public session C_SetPIN that gives an empty user PIN a value ends the
 * operations on public keys, destroyed ones included. */
static void test_set_pin_ends_ops(int destroy)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE opSession = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;

    printf("--- public C_SetPIN ends operations%s ---\n",
           destroy ? " on a destroyed key" : "");
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = empty_pin_token(slot);
    if (rv == CKR_PIN_LEN_RANGE) {
        printf("SKIP: empty user PIN not allowed\n");
        shutdown_lib(CK_INVALID_HANDLE);
        return;
    }
    if (rv == CKR_OK)
        rv = open_session(slot, &opSession);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_aes_key(opSession, CK_FALSE, pubId, &key);
    if (rv == CKR_OK)
        rv = encrypt_start(opSession, key);
    if (rv == CKR_OK && destroy)
        rv = funcList->C_DestroyObject(session, key);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, (CK_UTF8CHAR_PTR)"", 0, newPin,
                                sizeof(newPin) - 1);
    }
    CHECK_RV(rv, "encryption started and user PIN set", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_RV(encrypt_more(opSession), "encryption ended by C_SetPIN",
                 CKR_OPERATION_NOT_INITIALIZED);
    }
    if (opSession != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(opSession);
    shutdown_lib(session);
}

#ifdef TEST_FILE_STORE
/* A reload that drops the empty PIN's key ends an operation on a destroyed
 * public key. */
static void test_reload_ends_destroyed_op(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE opSession = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE other = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_C_INITIALIZE_ARGS args;
    pid_t pid;
    int status = 0;

    printf("--- reload ends an operation on a destroyed key ---\n");
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = empty_pin_token(slot);
    if (rv == CKR_PIN_LEN_RANGE) {
        printf("SKIP: empty user PIN not allowed\n");
        shutdown_lib(CK_INVALID_HANDLE);
        return;
    }
    if (rv == CKR_OK)
        rv = open_session(slot, &opSession);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_aes_key(opSession, CK_FALSE, pubId, &key);
    if (rv == CKR_OK)
        rv = encrypt_start(opSession, key);
    if (rv == CKR_OK)
        rv = funcList->C_DestroyObject(session, key);
    if (rv == CKR_OK) {
        pid = fork();
        if (pid == 0) {
            (void)funcList->C_Finalize(NULL);
            XMEMSET(&args, 0, sizeof(args));
            args.flags = CKF_OS_LOCKING_OK;
            if (funcList->C_Initialize(&args) != CKR_OK ||
                    open_session(slot, &other) != CKR_OK ||
                    funcList->C_SetPIN(other, (CK_UTF8CHAR_PTR)"", 0, newPin,
                                       sizeof(newPin) - 1) != CKR_OK) {
                _exit(1);
            }
            (void)funcList->C_Finalize(NULL);
            _exit(0);
        }
        if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0) {
            rv = CKR_GENERAL_ERROR;
        }
    }
    CHECK_RV(rv, "other process sets the user PIN", CKR_OK);
    if (rv == CKR_OK)
        rv = create_data_object(session);
    CHECK_RV(rv, "token loaded again", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_RV(encrypt_more(opSession), "encryption ended by the reload",
                 CKR_OPERATION_NOT_INITIALIZED);
    }
    if (opSession != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(opSession);
    shutdown_lib(session);
}
#endif
#endif

/* An SO logout after an SO C_InitPIN drops the keys again, so a public
 * session neither uses nor creates public token keys. */
static void test_so_logout_after_init_pin(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- SO logout after C_InitPIN drops the keys ---\n");
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &pub);
    CHECK_RV(rv, "provision token", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_RV(create_aes_key(pub, CK_FALSE, privId, &key),
                 "no public token key without login after provisioning",
                 CKR_USER_NOT_LOGGED_IN);
        rv = open_session(slot, &session);
    }
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin2, sizeof(userPin2) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    CHECK_RV(rv, "SO resets the user PIN and logs out", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(check_aes_key(pub, pubId) != CKR_OK,
                   "public key not usable without login");
        CHECK_RV(create_aes_key(pub, CK_FALSE, privId, &key),
                 "no public token key without login",
                 CKR_USER_NOT_LOGGED_IN);
    }
    if (pub != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(pub);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin2);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "public key usable with the reset user PIN", CKR_OK);
    shutdown_lib(session);
}

#ifdef HAVE_AES_KEYWRAP
/* A public token key loaded without a login is not decoded, so wrapping with
 * it, digesting it and using it as an HKDF salt key are refused. */
static void test_undecoded_token_key(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE tokenKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { CKM_AES_KEY_WRAP, NULL, 0 };
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    byte wrapped[40];
    byte keyData[16];
    CK_ULONG wrappedLen;
    static byte wrapId[] = "undecoded-token-key";
    CK_ATTRIBUTE tokenKeyTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &aesType,     sizeof(aesType)     },
        { CKA_VALUE,       aesValue,     sizeof(aesValue)    },
        { CKA_WRAP,        &ckTrue,      sizeof(ckTrue)      },
        { CKA_DERIVE,      &ckTrue,      sizeof(ckTrue)      },
        { CKA_TOKEN,       &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_ID,          wrapId,       sizeof(wrapId) - 1  },
    };
    CK_ATTRIBUTE keyTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_VALUE,       keyData,      sizeof(keyData)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_DERIVE,      &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
    };

    printf("--- public token key not decoded without login ---\n");
    XMEMSET(keyData, 0x55, sizeof(keyData));
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, tokenKeyTmpl,
            sizeof(tokenKeyTmpl) / sizeof(*tokenKeyTmpl), &tokenKey);
    }
    CHECK_RV(rv, "user creates public AES token key", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = find_key(session, wrapId, &tokenKey);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, keyTmpl,
            sizeof(keyTmpl) / sizeof(*keyTmpl), &key);
    }
    CHECK_RV(rv, "find token key and create session key", CKR_OK);
    if (rv == CKR_OK) {
        wrappedLen = sizeof(wrapped);
        CHECK_RV(funcList->C_WrapKey(session, &mech, tokenKey, key, wrapped,
                                     &wrappedLen),
                 "wrap with token key not decoded", CKR_USER_NOT_LOGGED_IN);
    }
#ifndef NO_SHA256
    if (rv == CKR_OK) {
        CK_MECHANISM digestMech = { CKM_SHA256, NULL, 0 };

        rv = funcList->C_DigestInit(session, &digestMech);
        CHECK_RV(rv, "digest init", CKR_OK);
        if (rv == CKR_OK) {
            CHECK_RV(funcList->C_DigestKey(session, tokenKey),
                     "digest token key not decoded", CKR_USER_NOT_LOGGED_IN);
        }
    }
#endif
#ifdef WOLFPKCS11_HKDF
    if (rv == CKR_OK) {
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
        CK_ULONG outLen = 32;
        CK_HKDF_PARAMS hkdf;
        CK_MECHANISM hkdfMech = { CKM_HKDF_DERIVE, NULL, 0 };
        CK_ATTRIBUTE outTmpl[] = {
            { CKA_CLASS,     &secretClass, sizeof(secretClass) },
            { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
            { CKA_VALUE_LEN, &outLen,      sizeof(outLen)      },
            { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        };

        XMEMSET(&hkdf, 0, sizeof(hkdf));
        hkdf.bExtract = CK_TRUE;
        hkdf.prfHashMechanism = CKM_SHA256_HMAC;
        hkdf.ulSaltType = CKF_HKDF_SALT_KEY;
        hkdf.hSaltKey = tokenKey;
        hkdfMech.pParameter = &hkdf;
        hkdfMech.ulParameterLen = sizeof(hkdf);
        CHECK_RV(funcList->C_DeriveKey(session, &hkdfMech, key, outTmpl,
                                       sizeof(outTmpl) / sizeof(*outTmpl),
                                       &derived),
                 "HKDF with salt token key not decoded",
                 CKR_USER_NOT_LOGGED_IN);
    }
#endif
    shutdown_lib(session);
}
#endif

#ifdef TEST_FILE_STORE
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

static int write_file(const char* name, const byte* buf, size_t len)
{
    FILE* f;
    size_t written;

    f = fopen(name, "wb");
    if (f == NULL)
        return -1;
    written = fwrite(buf, 1, len, f);
    fclose(f);
    return written == len ? 0 : -1;
}

static long get_be32(const byte* p)
{
    return ((long)p[0] << 24) | ((long)p[1] << 16) | ((long)p[2] << 8) |
        (long)p[3];
}

/* Read the token record and find the offset of its token flags. */
static long token_flags_offset(byte* rec, size_t recSz, long* len)
{
    char name[160];
    long off = 32;
    int i;

    XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "wp11_token_%016lx",
              TEST_DIR, 1UL);
    *len = read_file(name, rec, recSz);
    /* Label, then PIN hash, seed, failure count and times of SO and user. */
    for (i = 0; i < 2; i++) {
        if (off + 4 > *len)
            return -1;
        off += 4 + get_be32(rec + off) + 16 + 4 + 2 * (long)sizeof(time_t);
    }
    /* Token key seed, then the object types. */
    off += 16;
    if (off + 4 > *len)
        return -1;
    off += 4 + get_be32(rec + off) * (long)sizeof(CK_ULONG);
    if (off + 4 > *len)
        return -1;
    return off;
}

static int write_token_record(const byte* rec, long len)
{
    char name[160];

    XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "wp11_token_%016lx",
              TEST_DIR, 1UL);
    return write_file(name, rec, (size_t)len);
}

/* Flip a bit of the encrypted key in the user's copy of the public-object
 * key, which follows the flags, the next object id and the SO key seed. */
static int corrupt_user_copy(void)
{
    byte rec[1024];
    long len;
    long off = token_flags_offset(rec, sizeof(rec), &len);

    if (off < 0 || off + 4 + 4 + 16 + 60 > len)
        return -1;
    rec[off + 4 + 4 + 16 + 12] ^= 0x01;
    return write_token_record(rec, len);
}

/* A user PIN change whose old key does not open the user's copy of the
 * public-object key is refused while a key or the SO's copy needs it. */
static void test_user_copy_unopenable(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- user PIN change with a user copy that does not open ---\n");
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
    CHECK_TRUE(corrupt_user_copy() == 0, "corrupt the user copy");

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        CHECK_RV(funcList->C_SetPIN(session, userPin, sizeof(userPin) - 1,
                                    userPin3, sizeof(userPin3) - 1),
                 "PIN change refused while a key is under the copy",
                 CKR_FUNCTION_FAILED);
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        CHECK_RV(login(session, CKU_USER, userPin3),
                 "new user PIN not stored", CKR_PIN_INCORRECT);
        CHECK_RV(login(session, CKU_USER, userPin),
                 "old user PIN still logs in after restart", CKR_OK);
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    CHECK_RV(rv, "provision token", CKR_OK);
    shutdown_lib(CK_INVALID_HANDLE);
    if (rv != CKR_OK)
        return;
    CHECK_TRUE(corrupt_user_copy() == 0, "corrupt the user copy");

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        CHECK_RV(funcList->C_SetPIN(session, userPin, sizeof(userPin) - 1,
                                    userPin3, sizeof(userPin3) - 1),
                 "PIN change refused while the SO copy needs the key",
                 CKR_FUNCTION_FAILED);
        rv = login(session, CKU_SO, soPin);
    }
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "SO still creates public token keys", CKR_OK);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin3, sizeof(userPin3) - 1);
    CHECK_RV(rv, "SO resets the user PIN", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin3);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "user uses the SO's key after the reset", CKR_OK);
    shutdown_lib(session);
}

/* Put the public-object key copies and PIN seeds of an earlier record back,
 * as TPM storage keeps them after an older release writes a record. */
static int restore_stale_copies(const byte* old, long oldLen)
{
    byte rec[1024];
    long len;
    long off = token_flags_offset(rec, sizeof(rec), &len);

    if (off < 0 || len != oldLen || off + 8 > len)
        return -1;
    XMEMCPY(rec + off + 8, old + off + 8, (size_t)(len - off - 8));
    return write_token_record(rec, len);
}

/* Copies left from before a user PIN change are dropped at load, so the user
 * can change the PIN again and create public token keys. */
static void test_stale_copies_dropped(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;
    byte old[1024];
    long oldLen = 0;
    byte newId[] = "pub-aes-new";

    printf("--- stale public-object key copies after a PIN change ---\n");
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
    CHECK_TRUE(token_flags_offset(old, sizeof(old), &oldLen) > 0,
               "read the token record");

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, userPin, sizeof(userPin) - 1,
                                userPin3, sizeof(userPin3) - 1);
    }
    CHECK_RV(rv, "change the user PIN", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;
    CHECK_TRUE(restore_stale_copies(old, oldLen) == 0,
               "restore the stale copies");

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin3);
    if (rv == CKR_OK) {
        CHECK_RV(funcList->C_SetPIN(session, userPin3, sizeof(userPin3) - 1,
                                    userPin, sizeof(userPin) - 1),
                 "user changes the PIN again", CKR_OK);
        CHECK_RV(create_aes_key(session, CK_FALSE, newId, &key),
                 "user creates a public token key", CKR_OK);
    }
    CHECK_RV(rv, "user logs in with the changed PIN", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, newId);
    CHECK_RV(rv, "user uses the new key after restart", CKR_OK);
    shutdown_lib(session);
}

/* A public session C_SetPIN leaves no key loaded once a PIN protects it. */
static void test_public_set_pin_drops_keys(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- public session C_SetPIN drops the keys ---\n");
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, userPin, sizeof(userPin) - 1,
                                userPin3, sizeof(userPin3) - 1);
    }
    CHECK_RV(rv, "user PIN changed from a public session", CKR_OK);
    if (rv == CKR_OK) {
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
        CHECK_RV(rv, "no public token key without login",
                 CKR_USER_NOT_LOGGED_IN);
        rv = login(session, CKU_USER, userPin3);
    }
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "user creates public token key with the new PIN", CKR_OK);
    shutdown_lib(session);
}

/* With storage turned off, the SO keeps using the public keys it created after
 * logging in again. */
static void test_storage_off_so_key(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- storage turned off keeps the SO's public keys ---\n");
    cleanup_test_files();
    XSETENV("WOLFPKCS11_NO_STORE", "1", 1);
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = init_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "SO uses its public key after logging in again", CKR_OK);
    shutdown_lib(session);
    unsetenv("WOLFPKCS11_NO_STORE");
}

/* C_InitPIN by the SO replaces the public-object key, so a copy of the token
 * record from before it does not open keys created after it. */
static void test_init_pin_rotates_key(void)
{
    static byte rotId[] = "rot-aes";
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    char name[160];
    byte rec[1024];
    long recLen = -1;

    printf("--- C_InitPIN replaces the public-object key ---\n");
    XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "wp11_token_%016lx",
              TEST_DIR, 1UL);
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = init_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "SO creates public key before a user PIN", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv == CKR_OK) {
        recLen = read_file(name, rec, sizeof(rec));
        CHECK_TRUE(recLen > 0 && recLen < (long)sizeof(rec),
                   "copy the token record");
    }
    if (rv != CKR_OK || recLen <= 0)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    if (rv == CKR_OK)
        rv = find_key(session, pubId, &key);
    if (rv == CKR_OK)
        rv = funcList->C_DestroyObject(session, key);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, rotId, &key);
    CHECK_RV(rv, "SO sets the user PIN and creates a public key", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, rotId);
    CHECK_RV(rv, "user uses the key", CKR_OK);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, rotId);
    CHECK_RV(rv, "SO uses the key", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    CHECK_TRUE(write_file(name, rec, (size_t)recLen) == 0,
               "put back the old token record");
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    CHECK_RV(rv, "SO login with the old token record", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(check_aes_key(session, rotId) != CKR_OK,
                   "old token record does not open the new key");
    }
    shutdown_lib(session);
}

/* The public keys C_InitPIN moves to the new public-object key are stored by
 * C_InitPIN itself, before any logout or C_Finalize. */
static void test_init_pin_rekeys_stored_keys(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;
    pid_t pid;
    int status = 0;

    printf("--- C_InitPIN stores public keys under the new key ---\n");
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

    pid = fork();
    if (pid == 0) {
        if (restart(&slot) != CKR_OK ||
                open_session(slot, &session) != CKR_OK ||
                login(session, CKU_SO, soPin) != CKR_OK ||
                funcList->C_InitPIN(session, userPin2,
                                    sizeof(userPin2) - 1) != CKR_OK) {
            _exit(1);
        }
        _exit(0);
    }
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
        rv = CKR_GENERAL_ERROR;
    }
    CHECK_RV(rv, "other process resets the user PIN and exits", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin2);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "user uses the public key with the reset PIN", CKR_OK);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "SO uses the public key", CKR_OK);
    shutdown_lib(session);
}

/* Another process resetting the token leaves this one able to create public
 * token keys without a login, as the token has no user PIN. */
static void test_reload_after_init_token(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;
    CK_C_INITIALIZE_ARGS args;
    pid_t pid;
    int status = 0;

    printf("--- reload after another process resets the token ---\n");
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    CHECK_RV(rv, "provision token", CKR_OK);
    shutdown_lib(CK_INVALID_HANDLE);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK) {
        pid = fork();
        if (pid == 0) {
            (void)funcList->C_Finalize(NULL);
            XMEMSET(&args, 0, sizeof(args));
            args.flags = CKF_OS_LOCKING_OK;
            if (funcList->C_Initialize(&args) != CKR_OK ||
                    init_token(slot) != CKR_OK) {
                _exit(1);
            }
            (void)funcList->C_Finalize(NULL);
            _exit(0);
        }
        if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0) {
            rv = CKR_GENERAL_ERROR;
        }
    }
    CHECK_RV(rv, "other process resets the token", CKR_OK);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "public session creates public token key", CKR_OK);
    shutdown_lib(session);
}
#endif

#ifdef TEST_LEGACY_STORE
/* Public-object key bits of the token flags in the token record. */
static int token_pub_flags(void)
{
    byte rec[1024];
    long len;
    long off = token_flags_offset(rec, sizeof(rec), &len);

    if (off < 0)
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

/* An SO logout leaves a key that an older release stored, and that no login
 * decoded, as it is stored. */
static void test_so_logout_keeps_undecoded_key(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- SO logout keeps a key no login decoded ---\n");
    cleanup_test_files();
    WP11_Test_StoreLegacyFormat(1);
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = init_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "store public key before a user PIN in the old format",
             CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    WP11_Test_StoreLegacyFormat(0);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    CHECK_RV(rv, "SO sets the user PIN", CKR_OK);
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
        rv = funcList->C_Logout(session);
    CHECK_RV(rv, "SO logs in and out", CKR_OK);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "key value unchanged at the user login", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "key value unchanged after restart", CKR_OK);
    shutdown_lib(session);
}

/* On a token an older release created with a user PIN, the SO cannot use
 * public keys, and its C_InitPIN loses them. */
static void test_legacy_store_no_so_copy(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- older release token gives the SO no key copy ---\n");
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

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "user migrates the public key", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;
    CHECK_TRUE(token_pub_flags() == 0x0c, "token record has no SO copy");

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    CHECK_RV(rv, "SO login", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(check_aes_key(session, pubId) != CKR_OK,
                   "SO cannot use the public key");
        CHECK_RV(create_aes_key(session, CK_FALSE, privId, &key),
                 "SO cannot create a public token key",
                 CKR_USER_NOT_LOGGED_IN);
        rv = funcList->C_InitPIN(session, userPin2, sizeof(userPin2) - 1);
        CHECK_RV(rv, "SO resets the user PIN", CKR_OK);
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;
    CHECK_TRUE(token_pub_flags() == 0x1c, "reset stores both copies");

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin2);
    CHECK_RV(rv, "user login with the reset PIN", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(check_aes_key(session, pubId) != CKR_OK,
                   "public key lost by the reset");
    }
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
        rv = funcList->C_InitPIN(session, userPin3, sizeof(userPin3) - 1);
    CHECK_RV(rv, "SO resets the user PIN again with the lost key", CKR_OK);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, privId, &key);
    CHECK_RV(rv, "SO creates public token key", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin3);
    if (rv == CKR_OK)
        rv = check_aes_key(session, privId);
    CHECK_RV(rv, "user uses the new public key", CKR_OK);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, privId);
    CHECK_RV(rv, "SO uses the new public key", CKR_OK);
    shutdown_lib(session);
}

static pid_t storePid = -1;
static int storeGo = -1;
static int storeSoLogin = 0;

/* Let the waiting child store, so this process is stale. */
static void store_elsewhere_hook(void)
{
    char c = 0;
    int status = 0;

    if (storePid <= 0)
        return;
    CHECK_TRUE(write(storeGo, &c, 1) == 1 &&
               waitpid(storePid, &status, 0) >= 0 && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0,
               "other process stores");
    close(storeGo);
    storePid = -1;
}

/* Store a data object, or with storeSoLogin give the token an SO key seed. */
static int store_elsewhere(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK && storeSoLogin)
        rv = login(session, CKU_SO, soPin);
    else if (rv == CKR_OK)
        rv = create_data_object(session);
    shutdown_lib(session);
    return rv == CKR_OK ? 0 : 1;
}

/* An SO copy made after a stale SO login is under the stored SO key seed;
 * with soLogin a new SO key seed from another process ends the login. */
static void test_so_copy_after_stale_login(int soLogin)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;
    int fds[2];
    char c;

    printf("--- SO copy after an SO login another process outdated (%s) "
           "---\n", soLogin ? "SO key seed" : "data object");
    cleanup_test_files();
    WP11_Test_StoreLegacyFormat(1);
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    CHECK_RV(rv, "provision token in the old format", CKR_OK);
    shutdown_lib(CK_INVALID_HANDLE);
    WP11_Test_StoreLegacyFormat(0);
    if (rv != CKR_OK)
        return;

    storeSoLogin = soLogin;
    if (pipe(fds) != 0)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK) {
        storePid = fork();
        if (storePid == 0) {
            close(fds[1]);
            if (read(fds[0], &c, 1) != 1)
                _exit(10);
            _exit(store_elsewhere());
        }
        close(fds[0]);
        if (storePid < 0) {
            close(fds[1]);
            rv = CKR_GENERAL_ERROR;
        }
        storeGo = fds[1];
    }
    if (rv == CKR_OK)
        rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        WP11_Slot_SetPinCheckHook(store_elsewhere_hook);
        rv = login(session, CKU_SO, soPin);
        WP11_Slot_SetPinCheckHook(NULL);
    }
    CHECK_RV(rv, "SO login while another process stores", CKR_OK);
    if (rv == CKR_OK && soLogin) {
        rv = funcList->C_InitPIN(session, userPin2, sizeof(userPin2) - 1);
        CHECK_RV(rv, "new SO key seed ends the SO login",
                 CKR_USER_NOT_LOGGED_IN);
        shutdown_lib(session);
        return;
    }
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin2, sizeof(userPin2) - 1);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "SO resets the user PIN and creates a public key", CKR_OK);
    store_elsewhere_hook();
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
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "SO uses the public key after restart", CKR_OK);
    shutdown_lib(session);
}

/* A user copy that does not open is replaced when no key and no SO copy need
 * the key it holds. */
static void test_legacy_user_copy_replaced(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- user copy no key needs is replaced ---\n");
    cleanup_test_files();
    WP11_Test_StoreLegacyFormat(1);
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    CHECK_RV(rv, "provision token in the old format", CKR_OK);
    shutdown_lib(CK_INVALID_HANDLE);
    WP11_Test_StoreLegacyFormat(0);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = create_data_object(session);
    CHECK_RV(rv, "user login stores the user copy", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;
    CHECK_TRUE(token_pub_flags() == 0x0c, "token record has only a user copy");
    CHECK_TRUE(corrupt_user_copy() == 0, "corrupt the user copy");

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, userPin, sizeof(userPin) - 1,
                                userPin3, sizeof(userPin3) - 1);
    }
    CHECK_RV(rv, "PIN change replaces the copy", CKR_OK);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin3);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "user creates public token key after the change", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin3);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "public key usable after restart", CKR_OK);
    shutdown_lib(session);
}

/* On a token an older release created without a user PIN, the SO keeps a
 * public key it created before C_InitPIN. */
static void test_legacy_no_pin_so_key(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- older release token without a user PIN ---\n");
    cleanup_test_files();
    WP11_Test_StoreLegacyFormat(1);
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = init_token(slot);
    CHECK_RV(rv, "initialize token in the old format", CKR_OK);
    shutdown_lib(CK_INVALID_HANDLE);
    WP11_Test_StoreLegacyFormat(0);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "SO creates public token key", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(object_pub_bit(0) == 1,
                   "key record is under the public-object key");
    }
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
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "SO sets the user PIN after restart", CKR_OK);
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
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "SO uses its public key after C_InitPIN", CKR_OK);
    shutdown_lib(session);
}

/* A public key is not added when storing the public-object key fails. */
static void test_prepare_store_fails(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- failed store of the public-object key fails the add ---\n");
    cleanup_test_files();
    WP11_Test_StoreLegacyFormat(1);
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = init_token(slot);
    CHECK_RV(rv, "initialize token in the old format", CKR_OK);
    shutdown_lib(CK_INVALID_HANDLE);
    WP11_Test_StoreLegacyFormat(0);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    CHECK_RV(rv, "SO login", CKR_OK);
    if (rv == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(0);
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
        WP11_Test_StoreCloseFailAfter(-1);
        CHECK_RV(rv, "public key refused when its key is not stored",
                 CKR_FUNCTION_FAILED);
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
        CHECK_RV(rv, "public key added once the store works", CKR_OK);
    }
    if (rv == CKR_OK) {
        CHECK_TRUE(object_pub_bit(0) == 1,
                   "key record is under the public-object key");
    }
    shutdown_lib(session);
}

/* A PIN change whose store fails leaves the old PIN opening public keys. */
static void test_pin_change_store_fails(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- PIN changes whose store fails keep public keys ---\n");
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
    if (rv == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(0);
        CHECK_TRUE(funcList->C_SetPIN(session, soPin, sizeof(soPin) - 1,
                       soPin2, sizeof(soPin2) - 1) != CKR_OK,
                   "SO PIN change fails to store");
        WP11_Test_StoreCloseFailAfter(-1);
        WP11_Test_StoreCloseFailAfter(0);
        CHECK_TRUE(funcList->C_InitPIN(session, userPin2,
                       sizeof(userPin2) - 1) != CKR_OK,
                   "user PIN reset fails to store");
        WP11_Test_StoreCloseFailAfter(-1);
        rv = funcList->C_Logout(session);
    }
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK) {
        WP11_Test_StoreCloseFailAfter(0);
        CHECK_TRUE(funcList->C_SetPIN(session, userPin, sizeof(userPin) - 1,
                       userPin3, sizeof(userPin3) - 1) != CKR_OK,
                   "user PIN change fails to store");
        WP11_Test_StoreCloseFailAfter(-1);
        rv = funcList->C_Logout(session);
    }
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "old PINs open the public key in the same process", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK) {
        CHECK_RV(login(session, CKU_SO, soPin2), "new SO PIN not stored",
                 CKR_PIN_INCORRECT);
        rv = login(session, CKU_SO, soPin);
    }
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "SO uses the public key with the old PIN", CKR_OK);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    if (rv == CKR_OK) {
        CHECK_RV(login(session, CKU_USER, userPin2), "reset PIN not stored",
                 CKR_PIN_INCORRECT);
        CHECK_RV(login(session, CKU_USER, userPin3), "new PIN not stored",
                 CKR_PIN_INCORRECT);
        rv = login(session, CKU_USER, userPin);
    }
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "user uses the public key with the old PIN", CKR_OK);
    shutdown_lib(session);
}
#endif

#ifdef DEBUG_WOLFPKCS11
static CK_SESSION_HANDLE hookSession = CK_INVALID_HANDLE;

static void logout_hook(void)
{
    (void)funcList->C_Logout(hookSession);
}

/* An SO logout while C_InitPIN hashes the PIN fails it, and leaves the user
 * PIN and the public key as they were. */
static void test_init_pin_logout_race(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key;

    printf("--- SO logout during C_InitPIN ---\n");
    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = provision(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_FALSE, pubId, &key);
    CHECK_RV(rv, "SO creates a public key", CKR_OK);
    if (rv == CKR_OK) {
        hookSession = session;
        WP11_Slot_SetPinCheckHook(logout_hook);
        rv = funcList->C_InitPIN(session, userPin2, sizeof(userPin2) - 1);
        WP11_Slot_SetPinCheckHook(NULL);
        CHECK_RV(rv, "SO logout during C_InitPIN fails it",
                 CKR_FUNCTION_FAILED);
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_FUNCTION_FAILED)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = login(session, CKU_SO, soPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "SO uses the public key after a restart", CKR_OK);
    (void)funcList->C_Logout(session);
    if (rv == CKR_OK)
        rv = login(session, CKU_USER, userPin);
    if (rv == CKR_OK)
        rv = check_aes_key(session, pubId);
    CHECK_RV(rv, "old user PIN uses the public key", CKR_OK);
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
#ifdef HAVE_AES_CBC
    test_so_logout_ends_ops();
    test_set_pin_ends_ops(0);
    test_set_pin_ends_ops(1);
#endif
    test_so_logout_after_init_pin();
#ifdef HAVE_AES_KEYWRAP
    test_undecoded_token_key();
#endif
#ifdef TEST_FILE_STORE
    test_user_copy_unopenable();
    test_stale_copies_dropped();
    test_public_set_pin_drops_keys();
    test_storage_off_so_key();
    test_init_pin_rotates_key();
    test_init_pin_rekeys_stored_keys();
    test_reload_after_init_token();
#ifdef HAVE_AES_CBC
    test_reload_ends_destroyed_op();
#endif
#endif
#ifdef DEBUG_WOLFPKCS11
    test_init_pin_logout_race();
#endif
#ifdef TEST_LEGACY_STORE
    test_legacy_store_migrates();
    test_so_logout_keeps_undecoded_key();
    test_legacy_store_no_so_copy();
    test_so_copy_after_stale_login(0);
    test_so_copy_after_stale_login(1);
    test_legacy_user_copy_replaced();
    test_legacy_no_pin_so_key();
    test_prepare_store_fails();
    test_pin_change_store_fails();
#endif
    cleanup_test_files();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("AES or token store not available, skipping test\n");
    return 77;
}

#endif
