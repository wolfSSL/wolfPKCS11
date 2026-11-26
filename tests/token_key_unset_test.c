/* token_key_unset_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * Tests that token keys are only stored under a token key that the user can
 * decrypt with.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

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

#if !defined(NO_AES) && defined(HAVE_ECC) && !defined(WOLFPKCS11_NO_STORE)

#define TEST_DIR "." PATH_SEP "store" PATH_SEP "token_key_unset_test"
#define MAX_TEST_OBJS 16

static byte soPin[] = "password123456";
static byte userPin[] = "wolfpkcs11-test";
static byte aesId[] = "unset-aes";
static byte soAesId[] = "unset-so-aes";
static byte ecId[] = "unset-ec";
static byte dataId[] = "unset-data";

static byte aesValue[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
};

/* DER encoded OID for P-256. */
static byte ecParams[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

static void cleanup_test_files(void)
{
    static const char* prefixes[] = {
        "wp11_obj", "wp11_symmkey", "wp11_ecckey_priv", "wp11_ecckey_pub",
        "wp11_data"
    };
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

static CK_RV init_token(CK_SLOT_ID slot)
{
    CK_UTF8CHAR label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    return funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
}

static CK_RV init_user_pin(CK_SESSION_HANDLE session)
{
    CK_RV rv;

    rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_Logout(session);
    return rv;
}

static CK_RV open_session(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    return funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                   NULL, NULL, session);
}

static CK_RV create_aes_key(CK_SESSION_HANDLE session, CK_BBOOL isPrivate,
                             byte* id, CK_ULONG idLen)
{
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_HANDLE key;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,       &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,     &isPrivate,   sizeof(isPrivate)   },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_ENCRYPT,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,       aesValue,     sizeof(aesValue)    },
        { CKA_ID,          id,           idLen               },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &key);
}

static CK_RV generate_aes_key(CK_SESSION_HANDLE session)
{
    CK_ULONG keyLen = 32;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_HANDLE key;
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &ckTrue,  sizeof(ckTrue)  },
        { CKA_PRIVATE,   &ckFalse, sizeof(ckFalse) },
        { CKA_ENCRYPT,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_VALUE_LEN, &keyLen,  sizeof(keyLen)  },
    };

    return funcList->C_GenerateKey(session, &mech, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &key);
}

static CK_RV generate_ec_key_pair(CK_SESSION_HANDLE session)
{
    CK_BBOOL ckTrue = CK_TRUE;
    CK_OBJECT_HANDLE pubKey, privKey;
    CK_MECHANISM ecGen = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS, ecParams, sizeof(ecParams) },
        { CKA_TOKEN,     &ckTrue,  sizeof(ckTrue)   },
        { CKA_VERIFY,    &ckTrue,  sizeof(ckTrue)   },
        { CKA_ID,        ecId,     sizeof(ecId) - 1 },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,     &ckTrue,  sizeof(ckTrue)   },
        { CKA_SIGN,      &ckTrue,  sizeof(ckTrue)   },
        { CKA_ID,        ecId,     sizeof(ecId) - 1 },
    };

    return funcList->C_GenerateKeyPair(session, &ecGen,
        pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
        privTmpl, sizeof(privTmpl) / sizeof(*privTmpl), &pubKey, &privKey);
}

static CK_RV create_data_object(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass)  },
        { CKA_TOKEN,   &ckTrue,    sizeof(ckTrue)     },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)    },
        { CKA_VALUE,   dataId,     sizeof(dataId) - 1 },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
}

static CK_RV find_key(CK_SESSION_HANDLE session, CK_OBJECT_CLASS objClass,
                      byte* id, CK_ULONG idLen, CK_OBJECT_HANDLE* key)
{
    CK_RV rv;
    CK_ULONG count = 0;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &objClass, sizeof(objClass) },
        { CKA_ID,    id,        idLen            },
    };

    rv = funcList->C_FindObjectsInit(session, findTmpl,
        sizeof(findTmpl) / sizeof(*findTmpl));
    if (rv == CKR_OK)
        rv = funcList->C_FindObjects(session, key, 1, &count);
    if (rv == CKR_OK)
        rv = funcList->C_FindObjectsFinal(session);
    if (rv == CKR_OK && count != 1)
        rv = CKR_GENERAL_ERROR;
    return rv;
}

static CK_RV check_aes_key(CK_SESSION_HANDLE session, byte* id,
                           CK_ULONG idLen)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte value[sizeof(aesValue)];
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_VALUE, value, sizeof(value) },
    };

    rv = find_key(session, CKO_SECRET_KEY, id, idLen, &key);
    if (rv == CKR_OK)
        rv = funcList->C_GetAttributeValue(session, key, getTmpl, 1);
    if (rv == CKR_OK && (getTmpl[0].ulValueLen != sizeof(aesValue) ||
            XMEMCMP(value, aesValue, sizeof(aesValue)) != 0)) {
        rv = CKR_GENERAL_ERROR;
    }
    return rv;
}

static CK_RV check_ec_key(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM ecdsa = { CKM_ECDSA, NULL, 0 };
    byte hash[32];
    byte sig[128];
    CK_ULONG sigLen = sizeof(sig);

    XMEMSET(hash, 0x5a, sizeof(hash));
    rv = find_key(session, CKO_PRIVATE_KEY, ecId, sizeof(ecId) - 1, &key);
    if (rv == CKR_OK)
        rv = funcList->C_SignInit(session, &ecdsa, key);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, hash, sizeof(hash), sig, &sigLen);
    return rv;
}

static CK_RV user_login(CK_SESSION_HANDLE session)
{
    return funcList->C_Login(session, CKU_USER, userPin, sizeof(userPin) - 1);
}

/* No token key without a user login once the user PIN is set. */
static void test_no_user_key(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = init_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    CHECK_RV(rv, "provision token", CKR_OK);
    if (rv == CKR_OK) {
        rv = create_aes_key(session, CK_FALSE, soAesId, sizeof(soAesId) - 1);
        CHECK_RV(rv, "create token AES key as SO after C_InitPIN", CKR_OK);
        (void)funcList->C_Logout(session);
    }
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    CHECK_RV(rv, "open public session", CKR_OK);
    if (rv != CKR_OK) {
        shutdown_lib(session);
        return;
    }
    CHECK_RV(create_aes_key(session, CK_FALSE, aesId, sizeof(aesId) - 1),
             "create public token AES key without login",
             CKR_USER_NOT_LOGGED_IN);
    CHECK_RV(generate_aes_key(session),
             "generate public token AES key without login",
             CKR_USER_NOT_LOGGED_IN);
    CHECK_RV(create_data_object(session),
             "create public token data object without login", CKR_OK);

    rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1);
    CHECK_RV(rv, "SO login", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_RV(create_aes_key(session, CK_FALSE, aesId, sizeof(aesId) - 1),
                 "create public token AES key as SO", CKR_OK);
        (void)funcList->C_Logout(session);
    }

    rv = user_login(session);
    CHECK_RV(rv, "user login", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_RV(create_aes_key(session, CK_FALSE, aesId, sizeof(aesId) - 1),
                 "create public token AES key as user", CKR_OK);
        CHECK_RV(check_aes_key(session, aesId, sizeof(aesId) - 1),
                 "AES key usable as user", CKR_OK);
        CHECK_RV(check_aes_key(session, soAesId, sizeof(soAesId) - 1),
                 "AES key created by SO usable as user", CKR_OK);
    }
    shutdown_lib(session);
}

/* Keys created before C_InitPIN are re-encrypted under the user's key. */
static void test_keys_before_init_pin(int reload)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = init_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_TRUE, aesId, sizeof(aesId) - 1);
    if (rv == CKR_OK)
        rv = generate_ec_key_pair(session);
    CHECK_RV(rv, "create token keys before C_InitPIN", CKR_OK);
    if (rv == CKR_OK && reload) {
        shutdown_lib(session);
        session = CK_INVALID_HANDLE;
        rv = restart(&slot);
        if (rv == CKR_OK)
            rv = open_session(slot, &session);
    }
    if (rv == CKR_OK)
        rv = init_user_pin(session);
    CHECK_RV(rv, "C_InitPIN", CKR_OK);
    if (rv == CKR_OK)
        rv = user_login(session);
    if (rv == CKR_OK)
        rv = check_aes_key(session, aesId, sizeof(aesId) - 1);
    if (rv == CKR_OK)
        rv = check_ec_key(session);
    CHECK_RV(rv, reload ? "keys loaded before C_InitPIN usable after it" :
             "keys created before C_InitPIN usable after it", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = user_login(session);
    if (rv == CKR_OK)
        rv = check_aes_key(session, aesId, sizeof(aesId) - 1);
    if (rv == CKR_OK)
        rv = check_ec_key(session);
    CHECK_RV(rv, "keys usable after C_InitPIN and restart", CKR_OK);
    shutdown_lib(session);
}

/* Keys stored under an empty user PIN are re-encrypted by C_InitPIN. */
static void test_empty_pin_then_init_pin(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    cleanup_test_files();
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = init_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, (CK_UTF8CHAR_PTR)"", 0);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv == CKR_PIN_LEN_RANGE) {
        printf("SKIP: empty user PIN not allowed\n");
        return;
    }
    CHECK_RV(rv, "set empty user PIN", CKR_OK);
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = create_aes_key(session, CK_TRUE, aesId, sizeof(aesId) - 1);
    if (rv == CKR_OK)
        rv = generate_ec_key_pair(session);
    CHECK_RV(rv, "create token keys under empty user PIN", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = init_user_pin(session);
    CHECK_RV(rv, "C_InitPIN on empty user PIN token", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, &session);
    if (rv == CKR_OK)
        rv = user_login(session);
    if (rv == CKR_OK)
        rv = check_aes_key(session, aesId, sizeof(aesId) - 1);
    if (rv == CKR_OK)
        rv = check_ec_key(session);
    CHECK_RV(rv, "keys from empty user PIN usable after C_InitPIN", CKR_OK);
    shutdown_lib(session);
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 unset token key test ===\n");
    test_no_user_key();
    test_keys_before_init_pin(0);
    test_keys_before_init_pin(1);
    test_empty_pin_then_init_pin();
    cleanup_test_files();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("AES, ECC or token store not available, skipping test\n");
    return 77;
}

#endif
