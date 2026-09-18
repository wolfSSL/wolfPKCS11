/* hkdf_persistence_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * Regression test for F-8635: CKK_HKDF token keys must use the symmetric-key
 * persistence path and survive C_Finalize/C_Initialize.
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

#if defined(WOLFPKCS11_HKDF) && !defined(WOLFPKCS11_NO_STORE)

#define TEST_DIR "." PATH_SEP "store" PATH_SEP "hkdf_persistence_test"
#define TOKEN_FILE TEST_DIR PATH_SEP "wp11_token_0000000000000001"
#define OBJECT_FILE_0 \
    TEST_DIR PATH_SEP "wp11_obj_0000000000000001_0000000000000000"
#define OBJECT_FILE_1 \
    TEST_DIR PATH_SEP "wp11_obj_0000000000000001_0000000000000001"
#define KEY_FILE_0 \
    TEST_DIR PATH_SEP "wp11_symmkey_0000000000000001_0000000000000000"
#define KEY_FILE_1 \
    TEST_DIR PATH_SEP "wp11_symmkey_0000000000000001_0000000000000001"

static byte soPin[] = "password123456";
static byte userPin[] = "wolfpkcs11-test";
static byte keyId[] = "hkdf-persistence";

static void cleanup_test_files(void)
{
    (void)remove(KEY_FILE_1);
    (void)remove(KEY_FILE_0);
    (void)remove(OBJECT_FILE_1);
    (void)remove(OBJECT_FILE_0);
    (void)remove(TOKEN_FILE);
}

static CK_RV initialize(CK_SLOT_ID* slot)
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

static CK_RV open_user_session(CK_SLOT_ID slot, CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    rv = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(*session, CKU_USER, userPin,
                               sizeof(userPin) - 1);
    }
    return rv;
}

static CK_RV generate_token_key(CK_SESSION_HANDLE session)
{
    CK_MECHANISM mech = { CKM_HKDF_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG valueLen = 32;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,       &ckTrue,  sizeof(ckTrue)  },
        { CKA_PRIVATE,     &ckTrue,  sizeof(ckTrue)  },
        { CKA_SENSITIVE,   &ckFalse, sizeof(ckFalse) },
        { CKA_EXTRACTABLE, &ckTrue,  sizeof(ckTrue)  },
        { CKA_VALUE_LEN,   &valueLen, sizeof(valueLen) },
        { CKA_ID,          keyId,    sizeof(keyId) - 1 },
    };

    return funcList->C_GenerateKey(session, &mech, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &key);
}

static CK_RV read_file(const char* path, byte* data, size_t dataSz,
                       size_t* readSz)
{
    FILE* file = fopen(path, "rb");

    if (file == NULL)
        return CKR_GENERAL_ERROR;
    *readSz = fread(data, 1, dataSz, file);
    if (ferror(file)) {
        fclose(file);
        return CKR_GENERAL_ERROR;
    }
    fclose(file);
    return CKR_OK;
}

static CK_RV check_unique_persistent_nonces(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE keys[2] = { CK_INVALID_HANDLE, CK_INVALID_HANDLE };
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    byte secret[32];
    byte ids[2] = { 1, 2 };
    byte objectData[2][12];
    byte keyData[2][64];
    byte zeroIv[12] = { 0 };
    size_t objectSz[2];
    size_t keySz[2];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &objClass, sizeof(objClass) },
        { CKA_KEY_TYPE,    &keyType,  sizeof(keyType)  },
        { CKA_TOKEN,       &ckTrue,   sizeof(ckTrue)   },
        { CKA_PRIVATE,     &ckTrue,   sizeof(ckTrue)   },
        { CKA_SENSITIVE,   &ckFalse,  sizeof(ckFalse)  },
        { CKA_EXTRACTABLE, &ckTrue,   sizeof(ckTrue)   },
        { CKA_VALUE,       secret,    sizeof(secret)   },
        { CKA_ID,          &ids[0],   sizeof(ids[0])   },
    };

    XMEMSET(secret, 0x3c, sizeof(secret));
    rv = funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &keys[0]);
    if (rv == CKR_OK) {
        tmpl[7].pValue = &ids[1];
        rv = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &keys[1]);
    }
    if (rv == CKR_OK)
        rv = read_file(OBJECT_FILE_0, objectData[0], sizeof(objectData[0]),
                       &objectSz[0]);
    if (rv == CKR_OK)
        rv = read_file(OBJECT_FILE_1, objectData[1], sizeof(objectData[1]),
                       &objectSz[1]);
    if (rv == CKR_OK)
        rv = read_file(KEY_FILE_0, keyData[0], sizeof(keyData[0]), &keySz[0]);
    if (rv == CKR_OK)
        rv = read_file(KEY_FILE_1, keyData[1], sizeof(keyData[1]), &keySz[1]);
    if (rv == CKR_OK &&
            (objectSz[0] != sizeof(objectData[0]) ||
             objectSz[1] != sizeof(objectData[1]) ||
             XMEMCMP(objectData[0], zeroIv, sizeof(zeroIv)) == 0 ||
             XMEMCMP(objectData[1], zeroIv, sizeof(zeroIv)) == 0 ||
             XMEMCMP(objectData[0], objectData[1], sizeof(objectData[0])) == 0)) {
        rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK &&
            (keySz[0] != keySz[1] ||
             XMEMCMP(keyData[0], keyData[1], keySz[0]) == 0)) {
        rv = CKR_GENERAL_ERROR;
    }

    if (keys[1] != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, keys[1]);
    if (keys[0] != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, keys[0]);

    return rv;
}

static CK_RV find_and_check_token_key(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_HKDF;
    CK_ULONG count = 0;
    CK_ULONG valueLen = 0;
    byte value[32];
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS,    &objClass, sizeof(objClass) },
        { CKA_KEY_TYPE, &keyType,  sizeof(keyType)  },
        { CKA_ID,       keyId,     sizeof(keyId) - 1 },
    };
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_KEY_TYPE,  &keyType,  sizeof(keyType)  },
        { CKA_VALUE_LEN, &valueLen, sizeof(valueLen) },
        { CKA_VALUE,     value,     sizeof(value)    },
    };

    rv = funcList->C_FindObjectsInit(session, findTmpl,
        sizeof(findTmpl) / sizeof(*findTmpl));
    if (rv == CKR_OK)
        rv = funcList->C_FindObjects(session, &key, 1, &count);
    if (rv == CKR_OK)
        rv = funcList->C_FindObjectsFinal(session);
    if (rv == CKR_OK && count != 1)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        rv = funcList->C_GetAttributeValue(session, key, getTmpl,
                                           sizeof(getTmpl) / sizeof(*getTmpl));
    if (rv == CKR_OK &&
            (keyType != CKK_HKDF || valueLen != sizeof(value))) {
        rv = CKR_GENERAL_ERROR;
    }
    if (rv == CKR_OK)
        rv = funcList->C_DestroyObject(session, key);

    return rv;
}

static void run_test(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    cleanup_test_files();

    rv = pkcs11_load();
    CHECK_RV(rv, "load library (create phase)", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = initialize(&slot);
    CHECK_RV(rv, "initialize (create phase)", CKR_OK);
    if (rv == CKR_OK)
        rv = provision_token(slot);
    CHECK_RV(rv, "provision token", CKR_OK);
    if (rv == CKR_OK)
        rv = open_user_session(slot, &session);
    CHECK_RV(rv, "open user session (create phase)", CKR_OK);
    if (rv == CKR_OK)
        rv = check_unique_persistent_nonces(session);
    CHECK_RV(rv, "persistent secrets use distinct IVs and ciphertexts", CKR_OK);
    if (rv == CKR_OK)
        rv = generate_token_key(session);
    CHECK_RV(rv, "generate persistent CKK_HKDF key", CKR_OK);
    if (session != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(session);
    (void)funcList->C_Finalize(NULL);
    pkcs11_unload();

    session = CK_INVALID_HANDLE;
    rv = pkcs11_load();
    CHECK_RV(rv, "load library (reload phase)", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = initialize(&slot);
    CHECK_RV(rv, "initialize (reload phase)", CKR_OK);
    if (rv == CKR_OK)
        rv = open_user_session(slot, &session);
    CHECK_RV(rv, "open user session (reload phase)", CKR_OK);
    if (rv == CKR_OK)
        rv = find_and_check_token_key(session);
    CHECK_RV(rv, "reload and read persistent CKK_HKDF key", CKR_OK);

    if (session != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(session);
    (void)funcList->C_Finalize(NULL);
    pkcs11_unload();
    cleanup_test_files();
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 HKDF persistence test ===\n");
    run_test();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("HKDF persistence not available, skipping test\n");
    return 0;
}

#endif
