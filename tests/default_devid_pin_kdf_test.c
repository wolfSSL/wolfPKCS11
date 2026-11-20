/* default_devid_pin_kdf_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
    #include <dlfcn.h>
#endif

#ifndef WOLFPKCS11_DLL_FILENAME
    #ifdef __MACH__
        #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
    #else
        #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
    #endif
#endif

#if defined(WOLF_CRYPTO_CB) && defined(WOLFPKCS11_DEFAULT_DEVID) && \
    defined(WOLFPKCS11_PBKDF2)

#define TEST_DEVID WOLFPKCS11_DEFAULT_DEVID
#define TEST_OBJ_DEVID (TEST_DEVID + 1)
#define DEVID_TEST_DIR "./store/default_devid_pin_kdf_test"

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static int callbackCalls;
static int pinHashCalls;
static int cipherCalls;
static int objectCalls;

static int test_crypto_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)ctx;

    if (devId != TEST_DEVID || info == NULL)
        return BAD_FUNC_ARG;

    callbackCalls++;
    if (info->algo_type == WC_ALGO_TYPE_HMAC ||
        info->algo_type == WC_ALGO_TYPE_HASH) {
        pinHashCalls++;
    }
    if (info->algo_type == WC_ALGO_TYPE_CIPHER)
        cipherCalls++;

    return CRYPTOCB_UNAVAILABLE;
}

static int test_object_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)ctx;

    if (devId != TEST_OBJ_DEVID || info == NULL)
        return BAD_FUNC_ARG;

    objectCalls++;
    return CRYPTOCB_UNAVAILABLE;
}

static CK_RV get_function_list(void)
{
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList getFunctionList;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "FAIL: dlopen: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    getFunctionList = (CK_C_GetFunctionList)dlsym(dlib,
        "C_GetFunctionList");
    if (getFunctionList == NULL)
        return CKR_GENERAL_ERROR;
    return getFunctionList(&funcList);
#else
    return C_GetFunctionList(&funcList);
#endif
}

static void close_library(void)
{
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}

static CK_RV initialize_library(CK_SLOT_ID* slot)
{
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slots[4];
    CK_ULONG slotCount = sizeof(slots) / sizeof(slots[0]);
    CK_RV rv;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slots, &slotCount);
    if (rv == CKR_OK && slotCount == 0U)
        rv = CKR_SLOT_ID_INVALID;
    if (rv == CKR_OK)
        *slot = slots[0];

    return rv;
}

static CK_RV initialize_token(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR soPin[] = "password123456";
    CK_UTF8CHAR userPin[] = "wolfpkcs11-test";
    CK_RV rv;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1U, label);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slot,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    }
    if (rv == CKR_OK)
        rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1U);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1U);
    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }

    return rv;
}

static CK_RV exercise_device_cipher(CK_SLOT_ID slot)
{
    CK_UTF8CHAR userPin[] = "wolfpkcs11-test";
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BYTE keyValue[16] = { 0 };
    CK_BYTE iv[16] = { 0 };
    CK_BYTE plain[16] = { 0 };
    CK_BYTE cipher[32];
    CK_ULONG cipherLen = sizeof(cipher);
    CK_MECHANISM mechanism = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_MECHANISM hmacMech = { CKM_SHA256_HMAC, NULL, 0 };
    CK_OBJECT_HANDLE hmacKey = CK_INVALID_HANDLE;
    CK_KEY_TYPE hmacType = CKK_GENERIC_SECRET;
    CK_ULONG objDevId = TEST_OBJ_DEVID;
    CK_BYTE hmacValue[32] = { 0 };
    CK_BYTE mac[32];
    CK_ULONG macLen = sizeof(mac);
#ifdef WOLFSSL_HAVE_PRF
    CK_TLS_MAC_PARAMS tlsParams;
    CK_MECHANISM tlsMech = { CKM_TLS_MAC, &tlsParams, sizeof(tlsParams) };
    CK_MECHANISM_TYPE prfs[] = { CKM_SHA256, CKM_TLS_PRF };
    size_t i;
    CK_OBJECT_HANDLE preMaster = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE master = CK_INVALID_HANDLE;
    CK_BYTE preMasterValue[48] = { 0 };
    CK_BYTE clientRandom[32] = { 0 };
    CK_BYTE serverRandom[32] = { 0 };
    CK_VERSION version = { 3, 3 };
    CK_ULONG masterLen = 48;
    CK_TLS12_MASTER_KEY_DERIVE_PARAMS deriveParams;
#ifdef WOLFPKCS11_NSS
    CK_OBJECT_HANDLE emsMaster = CK_INVALID_HANDLE;
    CK_BYTE sessionHash[32] = { 0 };
    CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS emsParams;
    CK_MECHANISM emsMech = { CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE,
        &emsParams, sizeof(emsParams) };
#endif
    CK_MECHANISM deriveMech = { CKM_TLS12_MASTER_KEY_DERIVE, &deriveParams,
        sizeof(deriveParams) };
    CK_ATTRIBUTE preMasterAttrs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &hmacType, sizeof(hmacType) },
        { CKA_DERIVE, &ckTrue, sizeof(ckTrue) },
        { CKA_WOLFSSL_DEVID, &objDevId, sizeof(objDevId) },
        { CKA_VALUE, preMasterValue, sizeof(preMasterValue) }
    };
    CK_ATTRIBUTE masterAttrs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &hmacType, sizeof(hmacType) },
        { CKA_VALUE_LEN, &masterLen, sizeof(masterLen) }
    };
#endif
#ifdef HAVE_AESCMAC
    CK_MECHANISM cmacMech = { CKM_AES_CMAC, NULL, 0 };
    CK_OBJECT_HANDLE cmacKey = CK_INVALID_HANDLE;
    CK_ATTRIBUTE cmacAttrs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) },
        { CKA_WOLFSSL_DEVID, &objDevId, sizeof(objDevId) },
        { CKA_VALUE, keyValue, sizeof(keyValue) }
    };
#endif
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &ckTrue, sizeof(ckTrue) },
        { CKA_VALUE, keyValue, sizeof(keyValue) }
    };
    CK_ATTRIBUTE hmacAttrs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &hmacType, sizeof(hmacType) },
        { CKA_SIGN, &ckTrue, sizeof(ckTrue) },
        { CKA_WOLFSSL_DEVID, &objDevId, sizeof(objDevId) },
        { CKA_VALUE, hmacValue, sizeof(hmacValue) }
    };
    CK_RV rv;

    rv = funcList->C_OpenSession(slot,
        CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, userPin,
            sizeof(userPin) - 1U);
    }
#ifdef WOLFPKCS11_PIN_KDF_SOFTWARE
    if (rv == CKR_OK && pinHashCalls != 0) {
        fprintf(stderr, "FAIL: PIN PBKDF2 reached device %d\n", TEST_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }
#else
    if (rv == CKR_OK && pinHashCalls == 0) {
        fprintf(stderr, "FAIL: PIN PBKDF2 did not reach device %d\n",
            TEST_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }
#endif
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, attrs,
            sizeof(attrs) / sizeof(attrs[0]), &key);
    }
    if (rv == CKR_OK)
        rv = funcList->C_EncryptInit(session, &mechanism, key);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, plain, sizeof(plain), cipher,
            &cipherLen);
    if (rv == CKR_OK && cipherCalls == 0) {
        fprintf(stderr, "FAIL: AES did not reach device %d\n", TEST_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, hmacAttrs,
            sizeof(hmacAttrs) / sizeof(hmacAttrs[0]), &hmacKey);
    }
    if (rv == CKR_OK)
        rv = funcList->C_SignInit(session, &hmacMech, hmacKey);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, plain, sizeof(plain), mac, &macLen);
    if (rv == CKR_OK && objectCalls == 0) {
        fprintf(stderr, "FAIL: HMAC did not reach object device %d\n",
            TEST_OBJ_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }
#ifdef WOLFSSL_HAVE_PRF
    for (i = 0; rv == CKR_OK && i < sizeof(prfs) / sizeof(prfs[0]); i++) {
        tlsParams.prfHashMechanism = prfs[i];
        tlsParams.ulMacLength = 12;
        tlsParams.ulServerOrClient = 1;
        objectCalls = 0;
        macLen = sizeof(mac);
        rv = funcList->C_SignInit(session, &tlsMech, hmacKey);
        if (rv == CKR_OK)
            rv = funcList->C_Sign(session, plain, sizeof(plain), mac, &macLen);
        if (rv == CKR_OK && objectCalls == 0) {
            fprintf(stderr, "FAIL: TLS PRF 0x%lx did not reach object "
                "device %d\n", (unsigned long)prfs[i], TEST_OBJ_DEVID);
            rv = CKR_FUNCTION_FAILED;
        }
    }
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, preMasterAttrs,
            sizeof(preMasterAttrs) / sizeof(preMasterAttrs[0]), &preMaster);
    }
    if (rv == CKR_OK) {
        XMEMSET(&deriveParams, 0, sizeof(deriveParams));
        deriveParams.RandomInfo.pClientRandom = clientRandom;
        deriveParams.RandomInfo.ulClientRandomLen = sizeof(clientRandom);
        deriveParams.RandomInfo.pServerRandom = serverRandom;
        deriveParams.RandomInfo.ulServerRandomLen = sizeof(serverRandom);
        deriveParams.pVersion = &version;
        deriveParams.prfHashMechanism = CKM_SHA256;
        objectCalls = 0;
        rv = funcList->C_DeriveKey(session, &deriveMech, preMaster,
            masterAttrs, sizeof(masterAttrs) / sizeof(masterAttrs[0]),
            &master);
    }
    if (rv == CKR_OK && objectCalls == 0) {
        fprintf(stderr, "FAIL: TLS 1.2 master derive did not reach object "
            "device %d\n", TEST_OBJ_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }
#ifdef WOLFPKCS11_NSS
    if (rv == CKR_OK) {
        XMEMSET(&emsParams, 0, sizeof(emsParams));
        emsParams.prfHashMechanism = CKM_SHA256;
        emsParams.pSessionHash = sessionHash;
        emsParams.ulSessionHashLen = sizeof(sessionHash);
        emsParams.pVersion = &version;
        objectCalls = 0;
        rv = funcList->C_DeriveKey(session, &emsMech, preMaster,
            masterAttrs, sizeof(masterAttrs) / sizeof(masterAttrs[0]),
            &emsMaster);
    }
    if (rv == CKR_OK && objectCalls == 0) {
        fprintf(stderr, "FAIL: extended master derive did not reach object "
            "device %d\n", TEST_OBJ_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }
    if (emsMaster != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, emsMaster);
#endif
    if (master != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, master);
    if (preMaster != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, preMaster);
#endif
#ifdef HAVE_AESCMAC
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, cmacAttrs,
            sizeof(cmacAttrs) / sizeof(cmacAttrs[0]), &cmacKey);
    }
    if (rv == CKR_OK) {
        objectCalls = 0;
        macLen = sizeof(mac);
        rv = funcList->C_SignInit(session, &cmacMech, cmacKey);
    }
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, plain, sizeof(plain), mac, &macLen);
    if (rv == CKR_OK && objectCalls == 0) {
        fprintf(stderr, "FAIL: CMAC did not reach object device %d\n",
            TEST_OBJ_DEVID);
        rv = CKR_FUNCTION_FAILED;
    }
    if (cmacKey != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, cmacKey);
#endif

    if (hmacKey != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, hmacKey);
    if (key != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, key);
    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }

    return rv;
}

int main(void)
{
    CK_SLOT_ID slot = 0;
    CK_RV rv;
    int ret;
    int deviceRegistered = 0;
    int objectRegistered = 0;

    /* Only the dedicated CI jobs run this, and they build every mechanism */
    if (getenv("WOLFPKCS11_DEFAULT_DEVID_REQUIRED") == NULL) {
        printf("SKIP: set WOLFPKCS11_DEFAULT_DEVID_REQUIRED=1 to run\n");
        return 0;
    }
#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_NO_ENV)
    XSETENV("WOLFPKCS11_TOKEN_PATH", DEVID_TEST_DIR, 1);
#endif

    rv = get_function_list();
    if (rv == CKR_OK)
        rv = initialize_library(&slot);
    if (rv == CKR_OK) {
        ret = wc_CryptoCb_RegisterDevice(TEST_DEVID, test_crypto_cb, NULL);
        if (ret != 0) {
            fprintf(stderr, "FAIL: register device: %d\n", ret);
            rv = CKR_DEVICE_ERROR;
        }
        else {
            deviceRegistered = 1;
        }
    }
    if (rv == CKR_OK) {
        ret = wc_CryptoCb_RegisterDevice(TEST_OBJ_DEVID, test_object_cb,
            NULL);
        if (ret != 0) {
            fprintf(stderr, "FAIL: register object device: %d\n", ret);
            rv = CKR_DEVICE_ERROR;
        }
        else {
            objectRegistered = 1;
        }
    }
    if (rv == CKR_OK)
        rv = initialize_token(slot);
    if (rv == CKR_OK)
        rv = exercise_device_cipher(slot);

    if (objectRegistered)
        wc_CryptoCb_UnRegisterDevice(TEST_OBJ_DEVID);
    if (deviceRegistered)
        wc_CryptoCb_UnRegisterDevice(TEST_DEVID);
    if (funcList != NULL)
        (void)funcList->C_Finalize(NULL);
    close_library();

    if (rv != CKR_OK) {
        fprintf(stderr, "FAIL: PKCS11 operation: 0x%lx\n",
            (unsigned long)rv);
        return 1;
    }
    if (callbackCalls == 0) {
        fprintf(stderr, "FAIL: device callback was never called\n");
        return 1;
    }

#ifdef WOLFPKCS11_PIN_KDF_SOFTWARE
    printf("PASS: slot crypto used device %d and PIN PBKDF2 stayed local\n",
        TEST_DEVID);
#else
    printf("PASS: slot crypto and PIN PBKDF2 used device %d\n", TEST_DEVID);
#endif
    return 0;
}

#else

int main(void)
{
    /* Dedicated CI jobs set this so a dropped build flag fails, not skips. */
    if (getenv("WOLFPKCS11_DEFAULT_DEVID_REQUIRED") != NULL) {
        printf("FAIL: default device test needs WOLF_CRYPTO_CB, "
            "WOLFPKCS11_DEFAULT_DEVID and PBKDF2\n");
        return 1;
    }
    printf("SKIP: default device/PIN KDF configuration not enabled\n");
    return 0;
}

#endif
