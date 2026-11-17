/* slot_devid_default_test.c
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

/* These builds give the slot a device ID of their own. */
#if defined(WOLF_CRYPTO_CB) && defined(HAVE_AES_CBC) && !defined(NO_AES) && \
    !defined(NO_AES_CBC) && !defined(WOLFPKCS11_DEFAULT_DEVID) && \
    !defined(WOLFPKCS11_TPM) && !defined(WOLFSSL_MAXQ10XX_CRYPTO) && \
    !defined(WOLFSSL_STM32U5_DHUK)

#define SLOT_DEVID_TEST_DIR "./store/slot_devid_default_test"

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static int cipherCalls;

static int test_crypto_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    /* Hash inits can pick device 0 as wolfSSL's default, so count ciphers */
    if (info->algo_type == WC_ALGO_TYPE_CIPHER)
        cipherCalls++;
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

static CK_RV open_user_session(CK_SESSION_HANDLE* session)
{
    CK_SLOT_ID slots[4];
    CK_ULONG slotCount = sizeof(slots) / sizeof(slots[0]);
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR soPin[] = "password123456";
    CK_UTF8CHAR userPin[] = "wolfpkcs11-test";
    CK_SESSION_HANDLE so = CK_INVALID_HANDLE;
    CK_RV rv;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    rv = funcList->C_GetSlotList(CK_TRUE, slots, &slotCount);
    if (rv == CKR_OK && slotCount == 0U)
        rv = CKR_SLOT_ID_INVALID;
    if (rv == CKR_OK)
        rv = funcList->C_InitToken(slots[0], soPin, sizeof(soPin) - 1U, label);
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slots[0],
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &so);
    }
    if (rv == CKR_OK)
        rv = funcList->C_Login(so, CKU_SO, soPin, sizeof(soPin) - 1U);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(so, userPin, sizeof(userPin) - 1U);
    if (so != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(so);
        (void)funcList->C_CloseSession(so);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_OpenSession(slots[0],
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, session);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_Login(*session, CKU_USER, userPin,
            sizeof(userPin) - 1U);
    }

    return rv;
}

static CK_RV encrypt_once(CK_SESSION_HANDLE session, int setDevId)
{
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_ULONG devId = 0;
    CK_BYTE keyValue[16] = { 0 };
    CK_BYTE iv[16] = { 0 };
    CK_BYTE plain[16] = { 0 };
    CK_BYTE cipher[16];
    CK_ULONG cipherLen = sizeof(cipher);
    CK_MECHANISM mech = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &ckTrue, sizeof(ckTrue) },
        { CKA_VALUE, keyValue, sizeof(keyValue) },
        { CKA_WOLFSSL_DEVID, &devId, sizeof(devId) }
    };
    CK_ULONG attrCnt = sizeof(attrs) / sizeof(attrs[0]);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_RV rv;

    if (!setDevId)
        attrCnt--;
    rv = funcList->C_CreateObject(session, attrs, attrCnt, &key);
    if (rv == CKR_OK)
        rv = funcList->C_EncryptInit(session, &mech, key);
    if (rv == CKR_OK) {
        rv = funcList->C_Encrypt(session, plain, sizeof(plain), cipher,
            &cipherLen);
    }
    if (key != CK_INVALID_HANDLE)
        (void)funcList->C_DestroyObject(session, key);

    return rv;
}

int main(void)
{
    CK_C_INITIALIZE_ARGS args;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV rv;
    int registered = 0;
    int defaultCalls = 0;

#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_NO_ENV)
    XSETENV("WOLFPKCS11_TOKEN_PATH", SLOT_DEVID_TEST_DIR, 1);
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = get_function_list();
    if (rv == CKR_OK)
        rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK) {
        if (wc_CryptoCb_RegisterDevice(0, test_crypto_cb, NULL) != 0) {
            fprintf(stderr, "FAIL: register device 0\n");
            rv = CKR_DEVICE_ERROR;
        }
        else {
            registered = 1;
        }
    }
    if (rv == CKR_OK)
        rv = open_user_session(&session);
    if (rv == CKR_OK) {
        cipherCalls = 0;
        rv = encrypt_once(session, 0);
        defaultCalls = cipherCalls;
    }
    if (rv == CKR_OK) {
        cipherCalls = 0;
        rv = encrypt_once(session, 1);
    }

    if (session != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(session);
    if (funcList != NULL)
        (void)funcList->C_Finalize(NULL);
    if (registered)
        wc_CryptoCb_UnRegisterDevice(0);
    close_library();

    if (rv != CKR_OK) {
        fprintf(stderr, "FAIL: PKCS11 operation: 0x%lx\n", (unsigned long)rv);
        return 1;
    }
    if (defaultCalls != 0) {
        fprintf(stderr, "FAIL: a key without CKA_WOLFSSL_DEVID used "
            "device 0\n");
        return 1;
    }
    if (cipherCalls == 0) {
        printf("SKIP: the library does not share this wolfSSL\n");
        return 77;
    }
    printf("PASS: keys use software unless CKA_WOLFSSL_DEVID names a "
        "device\n");
    return 0;
}

#else

int main(void)
{
    printf("SKIP: build has no crypto callbacks or sets the slot device\n");
    return 77;
}

#endif
