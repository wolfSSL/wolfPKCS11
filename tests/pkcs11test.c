/* pkcs11test.c - unit tests
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "unit.h"
#include "testdata.h"
#include <wolfpkcs11/internal.h>


#define TEST_FLAG_INIT                 0x01
#define TEST_FLAG_TOKEN                0x02
#define TEST_FLAG_SESSION              0x04

#define PKCS11TEST_CASE(func, flags)                                       \
    TEST_CASE(func, flags, pkcs11_open_session, pkcs11_close_session,      \
              sizeof(CK_SESSION_HANDLE))
#define PKCS11TEST_FUNC_NO_INIT_DECL(func)                                 \
    PKCS11TEST_CASE(func, 0)
#define PKCS11TEST_FUNC_NO_TOKEN_DECL(func)                                \
    PKCS11TEST_CASE(func, TEST_FLAG_INIT)
#define PKCS11TEST_FUNC_TOKEN_DECL(func)                                   \
    PKCS11TEST_CASE(func, TEST_FLAG_INIT | TEST_FLAG_TOKEN)
#define PKCS11TEST_FUNC_SESS_DECL(func)                                    \
    PKCS11TEST_CASE(func, TEST_FLAG_INIT | TEST_FLAG_TOKEN | TEST_FLAG_SESSION)


#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static int slot = 0;
static const char* tokenName = "wolfpkcs11";

/* FIPS requires pin to be at least 14 characters, since it is used for
 * the HMAC key */
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen;

#if !defined(NO_RSA) || defined(HAVE_ECC) || !defined(NO_DH)
static CK_OBJECT_CLASS pubKeyClass     = CKO_PUBLIC_KEY;
#endif
static CK_OBJECT_CLASS privKeyClass    = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS secretKeyClass  = CKO_SECRET_KEY;
static CK_OBJECT_CLASS certificateClass = CKO_CERTIFICATE;

#if defined(HAVE_ECC) || !defined(NO_DH)
static CK_BBOOL ckFalse = CK_FALSE;
#endif
static CK_BBOOL ckTrue  = CK_TRUE;

#ifndef NO_RSA
static CK_KEY_TYPE rsaKeyType  = CKK_RSA;
#endif
#ifdef HAVE_ECC
static CK_KEY_TYPE eccKeyType  = CKK_EC;
#endif
#ifndef NO_DH
static CK_KEY_TYPE dhKeyType  = CKK_DH;
#endif
#ifndef NO_AES
static CK_KEY_TYPE aesKeyType  = CKK_AES;
#endif
static CK_KEY_TYPE genericKeyType  = CKK_GENERIC_SECRET;


static CK_RV test_get_function_list(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_FUNCTION_LIST* funcListPtr = NULL;

    (void)session;

    ret = funcList->C_GetFunctionList(NULL);
    CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Function List no pointer");
    if (ret == CKR_OK)
        ret = funcList->C_GetFunctionList(&funcListPtr);
    if (ret == CKR_OK && funcListPtr != funcList) {
        ret = -1;
        CHECK_CKR(ret, "Get FunctionList pointer");
    }

    return ret;
}

static CK_RV test_not_initialized(void* args)
{
    CK_RV ret;

    (void)args;

    ret = funcList->C_GetInfo(NULL);
    CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Get Info");
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Get Slot List");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotInfo(0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Get Slot Info");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetTokenInfo(0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Get Token Info");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismList(0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Get Mechanism List");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismInfo(0, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Get Mechanism Info");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(0, NULL, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Init Token");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_InitPIN(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Init PIN");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(0, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Set PIN");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(0, 0, NULL, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Open Session");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CloseSession(0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Close Session");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CloseAllSessions(0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Close All Sessions");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetSessionInfo(0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Get Session Info");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetOperationState(0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                         "Get Operation State");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetOperationState(0, NULL, 0, 0, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                         "Set Operation State");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(0, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Login");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Logout(0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Logout");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(0, NULL, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Create Object");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(0, 0, NULL, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Copy Object");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(0, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Destroy Object");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetObjectSize(0, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Get Object Size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(0, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                         "Get Attribute Value");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(0, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                         "Set Attribute Value");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsInit(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Find Objects Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(0, NULL, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Find Objects Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Encrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Encrypt");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Encrypt Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Encrypt Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Decrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Decrypt");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptUpdate(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Decrypt Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Decrypt Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestInit(0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Digest Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Digest(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Digest");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Digest Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestKey(0, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Digest Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestFinal(0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Digest Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Sign Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Sign");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignUpdate(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Sign Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignFinal(0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Sign Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecoverInit(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Sign Recover Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecover(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Sign Recover");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(0, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyUpdate(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Verify Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Verify Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecoverInit(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                         "Verify Recover Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecover(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Verify Recover");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestEncryptUpdate(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                       "Digest Encrypt Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptDigestUpdate(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                       "Decrypt Digest Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignEncryptUpdate(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                         "Sign Encrypt Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptVerifyUpdate(0, NULL, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                       "Decrypt Verify Update");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKey(0, NULL, NULL, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Generate Key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(0, NULL, NULL, 0, NULL, 0, NULL,
                                                                          NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Generate Key Pair");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(0, NULL, 0, 0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Wrap Key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(0, NULL, 0, NULL, 0, NULL, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Unrap Key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(0, NULL, 0, NULL, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Derive Key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SeedRandom(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Seed Random");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateRandom(0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Generate Random");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetFunctionStatus(0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                         "Get Function Status");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CancelFunction(0);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED, "Cancel Function");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WaitForSlotEvent(0, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_CRYPTOKI_NOT_INITIALIZED,
                                                         "Wait For Slot Event");
    }

    return ret;
}


static CK_RV test_no_token_init(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_TOKEN_INFO tokenInfo;
    CK_FLAGS expFlags = CKF_RNG | CKF_CLOCK_ON_TOKEN | CKF_TOKEN_INITIALIZED;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    session = CK_INVALID_HANDLE;
    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session");
    if (ret == CKR_OK) {
#ifndef WOLFPKCS11_NSS
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR_FAIL(ret, CKR_USER_PIN_NOT_INITIALIZED,
                                                         "Login SO no PIN set");
#endif
        if (ret == CKR_OK) {
            ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
            CHECK_CKR_FAIL(ret, CKR_USER_PIN_NOT_INITIALIZED,
                                                         "Login SO no PIN set");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_GetTokenInfo(slot, &tokenInfo);
            CHECK_CKR(ret, "Get Token Info - token not initialized");
        }
        if (ret == CKR_OK) {
            CHECK_COND(tokenInfo.flags == expFlags, ret,
                             "Get Token Info - token initialized flag not set");
        }
    }

    if (session != CK_INVALID_HANDLE)
        funcList->C_CloseSession(session);
    if (ret == CKR_OK && session != CK_INVALID_HANDLE) {
        ret = funcList->C_CloseSession(session);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                                "Close Session already closed");
    }

    return ret;
}

static CK_RV test_get_info(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_INFO info;

    (void)session;

    ret = funcList->C_GetInfo(NULL);
    CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Info no pointer");
    if (ret == CKR_OK)
        ret = funcList->C_GetInfo(&info);

    return ret;
}

static CK_RV test_slot(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_SLOT_ID* slotList = NULL;
    CK_SLOT_INFO slotInfo;
    CK_ULONG count;
    CK_MECHANISM_TYPE* list = NULL;
    CK_MECHANISM_INFO info;
    int i;

    (void)session;

    ret = funcList->C_GetSlotList(-1, NULL, &count);
    CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Slot List bad token present");
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Slot List no count ptr");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, NULL, &count);
        CHECK_CKR(ret, "Get Slot List count");
    }
    if (ret == CKR_OK) {
        slotList = (CK_SLOT_ID*)XMALLOC(count * sizeof(CK_SLOT_ID), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (slotList == NULL)
            ret = CKR_DEVICE_MEMORY;
        CHECK_CKR(ret, "Allocate slot info memory");
    }
    if (ret == CKR_OK) {
        count--;
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "Get Slot List small count");
        count++;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &count);
        CHECK_CKR(ret, "Get Slot List");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_FALSE, slotList, &count);
        CHECK_CKR(ret, "Get Slot List");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotInfo(0, &slotInfo);
        CHECK_CKR_FAIL(ret, CKR_SLOT_ID_INVALID, "Get Slot Info invalid slot");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotInfo(slot, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Slot Info no info");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotInfo(slot, &slotInfo);
        CHECK_CKR(ret, "Get Slot Info");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismList(0, NULL, &count);
        CHECK_CKR_FAIL(ret, CKR_SLOT_ID_INVALID,
                                             "Get Mechanism List invalid slot");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismList(slot, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                             "Get Mechanism List no count ptr");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismList(slot, NULL, &count);
        CHECK_CKR(ret, "Get Mechanism List count");
    }
    if (ret == CKR_OK) {
        list = (CK_MECHANISM_TYPE*)XMALLOC(count * sizeof(CK_MECHANISM_TYPE),
                                           NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (list == NULL)
            ret = CKR_DEVICE_MEMORY;
        CHECK_CKR(ret, "Allocate mechanism list memory");
    }
    if (ret == CKR_OK && count > 0) {
        count--;
        ret = funcList->C_GetMechanismList(slot, list, &count);
        count++;
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                              "Get Mechanism List count small");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismList(slot, list, &count);
        CHECK_CKR(ret, "Get Mechanism List count");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismInfo(0, list[0], &info);
        CHECK_CKR_FAIL(ret, CKR_SLOT_ID_INVALID,
                                             "Get Mechanism Info invalid slot");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismInfo(slot, list[0], NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Mechanism Info no info");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismInfo(slot, -1, &info);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                                                 "Get Mechanism Info bad mech");
    }
    if (ret == CKR_OK) {
        for (i = 0; ret == CKR_OK && i < (int)count; i++) {
            ret = funcList->C_GetMechanismInfo(slot, list[i], &info);
            CHECK_CKR(ret, "Get mechanism info");
        }
    }

    if (ret == CKR_OK) {
        CK_SLOT_ID slotId;
        ret = funcList->C_WaitForSlotEvent(0, &slotId, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED,
                                           "Wait For Slot Event not supported");
    }

    if (slotList != NULL)
        XFREE(slotList, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (list != NULL)
        XFREE(list, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

static CK_RV test_token(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_TOKEN_INFO tokenInfo;
    CK_FLAGS expFlags = CKF_RNG | CKF_CLOCK_ON_TOKEN | CKF_TOKEN_INITIALIZED;
    unsigned char label[32];
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));

    ret = funcList->C_GetTokenInfo(0, &tokenInfo);
    CHECK_CKR_FAIL(ret, CKR_SLOT_ID_INVALID, "Get Token Info invalid slot");
    if (ret == CKR_OK) {
        ret = funcList->C_GetTokenInfo(slot, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Token Info no info");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetTokenInfo(slot, &tokenInfo);
        CHECK_CKR(ret, "Get Token Info");
    }
    if (ret == CKR_OK) {
        CHECK_COND(tokenInfo.flags == expFlags, ret,
                                            "Get Token Info - token flags set");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(0, soPin, soPinLen, label);
        CHECK_CKR_FAIL(ret, CKR_SLOT_ID_INVALID, "Init Token invalid slot");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(slot, NULL, soPinLen, label);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Init Token no pin");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(slot, soPin, soPinLen, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Init Token no label");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(slot, soPin, 3, label);
        CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT, "Init Token too short PIN");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(slot, soPin, 33, label);
        CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT, "Init Token too long PIN");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
        CHECK_CKR(ret, "Init Token");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(slot, soPin, soPinLen - 1, label);
        CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT, "Init Token bad PIN");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
        CHECK_CKR(ret, "Init Token");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
        CHECK_CKR(ret, "Open Session");
        if (ret == CKR_OK) {
            ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
            CHECK_CKR_FAIL(ret, CKR_SESSION_EXISTS,
                                                   "Init Token session exists");
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, userPin, userPinLen, userPin,
                                                                    userPinLen);
                CHECK_CKR_FAIL(ret, CKR_USER_PIN_NOT_INITIALIZED,
                                                        "Set User PIN not set");
            }
            funcList->C_CloseSession(session);
        }
    }

    return ret;
}

#ifndef WOLFPKCS11_NSS
/* Fails on NSS due to single-session mode */
static CK_RV test_open_close_session(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    int rwFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int roFlags = CKF_SERIAL_SESSION;
    CK_OBJECT_HANDLE soSession;

    ret = funcList->C_OpenSession(0, rwFlags, NULL, NULL, &session);
    CHECK_CKR_FAIL(ret, CKR_SLOT_ID_INVALID, "Open Session invalid slot");
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, 0, NULL, NULL, &session);
        CHECK_CKR_FAIL(ret, CKR_SESSION_PARALLEL_NOT_SUPPORTED,
                                                 "Open Session no serial flag");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, rwFlags, NULL, NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Open Session no session");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, rwFlags, NULL, NULL, &soSession);
        CHECK_CKR(ret, "Open Session SO");
        if (ret == CKR_OK) {
            ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
            CHECK_CKR(ret, "Login SO");
            if (ret == CKR_OK) {
                ret = funcList->C_OpenSession(slot, roFlags, NULL, NULL,
                                                                      &session);
                CHECK_CKR_FAIL(ret, CKR_SESSION_READ_WRITE_SO_EXISTS,
                                             "Open Session already SO session");
                if (ret == CKR_OK) {
                    ret = funcList->C_OpenSession(slot, rwFlags, NULL, NULL,
                                                                      &session);
                    CHECK_CKR(ret, "Open Session already SO session");
                }
                if (ret == CKR_OK)
                    funcList->C_CloseSession(session);

                ret = funcList->C_Logout(soSession);
                CHECK_CKR(ret, "Session Logout failed");
            }
            ret = funcList->C_CloseSession(soSession);
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_CloseSession(CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                        "Close Session invalid session handle");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_CloseAllSessions(0);
        CHECK_CKR_FAIL(ret, CKR_SLOT_ID_INVALID,
                                             "Close All Sessions invalid slot");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CloseAllSessions(slot);
        CHECK_CKR(ret, "Close All Sessions");
    }

    return ret;
}
#endif

static CK_RV test_pin(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    int rwFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int roFlags = CKF_SERIAL_SESSION;

    funcList->C_CloseSession(session);

    ret = funcList->C_InitPIN(CK_INVALID_HANDLE, userPin, userPinLen);
    CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID, "Init PIN invalid session");
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, rwFlags, NULL, NULL, &session);
        CHECK_CKR(ret, "Init PIN - Open Session");
        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(session, userPin, userPinLen);
            CHECK_CKR_FAIL(ret, CKR_USER_NOT_LOGGED_IN,
                                                      "Init PIN not logged in");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
            CHECK_CKR(ret, "Login SO");
            if (ret == CKR_OK) {
                ret = funcList->C_InitPIN(session, NULL, userPinLen);
                CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Init PIN no pin");
#if WP11_MIN_PIN_LEN > 3
                if (ret == CKR_OK) {
                    ret = funcList->C_InitPIN(session, userPin, 3);
                    CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT,
                                                      "Init PIN too short PIN");
                }
#endif
                if (ret == CKR_OK) {
                    ret = funcList->C_InitPIN(session, userPin, 33);
                    CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT,
                                                       "Init PIN too long PIN");
                }
                funcList->C_Logout(session);
            }
            funcList->C_CloseSession(session);
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_SetPIN(CK_INVALID_HANDLE, userPin, userPinLen,
                                                           userPin, userPinLen);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                                     "Set PIN invalid session");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, rwFlags, NULL, NULL, &session);
        CHECK_CKR(ret, "Set PIN - Open Session");
        if (ret == CKR_OK) {
            ret = funcList->C_SetPIN(session, NULL, userPinLen, userPin,
                                                                    userPinLen);
            CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Set PIN no old pin");
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, userPin, userPinLen, NULL,
                                                                    userPinLen);
                CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Set PIN no new pin");
            }
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, userPin, 3, userPin,
                                                                    userPinLen);
                CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT,
                                                   "Set PIN too short old pin");
            }
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, userPin, 33, userPin,
                                                                    userPinLen);
                CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT,
                                                    "Set PIN too long old pin");
            }
#if WP11_MIN_PIN_LEN > 3
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, userPin, userPinLen,userPin,
                                                                             3);
                CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT,
                                                   "Set PIN too short new pin");
            }
#endif
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, userPin, userPinLen, userPin,
                                                                            33);
                CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT,
                                                    "Set PIN too long new pin");
            }
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, userPin, userPinLen, userPin,
                                                                    userPinLen);
                CHECK_CKR(ret, "Set PIN no login");
            }
            if (ret == CKR_OK) {
                ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
                CHECK_CKR(ret, "Login User");
                if (ret == CKR_OK) {
                    ret = funcList->C_SetPIN(session, userPin, userPinLen,
                                                           userPin, userPinLen);
                    CHECK_CKR(ret, "Set PIN logdeg in");
                }
                funcList->C_Logout(session);
                if (ret == CKR_OK) {
                    ret = funcList->C_SetPIN(session, soPin, soPinLen, userPin,
                                                                    userPinLen);
                    CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT,
                                                  "Set PIN wrong old user PIN");
                }
            }
            funcList->C_CloseSession(session);
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, roFlags, NULL, NULL, &session);
        CHECK_CKR(ret, "Set PIN - Open Session Read Only");
        if (ret == CKR_OK) {
            ret = funcList->C_SetPIN(session, userPin, userPinLen, userPin,
                                                                    userPinLen);
            CHECK_CKR_FAIL(ret, CKR_SESSION_READ_ONLY, "Set PIN Read Only");
            if (ret == CKR_OK) {
                ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
                CHECK_CKR(ret, "Login User");
                if (ret == CKR_OK) {
                    ret = funcList->C_SetPIN(session, userPin, userPinLen,
                                                           userPin, userPinLen);
                    CHECK_CKR_FAIL(ret, CKR_SESSION_READ_ONLY,
                                                           "Set PIN Read Only");
                }
                funcList->C_Logout(session);
            }
            funcList->C_CloseSession(session);
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, rwFlags, NULL, NULL, &session);
        CHECK_CKR(ret, "Set PIN - Open Session");
        if (ret == CKR_OK) {
            ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
            CHECK_CKR(ret, "Login User");
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, userPin, userPinLen, soPin,
                                                                      soPinLen);
                CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT,
                                                    "Set PIN wrong old SO PIN");
            }
            if (ret == CKR_OK) {
                ret = funcList->C_SetPIN(session, soPin, soPinLen, soPin,
                                                                      soPinLen);
                CHECK_CKR(ret, "Set PIN - SO");
            }
            funcList->C_Logout(session);
        }
        funcList->C_CloseSession(session);
    }

    return ret;
}

static CK_RV test_login_logout(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = 0;
    CK_TOKEN_INFO tokenInfo;
    CK_FLAGS expFlags = CKF_RNG | CKF_CLOCK_ON_TOKEN | CKF_LOGIN_REQUIRED |
                        CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;

    funcList->C_Logout(session);

    if (ret == CKR_OK) {
        ret = funcList->C_GetTokenInfo(slot, &tokenInfo);
        CHECK_CKR(ret, "Get Token Info - token not initialized");
    }
    if (ret == CKR_OK) {
        CHECK_COND(tokenInfo.flags == expFlags, ret,
                             "Get Token Info - token initialized flag not set");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_Login(CK_INVALID_HANDLE, CKU_USER, userPin,
                                                                    userPinLen);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                                "Login invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, NULL, userPinLen);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Login no PIN");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_CONTEXT_SPECIFIC, userPin,
                                                                    userPinLen);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                      "Login context specific");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, 3, userPin, userPinLen);
        CHECK_CKR_FAIL(ret, CKR_USER_TYPE_INVALID, "Login bad user type");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_USER, soPin, soPinLen);
        CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT, "Login wrong user PIN");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, userPin, userPinLen);
        CHECK_CKR_FAIL(ret, CKR_PIN_INCORRECT, "Login wrong SO PIN");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_Logout(CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                               "Logout invalid session handle");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetTokenInfo(slot, &tokenInfo);
        CHECK_CKR(ret, "Get Token Info - token not initialized");
    }
    if (ret == CKR_OK) {
        expFlags |= CKF_SO_PIN_COUNT_LOW | CKF_USER_PIN_COUNT_LOW;
        CHECK_COND(tokenInfo.flags == expFlags, ret,
                             "Get Token Info - token initialized flag not set");
    }

#ifndef WOLFPKCS11_NSS
    if (ret == CKR_OK) {
        CK_OBJECT_HANDLE roSession;
        int roFlags = CKF_SERIAL_SESSION;
        ret = funcList->C_OpenSession(slot, roFlags, NULL, NULL, &roSession);
        CHECK_CKR(ret, "Login/out - Open Session RO");
        if (ret == CKR_OK) {
            ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
            CHECK_CKR_FAIL(ret, CKR_SESSION_READ_ONLY_EXISTS,
                                                     "Login SO with Read-Only");
            funcList->C_CloseSession(roSession);
        }
    }
#endif

    return ret;
}

static CK_RV test_session(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_SESSION_INFO info;

    ret = funcList->C_GetSessionInfo(CK_INVALID_HANDLE, &info);
    CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                     "Get Session info invalid session handle");
    if (ret == CKR_OK) {
        ret = funcList->C_GetSessionInfo(session, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Session info no info");
    }

    /* Get session info and check expected values. */
    if (ret == CKR_OK) {
        ret = funcList->C_GetSessionInfo(session, &info);
        CHECK_CKR(ret, "Get Session info");
    }
    if (ret == CKR_OK) {
        CHECK_COND(info.flags & CKF_SERIAL_SESSION, ret,
                                                     "Get Session info serial");
    }
    if (ret == CKR_OK)
        CHECK_COND((info.flags & CKF_RW_SESSION), ret, "Get Session info RW");
    if (ret == CKR_OK) {
        CHECK_COND(info.state == CKS_RW_USER_FUNCTIONS, ret,
                                                      "Get Session info state");
    }
    if (ret == CKR_OK)
        CHECK_COND((info.ulDeviceError == 0), ret, "Get Session info error");

    /* Get function status and cancel function are not valid anymore. */
    if (ret == CKR_OK) {
        ret = funcList->C_GetFunctionStatus(CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                  "Get Function Status invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetFunctionStatus(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_PARALLEL, "Get Function Status");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CancelFunction(CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                      "Cancel Function invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CancelFunction(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_PARALLEL, "Cancel Function");
    }

    return ret;
}

#ifndef NO_SHA256
/* This test:
*  1. Starts a digest
*  2. Saves the state
*  3. Updates the digest
*  4. Tests the result
*  5. Restores the state (before the update)
*  6. Tests the result
*/
static CK_RV test_op_state_success(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    byte* data = NULL;
    CK_ULONG len = 0;
    CK_MECHANISM mech;
    byte shaData[32], hash[32];
    CK_ULONG dataSz, hashSz;
    const unsigned char sha256_exp[] = {
        0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
        0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
        0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
        0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
    };

    const unsigned char sha256_exp2[] = {
        0x37, 0x26, 0x83, 0x35, 0xdd, 0x69, 0x31, 0x04,
        0x5b, 0xdc, 0xdf, 0x92, 0x62, 0x3f, 0xf8, 0x19,
        0xa6, 0x42, 0x44, 0xb5, 0x3d, 0x0e, 0x74, 0x6d,
        0x43, 0x87, 0x97, 0x34, 0x9d, 0x4d, 0xa5, 0x78
    };

    XMEMSET(shaData, 0, sizeof(shaData));
    XMEMCPY(shaData, "test", 4);
    dataSz = 4;
    hashSz = sizeof(hash);

    mech.mechanism = CKM_SHA256;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = funcList->C_DigestInit(session, &mech);
    CHECK_CKR(ret, "Could not init digest");
    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, shaData, dataSz);
        CHECK_CKR(ret, "Could not update digest");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetOperationState(session, shaData, &len);
        CHECK_COND(ret == CKR_BUFFER_TOO_SMALL, ret,
            "Could not get operation state length");
        CHECK_COND(len > 0, ret, "Bad state length");
        ret = CKR_OK;
    }
    if (ret == CKR_OK) {
        data = XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ret = funcList->C_GetOperationState(session, data, &len);
        CHECK_CKR(ret, "Could not get operation state");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, shaData, dataSz);
        CHECK_CKR(ret, "Could not update digest");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestFinal(session, hash, &hashSz);
        CHECK_CKR(ret, "Error running digest final");
    }
    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(hash, sha256_exp2, 32) == 0, ret,
                   "SHA does not match");
        ret = funcList->C_SetOperationState(session, data, len, 0, 0);
        CHECK_CKR(ret, "Could not set operation state");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestFinal(session, hash, &hashSz);
        CHECK_CKR(ret, "Error running digest final");
    }
    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(hash, sha256_exp, 32) == 0, ret,
                   "SHA does not match");
    }
    XFREE(data, 0, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif

#ifdef WOLFPKCS11_NSS
/* Test creating a token stored CKO_NSS_TRUST object, closing session,
 * reopening session, logging in, and verifying persistence */
static CK_RV test_nss_trust_object_token_storage(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_SESSION_HANDLE newSession = CK_INVALID_HANDLE;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS nss_trust_class = CKO_NSS_TRUST;
    int rwFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    /* Values for attributes */
    static byte issuer[] = "CN=Token Test Signer,O=wolfSSL,C=US";
    static byte serial_number[] = { 0x02, 0x05, 0x00, 0xC6, 0xA7, 0x91, 0x85 };
    static byte sha1_hash[] = {
        0x01, 0x75, 0x85, 0x74, 0xF9, 0xD2, 0x3D, 0x09,
        0x74, 0x5B, 0x1A, 0x72, 0xBA, 0xA6, 0xCC, 0x15,
        0xF1, 0xD0, 0x7A, 0x37
    };
    static byte md5_hash[] = {
        0x48, 0xC3, 0x68, 0x9D, 0xB0, 0xEA, 0x15, 0x22,
        0xD3, 0xE6, 0xA1, 0x7D, 0x84, 0xA0, 0x8E, 0xEC
    };
    static byte label[] = "TokenTrustTest";
    CK_ULONG trust_value = 0xCE534353;
    CK_BBOOL step_up = CK_FALSE;

    /* Template for creating the token object */
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_CLASS, &nss_trust_class, sizeof(nss_trust_class) },
        { CKA_LABEL, label, sizeof(label)-1 },
        { CKA_ISSUER, issuer, sizeof(issuer)-1 },
        { CKA_SERIAL_NUMBER, serial_number, sizeof(serial_number) },
        { CKA_CERT_SHA1_HASH, sha1_hash, sizeof(sha1_hash) },
        { CKA_CERT_MD5_HASH, md5_hash, sizeof(md5_hash) },
        { CKA_TRUST_SERVER_AUTH, &trust_value, sizeof(trust_value) },
        { CKA_TRUST_CLIENT_AUTH, &trust_value, sizeof(trust_value) },
        { CKA_TRUST_CODE_SIGNING, &trust_value, sizeof(trust_value) },
        { CKA_TRUST_EMAIL_PROTECTION, &trust_value, sizeof(trust_value) },
        { CKA_TRUST_STEP_UP_APPROVED, &step_up, sizeof(step_up) }
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    /* Template for finding the object */
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &nss_trust_class, sizeof(nss_trust_class) },
        { CKA_LABEL, label, sizeof(label)-1 }
    };
    CK_ULONG findTmplCnt = sizeof(findTmpl) / sizeof(*findTmpl);

    /* Buffer to retrieve attribute values */
    CK_BYTE buffer[64];
    CK_ATTRIBUTE getAttr;
    CK_OBJECT_CLASS retClass;
    CK_ULONG retTrustValue;
    CK_BBOOL retBool;
    CK_ULONG count;

    /* Create the token stored NSS_TRUST object */
    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create Token NSS_TRUST Object");

    /* Close the session */
    if (ret == CKR_OK) {
        if (userPinLen != 0)
            funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }

    /* Open a new session */
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, rwFlags, NULL, NULL, &newSession);
        CHECK_CKR(ret, "Open New Session for Token Trust Test");
    }

    /* Login as user */
    if (ret == CKR_OK && userPinLen != 0) {
        ret = funcList->C_Login(newSession, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login User for Token Trust Test");
    }

    /* Find the token object */
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsInit(newSession, findTmpl, findTmplCnt);
        CHECK_CKR(ret, "Find Token NSS_TRUST Objects Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(newSession, &obj, 1, &count);
        CHECK_CKR(ret, "Find Token NSS_TRUST Objects");
    }
    if (ret == CKR_OK && count != 1) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object not found");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(newSession);
        CHECK_CKR(ret, "Find Token NSS_TRUST Objects Final");
    }

    /* Verify object class */
    if (ret == CKR_OK) {
        getAttr.type = CKA_CLASS;
        getAttr.pValue = &retClass;
        getAttr.ulValueLen = sizeof(retClass);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object class");
    }
    if (ret == CKR_OK && retClass != CKO_NSS_TRUST) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object class incorrect");
    }

    /* Verify ISSUER attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_ISSUER;
        getAttr.pValue = buffer;
        getAttr.ulValueLen = sizeof(buffer);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object issuer");
    }
    if (ret == CKR_OK && (getAttr.ulValueLen != sizeof(issuer)-1 ||
            XMEMCMP(buffer, issuer, sizeof(issuer)-1) != 0)) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object issuer incorrect");
    }

    /* Verify SERIAL_NUMBER attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_SERIAL_NUMBER;
        getAttr.pValue = buffer;
        getAttr.ulValueLen = sizeof(buffer);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object serial number");
    }
    if (ret == CKR_OK && (getAttr.ulValueLen != sizeof(serial_number) ||
            XMEMCMP(buffer, serial_number, sizeof(serial_number)) != 0)) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object serial number incorrect");
    }

    /* Verify SHA1_HASH attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_CERT_SHA1_HASH;
        getAttr.pValue = buffer;
        getAttr.ulValueLen = sizeof(buffer);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object SHA1 hash");
    }
    if (ret == CKR_OK && (getAttr.ulValueLen != sizeof(sha1_hash) ||
            XMEMCMP(buffer, sha1_hash, sizeof(sha1_hash)) != 0)) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object SHA1 hash incorrect");
    }

    /* Verify MD5_HASH attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_CERT_MD5_HASH;
        getAttr.pValue = buffer;
        getAttr.ulValueLen = sizeof(buffer);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object MD5 hash");
    }
    if (ret == CKR_OK && (getAttr.ulValueLen != sizeof(md5_hash) ||
            XMEMCMP(buffer, md5_hash, sizeof(md5_hash)) != 0)) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object MD5 hash incorrect");
    }

    /* Verify TRUST_SERVER_AUTH attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_TRUST_SERVER_AUTH;
        getAttr.pValue = &retTrustValue;
        getAttr.ulValueLen = sizeof(retTrustValue);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object server auth");
    }
    if (ret == CKR_OK && retTrustValue != trust_value) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object server auth incorrect");
    }

    /* Verify TRUST_CLIENT_AUTH attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_TRUST_CLIENT_AUTH;
        getAttr.pValue = &retTrustValue;
        getAttr.ulValueLen = sizeof(retTrustValue);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object client auth");
    }
    if (ret == CKR_OK && retTrustValue != trust_value) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object client auth incorrect");
    }

    /* Verify TRUST_CODE_SIGNING attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_TRUST_CODE_SIGNING;
        getAttr.pValue = &retTrustValue;
        getAttr.ulValueLen = sizeof(retTrustValue);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object code signing");
    }
    if (ret == CKR_OK && retTrustValue != trust_value) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object code signing incorrect");
    }

    /* Verify TRUST_EMAIL_PROTECTION attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_TRUST_EMAIL_PROTECTION;
        getAttr.pValue = &retTrustValue;
        getAttr.ulValueLen = sizeof(retTrustValue);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object email protection");
    }
    if (ret == CKR_OK && retTrustValue != trust_value) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object email protection incorrect");
    }

    /* Verify TRUST_STEP_UP_APPROVED attribute */
    if (ret == CKR_OK) {
        getAttr.type = CKA_TRUST_STEP_UP_APPROVED;
        getAttr.pValue = &retBool;
        getAttr.ulValueLen = sizeof(retBool);
        ret = funcList->C_GetAttributeValue(newSession, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get Token NSS_TRUST Object step up approved");
    }
    if (ret == CKR_OK && retBool != step_up) {
        ret = -1;
        CHECK_CKR(ret, "Token NSS_TRUST Object step up approved incorrect");
    }

    /* Destroy the token object */
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(newSession, obj);
        CHECK_CKR(ret, "Destroy Token NSS_TRUST Object");
    }

    /* Update the session handle for cleanup */
    *(CK_SESSION_HANDLE*)args = newSession;

    return ret;
}
#endif

static CK_RV test_op_state_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    byte data = 0x00;
    CK_ULONG len = 0;

    ret = funcList->C_GetOperationState(CK_INVALID_HANDLE, NULL, &len);
    CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                         "Get Operation State invalid session");
    if (ret == CKR_OK) {
        ret = funcList->C_GetOperationState(session, &data, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                             "Get Operation State - no length");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_SetOperationState(CK_INVALID_HANDLE, &data, len, 0,
                                                                             0);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                         "Set Operation State invalid session");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetOperationState(session, NULL, len, 0, 0);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                              "Set Operation State - no state");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetOperationState(session, &data, len, 0, 0);
        CHECK_CKR_FAIL(ret, CKR_SAVED_STATE_INVALID,
                                         "Set Operation State - not available");
    }

    return ret;
}

static CK_RV test_object(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
#ifndef WOLFPKCS11_NSS
    CK_SESSION_HANDLE sessionRO;
#endif
    static byte keyData[] = { 0x00 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)    },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
        { CKA_EXTRACTABLE,       &ckTrue,           sizeof(ckTrue)            },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_ATTRIBUTE tmplOnToken[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)    },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
        { CKA_EXTRACTABLE,       &ckTrue,           sizeof(ckTrue)            },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
    };
    CK_ULONG tmplOnTokenCnt = sizeof(tmplOnToken) / sizeof(*tmplOnToken);
    CK_ATTRIBUTE copyTmpl[] = {
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
    };
    CK_ULONG copyTmplCnt = sizeof(copyTmpl) / sizeof(*copyTmpl);
    CK_ULONG count;
#ifndef _WIN32
    CK_ATTRIBUTE empty[] = { };
#endif
    CK_ATTRIBUTE keyTypeNull[] = {
        { CKA_KEY_TYPE,          NULL,              sizeof(CK_KEY_TYPE)       }
    };
    CK_ATTRIBUTE keyTypeZeroLen[] = {
        { CKA_KEY_TYPE,          &genericKeyType,   0,                        }
    };
    CK_ULONG badKeyType = -1;
    CK_ATTRIBUTE keyTypeBadValue[] = {
        { CKA_KEY_TYPE,          &badKeyType,       sizeof(&badKeyType)       }
    };
    CK_ATTRIBUTE keyDataNull[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_VALUE,             NULL,              sizeof(keyData)           },
    };
    CK_ATTRIBUTE keyClassNull[] = {
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_CLASS,             NULL,              sizeof(CK_OBJECT_CLASS)   }
    };
    CK_ATTRIBUTE keyClassZeroLen[] = {
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_CLASS,             &secretKeyClass,   0,                        }
    };
    CK_ATTRIBUTE tokenNull[] = {
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_TOKEN,             NULL,              sizeof(CK_BBOOL)          },
    };
    CK_ATTRIBUTE tokenBadLen[] = {
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_TOKEN,             &ckTrue,           0                         },
    };
    CK_OBJECT_HANDLE obj, objOnToken, copyObj;
    CK_ULONG size;


    ret = funcList->C_CreateObject(CK_INVALID_HANDLE, tmpl, tmplCnt, &obj);
    CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                        "Create Object invalid session handle");
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, NULL, tmplCnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Create Object no template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, tmpl, tmplCnt, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Create Object no object");
    }
#ifndef _WIN32
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, empty, 0, &obj);
        CHECK_CKR_FAIL(ret, CKR_TEMPLATE_INCOMPLETE,
                                                   "Create Object no key type");
    }
#endif
    if (ret == CKR_OK) {
        count = sizeof(keyTypeNull) / sizeof(*keyTypeNull);
        ret = funcList->C_CreateObject(session, keyTypeNull, count, &obj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                                 "Create Object NULL key type");
    }
    if (ret == CKR_OK) {
        count = sizeof(keyTypeZeroLen) / sizeof(*keyTypeZeroLen);
        ret = funcList->C_CreateObject(session, keyTypeZeroLen, count, &obj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                             "Create Object zero len key type");
    }
    if (ret == CKR_OK) {
        count = sizeof(keyTypeBadValue) / sizeof(*keyTypeBadValue);
        ret = funcList->C_CreateObject(session, keyTypeBadValue, count, &obj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                            "Create Object bad key type value");
    }
    if (ret == CKR_OK) {
        count = sizeof(keyDataNull) / sizeof(*keyDataNull);
        ret = funcList->C_CreateObject(session, keyDataNull, count, &obj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                                 "Create Object NULL key data");
    }
    if (ret == CKR_OK) {
        count = sizeof(keyClassNull) / sizeof(*keyClassNull);
        ret = funcList->C_CreateObject(session, keyClassNull, count, &obj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                                "Create Object NULL key class");
    }
    if (ret == CKR_OK) {
        count = sizeof(keyClassZeroLen) / sizeof(*keyClassZeroLen);
        ret = funcList->C_CreateObject(session, keyClassZeroLen, count, &obj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                            "Create Object zero len key class");
    }
    if (ret == CKR_OK) {
        count = sizeof(tokenNull) / sizeof(*tokenNull);
        ret = funcList->C_CreateObject(session, tokenNull, count, &obj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                                    "Create Object NULL token");
    }
    if (ret == CKR_OK) {
        count = sizeof(tokenBadLen) / sizeof(*tokenBadLen);
        ret = funcList->C_CreateObject(session, tokenBadLen, count, &obj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                                "Create Object zero token len");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
        CHECK_CKR(ret, "Create Object");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, tmplOnToken, tmplOnTokenCnt,
                                                                   &objOnToken);
        CHECK_CKR(ret, "Create Object");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(CK_INVALID_HANDLE, obj, copyTmpl,
                                                         copyTmplCnt, &copyObj);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                          "Copy Object invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(session, 0, copyTmpl, copyTmplCnt,
                                                                      &copyObj);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID, "Copy Object bad obj");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(session, obj, NULL, copyTmplCnt, &copyObj);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Copy Object no template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(session, obj, copyTmpl, copyTmplCnt, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Copy Object no new obj");
    }
    if (ret == CKR_OK) {
        count = sizeof(tokenNull) / sizeof(*tokenNull);
        ret = funcList->C_CopyObject(session, obj, tokenNull, count, &copyObj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                                      "Copy Object NULL token");
    }
    if (ret == CKR_OK) {
        count = sizeof(tokenBadLen) / sizeof(*tokenBadLen);
        ret = funcList->C_CopyObject(session, obj, tokenBadLen, count,
                                                                      &copyObj);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                                                  "Copy Object zero token len");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(session, obj, copyTmpl, copyTmplCnt,
                                                                      &copyObj);
        CHECK_CKR(ret, "Copy Object symmetric key");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetObjectSize(CK_INVALID_HANDLE, obj, &size);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                      "Get Object Size invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetObjectSize(session, 0, &size);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                                     "Get Object size bad obj");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetObjectSize(session, obj, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Object size no size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetObjectSize(session, obj, &size);
        CHECK_CKR(ret, "Get Object size");
        if (size != CK_UNAVAILABLE_INFORMATION) {
            ret = -1;
            CHECK_CKR(ret, "Get Object size not available");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(CK_INVALID_HANDLE, obj);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                       "Destroy Object invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, 0);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                                      "Destroy Object bad obj");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, obj);
        CHECK_CKR(ret, "Destroy Object");
    }
#ifndef WOLFPKCS11_NSS
    if (ret == CKR_OK) {
        sessionRO = CK_INVALID_HANDLE;
        ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
                                                                    &sessionRO);
        CHECK_CKR(ret, "Open Session - read-only");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(sessionRO, tmpl, tmplCnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_SESSION_READ_ONLY,
                                          "Create Object in read-only session");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(sessionRO, objOnToken, copyTmpl,
                                                         copyTmplCnt, &copyObj);
        CHECK_CKR_FAIL(ret, CKR_SESSION_READ_ONLY,
                              "Copy Object symmetric key in read-only session");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(sessionRO, objOnToken);
        CHECK_CKR_FAIL(ret, CKR_SESSION_READ_ONLY,
                                         "Destroy object in read-only session");
    }

    if (ret == CKR_OK && sessionRO != CK_INVALID_HANDLE) {
        funcList->C_CloseSession(sessionRO);
    }
#endif
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, objOnToken);
        CHECK_CKR(ret, "Destroy Object");
    }

    return ret;
}

#if ((defined(WOLFPKCS11_NSS)) && ((WP11_SESSION_CNT_MAX != 1) || \
    (WP11_SESSION_CNT_MIN != 1)))
static CK_RV test_cross_session_object(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_SESSION_HANDLE sessionRO;
    CK_OBJECT_HANDLE obj;
    CK_ULONG size;
    static byte keyData[] = { 0x00 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,             &pubKeyClass,      sizeof(pubKeyClass)       },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
        { CKA_EXTRACTABLE,       &ckTrue,           sizeof(ckTrue)            },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create object");

    if (ret == CKR_OK) {
        sessionRO = CK_INVALID_HANDLE;
        ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
                                                                    &sessionRO);
        CHECK_CKR(ret, "Open Session - read-only");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetObjectSize(sessionRO, obj, &size);
        CHECK_CKR(ret, "Get Object size");
        if (size != CK_UNAVAILABLE_INFORMATION) {
            ret = -1;
            CHECK_CKR(ret, "Get Object size not available");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(sessionRO, obj);
        CHECK_CKR(ret, "Cross-session deletion");
    }

    return ret;
}
#endif

static CK_RV test_attribute(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte keyData[] = { 0x00 };
    byte retKeyData[1];
    CK_ULONG valueLen = 1;
    CK_BBOOL badBool = 2;
    CK_DATE date = { { 0, }, { 0, }, { 0, } };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_EXTRACTABLE,       &ckTrue,           sizeof(ckTrue)            },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_ULONG count;
    CK_ATTRIBUTE badTmpl[] = {
        { CKA_TOKEN,             &ckTrue,           0                         }
    };
    CK_ATTRIBUTE badAttrType[] = {
        { -1,                    &ckTrue,           sizeof(ckTrue)            }
    };
    CK_ATTRIBUTE badAttrLen[] = {
        { CKA_VALUE,             retKeyData,        0                         }
    };
    CK_ATTRIBUTE attrNotAvail[] = {
        { CKA_APPLICATION,       retKeyData,        1                         }
    };
    CK_ATTRIBUTE tmplLongNull[] = {
        { CKA_VALUE_LEN,         NULL,              sizeof(valueLen)          }
    };
    CK_ATTRIBUTE tmplLongLenBad[] = {
        { CKA_VALUE_LEN,         &valueLen,         1                         }
    };
    CK_ATTRIBUTE tmplBoolNull[] = {
        { CKA_ENCRYPT,           NULL,              sizeof(CK_BBOOL)          }
    };
    CK_ATTRIBUTE tmplBoolLenBad[] = {
        { CKA_ENCRYPT,           &ckTrue,           0                         }
    };
    CK_ATTRIBUTE tmplBoolVal[] = {
        { CKA_ENCRYPT,           &badBool,          sizeof(CK_BBOOL)          }
    };
    CK_ATTRIBUTE tmplDateNull[] = {
        { CKA_START_DATE,        NULL,              sizeof(CK_DATE)           }
    };
    CK_ATTRIBUTE tmplDateLenBad[] = {
        { CKA_START_DATE,        &date,             1                         }
    };
    CK_ATTRIBUTE tmplDataUnavail[] = {
        { CKA_VALUE,             keyData,           CK_UNAVAILABLE_INFORMATION }
    };

    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create Object");
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(CK_INVALID_HANDLE, obj, tmpl,
                                                                       tmplCnt);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                  "Get Attribute Value invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, CK_INVALID_HANDLE, tmpl,
                                                                       tmplCnt);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                   "Get Attribute Value invalid object handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, NULL, tmplCnt);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                             "Get Attribute Value no template");
    }
    if (ret == CKR_OK) {
        count = sizeof(badTmpl) / sizeof(*badTmpl);
        ret = funcList->C_GetAttributeValue(session, obj, badTmpl, count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                            "Get Attribute Value bad template");
    }
    if (ret == CKR_OK) {
        count = sizeof(badAttrType) / sizeof(*badAttrType);
        ret = funcList->C_GetAttributeValue(session, obj, badAttrType, count);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_TYPE_INVALID,
                                      "Get Attribute Value bad attribute type");
    }
    if (ret == CKR_OK) {
        count = sizeof(badAttrLen) / sizeof(*badAttrLen);
        ret = funcList->C_GetAttributeValue(session, obj, badAttrLen, count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                    "Get Attribute Value bad attribute length");
    }
    if (ret == CKR_OK) {
        count = sizeof(attrNotAvail) / sizeof(*attrNotAvail);
        ret = funcList->C_GetAttributeValue(session, obj, attrNotAvail, count);
        CHECK_CKR_FAIL(ret, CK_UNAVAILABLE_INFORMATION,
                                 "Get Attribute Value attribute not available");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(CK_INVALID_HANDLE, obj, tmpl,
                                                                       tmplCnt);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                  "Set Attribute Value invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, CK_INVALID_HANDLE, tmpl,
                                                                       tmplCnt);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                   "Set Attribute Value invalid object handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, obj, NULL, tmplCnt);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                             "Set Attribute Value no template");
    }
    if (ret == CKR_OK) {
        count = sizeof(tmplLongNull) / sizeof(*tmplLongNull);
        ret = funcList->C_SetAttributeValue(session, obj, tmplLongNull, count);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                           "Set Attribute Value NULL value for data type long");
    }
    if (ret == CKR_OK) {
        count = sizeof(tmplLongLenBad) / sizeof(*tmplLongLenBad);
        ret = funcList->C_SetAttributeValue(session, obj, tmplLongLenBad,
                                                                         count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                         "Set Attribute Value small length for data type long");
    }
    if (ret == CKR_OK) {
        count = sizeof(tmplBoolNull) / sizeof(*tmplBoolNull);
        ret = funcList->C_SetAttributeValue(session, obj, tmplBoolNull, count);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                           "Set Attribute Value NULL value for data type bool");
    }
    if (ret == CKR_OK) {
        count = sizeof(tmplBoolLenBad) / sizeof(*tmplBoolLenBad);
        ret = funcList->C_SetAttributeValue(session, obj, tmplBoolLenBad,
                                                                         count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                         "Set Attribute Value small length for data type bool");
    }
    if (ret == CKR_OK) {
        count = sizeof(tmplBoolVal) / sizeof(*tmplBoolVal);
        ret = funcList->C_SetAttributeValue(session, obj, tmplBoolVal, count);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                            "Set Attribute Value bad value for data type bool");
    }
    if (ret == CKR_OK) {
        count = sizeof(tmplDateNull) / sizeof(*tmplDateNull);
        ret = funcList->C_SetAttributeValue(session, obj, tmplDateNull, count);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                           "Set Attribute Value NULL value for data type date");
    }
    if (ret == CKR_OK) {
        count = sizeof(tmplDateLenBad) / sizeof(*tmplDateLenBad);
        ret = funcList->C_SetAttributeValue(session, obj, tmplDateLenBad,
                                                                         count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                         "Set Attribute Value small length for data type date");
    }
    if (ret == CKR_OK) {
        count = sizeof(tmplDataUnavail) / sizeof(*tmplDataUnavail);
        ret = funcList->C_SetAttributeValue(session, obj, tmplDataUnavail,
                                                                         count);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_VALUE_INVALID,
                          "Set Attribute Value unavailable for data type data");
    }

    if (obj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, obj);

    return ret;
}

static CK_RV test_attribute_types(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte keyData[] = { 0x00 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
        { CKA_SUBJECT,             NULL,                0                     },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_BBOOL privateBool, sensitive, extractable, modifiable, alwaysSensitive;
    CK_BBOOL neverExtractable, alwaysAuthenticate, copyable, destroyable, local;
    CK_BBOOL wrapWithTrusted, trusted;
    CK_BBOOL encrypt, decrypt, verify, verifyRecover, sign, signRecover;
    CK_BBOOL wrap, unwrap, derive;
    CK_ATTRIBUTE boolTmpl[] = {
        { CKA_PRIVATE,             &privateBool,        sizeof(CK_BBOOL)      },
        { CKA_SENSITIVE,           &sensitive,          sizeof(CK_BBOOL)      },
        { CKA_EXTRACTABLE,         &extractable,        sizeof(CK_BBOOL)      },
        { CKA_MODIFIABLE,          &modifiable,         sizeof(CK_BBOOL)      },
        { CKA_ALWAYS_SENSITIVE,    &alwaysSensitive,    sizeof(CK_BBOOL)      },
        { CKA_NEVER_EXTRACTABLE,   &neverExtractable,   sizeof(CK_BBOOL)      },
        { CKA_ALWAYS_AUTHENTICATE, &alwaysAuthenticate, sizeof(CK_BBOOL)      },
        { CKA_WRAP_WITH_TRUSTED,   &wrapWithTrusted,    sizeof(CK_BBOOL)      },
        { CKA_TRUSTED,             &trusted,            sizeof(CK_BBOOL)      },
        { CKA_COPYABLE,            &copyable,           sizeof(CK_BBOOL)      },
        { CKA_DESTROYABLE,         &destroyable,        sizeof(CK_BBOOL)      },
        { CKA_LOCAL,               &local,              sizeof(CK_BBOOL)      },
        { CKA_ENCRYPT,             &encrypt,            sizeof(CK_BBOOL)      },
        { CKA_DECRYPT,             &decrypt,            sizeof(CK_BBOOL)      },
        { CKA_VERIFY,              &verify,             sizeof(CK_BBOOL)      },
        { CKA_VERIFY_RECOVER,      &verifyRecover,      sizeof(CK_BBOOL)      },
        { CKA_SIGN,                &sign,               sizeof(CK_BBOOL)      },
        { CKA_SIGN_RECOVER,        &signRecover,        sizeof(CK_BBOOL)      },
        { CKA_WRAP,                &wrap,               sizeof(CK_BBOOL)      },
        { CKA_UNWRAP,              &unwrap,             sizeof(CK_BBOOL)      },
        { CKA_DERIVE,              &derive,             sizeof(CK_BBOOL)      },
    };
    CK_ULONG boolTmplCnt = sizeof(boolTmpl) / sizeof(*boolTmpl);
    CK_ATTRIBUTE boolSetTmpl[] = {
        { CKA_PRIVATE,             &privateBool,        sizeof(CK_BBOOL)      },
        { CKA_SENSITIVE,           &sensitive,          sizeof(CK_BBOOL)      },
        { CKA_EXTRACTABLE,         &extractable,        sizeof(CK_BBOOL)      },
        { CKA_MODIFIABLE,          &modifiable,         sizeof(CK_BBOOL)      },
        { CKA_ALWAYS_SENSITIVE,    &alwaysSensitive,    sizeof(CK_BBOOL)      },
        { CKA_NEVER_EXTRACTABLE,   &neverExtractable,   sizeof(CK_BBOOL)      },
        { CKA_ALWAYS_AUTHENTICATE, &alwaysAuthenticate, sizeof(CK_BBOOL)      },
        { CKA_WRAP_WITH_TRUSTED,   &wrapWithTrusted,    sizeof(CK_BBOOL)      },
        { CKA_TRUSTED,             &trusted,            sizeof(CK_BBOOL)      },
        { CKA_ENCRYPT,             &encrypt,            sizeof(CK_BBOOL)      },
        { CKA_DECRYPT,             &decrypt,            sizeof(CK_BBOOL)      },
        { CKA_VERIFY,              &verify,             sizeof(CK_BBOOL)      },
        { CKA_VERIFY_RECOVER,      &verifyRecover,      sizeof(CK_BBOOL)      },
        { CKA_SIGN,                &sign,               sizeof(CK_BBOOL)      },
        { CKA_SIGN_RECOVER,        &signRecover,        sizeof(CK_BBOOL)      },
        { CKA_WRAP,                &wrap,               sizeof(CK_BBOOL)      },
        { CKA_UNWRAP,              &unwrap,             sizeof(CK_BBOOL)      },
        { CKA_DERIVE,              &derive,             sizeof(CK_BBOOL)      },
#if 0
        { CKA_LOCAL,               &local,              sizeof(CK_BBOOL)      },
        { CKA_DESTROYABLE,         &destroyable,        sizeof(CK_BBOOL)      },
        { CKA_COPYABLE,            &copyable,           sizeof(CK_BBOOL)      },
#endif
    };
    CK_ULONG boolSetTmplCnt = sizeof(boolSetTmpl) / sizeof(*boolSetTmpl);
    CK_ATTRIBUTE badAttrsTmpl[] = {
        { CKA_WRAP_TEMPLATE,       NULL,                0                     },
        { CKA_UNWRAP_TEMPLATE,     NULL,                0                     },
        { CKA_ALLOWED_MECHANISMS,  NULL,                0                     },
    };
    CK_ULONG badAttrsTmplCnt = sizeof(badAttrsTmpl) / sizeof(*badAttrsTmpl);
    CK_DATE startDate = { {'2','0','1','8'}, {'0','1'}, {'0','1'} };
    CK_DATE endDate = { {'2','1','1','8'}, {'0','1'}, {'0','1'} };
    CK_CHAR label[32] = "The Key's Label!!!";
    CK_DATE emptyStartDate = { {'2','0','1','8'}, {'0','1'}, {'0','1'} };
    CK_DATE emptyEndDate = { {'2','1','1','8'}, {'0','1'}, {'0','1'} };
    CK_CHAR emptyLabel[32] = "The Key's Label!!!";
    CK_ATTRIBUTE setGetTmpl[] = {
        { CKA_START_DATE,          &emptyStartDate,     sizeof(CK_DATE)       },
        { CKA_END_DATE,            &emptyEndDate,       sizeof(CK_DATE)       },
        { CKA_LABEL,               emptyLabel,          sizeof(emptyLabel)    },
    };
    CK_ULONG setGetTmplCnt = sizeof(setGetTmpl) / sizeof(*setGetTmpl);

    /* Certificate test variables */
    CK_OBJECT_HANDLE certObj = CK_INVALID_HANDLE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_BYTE subject[] = "C = US, ST = Montana, L = Bozeman, O = wolfSSL, "
        "OU = Support, CN = www.wolfssl.com, emailAddress = info@wolfssl.com";
    CK_BYTE certificate[] = { 0x30, 0x82, 0x01, 0x00 }; /* Minimal cert data */
    CK_ATTRIBUTE certTmpl[] = {
        { CKA_CLASS,             &certificateClass, sizeof(certificateClass) },
        { CKA_CERTIFICATE_TYPE,  &certType,         sizeof(certType)         },
        { CKA_SUBJECT,           subject,           sizeof(subject)-1        },
        { CKA_VALUE,             certificate,       sizeof(certificate)      },
    };
    CK_ULONG certTmplCnt = sizeof(certTmpl) / sizeof(*certTmpl);
    CK_BYTE subjectBuffer[256];
    CK_ATTRIBUTE subjectAttr[] = {
        { CKA_SUBJECT,             subjectBuffer,       sizeof(subjectBuffer)    },
    };
    int i;

    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create Object");
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, boolTmpl,
                                                                   boolTmplCnt);
        CHECK_CKR(ret, "Get Boolean attributes");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, obj, boolSetTmpl,
                                                                boolSetTmplCnt);
        CHECK_CKR(ret, "Set Boolean attributes");
    }
    for (i = 0; i < (int)badAttrsTmplCnt; i++) {
        ret = funcList->C_GetAttributeValue(session, obj, &badAttrsTmpl[i], 1);
        CHECK_CKR_FAIL(ret, CK_UNAVAILABLE_INFORMATION,
                                                   "Get unavailable attribute");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, setGetTmpl,
                                                                 setGetTmplCnt);
        CHECK_CKR(ret, "Get Empty data attributes");
    }
    if (ret == CKR_OK) {
        setGetTmpl[0].pValue = &startDate;
        setGetTmpl[0].ulValueLen = sizeof(CK_DATE);
        setGetTmpl[1].pValue = &endDate;
        setGetTmpl[1].ulValueLen = sizeof(CK_DATE);
        setGetTmpl[2].pValue = label;
        setGetTmpl[2].ulValueLen = sizeof(label);
        ret = funcList->C_SetAttributeValue(session, obj, setGetTmpl,
                                                                 setGetTmplCnt);
        CHECK_CKR(ret, "Set Empty data attributes");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, setGetTmpl,
                                                                 setGetTmplCnt);
        CHECK_CKR(ret, "Get Empty data attributes");
    }

    /* Test CKA_SUBJECT attribute with CKO_CERTIFICATE object
     * This verifies that CKA_SUBJECT is properly supported for certificate objects
     * and that the subject data can be retrieved correctly. */
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, certTmpl, certTmplCnt,
            &certObj);
        CHECK_CKR(ret, "Create Certificate Object");
    }
    if (ret == CKR_OK) {
        /* First get the required buffer size for CKA_SUBJECT */
        subjectAttr[0].pValue = NULL;
        subjectAttr[0].ulValueLen = 0;
        ret = funcList->C_GetAttributeValue(session, certObj, subjectAttr, 1);
        CHECK_CKR(ret, "Get CKA_SUBJECT length from certificate");
    }
    if (ret == CKR_OK) {
        /* Verify the length matches our expected subject size */
        if (subjectAttr[0].ulValueLen != sizeof(subject)-1) {
            ret = CKR_GENERAL_ERROR;
            CHECK_CKR(ret, "CKA_SUBJECT length verification");
        }
    }
    if (ret == CKR_OK) {
        /* Now get the actual CKA_SUBJECT data */
        subjectAttr[0].pValue = subjectBuffer;
        subjectAttr[0].ulValueLen = sizeof(subjectBuffer);
        ret = funcList->C_GetAttributeValue(session, certObj, subjectAttr, 1);
        CHECK_CKR(ret, "Get CKA_SUBJECT data from certificate");
    }
    if (ret == CKR_OK) {
        /* Verify subject data matches what we set */
        if (subjectAttr[0].ulValueLen != sizeof(subject)-1 ||
            XMEMCMP(subjectAttr[0].pValue, subject, sizeof(subject)-1) != 0) {
            ret = CKR_GENERAL_ERROR;
            CHECK_CKR(ret, "CKA_SUBJECT data verification failed");
        }
    }

    if (obj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, obj);
    if (certObj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, certObj);

    return ret;
}

static CK_RV test_attribute_get(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj2 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj3 = CK_INVALID_HANDLE;
    static byte keyData[] = { 0x01 };
    static byte id[] = { 0x01, 0x02, 0x03 };
    int i = 0;
    CK_BBOOL falseBool = 0;
    CK_ATTRIBUTE createTmpl[] = {
        { CKA_CLASS,             &pubKeyClass,     sizeof(pubKeyClass)      },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_EXTRACTABLE,       &ckTrue,           sizeof(ckTrue)            },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
        { CKA_ID,                id,                sizeof(id)                },
        { CKA_PRIVATE,           &falseBool,        sizeof(falseBool)         }
    };
    CK_ULONG tmplCnt = sizeof(createTmpl) / sizeof(*createTmpl);
    CK_ATTRIBUTE createTmpl2[] = {
        { CKA_CLASS,             &pubKeyClass,     sizeof(pubKeyClass)      },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_EXTRACTABLE,       &ckFalse,          sizeof(ckFalse)            },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
        { CKA_ID,                id,                sizeof(id)                },
        { CKA_PRIVATE,           &ckTrue,           sizeof(ckTrue)            }
    };
    CK_ULONG tmplCnt2 = sizeof(createTmpl2) / sizeof(*createTmpl2);
    CK_ATTRIBUTE createTmpl3[] = {
        { CKA_CLASS,             &pubKeyClass,     sizeof(pubKeyClass)      },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_SENSITIVE,         &ckTrue,           sizeof(ckTrue)            },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
        { CKA_ID,                id,                sizeof(id)                },
        { CKA_PRIVATE,           &ckTrue,           sizeof(ckTrue)            }
    };
    CK_ULONG tmplCnt3 = sizeof(createTmpl3) / sizeof(*createTmpl3);
    CK_ATTRIBUTE updateTmpl[] = {
        { CKA_SENSITIVE,         &ckFalse,           sizeof(ckFalse)          },
    };
    CK_ULONG updateTmplCnt = sizeof(updateTmpl) / sizeof(*updateTmpl);
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_CLASS,          NULL,   0    },
        { CKA_KEY_TYPE,       NULL,   0    },
        { CKA_PRIVATE,        NULL,   0    },
        { CKA_ID,             NULL,   0    },
    };
    CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(*getTmpl);
    CK_ATTRIBUTE getTmpl2[] = {
        { CKA_VALUE,          NULL,   0    },
    };
    CK_ULONG getTmplCnt2 = sizeof(getTmpl2) / sizeof(*getTmpl2);

    ret = funcList->C_CreateObject(session, createTmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create Object");

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "C_GetAttributeValue");
    }

    if (ret == CKR_OK) {
        for (i = 0; i < (int)getTmplCnt; i++) {
            getTmpl[i].pValue = XMALLOC(getTmpl[i].ulValueLen * sizeof(byte),
                                        NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (getTmpl[i].pValue == NULL)
                ret = CKR_DEVICE_MEMORY;
            CHECK_CKR(ret, "Allocate get attribute memory");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "C_GetAttributeValue");
    }

    if (ret == CKR_OK) {
        if (getTmpl[0].ulValueLen != sizeof(pubKeyClass) ||
            (*((CK_OBJECT_CLASS *)(getTmpl[0].pValue))) != pubKeyClass) {
                ret = -1;
                CHECK_CKR(ret, "CKA_CLASS value match creation params");
        }
    }

    if (ret == CKR_OK) {
        if (getTmpl[1].ulValueLen != sizeof(genericKeyType) ||
            (*((CK_OBJECT_CLASS *)(getTmpl[1].pValue))) != genericKeyType) {
                ret = -1;
                CHECK_CKR(ret, "CKA_KEY_TYPE value match creation params");
        }
    }

    if (ret == CKR_OK) {
        if (getTmpl[2].ulValueLen != sizeof(falseBool) ||
            (*((CK_BBOOL *)(getTmpl[2].pValue))) != falseBool) {
                ret = -1;
                CHECK_CKR(ret, "CKA_PRIVATE boolean match creation params");
        }
    }

    if (ret == CKR_OK) {
        if (getTmpl[3].ulValueLen != sizeof(id) ||
            XMEMCMP(getTmpl[3].pValue, id, sizeof(id)) != 0) {
                ret = -1;
                CHECK_CKR(ret, "CKA_ID value and len match creation params");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, createTmpl2, tmplCnt2, &obj2);
        CHECK_CKR(ret, "Create Object 2");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, createTmpl3, tmplCnt3, &obj3);
        CHECK_CKR(ret, "Create Object 3");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl2, getTmplCnt2);
        CHECK_CKR(ret, "Get Attributes pass");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj2, getTmpl2, getTmplCnt2);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_SENSITIVE,
                       "Get Attributes not extractable");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj3, getTmpl2, getTmplCnt2);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_SENSITIVE,
                       "Get Attributes sensitive");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, obj3, updateTmpl,
                                            updateTmplCnt);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_READ_ONLY,
                       "Update attribute sensitive");
    }

    for (i = 0; i < (int)getTmplCnt; i++)
    {
        if (getTmpl[i].pValue != NULL)
            XFREE(getTmpl[i].pValue, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (obj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, obj);

    return ret;
}

static CK_RV get_generic_key(CK_SESSION_HANDLE session, unsigned char* data,
                             CK_ULONG len, CK_BBOOL extractable,
                             CK_OBJECT_HANDLE* key)
{
    CK_RV ret;
    CK_ATTRIBUTE generic_key[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)    },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_EXTRACTABLE,       &extractable,      sizeof(CK_BBOOL)          },
        { CKA_SIGN,              &ckTrue,           sizeof(ckTrue)            },
        { CKA_VERIFY,            &ckTrue,           sizeof(ckTrue)            },
        { CKA_VALUE,             data,              len                       },
    };
    int cnt = sizeof(generic_key)/sizeof(*generic_key);

    ret = funcList->C_CreateObject(session, generic_key, cnt, key);
    CHECK_CKR(ret, "Generic Key Create Object");

    return ret;
}

static CK_RV test_attributes_secret(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    unsigned char value[32];
    CK_ULONG valueLen = sizeof(value);
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
    };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_VALUE,               NULL,                0                     },
        { CKA_VALUE_LEN,           &valueLen,           sizeof(valueLen)      },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_ATTRIBUTE badTmpl[] = {
        { CKA_WRAP_TEMPLATE,       NULL,                0                     },
        { CKA_UNWRAP_TEMPLATE,     NULL,                0                     },
    };
    CK_ULONG badTmplCnt = sizeof(badTmpl) / sizeof(*badTmpl);
    int i;

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, key, tmpl, tmplCnt);
        CHECK_CKR_FAIL(ret, CKR_ATTRIBUTE_SENSITIVE,
                       "Get Attributes Secret Key");
    }
    if (ret == CKR_OK) {
        for (i = 0; i < (int)badTmplCnt; i++) {
            ret = funcList->C_GetAttributeValue(session, key, &badTmpl[i], 1);
            CHECK_CKR_FAIL(ret, CK_UNAVAILABLE_INFORMATION,
                                           "Get Attributes secret unavailable");
        }
    }
    if (ret == CKR_OK) {
        CHECK_COND(tmpl[0].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                                          "Get Attributes secret value length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(valueLen == sizeof(keyData), ret,
                                             "Get Attributes secret value len");
    }
    funcList->C_DestroyObject(session, key);
    if (ret == CKR_OK) {
        ret = get_generic_key(session, keyData, sizeof(keyData), CK_TRUE, &key);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, key, tmpl, tmplCnt);
        CHECK_CKR(ret, "Get Attributes secret length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(tmpl[0].ulValueLen == sizeof(keyData), ret,
                                          "Get Attributes secret value length");
        tmpl[0].pValue = value;
    }
    if (ret == CKR_OK) {
        CHECK_COND(valueLen == sizeof(keyData), ret,
                                             "Get Attributes secret value len");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, key, tmpl, tmplCnt);
        CHECK_CKR(ret, "Get Attributes secret key data");
    }
    funcList->C_DestroyObject(session, key);

    return ret;
}

#ifdef HAVE_AESECB
static CK_RV test_secret_key_check_value(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE key;
    CK_ATTRIBUTE checkValueTmpl[] = {
        { CKA_CHECK_VALUE, NULL, 0 }
    };
    CK_ULONG checkValueTmplCnt = sizeof(checkValueTmpl) / sizeof(*checkValueTmpl);
    CK_BYTE checkValue[3];

    static unsigned char expectedAes128CheckValue[] = {0x00, 0x1B, 0x7D};

    static unsigned char genericKeyData[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static unsigned char expectedGeneralCheckValue[] = {0xC6, 0xA1, 0x3B};

    /* Test AES-128 */
    if (ret == CKR_OK) {
        CK_ATTRIBUTE aes128Tmpl[] = {
            { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
            { CKA_KEY_TYPE,    &aesKeyType,     sizeof(aesKeyType)     },
            { CKA_VALUE,       aes_128_key,     sizeof(aes_128_key)    },
            { CKA_ENCRYPT,     &ckTrue,         sizeof(ckTrue)         },
            { CKA_DECRYPT,     &ckTrue,         sizeof(ckTrue)         }
        };
        CK_ULONG aes128TmplCnt = sizeof(aes128Tmpl) / sizeof(*aes128Tmpl);

        ret = funcList->C_CreateObject(session, aes128Tmpl, aes128TmplCnt,
            &key);
        CHECK_CKR(ret, "Create AES-128 key for check value test");
    }

    if (ret == CKR_OK) {
        /* Get the length of the check value first */
        ret = funcList->C_GetAttributeValue(session, key, checkValueTmpl,
            checkValueTmplCnt);
        CHECK_CKR(ret, "Get AES-128 check value length");
    }

    if (ret == CKR_OK) {
        /* Verify expected check value length is 3 bytes */
        if (checkValueTmpl[0].ulValueLen != 3) {
            ret = CKR_GENERAL_ERROR;
            CHECK_CKR(ret, "AES-128 check value length should be 3 bytes");
        }
    }

    if (ret == CKR_OK) {
        /* Get the actual check value */
        checkValueTmpl[0].pValue = checkValue;
        checkValueTmpl[0].ulValueLen = sizeof(checkValue);

        ret = funcList->C_GetAttributeValue(session, key, checkValueTmpl,
            checkValueTmplCnt);
        CHECK_CKR(ret, "Get AES-128 check value");

        if (ret == CKR_OK) {
            /* Verify the check value matches expected value */
            if (XMEMCMP(checkValue, expectedAes128CheckValue, 3) != 0) {
                ret = CKR_GENERAL_ERROR;
                CHECK_CKR(ret, "AES-128 check value doesn't match expected");
            }
        }
    }

    funcList->C_DestroyObject(session, key);

    /* Test Generic Secret Key */
    if (ret == CKR_OK) {

        CK_ATTRIBUTE genericTmpl[] = {
            { CKA_CLASS,       &secretKeyClass,   sizeof(secretKeyClass)   },
            { CKA_KEY_TYPE,    &genericKeyType,   sizeof(genericKeyType)   },
            { CKA_VALUE,       genericKeyData,    sizeof(genericKeyData)   },
            { CKA_SIGN,        &ckTrue,           sizeof(ckTrue)           },
            { CKA_VERIFY,      &ckTrue,           sizeof(ckTrue)           }
        };
        CK_ULONG genericTmplCnt = sizeof(genericTmpl) / sizeof(*genericTmpl);

        ret = funcList->C_CreateObject(session, genericTmpl, genericTmplCnt,
            &key);
        CHECK_CKR(ret, "Create Generic Secret key for check value test");
    }

    if (ret == CKR_OK) {
        checkValueTmpl[0].pValue = NULL;
        checkValueTmpl[0].ulValueLen = 0;

        ret = funcList->C_GetAttributeValue(session, key, checkValueTmpl,
            checkValueTmplCnt);
        CHECK_CKR(ret, "Get Generic Secret key check value length");
    }

    if (ret == CKR_OK) {
        if (checkValueTmpl[0].ulValueLen != 3) {
            ret = CKR_GENERAL_ERROR;
            CHECK_CKR(ret,
                "Generic Secret key check value length should be 3 bytes");
        }
    }

    if (ret == CKR_OK) {
        checkValueTmpl[0].pValue = checkValue;
        checkValueTmpl[0].ulValueLen = sizeof(checkValue);

        ret = funcList->C_GetAttributeValue(session, key, checkValueTmpl,
            checkValueTmplCnt);
        CHECK_CKR(ret, "Get Generic Secret key check value");
    }
    if (ret == CKR_OK) {
        if (checkValueTmpl[0].ulValueLen != 3) {
            ret = CKR_GENERAL_ERROR;
            CHECK_CKR(ret,
                "Generic Secret key check value should return 3 bytes");
        }

    }
    if (ret == CKR_OK) {
        if (XMEMCMP(checkValue, expectedGeneralCheckValue, 3) != 0) {
            ret = CKR_GENERAL_ERROR;
            CHECK_CKR(ret,
                "Generic Secret key check value doesn't match expected");
        }
    }

    funcList->C_DestroyObject(session, key);

    return ret;
}
#endif

static CK_RV test_find_objects(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte keyData[] = { 0x00 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
    };
    CK_ULONG findTmplCnt = sizeof(findTmpl) / sizeof(*findTmpl);
    CK_OBJECT_HANDLE found;
    CK_ULONG count;

    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create Object");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsInit(CK_INVALID_HANDLE, findTmpl,
                                                                   findTmplCnt);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                    "Find Objects Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsInit(session, NULL, findTmplCnt);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Find Objects Init no template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(CK_INVALID_HANDLE, &found, 1, &count);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                         "Find Objects invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, NULL, 1, &count);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Find Objects no objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, &found, 1, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Find Objects no count");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                   "Find Objects Final invalid session handle");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsInit(session, findTmpl, findTmplCnt);
        CHECK_CKR(ret, "Find Objects Init");
        if (ret == CKR_OK) {
            ret = funcList->C_FindObjectsInit(session, findTmpl, findTmplCnt);
            CHECK_CKR_FAIL(ret, CKR_OPERATION_ACTIVE,
                                                     "Find Objects Init twice");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_FindObjects(session, &found, 1, &count);
            CHECK_CKR(ret, "Find Objects first");
        }
        if (ret == CKR_OK && count != 1) {
            ret = -1;
            CHECK_CKR(ret, "Find Objects found 1");
        }
        if (ret == CKR_OK && found != obj) {
            ret = -1;
            CHECK_CKR(ret, "Find Objects object handle expected");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_FindObjects(session, &found, 1, &count);
            CHECK_CKR(ret, "Find Objects no more");
        }
        if (ret == CKR_OK && count != 0) {
            ret = -1;
            CHECK_CKR(ret, "Find Objects found no more");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "Find Objects Final");
    }

    return ret;
}

static CK_RV get_aes_128_key(CK_SESSION_HANDLE session, unsigned char* id,
                             int idLen, CK_OBJECT_HANDLE* key)
{
    CK_RV ret;
    CK_ATTRIBUTE aes_key[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)    },
#ifndef NO_AES
        { CKA_KEY_TYPE,          &aesKeyType,       sizeof(aesKeyType)        },
#else
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
#endif
        { CKA_ENCRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_VALUE,             aes_128_key,       sizeof(aes_128_key)       },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_ID,                id,                idLen                     },
    };
    int cnt = sizeof(aes_key)/sizeof(*aes_key);

    if (id == NULL)
        cnt -= 2;

    ret = funcList->C_CreateObject(session, aes_key, cnt, key);
    CHECK_CKR(ret, "AES-128 Key Create Object");

    return ret;
}

static CK_RV test_encrypt_decrypt(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    byte plain[32], enc[32], dec[32], iv[16];
    CK_ULONG plainSz, encSz, decSz, ivSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);

    mech.mechanism      = CKM_AES_CBC;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(CK_INVALID_HANDLE, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                 "AES-CBC Encrypt Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(CK_INVALID_HANDLE, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                 "AES-CBC Encrypt Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(session, NULL, key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                           "AES-CBC Encrypt Init no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(session, &mech, CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                     "AES-CBC Encrypt Init invalid key handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(CK_INVALID_HANDLE, plain, plainSz, enc,
                                                                        &encSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                      "AES-CBC Encrypt invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, NULL, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "AES-CBC Encrypt no plain");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "AES-CBC Encrypt no enc size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                     "AES-CBC Encrypt no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(CK_INVALID_HANDLE, plain, plainSz, enc,
                                                                        &encSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                               "AES-CBC Encrypt Update invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(session, NULL, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                             "AES-CBC Encrypt Update no plain");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(session, plain, plainSz, enc, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                          "AES-CBC Encrypt Update no enc size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                              "AES-CBC Encrypt Update no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(CK_INVALID_HANDLE, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                "AES-CBC Encrypt Final invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, enc, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                           "AES-CBC Encrypt Final no enc size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                              "AES-CBC Encrypt Final no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(CK_INVALID_HANDLE, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                 "AES-CBC Decrypt Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, NULL, key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                           "AES-CBC Decrypt Init no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                     "AES-CBC Decrypt Init invalid key handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(CK_INVALID_HANDLE, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                      "AES-CBC Decrypt invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, NULL, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "AES-CBC Decrypt no enc");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "AES-CBC Decrypt no dec size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                     "AES-CBC Decrypt no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptUpdate(CK_INVALID_HANDLE, enc, encSz, dec,
                                                                        &decSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                               "AES-CBC Decrypt Update invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptUpdate(session, NULL, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "AES-CBC Decrypt Update no enc");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptUpdate(session, enc, encSz, dec, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                          "AES-CBC Decrypt Update no dec size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptUpdate(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                              "AES-CBC Decrypt Update no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(CK_INVALID_HANDLE, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                "AES-CBC Decrypt Final invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, dec, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                           "AES-CBC Decrypt Final no dec size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, enc, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                               "AES-CBC Decrypt Final no init");
    }

    if (ret == CKR_OK) {
        mech.mechanism = CKM_SHA256_HMAC;
        ret = funcList->C_EncryptInit(session, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                               "Encrypt Init invalid mechanism for encryption");
        mech.mechanism = CKM_AES_CBC;
    }
    if (ret == CKR_OK) {
        mech.mechanism = CKM_SHA256_HMAC;
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                               "Decrypt Init invalid mechanism for decryption");
        mech.mechanism = CKM_AES_CBC;
    }
    return ret;
}

#ifndef NO_SHA256
static CK_RV test_digest(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    byte data[32], hash[32];
    CK_ULONG dataSz, hashSz;
    const unsigned char sha256_exp[] = {
        0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
        0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
        0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
        0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
    };

    const unsigned char sha256_exp2[] = {
        0x37, 0x26, 0x83, 0x35, 0xdd, 0x69, 0x31, 0x04,
        0x5b, 0xdc, 0xdf, 0x92, 0x62, 0x3f, 0xf8, 0x19,
        0xa6, 0x42, 0x44, 0xb5, 0x3d, 0x0e, 0x74, 0x6d,
        0x43, 0x87, 0x97, 0x34, 0x9d, 0x4d, 0xa5, 0x78
    };

    XMEMSET(data, 0, sizeof(data));
    XMEMCPY(data, "test", 4);
    dataSz = 4;
    hashSz = sizeof(hash);

    mech.mechanism = CKM_SHA256;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = funcList->C_DigestInit(session , &mech);
    CHECK_CKR(ret, "Could not init digest");
    if (ret == CKR_OK) {
        ret = funcList->C_Digest(session, data, dataSz, hash, &hashSz);
        CHECK_CKR(ret, "Error running digest");
    }
    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(hash, sha256_exp, 32) == 0, ret,
                   "SHA does not match");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestInit(session , &mech);
        CHECK_CKR(ret, "Could not init digest");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, data, dataSz);
        CHECK_CKR(ret, "Could not update digest");
    }

    if (ret == CKR_OK) {
        hashSz = sizeof(hash);
        ret = funcList->C_DigestFinal(session, hash, &hashSz);
        CHECK_CKR(ret, "Error running digest final");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(hash, sha256_exp, 32) == 0, ret,
                   "SHA does not match");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestInit(session , &mech);
        CHECK_CKR(ret, "Could not init digest");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, data, dataSz);
        CHECK_CKR(ret, "Could not update digest");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, data, dataSz);
        CHECK_CKR(ret, "Could not update digest");
    }

    if (ret == CKR_OK) {
        hashSz = sizeof(hash);
        ret = funcList->C_DigestFinal(session, hash, &hashSz);
        CHECK_CKR(ret, "Error running digest final");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(hash, sha256_exp2, 32) == 0, ret,
                   "SHA does not match");
    }

    return ret;
}
#endif

#ifdef WOLFSSL_SHA3
static CK_RV test_digest_sha3(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                              const byte* exp1, const byte* exp2,
                              CK_ULONG hashSz)
{
    CK_RV ret;
    byte data[32], hash[64];
    CK_ULONG dataSz;

    XMEMSET(data, 0, sizeof(data));
    XMEMCPY(data, "test", 4);
    dataSz = 4;

    ret = funcList->C_DigestInit(session , mech);
    CHECK_CKR(ret, "Could not init digest");
    if (ret == CKR_OK) {
        ret = funcList->C_Digest(session, data, dataSz, hash, &hashSz);
        CHECK_CKR(ret, "Error running digest");
    }
    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(hash, exp1, hashSz) == 0, ret,
                   "SHA does not match");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestInit(session , mech);
        CHECK_CKR(ret, "Could not init digest");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, data, dataSz);
        CHECK_CKR(ret, "Could not update digest");
    }

    if (ret == CKR_OK) {
        hashSz = sizeof(hash);
        ret = funcList->C_DigestFinal(session, hash, &hashSz);
        CHECK_CKR(ret, "Error running digest final");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(hash, exp1, hashSz) == 0, ret,
                   "SHA does not match");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestInit(session, mech);
        CHECK_CKR(ret, "Could not init digest");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, data, dataSz);
        CHECK_CKR(ret, "Could not update digest");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, data, dataSz);
        CHECK_CKR(ret, "Could not update digest");
    }

    if (ret == CKR_OK) {
        hashSz = sizeof(hash);
        ret = funcList->C_DigestFinal(session, hash, &hashSz);
        CHECK_CKR(ret, "Error running digest final");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(hash, exp2, hashSz) == 0, ret,
                   "SHA does not match");
    }
    return ret;
}

#ifndef WOLFSSL_NOSHA3_224
static CK_RV test_digest_sha3_224(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_ULONG hashSz;

    const unsigned char sha3_exp[] = {
        0x37, 0x97, 0xbf, 0x0a, 0xfb, 0xbf, 0xca, 0x4a,
        0x7b, 0xbb, 0xa7, 0x60, 0x2a, 0x2b, 0x55, 0x27,
        0x46, 0x87, 0x65, 0x17, 0xa7, 0xf9, 0xb7, 0xce,
        0x2d, 0xb0, 0xae, 0x7b
    };

    const unsigned char sha3_exp2[] = {
        0x6a, 0x6d, 0xef, 0x2f, 0x38, 0x35, 0x2a, 0xec,
        0x3b, 0xc8, 0x57, 0x85, 0xd5, 0x31, 0x34, 0xd6,
        0x62, 0x60, 0x2e, 0xbb, 0x87, 0x6b, 0xbc, 0x34,
        0xf9, 0x56, 0xd8, 0xb0
    };

    hashSz = 28;
    mech.mechanism = CKM_SHA3_224;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = test_digest_sha3(session, &mech, sha3_exp, sha3_exp2, hashSz);

    return ret;
}
#endif

#ifndef WOLFSSL_NOSHA3_256
static CK_RV test_digest_sha3_256(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_ULONG hashSz;

    const unsigned char sha3_exp[] = {
        0x36, 0xf0, 0x28, 0x58, 0x0b, 0xb0, 0x2c, 0xc8,
        0x27, 0x2a, 0x9a, 0x02, 0x0f, 0x42, 0x00, 0xe3,
        0x46, 0xe2, 0x76, 0xae, 0x66, 0x4e, 0x45, 0xee,
        0x80, 0x74, 0x55, 0x74, 0xe2, 0xf5, 0xab, 0x80
    };

    const unsigned char sha3_exp2[] = {
        0xf4, 0x19, 0x53, 0xab, 0x51, 0x04, 0xe7, 0x63,
        0x6b, 0xc1, 0x69, 0x41, 0xac, 0xa1, 0x9c, 0x1d,
        0x97, 0x25, 0x25, 0x25, 0x9d, 0x44, 0x1a, 0xa3,
        0xa9, 0x2d, 0x10, 0xe8, 0x27, 0x2e, 0x9b, 0xb1
    };

    hashSz = 32;
    mech.mechanism = CKM_SHA3_256;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = test_digest_sha3(session, &mech, sha3_exp, sha3_exp2, hashSz);

    return ret;
}
#endif

#ifndef WOLFSSL_NOSHA3_384
static CK_RV test_digest_sha3_384(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_ULONG hashSz;

    const unsigned char sha3_exp[] = {
        0xe5, 0x16, 0xda, 0xbb, 0x23, 0xb6, 0xe3, 0x00,
        0x26, 0x86, 0x35, 0x43, 0x28, 0x27, 0x80, 0xa3,
        0xae, 0x0d, 0xcc, 0xf0, 0x55, 0x51, 0xcf, 0x02,
        0x95, 0x17, 0x8d, 0x7f, 0xf0, 0xf1, 0xb4, 0x1e,
        0xec, 0xb9, 0xdb, 0x3f, 0xf2, 0x19, 0x00, 0x7c,
        0x4e, 0x09, 0x72, 0x60, 0xd5, 0x86, 0x21, 0xbd
    };

    const unsigned char sha3_exp2[] = {
        0x7a, 0x81, 0xba, 0x98, 0x63, 0xfd, 0x70, 0x4c,
        0x5b, 0xa6, 0xec, 0x0a, 0x19, 0xb4, 0xb6, 0xe7,
        0xe5, 0x55, 0xb5, 0x09, 0x19, 0x55, 0xde, 0x5a,
        0xbb, 0x98, 0xb0, 0x13, 0xc4, 0x7f, 0x85, 0xf4,
        0xe0, 0x3e, 0x87, 0xc6, 0x72, 0xd7, 0x87, 0x51,
        0x46, 0xb4, 0xa6, 0x74, 0x35, 0x34, 0xe5, 0x58
    };

    hashSz = 48;
    mech.mechanism = CKM_SHA3_384;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = test_digest_sha3(session, &mech, sha3_exp, sha3_exp2, hashSz);

    return ret;
}
#endif

#ifndef WOLFSSL_NOSHA3_512
static CK_RV test_digest_sha3_512(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_ULONG hashSz;

    const unsigned char sha3_exp[] = {
        0x9e, 0xce, 0x08, 0x6e, 0x9b, 0xac, 0x49, 0x1f,
        0xac, 0x5c, 0x1d, 0x10, 0x46, 0xca, 0x11, 0xd7,
        0x37, 0xb9, 0x2a, 0x2b, 0x2e, 0xbd, 0x93, 0xf0,
        0x05, 0xd7, 0xb7, 0x10, 0x11, 0x0c, 0x0a, 0x67,
        0x82, 0x88, 0x16, 0x6e, 0x7f, 0xbe, 0x79, 0x68,
        0x83, 0xa4, 0xf2, 0xe9, 0xb3, 0xca, 0x9f, 0x48,
        0x4f, 0x52, 0x1d, 0x0c, 0xe4, 0x64, 0x34, 0x5c,
        0xc1, 0xae, 0xc9, 0x67, 0x79, 0x14, 0x9c, 0x14
    };

    const unsigned char sha3_exp2[] = {
        0x64, 0xc3, 0x7f, 0x15, 0xca, 0x73, 0xf0, 0x4d,
        0x4a, 0xb3, 0x4f, 0x6f, 0x93, 0x88, 0xdc, 0x63,
        0x86, 0x0e, 0x63, 0x0e, 0xfc, 0x30, 0x11, 0xde,
        0xf4, 0x8c, 0x4e, 0x62, 0x5c, 0x9c, 0x37, 0x61,
        0x6d, 0xf5, 0x01, 0x7d, 0xf9, 0x46, 0x11, 0x04,
        0xb2, 0x8a, 0xad, 0x2b, 0x87, 0x4a, 0x5b, 0x46,
        0x47, 0x57, 0x39, 0x8b, 0x83, 0xc2, 0x4b, 0xa0,
        0x8e, 0xb5, 0x7d, 0x57, 0xd9, 0xd8, 0x3d, 0xfe
    };

    hashSz = 64;
    mech.mechanism = CKM_SHA3_512;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = test_digest_sha3(session, &mech, sha3_exp, sha3_exp2, hashSz);

    return ret;
}
#endif
#endif

static CK_RV test_digest_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    byte data[32], hash[32];
    CK_ULONG dataSz, hashSz;
    CK_OBJECT_HANDLE key;

    XMEMSET(data, 9, sizeof(data));
    dataSz = sizeof(data);
    hashSz = sizeof(hash);

    mech.mechanism = CKM_SHA256;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = get_generic_key(session, data, sizeof(data), CK_FALSE, &key);
    if (ret == CKR_OK) {
        ret = funcList->C_DigestInit(CK_INVALID_HANDLE, &mech);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                         "Digest Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestInit(session, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Digest Init no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Digest(CK_INVALID_HANDLE, data, dataSz, hash,
                                                                       &hashSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                               "Digest invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Digest(session, NULL, dataSz, hash, &hashSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Digest no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Digest(session, data, 0, hash, &hashSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Digest zero data length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Digest(session, data, dataSz, hash, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Digest no hash size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(CK_INVALID_HANDLE, data, dataSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                        "Digest Update invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, NULL, dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Digest Update no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestUpdate(session, data, 0);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                              "Digest Update zero data length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestKey(CK_INVALID_HANDLE, key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                           "Digest Key invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestKey(session, CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                            "Digest Key invalid object handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestFinal(CK_INVALID_HANDLE, hash, &hashSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                         "Digest Final invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestFinal(session, hash, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Digest Final no hash size");
    }

    return ret;
}

static CK_RV test_sign_verify(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    byte   data[32], out[64];
    byte   keyData[32];
    CK_ULONG dataSz, outSz;
    CK_ULONG keySz;
    CK_OBJECT_HANDLE key;

    memset(data, 9, sizeof(data));
    memset(keyData, 9, sizeof(keyData));
    dataSz = sizeof(data);
    outSz = sizeof(out);
    keySz = sizeof(keyData);

    mech.mechanism      = CKM_SHA256_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = get_generic_key(session, keyData, keySz, CK_FALSE, &key);
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(CK_INVALID_HANDLE, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                       "HMAC Sign Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, NULL, key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Sign Init no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                           "HMAC Sign Init invalid key handle");
    }
    if (ret == CKR_OK) {
        mech.mechanism = CKM_AES_CBC;
        ret = funcList->C_SignInit(session, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                                              "HMAC Sign Init wrong mechanism");
        mech.mechanism = CKM_SHA256_HMAC;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(CK_INVALID_HANDLE, data, dataSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                            "HMAC Sign invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, NULL, dataSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Sign no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, dataSz, out, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Sign no out size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED, "HMAC Sign no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignUpdate(CK_INVALID_HANDLE, data, dataSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                     "HMAC Sign Update invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignUpdate(session, NULL, dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Sign Update no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignUpdate(session, data, dataSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                    "HMAC Sign Update no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignFinal(CK_INVALID_HANDLE, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                      "HMAC Sign Final invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignFinal(session, out, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Sign Final NULL sig len");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignFinal(session, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                     "HMAC Sign Final no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(CK_INVALID_HANDLE, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                     "HMAC Verify Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, NULL, key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Verify Init no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                         "HMAC Verify Init invalid key handle");
    }
    if (ret == CKR_OK) {
        mech.mechanism = CKM_AES_CBC;
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                                            "HMAC Verify Init wrong mechanism");
        mech.mechanism = CKM_SHA256_HMAC;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(CK_INVALID_HANDLE, data, dataSz, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                          "HMAC Verify invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, NULL, dataSz, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Verify no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, NULL, outSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Verify no out");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                         "HMAC Verify no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyUpdate(CK_INVALID_HANDLE, data, dataSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                   "HMAC Verify Update invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyUpdate(session, NULL, dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Verify Update no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyUpdate(session, data, dataSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                  "HMAC Verify Update no init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(CK_INVALID_HANDLE, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                    "HMAC Verify Final invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, NULL, outSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "HMAC Verify Final no out");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED, "HMAC Verify Final");
    }

    return ret;
}

static CK_RV test_recover(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE key;
    byte   keyData[32];
    byte data[32], sig[32];
    CK_ULONG dataSz, sigSz;

    memset(keyData, 9, sizeof(keyData));
    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    sigSz = sizeof(sig);

    mech.mechanism      = CKM_SHA256_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecoverInit(CK_INVALID_HANDLE, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                    "Sign Recover Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecoverInit(session, NULL, key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                              "Sign Recover Init no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecoverInit(session, &mech, CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                     "Sign Recover Init invalid object handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecoverInit(session, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                                             "Sign Recover Init not supported");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecover(CK_INVALID_HANDLE, data, dataSz, sig,
                                                                        &sigSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                         "Sign Recover invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecover(session, NULL, dataSz, sig, &sigSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Sign Recover no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecover(session, data, 0, sig, &sigSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Sign Recover zero data length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecover(session, data, dataSz, sig, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                              "Sign Recover no signature size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignRecover(session, data, dataSz, sig, &sigSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                "Sign Recover not initialized");
    }

    mech.mechanism = CKM_RSA_PKCS;
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecoverInit(CK_INVALID_HANDLE, &mech, key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                  "Verify Recover Init invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecoverInit(session, NULL, key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                           "Verify Recover Init no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecoverInit(session, &mech, CK_INVALID_HANDLE);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                   "Verify Recover Init invalid object handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecover(CK_INVALID_HANDLE, sig, sigSz, data,
                                                                       &dataSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                       "Verify Recover invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecover(session, NULL, sigSz, data, &dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Verify Recover no sig");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecover(session, sig, 0, data, &dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                              "Verify Recover zero sig length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecover(session, sig, sigSz, data, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Verify Recover no data size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecover(session, sig, sigSz, data, &dataSz);
#ifndef NO_RSA
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                              "Verify Recover not initialized");
#else
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                                              "Verify Recover not initialized");
#endif
    }

    return ret;
}

#ifndef NO_RSA
static CK_RV rsa_verify_recover(CK_SESSION_HANDLE session,
                                CK_MECHANISM_TYPE mech_type)
{
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE private_key_handle;
    CK_OBJECT_HANDLE public_key_handle;

    CK_ATTRIBUTE rsa_2048_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,           rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT,  rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,           rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,           rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,        rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,        rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,       rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,   rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_EXTRACTABLE,       &ckTrue,           sizeof(ckTrue)            },
    };
    CK_ULONG tmplCnt = sizeof(rsa_2048_priv_key) / sizeof(*rsa_2048_priv_key);

    CK_ATTRIBUTE rsa_2048_pub_key[] = {
        { CKA_CLASS,             &pubKeyClass,      sizeof(pubKeyClass)       },
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_ENCRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,           rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PUBLIC_EXPONENT,   rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_ID,                NULL,              0                         },
    };
    int cnt = sizeof(rsa_2048_pub_key)/sizeof(*rsa_2048_pub_key);

    CK_MECHANISM sign_mechanism = {mech_type, NULL_PTR, 0};
    CK_MECHANISM verify_mechanism = {mech_type, NULL_PTR, 0};

    CK_BYTE signature[256];  // RSA-2048 key
    CK_ULONG signature_len = sizeof(signature);

    CK_BYTE recovered_data[256];
    CK_ULONG recovered_data_len = sizeof(recovered_data);

    const char* data_to_sign = "Hello, PKCS#11!";
    CK_ULONG data_length = 16;

    ret = funcList->C_CreateObject(session, rsa_2048_priv_key, tmplCnt,
                                   &private_key_handle);
    CHECK_CKR(ret, "Create object");

    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, rsa_2048_pub_key, cnt,
                                       &public_key_handle);
        CHECK_CKR(ret, "RSA Public Key Create Object");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &sign_mechanism,
                                   private_key_handle);
        CHECK_CKR(ret, "Sign init");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, (CK_BYTE_PTR)data_to_sign, data_length,
                               signature, &signature_len);
        CHECK_CKR(ret, "Sign");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecoverInit(session, &verify_mechanism,
                                            public_key_handle);
        CHECK_CKR(ret, "Verify recover init");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_VerifyRecover(session, signature, signature_len,
                                        recovered_data, &recovered_data_len);
        CHECK_CKR(ret, "Verify recover");
    }

    if (ret == CKR_OK) {
        CHECK_COND(recovered_data_len == data_length, ret, "Data length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(recovered_data, data_to_sign, data_length) == 0, ret,
                   "Data mismatch");
    }

    return ret;
}

static CK_RV test_verify_recover_pkcs(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    return rsa_verify_recover(session, CKM_RSA_PKCS);
}

static CK_RV test_verify_recover_x509(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    return rsa_verify_recover(session, CKM_RSA_X_509);
}
#endif

static CK_RV test_encdec_digest(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    byte data[32], enc[32];
    CK_ULONG dataSz, encSz;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    encSz = sizeof(enc);

    ret = funcList->C_DigestEncryptUpdate(CK_INVALID_HANDLE, data, dataSz, enc,
                                                                        &encSz);
    CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                "Digest Encrypt Update invalid session handle");
    if (ret == CKR_OK) {
        ret = funcList->C_DigestEncryptUpdate(session, NULL, dataSz, enc,
                                                                        &encSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                               "Digest Encrypt Update no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestEncryptUpdate(session, data, 0, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                      "Digest Encrypt Update zero data length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestEncryptUpdate(session, data, dataSz, enc, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                     "Digest Encrypt Update no encrypted size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DigestEncryptUpdate(session, data, dataSz, enc,
                                                                        &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                       "Digest Encrypt Update not initialized");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DecryptDigestUpdate(CK_INVALID_HANDLE, enc, encSz,
                                                                 data, &dataSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                "Decrypt Digest Update invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptDigestUpdate(session, NULL, encSz, data,
                                                                       &dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                          "Decrypt Digest Update no encrypted");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptDigestUpdate(session, enc, 0, data, &dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                 "Decrypt Digest Update zero encrypted length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptDigestUpdate(session, enc, encSz, data, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                          "Decrypt Digest Update no data size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptDigestUpdate(session, enc, encSz, data,
                                                                       &dataSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                       "Decrypt Digest Update not initialized");
    }

    return ret;
}

static CK_RV test_encdec_signverify(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    byte data[32], enc[32];
    CK_ULONG dataSz, encSz;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    encSz = sizeof(enc);

    ret = funcList->C_SignEncryptUpdate(CK_INVALID_HANDLE, data, dataSz, enc,
                                                                        &encSz);
    CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                  "Sign Encrypt Update invalid session handle");
    if (ret == CKR_OK) {
        ret = funcList->C_SignEncryptUpdate(session, NULL, dataSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                                 "Sign Encrypt Update no data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignEncryptUpdate(session, data, 0, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                        "Sign Encrypt Update zero data length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignEncryptUpdate(session, data, dataSz, enc, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                       "Sign Encrypt Update no encrypted size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignEncryptUpdate(session, data, dataSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                         "Sign Encrypt Update not initialized");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DecryptVerifyUpdate(CK_INVALID_HANDLE, enc, encSz,
                                                                 data, &dataSz);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                "Decrypt Verify Update invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptVerifyUpdate(session, NULL, encSz, data,
                                                                       &dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                          "Decrypt Verify Update no encrypted");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptVerifyUpdate(session, enc, 0, data, &dataSz);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                 "Decrypt Verify Update zero encrypted length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptVerifyUpdate(session, enc, encSz, data, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                          "Decrypt Verify Update no data size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptVerifyUpdate(session, enc, encSz, data,
                                                                       &dataSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                       "Decrypt Verify Update not initialized");
    }


    return ret;
}

static CK_RV test_generate_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE  key = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_ULONG          keyLen = 32;
    CK_ATTRIBUTE      tmpl[] = {
        { CKA_VALUE_LEN,       &keyLen,            sizeof(keyLen)             },
    };
    int               tmplCnt = sizeof(tmpl)/sizeof(*tmpl);

    mech.mechanism      = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_GenerateKey(CK_INVALID_HANDLE, &mech, tmpl, tmplCnt,
                                                                          &key);
    CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                         "Generate Key invalid session handle");
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKey(session, NULL, tmpl, tmplCnt, &key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Generate Key no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKey(session, &mech, NULL, tmplCnt, &key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Generate Key no template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKey(session, &mech, tmpl, tmplCnt, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Generate Key no object");
    }

    return ret;
}

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
static CK_RV test_generate_key_pair(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_ULONG          bits = 2048;
    CK_OBJECT_HANDLE  priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  pub = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_ATTRIBUTE      pubKeyTmpl[] = {
        { CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
        { CKA_ENCRYPT,         &ckTrue,  sizeof(ckTrue)  },
        { CKA_VERIFY,          &ckTrue,  sizeof(ckTrue)  },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp) }
    };
    int               pubTmplCnt = sizeof(pubKeyTmpl)/sizeof(*pubKeyTmpl);
    CK_ATTRIBUTE      privKeyTmpl[] = {
        {CKA_DECRYPT,  &ckTrue, sizeof(ckTrue) },
        {CKA_SIGN,     &ckTrue, sizeof(ckTrue) },
    };
    int               privTmplCnt = 2;

    mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_GenerateKeyPair(CK_INVALID_HANDLE, &mech, pubKeyTmpl,
                                           pubTmplCnt, privKeyTmpl, privTmplCnt,
                                           &pub, &priv);
    CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                    "Generate Key Pair invalid session handle");
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, NULL, pubKeyTmpl,
                                           pubTmplCnt, privKeyTmpl, privTmplCnt,
                                           &pub, &priv);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Generate Key no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mech, NULL, pubTmplCnt,
                                                 privKeyTmpl, privTmplCnt, &pub,
                                                 &priv);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                         "Generate Key no public key template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                                            pubTmplCnt, NULL, privTmplCnt, &pub,
                                            &priv);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                        "Generate Key no private key template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                                           pubTmplCnt, privKeyTmpl, privTmplCnt,
                                           NULL, &priv);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                           "Generate Key no public key object");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                                           pubTmplCnt, privKeyTmpl, privTmplCnt,
                                           &pub, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                          "Generate Key no private key object");
    }
    if (ret == CKR_OK) {
        mech.mechanism = CKM_RSA_PKCS;
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                                           pubTmplCnt, privKeyTmpl, privTmplCnt,
                                           &pub, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                                                  "Generate Key bad mechanism");
        mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    }

    return ret;
}
#endif

#ifdef HAVE_AES_KEYWRAP
static CK_RV test_aes_wrap_unwrap_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech = { CKM_AES_KEY_WRAP, NULL, 0 };
    CK_OBJECT_HANDLE wrappingKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte wrappedKey[40], keyData[32];
    CK_ULONG wrappedKeyLen;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)},
        { CKA_KEY_TYPE,          &aesKeyType,       sizeof(aesKeyType)    },
    };
    CK_ULONG     tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    memset(keyData, 7, sizeof(keyData));
    wrappedKeyLen = sizeof(wrappedKey);

    ret = get_aes_128_key(session, NULL, 0, &wrappingKey);
    if (ret == CKR_OK) {
        ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE,
                                                                          &key);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(session, &mech, wrappingKey, key, wrappedKey,
                                                                &wrappedKeyLen);
        CHECK_CKR(ret, "AES Wrap Key mechanism");
    }

    /* done with key, destroy now, since uwrap returns new handle */
    funcList->C_DestroyObject(session, key);
    key = CK_INVALID_HANDLE;

    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrappedKey,
                                            wrappedKeyLen, tmpl, tmplCnt, &key);
        CHECK_CKR(ret, "AES UnWrap Key mechanism");
    }

    funcList->C_DestroyObject(session, wrappingKey);
    funcList->C_DestroyObject(session, key);

    return ret;
}
static CK_RV test_aes_wrap_unwrap_pad_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech = { CKM_AES_KEY_WRAP_PAD, NULL, 0 };
    CK_OBJECT_HANDLE wrappingKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte wrappedKey[48], keyData[35];
    CK_ULONG wrappedKeyLen;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)},
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)},
    };
    CK_ULONG     tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    memset(keyData, 7, sizeof(keyData));
    wrappedKeyLen = sizeof(wrappedKey);

    ret = get_aes_128_key(session, NULL, 0, &wrappingKey);
    if (ret == CKR_OK) {
        ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE,
                                                                          &key);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(session, &mech, wrappingKey, key, wrappedKey,
                                                                &wrappedKeyLen);
        CHECK_CKR(ret, "AES Wrap Key mechanism");
    }

    /* done with key, destroy now, since uwrap returns new handle */
    funcList->C_DestroyObject(session, key);
    key = CK_INVALID_HANDLE;

    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrappedKey,
                                            wrappedKeyLen, tmpl, tmplCnt, &key);
        CHECK_CKR(ret, "AES UnWrap Key mechanism");
    }

    funcList->C_DestroyObject(session, wrappingKey);
    funcList->C_DestroyObject(session, key);

    return ret;
}
#endif /* HAVE_AES_KEYWRAP */

static CK_RV test_wrap_unwrap_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE wrappingKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte wrappedKey[32], wrappingKeyData[32], keyData[32];
    CK_ULONG wrappedKeyLen;
    CK_KEY_TYPE  keyType = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_VALUE, CK_NULL_PTR, 0},
    };
    CK_ULONG     tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    memset(wrappingKeyData, 9, sizeof(wrappingKeyData));
    memset(keyData, 7, sizeof(keyData));
    memset(&mech, 0, sizeof(mech));
    wrappedKeyLen = sizeof(wrappedKey);

    ret = get_generic_key(session, wrappingKeyData, sizeof(wrappingKeyData),
                                                        CK_FALSE, &wrappingKey);
    if (ret == CKR_OK) {
        ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE,
                                                                          &key);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(CK_INVALID_HANDLE, &mech, wrappingKey, key,
                                                    wrappedKey, &wrappedKeyLen);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                             "Wrap Key invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(session, NULL, wrappingKey, key, wrappedKey,
                                                                &wrappedKeyLen);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Wrap Key no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(session, &mech, CK_INVALID_HANDLE, key,
                                                    wrappedKey, &wrappedKeyLen);
        CHECK_CKR_FAIL(ret, CKR_WRAPPING_KEY_HANDLE_INVALID,
                                        "Wrap Key invalid wrapping key handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(session, &mech, wrappingKey,
                                 CK_INVALID_HANDLE, wrappedKey, &wrappedKeyLen);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                                 "Wrap Key invalid key handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(session, &mech, wrappingKey, key, wrappedKey,
                                                                          NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Wrap Key no wrapped key size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_WrapKey(session, &mech, wrappingKey, key, wrappedKey,
                                                                &wrappedKeyLen);
#ifndef WOLFPKCS11_NO_STORE
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                                            "Wrap Key mechanism not supported");
#else
        CHECK_CKR_FAIL(ret, CKR_KEY_NOT_WRAPPABLE,
                                            "Wrap Key mechanism not supported");
#endif
    }

    /* done with key, destroy now, since uwrap returns new handle */
    funcList->C_DestroyObject(session, key);

    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(CK_INVALID_HANDLE, &mech, wrappingKey,
                                       wrappedKey, wrappedKeyLen, tmpl, tmplCnt,
                                       &key);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                           "Unwrap Key invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, NULL, wrappingKey, wrappedKey,
                                            wrappedKeyLen, tmpl, tmplCnt, &key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Unwrap Key no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, &mech, CK_INVALID_HANDLE,
                                       wrappedKey, wrappedKeyLen, tmpl, tmplCnt,
                                       &key);
        CHECK_CKR_FAIL(ret, CKR_UNWRAPPING_KEY_HANDLE_INVALID,
                                      "Unwrap Key invalid wrapping key handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, NULL,
                                            wrappedKeyLen, tmpl, tmplCnt, &key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Unwrap Key no wrapped key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrappedKey, 0,
                                                           tmpl, tmplCnt, &key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD,
                                          "Unwrap Key zero wrapped key length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrappedKey,
                                            wrappedKeyLen, NULL, tmplCnt, &key);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Unwrap Key no template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrappedKey,
                                            wrappedKeyLen, tmpl, tmplCnt, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Unwrap Key no key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_UnwrapKey(session, &mech, wrappingKey, wrappedKey,
                                            wrappedKeyLen, tmpl, tmplCnt, &key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID,
                                          "Unwrap Key mechanism not supported");
    }

    funcList->C_DestroyObject(session, wrappingKey);
    funcList->C_DestroyObject(session, key);

    return ret;
}

#ifndef NO_DH
static CK_RV test_derive_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    byte out[32], peer[32];
    word32 outSz = sizeof(out);
    CK_MECHANISM     mech;
    CK_OBJECT_HANDLE privKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_KEY_TYPE      keyType = CKK_GENERIC_SECRET;
    CK_ULONG         secSz = outSz;
    CK_ATTRIBUTE     tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)        },
        { CKA_VALUE_LEN,   &secSz,          sizeof(secSz)          }
    };
    CK_ULONG         tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    memset(peer, 9, sizeof(peer));

    mech.mechanism      = CKM_DH_PKCS_DERIVE;
    mech.ulParameterLen = sizeof(peer);
    mech.pParameter     = peer;

    ret = get_generic_key(session, peer, sizeof(peer), CK_FALSE, &privKey);
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(CK_INVALID_HANDLE, &mech, privKey, tmpl,
                                                              tmplCnt, &secret);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                           "Derive Key invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, NULL, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Unwrap Key no mechanism");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mech, CK_INVALID_HANDLE, tmpl,
                                                              tmplCnt, &secret);
        CHECK_CKR_FAIL(ret, CKR_OBJECT_HANDLE_INVALID,
                                          "Unwrap Key invalid base key handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mech, privKey, NULL, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Unwrap Key no template");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                          NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Unwrap Key no secret");
    }
    if (ret == CKR_OK) {
        mech.mechanism = CKM_RSA_PKCS;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID, "Unwrap Key bad mechanism");
        mech.mechanism = CKM_DH_PKCS_DERIVE;
    }

    return ret;
}
#endif

#if !defined(NO_RSA) || defined(HAVE_ECC)
static CK_RV test_pubkey_sig_fail(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                                  CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub)
{
    CK_RV ret;
    byte   hash[32], out[2048/8];
    CK_ULONG hashSz, outSz;
    CK_OBJECT_HANDLE key;

    memset(hash, 9, sizeof(hash));
    hashSz = sizeof(hash);
    outSz = sizeof(out);

    ret = get_generic_key(session, hash, sizeof(hash), CK_FALSE, &key);
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, mech, key);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT, "Sign Init wrong key");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, mech, key);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT, "Verify Init wrong key");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, mech, priv);
        CHECK_CKR(ret, "Sign Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hash, hashSz, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED, "Verify wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, mech, pub);
        CHECK_CKR(ret, "Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED, "Sign wrong init");
    }

    return ret;
}
#endif

#ifndef NO_RSA
static CK_RV get_rsa_priv_key(CK_SESSION_HANDLE session, unsigned char* privId,
                              int privIdLen, CK_BBOOL extractable,
                              CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE rsa_2048_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,           rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT,  rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,           rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,           rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,        rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,        rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,       rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,   rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_EXTRACTABLE,       &extractable,      sizeof(CK_BBOOL)          },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_ID,                privId,            privIdLen                 },
    };
    int cnt = sizeof(rsa_2048_priv_key)/sizeof(*rsa_2048_priv_key);

    if (privId == NULL)
        cnt -= 2;

    ret = funcList->C_CreateObject(session, rsa_2048_priv_key, cnt, obj);
    CHECK_CKR(ret, "RSA Private Key Create Object");

    return ret;
}

static CK_RV get_rsa_pub_key(CK_SESSION_HANDLE session, unsigned char* pubId,
                           int pubIdLen, CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE rsa_2048_pub_key[] = {
        { CKA_CLASS,             &pubKeyClass,      sizeof(pubKeyClass)       },
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_ENCRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,           rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PUBLIC_EXPONENT,   rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_ID,                pubId,             pubIdLen                  },
    };
    int cnt = sizeof(rsa_2048_pub_key)/sizeof(*rsa_2048_pub_key);

    if (pubId == NULL)
        cnt -= 2;

    ret = funcList->C_CreateObject(session, rsa_2048_pub_key, cnt, obj);
    CHECK_CKR(ret, "RSA Public Key Create Object");

    return ret;
}

#ifdef WOLFSSL_KEY_GEN
static CK_RV gen_rsa_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* pubKey,
                       CK_OBJECT_HANDLE* privKey, unsigned char* id, int idLen)
{
    CK_RV             ret = CKR_OK;
    CK_ULONG          bits = 2048;
    CK_OBJECT_HANDLE  priv = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_ATTRIBUTE      pubKeyTmpl[] = {
        { CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
        { CKA_ENCRYPT,         &ckTrue,  sizeof(ckTrue)  },
        { CKA_VERIFY,          &ckTrue,  sizeof(ckTrue)  },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp) },
        { CKA_LABEL,           (unsigned char*)"", 0 },
    };
    int               pubTmplCnt = sizeof(pubKeyTmpl)/sizeof(*pubKeyTmpl);
    CK_ATTRIBUTE      privKeyTmpl[] = {
        { CKA_DECRYPT,  &ckTrue, sizeof(ckTrue) },
        { CKA_SIGN,     &ckTrue, sizeof(ckTrue) },
        { CKA_LABEL,    (unsigned char*)"priv_label", 10 },
        { CKA_ID,       id,      idLen          }
    };
    int               privTmplCnt = 3;

    if (idLen > 0)
        privTmplCnt++;
    if (ret == CKR_OK) {
        mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter     = NULL;

        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                           pubTmplCnt, privKeyTmpl, privTmplCnt, pubKey, &priv);
        CHECK_CKR(ret, "RSA Generate Key Pair");
    }
    if (ret == CKR_OK && privKey != NULL)
        *privKey = priv;
    if (ret == CKR_OK) {
        mech.pParameter = pubKeyTmpl;
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                           pubTmplCnt, privKeyTmpl, privTmplCnt, pubKey, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "RSA Generate Key Pair bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = sizeof(pubKeyTmpl);
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                           pubTmplCnt, privKeyTmpl, privTmplCnt, pubKey, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                  "RSA Generate Key Pair bad parameter Length");
        mech.ulParameterLen = 0;
    }

    return ret;
}
#endif

static CK_RV find_rsa_pub_key(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE* pubKey, unsigned char* id,
                              int idLen)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE      pubKeyTmpl[] = {
        { CKA_CLASS,     &pubKeyClass,   sizeof(pubKeyClass)  },
        { CKA_KEY_TYPE,  &rsaKeyType,    sizeof(rsaKeyType)   },
        { CKA_ID,        id,             idLen                }
    };
    CK_ULONG pubKeyTmplCnt = sizeof(pubKeyTmpl) / sizeof(*pubKeyTmpl);
    CK_ULONG count;

    ret = funcList->C_FindObjectsInit(session, pubKeyTmpl, pubKeyTmplCnt);
    CHECK_CKR(ret, "RSA Public Key Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, pubKey, 1, &count);
        CHECK_CKR(ret, "RSA Public Key Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "RSA Public Key Find Objects Final");
    }
    if (ret == CKR_OK && count == 0) {
        ret = -1;
        CHECK_CKR(ret, "RSA Public Key Find Objects Count");
    }

    return ret;
}

static CK_RV find_rsa_priv_key(CK_SESSION_HANDLE session,
                             CK_OBJECT_HANDLE* privKey, unsigned char* id,
                             int idLen)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE      privKeyTmpl[] = {
        { CKA_CLASS,     &privKeyClass,  sizeof(privKeyClass) },
        { CKA_KEY_TYPE,  &rsaKeyType,    sizeof(rsaKeyType)   },
        { CKA_ID,        id,             idLen                }
    };
    CK_ULONG privKeyTmplCnt = sizeof(privKeyTmpl) / sizeof(*privKeyTmpl);
    CK_ULONG count;

    ret = funcList->C_FindObjectsInit(session, privKeyTmpl, privKeyTmplCnt);
    CHECK_CKR(ret, "RSA Private Key Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, privKey, 1, &count);
        CHECK_CKR(ret, "RSA Private Key Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "RSA Private Key Find Objects Final");
    }
    if (ret == CKR_OK && count == 0) {
        ret = -1;
        CHECK_CKR(ret, "RSA Private Key Find Objects Count");
    }

    return ret;
}

#ifdef WOLFSSL_KEY_GEN
static CK_RV find_rsa_pub_key_label(CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE* pubKey)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE      pubKeyTmpl[] = {
#ifndef WOLFPKCS11_KEYPAIR_GEN_COMMON_LABEL
        { CKA_LABEL,     (unsigned char*)"", 0 },
#else
        { CKA_CLASS,     &pubKeyClass,  sizeof(privKeyClass) },
        { CKA_KEY_TYPE,  &rsaKeyType,    sizeof(rsaKeyType)  },
#endif
    };
    CK_ULONG pubKeyTmplCnt = sizeof(pubKeyTmpl) / sizeof(*pubKeyTmpl);
    CK_ULONG count;

    ret = funcList->C_FindObjectsInit(session, pubKeyTmpl, pubKeyTmplCnt);
    CHECK_CKR(ret, "RSA Public Key Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, pubKey, 1, &count);
        CHECK_CKR(ret, "RSA Public Key Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "RSA Public Key Find Objects Final");
    }
    if (ret == CKR_OK && count == 0) {
        ret = -1;
        CHECK_CKR(ret, "RSA Public Key Find Objects Count");
    }

    return ret;
}

static CK_RV find_rsa_priv_key_label(CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE* privKey)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE      privKeyTmpl[] = {
        { CKA_CLASS,     &privKeyClass,  sizeof(privKeyClass) },
        { CKA_KEY_TYPE,  &rsaKeyType,    sizeof(rsaKeyType)   },
        { CKA_LABEL,     (unsigned char*)"priv_label", 10 },
    };
    CK_ULONG privKeyTmplCnt = sizeof(privKeyTmpl) / sizeof(*privKeyTmpl);
    CK_ULONG count;

    ret = funcList->C_FindObjectsInit(session, privKeyTmpl, privKeyTmplCnt);
    CHECK_CKR(ret, "RSA Private Key Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, privKey, 1, &count);
        CHECK_CKR(ret, "RSA Private Key Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "RSA Private Key Find Objects Final");
    }
    if (ret == CKR_OK && count == 0) {
        ret = -1;
        CHECK_CKR(ret, "RSA Private Key Find Objects Count");
    }

    return ret;
}
#endif

static CK_RV test_attributes_rsa(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    unsigned char modulus[2048/8];
    unsigned char pubExp[3];
    unsigned char privExp[2048/8];
    unsigned char prime1[2048/2/8];
    unsigned char prime2[2048/2/8];
    unsigned char exp1[2048/2/8];
    unsigned char exp2[2048/2/8];
    unsigned char coeff[2048/2/8];
    CK_ULONG bits;
    CK_ATTRIBUTE rsaPubTmpl[] = {
        { CKA_MODULUS,             modulus,             sizeof(modulus)       },
        { CKA_PUBLIC_EXPONENT,     pubExp,              sizeof(pubExp)        },
        { CKA_MODULUS_BITS,        &bits,               sizeof(bits)          },
    };
    CK_ULONG rsaPubTmplCnt = sizeof(rsaPubTmpl) / sizeof(*rsaPubTmpl);
    CK_ATTRIBUTE rsaPubBadTmpl[] = {
        { CKA_WRAP_TEMPLATE,       NULL,                0                     },
        { CKA_UNWRAP_TEMPLATE,     NULL,                0                     },
    };
    CK_ULONG rsaPubBadTmplCnt = sizeof(rsaPubBadTmpl) / sizeof(*rsaPubBadTmpl);
    CK_ATTRIBUTE rsaPrivTmpl[] = {
        { CKA_MODULUS,             NULL,                0                     },
        { CKA_PRIVATE_EXPONENT,    NULL,                0                     },
        { CKA_PRIME_1,             NULL,                0                     },
        { CKA_PRIME_2,             NULL,                0                     },
        { CKA_EXPONENT_1,          NULL,                0                     },
        { CKA_EXPONENT_2,          NULL,                0                     },
        { CKA_COEFFICIENT,         NULL,                0                     },
    };
    CK_ULONG rsaPrivTmplCnt = sizeof(rsaPrivTmpl) / sizeof(*rsaPrivTmpl);
    int i;

    ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, pub, rsaPubTmpl,
                                                                 rsaPubTmplCnt);
        CHECK_CKR(ret, "Get Attributes RSA Public Key");
    }
    if (ret == CKR_OK) {
        for (i = 0; i < (int)rsaPubBadTmplCnt; i++) {
            ret = funcList->C_GetAttributeValue(session, pub, &rsaPubBadTmpl[i],
                                                                             1);
            CHECK_CKR_FAIL(ret, CK_UNAVAILABLE_INFORMATION,
                                              "Get Attributes RSA unavailable");
        }
    }
    if (ret == CKR_OK) {
        ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, rsaPrivTmpl,
                                                                rsaPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes RSA private key length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[0].ulValueLen == sizeof(modulus), ret,
                               "Get Attributes RSA private key modulus length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[1].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                      "Get Attributes RSA private key private exponent length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[2].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                               "Get Attributes RSA private key prime 1 length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[3].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                               "Get Attributes RSA private key prime 2 length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[4].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                            "Get Attributes RSA private key exponent 1 length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[5].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                            "Get Attributes RSA private key exponent 2 length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[6].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                            "Get Attributes RSA private key exponent 2 length");
    }
    funcList->C_DestroyObject(session, priv);
    if (ret == CKR_OK) {
        ret = get_rsa_priv_key(session, NULL, 0, CK_TRUE, &priv);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, rsaPrivTmpl,
                                                                rsaPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes RSA private key length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[0].ulValueLen == sizeof(modulus), ret,
                               "Get Attributes RSA private key modulus length");
        rsaPrivTmpl[0].pValue = modulus;
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[1].ulValueLen == sizeof(privExp), ret,
                      "Get Attributes RSA private key private exponent length");
        rsaPrivTmpl[1].pValue = privExp;
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[2].ulValueLen == sizeof(prime1), ret,
                               "Get Attributes RSA private key prime 1 length");
        rsaPrivTmpl[2].pValue = prime1;
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[3].ulValueLen == sizeof(prime2), ret,
                               "Get Attributes RSA private key prime 2 length");
        rsaPrivTmpl[3].pValue = prime2;
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[4].ulValueLen == sizeof(exp1), ret,
                            "Get Attributes RSA private key exponent 1 length");
        rsaPrivTmpl[4].pValue = exp1;
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[5].ulValueLen == sizeof(exp2), ret,
                            "Get Attributes RSA private key exponent 2 length");
        rsaPrivTmpl[5].pValue = exp2;
    }
    if (ret == CKR_OK) {
        CHECK_COND(rsaPrivTmpl[6].ulValueLen == sizeof(coeff), ret,
                            "Get Attributes RSA private key exponent 2 length");
        rsaPrivTmpl[6].pValue = coeff;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, rsaPrivTmpl,
                                                                rsaPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes RSA private key length");
    }
    funcList->C_DestroyObject(session, priv);

    return ret;
}

static CK_RV rsa_raw_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
                       CK_OBJECT_HANDLE pub)
{
    CK_RV  ret = CKR_OK;
    byte   plain[2048/8], out[2048/8], dec[2048/8];
    CK_ULONG plainSz, outSz, decSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    plainSz = sizeof(plain);
    outSz = sizeof(out);
    decSz = sizeof(dec);

    mech.mechanism      = CKM_RSA_X_509;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_EncryptInit(session, &mech, pub);
    CHECK_CKR(ret, "RSA Encrypt Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &outSz);
        CHECK_CKR(ret, "RSA Encrypt no out");
    }
    if (ret == CKR_OK && (outSz == 0 || outSz > sizeof(out))) {
        ret = -1;
        CHECK_CKR(ret, "RSA Encrypt returned output size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "RSA Encrypt zero out size");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, out, &outSz);
        CHECK_CKR(ret, "RSA Encrypt");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR(ret, "RSA Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, out, outSz, NULL, &decSz);
        CHECK_CKR(ret, "RSA Decrypt no dec");
    }
    if (ret == CKR_OK && (decSz == 0 || decSz > sizeof(dec))) {
        ret = -1;
        CHECK_CKR(ret, "RSA Decrypt returned output size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, out, outSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "RSA Decrypt zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, out, outSz, dec, &decSz);
        CHECK_CKR(ret, "RSA Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "RSA Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV rsa_pkcs15_enc_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
                               CK_OBJECT_HANDLE pub)
{
    CK_RV  ret = CKR_OK;
    byte   plain[128], out[2048/8], dec[2048/8];
    CK_ULONG plainSz, outSz, decSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    plainSz = sizeof(plain);
    outSz = sizeof(out);
    decSz = sizeof(dec);

    mech.mechanism      = CKM_RSA_PKCS;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_EncryptInit(session, &mech, pub);
    CHECK_CKR(ret, "RSA PKCS#1.5 Encrypt Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Encrypt no out");
    }
    if (ret == CKR_OK && (outSz == 0 || outSz > sizeof(out))) {
        ret = -1;
        CHECK_CKR(ret, "RSA PKCS#1.5 Encrypt returned output size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                          "RSA PKCS#1.5 Encrypt zero out size");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, out, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Encrypt");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR(ret, "RSA PKCS#1.5 Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, out, outSz, NULL, &decSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Decrypt no dec");
    }
    if (ret == CKR_OK && (decSz == 0 || decSz > sizeof(dec))) {
        ret = -1;
        CHECK_CKR(ret, "RSA PKCS#1.5 Decrypt returned output size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, out, outSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                          "RSA PKCS#1.5 Decrypt zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, out, outSz, dec, &decSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "RSA PKCS#1.5 Decrypted data match plain text");
        }
    }

    return ret;
}

#ifndef WC_NO_RSA_OAEP
static CK_RV rsa_oaep_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
                           CK_OBJECT_HANDLE pub, int hashAlg, int mgf,
                           unsigned char* source, int sourceLen)
{
    CK_RV  ret = CKR_OK;
    byte   plain[64], out[2048/8], dec[2048/8];
    CK_ULONG plainSz, outSz, decSz;
    CK_MECHANISM mech;
    CK_RSA_PKCS_OAEP_PARAMS params;

    memset(plain, 9, sizeof(plain));
    plainSz = sizeof(plain);
    outSz = sizeof(out);
    decSz = sizeof(dec);

    params.hashAlg = hashAlg;
    params.mgf = mgf;
    params.source = CKZ_DATA_SPECIFIED;
    params.pSourceData = source;
    params.ulSourceDataLen = sourceLen;

    mech.mechanism      = CKM_RSA_PKCS_OAEP;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter     = &params;

    ret = funcList->C_EncryptInit(session, &mech, pub);
    CHECK_CKR(ret, "RSA OAEP Encrypt Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &outSz);
        CHECK_CKR(ret, "RSA OAEP Encrypt no out");
    }
    if (ret == CKR_OK && (outSz == 0 || outSz > sizeof(out))) {
        ret = -1;
        CHECK_CKR(ret, "RSA OAEP Encrypt returned output size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                              "RSA OAEP Encrypt zero out size");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, out, &outSz);
        CHECK_CKR(ret, "RSA OAEP Encrypt");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR(ret, "RSA OAEP Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, out, outSz, NULL, &decSz);
        CHECK_CKR(ret, "RSA OAEP Decrypt no dec");
    }
    if (ret == CKR_OK && (decSz == 0 || decSz > sizeof(dec))) {
        ret = -1;
        CHECK_CKR(ret, "RSA OAEP Decrypt returned output size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, out, outSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                              "RSA OAEP Decrypt zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, out, outSz, dec, &decSz);
        CHECK_CKR(ret, "RSA OAEP Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "RSA OAEP Decrypted data match plain text");
        }
    }

    return ret;
}
#endif

#if !defined(NO_RSA) && defined(WC_RSA_DIRECT)
static CK_RV rsa_x_509_sig_test(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub,
                                int hashSz)
{
    CK_RV  ret = CKR_OK;
    byte   hash[64], badHash[32], out[2048/8];
    CK_ULONG outSz;
    CK_MECHANISM mech;

    memset(hash, 9, sizeof(hash));
    memset(badHash, 7, sizeof(badHash));
    outSz = sizeof(out);

    mech.mechanism      = CKM_RSA_X_509;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_SignInit(session, &mech, priv);
    CHECK_CKR(ret, "RSA X_509 Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, NULL, &outSz);
        CHECK_CKR(ret, "RSA X_509 Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == sizeof(out), ret, "RSA X_509 Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                                "RSA X_509 Sign zero out size");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR(ret, "RSA X_509 Sign");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_CKR(ret, "RSA X_509 Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hash, hashSz, out, outSz);
        CHECK_CKR(ret, "RSA X_509 Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, badHash, sizeof(badHash), out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "RSA X_509 Verify bad hash");
    }

    return ret;
}
#endif

static CK_RV rsa_pkcs15_sig_test(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub,
                                 int hashSz)
{
    CK_RV  ret = CKR_OK;
    byte   hash[64], badHash[32], out[2048/8];
    CK_ULONG outSz;
    CK_MECHANISM mech;

    memset(hash, 9, sizeof(hash));
    memset(badHash, 7, sizeof(badHash));
    outSz = sizeof(out);

    mech.mechanism      = CKM_RSA_PKCS;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_SignInit(session, &mech, priv);
    CHECK_CKR(ret, "RSA PKCS#1.5 Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, NULL, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == sizeof(out), ret, "RSA PKCS#1.5 Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                             "RSA PKCS#1.5 Sign zero out size");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Sign");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_CKR(ret, "RSA PKCS#1.5 Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hash, hashSz, out, outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, badHash, sizeof(badHash), out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID,
                                                "RSA PKCS#1.5 Verify bad hash");
    }

    return ret;
}

#ifndef NO_SHA256
static CK_RV test_sha256_rsa_pkcs15(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV    ret = CKR_OK;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_BYTE          data[72] = { 0 };
    CK_BYTE          sigOut[256] = { 0 };
    CK_ULONG         sigOutLen = sizeof(sigOut);
    CK_BYTE          expectedKey[] = {
        0x30, 0xb5, 0xf9, 0x9e, 0xde, 0x21, 0x49, 0x91, 0x65, 0x19, 0x3b, 0x30,
        0x45, 0x42, 0xe8, 0x6e, 0x51, 0x8d, 0xce, 0x12, 0xf1, 0x29, 0xba, 0x95,
        0x09, 0x9a, 0xbb, 0x9c, 0x5b, 0x0f, 0x3a, 0x12, 0x44, 0xe1, 0xc9, 0xea,
        0x03, 0x8c, 0x65, 0x4c, 0xd2, 0x14, 0x28, 0x6a, 0x11, 0xf3, 0x61, 0x9b,
        0xd8, 0x5d, 0x6b, 0x7f, 0x19, 0xd3, 0xff, 0x02, 0xfa, 0xbb, 0xb6, 0xd4,
        0xa1, 0x9f, 0x2b, 0xcc, 0x9e, 0x98, 0x66, 0xa1, 0x84, 0x32, 0x77, 0x2b,
        0xf9, 0xd3, 0xe4, 0x00, 0x19, 0x69, 0x4d, 0xa5, 0x09, 0xf9, 0x28, 0x00,
        0x7d, 0xe2, 0x4d, 0x6e, 0x06, 0x3b, 0xae, 0x88, 0xc6, 0x10, 0xdd, 0x57,
        0xc4, 0x2c, 0x71, 0x8a, 0xa5, 0x4e, 0xf5, 0x6e, 0xc8, 0x91, 0x63, 0x02,
        0xb7, 0xd0, 0xfc, 0x81, 0x23, 0xd8, 0xa7, 0xa1, 0x50, 0x64, 0xfe, 0x5f,
        0xda, 0x7c, 0xb6, 0x1f, 0xd6, 0x7d, 0x90, 0x8f, 0x92, 0xe6, 0xb2, 0xaa,
        0x61, 0xea, 0xfb, 0xd1, 0xa9, 0x51, 0x27, 0xd8, 0xe3, 0x63, 0xa8, 0xe0,
        0xa4, 0xba, 0x26, 0xe7, 0x7a, 0xec, 0x51, 0x1c, 0xec, 0x51, 0x31, 0x6b,
        0x19, 0x07, 0x60, 0x81, 0x12, 0xab, 0xcb, 0xdf, 0x09, 0x9e, 0xec, 0x0a,
        0xfe, 0xe5, 0x68, 0xfa, 0x2b, 0xb7, 0xf4, 0x70, 0x24, 0xea, 0xd5, 0x16,
        0xaa, 0xa8, 0x0d, 0xa1, 0xd3, 0x2d, 0x88, 0xfe, 0x57, 0x71, 0x35, 0x4a,
        0xdb, 0xde, 0x0a, 0xdb, 0x8d, 0x9b, 0x8a, 0x1e, 0xfa, 0x52, 0xb5, 0x49,
        0x7d, 0x1a, 0x54, 0x34, 0xaf, 0x81, 0xe2, 0xc2, 0x1f, 0x92, 0xdc, 0x0e,
        0x4c, 0xb8, 0x4c, 0xec, 0x42, 0xb9, 0x1f, 0x5b, 0x69, 0xd6, 0xb3, 0x97,
        0x9e, 0x97, 0x0d, 0x5d, 0xfc, 0x68, 0xf2, 0xf9, 0x59, 0xfb, 0xa8, 0xcb,
        0xe6, 0xc2, 0x13, 0xba, 0xb2, 0x8a, 0x4a, 0xee, 0x62, 0x09, 0x5d, 0xa9,
        0xc4, 0x8c, 0x89, 0x72
    };

    /* Store a fixed key */
    CK_ATTRIBUTE rsa_2048_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,           rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT,  rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,           rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,           rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,        rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,        rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,       rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,   rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_EXTRACTABLE,       &ckTrue,           sizeof(ckTrue)            },
    };
    CK_ULONG tmplCnt = sizeof(rsa_2048_priv_key) / sizeof(*rsa_2048_priv_key);

    CK_MECHANISM mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };

    ret = funcList->C_CreateObject(session, rsa_2048_priv_key, tmplCnt, &key);
    CHECK_CKR(ret, "Create object");

    /* Sign with RSA */
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, key);
        CHECK_CKR(ret, "Sign init");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, sizeof(data), sigOut, &sigOutLen);
        CHECK_CKR(ret, "Sign fail");
    }

    if (ret == CKR_OK) {
        CHECK_COND(sigOutLen == sizeof(expectedKey), ret, "Key size");
    }
    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(sigOut, expectedKey, sizeof(expectedKey)) == 0, ret,
                   "Compare signature");
    }

    return ret;
}

static CK_RV sha256_rsa_pkcs15_sig_test(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub,
    int hashSz)
{
    CK_RV  ret = CKR_OK;
    byte   hash[64], badHash[32], out[2048/8];
    CK_ULONG outSz;
    CK_MECHANISM mech;

    memset(hash, 9, sizeof(hash));
    memset(badHash, 7, sizeof(badHash));
    outSz = sizeof(out);

    mech.mechanism      = CKM_SHA256_RSA_PKCS;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_SignInit(session, &mech, priv);
    CHECK_CKR(ret, "RSA PKCS#1.5 Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, NULL, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == sizeof(out), ret, "RSA PKCS#1.5 Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                             "RSA PKCS#1.5 Sign zero out size");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Sign");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_CKR(ret, "RSA PKCS#1.5 Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hash, hashSz, out, outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, badHash, sizeof(badHash), out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID,
                                                "RSA PKCS#1.5 Verify bad hash");
    }

    return ret;
}
#endif

#ifdef WC_RSA_PSS
static CK_RV rsa_pss_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
                        CK_OBJECT_HANDLE pub, int hashAlg, int mgf, int hashSz)
{
    CK_RV  ret = CKR_OK;
    byte   hash[64], badHash[64], out[2048/8];
    CK_ULONG outSz;
    CK_MECHANISM mech;
    CK_RSA_PKCS_PSS_PARAMS params;

    memset(hash, 9, sizeof(hash));
    memset(badHash, 7, sizeof(badHash));
    outSz = sizeof(out);

    params.hashAlg = hashAlg;
    params.mgf = mgf;
    params.sLen = hashSz <= 62 ? hashSz : 62;

    mech.mechanism      = CKM_RSA_PKCS_PSS;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter     = &params;

    ret = funcList->C_SignInit(session, &mech, priv);
    CHECK_CKR(ret, "RSA PKCS#1 PSS Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, NULL, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 PSS Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == sizeof(out), ret, "RSA PKCS#1 PSS Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                           "RSA PKCS#1 PSS Sign zero out size");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1 PSS Sign");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_CKR(ret, "RSA PKCS#1 PSS Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hash, hashSz, out, outSz);
        CHECK_CKR(ret, "RSA PKCS#1 PSS Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, badHash, hashSz, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID,
                                              "RSA PKCS#1 PSS Verify bad hash");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR(ret, "RSA PKCS#1 PSS Sign Init");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                      "RSA PKCS#1 PSS Sign out size too small");
        outSz = sizeof(out);
    }

    return ret;
}

#ifndef NO_SHA256
static CK_RV sha256_rsa_pss_test(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub, int hashAlg, int mgf,
    int hashSz)
{
    CK_RV  ret = CKR_OK;
    byte   hash[64], badHash[64], out[2048/8];
    CK_ULONG outSz;
    CK_MECHANISM mech;
    CK_RSA_PKCS_PSS_PARAMS params;

    memset(hash, 9, sizeof(hash));
    memset(badHash, 7, sizeof(badHash));
    outSz = sizeof(out);

    params.hashAlg = hashAlg;
    params.mgf = mgf;
    params.sLen = hashSz <= 62 ? hashSz : 62;

    mech.mechanism      = CKM_SHA256_RSA_PKCS_PSS;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter     = &params;

    ret = funcList->C_SignInit(session, &mech, priv);
    CHECK_CKR(ret, "RSA PKCS#1 PSS Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, NULL, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1.5 PSS Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == sizeof(out), ret, "RSA PKCS#1 PSS Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                            "RSA PKCS#1 PSS Sign zero out size");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR(ret, "RSA PKCS#1 PSS Sign");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, pub);
        CHECK_CKR(ret, "RSA PKCS#1 PSS Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hash, hashSz, out, outSz);
        CHECK_CKR(ret, "RSA PKCS#1 PSS Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, badHash, hashSz, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID,
                                "RSA PKCS#1 PSS Verify bad hash");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR(ret, "RSA PKCS#1 PSS Sign Init");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                        "RSA PKCS#1 PSS Sign out size too small");
        outSz = sizeof(out);
    }

    return ret;
}
#endif
#endif

static CK_RV test_rsa_no_modulus(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_BBOOL extractable = CK_TRUE;
    CK_OBJECT_HANDLE hTest = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    CK_ATTRIBUTE rsa_2048_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_PRIVATE_EXPONENT,  rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,           rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,           rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,        rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,        rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,       rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_EXTRACTABLE,       &extractable,      sizeof(CK_BBOOL)          },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_PUBLIC_EXPONENT,   rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_ID,                NULL,              0                         },
    };
    int cnt = sizeof(rsa_2048_priv_key)/sizeof(*rsa_2048_priv_key);


    ret = funcList->C_CreateObject(session, rsa_2048_priv_key, cnt, &hTest);

    CHECK_CKR(ret, "Create object");

    if ((ret == CKR_OK) && (userPinLen != 0)) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
        CHECK_CKR(ret, "Open Session");
    }

    /* Login will encode and decode the RSA and fail if there is modulus */
    if (ret == CKR_OK && userPinLen != 0) {
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login");
    }

    funcList->C_DestroyObject(session, hTest);

    return ret;
}

static CK_RV test_rsa_no_public_exponent(void *args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_BBOOL extractable = CK_TRUE;
    CK_OBJECT_HANDLE hTest = CK_INVALID_HANDLE;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    CK_ATTRIBUTE rsa_2048_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,           rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT,  rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,           rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,           rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,        rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,        rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,       rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_EXTRACTABLE,       &extractable,      sizeof(CK_BBOOL)          },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_ID,                NULL,              0                         },
    };
    int cnt = sizeof(rsa_2048_priv_key)/sizeof(*rsa_2048_priv_key);


    ret = funcList->C_CreateObject(session, rsa_2048_priv_key, cnt, &hTest);

    CHECK_CKR(ret, "Create object");

    if ((ret == CKR_OK) && (userPinLen != 0)) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
        CHECK_CKR(ret, "Open Session");
    }

    /* Login will encode and decode the RSA and fail if there is no public
    exponent */
    if (ret == CKR_OK && userPinLen != 0) {
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login");
    }

    funcList->C_DestroyObject(session, hTest);

    return ret;
}

static CK_RV test_rsa_fixed_keys_raw(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK)
        ret = rsa_raw_test(session, priv, pub);

    return ret;
}

static CK_RV test_rsa_fixed_keys_pkcs15_enc(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK)
        ret = rsa_pkcs15_enc_test(session, priv, pub);

    return ret;
}

#ifndef WC_NO_RSA_OAEP
static CK_RV test_rsa_fixed_keys_oaep(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK) {
        ret = rsa_oaep_test(session, priv, pub, CKM_SHA256, CKG_MGF1_SHA256,
                                                                       NULL, 0);
        CHECK_CKR(ret, "SHA256 No AAD");
    }
    if (ret == CKR_OK) {
        ret = rsa_oaep_test(session, priv, pub, CKM_SHA256, CKG_MGF1_SHA256,
                                                      (unsigned char*)"aad", 3);
        CHECK_CKR(ret, "SHA256 with AAD");
    }
    if (ret == CKR_OK) {
        ret = rsa_oaep_test(session, priv, pub, CKM_SHA1, CKG_MGF1_SHA1, NULL,
                                                                             0);
        CHECK_CKR(ret, "SHA1 No AAD");
    }
#ifdef WOLFSSL_SHA224
    if (ret == CKR_OK) {
        ret = rsa_oaep_test(session, priv, pub, CKM_SHA224, CKG_MGF1_SHA224,
                                                                       NULL, 0);
        CHECK_CKR(ret, "SHA224 No AAD");
    }
#endif
    if (ret == CKR_OK) {
        ret = rsa_oaep_test(session, priv, pub, CKM_SHA384, CKG_MGF1_SHA384,
                                                                       NULL, 0);
        CHECK_CKR(ret, "SHA384 No AAD");
    }
    if (ret == CKR_OK) {
        ret = rsa_oaep_test(session, priv, pub, CKM_SHA512, CKG_MGF1_SHA512,
                                                                       NULL, 0);
        CHECK_CKR(ret, "SHA512 No AAD");
    }

    return ret;
}
#endif

#if !defined(NO_RSA) && defined(WC_RSA_DIRECT)
static CK_RV test_rsa_fixed_keys_x_509_sig(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK) {
        ret = rsa_x_509_sig_test(session, priv, pub, 32);
        CHECK_CKR(ret, "RSA X_509 - 32 byte hash");
    }
    if (ret == CKR_OK) {
        ret = rsa_x_509_sig_test(session, priv, pub, 28);
        CHECK_CKR(ret, "RSA X_509 - 28 byte hash");
    }
    if (ret == CKR_OK) {
        ret = rsa_x_509_sig_test(session, priv, pub, 48);
        CHECK_CKR(ret, "RSA X_509 - 48 byte hash");
    }
    if (ret == CKR_OK) {
        ret = rsa_x_509_sig_test(session, priv, pub, 64);
        CHECK_CKR(ret, "RSA X_509 - 64 byte hash");
    }

    return ret;
}
#endif

static CK_RV test_rsa_fixed_keys_pkcs15_sig(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK) {
        ret = rsa_pkcs15_sig_test(session, priv, pub, 32);
        CHECK_CKR(ret, "RSA PKCS#1.5 - 32 byte hash");
    }
    if (ret == CKR_OK) {
        ret = rsa_pkcs15_sig_test(session, priv, pub, 28);
        CHECK_CKR(ret, "RSA PKCS#1.5 - 28 byte hash");
    }
    if (ret == CKR_OK) {
        ret = rsa_pkcs15_sig_test(session, priv, pub, 48);
        CHECK_CKR(ret, "RSA PKCS#1.5 - 48 byte hash");
    }
    if (ret == CKR_OK) {
        ret = rsa_pkcs15_sig_test(session, priv, pub, 64);
        CHECK_CKR(ret, "RSA PKCS#1.5 - 64 byte hash");
    }

    if (ret == CKR_OK) {
        ret = sha256_rsa_pkcs15_sig_test(session, priv, pub, 32);
        CHECK_CKR(ret, "RSA PKCS#1.5 - 32 byte hash");
    }
    if (ret == CKR_OK) {
        ret = sha256_rsa_pkcs15_sig_test(session, priv, pub, 28);
        CHECK_CKR(ret, "RSA PKCS#1.5 - 28 byte hash");
    }
    if (ret == CKR_OK) {
        ret = sha256_rsa_pkcs15_sig_test(session, priv, pub, 48);
        CHECK_CKR(ret, "RSA PKCS#1.5 - 48 byte hash");
    }
    if (ret == CKR_OK) {
        ret = sha256_rsa_pkcs15_sig_test(session, priv, pub, 64);
        CHECK_CKR(ret, "RSA PKCS#1.5 - 64 byte hash");
    }

    return ret;
}

#ifdef WC_RSA_PSS
static CK_RV test_rsa_fixed_keys_pss(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK) {
        ret = rsa_pss_test(session, priv, pub, CKM_SHA256, CKG_MGF1_SHA256, 32);
        CHECK_CKR(ret, "RSA PKCS#1 PSS - SHA256");
    }
    if (ret == CKR_OK) {
        ret = rsa_pss_test(session, priv, pub, CKM_SHA1, CKG_MGF1_SHA1, 20);
        CHECK_CKR(ret, "RSA PKCS#1 PSS - SHA1");
    }
#ifdef WOLFSSL_SHA224
    if (ret == CKR_OK) {
        ret = rsa_pss_test(session, priv, pub, CKM_SHA224, CKG_MGF1_SHA224, 28);
        CHECK_CKR(ret, "RSA PKCS#1 PSS - SHA224");
    }
#endif
    if (ret == CKR_OK) {
        ret = rsa_pss_test(session, priv, pub, CKM_SHA384, CKG_MGF1_SHA384, 48);
        CHECK_CKR(ret, "RSA PKCS#1 PSS - SHA384");
    }
    if (ret == CKR_OK) {
        ret = rsa_pss_test(session, priv, pub, CKM_SHA512, CKG_MGF1_SHA512, 64);
        CHECK_CKR(ret, "RSA PKCS#1 PSS - SHA512");
    }

    if (ret == CKR_OK) {
        ret = sha256_rsa_pss_test(session, priv, pub, CKM_SHA256,
            CKG_MGF1_SHA256, 32);
        CHECK_CKR(ret, "RSA PKCS#1 PSS - SHA256");
    }

    return ret;
}
#endif

static CK_RV test_rsa_fixed_keys_store_token(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_SESSION_HANDLE sessionRO = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    unsigned char* privId = (unsigned char *)"123rsafixedpriv";
    int privIdLen = (int)strlen((char*)privId);
    unsigned char* pubId = (unsigned char *)"123rsafixedpub";
    int pubIdLen = (int)strlen((char*)pubId);

    ret = get_rsa_priv_key(session, privId, privIdLen, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, pubId, pubIdLen, &pub);

#if ((defined(WOLFPKCS11_NSS)) && ((WP11_SESSION_CNT_MAX != 1) || \
    (WP11_SESSION_CNT_MIN != 1)))
    if (ret == CKR_OK) {
        ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
                                                                    &sessionRO);
        CHECK_CKR(ret, "Open Session read only");
    }
#endif
    if (ret == CKR_OK)
        ret = find_rsa_priv_key(session, &priv, privId, privIdLen);
    if (ret == CKR_OK)
        ret = find_rsa_pub_key(session, &pub, pubId, pubIdLen);
    if (ret == CKR_OK)
        ret = rsa_raw_test(session, priv, pub);

    funcList->C_CloseSession(sessionRO);
    funcList->C_DestroyObject(session, pub);
    funcList->C_DestroyObject(session, priv);
    return ret;
}

static CK_RV test_rsa_encdec_fail(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                                  CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub)
{
    CK_RV ret;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte   plain[1024/8], enc[2048/8], dec[2048/8];
    CK_ULONG plainSz, encSz, decSz;
    byte keyData[32] = { 0, };

    memset(plain, 9, sizeof(plain));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(session, mech, key);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                             "RSA Encrypt Init wrong key type");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, mech, key);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                             "RSA Decrypt Init wrong key type");
    }
    if (ret == CKR_OK) {
       ret = funcList->C_EncryptInit(session, mech, pub);
       CHECK_CKR(ret, "RSA Encrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                      "RSA Decrypt wrong init");
    }
    if (ret == CKR_OK) {
       ret = funcList->C_DecryptInit(session, mech, priv);
       CHECK_CKR(ret, "RSA Decrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                      "RSA Encrypt wrong init");
    }

    return ret;
}

static CK_RV test_rsa_x_509_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    byte data[1];

    mech.mechanism      = CKM_RSA_X_509;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK)
        ret = test_rsa_encdec_fail(session, &mech, priv, pub);
    if (ret == CKR_OK) {
        mech.pParameter = data;
        ret = funcList->C_EncryptInit(session, &mech, pub);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "RSA Encrypt Init bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_EncryptInit(session, &mech, pub);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                       "RSA Encrypt Init bad parameter length");
        mech.ulParameterLen = 0;
    }
    if (ret == CKR_OK) {
        mech.pParameter = data;
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "RSA Decrypt Init bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                       "RSA Decrypt Init bad parameter length");
        mech.ulParameterLen = 0;
    }

    return ret;
}

static CK_RV test_rsa_pkcs_encdec_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    byte data[1];

    mech.mechanism      = CKM_RSA_PKCS;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK)
        ret = test_rsa_encdec_fail(session, &mech, priv, pub);
    if (ret == CKR_OK) {
        mech.pParameter = data;
        ret = funcList->C_EncryptInit(session, &mech, pub);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "RSA Encrypt Init bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_EncryptInit(session, &mech, pub);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                       "RSA Encrypt Init bad parameter length");
        mech.ulParameterLen = 0;
    }
    if (ret == CKR_OK) {
        mech.pParameter = data;
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "RSA Decrypt Init bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                       "RSA Decrypt Init bad parameter length");
        mech.ulParameterLen = 0;
    }

    return ret;
}

#ifndef WC_NO_RSA_OAEP
static CK_RV test_rsa_pkcs_oaep_encdec_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_RSA_PKCS_OAEP_PARAMS params;

    params.hashAlg = CKM_SHA256;
    params.mgf = CKG_MGF1_SHA256;
    params.source = CKZ_DATA_SPECIFIED;
    params.pSourceData = NULL;
    params.ulSourceDataLen = 0;

    mech.mechanism      = CKM_RSA_PKCS_OAEP;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter     = &params;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK)
        ret = test_rsa_encdec_fail(session, &mech, priv, pub);
    if (ret == CKR_OK) {
        mech.pParameter = NULL;
        ret = funcList->C_EncryptInit(session, &mech, pub);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "RSA Encrypt Init bad parameter");
        mech.pParameter = &params;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 0;
        ret = funcList->C_EncryptInit(session, &mech, pub);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                       "RSA Encrypt Init bad parameter length");
        mech.ulParameterLen = sizeof(params);;
    }
    if (ret == CKR_OK) {
        params.source = 0;
        ret = funcList->C_EncryptInit(session, &mech, pub);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                 "RSA Encrypt Init bad source");
        params.source = CKZ_DATA_SPECIFIED;
    }
    if (ret == CKR_OK) {
        mech.pParameter = NULL;
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "RSA Decrypt Init bad parameter");
        mech.pParameter = &params;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 0;
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                       "RSA Decrypt Init bad parameter length");
        mech.ulParameterLen = sizeof(params);
    }
    if (ret == CKR_OK) {
        params.source = 0;
        ret = funcList->C_DecryptInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                 "RSA Decrypt Init bad source");
        params.source = CKZ_DATA_SPECIFIED;
    }

    return ret;
}
#endif

static CK_RV test_rsa_pkcs_sig_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    byte data[1];

    mech.mechanism      = CKM_RSA_PKCS;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK)
        ret = test_pubkey_sig_fail(session, &mech, priv, pub);
    if (ret == CKR_OK) {
        mech.pParameter = data;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                     "Sign Init bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "Sign Init bad parameter length");
        mech.ulParameterLen = 0;
    }
    if (ret == CKR_OK) {
        mech.pParameter = data;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                   "Verify Init bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                            "Verify Init bad parameter length");
        mech.ulParameterLen = 0;
    }

    return ret;
}

#ifdef WC_RSA_PSS
static CK_RV test_rsa_pkcs_pss_sig_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_RSA_PKCS_PSS_PARAMS params;

    params.hashAlg = CKM_SHA256;
    params.mgf = CKG_MGF1_SHA256;
    params.sLen = 32;

    mech.mechanism      = CKM_RSA_PKCS_PSS;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter     = &params;

    ret = get_rsa_priv_key(session, NULL, 0, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_rsa_pub_key(session, NULL, 0, &pub);
    if (ret == CKR_OK)
        ret = test_pubkey_sig_fail(session, &mech, priv, pub);
    if (ret == CKR_OK) {
        mech.pParameter = NULL;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                    "Sign Init NULL parameter");
        mech.pParameter = &params;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 0;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "Sign Init bad parameter length");
        mech.ulParameterLen = sizeof(params);
    }
    if (ret == CKR_OK) {
        params.hashAlg = CKM_RSA_PKCS;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                "Sign Init bad hash algorithm");
        params.hashAlg = CKM_SHA256;
    }
    if (ret == CKR_OK) {
        params.mgf = 0;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                 "Sign Init bad mgf algorithm");
        params.mgf = CKG_MGF1_SHA256;
    }
    if (ret == CKR_OK) {
        params.sLen = 63;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                   "Sign Init bad salt length");
        params.sLen = 32;
    }
    if (ret == CKR_OK) {
        mech.pParameter = NULL;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                  "Verify Init NULL parameter");
        mech.pParameter = &params;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 0;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                            "Verify Init bad parameter length");
        mech.ulParameterLen = sizeof(params);
    }
    if (ret == CKR_OK) {
        params.hashAlg = CKM_RSA_PKCS;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "Verify Init bad hash algorithm");
        params.hashAlg = CKM_SHA256;
    }
    if (ret == CKR_OK) {
        params.mgf = 0;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                               "Verify Init bad mgf algorithm");
        params.mgf = CKG_MGF1_SHA256;
    }
    if (ret == CKR_OK) {
        params.sLen = 63;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                 "Verify Init bad salt length");
        params.sLen = 32;
    }

    return ret;
}
#endif

#ifdef WOLFSSL_KEY_GEN
static CK_RV test_rsa_gen_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = gen_rsa_key(session, &pub, &priv, NULL, 0);
    if (ret == CKR_OK)
        ret = find_rsa_pub_key_label(session, &pub);
    if (ret == CKR_OK)
        ret = find_rsa_priv_key_label(session, &priv);
    if (ret == CKR_OK)
        ret = rsa_raw_test(session, priv, pub);
    if (ret == CKR_OK)
        ret = rsa_pkcs15_enc_test(session, priv, pub);
#ifndef WC_NO_RSA_OAEP
    if (ret == CKR_OK) {
        ret = rsa_oaep_test(session, priv, pub, CKM_SHA256, CKG_MGF1_SHA256,
                                                                       NULL, 0);
    }
#endif
    if (ret == CKR_OK)
        ret = rsa_pkcs15_sig_test(session, priv, pub, 32);
#ifdef WC_RSA_PSS
    if (ret == CKR_OK)
        ret = rsa_pss_test(session, priv, pub, CKM_SHA256, CKG_MGF1_SHA256, 32);
#endif

    return ret;
}

static CK_RV test_rsa_gen_keys_id(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    unsigned char* id = (unsigned char *)"123rsa";
    int idLen = (int)strlen((char*)id);

    ret = gen_rsa_key(session, &pub, NULL, id, idLen);
    if (ret == CKR_OK)
        ret = find_rsa_priv_key(session, &priv, id, idLen);
    if (ret == CKR_OK)
        ret = rsa_raw_test(session, priv, pub);
    if (ret == CKR_OK)
        ret = rsa_pkcs15_enc_test(session, priv, pub);
#ifndef WC_NO_RSA_OAEP
    if (ret == CKR_OK) {
        ret = rsa_oaep_test(session, priv, pub, CKM_SHA256, CKG_MGF1_SHA256,
                                                                       NULL, 0);
    }
#endif
    if (ret == CKR_OK)
        ret = rsa_pkcs15_sig_test(session, priv, pub, 32);
#ifdef WC_RSA_PSS
    if (ret == CKR_OK)
        ret = rsa_pss_test(session, priv, pub, CKM_SHA256, CKG_MGF1_SHA256, 32);
#endif

    return ret;
}
#endif
#endif

#if defined(HAVE_ECC) || !defined(NO_DH)
static CK_RV extract_secret(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                            byte* out, word32* outSz)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE tmpl[] = {
      {CKA_VALUE, CK_NULL_PTR, 0}
    };
    CK_ULONG     tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    ret = funcList->C_GetAttributeValue(session, key, tmpl, tmplCnt);
    CHECK_CKR(ret, "Extract Secret - Get Length of key");
    if (ret == CKR_OK) {
        tmpl[0].pValue = out;
        ret = funcList->C_GetAttributeValue(session, key, tmpl, tmplCnt);
        CHECK_CKR(ret, "Extract Secret - Get key");
    }
    if (ret == CKR_OK)
        *outSz = (word32)tmpl[0].ulValueLen;

    return ret;
}
#endif

#ifdef HAVE_ECC
static CK_OBJECT_HANDLE get_ecc_priv_key(CK_SESSION_HANDLE session,
                                         CK_BBOOL extractable,
                                         CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE ecc_p256_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &eccKeyType,       sizeof(eccKeyType)        },
        { CKA_EXTRACTABLE,       &extractable,      sizeof(CK_BBOOL)          },
        { CKA_VERIFY,            &ckTrue,           sizeof(ckTrue)            },
        { CKA_EC_PARAMS,         ecc_p256_params,   sizeof(ecc_p256_params)   },
        { CKA_VALUE,             ecc_p256_priv,     sizeof(ecc_p256_priv)     },
    };
    int ecc_p256_priv_key_cnt =
                           sizeof(ecc_p256_priv_key)/sizeof(*ecc_p256_priv_key);

    ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                    ecc_p256_priv_key_cnt, obj);

    CHECK_CKR(ret, "EC Private Key Create Object");

    return ret;
}

static CK_OBJECT_HANDLE get_ecc_pub_key(CK_SESSION_HANDLE session,
                                        CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    static CK_ATTRIBUTE ecc_p256_pub_key[] = {
        { CKA_CLASS,             &pubKeyClass,      sizeof(pubKeyClass)       },
        { CKA_KEY_TYPE,          &eccKeyType,       sizeof(eccKeyType)        },
        { CKA_SIGN,              &ckTrue,           sizeof(ckTrue)            },
        { CKA_EC_PARAMS,         ecc_p256_params,   sizeof(ecc_p256_params)   },
        { CKA_EC_POINT,          ecc_p256_pub,      sizeof(ecc_p256_pub)      },
    };
    static int ecc_p256_pub_key_cnt =
                             sizeof(ecc_p256_pub_key)/sizeof(*ecc_p256_pub_key);

    ret = funcList->C_CreateObject(session, ecc_p256_pub_key,
                                                     ecc_p256_pub_key_cnt, obj);
    CHECK_CKR(ret, "EC Public Key Create Object");

    return ret;
}

static CK_RV gen_ec_keys(CK_SESSION_HANDLE session, byte* params, int paramSz,
                         CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
                         unsigned char* privId, int privIdLen,
                         unsigned char* pubId, int pubIdLen, int onToken)
{
    CK_RV             ret = CKR_OK;
    CK_OBJECT_HANDLE  priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  pub = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_BBOOL          token;
    CK_ATTRIBUTE      pubKeyTmpl[] = {
        { CKA_EC_PARAMS,       params,             paramSz                    },
        { CKA_VERIFY,          &ckTrue,            sizeof(ckTrue)             },
        { CKA_TOKEN,           &token,             sizeof(token)              },
        { CKA_ID,              pubId,              pubIdLen                   },
    };
    int               pubTmplCnt = sizeof(pubKeyTmpl)/sizeof(*pubKeyTmpl);
    CK_ATTRIBUTE      privKeyTmpl[] = {
        { CKA_SIGN,            &ckTrue,            sizeof(ckTrue)             },
        { CKA_DERIVE,          &ckTrue,            sizeof(ckTrue)             },
        { CKA_TOKEN,           &token,             sizeof(token)              },
        { CKA_ID,              privId,             privIdLen                  },
    };
    int               privTmplCnt = sizeof(privKeyTmpl)/sizeof(*privKeyTmpl);

    if (privId == NULL)
        privTmplCnt--;
    if (pubId == NULL)
        pubTmplCnt--;
    token = onToken;

    if (ret == CKR_OK) {
        mech.mechanism      = CKM_EC_KEY_PAIR_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter     = NULL;

        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                             pubTmplCnt, privKeyTmpl, privTmplCnt, &pub, &priv);
        CHECK_CKR(ret, "EC Key Generation");
    }
    if (ret == CKR_OK && privKey != NULL)
        *privKey = priv;
    if (ret == CKR_OK && pubKey != NULL)
        *pubKey = pub;
    if (ret == CKR_OK) {
        mech.pParameter = pubKeyTmpl;
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                             pubTmplCnt, privKeyTmpl, privTmplCnt, &pub, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "RSA Generate Key Pair bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = sizeof(pubKeyTmpl);
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                             pubTmplCnt, privKeyTmpl, privTmplCnt, &pub, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                  "RSA Generate Key Pair bad parameter Length");
        mech.ulParameterLen = 0;
    }

    return ret;
}

static CK_RV find_ecc_priv_key(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE* privKey, unsigned char* id,
                               int idLen)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE      privKeyTmpl[] = {
        { CKA_CLASS,     &privKeyClass,  sizeof(privKeyClass) },
        { CKA_KEY_TYPE,  &eccKeyType,    sizeof(eccKeyType)   },
        { CKA_ID,        id,             idLen                }
    };
    CK_ULONG privKeyTmplCnt = sizeof(privKeyTmpl) / sizeof(*privKeyTmpl);
    CK_ULONG count;

    ret = funcList->C_FindObjectsInit(session, privKeyTmpl, privKeyTmplCnt);
    CHECK_CKR(ret, "EC Private Key Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, privKey, 1, &count);
        CHECK_CKR(ret, "EC Private Key Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "EC Private Key Find Objects Final");
    }
    if (ret == CKR_OK && count == 0) {
        ret = -1;
        CHECK_CKR(ret, "EC Private Key Find Objects Count");
    }

    return ret;
}

static CK_RV find_ecc_pub_key(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE* pubKey, unsigned char* id,
                              int idLen)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE      pubKeyTmpl[] = {
        { CKA_CLASS,     &pubKeyClass, sizeof(pubKeyClass) },
        { CKA_KEY_TYPE,  &eccKeyType,   sizeof(eccKeyType)  },
        { CKA_ID,        id,            idLen               }
    };
    CK_ULONG pubKeyTmplCnt = sizeof(pubKeyTmpl) / sizeof(*pubKeyTmpl);
    CK_ULONG count;

    ret = funcList->C_FindObjectsInit(session, pubKeyTmpl, pubKeyTmplCnt);
    CHECK_CKR(ret, "EC Public Key Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, pubKey, 1, &count);
        CHECK_CKR(ret, "EC Public Key Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "EC Public Key Find Objects Final");
    }
    if (ret == CKR_OK && count == 0) {
        ret = -1;
        CHECK_CKR(ret, "EC Public Key Find Objects Count");
    }

    return ret;
}

static CK_RV test_attributes_ecc(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    unsigned char params[20];
    unsigned char point[80];
    unsigned char value[32];
    CK_ATTRIBUTE eccTmpl[] = {
        { CKA_EC_PARAMS,           params,              sizeof(params)        },
        { CKA_EC_POINT,            point,               sizeof(point)         },
    };
    CK_ULONG eccTmplCnt = sizeof(eccTmpl) / sizeof(*eccTmpl);
    CK_ATTRIBUTE eccBadTmpl[] = {
        { CKA_WRAP_TEMPLATE,       NULL,                0                     },
        { CKA_UNWRAP_TEMPLATE,     NULL,                0                     },
        { CKA_DERIVE_TEMPLATE,     NULL,                0                     },
    };
    CK_ULONG eccBadTmplCnt = sizeof(eccBadTmpl) / sizeof(*eccBadTmpl);
    CK_ATTRIBUTE eccPrivTmpl[] = {
        { CKA_EC_PARAMS,           NULL,                0                     },
        { CKA_VALUE,               NULL,                0                     },
        { CKA_EC_POINT,            NULL,                0                     },
    };
    CK_ULONG eccPrivTmplCnt = sizeof(eccPrivTmpl) / sizeof(*eccPrivTmpl);
    int i;

    ret = get_ecc_pub_key(session, &pub);
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, pub, eccTmpl, eccTmplCnt);
        CHECK_CKR(ret, "Get Attributes EC Public Key");
    }
    if (ret == CKR_OK) {
        eccTmpl[0].ulValueLen = 1;
        ret = funcList->C_GetAttributeValue(session, pub, eccTmpl, eccTmplCnt);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                              "Get Attributes EC Public Key bad params length");
        eccTmpl[0].ulValueLen = sizeof(params);
    }
    if (ret == CKR_OK) {
        eccTmpl[1].ulValueLen = 1;
        ret = funcList->C_GetAttributeValue(session, pub, eccTmpl, eccTmplCnt);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                               "Get Attributes EC Public Key bad point length");
        eccTmpl[1].ulValueLen = sizeof(point);
    }
    if (ret == CKR_OK) {
        eccTmpl[1].pValue = NULL;
        ret = funcList->C_GetAttributeValue(session, pub, eccTmpl, eccTmplCnt);
        CHECK_CKR(ret, "Get Attributes EC Public Key point length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(eccTmpl[1].ulValueLen == sizeof(ecc_p256_pub), ret,
                                   "Get Attributes EC public key point length");
    }
    if (ret == CKR_OK) {
        for (i = 0; i < (int)eccBadTmplCnt; i++) {
            ret = funcList->C_GetAttributeValue(session, pub, &eccBadTmpl[i],
                                                                             1);
            CHECK_CKR_FAIL(ret, CK_UNAVAILABLE_INFORMATION,
                                               "Get Attributes EC unavailable");
        }
    }
    if (ret == CKR_OK) {
        ret = get_ecc_priv_key(session, CK_FALSE, &priv);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, eccPrivTmpl,
                                                                eccPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes EC Private Key NULL values");
    }
    if (ret == CKR_OK) {
        CHECK_COND(eccPrivTmpl[0].ulValueLen == sizeof(ecc_p256_params), ret,
                                 "Get Attributes EC private key params length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(eccPrivTmpl[1].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                                  "Get Attributes EC private key value length");
    }
    if (ret == CKR_OK) {
        CHECK_COND(eccPrivTmpl[2].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                             "Get Attributes EC private key public key length");
    }
    funcList->C_DestroyObject(session, priv);
    if (ret == CKR_OK) {
        ret = get_ecc_priv_key(session, CK_TRUE, &priv);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, eccPrivTmpl,
                                                                eccPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes EC Private Key NULL values");
    }
    if (ret == CKR_OK) {
        CHECK_COND(eccPrivTmpl[0].ulValueLen == sizeof(ecc_p256_params), ret,
                               "Get Attributes RSA private key modulus length");
        eccPrivTmpl[0].pValue = params;
    }
    if (ret == CKR_OK) {
        CHECK_COND(eccPrivTmpl[1].ulValueLen == sizeof(value), ret,
                      "Get Attributes RSA private key private exponent length");
        eccPrivTmpl[1].pValue = value;
    }
    if (ret == CKR_OK) {
        CHECK_COND(eccPrivTmpl[2].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                             "Get Attributes EC private key public key length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, eccPrivTmpl,
                                                                eccPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes EC Private Key values");
    }
    funcList->C_DestroyObject(session, priv);

    return ret;
}

static CK_RV ecdh_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privKey,
                       byte* point, int pointLen, int check)
{
    CK_RV  ret;
    byte   out[256/8];
    word32 outSz = sizeof(out);
    CK_MECHANISM     mech;
    CK_OBJECT_HANDLE secret;
    CK_KEY_TYPE      keyType = CKK_GENERIC_SECRET;
    CK_ULONG         secSz = outSz;
    CK_ATTRIBUTE     tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)        },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &secSz,          sizeof(secSz)          }
    };
    CK_ULONG         tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_ECDH1_DERIVE_PARAMS params;

    params.kdf             = CKD_NULL;
    params.pSharedData     = NULL;
    params.ulSharedDataLen = 0;
    params.pPublicData     = point;
    params.ulPublicDataLen = pointLen;

    mech.mechanism      = CKM_ECDH1_DERIVE;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter     = &params;

    ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
    CHECK_CKR(ret, "EC Derive Key");
    if (ret == CKR_OK)
        ret = extract_secret(session, secret, out, &outSz);
    if (ret == CKR_OK && check) {
        if (outSz != (word32)sizeof_ecc_secret_256 ||
                                      memcmp(out, ecc_secret_256, outSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "Secret compare with expected");
        }
    }
    if (ret == CKR_OK) {
        mech.pParameter = NULL;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                  "EC Derive Key no parameter");
        mech.pParameter = &params;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 0;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "EC Derive Key zero parameter length");
        mech.ulParameterLen = sizeof(params);
    }
    if (ret == CKR_OK) {
        params.kdf = 0;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                       "EC Derive Key bad KDF");
        params.kdf = CKD_NULL;
    }
    if (ret == CKR_OK) {
        params.pPublicData = NULL;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                "EC Derive Key no public data");
        params.pPublicData = point;
    }
    if (ret == CKR_OK) {
        params.ulPublicDataLen = 0;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                       "EC Derive Key zero public data length");
        params.ulPublicDataLen = pointLen;
    }

    return ret;
}

static CK_RV ecdsa_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privKey,
                        CK_OBJECT_HANDLE pubKey)
{
    CK_RV  ret = CKR_OK;
    byte   hash[32], out[64];
    CK_ULONG hashSz, outSz;
    CK_MECHANISM mech;
    unsigned long i;
    CK_MECHANISM_TYPE digestTypes[] = {
#ifndef WOLFPKCS11_TPM
        /* the ibmswtpm2 backend we use for testing appears to not support
         * these hash sizes for ecdsa */
#ifndef NO_SHA
        CKM_ECDSA_SHA1,
#endif
#ifdef WOLFSSL_SHA224
        CKM_ECDSA_SHA224,
#endif
#endif
#ifndef NO_SHA256
        CKM_ECDSA_SHA256,
#endif
#ifdef WOLFSSL_SHA384
        CKM_ECDSA_SHA384,
#endif
#ifdef WOLFSSL_SHA512
        CKM_ECDSA_SHA512,
#endif
    };

    memset(hash, 9, sizeof(hash));
    hashSz = sizeof(hash);
    outSz = sizeof(out);

    mech.mechanism      = CKM_ECDSA;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_SignInit(session, &mech, privKey);
    CHECK_CKR(ret, "ECDSA Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, NULL, &outSz);
        CHECK_CKR(ret, "ECDSA Sign out size no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == sizeof(out), ret, "ECDSA Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                               "ECDSA Sign out size too small");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, hash, hashSz, out, &outSz);
        CHECK_CKR(ret, "ECDSA Sign");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, pubKey);
        CHECK_CKR(ret, "ECDSA Verify Init");
    }
#ifndef WOLFSSL_MAXQ10XX_CRYPTO
    /* In the case of MAXQ1065 it will be signed by the pre-provisioned private
     * key so verify operation will fail as this is NOT the corresponding
     * public key. */
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hash, hashSz, out, outSz);
        CHECK_CKR(ret, "ECDSA Verify");
    }
#endif
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hash, hashSz - 1, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "ECDSA Verify bad hash");
    }
    if (ret == CKR_OK) {
        outSz = 1;
        ret = funcList->C_Verify(session, hash, hashSz, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED, "ECDSA Verify bad sig");
    }

    /* Test digests */
    for (i = 0; ret == CKR_OK && i < (sizeof(digestTypes)/sizeof(*digestTypes));
            i++) {
        byte   data[256];
        CK_ULONG dataSz;

        memset(data, 9, sizeof(data));
        dataSz = sizeof(data);
        outSz = sizeof(out);

        mech.mechanism      = digestTypes[i];
        mech.ulParameterLen = 0;
        mech.pParameter     = NULL;

        ret = funcList->C_SignInit(session, &mech, privKey);
        CHECK_CKR(ret, "ECDSA Sign Init");
        if (ret == CKR_OK) {
            outSz = 0;
            ret = funcList->C_Sign(session, data, dataSz, NULL, &outSz);
            CHECK_CKR(ret, "ECDSA Sign out size no out");
        }
        if (ret == CKR_OK) {
            CHECK_COND(outSz == sizeof(out), ret, "ECDSA Sign out size");
        }
        if (ret == CKR_OK) {
            outSz = 0;
            ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
            CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                                   "ECDSA Sign out size too small");
            outSz = sizeof(out);
        }
        if (ret == CKR_OK) {
            ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
            CHECK_CKR(ret, "ECDSA Sign");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_VerifyInit(session, &mech, pubKey);
            CHECK_CKR(ret, "ECDSA Verify Init");
        }
#ifndef WOLFSSL_MAXQ10XX_CRYPTO
        /* In the case of MAXQ1065 it will be signed by the pre-provisioned
         * private key so verify operation will fail as this is NOT the
         * corresponding public key. */
        if (ret == CKR_OK) {
            ret = funcList->C_Verify(session, data, dataSz, out, outSz);
            CHECK_CKR(ret, "ECDSA Verify");
        }
#endif
        if (ret == CKR_OK) {
            ret = funcList->C_Verify(session, data, dataSz - 1, out, outSz);
            CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "ECDSA Verify bad hash");
        }
        if (ret == CKR_OK) {
            outSz = 1;
            ret = funcList->C_Verify(session, data, dataSz, out, outSz);
            CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED, "ECDSA Verify bad sig");
        }
    }

    return ret;
}

/* Tests for error occurring when private and public curves mismatch. */
/* Crashes with TPM test right now. */
#ifndef WOLFPKCS11_TPM
static CK_RV test_ecc_curve(void *args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE hAlicePubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hAlicePrivKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hBobPubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hBobPrivKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hSharedSecret = CK_INVALID_HANDLE;
    CK_MECHANISM mechanismGen = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_BYTE ecParams_secp256r1[] =
        { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

    CK_ATTRIBUTE alicePubKeyTemplate[] = {
        {CKA_EC_PARAMS, ecParams_secp256r1, sizeof(ecParams_secp256r1)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},
        {CKA_ENCRYPT, &ckFalse, sizeof(ckFalse)},
        {CKA_WRAP, &ckFalse, sizeof(ckFalse)},
        {CKA_LABEL, (CK_UTF8CHAR_PTR)"Alice_PublicKey",
            strlen("Alice_PublicKey")}
    };
    CK_ULONG ulAlicePubKeyAttrCount =
        sizeof(alicePubKeyTemplate) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE alicePrivKeyTemplate[] = {
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
        {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)},
        {CKA_SIGN, &ckFalse, sizeof(ckFalse)},
        {CKA_DECRYPT, &ckFalse, sizeof(ckFalse)},
        {CKA_DERIVE, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, (CK_UTF8CHAR_PTR)"Alice_PrivateKey",
            strlen("Alice_PrivateKey")}
    };
    CK_ULONG ulAlicePrivKeyAttrCount =
        sizeof(alicePrivKeyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ATTRIBUTE bobPubKeyTemplate[] = {
        {CKA_EC_PARAMS, ecParams_secp256r1, sizeof(ecParams_secp256r1)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, (CK_UTF8CHAR_PTR)"Bob_PublicKey", strlen("Bob_PublicKey")}
    };
    CK_ULONG ulBobPubKeyAttrCount =
        sizeof(bobPubKeyTemplate) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE bobPrivKeyTemplate[] = {
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
        {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)},
        {CKA_DERIVE, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, (CK_UTF8CHAR_PTR)"Bob_PrivateKey", strlen("Bob_PrivateKey")}
    };
    CK_ULONG ulBobPrivKeyAttrCount =
        sizeof(bobPrivKeyTemplate) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE bobEcPointAttr = { CKA_EC_POINT, NULL_PTR, 0 };

    CK_ECDH1_DERIVE_PARAMS ecdhParams;
    CK_MECHANISM mechanismECDH =
        { CKM_ECDH1_DERIVE, &ecdhParams, sizeof(ecdhParams) };

    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_ATTRIBUTE sharedSecretTemplate[] = {
        {CKA_CLASS, &secretClass, sizeof(secretClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
        {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)},
        {CKA_DERIVE, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, (CK_UTF8CHAR_PTR)"ECDH_SharedSecret",
            strlen("ECDH_SharedSecret")}
    };
    CK_ULONG ulSharedSecretAttrCount =
        sizeof(sharedSecretTemplate) / sizeof(CK_ATTRIBUTE);

    ret = funcList->C_GenerateKeyPair(session, &mechanismGen,
                                alicePubKeyTemplate, ulAlicePubKeyAttrCount,
                                alicePrivKeyTemplate, ulAlicePrivKeyAttrCount,
                                &hAlicePubKey, &hAlicePrivKey);

    CHECK_CKR(ret, "Alice key gen failure");
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateKeyPair(session, &mechanismGen,
            bobPubKeyTemplate, ulBobPubKeyAttrCount,
            bobPrivKeyTemplate, ulBobPrivKeyAttrCount,
            &hBobPubKey, &hBobPrivKey);
        CHECK_CKR(ret, "Bob key gen failure");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, hBobPubKey,
            &bobEcPointAttr, 1);
        CHECK_CKR(ret, "C_GetAttributeValue (Bob EC Point size)");
    }

    if (ret == CKR_OK) {
        bobEcPointAttr.pValue = XMALLOC(bobEcPointAttr.ulValueLen, NULL,
                                        DYNAMIC_TYPE_TMP_BUFFER);
        if (bobEcPointAttr.pValue == NULL)
            ret = CKR_DEVICE_MEMORY;
        CHECK_CKR(ret, "Allocate Bob's EC point");
    }

    if (ret == CKR_OK){
        ret = funcList->C_GetAttributeValue(session, hBobPubKey,
            &bobEcPointAttr, 1);
        CHECK_CKR(ret, "C_GetAttributeValue (Bob EC Point value)");
    }

    if (ret == CKR_OK) {
        ecdhParams.kdf = CKD_NULL;
        ecdhParams.ulSharedDataLen = 0; /* No shared data in this step */
        ecdhParams.pSharedData = NULL_PTR;
        ecdhParams.ulPublicDataLen = bobEcPointAttr.ulValueLen;
        ecdhParams.pPublicData = (CK_BYTE_PTR)bobEcPointAttr.pValue;

        /* Derive the key using Alice's Private Key and Bob's Public Data */
        ret = funcList->C_DeriveKey(session, &mechanismECDH, hAlicePrivKey,
            sharedSecretTemplate, ulSharedSecretAttrCount,
            &hSharedSecret);
        CHECK_CKR(ret, "C_DeriveKey (ECDH1)");
    }
    funcList->C_DestroyObject(session, hSharedSecret);
    funcList->C_DestroyObject(session, hAlicePrivKey);
    funcList->C_DestroyObject(session, hAlicePubKey);
    funcList->C_DestroyObject(session, hBobPrivKey);
    funcList->C_DestroyObject(session, hBobPubKey);
    XFREE(bobEcPointAttr.pValue, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif

/* Calling C_SetAttributeValue used to erase a key */
static CK_RV test_ecc_key_erase_bug(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE obj;
    byte keyGet[sizeof(ecc_p256_priv)];
    CK_ATTRIBUTE ecc_p256_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &eccKeyType,       sizeof(eccKeyType)        },
        { CKA_VERIFY,            &ckTrue,           sizeof(ckTrue)            },
        { CKA_EC_PARAMS,         ecc_p256_params,   sizeof(ecc_p256_params)   },
        { CKA_VALUE,             ecc_p256_priv,     sizeof(ecc_p256_priv)     },
    };
    static int ecc_p256_priv_key_cnt =
                           sizeof(ecc_p256_priv_key)/sizeof(*ecc_p256_priv_key);
    CK_ATTRIBUTE updateTmpl[] = {
        { CKA_EXTRACTABLE,         &ckTrue,         sizeof(ckTrue)            },
    };
    CK_ULONG updateTmplCnt = sizeof(updateTmpl) / sizeof(*updateTmpl);

    CK_ATTRIBUTE getTmpl[] = {
        { CKA_VALUE,          keyGet,   sizeof(ecc_p256_priv) },
    };
    CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(*getTmpl);

    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR(ret, "EC Private Key Create Object");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_SetAttributeValue(session, obj, updateTmpl,
                                            updateTmplCnt);
        CHECK_CKR(ret, "Update attribute sensitive");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "Get key value");
    }

    if (ret == CKR_OK) {
        if (XMEMCMP(keyGet, ecc_p256_priv, sizeof(ecc_p256_priv)) != 0)
            ret = CKR_FUNCTION_FAILED;
        CHECK_CKR(ret, "Key compare");
    }
    return ret;
}

static CK_RV test_ecc_create_key_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE ecc_p256_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &eccKeyType,       sizeof(eccKeyType)        },
        { CKA_VERIFY,            &ckTrue,           sizeof(ckTrue)            },
        { CKA_EC_PARAMS,         ecc_p256_params,   sizeof(ecc_p256_params)   },
        { CKA_VALUE,             ecc_p256_priv,     sizeof(ecc_p256_priv)     },
        { CKA_EC_POINT,          ecc_p256_pub,      sizeof(ecc_p256_pub)      },
    };
    static unsigned char paramsNotObj[] = {
        0x04, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    static unsigned char paramsObjLen[] = {
        0x06, 0x06, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    static unsigned char paramsBadOid[] = {
        0x06, 0x08, 0x2B, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    static unsigned char pubNotOctet[] = {
        0x02, 0x41, 0x04, 0x55, 0xBF, 0xF4, 0x0F, 0x44,
        0x50, 0x9A, 0x3D, 0xCE, 0x9B, 0xB7, 0xF0, 0xC5,
        0x4D, 0xF5, 0x70, 0x7B, 0xD4, 0xEC, 0x24, 0x8E,
        0x19, 0x80, 0xEC, 0x5A, 0x4C, 0xA2, 0x24, 0x03,
        0x62, 0x2C, 0x9B, 0xDA, 0xEF, 0xA2, 0x35, 0x12,
        0x43, 0x84, 0x76, 0x16, 0xC6, 0x56, 0x95, 0x06,
        0xCC, 0x01, 0xA9, 0xBD, 0xF6, 0x75, 0x1A, 0x42,
        0xF7, 0xBD, 0xA9, 0xB2, 0x36, 0x22, 0x5F, 0xC7,
        0x5D, 0x7F, 0xB4
    };
    static unsigned char pubOctetLen[] = {
        0x04, 0x40, 0x04, 0x55, 0xBF, 0xF4, 0x0F, 0x44,
        0x50, 0x9A, 0x3D, 0xCE, 0x9B, 0xB7, 0xF0, 0xC5,
        0x4D, 0xF5, 0x70, 0x7B, 0xD4, 0xEC, 0x24, 0x8E,
        0x19, 0x80, 0xEC, 0x5A, 0x4C, 0xA2, 0x24, 0x03,
        0x62, 0x2C, 0x9B, 0xDA, 0xEF, 0xA2, 0x35, 0x12,
        0x43, 0x84, 0x76, 0x16, 0xC6, 0x56, 0x95, 0x06,
        0xCC, 0x01, 0xA9, 0xBD, 0xF6, 0x75, 0x1A, 0x42,
        0xF7, 0xBD, 0xA9, 0xB2, 0x36, 0x22, 0x5F, 0xC7,
        0x5D, 0x7F, 0xB4
    };
    static unsigned char pubOctetBadLongLen[] = {
        0x04, 0x80, 0x81,
        0x04,
        0x55, 0xBF, 0xF4, 0x0F, 0x44, 0x50, 0x9A, 0x3D,
        0xCE, 0x9B, 0xB7, 0xF0, 0xC5, 0x4D, 0xF5, 0x70,
        0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80, 0xEC,
        0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B,
        0xDA, 0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76,
        0x16, 0xC6, 0x56, 0x95, 0x06, 0xCC, 0x01, 0xA9,
        0xBD, 0xF6, 0x75, 0x1A, 0x42, 0xF7, 0xBD, 0xA9,
        0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D, 0x7F, 0xB4,
        0x55, 0xBF, 0xF4, 0x0F, 0x44, 0x50, 0x9A, 0x3D,
        0xCE, 0x9B, 0xB7, 0xF0, 0xC5, 0x4D, 0xF5, 0x70,
        0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80, 0xEC,
        0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B,
        0xDA, 0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76,
        0x16, 0xC6, 0x56, 0x95, 0x06, 0xCC, 0x01, 0xA9,
        0xBD, 0xF6, 0x75, 0x1A, 0x42, 0xF7, 0xBD, 0xA9,
        0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D, 0x7F, 0xB4
    };
    static unsigned char pubOctetBadLenLong[] = {
        0x04, 0x81, 0x80,
        0x04,
        0x55, 0xBF, 0xF4, 0x0F, 0x44, 0x50, 0x9A, 0x3D,
        0xCE, 0x9B, 0xB7, 0xF0, 0xC5, 0x4D, 0xF5, 0x70,
        0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80, 0xEC,
        0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B,
        0xDA, 0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76,
        0x16, 0xC6, 0x56, 0x95, 0x06, 0xCC, 0x01, 0xA9,
        0xBD, 0xF6, 0x75, 0x1A, 0x42, 0xF7, 0xBD, 0xA9,
        0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D, 0x7F, 0xB4,
        0x55, 0xBF, 0xF4, 0x0F, 0x44, 0x50, 0x9A, 0x3D,
        0xCE, 0x9B, 0xB7, 0xF0, 0xC5, 0x4D, 0xF5, 0x70,
        0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80, 0xEC,
        0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B,
        0xDA, 0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76,
        0x16, 0xC6, 0x56, 0x95, 0x06, 0xCC, 0x01, 0xA9,
        0xBD, 0xF6, 0x75, 0x1A, 0x42, 0xF7, 0xBD, 0xA9,
        0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D, 0x7F, 0xB4
    };
    static int ecc_p256_priv_key_cnt =
                           sizeof(ecc_p256_priv_key)/sizeof(*ecc_p256_priv_key);

    if (ret == CKR_OK) {
        ecc_p256_priv_key[3].ulValueLen = 1;
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                              "EC Private Key Create Object - param len short");
        ecc_p256_priv_key[3].ulValueLen = sizeof(ecc_p256_params);
    }
    if (ret == CKR_OK) {
        ecc_p256_priv_key[3].pValue = paramsNotObj;
        ecc_p256_priv_key[3].ulValueLen = sizeof(paramsNotObj);
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                         "EC Private Key Create Object - not object in params");
        ecc_p256_priv_key[3].pValue = ecc_p256_params;
        ecc_p256_priv_key[3].ulValueLen = sizeof(ecc_p256_params);
    }
    if (ret == CKR_OK) {
        ecc_p256_priv_key[3].pValue = paramsObjLen;
        ecc_p256_priv_key[3].ulValueLen = sizeof(paramsObjLen);
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                     "EC Private Key Create Object - bad object len in params");
        ecc_p256_priv_key[3].pValue = ecc_p256_params;
        ecc_p256_priv_key[3].ulValueLen = sizeof(ecc_p256_params);
    }
    if (ret == CKR_OK) {
        ecc_p256_priv_key[3].pValue = paramsBadOid;
        ecc_p256_priv_key[3].ulValueLen = sizeof(paramsBadOid);
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                            "EC Private Key Create Object - bad OID in params");
        ecc_p256_priv_key[3].pValue = ecc_p256_params;
        ecc_p256_priv_key[3].ulValueLen = sizeof(ecc_p256_params);
    }
    if (ret == CKR_OK) {
        ecc_p256_priv_key[5].ulValueLen = 1;
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                              "EC Private Key Create Object - point len short");
        ecc_p256_priv_key[5].ulValueLen = sizeof(ecc_p256_params);
    }
    if (ret == CKR_OK) {
        ecc_p256_priv_key[5].pValue = pubNotOctet;
        ecc_p256_priv_key[5].ulValueLen = sizeof(pubNotOctet);
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                           "EC Private Key Create Object - not octet in point");
        ecc_p256_priv_key[5].pValue = ecc_p256_pub;
        ecc_p256_priv_key[5].ulValueLen = sizeof(ecc_p256_pub);
    }
    if (ret == CKR_OK) {
        ecc_p256_priv_key[5].pValue = pubOctetLen;
        ecc_p256_priv_key[5].ulValueLen = sizeof(pubOctetLen);
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                       "EC Private Key Create Object - bad octet len in point");
        ecc_p256_priv_key[5].pValue = ecc_p256_pub;
        ecc_p256_priv_key[5].ulValueLen = sizeof(ecc_p256_pub);
    }
    if (ret == CKR_OK) {
        ecc_p256_priv_key[5].pValue = pubOctetBadLongLen;
        ecc_p256_priv_key[5].ulValueLen = sizeof(pubOctetBadLongLen);
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                  "EC Private Key Create Object - bad octet long len in point");
        ecc_p256_priv_key[5].pValue = ecc_p256_pub;
        ecc_p256_priv_key[5].ulValueLen = sizeof(ecc_p256_pub);
    }
    if (ret == CKR_OK) {
        ecc_p256_priv_key[5].pValue = pubOctetBadLenLong;
        ecc_p256_priv_key[5].ulValueLen = sizeof(pubOctetBadLenLong);
        ret = funcList->C_CreateObject(session, ecc_p256_priv_key,
                                                   ecc_p256_priv_key_cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                  "EC Private Key Create Object - bad octet len long in point");
        ecc_p256_priv_key[5].pValue = ecc_p256_pub;
        ecc_p256_priv_key[5].ulValueLen = sizeof(ecc_p256_pub);
    }

    return ret;
}

static CK_RV test_ecc_fixed_keys_ecdh(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_ecc_priv_key(session, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_ecc_pub_key(session, &pub);
    if (ret == CKR_OK) {
        ret = ecdh_test(session, priv, ecc_p256_point, sizeof(ecc_p256_point),
                                                                             1);
    }

    return ret;
}

static CK_RV test_ecc_fixed_keys_ecdsa(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_ecc_priv_key(session, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_ecc_pub_key(session, &pub);
    if (ret == CKR_OK)
        ret = ecdsa_test(session, priv, pub);

    return ret;
}

static CK_RV test_ecc_gen_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = gen_ec_keys(session, ecc_p256_params, sizeof(ecc_p256_params), &pub,
                                                    &priv, NULL, 0, NULL, 0, 0);
    if (ret == CKR_OK) {
       ret = ecdh_test(session, priv, ecc_p256_point, sizeof(ecc_p256_point),
                                                                             0);
    }
    if (ret == CKR_OK)
       ret = ecdsa_test(session, priv, pub);

    return ret;
}

static CK_RV test_ecc_gen_keys_id(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    unsigned char* id = (unsigned char *)"123ecc";
    int idLen = (int)strlen((char*)id);

    ret = gen_ec_keys(session, ecc_p256_params, sizeof(ecc_p256_params), &pub,
                                                   NULL, id, idLen, NULL, 0, 0);
    if (ret == CKR_OK)
        ret = find_ecc_priv_key(session, &priv, id, idLen);
    if (ret == CKR_OK) {
        ret = ecdh_test(session, priv, ecc_p256_point, sizeof(ecc_p256_point),
                                                                             0);
    }
    if (ret == CKR_OK)
        ret = ecdsa_test(session, priv, pub);

    return ret;
}

static CK_RV test_ecc_gen_keys_token(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    unsigned char* privId = (unsigned char *)"123eccprivtoken";
    int privIdLen = (int)strlen((char*)privId);
    unsigned char* pubId = (unsigned char *)"123eccpubtoken";
    int pubIdLen = (int)strlen((char*)pubId);

    ret = gen_ec_keys(session, ecc_p256_params, sizeof(ecc_p256_params), NULL,
                                   NULL, privId, privIdLen, pubId, pubIdLen, 1);

    return ret;
}

static CK_RV test_ecc_token_keys_ecdsa(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    unsigned char* privId = (unsigned char *)"123eccprivtoken";
    int privIdLen = (int)strlen((char*)privId);
    unsigned char* pubId = (unsigned char *)"123eccpubtoken";
    int pubIdLen = (int)strlen((char*)pubId);

    ret = find_ecc_priv_key(session, &priv, privId, privIdLen);
    if (ret == CKR_OK)
        ret = find_ecc_pub_key(session, &pub, pubId, pubIdLen);
    if (ret == CKR_OK)
        ret = ecdsa_test(session, priv, pub);

    return ret;
}

static CK_RV test_ecdsa_sig_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    byte data[1];

    mech.mechanism      = CKM_ECDSA;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = get_ecc_priv_key(session, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_ecc_pub_key(session, &pub);
    if (ret == CKR_OK)
        ret = test_pubkey_sig_fail(session, &mech, priv, pub);
    if (ret == CKR_OK) {
        mech.pParameter = data;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                     "Sign Init bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                              "Sign Init bad parameter length");
        mech.ulParameterLen = 0;
    }
    if (ret == CKR_OK) {
        mech.pParameter = data;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                   "Verify Init bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_VerifyInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                            "Verify Init bad parameter length");
        mech.ulParameterLen = 0;
    }

    return ret;
}
#endif

#ifndef NO_DH
static CK_OBJECT_HANDLE get_dh_priv_key(CK_SESSION_HANDLE session,
                                        CK_BBOOL extractable,
                                        CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE dh_2048_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &dhKeyType,        sizeof(dhKeyType)         },
        { CKA_EXTRACTABLE,       &extractable,      sizeof(CK_BBOOL)          },
        { CKA_DERIVE,            &ckTrue,           sizeof(ckTrue)            },
        { CKA_PRIME,             dh_ffdhe2048_p,    sizeof(dh_ffdhe2048_p)    },
        { CKA_BASE,              dh_ffdhe2048_g,    sizeof(dh_ffdhe2048_g)    },
        { CKA_VALUE,             dh_2048_priv,      sizeof(dh_2048_priv)      },
    };
    int dh_2048_priv_key_cnt =
                             sizeof(dh_2048_priv_key)/sizeof(*dh_2048_priv_key);

    ret = funcList->C_CreateObject(session, dh_2048_priv_key,
                                                     dh_2048_priv_key_cnt, obj);

    CHECK_CKR(ret, "DH Private Key Create Object");

    return ret;
}

static CK_OBJECT_HANDLE get_dh_pub_key(CK_SESSION_HANDLE session,
                                       CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    static CK_ATTRIBUTE dh_2048_pub_key[] = {
        { CKA_CLASS,             &pubKeyClass,      sizeof(pubKeyClass)       },
        { CKA_KEY_TYPE,          &dhKeyType,        sizeof(dhKeyType)         },
        { CKA_PRIME,             dh_ffdhe2048_p,    sizeof(dh_ffdhe2048_p)    },
        { CKA_BASE,              dh_ffdhe2048_g,    sizeof(dh_ffdhe2048_g)    },
        { CKA_VALUE,             dh_2048_pub,       sizeof(dh_2048_pub)       },
    };
    static int dh_2048_pub_key_cnt =
                               sizeof(dh_2048_pub_key)/sizeof(*dh_2048_pub_key);

    ret = funcList->C_CreateObject(session, dh_2048_pub_key,
                                                      dh_2048_pub_key_cnt, obj);
    CHECK_CKR(ret, "DH Public Key Create Object");

    return ret;
}

static CK_RV gen_dh_keys(CK_SESSION_HANDLE session, byte* prime, int primeSz,
                         byte* generator, int generatorSz,
                         CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
                         unsigned char* privId, int privIdLen,
                         unsigned char* pubId, int pubIdLen, int onToken)
{
    CK_RV             ret = CKR_OK;
    CK_OBJECT_HANDLE  priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  pub = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_BBOOL          token;
    CK_ATTRIBUTE      pubKeyTmpl[] = {
        { CKA_PRIME,           prime,              primeSz                    },
        { CKA_BASE,            generator,          generatorSz                },
        { CKA_TOKEN,           &token,             sizeof(token)              },
        { CKA_ID,              pubId,              pubIdLen                   },
    };
    int               pubTmplCnt = sizeof(pubKeyTmpl)/sizeof(*pubKeyTmpl);
    CK_ATTRIBUTE      privKeyTmpl[] = {
        { CKA_DERIVE,          &ckTrue,            sizeof(ckTrue)             },
        { CKA_TOKEN,           &token,             sizeof(token)              },
        { CKA_ID,              privId,             privIdLen                  },
    };
    int               privTmplCnt = sizeof(privKeyTmpl)/sizeof(*privKeyTmpl);

    if (privId == NULL)
        privTmplCnt--;
    if (pubId == NULL)
        pubTmplCnt--;
    token = onToken;

    if (ret == CKR_OK) {
        mech.mechanism      = CKM_DH_PKCS_KEY_PAIR_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter     = NULL;

        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                             pubTmplCnt, privKeyTmpl, privTmplCnt, &pub, &priv);
        CHECK_CKR(ret, "DH Key Generation");
    }
    if (ret == CKR_OK && privKey != NULL)
        *privKey = priv;
    if (ret == CKR_OK && pubKey != NULL)
        *pubKey = pub;
    if (ret == CKR_OK) {
        mech.pParameter = pubKeyTmpl;
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                             pubTmplCnt, privKeyTmpl, privTmplCnt, &pub, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "RSA Generate Key Pair bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = sizeof(pubKeyTmpl);
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                             pubTmplCnt, privKeyTmpl, privTmplCnt, &pub, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                  "RSA Generate Key Pair bad parameter Length");
        mech.ulParameterLen = 0;
    }

    return ret;
}

static CK_RV test_attributes_dh(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    unsigned char prime[2048/8];
    unsigned char base[1];
    unsigned char pubValue[2048/8];
    unsigned char privValue[sizeof(dh_2048_priv)];
    CK_ATTRIBUTE dhTmpl[] = {
        { CKA_PRIME,               prime,               sizeof(prime)         },
        { CKA_BASE,                base,                sizeof(base)          },
        { CKA_VALUE,               pubValue,            sizeof(pubValue)      },
    };
    CK_ULONG dhTmplCnt = sizeof(dhTmpl) / sizeof(*dhTmpl);
    CK_ATTRIBUTE dhBadTmpl[] = {
        { CKA_WRAP_TEMPLATE,       NULL,                0                     },
        { CKA_UNWRAP_TEMPLATE,     NULL,                0                     },
        { CKA_DERIVE_TEMPLATE,     NULL,                0                     },
    };
    CK_ULONG dhBadTmplCnt = sizeof(dhBadTmpl) / sizeof(*dhBadTmpl);
    CK_ATTRIBUTE dhPrivTmpl[] = {
        { CKA_PRIME,               NULL,                0                     },
        { CKA_BASE,                NULL,                0                     },
        { CKA_VALUE,               NULL,                0                     },
    };
    CK_ULONG dhPrivTmplCnt = sizeof(dhPrivTmpl) / sizeof(*dhPrivTmpl);
    int i;

    ret = get_dh_pub_key(session, &pub);
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, pub, dhTmpl, dhTmplCnt);
        CHECK_CKR(ret, "Get Attributes DH Public Key");
    }
    if (ret == CKR_OK) {
        for (i = 0; i < (int)dhBadTmplCnt; i++) {
            ret = funcList->C_GetAttributeValue(session, pub, &dhBadTmpl[i], 1);
            CHECK_CKR_FAIL(ret, CK_UNAVAILABLE_INFORMATION,
                                               "Get Attributes DH unavailable");
        }
    }
    if (ret == CKR_OK) {
        dhTmpl[2].pValue = NULL;
        dhTmpl[2].ulValueLen = 0;
        ret = funcList->C_GetAttributeValue(session, pub, dhTmpl, dhTmplCnt);
        CHECK_CKR(ret, "Get Attributes DH Public Key");
        dhTmpl[2].pValue = pubValue;
    }
    if (ret == CKR_OK) {
        CHECK_COND(dhTmpl[2].ulValueLen == sizeof(pubValue), ret,
                                          "Get Attributes DH pub value length");
    }

    if (ret == CKR_OK) {
        ret = get_dh_priv_key(session, CK_FALSE, &priv);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, dhPrivTmpl,
                                                                 dhPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes DH Public Key");
    }
    if (ret == CKR_OK) {
        CHECK_COND(dhPrivTmpl[0].ulValueLen == sizeof(prime), ret,
                                      "Get Attributes DH private prime length");
        dhPrivTmpl[0].pValue = prime;
    }
    if (ret == CKR_OK) {
        CHECK_COND(dhPrivTmpl[1].ulValueLen == sizeof(base), ret,
                                       "Get Attributes DH private base length");
        dhPrivTmpl[1].pValue = base;
    }
    if (ret == CKR_OK) {
        CHECK_COND(dhPrivTmpl[2].ulValueLen == CK_UNAVAILABLE_INFORMATION, ret,
                                      "Get Attributes DH private value length");
        dhPrivTmpl[2].pValue = privValue;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, dhPrivTmpl,
                                                                 dhPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes DH Public Key");
    }
    funcList->C_DestroyObject(session, priv);
    if (ret == CKR_OK) {
        ret = get_dh_priv_key(session, CK_TRUE, &priv);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, dhPrivTmpl,
                                                                 dhPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes DH Public Key");
    }
    if (ret == CKR_OK) {
        CHECK_COND(dhPrivTmpl[0].ulValueLen == sizeof(prime), ret,
                                      "Get Attributes DH private prime length");
        dhPrivTmpl[0].pValue = prime;
    }
    if (ret == CKR_OK) {
        CHECK_COND(dhPrivTmpl[1].ulValueLen == sizeof(base), ret,
                                       "Get Attributes DH private base length");
        dhPrivTmpl[1].pValue = base;
    }
    if (ret == CKR_OK) {
        CHECK_COND(dhPrivTmpl[2].ulValueLen == sizeof(privValue), ret,
                                      "Get Attributes DH private value length");
        dhPrivTmpl[2].pValue = privValue;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, dhPrivTmpl,
                                                                 dhPrivTmplCnt);
        CHECK_CKR(ret, "Get Attributes DH Public Key");
    }
    funcList->C_DestroyObject(session, priv);

    return ret;
}

static CK_RV dh_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privKey,
                     byte* pub, int pubLen, int check)
{
    CK_RV  ret;
    byte   out[2048/8];
    word32 outSz = sizeof(out);
    CK_MECHANISM     mech;
    CK_OBJECT_HANDLE secret;
    CK_KEY_TYPE      keyType = CKK_GENERIC_SECRET;
    CK_ULONG         secSz = outSz;
    CK_ATTRIBUTE     tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)        },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &secSz,          sizeof(secSz)          }
    };
    CK_ULONG         tmplCnt = sizeof(tmpl) / sizeof(*tmpl);

    mech.mechanism      = CKM_DH_PKCS_DERIVE;
    mech.ulParameterLen = pubLen;
    mech.pParameter     = pub;

    ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
    CHECK_CKR(ret, "DH Derive Key");
    if (ret == CKR_OK)
        ret = extract_secret(session, secret, out, &outSz);
    if (ret == CKR_OK && check) {
        if (outSz != (word32)sizeof_dh_2048_exp ||
                                         memcmp(out, dh_2048_exp, outSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "Secret compare with expected");
        }
    }
    if (ret == CKR_OK) {
        mech.pParameter = NULL;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                  "DH Derive Key no parameter");
        mech.pParameter = pub;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 0;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "DH Derive Key zero parameter length");
        mech.ulParameterLen = pubLen;
    }

    return ret;
}

static CK_RV test_dh_fixed_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = get_dh_priv_key(session, CK_FALSE, &priv);
    if (ret == CKR_OK)
        ret = get_dh_pub_key(session, &pub);
    if (ret == CKR_OK) {
        ret = dh_test(session, priv, dh_2048_peer, sizeof(dh_2048_peer), 1);
    }

    return ret;
}

static CK_RV test_dh_gen_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;

    ret = gen_dh_keys(session, dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p),
                      dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g), &pub, &priv, NULL,
                      0, NULL, 0, 0);
    if (ret == CKR_OK)
       ret = dh_test(session, priv, dh_2048_peer, sizeof(dh_2048_peer), 0);

    return ret;
}
#endif

#ifndef NO_AES
static CK_RV gen_aes_key(CK_SESSION_HANDLE session, int len, unsigned char* id,
                         int idLen, int onToken, CK_OBJECT_HANDLE* keyObj)
{
    CK_RV             ret = CKR_OK;
    CK_OBJECT_HANDLE  key = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_BBOOL          token;
    CK_ULONG          keyLen = len;
    CK_ATTRIBUTE      keyTmpl[] = {
        { CKA_VALUE_LEN,       &keyLen,            sizeof(keyLen)             },
        { CKA_TOKEN,           &token,             sizeof(token)              },
        { CKA_ID,              id,                 idLen                      },
    };
    int               keyTmplCnt = sizeof(keyTmpl)/sizeof(*keyTmpl);

    if (id == NULL)
        keyTmplCnt--;
    token = onToken;

    if (ret == CKR_OK) {
        mech.mechanism      = CKM_AES_KEY_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter     = NULL;

        ret = funcList->C_GenerateKey(session, &mech, keyTmpl, keyTmplCnt,
                                                                          &key);
        CHECK_CKR(ret, "AES Key Generation");
    }
    if (ret == CKR_OK && keyObj != NULL)
        *keyObj = key;
    if (ret == CKR_OK) {
        mech.pParameter = keyTmpl;
        ret = funcList->C_GenerateKey(session, &mech, keyTmpl, keyTmplCnt,
                                                                          &key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                  "Generate Key bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = sizeof(keyTmpl);
        ret = funcList->C_GenerateKey(session, &mech, keyTmpl, keyTmplCnt,
                                                                          &key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                           "Generate Key bad parameter length");
        mech.ulParameterLen = 0;
    }

    return ret;
}

static CK_RV find_aes_key(CK_SESSION_HANDLE session, unsigned char* id,
                             int idLen, CK_OBJECT_HANDLE* key)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE      keyTmpl[] = {
        { CKA_CLASS,     &secretKeyClass,  sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,  &aesKeyType,      sizeof(aesKeyType)     },
        { CKA_ID,        id,               idLen                  }
    };
    CK_ULONG keyTmplCnt = sizeof(keyTmpl) / sizeof(*keyTmpl);
    CK_ULONG count;

    ret = funcList->C_FindObjectsInit(session, keyTmpl, keyTmplCnt);
    CHECK_CKR(ret, "AES Key Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, key, 1, &count);
        CHECK_CKR(ret, "AES Key Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "AES Key Find Objects Final");
    }
    if (ret == CKR_OK && count == 0) {
        ret = -1;
        CHECK_CKR(ret, "AES Key Find Objects Count");
    }

    return ret;
}

#ifdef HAVE_AES_CBC
static CK_RV aes_cbc_encrypt_data_test(CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE privKey, int check)
{
    CK_RV  ret;
    byte   out[32];
    word32 outSz = sizeof(out);
    CK_OBJECT_HANDLE secret;
    CK_KEY_TYPE      keyType = CKK_GENERIC_SECRET;
    CK_ULONG         secSz = outSz;
    CK_BYTE          data[16] = { 0 };
    CK_AES_CBC_ENCRYPT_DATA_PARAMS aesParams = {
        { 0 }, data, sizeof(data)
    };
    CK_ATTRIBUTE     tmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)        },
        { CKA_PRIVATE,     &ckFalse,        sizeof(ckFalse)        },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &secSz,          sizeof(secSz)          }
    };
    CK_ULONG         tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_MECHANISM     mech = {
        CKM_AES_CBC_ENCRYPT_DATA, &aesParams, sizeof(aesParams)
    };

    ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
    CHECK_CKR(ret, "AES CBC Encrypt Derive Key");
    if (ret == CKR_OK)
        ret = extract_secret(session, secret, out, &outSz);
    if (ret == CKR_OK && check) {
        if (outSz != sizeof(aes_128_cbc_encrypt_exp) ||
                             memcmp(out, aes_128_cbc_encrypt_exp, outSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "Secret compare with expected");
        }
    }
    if (ret == CKR_OK) {
        mech.pParameter = NULL;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                     "AES CBC Encrypt Derive Key no parameter");
        mech.pParameter = &aesParams;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 0;
        ret = funcList->C_DeriveKey(session, &mech, privKey, tmpl, tmplCnt,
                                                                       &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                            "AES CBC Encrypt Derive Key zero parameter length");
        mech.ulParameterLen = sizeof(aesParams);
    }

    return ret;
}


static CK_RV test_aes_cbc_encdec(CK_SESSION_HANDLE session, unsigned char* exp,
                                 CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    byte plain[32], enc[32], dec[32], iv[16];
    CK_ULONG plainSz, encSz, decSz, ivSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);

    mech.mechanism      = CKM_AES_CBC;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CBC Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Encrypt no enc");
    }
    if (ret == CKR_OK && encSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Encrypt encrypted length");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                               "AES-CBC Encrypt zero enc size");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR(ret, "AES-CBC Encrypt");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (encSz != plainSz || XMEMCMP(enc, exp, encSz) != 0)
            ret = -1;
        CHECK_CKR(ret, "AES-CBC Encrypt Result not matching expected");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, NULL, &decSz);
        CHECK_CKR(ret, "AES-CBC Decrypt");
    }
    if (ret == CKR_OK && decSz != encSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Decrypt decrypted length");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                               "AES-CBC Decrypt zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-CBC Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Decrypted data match plain text");
        }
    }


    return ret;
}

static CK_RV test_aes_cbc_update(CK_SESSION_HANDLE session, unsigned char* exp,
                                 CK_OBJECT_HANDLE key, CK_ULONG inc)
{
    CK_RV ret;
    byte plain[32], enc[32], dec[32], iv[16];
    byte* pIn;
    byte* pOut = NULL;
    CK_ULONG plainSz, encSz, decSz, ivSz, remSz, cumSz, partSz, inRemSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    memset(enc, 0, sizeof(enc));
    memset(dec, 0, sizeof(dec));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);
    remSz = encSz;
    cumSz = 0;

    mech.mechanism      = CKM_AES_CBC;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CBC Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 1;
        ret = funcList->C_EncryptUpdate(session, plain, 1, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Encrypt Update");
    }
    if (ret == CKR_OK && encSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Encrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 16, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Encrypt Update");
    }
    if (ret == CKR_OK && encSz != 16) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Encrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 16, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                        "AES-CBC Encrypt Update zero enc size");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        pIn = plain;
        pOut = enc;
        inRemSz = plainSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_EncryptUpdate(session, pIn, partSz, pOut, &encSz);
            CHECK_CKR(ret, "AES-CBC Encrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += encSz;
            cumSz += encSz;
            encSz = (remSz -= encSz);
        }
    }
    if (ret == CKR_OK) {
        encSz = 1;
        ret = funcList->C_EncryptFinal(session, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Encrypt Final");
    }
    if (ret == CKR_OK && encSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Encrypt Final encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = remSz;
        ret = funcList->C_EncryptFinal(session, pOut, &encSz);
        CHECK_CKR(ret, "AES-CBC Encrypt Final");
        encSz += cumSz;
    }
    if (ret == CKR_OK && exp != NULL) {
        if (encSz != plainSz || XMEMCMP(enc, exp, encSz) != 0)
            ret = -1;
        CHECK_CKR(ret, "AES-CBC Encrypt Update Result not matching expected");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 1;
        ret = funcList->C_DecryptUpdate(session, enc, 1, NULL, &decSz);
        CHECK_CKR(ret, "AES-CBC Decrypt Update");
    }
    if (ret == CKR_OK && decSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Decrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_DecryptUpdate(session, enc, 16, NULL, &decSz);
        CHECK_CKR(ret, "AES-CBC Decrypt Update");
    }
    if (ret == CKR_OK && decSz != 16) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Decrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_DecryptUpdate(session, enc, 16, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                        "AES-CBC Encrypt Update zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        pIn = enc;
        pOut = dec;
        cumSz = 0;
        remSz = decSz;
        inRemSz = encSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_DecryptUpdate(session, pIn, partSz, pOut, &decSz);
            CHECK_CKR(ret, "AES-CBC Decrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += decSz;
            cumSz += decSz;
            decSz = (remSz -= decSz);
        }
    }
    if (ret == CKR_OK) {
        decSz = 1;
        ret = funcList->C_DecryptFinal(session, NULL, &decSz);
        CHECK_CKR(ret, "AES-CBC Decrypt Final");
    }
    if (ret == CKR_OK && decSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Decrypt Final decrypted size");
    }
    if (ret == CKR_OK) {
        decSz = remSz;
        ret = funcList->C_DecryptFinal(session, pOut, &decSz);
        CHECK_CKR(ret, "AES-CBC Decrypt Final");
        decSz += cumSz;
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Decrypted data length match");
        }
        else if (XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Decrypted data match plain text");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Encrypt Init");
    }
    if (ret == CKR_OK) {
        encSz = sizeof(enc);
        ret = funcList->C_EncryptUpdate(session, plain, 1, enc, &encSz);
        CHECK_CKR(ret, "AES-CBC Encrypt Update");
    }
    if (ret == CKR_OK) {
        CHECK_COND(encSz == 0, ret,
                             "AES-CBC Encrypt Update less than block out size");
    }
    if (ret == CKR_OK) {
        encSz = sizeof(enc);
        ret = funcList->C_EncryptFinal(session, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_DATA_LEN_RANGE,
                                       "AES-CBC Encrypt Final less than block");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        ret = funcList->C_DecryptUpdate(session, enc, 1, dec, &decSz);
        CHECK_CKR(ret, "AES-CBC Decrypt Update");
    }
    if (ret == CKR_OK) {
        CHECK_COND(decSz == 0, ret,
                             "AES-CBC Decrypt Update less than block out size");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        ret = funcList->C_DecryptFinal(session, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_DATA_LEN_RANGE,
                                       "AES-CBC Decrypt Final less than block");
    }

    return ret;
}

static CK_RV test_aes_cbc_fixed_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_encdec(session, aes_128_cbc_exp, key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_update(session, aes_128_cbc_exp, key, 16);
    if (ret == CKR_OK)
        ret = test_aes_cbc_update(session, aes_128_cbc_exp, key, 1);
    if (ret == CKR_OK)
        ret = test_aes_cbc_update(session, aes_128_cbc_exp, key, 5);
    if (ret == CKR_OK)
        ret = test_aes_cbc_update(session, aes_128_cbc_exp, key, 18);
    if (ret == CKR_OK)
        ret = aes_cbc_encrypt_data_test(session, key, 1);

    return ret;
}

static CK_RV test_aes_cbc_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    CK_OBJECT_HANDLE generic;
    byte plain[32], enc[32], dec[32], iv[16];
    CK_ULONG plainSz, encSz, decSz, ivSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);

    mech.mechanism      = CKM_AES_CBC;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK) {
        ret = get_generic_key(session, plain, sizeof(plain), CK_FALSE,
                                                                      &generic);
    }
    if (ret == CKR_OK) {
       ret = funcList->C_EncryptInit(session, &mech, generic);
       CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                         "AES-CBC Encrypt Init wrong key type");
    }
    if (ret == CKR_OK) {
       ret = funcList->C_DecryptInit(session, &mech, generic);
       CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                         "AES-CBC Decrypt Init wrong key type");
    }

    if (ret == CKR_OK) {
       mech.pParameter = NULL;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "AES-CBC Encrypt Init parameter NULL");
       mech.pParameter = iv;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = ivSz - 1;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                 "AES-CBC Encrypt Init parameter length short");
       mech.ulParameterLen = ivSz;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = ivSz + 1;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                  "AES-CBC Encrypt Init parameter length long");
       mech.ulParameterLen = ivSz;
    }
    if (ret == CKR_OK) {
       mech.pParameter = NULL;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "AES-CBC Decrypt Init parameter NULL");
       mech.pParameter = iv;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = ivSz - 1;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                 "AES-CBC Decrypt Init parameter length short");
       mech.ulParameterLen = ivSz;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = ivSz + 1;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                  "AES-CBC Decrypt Init parameter length long");
       mech.ulParameterLen = ivSz;
    }

    if (ret == CKR_OK) {
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR(ret, "AES-CBC Encrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                  "AES-CBC Decrypt wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptUpdate(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                           "AES-CBC Decrypt Update wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, enc, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                            "AES-CBC Decrypt Final wrong init");
    }
    if (ret == CKR_OK) {
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR(ret, "AES-CBC Decrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                  "AES-CBC Encrypt wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                           "AES-CBC Encrypt Update wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                            "AES-CBC Encrypt Final wrong init");
    }

    return ret;
}

static CK_RV test_aes_cbc_gen_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = gen_aes_key(session, 16, NULL, 0, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_encdec(session, NULL, key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_update(session, NULL, key, 32);
    if (ret == CKR_OK)
        ret = aes_cbc_encrypt_data_test(session, key, 0);

    return ret;
}

static CK_RV test_aes_cbc_gen_key_id(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    unsigned char* id = (unsigned char*)"123aes128";
    int idSz = 9;

    ret = gen_aes_key(session, 32, id, idSz, 0, NULL);
    if (ret == CKR_OK)
        ret = find_aes_key(session, id, idSz, &key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_encdec(session, NULL, key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_update(session, NULL, key, 32);
    if (ret == CKR_OK)
        ret = aes_cbc_encrypt_data_test(session, key, 0);

    return ret;
}

static CK_RV test_aes_cbc_pad_len_test(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    CK_MECHANISM mech;
    CK_ULONG plainSz, encSz, ivSz;
    byte plain[15], iv[16];

    memset(plain, 9, sizeof(plain));
    plainSz = sizeof(plain);
    encSz = plainSz;
    ivSz = sizeof(iv);

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = get_aes_128_key(session, NULL, 0, &key);
    CHECK_CKR(ret, "Getting AES key");
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Init");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt no enc");
    }
    /* CKM_AES_CBC_PAD length is rounded up to the nearest multiple of 16 */
    if (ret == CKR_OK && encSz != 16) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Encrypt encrypted length");
    }
    return ret;
}

static CK_RV test_aes_cbc_pad_encdec(CK_SESSION_HANDLE session,
                                     unsigned char* exp, CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    byte plain[32], enc[sizeof(plain)+16], dec[32], iv[16];
    CK_ULONG plainSz, encSz, decSz, ivSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CBC Pad Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt no enc");
    }
    if (ret == CKR_OK && encSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Encrypt encrypted length");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                           "AES-CBC Pad Encrypt zero enc size");
    }
    if (ret == CKR_OK) {
        encSz = sizeof(enc);
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (encSz != plainSz + 16 || XMEMCMP(enc, exp, encSz) != 0)
            ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Result not matching expected");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, NULL, &decSz);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt");
    }
    if (ret == CKR_OK && decSz != encSz-1) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Decrypt decrypted length");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Pad Decrypted data match plain text");
        }
    }


    return ret;
}

static CK_RV test_aes_cbc_pad_update(CK_SESSION_HANDLE session,
                                     unsigned char* exp, CK_OBJECT_HANDLE key,
                                     CK_ULONG inc)
{
    CK_RV ret;
    byte plain[32], enc[sizeof(plain)+16], dec[32], iv[16];
    byte* pIn;
    byte* pOut = NULL;
    CK_ULONG plainSz, encSz, decSz, ivSz, remSz, cumSz, partSz, inRemSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    memset(enc, 0, sizeof(enc));
    memset(dec, 0, sizeof(dec));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);
    remSz = encSz;
    cumSz = 0;

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CBC Pad Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 1;
        ret = funcList->C_EncryptUpdate(session, plain, 1, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Update");
    }
    if (ret == CKR_OK && encSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 16, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Update");
    }
    if (ret == CKR_OK && encSz != 16) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 16, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                    "AES-CBC Pad Encrypt Update zero enc size");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        pIn = plain;
        pOut = enc;
        inRemSz = plainSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_EncryptUpdate(session, pIn, partSz, pOut, &encSz);
            CHECK_CKR(ret, "AES-CBC Pad Encrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += encSz;
            cumSz += encSz;
            encSz = (remSz -= encSz);
        }
    }
    if (ret == CKR_OK) {
        encSz = 1;
        ret = funcList->C_EncryptFinal(session, NULL, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Final");
    }
    if (ret == CKR_OK && encSz != 16) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Final encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = remSz;
        ret = funcList->C_EncryptFinal(session, pOut, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Final");
        encSz += cumSz;
    }
    if (ret == CKR_OK && exp != NULL) {
        if (encSz != plainSz + 16 || XMEMCMP(enc, exp, encSz) != 0)
            ret = -1;
        CHECK_CKR(ret,
                     "AES-CBC Pad Encrypt Update Result not matching expected");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 1;
        ret = funcList->C_DecryptUpdate(session, enc, 1, NULL, &decSz);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Update");
    }
    if (ret == CKR_OK && decSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_DecryptUpdate(session, enc, 16, NULL, &decSz);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Update");
    }
    if (ret == CKR_OK && decSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_DecryptUpdate(session, enc, 32, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                    "AES-CBC Pad Encrypt Update zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        pIn = enc;
        pOut = dec;
        cumSz = 0;
        remSz = decSz;
        inRemSz = encSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_DecryptUpdate(session, pIn, partSz, pOut, &decSz);
            CHECK_CKR(ret, "AES-CBC Pad Decrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += decSz;
            cumSz += decSz;
            decSz = (remSz -= decSz);
        }
    }
    if (ret == CKR_OK) {
        decSz = 16;
        ret = funcList->C_DecryptFinal(session, NULL, &decSz);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Final");
    }
    if (ret == CKR_OK && decSz != 15) {
        ret = -1;
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Final decrypted size");
    }
    if (ret == CKR_OK) {
        decSz = remSz;
        ret = funcList->C_DecryptFinal(session, pOut, &decSz);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Final");
        decSz += cumSz;
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Pad Decrypted data length match");
        }
        else if (XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Pad Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV test_aes_cbc_pad(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                              CK_ULONG len, CK_ULONG inc)
{
    CK_RV ret;
    byte plain[32], enc[sizeof(plain)+16], dec[32], iv[16];
    byte* pIn;
    byte* pOut = NULL;
    CK_ULONG encSz, decSz, ivSz, remSz, cumSz, partSz, inRemSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    memset(enc, 0, sizeof(enc));
    memset(dec, 0, sizeof(dec));
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);
    remSz = encSz;
    cumSz = 0;

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CBC Pad Encrypt Init");
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, len, enc, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt no enc");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != len) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Pad Decrypted data length match");
        }
        else if (XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Pad Decrypted data match plain text");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Init");
    }
    if (ret == CKR_OK) {
        pIn = plain;
        pOut = enc;
        inRemSz = len;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_EncryptUpdate(session, pIn, partSz, pOut, &encSz);
            CHECK_CKR(ret, "AES-CBC Pad Encrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += encSz;
            cumSz += encSz;
            encSz = (remSz -= encSz);
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, pOut, &encSz);
        CHECK_CKR(ret, "AES-CBC Pad Encrypt Final");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Init");
    }
    if (ret == CKR_OK) {
        pIn = enc;
        pOut = dec;
        cumSz = 0;
        remSz = decSz;
        inRemSz = encSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_DecryptUpdate(session, pIn, partSz, pOut, &decSz);
            CHECK_CKR(ret, "AES-CBC Pad Decrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += decSz;
            cumSz += decSz;
            decSz = (remSz -= decSz);
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, pOut, &decSz);
        CHECK_CKR(ret, "AES-CBC Pad Decrypt Final");
        decSz += cumSz;
    }
    if (ret == CKR_OK) {
        if (decSz != len) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Pad Decrypted data length match");
        }
        else if (XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CBC Pad Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV test_aes_cbc_pad_fixed_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_encdec(session, aes_128_cbc_pad_exp, key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_update(session, aes_128_cbc_pad_exp, key, 16);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_update(session, aes_128_cbc_pad_exp, key, 1);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_update(session, aes_128_cbc_pad_exp, key, 5);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_update(session, aes_128_cbc_pad_exp, key, 18);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad(session, key, 31, 1);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad(session, key, 17, 4);

    return ret;
}

static CK_RV test_aes_cbc_pad_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    CK_OBJECT_HANDLE generic;
    byte plain[32], enc[sizeof(plain)+16], dec[32], iv[16];
    CK_ULONG plainSz, encSz, decSz, ivSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK) {
        ret = get_generic_key(session, plain, sizeof(plain), CK_FALSE,
                                                                      &generic);
    }
    if (ret == CKR_OK) {
       ret = funcList->C_EncryptInit(session, &mech, generic);
       CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                     "AES-CBC Pad Encrypt Init wrong key type");
    }
    if (ret == CKR_OK) {
       ret = funcList->C_DecryptInit(session, &mech, generic);
       CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                     "AES-CBC Pad Decrypt Init wrong key type");
    }

    if (ret == CKR_OK) {
       mech.pParameter = NULL;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                     "AES-CBC Pad Encrypt Init parameter NULL");
       mech.pParameter = iv;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = ivSz - 1;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                             "AES-CBC Pad Encrypt Init parameter length short");
       mech.ulParameterLen = ivSz;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = ivSz + 1;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                              "AES-CBC Pad Encrypt Init parameter length long");
       mech.ulParameterLen = ivSz;
    }
    if (ret == CKR_OK) {
       mech.pParameter = NULL;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                     "AES-CBC Pad Decrypt Init parameter NULL");
       mech.pParameter = iv;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = ivSz - 1;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                             "AES-CBC Pad Decrypt Init parameter length short");
       mech.ulParameterLen = ivSz;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = ivSz + 1;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                              "AES-CBC Pad Decrypt Init parameter length long");
       mech.ulParameterLen = ivSz;
    }

    if (ret == CKR_OK) {
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR(ret, "AES-CBC Pad Encrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                              "AES-CBC Pad Decrypt wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptUpdate(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                       "AES-CBC Pad Decrypt Update wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, enc, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                        "AES-CBC Pad Decrypt Final wrong init");
    }
    if (ret == CKR_OK) {
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR(ret, "AES-CBC Pad Decrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                              "AES-CBC Pad Encrypt wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                       "AES-CBC Pad Encrypt Update wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                        "AES-CBC Pad Encrypt Final wrong init");
    }

    return ret;
}

static CK_RV test_aes_cbc_pad_gen_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = gen_aes_key(session, 16, NULL, 0, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_encdec(session, NULL, key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_update(session, NULL, key, 32);

    return ret;
}

static CK_RV test_aes_cbc_pad_gen_key_id(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    unsigned char* id = (unsigned char*)"123aes128";
    int idSz = 9;

    ret = gen_aes_key(session, 32, id, idSz, 0, NULL);
    if (ret == CKR_OK)
        ret = find_aes_key(session, id, idSz, &key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_encdec(session, NULL, key);
    if (ret == CKR_OK)
        ret = test_aes_cbc_pad_update(session, NULL, key, 32);

    return ret;
}
#endif

#ifdef HAVE_AESCTR
static CK_RV test_aes_ctr_encdec(CK_SESSION_HANDLE session,
                                  unsigned char* exp, CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    byte plain[32], enc[sizeof(plain)], dec[32];
    CK_ULONG plainSz, encSz, decSz;
    CK_MECHANISM mech;
    CK_AES_CTR_PARAMS ctrParams;

    memset(plain, 9, sizeof(plain));
    memset(ctrParams.cb, 0, sizeof(ctrParams.cb)); // Initialize counter to zero
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);

    mech.mechanism      = CKM_AES_CTR;
    mech.pParameter     = &ctrParams;
    mech.ulParameterLen = sizeof(ctrParams);
    ctrParams.ulCounterBits = 128;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CTR Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &encSz);
        CHECK_CKR(ret, "AES-CTR Encrypt no enc");
    }
    if (ret == CKR_OK && encSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTR Encrypt encrypted length");
    }
    if (ret == CKR_OK) {
        encSz = sizeof(enc);
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR(ret, "AES-CTR Encrypt");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (XMEMCMP(enc, exp, encSz) != 0)
            ret = -1;
        CHECK_CKR(ret, "AES-CTR Encrypt Result not matching expected");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTR Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-CTR Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CTR Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV test_aes_ctr_update(CK_SESSION_HANDLE session,
                                  unsigned char* exp, CK_OBJECT_HANDLE key,
                                  CK_ULONG inc)
{
    CK_RV ret;
    byte plain[32], enc[sizeof(plain)], dec[32];
    byte* pIn;
    byte* pOut = NULL;
    CK_ULONG plainSz, encSz, decSz, remSz, cumSz, partSz, inRemSz;
    CK_MECHANISM mech;
    CK_AES_CTR_PARAMS ctrParams;

    memset(plain, 9, sizeof(plain));
    memset(ctrParams.cb, 0, sizeof(ctrParams.cb)); // Initialize counter to zero
    memset(enc, 0, sizeof(enc));
    memset(dec, 0, sizeof(dec));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    remSz = encSz;
    cumSz = 0;

    mech.mechanism      = CKM_AES_CTR;
    mech.pParameter     = &ctrParams;
    mech.ulParameterLen = sizeof(ctrParams);
    ctrParams.ulCounterBits = 128;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CTR Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 16, NULL, &encSz);
        CHECK_CKR(ret, "AES-CTR Encrypt Update");
    }
    if (ret == CKR_OK && encSz != 16) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTR Encrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = sizeof(enc);
        pIn = plain;
        pOut = enc;
        inRemSz = plainSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_EncryptUpdate(session, pIn, partSz, pOut, &encSz);
            CHECK_CKR(ret, "AES-CTR Encrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += encSz;
            cumSz += encSz;
            encSz = (remSz -= encSz);
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, pOut, &encSz);
        CHECK_CKR(ret, "AES-CTR Encrypt Final");
        encSz += cumSz;
    }
    if (ret == CKR_OK && exp != NULL) {
        if (XMEMCMP(enc, exp, encSz) != 0)
            ret = -1;
        CHECK_CKR(ret,
                     "AES-CTR Encrypt Update Result not matching expected");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTR Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        pIn = enc;
        pOut = dec;
        cumSz = 0;
        remSz = decSz;
        inRemSz = encSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_DecryptUpdate(session, pIn, partSz, pOut, &decSz);
            CHECK_CKR(ret, "AES-CTR Decrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += decSz;
            cumSz += decSz;
            decSz = (remSz -= decSz);
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, pOut, &decSz);
        CHECK_CKR(ret, "AES-CTR Decrypt Final");
        decSz += cumSz;
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CTR Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV test_aes_ctr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                          CK_ULONG len, CK_ULONG inc)
{
    CK_RV ret;
    byte plain[32], enc[sizeof(plain)], dec[32];
    byte* pIn;
    byte* pOut = NULL;
    CK_ULONG encSz, decSz, remSz, cumSz, partSz, inRemSz;
    CK_MECHANISM mech;
    CK_AES_CTR_PARAMS ctrParams;

    memset(plain, 9, sizeof(plain));
    memset(ctrParams.cb, 0, sizeof(ctrParams.cb)); // Initialize counter to zero
    memset(enc, 0, sizeof(enc));
    memset(dec, 0, sizeof(dec));
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    remSz = encSz;
    cumSz = 0;

    mech.mechanism      = CKM_AES_CTR;
    mech.pParameter     = &ctrParams;
    mech.ulParameterLen = sizeof(ctrParams);
    ctrParams.ulCounterBits = 128;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CTR Encrypt Init");
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, len, enc, &encSz);
        CHECK_CKR(ret, "AES-CTR Encrypt no enc");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTR Decrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-CTR Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != len || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CTR Decrypted data match plain text");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTR Encrypt Init");
    }
    if (ret == CKR_OK) {
        pIn = plain;
        pOut = enc;
        inRemSz = len;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_EncryptUpdate(session, pIn, partSz, pOut, &encSz);
            CHECK_CKR(ret, "AES-CTR Encrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += encSz;
            cumSz += encSz;
            encSz = (remSz -= encSz);
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, pOut, &encSz);
        CHECK_CKR(ret, "AES-CTR Encrypt Final");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTR Decrypt Init");
    }
    if (ret == CKR_OK) {
        encSz = sizeof(enc);
        decSz = sizeof(dec);
        remSz = encSz;
        cumSz = 0;
        pIn = enc;
        pOut = dec;
        inRemSz = len;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_DecryptUpdate(session, pIn, partSz, pOut, &decSz);
            CHECK_CKR(ret, "AES-CTR Decrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += decSz;
            cumSz += decSz;
            decSz = (remSz -= decSz);
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, pOut, &decSz);
        CHECK_CKR(ret, "AES-CTR Decrypt Final");
        decSz += cumSz;
    }
    if (ret == CKR_OK) {
        if (decSz != len || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CTR Decrypted data match plain text");
        }
    }

    return ret;
}

static byte aes_128_ctr_exp[32] = {
    0x09, 0x12, 0x74, 0x6f, 0x55, 0xd5, 0xb2, 0x8b, 0x10, 0x05, 0xed, 0x50,
    0xf3, 0x0c, 0x47, 0x16, 0xf2, 0xec, 0x03, 0x0d, 0xa5, 0x8d, 0x41, 0x0b,
    0xe7, 0x3a, 0x3c, 0xcd, 0x81, 0xb6, 0xf6, 0x18
};

static CK_RV test_aes_ctr_fixed_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_ctr_encdec(session, aes_128_ctr_exp, key);
    if (ret == CKR_OK)
        ret = test_aes_ctr_update(session, aes_128_ctr_exp, key, 16);
    if (ret == CKR_OK)
        ret = test_aes_ctr_update(session, aes_128_ctr_exp, key, 1);
    if (ret == CKR_OK)
        ret = test_aes_ctr_update(session, aes_128_ctr_exp, key, 5);
    if (ret == CKR_OK)
        ret = test_aes_ctr_update(session, aes_128_ctr_exp, key, 18);
    if (ret == CKR_OK)
        ret = test_aes_ctr(session, key, 31, 1);
    if (ret == CKR_OK)
        ret = test_aes_ctr(session, key, 17, 4);

    return ret;
}
#endif /* HAVE_AESCTR */

#ifdef HAVE_AESGCM
static CK_RV test_aes_gcm_encdec(CK_SESSION_HANDLE session, unsigned char* aad,
                                 int aadLen, int tagBits, unsigned char* exp,
                                 unsigned char* expTag, CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    byte plain[32], enc[48], dec[48], iv[12];
    CK_ULONG plainSz, encSz, decSz;
    CK_MECHANISM mech;
    CK_GCM_PARAMS gcmParams;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);

    gcmParams.pIv       = iv;
    gcmParams.ulIvLen   = sizeof(iv);
    gcmParams.pAAD      = aad;
    gcmParams.ulAADLen  = aadLen;
    gcmParams.ulTagBits = tagBits;

    mech.mechanism      = CKM_AES_GCM;
    mech.ulParameterLen = sizeof(gcmParams);
    mech.pParameter     = &gcmParams;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-GCM Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &encSz);
        CHECK_CKR(ret, "AES-GCM Encrypt");
    }
    if (ret == CKR_OK && encSz != plainSz + tagBits / 8) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt encrypted length");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "AES-GCM Encrypt");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR(ret, "AES-GCM Encrypt");
    }
    if (ret == CKR_OK && encSz != plainSz + tagBits / 8) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt Result not correct length");
    }
    if (ret == CKR_OK && exp != NULL && XMEMCMP(enc, exp, plainSz) != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt Result not matching expected");
    }
    if (ret == CKR_OK && expTag != NULL &&
                             XMEMCMP(enc + plainSz, expTag, tagBits / 8) != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt Result not matching expected tag");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-GCM Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, NULL, &decSz);
        CHECK_CKR(ret, "AES-GCM Decrypt");
    }
    if (ret == CKR_OK && decSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Decrypt decrypted length");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "AES-GCM Decrypt");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-GCM Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-GCM Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV test_aes_gcm_update(CK_SESSION_HANDLE session, unsigned char* aad,
                                 int aadLen, int tagBits, unsigned char* exp,
                                 unsigned char* expTag, CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    byte plain[32], enc[32], dec[32], iv[12], auth[16];
    CK_ULONG plainSz, encSz, decSz, authSz;
    CK_MECHANISM mech;
    CK_GCM_PARAMS gcmParams;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    authSz = sizeof(dec);

    gcmParams.pIv       = iv;
    gcmParams.ulIvLen   = sizeof(iv);
    gcmParams.pAAD      = aad;
    gcmParams.ulAADLen  = aadLen;
    gcmParams.ulTagBits = tagBits;

    mech.mechanism      = CKM_AES_GCM;
    mech.ulParameterLen = sizeof(gcmParams);
    mech.pParameter     = &gcmParams;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-GCM Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 1, NULL, &encSz);
        CHECK_CKR(ret, "AES-GCM Encrypt Update");
    }
    if (ret == CKR_OK && encSz != 1) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 1, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                        "AES-GCM Encrypt Update zero enc size");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(session, plain, plainSz, enc, &encSz);
        CHECK_CKR(ret, "AES-GCM Encrypt Update");
    }
    if (ret == CKR_OK) {
        authSz = 0;
        ret = funcList->C_EncryptFinal(session, NULL, &authSz);
        CHECK_CKR(ret, "AES-GCM Encrypt Final no auth");
    }
    if (ret == CKR_OK && authSz != (CK_ULONG)tagBits / 8) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt Final encrypted size");
    }
    if (ret == CKR_OK) {
        authSz = 0;
        ret = funcList->C_EncryptFinal(session, auth, &authSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                        "AES-GCM Encrypt Final zero auth size");
        authSz = sizeof(auth);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, auth, &authSz);
        CHECK_CKR(ret, "AES-GCM Encrypt Final");
    }
    if (ret == CKR_OK && encSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt Result not correct length");
    }
    if (ret == CKR_OK && exp != NULL && XMEMCMP(enc, exp, plainSz) != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt Result not matching expected");
    }
    if (ret == CKR_OK && expTag != NULL &&
                                      XMEMCMP(auth, expTag, tagBits / 8) != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Encrypt Result not matching expected tag");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-GCM Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 1;
        ret = funcList->C_DecryptUpdate(session, enc, encSz, NULL, &decSz);
        CHECK_CKR(ret, "AES-GCM Decrypt Update no dec");
    }
    if (ret == CKR_OK && decSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Decrypt decrypt size");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        ret = funcList->C_DecryptUpdate(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-GCM Decrypt Update no dec");
    }
    if (ret == CKR_OK && decSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Decrypt decrypt size");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        ret = funcList->C_DecryptUpdate(session, auth, authSz, dec, &decSz);
        CHECK_CKR(ret, "AES-GCM Decrypt Update");
    }
    if (ret == CKR_OK && decSz != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Decrypt Update Result not correct length");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_DecryptFinal(session, NULL, &decSz);
        CHECK_CKR(ret, "AES-GCM Decrypt Final no dec");
    }
    if (ret == CKR_OK && decSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-GCM Decrypt Final decrypted size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_DecryptFinal(session, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                         "AES-GCM Decrypt Final zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, dec, &decSz);
        CHECK_CKR(ret, "AES-GCM Decrypt Final");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz) {
            ret = -1;
            CHECK_CKR(ret, "AES-GCM Decrypted data length does not match");
        }
        if (ret == CKR_OK && XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-GCM Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV test_aes_gcm_fixed_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    byte* aad = (unsigned char*)"aad";

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK) {
        ret = test_aes_gcm_encdec(session, NULL, 0, 128, aes_128_gcm_exp,
                                                      aes_128_gcm_exp_tag, key);
    }
    if (ret == CKR_OK) {
        ret = test_aes_gcm_update(session, NULL, 0, 128, aes_128_gcm_exp,
                                                      aes_128_gcm_exp_tag, key);
    }
    if (ret == CKR_OK) {
        ret = test_aes_gcm_encdec(session, aad, 3, 128, NULL, NULL, key);
    }
    if (ret == CKR_OK) {
        ret = test_aes_gcm_update(session, aad, 3, 128, NULL, NULL, key);
    }

    return ret;
}

static CK_RV test_aes_gcm_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    CK_OBJECT_HANDLE generic;
    byte plain[32], enc[48], dec[48], iv[12];
    CK_ULONG plainSz, encSz, decSz;
    CK_MECHANISM mech;
    CK_GCM_PARAMS gcmParams;
    int tagBits = 128;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);

    gcmParams.pIv       = iv;
    gcmParams.ulIvLen   = sizeof(iv);
    gcmParams.pAAD      = NULL;
    gcmParams.ulAADLen  = 0;
    gcmParams.ulTagBits = tagBits;

    mech.mechanism      = CKM_AES_GCM;
    mech.ulParameterLen = sizeof(gcmParams);
    mech.pParameter     = &gcmParams;

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK) {
        ret = get_generic_key(session, plain, sizeof(plain), CK_FALSE,
                                                                      &generic);
    }
    if (ret == CKR_OK) {
       ret = funcList->C_EncryptInit(session, &mech, generic);
       CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                         "AES-GCM Encrypt Init wrong key type");
    }
    if (ret == CKR_OK) {
       ret = funcList->C_DecryptInit(session, &mech, generic);
       CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                         "AES-GCM Decrypt Init wrong key type");
    }

    if (ret == CKR_OK) {
       mech.pParameter = NULL;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "AES-GCM Encrypt Init parameter NULL");
       mech.pParameter = &gcmParams;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = 0;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                  "AES-GCM Encrypt Init parameter length zero");
       mech.ulParameterLen = sizeof(gcmParams);
    }
    if (ret == CKR_OK) {
       gcmParams.ulIvLen = 32;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "AES-GCM Encrypt Init IV length long");
       gcmParams.ulIvLen = sizeof(iv);
    }
    if (ret == CKR_OK) {
       gcmParams.ulTagBits = 256;
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                   "AES-GCM Encrypt Init tag bits length long");
       gcmParams.ulTagBits = tagBits;
    }
    if (ret == CKR_OK) {
       mech.pParameter = NULL;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "AES-GCM Decrypt Init parameter NULL");
       mech.pParameter = &gcmParams;
    }
    if (ret == CKR_OK) {
       mech.ulParameterLen = 0;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                  "AES-GCM Decrypt Init parameter length zero");
       mech.ulParameterLen = sizeof(gcmParams);
    }
    if (ret == CKR_OK) {
       gcmParams.ulIvLen = 32;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "AES-GCM Decrypt Init IV length long");
       gcmParams.ulIvLen = sizeof(iv);
    }
    if (ret == CKR_OK) {
       gcmParams.ulTagBits = 256;
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                   "AES-GCM Decrypt Init tag bits length long");
       gcmParams.ulTagBits = tagBits;
    }

    if (ret == CKR_OK) {
       ret = funcList->C_EncryptInit(session, &mech, key);
       CHECK_CKR(ret, "AES-GCM Encrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                  "AES-GCM Decrypt wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptUpdate(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                           "AES-GCM Decrypt Update wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptFinal(session, enc, &decSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                            "AES-GCM Decrypt Final wrong init");
    }
    if (ret == CKR_OK) {
       ret = funcList->C_DecryptInit(session, &mech, key);
       CHECK_CKR(ret, "AES-GCM Decrypt Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                  "AES-GCM Encrypt wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptUpdate(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                           "AES-GCM Encrypt Update wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                            "AES-GCM Encrypt Final wrong init");
    }

    return ret;
}

static CK_RV test_aes_gcm_gen_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = gen_aes_key(session, 16, NULL, 0, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_gcm_encdec(session, NULL, 0, 128, NULL, NULL, key);
    if (ret == CKR_OK)
        ret = test_aes_gcm_update(session, NULL, 0, 128, NULL, NULL, key);

    return ret;
}

static CK_RV test_aes_gcm_gen_key_id(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    unsigned char* id = (unsigned char*)"123aes128";
    int idSz = 9;

    ret = gen_aes_key(session, 32, id, idSz, 0, NULL);
    if (ret == CKR_OK)
        ret = find_aes_key(session, id, idSz, &key);
    if (ret == CKR_OK)
        ret = test_aes_gcm_encdec(session, NULL, 0, 128, NULL, NULL, key);
    if (ret == CKR_OK)
        ret = test_aes_gcm_update(session, NULL, 0, 128, NULL, NULL, key);

    return ret;
}
#endif

#ifdef HAVE_AESCCM
static CK_RV test_aes_ccm_encdec(CK_SESSION_HANDLE session,
                                 int macLen, unsigned char* exp,
                                 unsigned char* expMac, CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    byte plain[32];
    byte enc[48]; /* 32 bytes of plaintext + 16 bytes of mac */
    byte dec[32];
    byte aad[10];
    byte iv[13];
    CK_ULONG plainSz, encSz, decSz;
    CK_MECHANISM mech;
    CK_CCM_PARAMS ccmParams;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    memset(aad, 9, sizeof(aad));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);

    ccmParams.pIv    = iv;
    ccmParams.ulIvLen = sizeof(iv);
    ccmParams.pAAD      = aad;
    ccmParams.ulAADLen  = sizeof(aad);
    ccmParams.ulMacLen  = macLen;

    mech.mechanism      = CKM_AES_CCM;
    mech.ulParameterLen = sizeof(ccmParams);
    mech.pParameter     = &ccmParams;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CCM Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &encSz);
        CHECK_CKR(ret, "AES-CCM Encrypt");
    }
    if (ret == CKR_OK && encSz != plainSz + macLen) {
        ret = -1;
        CHECK_CKR(ret, "AES-CCM Encrypt encrypted length");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "AES-CCM Encrypt");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR(ret, "AES-CCM Encrypt");
    }
    if (ret == CKR_OK && encSz != plainSz + macLen) {
        ret = -1;
        CHECK_CKR(ret, "AES-CCM Encrypt Result not correct length");
    }
    if (ret == CKR_OK && exp != NULL && XMEMCMP(enc, exp, plainSz) != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CCM Encrypt Result not matching expected");
    }
    if (ret == CKR_OK && expMac != NULL &&
                             XMEMCMP(enc + plainSz, expMac, macLen) != 0) {
        ret = -1;
        CHECK_CKR(ret, "AES-CCM Encrypt Result not matching expected tag");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CCM Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, NULL, &decSz);
        CHECK_CKR(ret, "AES-CCM Decrypt");
    }
    if (ret == CKR_OK && decSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-CCM Decrypt decrypted length");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "AES-CCM Decrypt");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-CCM Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CCM Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV test_aes_ccm_gen_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = gen_aes_key(session, 16, NULL, 0, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_ccm_encdec(session, 16, NULL, NULL, key);

    return ret;
}

#endif /* HAVE_AESCCM */

#ifdef HAVE_AESCTS
static CK_RV test_aes_cts_encdec(CK_SESSION_HANDLE session, unsigned char* exp,
                                 CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    byte plain[32], enc[32], dec[32], iv[16];
    CK_ULONG plainSz, encSz, decSz, ivSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);

    mech.mechanism      = CKM_AES_CTS;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CTS Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &encSz);
        CHECK_CKR(ret, "AES-CTS Encrypt no enc");
    }
    if (ret == CKR_OK && encSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTS Encrypt encrypted length");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                               "AES-CTS Encrypt zero enc size");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR(ret, "AES-CTS Encrypt");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (encSz != plainSz || XMEMCMP(enc, exp, encSz) != 0)
            ret = -1;
        CHECK_CKR(ret, "AES-CTS Encrypt Result not matching expected");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTS Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, NULL, &decSz);
        CHECK_CKR(ret, "AES-CTS Decrypt");
    }
    if (ret == CKR_OK && decSz != encSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTS Decrypt decrypted length");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                               "AES-CTS Decrypt zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-CTS Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CTS Decrypted data match plain text");
        }
    }


    return ret;
}

static CK_RV test_aes_cts_update(CK_SESSION_HANDLE session, unsigned char* exp,
                                 CK_OBJECT_HANDLE key, CK_ULONG inc)
{
    CK_RV ret;
    byte plain[32], enc[32], dec[32], iv[16];
    byte* pIn;
    byte* pOut = NULL;
    CK_ULONG plainSz, encSz, decSz, ivSz, remSz, cumSz, partSz, inRemSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    memset(iv, 9, sizeof(iv));
    memset(enc, 0, sizeof(enc));
    memset(dec, 0, sizeof(dec));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);
    ivSz = sizeof(iv);
    remSz = encSz;
    cumSz = 0;

    mech.mechanism      = CKM_AES_CTS;
    mech.ulParameterLen = ivSz;
    mech.pParameter     = iv;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CTS Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 1;
        ret = funcList->C_EncryptUpdate(session, plain, 1, NULL, &encSz);
        CHECK_CKR(ret, "AES-CTS Encrypt Update");
    }
    if (ret == CKR_OK && encSz != 33) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTS Encrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 16, NULL, &encSz);
        CHECK_CKR(ret, "AES-CTS Encrypt Update");
    }
    if (ret == CKR_OK && encSz != 48) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTS Encrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_EncryptUpdate(session, plain, 16, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                        "AES-CTS Encrypt Update zero enc size");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        pIn = plain;
        pOut = enc;
        inRemSz = plainSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_EncryptUpdate(session, pIn, partSz, pOut, &encSz);
            CHECK_CKR(ret, "AES-CTS Encrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += encSz;
            cumSz += encSz;
            encSz = (remSz -= encSz);
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_EncryptFinal(session, pOut, &encSz);
        CHECK_CKR(ret, "AES-CTS Encrypt Final");
    }
    if (ret == CKR_OK && encSz != 32) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTS Encrypt Final encrypted size");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (encSz != plainSz || XMEMCMP(enc, exp, encSz) != 0)
            ret = -1;
        CHECK_CKR(ret, "AES-CTS Encrypt Update Result not matching expected");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTS Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 1;
        ret = funcList->C_DecryptUpdate(session, enc, 1, NULL, &decSz);
        CHECK_CKR(ret, "AES-CTS Decrypt Update");
    }
    if (ret == CKR_OK && decSz != 33) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTS Decrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_DecryptUpdate(session, enc, 16, NULL, &decSz);
        CHECK_CKR(ret, "AES-CTS Decrypt Update");
    }
    if (ret == CKR_OK && decSz != 48) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTS Decrypt Update encrypted size");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_DecryptUpdate(session, enc, 16, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                        "AES-CTS Encrypt Update zero dec size");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        pIn = enc;
        pOut = dec;
        cumSz = 0;
        remSz = decSz;
        inRemSz = encSz;
        partSz = inc;
        while (ret == CKR_OK && inRemSz > 0) {
            if (inc > inRemSz)
                partSz = inRemSz;
            ret = funcList->C_DecryptUpdate(session, pIn, partSz, pOut, &decSz);
            CHECK_CKR(ret, "AES-CTS Decrypt Update");
            pIn += partSz;
            inRemSz -= partSz;
            pOut += decSz;
            cumSz += decSz;
            decSz = (remSz -= decSz);
        }
    }
    if (ret == CKR_OK) {
        decSz = 1;
        ret = funcList->C_DecryptFinal(session, NULL, &decSz);
        CHECK_CKR(ret, "AES-CTS Decrypt Final");
    }
    if (ret == CKR_OK && decSz != 32) {
        ret = -1;
        CHECK_CKR(ret, "AES-CTS Decrypt Final decrypted size");
    }
    if (ret == CKR_OK) {
        decSz = remSz;
        ret = funcList->C_DecryptFinal(session, pOut, &decSz);
        CHECK_CKR(ret, "AES-CTS Decrypt Final");
        decSz += cumSz;
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz) {
            ret = -1;
            CHECK_CKR(ret, "AES-CTS Decrypted data length match");
        }
        else if (XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CTS Decrypted data match plain text");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_EncryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTS Encrypt Init");
    }
    if (ret == CKR_OK) {
        encSz = sizeof(enc);
        ret = funcList->C_EncryptUpdate(session, plain, 1, enc, &encSz);
        CHECK_CKR(ret, "AES-CTS Encrypt Update");
    }
    if (ret == CKR_OK) {
        CHECK_COND(encSz == 0, ret,
                             "AES-CTS Encrypt Update less than block out size");
    }
    if (ret == CKR_OK) {
        encSz = sizeof(enc);
        ret = funcList->C_EncryptFinal(session, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                                  "AES-CTS Encrypt Final less than two blocks");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CTS Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        ret = funcList->C_DecryptUpdate(session, enc, 1, dec, &decSz);
        CHECK_CKR(ret, "AES-CTS Decrypt Update");
    }
    if (ret == CKR_OK) {
        CHECK_COND(decSz == 0, ret,
                             "AES-CTS Decrypt Update less than block out size");
    }
    if (ret == CKR_OK) {
        decSz = sizeof(dec);
        ret = funcList->C_DecryptFinal(session, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                                  "AES-CTS Decrypt Final less than two blocks");
    }

    return ret;
}

static CK_RV test_aes_cts_fixed_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_cts_encdec(session, aes_128_cts_exp, key);
    if (ret == CKR_OK)
        ret = test_aes_cts_update(session, aes_128_cts_exp, key, 16);
    if (ret == CKR_OK)
        ret = test_aes_cts_update(session, aes_128_cts_exp, key, 1);
    if (ret == CKR_OK)
        ret = test_aes_cts_update(session, aes_128_cts_exp, key, 5);
    if (ret == CKR_OK)
        ret = test_aes_cts_update(session, aes_128_cts_exp, key, 18);

    return ret;
}

#endif /* HAVE_AESCTS */

#ifdef HAVE_AESECB
static CK_RV test_aes_ecb_encdec(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE key)
{
    CK_RV ret;
    byte plain[32];
    byte enc[32];
    byte dec[32];
    CK_ULONG plainSz, encSz, decSz;
    CK_MECHANISM mech;

    memset(plain, 9, sizeof(plain));
    plainSz = sizeof(plain);
    encSz = sizeof(enc);
    decSz = sizeof(dec);

    mech.mechanism      = CKM_AES_ECB;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_EncryptInit(session, &mech, key);
    CHECK_CKR(ret, "AES-ECB Encrypt Init");
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, NULL, &encSz);
        CHECK_CKR(ret, "AES-ECB Encrypt");
    }
    if (ret == CKR_OK && encSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-ECB Encrypt encrypted length");
    }
    if (ret == CKR_OK) {
        encSz = 0;
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "AES-ECB Encrypt");
        encSz = sizeof(enc);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Encrypt(session, plain, plainSz, enc, &encSz);
        CHECK_CKR(ret, "AES-ECB Encrypt");
    }
    if (ret == CKR_OK && encSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-ECB Encrypt Result not correct length");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DecryptInit(session, &mech, key);
        CHECK_CKR(ret, "AES-ECB Decrypt Init");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, NULL, &decSz);
        CHECK_CKR(ret, "AES-ECB Decrypt");
    }
    if (ret == CKR_OK && decSz != plainSz) {
        ret = -1;
        CHECK_CKR(ret, "AES-ECB Decrypt decrypted length");
    }
    if (ret == CKR_OK) {
        decSz = 0;
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "AES-ECB Decrypt");
        decSz = sizeof(dec);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Decrypt(session, enc, encSz, dec, &decSz);
        CHECK_CKR(ret, "AES-ECB Decrypt");
    }
    if (ret == CKR_OK) {
        if (decSz != plainSz || XMEMCMP(plain, dec, decSz) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-ECB Decrypted data match plain text");
        }
    }

    return ret;
}

static CK_RV test_aes_ecb_gen_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;

    ret = gen_aes_key(session, 16, NULL, 0, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_ecb_encdec(session, key);

    return ret;
}

#endif /* HAVE_AESECB */


#ifdef HAVE_AESCMAC

static CK_RV test_aes_cmac_one_shot(CK_SESSION_HANDLE session,
        unsigned char* exp, int expLen, CK_OBJECT_HANDLE key)
{
    CK_RV  ret = CKR_OK;
    byte   data[72], out[8];
    CK_ULONG dataSz, outSz;
    CK_MECHANISM mech;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    outSz = sizeof(out);

    mech.mechanism      = CKM_AES_CMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_SignInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CMAC Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, NULL, &outSz);
        CHECK_CKR(ret, "AES-CMAC Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == 8, ret, "AES-CMAC Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                                "AES-CMAC Sign out size too small");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR(ret, "AES-CMAC Sign");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (expLen != (int)outSz) {
            ret = -1;
            CHECK_CKR(ret, "AES-CMAC Sign Result expected length");
        }
        if (ret == CKR_OK && XMEMCMP(out, exp, expLen) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CMAC Sign Result not matching expected");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, out, outSz);
        CHECK_CKR(ret, "AES-CMAC Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz - 1, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "AES-CMAC Verify bad hash");
    }

    return ret;
}


static CK_RV test_aes_cmac_update(CK_SESSION_HANDLE session, unsigned char* exp,
        int expLen, CK_OBJECT_HANDLE key)
{
    CK_RV  ret = CKR_OK;
    byte   data[72], out[8];
    CK_ULONG dataSz, outSz;
    CK_MECHANISM mech;
    int i;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    outSz = sizeof(out);

    mech.mechanism      = CKM_AES_CMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_SignInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CMAC Sign Init");
    if (ret == CKR_OK) {
        for (i = 0; ret == CKR_OK && i < (int)dataSz; i++) {
            ret = funcList->C_SignUpdate(session, data + i, 1);
            CHECK_CKR(ret, "AES-CMAC Sign Update");
        }
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_SignFinal(session, NULL, &outSz);
        CHECK_CKR(ret, "AES-CMAC Sign Final no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == 8, ret, "AES-CMAC Sign Final out size");
    }
    if (ret == CKR_OK) {
        outSz = sizeof(out);
        ret = funcList->C_SignFinal(session, out, &outSz);
        CHECK_CKR(ret, "AES-CMAC Sign Final");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (expLen != (int)outSz) {
            ret = -1;
            CHECK_CKR(ret, "AES-CMAC Sign Result expected length");
        }
        if (ret == CKR_OK && XMEMCMP(out, exp, expLen) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CMAC Sign Result not matching expected");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Verify Init");
    }
    if (ret == CKR_OK) {
        for (i = 0; ret == CKR_OK && i < (int)dataSz; i++) {
            ret = funcList->C_VerifyUpdate(session, data + i, 1);
            CHECK_CKR(ret, "AES-CMAC Verify Update");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, out, outSz);
        CHECK_CKR(ret, "AES-CMAC Verify Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "AES-CMAC Verify bad data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Sign Init");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_SignFinal(session, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                          "AES-CMAC Sign Final out size too small");
        outSz = sizeof(out);
    }

    return ret;
}

static CK_RV test_aes_cmac(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char exp[] = {
        0x81, 0x4f, 0x6c, 0xe5, 0x04, 0x97, 0xf9, 0x26
    };

    ret = get_aes_128_key(session, NULL, 0, &key);
    if (ret == CKR_OK)
        ret = test_aes_cmac_one_shot(session, exp, sizeof(exp), key);
    if (ret == CKR_OK)
        ret = test_aes_cmac_update(session, exp, sizeof(exp), key);

    return ret;
}
static CK_RV test_aes_cmac_general_one_shot(CK_SESSION_HANDLE session,
        unsigned char* exp, int expLen, CK_OBJECT_HANDLE key)
{
    CK_RV  ret = CKR_OK;
    byte   data[72], out[16];
    CK_ULONG dataSz, outSz;
    CK_MECHANISM mech;
    CK_MAC_GENERAL_PARAMS macParams = (CK_MAC_GENERAL_PARAMS)expLen;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    outSz = sizeof(out);

    mech.mechanism      = CKM_AES_CMAC_GENERAL;
    mech.ulParameterLen = sizeof(macParams);
    mech.pParameter     = &macParams;

    ret = funcList->C_SignInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CMAC Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, NULL, &outSz);
        CHECK_CKR(ret, "AES-CMAC Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND((int)outSz == expLen, ret, "AES-CMAC Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                                "AES-CMAC Sign out size too small");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR(ret, "AES-CMAC Sign");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (expLen != (int)outSz) {
            ret = -1;
            CHECK_CKR(ret, "AES-CMAC Sign Result expected length");
        }
        if (ret == CKR_OK && XMEMCMP(out, exp, expLen) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CMAC Sign Result not matching expected");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, out, outSz);
        CHECK_CKR(ret, "AES-CMAC Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz - 1, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "AES-CMAC Verify bad hash");
    }

    return ret;
}


static CK_RV test_aes_cmac_general_update(CK_SESSION_HANDLE session,
        unsigned char* exp, int expLen, CK_OBJECT_HANDLE key)
{
    CK_RV  ret = CKR_OK;
    byte   data[72], out[16];
    CK_ULONG dataSz, outSz;
    CK_MECHANISM mech;
    int i;
    CK_MAC_GENERAL_PARAMS macParams = (CK_MAC_GENERAL_PARAMS)expLen;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    outSz = sizeof(out);

    mech.mechanism      = CKM_AES_CMAC_GENERAL;
    mech.ulParameterLen = sizeof(macParams);
    mech.pParameter     = &macParams;

    ret = funcList->C_SignInit(session, &mech, key);
    CHECK_CKR(ret, "AES-CMAC Sign Init");
    if (ret == CKR_OK) {
        for (i = 0; ret == CKR_OK && i < (int)dataSz; i++) {
            ret = funcList->C_SignUpdate(session, data + i, 1);
            CHECK_CKR(ret, "AES-CMAC Sign Update");
        }
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_SignFinal(session, NULL, &outSz);
        CHECK_CKR(ret, "AES-CMAC Sign Final no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND((int)outSz == expLen, ret, "AES-CMAC Sign Final out size");
    }
    if (ret == CKR_OK) {
        outSz = sizeof(out);
        ret = funcList->C_SignFinal(session, out, &outSz);
        CHECK_CKR(ret, "AES-CMAC Sign Final");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (expLen != (int)outSz) {
            ret = -1;
            CHECK_CKR(ret, "AES-CMAC Sign Result expected length");
        }
        if (ret == CKR_OK && XMEMCMP(out, exp, expLen) != 0) {
            ret = -1;
            CHECK_CKR(ret, "AES-CMAC Sign Result not matching expected");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Verify Init");
    }
    if (ret == CKR_OK) {
        for (i = 0; ret == CKR_OK && i < (int)dataSz; i++) {
            ret = funcList->C_VerifyUpdate(session, data + i, 1);
            CHECK_CKR(ret, "AES-CMAC Verify Update");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, out, outSz);
        CHECK_CKR(ret, "AES-CMAC Verify Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "AES-CMAC Verify bad data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, key);
        CHECK_CKR(ret, "AES-CMAC Sign Init");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_SignFinal(session, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                          "AES-CMAC Sign Final out size too small");
        outSz = sizeof(out);
    }

    return ret;
}

static CK_RV test_aes_cmac_general(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char exp[] = {
        0x81, 0x4f, 0x6c, 0xe5, 0x04, 0x97, 0xf9, 0x26,
        0x9b, 0x5b, 0xa0, 0x87, 0xe4, 0x64, 0xf4, 0xf9
    };
    int i;

    ret = get_aes_128_key(session, NULL, 0, &key);

    for (i = 4; i < 16 && ret == CKR_OK; i++)
        ret = test_aes_cmac_general_one_shot(session, exp, i, key);
    for (i = 4; i < 16 && ret == CKR_OK; i++)
        ret = test_aes_cmac_general_update(session, exp, i, key);

    return ret;
}


#endif /* HAVE_AESCMAC */

#endif


static CK_RV test_tls_mac(CK_SESSION_HANDLE session, int hashType,
        unsigned char* exp, int expLen, CK_OBJECT_HANDLE key)
{
    CK_RV  ret = CKR_OK;
    byte   data[32], out[64];
    CK_ULONG dataSz, outSz;
    CK_MECHANISM mech;
    CK_TLS_MAC_PARAMS params;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    outSz = sizeof(out);

    mech.mechanism      = CKM_TLS_MAC;
    mech.pParameter     = &params;
    mech.ulParameterLen = sizeof(params);

    params.prfHashMechanism = hashType;
    params.ulMacLength = expLen;
    params.ulServerOrClient = 1;

    ret = funcList->C_SignInit(session, &mech, key);
    CHECK_CKR(ret, "TLS-MAC Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, NULL, &outSz);
        CHECK_CKR(ret, "TLS-MAC Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == (CK_ULONG)expLen, ret, "TLS-MAC Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                                "TLS-MAC Sign out size too small");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR(ret, "TLS-MAC Sign");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (expLen != (int)outSz) {
            ret = -1;
            CHECK_CKR(ret, "TLS-MAC Sign Result expected length");
        }
        if (ret == CKR_OK && XMEMCMP(out, exp, expLen) != 0) {
            ret = -1;
            CHECK_CKR(ret, "TLS-MAC Sign Result not matching expected");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "TLS-MAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, out, outSz);
        CHECK_CKR(ret, "TLS-MAC Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "TLS-MAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz - 1, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "TLS-MAC Verify bad hash");
    }

    return ret;
}


static CK_RV test_tls_mac_tls_prf(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    };
    static unsigned char exp[] = {
        0x17, 0x74, 0x60, 0x8b, 0x2c, 0x7d, 0x75, 0x60,
        0xe7, 0x2d, 0xef, 0x6c
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_tls_mac(session, CKM_TLS_PRF, exp, sizeof(exp), key);

    return ret;
}

#ifndef NO_SHA256
static CK_RV test_tls_mac_sha256(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    };
    static unsigned char exp[] = {
        0xf8, 0x51, 0xa1, 0xa4, 0x69, 0xbc, 0x26, 0x42,
        0x99, 0xbf, 0xf4, 0x99
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_tls_mac(session, CKM_SHA256, exp, sizeof(exp), key);

    return ret;
}
#endif

#ifdef WOLFSSL_SHA384
static CK_RV test_tls_mac_sha384(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    };
    static unsigned char exp[] = {
        0x45, 0x42, 0x8e, 0x1d, 0xf7, 0x96, 0x62, 0x37,
        0x16, 0xb3, 0xb2, 0x52
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_tls_mac(session, CKM_SHA384, exp, sizeof(exp), key);

    return ret;
}
#endif

#ifdef WOLFSSL_SHA512
static CK_RV test_tls_mac_sha512(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    };
    static unsigned char exp[] = {
        0xab, 0x3f, 0xeb, 0xe5, 0x01, 0xad, 0xf1, 0x25,
        0xce, 0x41, 0x95, 0x83
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_tls_mac(session, CKM_SHA512, exp, sizeof(exp), key);

    return ret;
}
#endif

#ifndef NO_HMAC
static CK_RV test_hmac(CK_SESSION_HANDLE session, int mechanism,
                       unsigned char* exp, int expLen, CK_OBJECT_HANDLE key)
{
    CK_RV  ret = CKR_OK;
    byte   data[32], out[64];
    CK_ULONG dataSz, outSz;
    CK_MECHANISM mech;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    outSz = sizeof(out);

    mech.mechanism      = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_SignInit(session, &mech, key);
    CHECK_CKR(ret, "HMAC Sign Init");
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, NULL, &outSz);
        CHECK_CKR(ret, "HMAC Sign no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == (CK_ULONG)expLen, ret, "HMAC Sign out size");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                                "HMAC Sign out size too small");
        outSz = sizeof(out);
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR(ret, "HMAC Sign");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (expLen != (int)outSz) {
            ret = -1;
            CHECK_CKR(ret, "HMAC Sign Result expected length");
        }
        if (ret == CKR_OK && XMEMCMP(out, exp, expLen) != 0) {
            ret = -1;
            CHECK_CKR(ret, "HMAC Sign Result not matching expected");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "HMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, out, outSz);
        CHECK_CKR(ret, "HMAC Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "HMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz - 1, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "HMAC Verify bad hash");
    }

    return ret;
}

static CK_RV test_hmac_update(CK_SESSION_HANDLE session, int mechanism,
                              unsigned char* exp, int expLen,
                              CK_OBJECT_HANDLE key)
{
    CK_RV  ret = CKR_OK;
    byte   data[32], out[64];
    CK_ULONG dataSz, outSz;
    CK_MECHANISM mech;
    int i;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    outSz = sizeof(out);

    mech.mechanism      = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_SignInit(session, &mech, key);
    CHECK_CKR(ret, "HMAC Sign Init");
    if (ret == CKR_OK) {
        for (i = 0; ret == CKR_OK && i < (int)dataSz; i++) {
            ret = funcList->C_SignUpdate(session, data + i, 1);
            CHECK_CKR(ret, "HMAC Sign Update");
        }
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_SignFinal(session, NULL, &outSz);
        CHECK_CKR(ret, "HMAC Sign Final no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(outSz == (CK_ULONG)expLen, ret, "HMAC Sign Final out size");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignFinal(session, out, &outSz);
        CHECK_CKR(ret, "HMAC Sign Final");
    }
    if (ret == CKR_OK && exp != NULL) {
        if (expLen != (int)outSz) {
            ret = -1;
            CHECK_CKR(ret, "HMAC Sign Result expected length");
        }
        if (ret == CKR_OK && XMEMCMP(out, exp, expLen) != 0) {
            ret = -1;
            CHECK_CKR(ret, "HMAC Sign Result not matching expected");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "HMAC Verify Init");
    }
    if (ret == CKR_OK) {
        for (i = 0; ret == CKR_OK && i < (int)dataSz; i++) {
            ret = funcList->C_VerifyUpdate(session, data + i, 1);
            CHECK_CKR(ret, "HMAC Verify Update");
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, out, outSz);
        CHECK_CKR(ret, "HMAC Verify Final");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, &mech, key);
        CHECK_CKR(ret, "HMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "HMAC Verify bad data");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, key);
        CHECK_CKR(ret, "HMAC Sign Init");
    }
    if (ret == CKR_OK) {
        outSz = 0;
        ret = funcList->C_SignFinal(session, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                                          "HMAC Sign Final out size too small");
        outSz = sizeof(out);
    }

    return ret;
}

static CK_RV test_hmac_fail(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                            unsigned char* keyData, int keySz)
{
    CK_RV  ret = CKR_OK;
    byte   data[32], out[64];
    CK_ULONG dataSz, outSz;
    CK_OBJECT_HANDLE key, aesKey;

    memset(data, 9, sizeof(data));
    dataSz = sizeof(data);
    outSz = sizeof(out);

    ret = get_generic_key(session, keyData, keySz, CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = get_aes_128_key(session, NULL, 0, &aesKey);

#ifndef NO_AES
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, mech, aesKey);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                               "HMAC Sign Init wrong key type");
    }
#endif
    if (ret == CKR_OK) {
        mech->pParameter = data;
        ret = funcList->C_SignInit(session, mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                               "HMAC Sign Init bad parameter");
        mech->pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech->ulParameterLen = sizeof(data);
        ret = funcList->C_SignInit(session, mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                         "HMAC Sign Init bad parameter length");
        mech->ulParameterLen = 0;
    }
#ifndef NO_AES
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, mech, aesKey);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                                             "HMAC Verify Init wrong key type");
    }
#endif
    if (ret == CKR_OK) {
        mech->pParameter = data;
        ret = funcList->C_VerifyInit(session, mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                             "HMAC Verify Init bad parameter");
        mech->pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech->ulParameterLen = sizeof(data);
        ret = funcList->C_VerifyInit(session, mech, key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                       "HMAC Verify Init bad parameter length");
        mech->ulParameterLen = 0;
    }

    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, mech, key);
        CHECK_CKR(ret, "HMAC Sign Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                      "HMAC Verify wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyUpdate(session, data, dataSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                               "HMAC Verify Update wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyFinal(session, out, outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                "HMAC Verify Final wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, mech, key);
        CHECK_CKR(ret, "HMAC Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, dataSz, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                        "HMAC Sign wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignUpdate(session, data, dataSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                 "HMAC Sign Update wrong init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignFinal(session, out, &outSz);
        CHECK_CKR_FAIL(ret, CKR_OPERATION_NOT_INITIALIZED,
                                                  "HMAC Sign Final wrong init");
    }

    return ret;
}
#ifndef NO_MD5
static CK_RV test_hmac_md5(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    };
    static unsigned char exp[] = {
        0xa5, 0x5d, 0x8e, 0x44, 0x73, 0x95, 0x4a, 0x80,
        0x08, 0xab, 0x2b, 0xe8, 0x8a, 0x05, 0x89, 0x5c
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_MD5_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_md5_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    };

    mech.mechanism      = CKM_MD5_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif

#ifndef NO_SHA
static CK_RV test_hmac_sha1(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6,
    };
    static unsigned char exp[] = {
        0xd3, 0x54, 0x83, 0x93, 0x60, 0x14, 0x6a, 0x0c,
        0x6e, 0x26, 0x1d, 0xae, 0xa3, 0xbb, 0xf0, 0xc4,
        0x9e, 0x8f, 0x89, 0x1f
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA1_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha1_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6,
    };

    mech.mechanism      = CKM_SHA1_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif

#ifdef WOLFSSL_SHA224
static CK_RV test_hmac_sha224(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D
    };
    static unsigned char exp[] = {
        0x41, 0xd1, 0x73, 0xa6, 0x2f, 0xa2, 0x71, 0xf7,
        0x71, 0x15, 0x65, 0x22, 0x9d, 0x57, 0x2f, 0x99,
        0xb1, 0x10, 0x66, 0x23, 0x62, 0x8b, 0x67, 0x09,
        0x45, 0x55, 0x60, 0x99
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA224_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha224_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D
    };

    mech.mechanism      = CKM_SHA224_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif

#ifndef NO_SHA256
static CK_RV test_hmac_sha256(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
    };
    static unsigned char exp[] = {
        0xc3, 0x0a, 0xcb, 0xa9, 0xb0, 0x06, 0x5b, 0xc0,
        0x9e, 0x99, 0x2e, 0x71, 0x12, 0xd8, 0xc6, 0xb2,
        0xbb, 0x4b, 0xd1, 0x45, 0x3e, 0x80, 0x33, 0x4d,
        0xd6, 0xac, 0x35, 0x65, 0x27, 0xf9, 0x54, 0xb4
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA256_HMAC, exp, sizeof(exp), key);
    if (ret == CKR_OK)
        ret = test_hmac_update(session, CKM_SHA256_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha256_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
    };

    mech.mechanism      = CKM_SHA256_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif
#ifdef WOLFSSL_SHA384
static CK_RV test_hmac_sha384(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
        0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
    };
    static unsigned char exp[] = {
        0x34, 0xa7, 0xf2, 0xa4, 0x05, 0x5f, 0x31, 0x9c,
        0xd5, 0x7c, 0x57, 0x96, 0x53, 0x87, 0x45, 0xf0,
        0x81, 0xcf, 0x19, 0xd7, 0xcc, 0xe8, 0x3e, 0x8b,
        0xe5, 0xbe, 0x0f, 0xa3, 0x93, 0x9c, 0x2d, 0x5d,
        0x1e, 0x7e, 0xca, 0x06, 0xdd, 0x75, 0x40, 0xcd,
        0x8f, 0x18, 0x0e, 0x54, 0xe4, 0xc5, 0x83, 0xd5
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA384_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha384_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
        0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
    };

    mech.mechanism      = CKM_SHA384_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif

#ifdef WOLFSSL_SHA512
static CK_RV test_hmac_sha512(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
        0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
        0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47,
        0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24, 0x69,
    };
    static unsigned char exp[] = {
        0xdf, 0x6e, 0x3f, 0x5b, 0x14, 0x81, 0x66, 0x91,
        0x86, 0x82, 0x61, 0x3c, 0x51, 0x61, 0x59, 0xd8,
        0x25, 0xf1, 0x73, 0xc7, 0x74, 0x53, 0x95, 0x59,
        0x18, 0xe0, 0x10, 0xa3, 0xb6, 0xa5, 0xcc, 0x64,
        0xf2, 0xff, 0x3b, 0xf2, 0x73, 0xf2, 0xdc, 0x50,
        0x81, 0x5f, 0xd5, 0x3a, 0x1c, 0x52, 0x3e, 0x3a,
        0x92, 0xdf, 0xe3, 0xd3, 0xd0, 0x15, 0xa5, 0x43,
        0x27, 0xb1, 0x4f, 0xed, 0x18, 0x05, 0xb6, 0x6d
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA512_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha512_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
        0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
        0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47,
        0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24, 0x69,
    };

    mech.mechanism      = CKM_SHA512_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif

#ifndef WOLFSSL_NOSHA3_224
static CK_RV test_hmac_sha3_224(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D
    };
    static unsigned char exp[] = {
        0x90, 0xd9, 0x41, 0xd4, 0x42, 0x95, 0xc9, 0xe5,
        0xdc, 0xa1, 0x58, 0x27, 0x31, 0xe7, 0x20, 0x50,
        0x2b, 0xb6, 0xd6, 0xe9, 0x21, 0xbb, 0x8e, 0x44,
        0x4a, 0x43, 0xb9, 0x30
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA3_224_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha3_224_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D
    };

    mech.mechanism      = CKM_SHA3_224_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif

#ifndef WOLFSSL_NOSHA3_256
static CK_RV test_hmac_sha3_256(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67
    };
    static unsigned char exp[] = {
        0xb7, 0xfb, 0x61, 0x54, 0xd6, 0x2d, 0x34, 0x39,
        0x91, 0xa8, 0x2f, 0xa4, 0x62, 0x3d, 0xc6, 0x9b,
        0x67, 0xda, 0x85, 0x80, 0xcb, 0x40, 0xcb, 0xd0,
        0x58, 0x99, 0x7f, 0x9f, 0xf6, 0x37, 0x34, 0x2e
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA3_256_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha3_256_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67
    };

    mech.mechanism      = CKM_SHA3_256_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}

#endif

#ifndef WOLFSSL_NOSHA3_384
static CK_RV test_hmac_sha3_384(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
        0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
    };
    static unsigned char exp[] = {
        0x33, 0x52, 0xd6, 0xe1, 0x5e, 0x09, 0xc2, 0x68,
        0x53, 0xee, 0xc2, 0xbc, 0xf6, 0x49, 0xa1, 0x6d,
        0x5c, 0xf2, 0x2b, 0xc3, 0x1d, 0xfc, 0x96, 0x4b,
        0xf5, 0x7b, 0x2d, 0xe4, 0xd6, 0x03, 0x43, 0xcd,
        0xda, 0x67, 0xbc, 0xef, 0xe3, 0x95, 0x84, 0x1c,
        0xf7, 0x1b, 0x1e, 0x8d, 0x1e, 0x47, 0x88, 0x28
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA3_384_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha3_384_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
        0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
        0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47,
        0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24, 0x69,
    };

    mech.mechanism      = CKM_SHA3_384_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif

#ifndef WOLFSSL_NOSHA3_512
static CK_RV test_hmac_sha3_512(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE key;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
        0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
        0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47,
        0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24, 0x69,
    };
    static unsigned char exp[] = {
        0xf0, 0xe1, 0x30, 0xfa, 0xc8, 0xa7, 0x82, 0x54,
        0xc2, 0xc8, 0xc8, 0x1f, 0x98, 0xad, 0x81, 0x38,
        0xdd, 0xf8, 0xe4, 0xc9, 0x99, 0x52, 0x83, 0x69,
        0x7c, 0x0d, 0xd1, 0x3b, 0x71, 0xc6, 0x02, 0x39,
        0x5b, 0xe8, 0x9e, 0x8b, 0x37, 0x97, 0x9f, 0x02,
        0x47, 0x5e, 0x39, 0x8b, 0x50, 0xa8, 0x80, 0xd4,
        0xe3, 0x48, 0x39, 0x8a, 0x9c, 0x11, 0xc8, 0x31,
        0x29, 0x03, 0x85, 0xdf, 0x14, 0x68, 0x90, 0x14
    };

    ret = get_generic_key(session, keyData, sizeof(keyData), CK_FALSE, &key);
    if (ret == CKR_OK)
        ret = test_hmac(session, CKM_SHA3_512_HMAC, exp, sizeof(exp), key);

    return ret;
}

static CK_RV test_hmac_sha3_512_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV  ret = CKR_OK;
    CK_MECHANISM mech;
    static unsigned char keyData[] = {
        0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
        0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
        0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
        0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2,
        0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF,
        0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47,
        0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24, 0x69,
    };

    mech.mechanism      = CKM_SHA3_512_HMAC;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = test_hmac_fail(session, &mech, keyData, sizeof(keyData));

    return ret;
}
#endif
#endif

static CK_RV test_x509(void* args)
{
    CK_RV ret = CKR_OK;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_UTF8CHAR label[] = "A certificate object";
    CK_BYTE subject[] = "C = US, ST = Montana, L = Bozeman, O = wolfSSL, "
        "OU = Support, CN = www.wolfssl.com, emailAddress = info@wolfssl.com";
    CK_BYTE id[] = {0x27, 0x8E, 0x67, 0x11, 0x74, 0xC3, 0x26, 0x1D, 0x3F, 0xED,
                    0x33, 0x63, 0xB3, 0xA4, 0xD8, 0x1D, 0x30, 0xE5, 0xE8, 0xD5
    };
    CK_BYTE certificate[] = { /* ./certs/server-cert.der, 2048-bit */
        0x30, 0x82, 0x04, 0xE8, 0x30, 0x82, 0x03, 0xD0, 0xA0, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
        0x00, 0x30, 0x81, 0x94, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30,
        0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F,
        0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E, 0x06,
        0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42, 0x6F, 0x7A, 0x65,
        0x6D, 0x61, 0x6E, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55,
        0x04, 0x0A, 0x0C, 0x08, 0x53, 0x61, 0x77, 0x74, 0x6F, 0x6F,
        0x74, 0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
        0x0B, 0x0C, 0x0A, 0x43, 0x6F, 0x6E, 0x73, 0x75, 0x6C, 0x74,
        0x69, 0x6E, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F,
        0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31,
        0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F,
        0x40, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63,
        0x6F, 0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x33, 0x31, 0x32,
        0x31, 0x33, 0x32, 0x32, 0x31, 0x39, 0x32, 0x38, 0x5A, 0x17,
        0x0D, 0x32, 0x36, 0x30, 0x39, 0x30, 0x38, 0x32, 0x32, 0x31,
        0x39, 0x32, 0x38, 0x5A, 0x30, 0x81, 0x90, 0x31, 0x0B, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
        0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10,
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42,
        0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x10, 0x30, 0x0E,
        0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x77, 0x6F, 0x6C,
        0x66, 0x53, 0x53, 0x4C, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
        0x55, 0x04, 0x0B, 0x0C, 0x07, 0x53, 0x75, 0x70, 0x70, 0x6F,
        0x72, 0x74, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C,
        0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F,
        0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40,
        0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F,
        0x6D, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02,
        0x82, 0x01, 0x01, 0x00, 0xC0, 0x95, 0x08, 0xE1, 0x57, 0x41,
        0xF2, 0x71, 0x6D, 0xB7, 0xD2, 0x45, 0x41, 0x27, 0x01, 0x65,
        0xC6, 0x45, 0xAE, 0xF2, 0xBC, 0x24, 0x30, 0xB8, 0x95, 0xCE,
        0x2F, 0x4E, 0xD6, 0xF6, 0x1C, 0x88, 0xBC, 0x7C, 0x9F, 0xFB,
        0xA8, 0x67, 0x7F, 0xFE, 0x5C, 0x9C, 0x51, 0x75, 0xF7, 0x8A,
        0xCA, 0x07, 0xE7, 0x35, 0x2F, 0x8F, 0xE1, 0xBD, 0x7B, 0xC0,
        0x2F, 0x7C, 0xAB, 0x64, 0xA8, 0x17, 0xFC, 0xCA, 0x5D, 0x7B,
        0xBA, 0xE0, 0x21, 0xE5, 0x72, 0x2E, 0x6F, 0x2E, 0x86, 0xD8,
        0x95, 0x73, 0xDA, 0xAC, 0x1B, 0x53, 0xB9, 0x5F, 0x3F, 0xD7,
        0x19, 0x0D, 0x25, 0x4F, 0xE1, 0x63, 0x63, 0x51, 0x8B, 0x0B,
        0x64, 0x3F, 0xAD, 0x43, 0xB8, 0xA5, 0x1C, 0x5C, 0x34, 0xB3,
        0xAE, 0x00, 0xA0, 0x63, 0xC5, 0xF6, 0x7F, 0x0B, 0x59, 0x68,
        0x78, 0x73, 0xA6, 0x8C, 0x18, 0xA9, 0x02, 0x6D, 0xAF, 0xC3,
        0x19, 0x01, 0x2E, 0xB8, 0x10, 0xE3, 0xC6, 0xCC, 0x40, 0xB4,
        0x69, 0xA3, 0x46, 0x33, 0x69, 0x87, 0x6E, 0xC4, 0xBB, 0x17,
        0xA6, 0xF3, 0xE8, 0xDD, 0xAD, 0x73, 0xBC, 0x7B, 0x2F, 0x21,
        0xB5, 0xFD, 0x66, 0x51, 0x0C, 0xBD, 0x54, 0xB3, 0xE1, 0x6D,
        0x5F, 0x1C, 0xBC, 0x23, 0x73, 0xD1, 0x09, 0x03, 0x89, 0x14,
        0xD2, 0x10, 0xB9, 0x64, 0xC3, 0x2A, 0xD0, 0xA1, 0x96, 0x4A,
        0xBC, 0xE1, 0xD4, 0x1A, 0x5B, 0xC7, 0xA0, 0xC0, 0xC1, 0x63,
        0x78, 0x0F, 0x44, 0x37, 0x30, 0x32, 0x96, 0x80, 0x32, 0x23,
        0x95, 0xA1, 0x77, 0xBA, 0x13, 0xD2, 0x97, 0x73, 0xE2, 0x5D,
        0x25, 0xC9, 0x6A, 0x0D, 0xC3, 0x39, 0x60, 0xA4, 0xB4, 0xB0,
        0x69, 0x42, 0x42, 0x09, 0xE9, 0xD8, 0x08, 0xBC, 0x33, 0x20,
        0xB3, 0x58, 0x22, 0xA7, 0xAA, 0xEB, 0xC4, 0xE1, 0xE6, 0x61,
        0x83, 0xC5, 0xD2, 0x96, 0xDF, 0xD9, 0xD0, 0x4F, 0xAD, 0xD7,
        0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x45, 0x30,
        0x82, 0x01, 0x41, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E,
        0x04, 0x16, 0x04, 0x14, 0xB3, 0x11, 0x32, 0xC9, 0x92, 0x98,
        0x84, 0xE2, 0xC9, 0xF8, 0xD0, 0x3B, 0x6E, 0x03, 0x42, 0xCA,
        0x1F, 0x0E, 0x8E, 0x3C, 0x30, 0x81, 0xD4, 0x06, 0x03, 0x55,
        0x1D, 0x23, 0x04, 0x81, 0xCC, 0x30, 0x81, 0xC9, 0x80, 0x14,
        0x27, 0x8E, 0x67, 0x11, 0x74, 0xC3, 0x26, 0x1D, 0x3F, 0xED,
        0x33, 0x63, 0xB3, 0xA4, 0xD8, 0x1D, 0x30, 0xE5, 0xE8, 0xD5,
        0xA1, 0x81, 0x9A, 0xA4, 0x81, 0x97, 0x30, 0x81, 0x94, 0x31,
        0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04,
        0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C,
        0x07, 0x42, 0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x11,
        0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x53,
        0x61, 0x77, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x31, 0x13, 0x30,
        0x11, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x43, 0x6F,
        0x6E, 0x73, 0x75, 0x6C, 0x74, 0x69, 0x6E, 0x67, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77,
        0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C,
        0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16,
        0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77, 0x6F, 0x6C, 0x66,
        0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x14, 0x33,
        0x44, 0x1A, 0xA8, 0x6C, 0x01, 0xEC, 0xF6, 0x60, 0xF2, 0x70,
        0x51, 0x0A, 0x4C, 0xD1, 0x14, 0xFA, 0xBC, 0xE9, 0x44, 0x30,
        0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03,
        0x01, 0x01, 0xFF, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x1D, 0x11,
        0x04, 0x15, 0x30, 0x13, 0x82, 0x0B, 0x65, 0x78, 0x61, 0x6D,
        0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x87, 0x04, 0x7F,
        0x00, 0x00, 0x01, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25,
        0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
        0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03,
        0x82, 0x01, 0x01, 0x00, 0x4A, 0xFF, 0xB9, 0xE5, 0x85, 0x9B,
        0xDA, 0x53, 0x66, 0x7F, 0x07, 0x22, 0xBF, 0xB6, 0x19, 0xEA,
        0x42, 0xEB, 0xA4, 0x11, 0x07, 0x62, 0xFF, 0x39, 0x5F, 0x33,
        0x37, 0x3A, 0x87, 0x26, 0x71, 0x3D, 0x13, 0xB2, 0xCA, 0xB8,
        0x64, 0x38, 0x7B, 0x8A, 0x99, 0x48, 0x0E, 0xA5, 0xA4, 0x6B,
        0xB1, 0x99, 0x6E, 0xE0, 0x46, 0x51, 0xBD, 0x19, 0x52, 0xAD,
        0xBC, 0xA6, 0x7E, 0x2A, 0x7A, 0x7C, 0x23, 0xA7, 0xCC, 0xDB,
        0x5E, 0x43, 0x7D, 0x6B, 0x04, 0xC8, 0xB7, 0xDD, 0x95, 0xAD,
        0xF0, 0x91, 0x80, 0x59, 0xC5, 0x19, 0x91, 0x26, 0x27, 0x91,
        0xB8, 0x48, 0x1C, 0xEB, 0x55, 0xB6, 0xAA, 0x7D, 0xA4, 0x38,
        0xF1, 0x03, 0xBC, 0x6C, 0x8B, 0xAA, 0x94, 0xD6, 0x3C, 0x05,
        0x7A, 0x96, 0xC5, 0x06, 0xF1, 0x26, 0x14, 0x2E, 0x75, 0xFB,
        0xDD, 0xE5, 0x35, 0xB3, 0x01, 0x2C, 0xB3, 0xAD, 0x62, 0x5A,
        0x21, 0x9A, 0x08, 0xBE, 0x56, 0xFC, 0xF9, 0xA2, 0x42, 0x87,
        0x86, 0xE5, 0xA9, 0xC5, 0x99, 0xCF, 0xAE, 0x14, 0xBE, 0xE0,
        0xB9, 0x08, 0x24, 0x0D, 0x1D, 0x5C, 0xD6, 0x14, 0xE1, 0x4C,
        0x9F, 0x40, 0xB3, 0xA9, 0xE9, 0x2D, 0x52, 0x8B, 0x4C, 0xBF,
        0xAC, 0x44, 0x31, 0x67, 0xC1, 0x8D, 0x06, 0x85, 0xEC, 0x0F,
        0xE4, 0x99, 0xD7, 0x4B, 0x7B, 0x21, 0x06, 0x66, 0xD4, 0xE4,
        0xF5, 0x9D, 0xFF, 0x8E, 0xF0, 0x86, 0x39, 0x58, 0x1D, 0xA4,
        0x5B, 0xE2, 0x63, 0xEF, 0x7C, 0xC9, 0x18, 0x87, 0xA8, 0x02,
        0x25, 0x10, 0x3E, 0x87, 0x28, 0xF9, 0xF5, 0xEF, 0x47, 0x9E,
        0xA5, 0x80, 0x08, 0x11, 0x90, 0x68, 0xFE, 0xD1, 0xA3, 0xA8,
        0x51, 0xB9, 0x37, 0xFF, 0xD5, 0xCA, 0x7C, 0x87, 0x7F, 0x6B,
        0xBC, 0x2C, 0x12, 0xC8, 0xC5, 0x85, 0x8B, 0xFC, 0x0C, 0xC6,
        0xB9, 0x86, 0xB8, 0xC9, 0x04, 0xC3, 0x51, 0x37, 0xD2, 0x4F
    };

    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &certificateClass, sizeof(certificateClass)},
        {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, label, sizeof(label)-1},
        {CKA_SUBJECT, subject, sizeof(subject)-1},
        {CKA_ID, id, sizeof(id)},
        {CKA_VALUE, certificate, sizeof(certificate)}
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_VALUE,          NULL,   0    }
    };
    CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(*getTmpl);
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_ID,          id,   sizeof(id)}
    };
    CK_ULONG findTmplCnt = sizeof(findTmpl) / sizeof(*findTmpl);
    CK_ULONG count = 1;

    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create certificate object");
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "C_GetAttributeValue");

        if (ret == CKR_OK) {
            getTmpl[0].pValue = XMALLOC(getTmpl[0].ulValueLen * sizeof(byte),
                                                    NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (getTmpl[0].pValue == NULL)
                ret = CKR_DEVICE_MEMORY;
            CHECK_CKR(ret, "Allocate get attribute memory");

            if (ret == CKR_OK) {
                ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
                CHECK_CKR(ret, "C_GetAttributeValue");

                if (sizeof(certificate) != getTmpl[0].ulValueLen) {
                    ret = CKR_GENERAL_ERROR;
                }
                if (XMEMCMP(certificate, getTmpl[0].pValue, sizeof(certificate)) != 0) {
                    ret = CKR_GENERAL_ERROR;
                }
                CHECK_CKR(ret, "Verify that stored cert matches original");

                XFREE(getTmpl[0].pValue, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
    }

    /* Do a login/logout cycle and check that the value still matches */
    if (userPinLen != 0)
        funcList->C_Logout(session);
    funcList->C_CloseSession(session);

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session");
    if (ret == CKR_OK && userPinLen != 0) {
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login");
    }

    ret = funcList->C_FindObjectsInit(session, findTmpl, findTmplCnt);
    CHECK_CKR(ret, "C_FindObjectsInit");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, &obj, 1, &count);
        CHECK_CKR(ret, "C_FindObjects");
        if (ret == CKR_OK) {
            ret = funcList->C_FindObjectsFinal(session);
            CHECK_CKR(ret, "C_FindObjectsFinal");
        }
    }

    if (ret == CKR_OK) {
        getTmpl[0].pValue = NULL;
        getTmpl[0].ulValueLen = 0;
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "C_GetAttributeValue");
        if (ret == CKR_OK) {
            getTmpl[0].pValue = XMALLOC(getTmpl[0].ulValueLen * sizeof(byte),
                                                    NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (getTmpl[0].pValue == NULL)
                ret = CKR_DEVICE_MEMORY;
            CHECK_CKR(ret, "Allocate get attribute memory");

            if (ret == CKR_OK) {
                ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
                CHECK_CKR(ret, "C_GetAttributeValue");

                if (sizeof(certificate) != getTmpl[0].ulValueLen) {
                    ret = CKR_GENERAL_ERROR;
                }
                if (XMEMCMP(certificate, getTmpl[0].pValue, sizeof(certificate)) != 0) {
                    ret = CKR_GENERAL_ERROR;
                }
                CHECK_CKR(ret, "Verify that stored cert matches original");

                XFREE(getTmpl[0].pValue, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
        ret = funcList->C_DestroyObject(session, obj);
    }

    return ret;
}

#ifndef NO_RSA
/* Tests finding a CKA_MODULUS in a CKO_CERTIFICATE, which will always fail */
static CK_RV test_x509_cert_find_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE hTest = 0;
    CK_OBJECT_HANDLE hObjectFound = 0;
    CK_ULONG ulObjectCount = 0;

    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_UTF8CHAR label[] = "A certificate object";
    CK_BYTE subject[] = "C = US, ST = Montana, L = Bozeman, O = wolfSSL, "
        "OU = Support, CN = www.wolfssl.com, emailAddress = info@wolfssl.com";
    CK_BYTE id[] = {0x27, 0x8E, 0x67, 0x11, 0x74, 0xC3, 0x26, 0x1D, 0x3F, 0xED,
                    0x33, 0x63, 0xB3, 0xA4, 0xD8, 0x1D, 0x30, 0xE5, 0xE8, 0xD5
    };
    CK_BYTE certificate[] = { /* ./certs/server-cert.der, 2048-bit */
        0x30, 0x82, 0x04, 0xE8, 0x30, 0x82, 0x03, 0xD0, 0xA0, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
        0x00, 0x30, 0x81, 0x94, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30,
        0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F,
        0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E, 0x06,
        0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42, 0x6F, 0x7A, 0x65,
        0x6D, 0x61, 0x6E, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55,
        0x04, 0x0A, 0x0C, 0x08, 0x53, 0x61, 0x77, 0x74, 0x6F, 0x6F,
        0x74, 0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
        0x0B, 0x0C, 0x0A, 0x43, 0x6F, 0x6E, 0x73, 0x75, 0x6C, 0x74,
        0x69, 0x6E, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F,
        0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31,
        0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F,
        0x40, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63,
        0x6F, 0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x33, 0x31, 0x32,
        0x31, 0x33, 0x32, 0x32, 0x31, 0x39, 0x32, 0x38, 0x5A, 0x17,
        0x0D, 0x32, 0x36, 0x30, 0x39, 0x30, 0x38, 0x32, 0x32, 0x31,
        0x39, 0x32, 0x38, 0x5A, 0x30, 0x81, 0x90, 0x31, 0x0B, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
        0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10,
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42,
        0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x10, 0x30, 0x0E,
        0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x77, 0x6F, 0x6C,
        0x66, 0x53, 0x53, 0x4C, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
        0x55, 0x04, 0x0B, 0x0C, 0x07, 0x53, 0x75, 0x70, 0x70, 0x6F,
        0x72, 0x74, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C,
        0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F,
        0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40,
        0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F,
        0x6D, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02,
        0x82, 0x01, 0x01, 0x00, 0xC0, 0x95, 0x08, 0xE1, 0x57, 0x41,
        0xF2, 0x71, 0x6D, 0xB7, 0xD2, 0x45, 0x41, 0x27, 0x01, 0x65,
        0xC6, 0x45, 0xAE, 0xF2, 0xBC, 0x24, 0x30, 0xB8, 0x95, 0xCE,
        0x2F, 0x4E, 0xD6, 0xF6, 0x1C, 0x88, 0xBC, 0x7C, 0x9F, 0xFB,
        0xA8, 0x67, 0x7F, 0xFE, 0x5C, 0x9C, 0x51, 0x75, 0xF7, 0x8A,
        0xCA, 0x07, 0xE7, 0x35, 0x2F, 0x8F, 0xE1, 0xBD, 0x7B, 0xC0,
        0x2F, 0x7C, 0xAB, 0x64, 0xA8, 0x17, 0xFC, 0xCA, 0x5D, 0x7B,
        0xBA, 0xE0, 0x21, 0xE5, 0x72, 0x2E, 0x6F, 0x2E, 0x86, 0xD8,
        0x95, 0x73, 0xDA, 0xAC, 0x1B, 0x53, 0xB9, 0x5F, 0x3F, 0xD7,
        0x19, 0x0D, 0x25, 0x4F, 0xE1, 0x63, 0x63, 0x51, 0x8B, 0x0B,
        0x64, 0x3F, 0xAD, 0x43, 0xB8, 0xA5, 0x1C, 0x5C, 0x34, 0xB3,
        0xAE, 0x00, 0xA0, 0x63, 0xC5, 0xF6, 0x7F, 0x0B, 0x59, 0x68,
        0x78, 0x73, 0xA6, 0x8C, 0x18, 0xA9, 0x02, 0x6D, 0xAF, 0xC3,
        0x19, 0x01, 0x2E, 0xB8, 0x10, 0xE3, 0xC6, 0xCC, 0x40, 0xB4,
        0x69, 0xA3, 0x46, 0x33, 0x69, 0x87, 0x6E, 0xC4, 0xBB, 0x17,
        0xA6, 0xF3, 0xE8, 0xDD, 0xAD, 0x73, 0xBC, 0x7B, 0x2F, 0x21,
        0xB5, 0xFD, 0x66, 0x51, 0x0C, 0xBD, 0x54, 0xB3, 0xE1, 0x6D,
        0x5F, 0x1C, 0xBC, 0x23, 0x73, 0xD1, 0x09, 0x03, 0x89, 0x14,
        0xD2, 0x10, 0xB9, 0x64, 0xC3, 0x2A, 0xD0, 0xA1, 0x96, 0x4A,
        0xBC, 0xE1, 0xD4, 0x1A, 0x5B, 0xC7, 0xA0, 0xC0, 0xC1, 0x63,
        0x78, 0x0F, 0x44, 0x37, 0x30, 0x32, 0x96, 0x80, 0x32, 0x23,
        0x95, 0xA1, 0x77, 0xBA, 0x13, 0xD2, 0x97, 0x73, 0xE2, 0x5D,
        0x25, 0xC9, 0x6A, 0x0D, 0xC3, 0x39, 0x60, 0xA4, 0xB4, 0xB0,
        0x69, 0x42, 0x42, 0x09, 0xE9, 0xD8, 0x08, 0xBC, 0x33, 0x20,
        0xB3, 0x58, 0x22, 0xA7, 0xAA, 0xEB, 0xC4, 0xE1, 0xE6, 0x61,
        0x83, 0xC5, 0xD2, 0x96, 0xDF, 0xD9, 0xD0, 0x4F, 0xAD, 0xD7,
        0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x45, 0x30,
        0x82, 0x01, 0x41, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E,
        0x04, 0x16, 0x04, 0x14, 0xB3, 0x11, 0x32, 0xC9, 0x92, 0x98,
        0x84, 0xE2, 0xC9, 0xF8, 0xD0, 0x3B, 0x6E, 0x03, 0x42, 0xCA,
        0x1F, 0x0E, 0x8E, 0x3C, 0x30, 0x81, 0xD4, 0x06, 0x03, 0x55,
        0x1D, 0x23, 0x04, 0x81, 0xCC, 0x30, 0x81, 0xC9, 0x80, 0x14,
        0x27, 0x8E, 0x67, 0x11, 0x74, 0xC3, 0x26, 0x1D, 0x3F, 0xED,
        0x33, 0x63, 0xB3, 0xA4, 0xD8, 0x1D, 0x30, 0xE5, 0xE8, 0xD5,
        0xA1, 0x81, 0x9A, 0xA4, 0x81, 0x97, 0x30, 0x81, 0x94, 0x31,
        0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04,
        0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C,
        0x07, 0x42, 0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x11,
        0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x53,
        0x61, 0x77, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x31, 0x13, 0x30,
        0x11, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x43, 0x6F,
        0x6E, 0x73, 0x75, 0x6C, 0x74, 0x69, 0x6E, 0x67, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77,
        0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C,
        0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16,
        0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77, 0x6F, 0x6C, 0x66,
        0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x14, 0x33,
        0x44, 0x1A, 0xA8, 0x6C, 0x01, 0xEC, 0xF6, 0x60, 0xF2, 0x70,
        0x51, 0x0A, 0x4C, 0xD1, 0x14, 0xFA, 0xBC, 0xE9, 0x44, 0x30,
        0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03,
        0x01, 0x01, 0xFF, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x1D, 0x11,
        0x04, 0x15, 0x30, 0x13, 0x82, 0x0B, 0x65, 0x78, 0x61, 0x6D,
        0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x87, 0x04, 0x7F,
        0x00, 0x00, 0x01, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25,
        0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
        0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03,
        0x82, 0x01, 0x01, 0x00, 0x4A, 0xFF, 0xB9, 0xE5, 0x85, 0x9B,
        0xDA, 0x53, 0x66, 0x7F, 0x07, 0x22, 0xBF, 0xB6, 0x19, 0xEA,
        0x42, 0xEB, 0xA4, 0x11, 0x07, 0x62, 0xFF, 0x39, 0x5F, 0x33,
        0x37, 0x3A, 0x87, 0x26, 0x71, 0x3D, 0x13, 0xB2, 0xCA, 0xB8,
        0x64, 0x38, 0x7B, 0x8A, 0x99, 0x48, 0x0E, 0xA5, 0xA4, 0x6B,
        0xB1, 0x99, 0x6E, 0xE0, 0x46, 0x51, 0xBD, 0x19, 0x52, 0xAD,
        0xBC, 0xA6, 0x7E, 0x2A, 0x7A, 0x7C, 0x23, 0xA7, 0xCC, 0xDB,
        0x5E, 0x43, 0x7D, 0x6B, 0x04, 0xC8, 0xB7, 0xDD, 0x95, 0xAD,
        0xF0, 0x91, 0x80, 0x59, 0xC5, 0x19, 0x91, 0x26, 0x27, 0x91,
        0xB8, 0x48, 0x1C, 0xEB, 0x55, 0xB6, 0xAA, 0x7D, 0xA4, 0x38,
        0xF1, 0x03, 0xBC, 0x6C, 0x8B, 0xAA, 0x94, 0xD6, 0x3C, 0x05,
        0x7A, 0x96, 0xC5, 0x06, 0xF1, 0x26, 0x14, 0x2E, 0x75, 0xFB,
        0xDD, 0xE5, 0x35, 0xB3, 0x01, 0x2C, 0xB3, 0xAD, 0x62, 0x5A,
        0x21, 0x9A, 0x08, 0xBE, 0x56, 0xFC, 0xF9, 0xA2, 0x42, 0x87,
        0x86, 0xE5, 0xA9, 0xC5, 0x99, 0xCF, 0xAE, 0x14, 0xBE, 0xE0,
        0xB9, 0x08, 0x24, 0x0D, 0x1D, 0x5C, 0xD6, 0x14, 0xE1, 0x4C,
        0x9F, 0x40, 0xB3, 0xA9, 0xE9, 0x2D, 0x52, 0x8B, 0x4C, 0xBF,
        0xAC, 0x44, 0x31, 0x67, 0xC1, 0x8D, 0x06, 0x85, 0xEC, 0x0F,
        0xE4, 0x99, 0xD7, 0x4B, 0x7B, 0x21, 0x06, 0x66, 0xD4, 0xE4,
        0xF5, 0x9D, 0xFF, 0x8E, 0xF0, 0x86, 0x39, 0x58, 0x1D, 0xA4,
        0x5B, 0xE2, 0x63, 0xEF, 0x7C, 0xC9, 0x18, 0x87, 0xA8, 0x02,
        0x25, 0x10, 0x3E, 0x87, 0x28, 0xF9, 0xF5, 0xEF, 0x47, 0x9E,
        0xA5, 0x80, 0x08, 0x11, 0x90, 0x68, 0xFE, 0xD1, 0xA3, 0xA8,
        0x51, 0xB9, 0x37, 0xFF, 0xD5, 0xCA, 0x7C, 0x87, 0x7F, 0x6B,
        0xBC, 0x2C, 0x12, 0xC8, 0xC5, 0x85, 0x8B, 0xFC, 0x0C, 0xC6,
        0xB9, 0x86, 0xB8, 0xC9, 0x04, 0xC3, 0x51, 0x37, 0xD2, 0x4F
    };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,            &certificateClass, sizeof(certificateClass) },
        { CKA_CERTIFICATE_TYPE, &certType,         sizeof(certType)         },
        { CKA_TOKEN,            &ckTrue,           sizeof(ckTrue)           },
        { CKA_LABEL,            label,             sizeof(label)-1          },
        { CKA_SUBJECT,          subject,           sizeof(subject)-1        },
        { CKA_ID,               id,                sizeof(id)               },
        { CKA_VALUE,            certificate,       sizeof(certificate)      },
    };

    ret = funcList->C_CreateObject(session, tmpl,
                                   sizeof(tmpl) / sizeof(CK_ATTRIBUTE), &hTest);
    CHECK_CKR(ret, "Create certificate object");

    if (ret == CKR_OK) {
        CK_BYTE dummyModulus[] = { 0x00, 0x01, 0x02 };

        CK_ATTRIBUTE aSearchAttributes[] = {
            { CKA_KEY_TYPE,         &rsaKeyType,  sizeof(rsaKeyType)   },
            { CKA_MODULUS,          dummyModulus, sizeof(dummyModulus) },
            { CKA_CERTIFICATE_TYPE, &certType,    sizeof(certType)     }
        };

        ret = funcList->C_FindObjectsInit(session, aSearchAttributes,
                                          sizeof(aSearchAttributes) /
                                          sizeof(CK_ATTRIBUTE));
        CHECK_CKR(ret, "C_FindObjectsInit");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, &hObjectFound, 1,
                                      &ulObjectCount);
        CHECK_CKR(ret, "C_FindObjects");
    }

    if (ret == CKR_OK) {
        CHECK_COND(ulObjectCount == 0, ret, "Objects found");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "C_FindObjectsFinal");
    }

    funcList->C_DestroyObject(session, hTest);

    return ret;
}
#endif

static CK_RV test_x509_find_by_type(void* args)
{
    CK_RV ret = CKR_OK;
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_OBJECT_HANDLE hTest = 0;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_UTF8CHAR label[] = "A certificate object";
    CK_BYTE subject[] = "C = US, ST = Montana, L = Bozeman, O = wolfSSL, "
        "OU = Support, CN = www.wolfssl.com, emailAddress = info@wolfssl.com";
    /* Certificate ID */
    CK_BYTE certId[] = {
        0x27, 0x8E, 0x67, 0x11, 0x74, 0xC3, 0x26, 0x1D, 0x3F, 0xED,
        0x33, 0x63, 0xB3, 0xA4, 0xD8, 0x1D, 0x30, 0xE5, 0xE8, 0xD5
    };
    /* Certificate data - this is the actual X.509 certificate in DER format */
    CK_BYTE certData[] = {
        0x30, 0x82, 0x04, 0xE8, 0x30, 0x82, 0x03, 0xD0, 0xA0, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
        0x00, 0x30, 0x81, 0x94, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30,
        0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F,
        0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E, 0x06,
        0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42, 0x6F, 0x7A, 0x65,
        0x6D, 0x61, 0x6E, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55,
        0x04, 0x0A, 0x0C, 0x08, 0x53, 0x61, 0x77, 0x74, 0x6F, 0x6F,
        0x74, 0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
        0x0B, 0x0C, 0x0A, 0x43, 0x6F, 0x6E, 0x73, 0x75, 0x6C, 0x74,
        0x69, 0x6E, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F,
        0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31,
        0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F,
        0x40, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63,
        0x6F, 0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x33, 0x31, 0x32,
        0x31, 0x33, 0x32, 0x32, 0x31, 0x39, 0x32, 0x38, 0x5A, 0x17,
        0x0D, 0x32, 0x36, 0x30, 0x39, 0x30, 0x38, 0x32, 0x32, 0x31,
        0x39, 0x32, 0x38, 0x5A, 0x30, 0x81, 0x90, 0x31, 0x0B, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
        0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10,
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42,
        0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x10, 0x30, 0x0E,
        0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x77, 0x6F, 0x6C,
        0x66, 0x53, 0x53, 0x4C, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
        0x55, 0x04, 0x0B, 0x0C, 0x07, 0x53, 0x75, 0x70, 0x70, 0x6F,
        0x72, 0x74, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C,
        0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F,
        0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40,
        0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F,
        0x6D, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02,
        0x82, 0x01, 0x01, 0x00, 0xC0, 0x95, 0x08, 0xE1, 0x57, 0x41,
        0xF2, 0x71, 0x6D, 0xB7, 0xD2, 0x45, 0x41, 0x27, 0x01, 0x65,
        0xC6, 0x45, 0xAE, 0xF2, 0xBC, 0x24, 0x30, 0xB8, 0x95, 0xCE,
        0x2F, 0x4E, 0xD6, 0xF6, 0x1C, 0x88, 0xBC, 0x7C, 0x9F, 0xFB,
        0xA8, 0x67, 0x7F, 0xFE, 0x5C, 0x9C, 0x51, 0x75, 0xF7, 0x8A,
        0xCA, 0x07, 0xE7, 0x35, 0x2F, 0x8F, 0xE1, 0xBD, 0x7B, 0xC0,
        0x2F, 0x7C, 0xAB, 0x64, 0xA8, 0x17, 0xFC, 0xCA, 0x5D, 0x7B,
        0xBA, 0xE0, 0x21, 0xE5, 0x72, 0x2E, 0x6F, 0x2E, 0x86, 0xD8,
        0x95, 0x73, 0xDA, 0xAC, 0x1B, 0x53, 0xB9, 0x5F, 0x3F, 0xD7,
        0x19, 0x0D, 0x25, 0x4F, 0xE1, 0x63, 0x63, 0x51, 0x8B, 0x0B,
        0x64, 0x3F, 0xAD, 0x43, 0xB8, 0xA5, 0x1C, 0x5C, 0x34, 0xB3,
        0xAE, 0x00, 0xA0, 0x63, 0xC5, 0xF6, 0x7F, 0x0B, 0x59, 0x68,
        0x78, 0x73, 0xA6, 0x8C, 0x18, 0xA9, 0x02, 0x6D, 0xAF, 0xC3,
        0x19, 0x01, 0x2E, 0xB8, 0x10, 0xE3, 0xC6, 0xCC, 0x40, 0xB4,
        0x69, 0xA3, 0x46, 0x33, 0x69, 0x87, 0x6E, 0xC4, 0xBB, 0x17,
        0xA6, 0xF3, 0xE8, 0xDD, 0xAD, 0x73, 0xBC, 0x7B, 0x2F, 0x21,
        0xB5, 0xFD, 0x66, 0x51, 0x0C, 0xBD, 0x54, 0xB3, 0xE1, 0x6D,
        0x5F, 0x1C, 0xBC, 0x23, 0x73, 0xD1, 0x09, 0x03, 0x89, 0x14,
        0xD2, 0x10, 0xB9, 0x64, 0xC3, 0x2A, 0xD0, 0xA1, 0x96, 0x4A,
        0xBC, 0xE1, 0xD4, 0x1A, 0x5B, 0xC7, 0xA0, 0xC0, 0xC1, 0x63,
        0x78, 0x0F, 0x44, 0x37, 0x30, 0x32, 0x96, 0x80, 0x32, 0x23,
        0x95, 0xA1, 0x77, 0xBA, 0x13, 0xD2, 0x97, 0x73, 0xE2, 0x5D,
        0x25, 0xC9, 0x6A, 0x0D, 0xC3, 0x39, 0x60, 0xA4, 0xB4, 0xB0,
        0x69, 0x42, 0x42, 0x09, 0xE9, 0xD8, 0x08, 0xBC, 0x33, 0x20,
        0xB3, 0x58, 0x22, 0xA7, 0xAA, 0xEB, 0xC4, 0xE1, 0xE6, 0x61,
        0x83, 0xC5, 0xD2, 0x96, 0xDF, 0xD9, 0xD0, 0x4F, 0xAD, 0xD7,
        0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x45, 0x30,
        0x82, 0x01, 0x41, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E,
        0x04, 0x16, 0x04, 0x14, 0xB3, 0x11, 0x32, 0xC9, 0x92, 0x98,
        0x84, 0xE2, 0xC9, 0xF8, 0xD0, 0x3B, 0x6E, 0x03, 0x42, 0xCA,
        0x1F, 0x0E, 0x8E, 0x3C, 0x30, 0x81, 0xD4, 0x06, 0x03, 0x55,
        0x1D, 0x23, 0x04, 0x81, 0xCC, 0x30, 0x81, 0xC9, 0x80, 0x14,
        0x27, 0x8E, 0x67, 0x11, 0x74, 0xC3, 0x26, 0x1D, 0x3F, 0xED,
        0x33, 0x63, 0xB3, 0xA4, 0xD8, 0x1D, 0x30, 0xE5, 0xE8, 0xD5,
        0xA1, 0x81, 0x9A, 0xA4, 0x81, 0x97, 0x30, 0x81, 0x94, 0x31,
        0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04,
        0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C,
        0x07, 0x42, 0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x11,
        0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x53,
        0x61, 0x77, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x31, 0x13, 0x30,
        0x11, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x43, 0x6F,
        0x6E, 0x73, 0x75, 0x6C, 0x74, 0x69, 0x6E, 0x67, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77,
        0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C,
        0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16,
        0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77, 0x6F, 0x6C, 0x66,
        0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x14, 0x33,
        0x44, 0x1A, 0xA8, 0x6C, 0x01, 0xEC, 0xF6, 0x60, 0xF2, 0x70,
        0x51, 0x0A, 0x4C, 0xD1, 0x14, 0xFA, 0xBC, 0xE9, 0x44, 0x30,
        0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03,
        0x01, 0x01, 0xFF, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x1D, 0x11,
        0x04, 0x15, 0x30, 0x13, 0x82, 0x0B, 0x65, 0x78, 0x61, 0x6D,
        0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x87, 0x04, 0x7F,
        0x00, 0x00, 0x01, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25,
        0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
        0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03,
        0x82, 0x01, 0x01, 0x00, 0x4A, 0xFF, 0xB9, 0xE5, 0x85, 0x9B,
        0xDA, 0x53, 0x66, 0x7F, 0x07, 0x22, 0xBF, 0xB6, 0x19, 0xEA,
        0x42, 0xEB, 0xA4, 0x11, 0x07, 0x62, 0xFF, 0x39, 0x5F, 0x33,
        0x37, 0x3A, 0x87, 0x26, 0x71, 0x3D, 0x13, 0xB2, 0xCA, 0xB8,
        0x64, 0x38, 0x7B, 0x8A, 0x99, 0x48, 0x0E, 0xA5, 0xA4, 0x6B,
        0xB1, 0x99, 0x6E, 0xE0, 0x46, 0x51, 0xBD, 0x19, 0x52, 0xAD,
        0xBC, 0xA6, 0x7E, 0x2A, 0x7A, 0x7C, 0x23, 0xA7, 0xCC, 0xDB,
        0x5E, 0x43, 0x7D, 0x6B, 0x04, 0xC8, 0xB7, 0xDD, 0x95, 0xAD,
        0xF0, 0x91, 0x80, 0x59, 0xC5, 0x19, 0x91, 0x26, 0x27, 0x91,
        0xB8, 0x48, 0x1C, 0xEB, 0x55, 0xB6, 0xAA, 0x7D, 0xA4, 0x38,
        0xF1, 0x03, 0xBC, 0x6C, 0x8B, 0xAA, 0x94, 0xD6, 0x3C, 0x05,
        0x7A, 0x96, 0xC5, 0x06, 0xF1, 0x26, 0x14, 0x2E, 0x75, 0xFB,
        0xDD, 0xE5, 0x35, 0xB3, 0x01, 0x2C, 0xB3, 0xAD, 0x62, 0x5A,
        0x21, 0x9A, 0x08, 0xBE, 0x56, 0xFC, 0xF9, 0xA2, 0x42, 0x87,
        0x86, 0xE5, 0xA9, 0xC5, 0x99, 0xCF, 0xAE, 0x14, 0xBE, 0xE0,
        0xB9, 0x08, 0x24, 0x0D, 0x1D, 0x5C, 0xD6, 0x14, 0xE1, 0x4C,
        0x9F, 0x40, 0xB3, 0xA9, 0xE9, 0x2D, 0x52, 0x8B, 0x4C, 0xBF,
        0xAC, 0x44, 0x31, 0x67, 0xC1, 0x8D, 0x06, 0x85, 0xEC, 0x0F,
        0xE4, 0x99, 0xD7, 0x4B, 0x7B, 0x21, 0x06, 0x66, 0xD4, 0xE4,
        0xF5, 0x9D, 0xFF, 0x8E, 0xF0, 0x86, 0x39, 0x58, 0x1D, 0xA4,
        0x5B, 0xE2, 0x63, 0xEF, 0x7C, 0xC9, 0x18, 0x87, 0xA8, 0x02,
        0x25, 0x10, 0x3E, 0x87, 0x28, 0xF9, 0xF5, 0xEF, 0x47, 0x9E,
        0xA5, 0x80, 0x08, 0x11, 0x90, 0x68, 0xFE, 0xD1, 0xA3, 0xA8,
        0x51, 0xB9, 0x37, 0xFF, 0xD5, 0xCA, 0x7C, 0x87, 0x7F, 0x6B,
        0xBC, 0x2C, 0x12, 0xC8, 0xC5, 0x85, 0x8B, 0xFC, 0x0C, 0xC6,
        0xB9, 0x86, 0xB8, 0xC9, 0x04, 0xC3, 0x51, 0x37, 0xD2, 0x4F
    };

    CK_ATTRIBUTE aTemplateAttributes[] = {
        {CKA_CLASS, &certClass, sizeof(certClass)},
        {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, label, sizeof(label)-1},
        {CKA_SUBJECT, subject, sizeof(subject)-1},
        {CKA_ID, certId, sizeof(certId)},
        {CKA_VALUE, certData, sizeof(certData)},
        {CKA_SERIAL_NUMBER, (CK_BYTE*)"\x02\x01\x01", 3},
        {CKA_PRIVATE, &ckFalse, sizeof(ckFalse)}
    };

    /* Create certificate object */
    ret = funcList->C_CreateObject(session, aTemplateAttributes,
        sizeof(aTemplateAttributes) / sizeof(CK_ATTRIBUTE), &hTest);
    CHECK_CKR(ret, "Create certificate object");

    if (ret == CKR_OK) {
        /* Search for certificate */
        CK_ATTRIBUTE aSearchAttributes[] = {
            { CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
            { CKA_CLASS, &certClass, sizeof(certClass) }
        };

        ret = funcList->C_FindObjectsInit(session, aSearchAttributes,
            sizeof(aSearchAttributes) / sizeof(CK_ATTRIBUTE));
        CHECK_CKR(ret, "C_FindObjectsInit");

        if (ret == CKR_OK) {
            CK_OBJECT_HANDLE hObjectFound = 0;
            CK_ULONG ulObjectCount = 0;
            CK_BBOOL bKeyFound = CK_FALSE;

            while (!bKeyFound) {
                ret = funcList->C_FindObjects(session, &hObjectFound, 1, &ulObjectCount);
                CHECK_CKR(ret, "C_FindObjects");

                if (ulObjectCount == 0) {
                    ret = CKR_GENERAL_ERROR;
                    CHECK_CKR(ret, "No certificate found by type");
                    break;
                }

                /* Get attributes to verify the found object */
                CK_ATTRIBUTE aAttributes[] = {
                    { CKA_CLASS, NULL_PTR, 0 },
                    { CKA_CERTIFICATE_TYPE, NULL_PTR, 0 },
                    { CKA_LABEL, NULL_PTR, 0 },
                    { CKA_ID, NULL_PTR, 0 }
                };
                unsigned int uiNumberOfAttributes = sizeof(aAttributes) / sizeof(CK_ATTRIBUTE);

                ret = funcList->C_GetAttributeValue(session, hObjectFound,
                    aAttributes, uiNumberOfAttributes);
                CHECK_CKR(ret, "C_GetAttributeValue");

                if (ret == CKR_OK) {
                    /* Allocate memory for attribute values */
                    for (unsigned int i = 0; i < uiNumberOfAttributes; ++i) {
                        void* pBuffer = XMALLOC(aAttributes[i].ulValueLen, NULL,
                                              DYNAMIC_TYPE_TMP_BUFFER);
                        if (pBuffer == NULL) {
                            ret = CKR_DEVICE_MEMORY;
                            break;
                        }
                        aAttributes[i].pValue = pBuffer;
                    }

                    if (ret == CKR_OK) {
                        ret = funcList->C_GetAttributeValue(session, hObjectFound,
                            aAttributes, uiNumberOfAttributes);
                        CHECK_CKR(ret, "C_GetAttributeValue");

                        /* Free allocated memory */
                        for (unsigned int i = 0; i < uiNumberOfAttributes; ++i) {
                            XFREE(aAttributes[i].pValue, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                            aAttributes[i].pValue = NULL;
                        }
                    }
                }

                if (ret == CKR_OK) {
                    bKeyFound = CK_TRUE;
                }
            }

            ret = funcList->C_FindObjectsFinal(session);
            CHECK_CKR(ret, "C_FindObjectsFinal");
        }
    }

    /* Clean up */
    if (hTest != CK_INVALID_HANDLE) {
        CK_RV destroyRet = funcList->C_DestroyObject(session, hTest);
        CHECK_CKR(destroyRet, "Destroy certificate object");
    }

    return ret;
}


#ifdef WOLFPKCS11_HKDF
static CK_RV test_hkdf_derive_extract_then_expand_salt_data(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE hDerivedKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hExpandKey = CK_INVALID_HANDLE;

    CK_BYTE salt_bytes[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    CK_BYTE expected_prk[] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };
    CK_BYTE ikm_tc1_hex[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    CK_BYTE expected_okm[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    CK_BYTE info_bytes[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };
    CK_ULONG ikm_len = sizeof(ikm_tc1_hex);
    CK_BYTE derived_value[32];
    CK_BYTE derived_value2[42];
    CK_ULONG derived_len = sizeof(derived_value);
    CK_ULONG derived_len2 = sizeof(derived_value2);
    CK_OBJECT_HANDLE hBaseKey1 = CK_INVALID_HANDLE;
    CK_ATTRIBUTE templateB = {CKA_VALUE, NULL_PTR, 0};

    CK_HKDF_PARAMS params = {
        CK_TRUE,
        CK_FALSE,
        CKM_SHA256_HMAC,
        CKF_HKDF_SALT_DATA,
        salt_bytes,
        sizeof(salt_bytes),
        CK_INVALID_HANDLE,
        NULL_PTR,
        0
    };

    CK_MECHANISM mechanism = { CKM_HKDF_DERIVE, &params, sizeof(params) };

    /* Template for the derived key (PRK) */
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE_LEN, &derived_len, sizeof(derived_len)}
    };
    CK_ULONG template_count = sizeof(template) / sizeof(template[0]);

    CK_ATTRIBUTE templateExpand[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE_LEN, &derived_len2, sizeof(derived_len2)}
    };
    CK_ULONG templateExpand_count =
        sizeof(templateExpand) / sizeof(templateExpand[0]);

    CK_HKDF_PARAMS paramsExpand = {
        CK_FALSE,
        CK_TRUE,
        CKM_SHA256_HMAC,
        CKF_HKDF_SALT_NULL,
        NULL_PTR,
        0,
        CK_INVALID_HANDLE,
        info_bytes,
        sizeof(info_bytes)
    };

    CK_MECHANISM mechanismExpand =
        { CKM_HKDF_DERIVE, &paramsExpand, sizeof(paramsExpand) };

    CK_ATTRIBUTE templateSecret[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE, ikm_tc1_hex, ikm_len},
        {CKA_VALUE_LEN, &ikm_len, sizeof(ikm_len)},
        {CKA_DERIVE, &ckTrue, sizeof(ckTrue)}
    };
    CK_ULONG templateSecretCount =
        sizeof(templateSecret) / sizeof(templateSecret[0]);

    ret = funcList->C_CreateObject(session, templateSecret, templateSecretCount,
        &hBaseKey1);
    CHECK_CKR(ret, "Create object failed");

    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mechanism, hBaseKey1, template,
            template_count, &hDerivedKey);
        CHECK_CKR(ret, "C_DeriveKey failed");
    }

    /* Verify the derived key value */
    if (ret == CKR_OK) {
        templateB.ulValueLen = 0;
        templateB.pValue = NULL_PTR;
        ret = funcList->C_GetAttributeValue(session, hDerivedKey, &templateB,
            1);
        if (ret == CKR_BUFFER_TOO_SMALL)
            ret = CKR_OK;
        CHECK_CKR(ret, "Derived key length");
    }
    if (ret == CKR_OK) {
        if (derived_len < templateB.ulValueLen) {
            ret = CKR_BUFFER_TOO_SMALL;
        }
        CHECK_CKR(ret, "Buffer length");
    }
    if (ret == CKR_OK) {
        templateB.pValue = derived_value;
        ret = funcList->C_GetAttributeValue(session, hDerivedKey, &templateB,
            1);
        CHECK_CKR(ret, "Get value");
    }

    if (ret == CKR_OK) {
        if (sizeof(expected_prk) != templateB.ulValueLen) {
            ret = CKR_DATA_LEN_RANGE;
            CHECK_CKR(ret, "Output length");
        }
    }

    if (ret == CKR_OK) {
        if (XMEMCMP(expected_prk, derived_value, sizeof(expected_prk))) {
            ret = CKR_DATA_INVALID;
            CHECK_CKR(ret, "Derived PRK doesn't match");
        }
    }

    /* Test Expand */
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mechanismExpand, hDerivedKey,
            templateExpand, templateExpand_count, &hExpandKey);
        CHECK_CKR(ret, "Expand derive");
    }

    /* Verify the derived key value */
    if (ret == CKR_OK) {
        templateB.ulValueLen = 0;
        templateB.pValue = NULL_PTR;
        ret = funcList->C_GetAttributeValue(session, hExpandKey, &templateB,
            1);
        if (ret == CKR_BUFFER_TOO_SMALL)
            ret = CKR_OK;
        CHECK_CKR(ret, "Derived key length");
    }
    if (ret == CKR_OK) {
        if (derived_len2 < templateB.ulValueLen) {
            ret = CKR_BUFFER_TOO_SMALL;
        }
        CHECK_CKR(ret, "Buffer length");
    }
    if (ret == CKR_OK) {
        templateB.pValue = derived_value2;
        ret = funcList->C_GetAttributeValue(session, hExpandKey, &templateB,
            1);
        CHECK_CKR(ret, "Get value");
    }
    if (ret == CKR_OK) {
        if (sizeof(expected_okm) != templateB.ulValueLen) {
            ret = CKR_DATA_LEN_RANGE;
            CHECK_CKR(ret, "Output length");
        }
    }

    if (ret == CKR_OK) {
        if (XMEMCMP(expected_okm, derived_value2, sizeof(expected_prk))) {
            ret = CKR_DATA_INVALID;
            CHECK_CKR(ret, "Derived PRK doesn't match");
        }
    }

    return ret;
}

static CK_RV test_hkdf_derive_extract_with_expand_salt_data(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE hDerivedKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hBaseKey1 = CK_INVALID_HANDLE;

    CK_BYTE salt_bytes[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    CK_BYTE expected_okm[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    CK_BYTE info_bytes[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };
    CK_BYTE ikm_tc1_hex[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    CK_ULONG ikm_len = sizeof(ikm_tc1_hex);

    CK_BYTE derived_value[42];
    CK_ULONG derived_len = sizeof(derived_value);

    CK_HKDF_PARAMS params = {
        CK_TRUE,
        CK_TRUE,
        CKM_SHA256_HMAC,
        CKF_HKDF_SALT_DATA,
        salt_bytes,
        sizeof(salt_bytes),
        CK_INVALID_HANDLE,
        info_bytes,
        sizeof(info_bytes)
    };

    CK_MECHANISM mechanism = { CKM_HKDF_DERIVE, &params, sizeof(params) };

    // Template for the derived key (OKM)
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE_LEN, &derived_len, sizeof(derived_len)} // Expecting 42 bytes OKM
    };
    CK_ULONG template_count = sizeof(template) / sizeof(template[0]);

    CK_ATTRIBUTE templateSecret[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE, ikm_tc1_hex, ikm_len},
        {CKA_VALUE_LEN, &ikm_len, sizeof(ikm_len)},
        {CKA_DERIVE, &ckTrue, sizeof(ckTrue)}
    };
    CK_ULONG templateSecretCount =
        sizeof(templateSecret) / sizeof(templateSecret[0]);


    CK_ATTRIBUTE templateB = {CKA_VALUE, NULL_PTR, 0};

    ret = funcList->C_CreateObject(session, templateSecret, templateSecretCount,
        &hBaseKey1);
    CHECK_CKR(ret, "Create object failed");

    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mechanism, hBaseKey1, template,
            template_count, &hDerivedKey);
        CHECK_CKR(ret, "Derive key");
    }

    if (ret == CKR_OK) {
        templateB.ulValueLen = 0;
        templateB.pValue = NULL_PTR;
        ret = funcList->C_GetAttributeValue(session, hDerivedKey, &templateB,
            1);
        if (ret == CKR_BUFFER_TOO_SMALL)
            ret = CKR_OK;
        CHECK_CKR(ret, "Derived key length");
    }
    if (ret == CKR_OK) {
        if (derived_len < templateB.ulValueLen) {
            ret = CKR_BUFFER_TOO_SMALL;
        }
        CHECK_CKR(ret, "Buffer length");
    }
    if (ret == CKR_OK) {
        templateB.pValue = derived_value;
        ret = funcList->C_GetAttributeValue(session, hDerivedKey, &templateB,
            1);
        CHECK_CKR(ret, "Get value");
    }

    if (ret == CKR_OK) {
        if (sizeof(expected_okm) != templateB.ulValueLen) {
            ret = CKR_DATA_LEN_RANGE;
            CHECK_CKR(ret, "Output length");
        }
    }

    if (ret == CKR_OK) {
        if (XMEMCMP(expected_okm, derived_value, sizeof(expected_okm))) {
            ret = CKR_DATA_INVALID;
            CHECK_CKR(ret, "Derived PRK doesn't match");
        }
    }

    return ret;
}

/* Extract-and-Expand with NULL Salt */
static CK_RV test_hkdf_derive_expand_with_extract_null_salt(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE hDerivedKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hBaseKey1 = CK_INVALID_HANDLE;

    CK_BYTE expected_okm[] = {
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
        0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
        0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
        0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
        0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
        0x96, 0xc8
    };
    CK_BYTE derived_value[42];
    CK_ULONG derived_len = sizeof(derived_value);

    CK_BYTE ikm_tc1_hex[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    CK_ULONG ikm_len = sizeof(ikm_tc1_hex);

    CK_HKDF_PARAMS params = {
        CK_TRUE,
        CK_TRUE,
        CKM_SHA256_HMAC,
        CKF_HKDF_SALT_NULL,
        NULL_PTR,
        0,
        CK_INVALID_HANDLE,
        NULL_PTR,
        0
    };

    CK_MECHANISM mechanism = { CKM_HKDF_DERIVE, &params, sizeof(params) };

    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE_LEN, &derived_len, sizeof(derived_len)}
    };
    CK_ULONG template_count = sizeof(template) / sizeof(template[0]);

    CK_ATTRIBUTE templateSecret[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE, ikm_tc1_hex, ikm_len},
        {CKA_VALUE_LEN, &ikm_len, sizeof(ikm_len)},
        {CKA_DERIVE, &ckTrue, sizeof(ckTrue)}
    };
    CK_ULONG templateSecretCount =
        sizeof(templateSecret) / sizeof(templateSecret[0]);

    CK_ATTRIBUTE templateB = {CKA_VALUE, NULL_PTR, 0};

    ret = funcList->C_CreateObject(session, templateSecret, templateSecretCount,
        &hBaseKey1);
    CHECK_CKR(ret, "Create object failed");

    if (ret == CKR_OK) {
        ret= funcList->C_DeriveKey(session, &mechanism, hBaseKey1, template,
            template_count, &hDerivedKey);
        CHECK_CKR(ret, "Derive key");
    }

    if (ret == CKR_OK) {
        templateB.ulValueLen = 0;
        templateB.pValue = NULL_PTR;
        ret = funcList->C_GetAttributeValue(session, hDerivedKey, &templateB,
            1);
        if (ret == CKR_BUFFER_TOO_SMALL)
            ret = CKR_OK;
        CHECK_CKR(ret, "Derived key length");
    }
    if (ret == CKR_OK) {
        if (derived_len < templateB.ulValueLen) {
            ret = CKR_BUFFER_TOO_SMALL;
        }
        CHECK_CKR(ret, "Buffer length");
    }
    if (ret == CKR_OK) {
        templateB.pValue = derived_value;
        ret = funcList->C_GetAttributeValue(session, hDerivedKey, &templateB,
            1);
        CHECK_CKR(ret, "Get value");
    }

    if (ret == CKR_OK) {
        if (sizeof(expected_okm) != templateB.ulValueLen) {
            ret = CKR_DATA_LEN_RANGE;
            CHECK_CKR(ret, "Output length");
        }
    }

    if (ret == CKR_OK) {
        if (XMEMCMP(expected_okm, derived_value, sizeof(expected_okm))) {
            ret = CKR_DATA_INVALID;
            CHECK_CKR(ret, "Derived PRK doesn't match");
        }
    }

    return ret;
}


static CK_RV test_hkdf_derive_extract_with_expand_salt_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE hDerivedKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hBaseKey1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hSaltKey1 = CK_INVALID_HANDLE;

    CK_BYTE salt_bytes[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    CK_ULONG salt_bytes_len = sizeof(salt_bytes);
    CK_BYTE expected_okm[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    CK_BYTE info_bytes[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };
    CK_BYTE ikm_tc1_hex[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    CK_ULONG ikm_len = sizeof(ikm_tc1_hex);

    CK_BYTE derived_value[42];
    CK_ULONG derived_len = sizeof(derived_value);

    // Template for the derived key (OKM)
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE_LEN, &derived_len, sizeof(derived_len)} // Expecting 42 bytes OKM
    };
    CK_ULONG template_count = sizeof(template) / sizeof(template[0]);

    CK_ATTRIBUTE templateSecret[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE, ikm_tc1_hex, ikm_len},
        {CKA_VALUE_LEN, &ikm_len, sizeof(ikm_len)},
        {CKA_DERIVE, &ckTrue, sizeof(ckTrue)}
    };
    CK_ULONG templateSecretCount =
        sizeof(templateSecret) / sizeof(templateSecret[0]);

    CK_ATTRIBUTE templateSalt[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
        {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_VALUE, salt_bytes, salt_bytes_len},
        {CKA_VALUE_LEN, &salt_bytes_len, sizeof(salt_bytes_len)},
        {CKA_DERIVE, &ckTrue, sizeof(ckTrue)}
    };
    CK_ULONG templateSaltCount =
        sizeof(templateSalt) / sizeof(templateSalt[0]);


    CK_ATTRIBUTE templateB = {CKA_VALUE, NULL_PTR, 0};

    ret = funcList->C_CreateObject(session, templateSecret, templateSecretCount,
        &hBaseKey1);
    CHECK_CKR(ret, "Create object failed");

    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, templateSalt, templateSaltCount,
            &hSaltKey1);
        CHECK_CKR(ret, "Create object failed");
    }

    if (ret == CKR_OK) {
        CK_HKDF_PARAMS params = {
            CK_TRUE,
            CK_TRUE,
            CKM_SHA256_HMAC,
            CKF_HKDF_SALT_KEY,
            NULL_PTR,
            0,
            hSaltKey1,
            info_bytes,
            sizeof(info_bytes)
        };

        CK_MECHANISM mechanism = { CKM_HKDF_DERIVE, &params, sizeof(params) };
        ret = funcList->C_DeriveKey(session, &mechanism, hBaseKey1, template,
            template_count, &hDerivedKey);
        CHECK_CKR(ret, "Derive key");
    }

    if (ret == CKR_OK) {
        templateB.ulValueLen = 0;
        templateB.pValue = NULL_PTR;
        ret = funcList->C_GetAttributeValue(session, hDerivedKey, &templateB,
            1);
        if (ret == CKR_BUFFER_TOO_SMALL)
            ret = CKR_OK;
        CHECK_CKR(ret, "Derived key length");
    }
    if (ret == CKR_OK) {
        if (derived_len < templateB.ulValueLen) {
            ret = CKR_BUFFER_TOO_SMALL;
        }
        CHECK_CKR(ret, "Buffer length");
    }
    if (ret == CKR_OK) {
        templateB.pValue = derived_value;
        ret = funcList->C_GetAttributeValue(session, hDerivedKey, &templateB,
            1);
        CHECK_CKR(ret, "Get value");
    }

    if (ret == CKR_OK) {
        if (sizeof(expected_okm) != templateB.ulValueLen) {
            ret = CKR_DATA_LEN_RANGE;
            CHECK_CKR(ret, "Output length");
        }
    }

    if (ret == CKR_OK) {
        if (XMEMCMP(expected_okm, derived_value, sizeof(expected_okm))) {
            ret = CKR_DATA_INVALID;
            CHECK_CKR(ret, "Derived PRK doesn't match");
        }
    }

    return ret;
}

static CK_RV test_hkdf_gen_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV             ret = CKR_OK;
    CK_OBJECT_HANDLE  key = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_ULONG          keyLen = 48;
    CK_ATTRIBUTE      keyTmpl[] = {
        { CKA_VALUE_LEN,       &keyLen,            sizeof(keyLen)             },
    };
    int               keyTmplCnt = sizeof(keyTmpl)/sizeof(*keyTmpl);

    if (ret == CKR_OK) {
        mech.mechanism      = CKM_HKDF_KEY_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter     = NULL;

        ret = funcList->C_GenerateKey(session, &mech, keyTmpl, keyTmplCnt,
                                                                          &key);
        CHECK_CKR(ret, "AES Key Generation");
    }
    if (ret == CKR_OK) {
        mech.pParameter = keyTmpl;
        ret = funcList->C_GenerateKey(session, &mech, keyTmpl, keyTmplCnt,
                                                                          &key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                                  "Generate Key bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = sizeof(keyTmpl);
        ret = funcList->C_GenerateKey(session, &mech, keyTmpl, keyTmplCnt,
                                                                          &key);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                                           "Generate Key bad parameter length");
        mech.ulParameterLen = 0;
    }

    return ret;
}
#endif

static CK_RV test_x509_check_value(void* args)
{
    CK_RV ret = CKR_OK;
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_UTF8CHAR label[] = "A certificate object";
    CK_BYTE subject[] = "C = US, ST = Montana, L = Bozeman, O = wolfSSL, "
        "OU = Support, CN = www.wolfssl.com, emailAddress = info@wolfssl.com";
    CK_BYTE id[] = {0x27, 0x8E, 0x67, 0x11, 0x74, 0xC3, 0x26, 0x1D, 0x3F, 0xED,
                    0x33, 0x63, 0xB3, 0xA4, 0xD8, 0x1D, 0x30, 0xE5, 0xE8, 0xD5
    };
    CK_BYTE certificate[] = { /* ./certs/server-cert.der, 2048-bit */
        0x30, 0x82, 0x04, 0xE8, 0x30, 0x82, 0x03, 0xD0, 0xA0, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
        0x00, 0x30, 0x81, 0x94, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30,
        0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F,
        0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E, 0x06,
        0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42, 0x6F, 0x7A, 0x65,
        0x6D, 0x61, 0x6E, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55,
        0x04, 0x0A, 0x0C, 0x08, 0x53, 0x61, 0x77, 0x74, 0x6F, 0x6F,
        0x74, 0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
        0x0B, 0x0C, 0x0A, 0x43, 0x6F, 0x6E, 0x73, 0x75, 0x6C, 0x74,
        0x69, 0x6E, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F,
        0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31,
        0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F,
        0x40, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63,
        0x6F, 0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x33, 0x31, 0x32,
        0x31, 0x33, 0x32, 0x32, 0x31, 0x39, 0x32, 0x38, 0x5A, 0x17,
        0x0D, 0x32, 0x36, 0x30, 0x39, 0x30, 0x38, 0x32, 0x32, 0x31,
        0x39, 0x32, 0x38, 0x5A, 0x30, 0x81, 0x90, 0x31, 0x0B, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
        0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10,
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42,
        0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x10, 0x30, 0x0E,
        0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x77, 0x6F, 0x6C,
        0x66, 0x53, 0x53, 0x4C, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
        0x55, 0x04, 0x0B, 0x0C, 0x07, 0x53, 0x75, 0x70, 0x70, 0x6F,
        0x72, 0x74, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C,
        0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F,
        0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40,
        0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F,
        0x6D, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02,
        0x82, 0x01, 0x01, 0x00, 0xC0, 0x95, 0x08, 0xE1, 0x57, 0x41,
        0xF2, 0x71, 0x6D, 0xB7, 0xD2, 0x45, 0x41, 0x27, 0x01, 0x65,
        0xC6, 0x45, 0xAE, 0xF2, 0xBC, 0x24, 0x30, 0xB8, 0x95, 0xCE,
        0x2F, 0x4E, 0xD6, 0xF6, 0x1C, 0x88, 0xBC, 0x7C, 0x9F, 0xFB,
        0xA8, 0x67, 0x7F, 0xFE, 0x5C, 0x9C, 0x51, 0x75, 0xF7, 0x8A,
        0xCA, 0x07, 0xE7, 0x35, 0x2F, 0x8F, 0xE1, 0xBD, 0x7B, 0xC0,
        0x2F, 0x7C, 0xAB, 0x64, 0xA8, 0x17, 0xFC, 0xCA, 0x5D, 0x7B,
        0xBA, 0xE0, 0x21, 0xE5, 0x72, 0x2E, 0x6F, 0x2E, 0x86, 0xD8,
        0x95, 0x73, 0xDA, 0xAC, 0x1B, 0x53, 0xB9, 0x5F, 0x3F, 0xD7,
        0x19, 0x0D, 0x25, 0x4F, 0xE1, 0x63, 0x63, 0x51, 0x8B, 0x0B,
        0x64, 0x3F, 0xAD, 0x43, 0xB8, 0xA5, 0x1C, 0x5C, 0x34, 0xB3,
        0xAE, 0x00, 0xA0, 0x63, 0xC5, 0xF6, 0x7F, 0x0B, 0x59, 0x68,
        0x78, 0x73, 0xA6, 0x8C, 0x18, 0xA9, 0x02, 0x6D, 0xAF, 0xC3,
        0x19, 0x01, 0x2E, 0xB8, 0x10, 0xE3, 0xC6, 0xCC, 0x40, 0xB4,
        0x69, 0xA3, 0x46, 0x33, 0x69, 0x87, 0x6E, 0xC4, 0xBB, 0x17,
        0xA6, 0xF3, 0xE8, 0xDD, 0xAD, 0x73, 0xBC, 0x7B, 0x2F, 0x21,
        0xB5, 0xFD, 0x66, 0x51, 0x0C, 0xBD, 0x54, 0xB3, 0xE1, 0x6D,
        0x5F, 0x1C, 0xBC, 0x23, 0x73, 0xD1, 0x09, 0x03, 0x89, 0x14,
        0xD2, 0x10, 0xB9, 0x64, 0xC3, 0x2A, 0xD0, 0xA1, 0x96, 0x4A,
        0xBC, 0xE1, 0xD4, 0x1A, 0x5B, 0xC7, 0xA0, 0xC0, 0xC1, 0x63,
        0x78, 0x0F, 0x44, 0x37, 0x30, 0x32, 0x96, 0x80, 0x32, 0x23,
        0x95, 0xA1, 0x77, 0xBA, 0x13, 0xD2, 0x97, 0x73, 0xE2, 0x5D,
        0x25, 0xC9, 0x6A, 0x0D, 0xC3, 0x39, 0x60, 0xA4, 0xB4, 0xB0,
        0x69, 0x42, 0x42, 0x09, 0xE9, 0xD8, 0x08, 0xBC, 0x33, 0x20,
        0xB3, 0x58, 0x22, 0xA7, 0xAA, 0xEB, 0xC4, 0xE1, 0xE6, 0x61,
        0x83, 0xC5, 0xD2, 0x96, 0xDF, 0xD9, 0xD0, 0x4F, 0xAD, 0xD7,
        0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x45, 0x30,
        0x82, 0x01, 0x41, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E,
        0x04, 0x16, 0x04, 0x14, 0xB3, 0x11, 0x32, 0xC9, 0x92, 0x98,
        0x84, 0xE2, 0xC9, 0xF8, 0xD0, 0x3B, 0x6E, 0x03, 0x42, 0xCA,
        0x1F, 0x0E, 0x8E, 0x3C, 0x30, 0x81, 0xD4, 0x06, 0x03, 0x55,
        0x1D, 0x23, 0x04, 0x81, 0xCC, 0x30, 0x81, 0xC9, 0x80, 0x14,
        0x27, 0x8E, 0x67, 0x11, 0x74, 0xC3, 0x26, 0x1D, 0x3F, 0xED,
        0x33, 0x63, 0xB3, 0xA4, 0xD8, 0x1D, 0x30, 0xE5, 0xE8, 0xD5,
        0xA1, 0x81, 0x9A, 0xA4, 0x81, 0x97, 0x30, 0x81, 0x94, 0x31,
        0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04,
        0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C,
        0x07, 0x42, 0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x11,
        0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x53,
        0x61, 0x77, 0x74, 0x6F, 0x6F, 0x74, 0x68, 0x31, 0x13, 0x30,
        0x11, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x43, 0x6F,
        0x6E, 0x73, 0x75, 0x6C, 0x74, 0x69, 0x6E, 0x67, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77,
        0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C,
        0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16,
        0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77, 0x6F, 0x6C, 0x66,
        0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x14, 0x33,
        0x44, 0x1A, 0xA8, 0x6C, 0x01, 0xEC, 0xF6, 0x60, 0xF2, 0x70,
        0x51, 0x0A, 0x4C, 0xD1, 0x14, 0xFA, 0xBC, 0xE9, 0x44, 0x30,
        0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03,
        0x01, 0x01, 0xFF, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x1D, 0x11,
        0x04, 0x15, 0x30, 0x13, 0x82, 0x0B, 0x65, 0x78, 0x61, 0x6D,
        0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x87, 0x04, 0x7F,
        0x00, 0x00, 0x01, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25,
        0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
        0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03,
        0x82, 0x01, 0x01, 0x00, 0x4A, 0xFF, 0xB9, 0xE5, 0x85, 0x9B,
        0xDA, 0x53, 0x66, 0x7F, 0x07, 0x22, 0xBF, 0xB6, 0x19, 0xEA,
        0x42, 0xEB, 0xA4, 0x11, 0x07, 0x62, 0xFF, 0x39, 0x5F, 0x33,
        0x37, 0x3A, 0x87, 0x26, 0x71, 0x3D, 0x13, 0xB2, 0xCA, 0xB8,
        0x64, 0x38, 0x7B, 0x8A, 0x99, 0x48, 0x0E, 0xA5, 0xA4, 0x6B,
        0xB1, 0x99, 0x6E, 0xE0, 0x46, 0x51, 0xBD, 0x19, 0x52, 0xAD,
        0xBC, 0xA6, 0x7E, 0x2A, 0x7A, 0x7C, 0x23, 0xA7, 0xCC, 0xDB,
        0x5E, 0x43, 0x7D, 0x6B, 0x04, 0xC8, 0xB7, 0xDD, 0x95, 0xAD,
        0xF0, 0x91, 0x80, 0x59, 0xC5, 0x19, 0x91, 0x26, 0x27, 0x91,
        0xB8, 0x48, 0x1C, 0xEB, 0x55, 0xB6, 0xAA, 0x7D, 0xA4, 0x38,
        0xF1, 0x03, 0xBC, 0x6C, 0x8B, 0xAA, 0x94, 0xD6, 0x3C, 0x05,
        0x7A, 0x96, 0xC5, 0x06, 0xF1, 0x26, 0x14, 0x2E, 0x75, 0xFB,
        0xDD, 0xE5, 0x35, 0xB3, 0x01, 0x2C, 0xB3, 0xAD, 0x62, 0x5A,
        0x21, 0x9A, 0x08, 0xBE, 0x56, 0xFC, 0xF9, 0xA2, 0x42, 0x87,
        0x86, 0xE5, 0xA9, 0xC5, 0x99, 0xCF, 0xAE, 0x14, 0xBE, 0xE0,
        0xB9, 0x08, 0x24, 0x0D, 0x1D, 0x5C, 0xD6, 0x14, 0xE1, 0x4C,
        0x9F, 0x40, 0xB3, 0xA9, 0xE9, 0x2D, 0x52, 0x8B, 0x4C, 0xBF,
        0xAC, 0x44, 0x31, 0x67, 0xC1, 0x8D, 0x06, 0x85, 0xEC, 0x0F,
        0xE4, 0x99, 0xD7, 0x4B, 0x7B, 0x21, 0x06, 0x66, 0xD4, 0xE4,
        0xF5, 0x9D, 0xFF, 0x8E, 0xF0, 0x86, 0x39, 0x58, 0x1D, 0xA4,
        0x5B, 0xE2, 0x63, 0xEF, 0x7C, 0xC9, 0x18, 0x87, 0xA8, 0x02,
        0x25, 0x10, 0x3E, 0x87, 0x28, 0xF9, 0xF5, 0xEF, 0x47, 0x9E,
        0xA5, 0x80, 0x08, 0x11, 0x90, 0x68, 0xFE, 0xD1, 0xA3, 0xA8,
        0x51, 0xB9, 0x37, 0xFF, 0xD5, 0xCA, 0x7C, 0x87, 0x7F, 0x6B,
        0xBC, 0x2C, 0x12, 0xC8, 0xC5, 0x85, 0x8B, 0xFC, 0x0C, 0xC6,
        0xB9, 0x86, 0xB8, 0xC9, 0x04, 0xC3, 0x51, 0x37, 0xD2, 0x4F
    };
    /* Expected check value - first 3 bytes of SHA-1 hash of the certificate */
    CK_BYTE expectedCheckValue[] = {0xB6, 0x38, 0x75};

    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &certificateClass, sizeof(certificateClass)},
        {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
        {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
        {CKA_LABEL, label, sizeof(label)-1},
        {CKA_SUBJECT, subject, sizeof(subject)-1},
        {CKA_ID, id, sizeof(id)},
        {CKA_VALUE, certificate, sizeof(certificate)}
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE checkValueTmpl[] = {
        { CKA_CHECK_VALUE, NULL, 0 }
    };
    CK_ULONG checkValueTmplCnt = sizeof(checkValueTmpl) / sizeof(*checkValueTmpl);
    CK_BYTE checkValue[3];

    /* Create certificate object */
    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create certificate object");

    if (ret == CKR_OK) {
        /* Get the length of the check value first */
        ret = funcList->C_GetAttributeValue(session, obj, checkValueTmpl, checkValueTmplCnt);
        CHECK_CKR(ret, "C_GetAttributeValue for check value length");
    }

    if (ret == CKR_OK) {
        /* Verify expected check value length is 3 bytes */
        if (checkValueTmpl[0].ulValueLen != 3) {
            ret = CKR_GENERAL_ERROR;
            CHECK_CKR(ret, "Check value length should be 3 bytes");
        }
    }

    if (ret == CKR_OK) {
        /* Get the actual check value */
        checkValueTmpl[0].pValue = checkValue;
        checkValueTmpl[0].ulValueLen = sizeof(checkValue);

        ret = funcList->C_GetAttributeValue(session, obj, checkValueTmpl, checkValueTmplCnt);
        CHECK_CKR(ret, "C_GetAttributeValue for check value");

        if (ret == CKR_OK) {
            /* Verify the check value matches expected value */
            if (XMEMCMP(checkValue, expectedCheckValue, 3) != 0) {
                ret = CKR_GENERAL_ERROR;
                CHECK_CKR(ret, "Check value doesn't match expected SHA-1 hash prefix");
            }
        }
    }

    /* Clean up the object */
    funcList->C_DestroyObject(session, obj);

    return ret;
}


static CK_RV test_random(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    unsigned char* seed = (unsigned char *)"Test";
    int seedLen = 4;
    unsigned char data1[32];
    unsigned char data2[32];
    int i;
    unsigned char b;

    XMEMSET(data1, 0, sizeof(data1));
    XMEMSET(data2, 0, sizeof(data2));

    ret = funcList->C_SeedRandom(session, seed, seedLen);
    CHECK_CKR(ret, "Seed Random 1");
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateRandom(session, data1, sizeof(data1));
        CHECK_CKR(ret, "Generate Random 1");
    }
    if (ret == CKR_OK) {
        b = 0;
        for (i = 0; i < (int)sizeof(data1); i++)
            b |= data1[i];
        if (b == 0)
            ret = -1;
        CHECK_CKR(ret, "Generated non-zero 1");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SeedRandom(session, seed, seedLen);
        CHECK_CKR(ret, "Seed Random 2");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateRandom(session, data2, sizeof(data2));
        CHECK_CKR(ret, "Generate Random 2");
    }
    if (ret == CKR_OK) {
        b = 0;
        for (i = 0; i < (int)sizeof(data2); i++)
            b |= data2[i];
        if (b == 0)
            ret = -1;
        CHECK_CKR(ret, "Generated non-zero 2");
    }
    if (ret == CKR_OK && XMEMCMP(data1, data2, sizeof(data1)) == 0) {
        ret = -1;
        CHECK_CKR(ret, "Seed-Generate result different");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SeedRandom(CK_INVALID_HANDLE, seed, seedLen);
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                          "Seed Random invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SeedRandom(session, NULL, seedLen);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Seed Random no seed");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateRandom(CK_INVALID_HANDLE, data1,
                                                                 sizeof(data1));
        CHECK_CKR_FAIL(ret, CKR_SESSION_HANDLE_INVALID,
                                      "Generate Random invalid session handle");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GenerateRandom(session, NULL, sizeof(data1));
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Generate Random no data");
    }

    return ret;
}

#ifdef WOLFSSL_HAVE_PRF
static CK_RV test_derive_tls12_key_and_mac(void *args) {
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE premasterSecret;
    unsigned char clientIV[16], serverIV[16];
    CK_BBOOL trueValue = CK_TRUE;
    CK_BBOOL falseValue = CK_FALSE;
    CK_OBJECT_HANDLE hDerivedKey = CK_INVALID_HANDLE;
    static unsigned char test_premaster_secret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30
    };

    static unsigned char test_client_random[] = {
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80
    };

    static unsigned char test_server_random[] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60
    };

    static unsigned char expected_client_mac_key[] = {
        0x2e, 0xe2, 0xcb, 0x38, 0xb5, 0xd8, 0x50, 0x90,
        0xda, 0xc2, 0x87, 0x65, 0xeb, 0xfb, 0x59, 0x34,
        0xb1, 0x54, 0xa3, 0xc8, 0x2a, 0x9d, 0xad, 0xed,
        0x5f, 0xa3, 0x01, 0x79, 0xd8, 0x10, 0x93, 0xcc
    };

    static unsigned char expected_server_mac_key[] = {
        0xdd, 0x6e, 0xc7, 0x90, 0x9d, 0xf9, 0xbf, 0x39,
        0xec, 0x2f, 0x44, 0x89, 0x4a, 0xc4, 0x04, 0xfe,
        0x93, 0xb9, 0x77, 0xff, 0xed, 0x96, 0x7d, 0x1f,
        0xeb, 0x26, 0x61, 0x45, 0xfc, 0x48, 0x2d, 0x1b
    };

    static unsigned char expected_client_key[] = {
        0x2a, 0xb4, 0x47, 0x20, 0x2e, 0x35, 0xd2, 0xe6,
        0xe3, 0xdd, 0x71, 0x34, 0x84, 0x00, 0x9d, 0xb5
    };

    static unsigned char expected_server_key[] = {
        0x19, 0xca, 0x53, 0x63, 0x3e, 0x49, 0x86, 0x63,
        0x7f, 0x3d, 0x18, 0x12, 0xa3, 0x9d, 0x0a, 0x4a
    };

    static unsigned char expected_client_iv[] = {
        0xb8, 0xdb, 0x5b, 0xf6, 0xce, 0x7e, 0x3a, 0x31,
        0x97, 0x30, 0xbb, 0x57, 0x6f, 0xa7, 0xb1, 0x72
    };

    static unsigned char expected_server_iv[] = {
        0x15, 0xe9, 0xad, 0xa0, 0x0b, 0xfe, 0x61, 0xd6,
        0x3a, 0xfa, 0x1b, 0xc3, 0x8c, 0x4a, 0xa2, 0x95
    };

    CK_ATTRIBUTE premasterAttrs[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_VALUE, test_premaster_secret, sizeof(test_premaster_secret)},
        {CKA_DERIVE, &trueValue, sizeof(trueValue)}
    };

    CK_SSL3_RANDOM_DATA randomInfo = {
        test_client_random, sizeof(test_client_random),
        test_server_random, sizeof(test_server_random)
    };

    CK_SSL3_KEY_MAT_OUT keyMaterialOut = {
        CK_INVALID_HANDLE, CK_INVALID_HANDLE,
        CK_INVALID_HANDLE, CK_INVALID_HANDLE,
        clientIV, serverIV
    };

    CK_TLS12_KEY_MAT_PARAMS params = {
        32*8,
        16*8,
        16*8,
        CK_FALSE,
        randomInfo,
        &keyMaterialOut,
        CKM_SHA256
    };

    CK_MECHANISM mechanism = {
        CKM_TLS12_KEY_AND_MAC_DERIVE,
        &params,
        sizeof(params)
    };

    CK_ATTRIBUTE derivedKeyTemplate[] = {
        {CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass)},
        {CKA_KEY_TYPE, &genericKeyType, sizeof(genericKeyType)},
        {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
        {CKA_EXTRACTABLE, &trueValue, sizeof(trueValue)},
        {CKA_DERIVE, &trueValue, sizeof(trueValue)},
        {CKA_ENCRYPT, &falseValue, sizeof(falseValue)},
        {CKA_DECRYPT, &falseValue, sizeof(falseValue)},
        {CKA_TOKEN, &falseValue, sizeof(falseValue)}
    };
    CK_ULONG ulDerivedKeyTemplateCount =
        sizeof(derivedKeyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_BYTE derivedKeyValue[48];
    CK_ATTRIBUTE getValueTemplate[] = {
        {CKA_VALUE, derivedKeyValue, sizeof(derivedKeyValue)}
    };
    CK_ULONG ulGetValueTemplateCount =
        sizeof(getValueTemplate) / sizeof(CK_ATTRIBUTE);

    ret = funcList->C_CreateObject(session, premasterAttrs,
                                sizeof(premasterAttrs) / sizeof(CK_ATTRIBUTE),
                                &premasterSecret);
    CHECK_CKR(ret, "Create object");
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mechanism, premasterSecret,
                                    derivedKeyTemplate,
                                    ulDerivedKeyTemplateCount, &hDerivedKey);
        CHECK_CKR(ret, "Derive key");
    }

    if (ret == CKR_OK) {
        CHECK_COND(hDerivedKey == CK_INVALID_HANDLE, ret,
                   "No single derived key");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(clientIV, expected_client_iv,
                           sizeof(expected_client_iv)) == 0,
                   ret, "Client IV compare");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(serverIV, expected_server_iv,
                           sizeof(expected_server_iv)) == 0,
                   ret, "Server IV compare");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session,
                                            keyMaterialOut.hClientMacSecret,
                                            getValueTemplate,
                                            ulGetValueTemplateCount);
    }

    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen == 32, ret, "Get CKA_VALUE");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(derivedKeyValue, expected_client_mac_key, 32) == 0,
                   ret, "Client mac compare");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session,
                                            keyMaterialOut.hServerMacSecret,
                                            getValueTemplate,
                                            ulGetValueTemplateCount);
    }

    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen == 32, ret,
                   "Get CKA_VALUE");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(derivedKeyValue, expected_server_mac_key, 32) == 0,
                   ret, "Client mac compare");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session,
                                            keyMaterialOut.hClientKey,
                                            getValueTemplate,
                                            ulGetValueTemplateCount);
    }

    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen == 16, ret,
                   "Get CKA_VALUE");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(derivedKeyValue, expected_client_key, 16) == 0,
                   ret, "Client key compare");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session,
                                            keyMaterialOut.hServerKey,
                                            getValueTemplate,
                                            ulGetValueTemplateCount);
    }

    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen == 16, ret,
                   "Get CKA_VALUE");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(derivedKeyValue, expected_server_key, 16) == 0,
                   ret, "Server key compare");
    }

    return ret;
}

static CK_RV test_derive_tls12_master_key_dh(void* args) {
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE hBaseKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hDerivedKey = CK_INVALID_HANDLE;

    CK_BYTE preMasterSecret[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };
    CK_ULONG ulPreMasterSecretLen = sizeof(preMasterSecret);

    CK_BYTE clientRandom[] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
    };
    CK_BYTE serverRandom[] = {
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB
    };

    /* Generated using Python scapy.layers.tls.crypto.prf */
    CK_BYTE expectedMasterSecret[] = {
        0xc8, 0x43, 0xf0, 0x67, 0xbf, 0xc2, 0x7b, 0xd6,
        0xb6, 0x42, 0x26, 0x01, 0xe9, 0x1a, 0xc9, 0xb5,
        0x32, 0xaa, 0x4b, 0xbb, 0x02, 0xd0, 0x1f, 0x20,
        0xe9, 0x3b, 0x75, 0x60, 0x2d, 0x6d, 0x0d, 0xf1,
        0x4f, 0x4b, 0xff, 0xff, 0x2a, 0x12, 0x9b, 0xf1,
        0x6a, 0x4d, 0x16, 0x69, 0x07, 0x55, 0x38, 0x30
    };
    CK_ULONG ulExpectedMasterSecretLen = sizeof(expectedMasterSecret);

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL trueValue = CK_TRUE;
    CK_BBOOL falseValue = CK_FALSE;

    CK_ATTRIBUTE baseKeyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VALUE, preMasterSecret, ulPreMasterSecretLen},
        {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
        {CKA_EXTRACTABLE, &falseValue, sizeof(falseValue)},
        {CKA_DERIVE, &trueValue, sizeof(trueValue)},
        {CKA_TOKEN, &falseValue, sizeof(falseValue)}
    };
    CK_ULONG ulBaseKeyTemplateCount =
        sizeof(baseKeyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_TLS12_MASTER_KEY_DERIVE_PARAMS params;
    params.RandomInfo.pClientRandom = clientRandom;
    params.RandomInfo.ulClientRandomLen = sizeof(clientRandom);
    params.RandomInfo.pServerRandom = serverRandom;
    params.RandomInfo.ulServerRandomLen = sizeof(serverRandom);
    /* Version for TLS 1.2 is {3, 3} */
    CK_VERSION version = {3, 3};
    params.pVersion = &version;
    params.prfHashMechanism = CKM_SHA256;
    CK_MECHANISM mechanism = {
        CKM_TLS12_MASTER_KEY_DERIVE_DH, &params, sizeof(params)
    };

    CK_ULONG derivedKeyLength = 48;
    CK_KEY_TYPE derivedKeyType = CKK_GENERIC_SECRET;

    CK_ATTRIBUTE derivedKeyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &derivedKeyType, sizeof(derivedKeyType)},
        {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
        {CKA_EXTRACTABLE, &trueValue, sizeof(trueValue)},
        {CKA_DERIVE, &trueValue, sizeof(trueValue)},
        {CKA_ENCRYPT, &falseValue, sizeof(falseValue)},
        {CKA_DECRYPT, &falseValue, sizeof(falseValue)},
        {CKA_TOKEN, &falseValue, sizeof(falseValue)},
        {CKA_VALUE_LEN, &derivedKeyLength, sizeof(derivedKeyLength)}
    };
    CK_ULONG ulDerivedKeyTemplateCount =
        sizeof(derivedKeyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_BYTE derivedKeyValue[48];
    CK_ATTRIBUTE getValueTemplate[] = {
        {CKA_VALUE, derivedKeyValue, sizeof(derivedKeyValue)}
    };
    CK_ULONG ulGetValueTemplateCount =
        sizeof(getValueTemplate) / sizeof(CK_ATTRIBUTE);


    ret = funcList->C_CreateObject(session, baseKeyTemplate,
                                   ulBaseKeyTemplateCount, &hBaseKey);
    CHECK_CKR(ret, "Base key");
    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mechanism, hBaseKey,
                                    derivedKeyTemplate,
                                    ulDerivedKeyTemplateCount, &hDerivedKey);
        CHECK_CKR(ret, "Derive key");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, hDerivedKey,
                                            getValueTemplate,
                                            ulGetValueTemplateCount);
    }
    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen == ulExpectedMasterSecretLen,
                   ret, "Derived key length mismatch");
    }
    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen != (CK_ULONG)-1, ret,
                   "Get CKA_VALUE");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(derivedKeyValue, expectedMasterSecret,
                           ulExpectedMasterSecretLen) == 0, ret,
                   "Secret compare");
    }

    return ret;
}

static CK_RV test_derive_tls12_master_key(void* args) {
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE hBaseKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hDerivedKey = CK_INVALID_HANDLE;

    CK_BYTE preMasterSecret[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };
    CK_ULONG ulPreMasterSecretLen = sizeof(preMasterSecret);

    CK_BYTE clientRandom[] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
    };
    CK_BYTE serverRandom[] = {
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB
    };

    /* Generated using Python scapy.layers.tls.crypto.prf */
    CK_BYTE expectedMasterSecret[] = {
        0xc8, 0x43, 0xf0, 0x67, 0xbf, 0xc2, 0x7b, 0xd6,
        0xb6, 0x42, 0x26, 0x01, 0xe9, 0x1a, 0xc9, 0xb5,
        0x32, 0xaa, 0x4b, 0xbb, 0x02, 0xd0, 0x1f, 0x20,
        0xe9, 0x3b, 0x75, 0x60, 0x2d, 0x6d, 0x0d, 0xf1,
        0x4f, 0x4b, 0xff, 0xff, 0x2a, 0x12, 0x9b, 0xf1,
        0x6a, 0x4d, 0x16, 0x69, 0x07, 0x55, 0x38, 0x30
    };
    CK_ULONG ulExpectedMasterSecretLen = sizeof(expectedMasterSecret);

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL trueValue = CK_TRUE;
    CK_BBOOL falseValue = CK_FALSE;

    CK_ATTRIBUTE baseKeyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VALUE, preMasterSecret, ulPreMasterSecretLen},
        {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
        {CKA_EXTRACTABLE, &falseValue, sizeof(falseValue)},
        {CKA_DERIVE, &trueValue, sizeof(trueValue)},
        {CKA_TOKEN, &falseValue, sizeof(falseValue)}
    };
    CK_ULONG ulBaseKeyTemplateCount =
        sizeof(baseKeyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_TLS12_MASTER_KEY_DERIVE_PARAMS params;
    params.RandomInfo.pClientRandom = clientRandom;
    params.RandomInfo.ulClientRandomLen = sizeof(clientRandom);
    params.RandomInfo.pServerRandom = serverRandom;
    params.RandomInfo.ulServerRandomLen = sizeof(serverRandom);
    /* Version for TLS 1.2 is {3, 3} */
    CK_VERSION version = {3, 3};
    params.pVersion = &version;
    params.prfHashMechanism = CKM_SHA256;
    CK_MECHANISM mechanism = {
        CKM_TLS12_MASTER_KEY_DERIVE, &params, sizeof(params)
    };

    CK_ULONG derivedKeyLength = 48;
    CK_KEY_TYPE derivedKeyType = CKK_GENERIC_SECRET;

    CK_ATTRIBUTE derivedKeyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &derivedKeyType, sizeof(derivedKeyType)},
        {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
        {CKA_EXTRACTABLE, &trueValue, sizeof(trueValue)},
        {CKA_DERIVE, &trueValue, sizeof(trueValue)},
        {CKA_ENCRYPT, &falseValue, sizeof(falseValue)},
        {CKA_DECRYPT, &falseValue, sizeof(falseValue)},
        {CKA_TOKEN, &falseValue, sizeof(falseValue)},
        {CKA_VALUE_LEN, &derivedKeyLength, sizeof(derivedKeyLength)}
    };
    CK_ULONG ulDerivedKeyTemplateCount =
        sizeof(derivedKeyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_BYTE derivedKeyValue[48];
    CK_ATTRIBUTE getValueTemplate[] = {
        {CKA_VALUE, derivedKeyValue, sizeof(derivedKeyValue)}
    };
    CK_ULONG ulGetValueTemplateCount =
        sizeof(getValueTemplate) / sizeof(CK_ATTRIBUTE);


    ret = funcList->C_CreateObject(session, baseKeyTemplate,
                                   ulBaseKeyTemplateCount, &hBaseKey);
    CHECK_CKR(ret, "Base key");

    if (ret == CKR_OK) {
        version.major = 2;
        ret = funcList->C_DeriveKey(session, &mechanism, hBaseKey,
                                    derivedKeyTemplate,
                                    ulDerivedKeyTemplateCount, &hDerivedKey);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_INVALID, "Invalid version");
        version.major = 3;
    }


    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mechanism, hBaseKey,
                                    derivedKeyTemplate,
                                    ulDerivedKeyTemplateCount, &hDerivedKey);
        CHECK_CKR(ret, "Derive key");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, hDerivedKey,
                                            getValueTemplate,
                                            ulGetValueTemplateCount);
    }
    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen == ulExpectedMasterSecretLen,
                   ret, "Derived key length mismatch");
    }
    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen != (CK_ULONG)-1, ret,
                   "Get CKA_VALUE");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(derivedKeyValue, expectedMasterSecret,
                           ulExpectedMasterSecretLen) == 0, ret,
                   "Secret compare");
    }

    return ret;
}
#ifdef WOLFPKCS11_NSS
/* Test creating a CKO_NSS_TRUST object and verifying its attributes */
static CK_RV test_nss_trust_object(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS nss_trust_class = CKO_NSS_TRUST;

    /* Values for attributes */
    static byte issuer[] = "CN=PDF Signer,O=wolfSSL,C=US";
    static byte serial_number[] = { 0x02, 0x05, 0x00, 0xC6, 0xA7, 0x91, 0x84 };
    static byte sha1_hash[] = {
        0x00, 0x75, 0x85, 0x74, 0xF9, 0xD2, 0x3D, 0x09,
        0x74, 0x5B, 0x1A, 0x72, 0xBA, 0xA6, 0xCC, 0x15,
        0xF1, 0xD0, 0x7A, 0x36
    };
    static byte md5_hash[] = {
        0x47, 0xC3, 0x68, 0x9D, 0xB0, 0xEA, 0x15, 0x22,
        0xD3, 0xE6, 0xA1, 0x7D, 0x84, 0xA0, 0x8E, 0xEB
    };
    CK_ULONG trust_value = 0xCE534352;
    CK_BBOOL step_up = CK_FALSE;

    /* Template for creating the object */
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_CLASS, &nss_trust_class, sizeof(nss_trust_class) },
        { CKA_ISSUER, issuer, sizeof(issuer)-1 },
        { CKA_SERIAL_NUMBER, serial_number, sizeof(serial_number) },
        { CKA_CERT_SHA1_HASH, sha1_hash, sizeof(sha1_hash) },
        { CKA_CERT_MD5_HASH, md5_hash, sizeof(md5_hash) },
        { CKA_TRUST_SERVER_AUTH, &trust_value, sizeof(trust_value) },
        { CKA_TRUST_CLIENT_AUTH, &trust_value, sizeof(trust_value) },
        { CKA_TRUST_CODE_SIGNING, &trust_value, sizeof(trust_value) },
        { CKA_TRUST_EMAIL_PROTECTION, &trust_value, sizeof(trust_value) },
        { CKA_TRUST_STEP_UP_APPROVED, &step_up, sizeof(step_up) }
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    /* Buffer to retrieve attribute values */
    CK_BYTE buffer[64];
    CK_ATTRIBUTE getAttr;
    CK_OBJECT_CLASS retClass;
    CK_ULONG retTrustValue;
    CK_BBOOL retBool;

    /* Create the NSS_TRUST object */
    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create NSS_TRUST Object");

    if (ret == CKR_OK) {
        /* Verify object class */
        getAttr.type = CKA_CLASS;
        getAttr.pValue = &retClass;
        getAttr.ulValueLen = sizeof(retClass);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object class");
    }
    if (ret == CKR_OK && retClass != CKO_NSS_TRUST) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object class incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify ISSUER attribute */
        getAttr.type = CKA_ISSUER;
        getAttr.pValue = buffer;
        getAttr.ulValueLen = sizeof(buffer);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object issuer");
    }
    if (ret == CKR_OK && (getAttr.ulValueLen != sizeof(issuer)-1 ||
            XMEMCMP(buffer, issuer, sizeof(issuer)-1) != 0)) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object issuer incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify SERIAL_NUMBER attribute */
        getAttr.type = CKA_SERIAL_NUMBER;
        getAttr.pValue = buffer;
        getAttr.ulValueLen = sizeof(buffer);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object serial number");
    }
    if (ret == CKR_OK && (getAttr.ulValueLen != sizeof(serial_number) ||
            XMEMCMP(buffer, serial_number, sizeof(serial_number)) != 0)) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object serial number incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify SHA1_HASH attribute */
        getAttr.type = CKA_CERT_SHA1_HASH;
        getAttr.pValue = buffer;
        getAttr.ulValueLen = sizeof(buffer);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object SHA1 hash");
    }
    if (ret == CKR_OK && (getAttr.ulValueLen != sizeof(sha1_hash) ||
            XMEMCMP(buffer, sha1_hash, sizeof(sha1_hash)) != 0)) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object SHA1 hash incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify MD5_HASH attribute */
        getAttr.type = CKA_CERT_MD5_HASH;
        getAttr.pValue = buffer;
        getAttr.ulValueLen = sizeof(buffer);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object MD5 hash");
    }

    if (ret == CKR_OK && (getAttr.ulValueLen != sizeof(md5_hash) ||
            XMEMCMP(buffer, md5_hash, sizeof(md5_hash)) != 0)) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object MD5 hash incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify TRUST_SERVER_AUTH attribute */
        getAttr.type = CKA_TRUST_SERVER_AUTH;
        getAttr.pValue = &retTrustValue;
        getAttr.ulValueLen = sizeof(retTrustValue);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object server auth");
    }
    if (ret == CKR_OK && retTrustValue != trust_value) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object server auth incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify TRUST_CLIENT_AUTH attribute */
        getAttr.type = CKA_TRUST_CLIENT_AUTH;
        getAttr.pValue = &retTrustValue;
        getAttr.ulValueLen = sizeof(retTrustValue);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object client auth");
    }
    if (ret == CKR_OK && retTrustValue != trust_value) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object client auth incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify TRUST_CODE_SIGNING attribute */
        getAttr.type = CKA_TRUST_CODE_SIGNING;
        getAttr.pValue = &retTrustValue;
        getAttr.ulValueLen = sizeof(retTrustValue);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object code signing");
    }
    if (ret == CKR_OK && retTrustValue != trust_value) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object code signing incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify TRUST_EMAIL_PROTECTION attribute */
        getAttr.type = CKA_TRUST_EMAIL_PROTECTION;
        getAttr.pValue = &retTrustValue;
        getAttr.ulValueLen = sizeof(retTrustValue);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object email protection");
    }
    if (ret == CKR_OK && retTrustValue != trust_value) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object email protection incorrect");
    }

    if (ret == CKR_OK) {
        /* Verify TRUST_STEP_UP_APPROVED attribute */
        getAttr.type = CKA_TRUST_STEP_UP_APPROVED;
        getAttr.pValue = &retBool;
        getAttr.ulValueLen = sizeof(retBool);
        ret = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
        CHECK_CKR(ret, "Get NSS_TRUST Object step up approved");
    }
    if (ret == CKR_OK && retBool != step_up) {
        ret = -1;
        CHECK_CKR(ret, "NSS_TRUST Object step up approved incorrect");
    }

    /* Destroy the object */
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, obj);
        CHECK_CKR(ret, "Destroy NSS_TRUST Object");
    }

    return ret;
}

static CK_RV test_nss_derive_tls12_master_key(void* args) {
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE hBaseKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hDerivedKey = CK_INVALID_HANDLE;

    CK_BYTE preMasterSecret[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };
    CK_ULONG ulPreMasterSecretLen = sizeof(preMasterSecret);

    CK_BYTE sessionHash[] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
    };

    /* Generated using Python scapy.layers.tls.crypto.prf */
    CK_BYTE expectedMasterSecret[] = {
        0xc4, 0x7f, 0xec, 0x16, 0xb4, 0x77, 0xb4, 0xc0,
        0x15, 0x1e, 0x21, 0xb4, 0x5d, 0x18, 0x43, 0xdd,
        0x65, 0xd8, 0x54, 0xaa, 0x32, 0x5e, 0xe6, 0x95,
        0x11, 0xaa, 0x14, 0x53, 0x76, 0xb8, 0x21, 0xf5,
        0x9c, 0x17, 0x63, 0x4e, 0x24, 0xce, 0x14, 0xf7,
        0xe4, 0x3b, 0x71, 0x9f, 0xc5, 0xa2, 0x36, 0xdb
    };
    CK_ULONG ulExpectedMasterSecretLen = sizeof(expectedMasterSecret);

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL trueValue = CK_TRUE;
    CK_BBOOL falseValue = CK_FALSE;

    CK_ATTRIBUTE baseKeyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VALUE, preMasterSecret, ulPreMasterSecretLen},
        {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
        {CKA_EXTRACTABLE, &falseValue, sizeof(falseValue)},
        {CKA_DERIVE, &trueValue, sizeof(trueValue)},
        {CKA_TOKEN, &falseValue, sizeof(falseValue)}
    };
    CK_ULONG ulBaseKeyTemplateCount =
        sizeof(baseKeyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS params;
    params.pSessionHash = sessionHash;
    params.ulSessionHashLen = sizeof(sessionHash);
    /* Version for TLS 1.2 is {3, 3} */
    CK_VERSION version = {3, 3};
    params.pVersion = &version;
    params.prfHashMechanism = CKM_SHA256;
    CK_MECHANISM mechanism = {
        CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE, &params, sizeof(params)
    };

    CK_ULONG derivedKeyLength = 48;
    CK_KEY_TYPE derivedKeyType = CKK_GENERIC_SECRET;

    CK_ATTRIBUTE derivedKeyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &derivedKeyType, sizeof(derivedKeyType)},
        {CKA_SENSITIVE, &falseValue, sizeof(falseValue)},
        {CKA_EXTRACTABLE, &trueValue, sizeof(trueValue)},
        {CKA_DERIVE, &trueValue, sizeof(trueValue)},
        {CKA_ENCRYPT, &falseValue, sizeof(falseValue)},
        {CKA_DECRYPT, &falseValue, sizeof(falseValue)},
        {CKA_TOKEN, &falseValue, sizeof(falseValue)},
        {CKA_VALUE_LEN, &derivedKeyLength, sizeof(derivedKeyLength)}
    };
    CK_ULONG ulDerivedKeyTemplateCount =
        sizeof(derivedKeyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_BYTE derivedKeyValue[48];
    CK_ATTRIBUTE getValueTemplate[] = {
        {CKA_VALUE, derivedKeyValue, sizeof(derivedKeyValue)}
    };
    CK_ULONG ulGetValueTemplateCount =
        sizeof(getValueTemplate) / sizeof(CK_ATTRIBUTE);


    ret = funcList->C_CreateObject(session, baseKeyTemplate,
                                   ulBaseKeyTemplateCount, &hBaseKey);
    CHECK_CKR(ret, "Base key");

    if (ret == CKR_OK) {
        ret = funcList->C_DeriveKey(session, &mechanism, hBaseKey,
                                    derivedKeyTemplate,
                                    ulDerivedKeyTemplateCount, &hDerivedKey);
        CHECK_CKR(ret, "Derive key");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, hDerivedKey,
                                            getValueTemplate,
                                            ulGetValueTemplateCount);
    }
    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen == ulExpectedMasterSecretLen,
                   ret, "Derived key length mismatch");
    }
    if (ret == CKR_OK) {
        CHECK_COND(getValueTemplate[0].ulValueLen != (CK_ULONG)-1, ret,
                   "Get CKA_VALUE");
    }

    if (ret == CKR_OK) {
        CHECK_COND(XMEMCMP(derivedKeyValue, expectedMasterSecret,
                           ulExpectedMasterSecretLen) == 0, ret,
                   "Secret compare");
    }

    return ret;
}
#endif
#endif

static CK_RV pkcs11_lib_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;

    XMEMSET(&args, 0x00, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(NULL);
    CHECK_CKR(ret, "Initialize");

    return ret;
}

static CK_RV pkcs11_init_token(void)
{
    CK_RV ret;
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));

    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "Init Token");

    return ret;
}

static void pkcs11_final(int closeDl)
{
    funcList->C_Finalize(NULL);
    if (closeDl) {
    #ifndef HAVE_PKCS11_STATIC
        dlclose(dlib);
    #endif
    }
}

static CK_RV pkcs11_set_user_pin(int slotId)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slotId, flags, NULL, NULL, &session);
    CHECK_CKR(ret, "Set User PIN - Open Session");
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Set User PIN - Login");
        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(session, userPin, userPinLen);
            CHECK_CKR(ret, "Set User PIN - Init PIN");
        }
        funcList->C_CloseSession(session);
    }

    if (ret != CKR_OK)
        fprintf(stderr, "FAILED: Setting user PIN\n");
    return ret;
}

static CK_RV pkcs11_open_session(int flags, void* args)
{
    CK_SESSION_HANDLE* session = (CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    if (flags & TEST_FLAG_SESSION) {
        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
        CHECK_CKR(ret, "Open Session");
        if (ret == CKR_OK && userPinLen != 0) {
            ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
            CHECK_CKR(ret, "Login");
        }
    }

    return ret;
}

static void pkcs11_close_session(int flags, void* args)
{
    CK_SESSION_HANDLE* session = (CK_SESSION_HANDLE*)args;

    if (flags & TEST_FLAG_SESSION) {
        if (userPinLen != 0)
            funcList->C_Logout(*session);
        funcList->C_CloseSession(*session);
    }
}

/* Test for bug fix in internal.c where bitwise OR was changed to AND
 * This test validates that private objects (CKA_PRIVATE = TRUE) are properly
 * filtered based on login state:
 * - When not logged in: private objects should NOT be found
 * - When logged in: private objects should be found
 */
static CK_RV test_private_object_access(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte keyData[] = { 0x01, 0x02, 0x03, 0x04 };
    static byte id[] = { 0x10, 0x11, 0x12, 0x13 };
    CK_BBOOL isPrivate = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)    },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_VALUE,             keyData,           sizeof(keyData)           },
        { CKA_PRIVATE,           &isPrivate,        sizeof(isPrivate)         },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_ID,                id,                sizeof(id)                },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_ID,                id,                sizeof(id)                },
    };
    CK_ULONG findTmplCnt = sizeof(findTmpl) / sizeof(*findTmpl);
    CK_OBJECT_HANDLE found;
    CK_ULONG count;

    /* Create a private object while logged in (test setup logs us in) */
    ret = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_CKR(ret, "Create Private Object");

    if (ret == CKR_OK) {
        /* Logout to test private object access control */
        ret = funcList->C_Logout(session);
        CHECK_CKR(ret, "Logout for private object test");
    }

    if (ret == CKR_OK) {
        /* Try to find the private object while not logged in - should NOT find it */
        ret = funcList->C_FindObjectsInit(session, findTmpl, findTmplCnt);
        CHECK_CKR(ret, "Find Objects Init - not logged in");
        if (ret == CKR_OK) {
            ret = funcList->C_FindObjects(session, &found, 1, &count);
            CHECK_CKR(ret, "Find Objects - not logged in");
        }
        if (ret == CKR_OK && count != 0) {
            ret = -1;
            CHECK_CKR(ret, "Private object should not be found when not logged in");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_FindObjectsFinal(session);
            CHECK_CKR(ret, "Find Objects Final - not logged in");
        }
    }

    if (ret == CKR_OK) {
        /* Login as user */
        ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login for private object test");
    }

    if (ret == CKR_OK) {
        /* Now try to find the private object while logged in - should find it */
        ret = funcList->C_FindObjectsInit(session, findTmpl, findTmplCnt);
        CHECK_CKR(ret, "Find Objects Init - logged in");
        if (ret == CKR_OK) {
            ret = funcList->C_FindObjects(session, &found, 1, &count);
            CHECK_CKR(ret, "Find Objects - logged in");
        }
        if (ret == CKR_OK && count != 1) {
            ret = -1;
            CHECK_CKR(ret, "Private object should be found when logged in");
        }
        if (ret == CKR_OK && found != obj) {
            ret = -1;
            CHECK_CKR(ret, "Found object should match created object");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_FindObjectsFinal(session);
            CHECK_CKR(ret, "Find Objects Final - logged in");
        }
    }

    if (obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, obj);
    }

    return ret;
}

static TEST_FUNC testFunc[] = {
    PKCS11TEST_FUNC_NO_INIT_DECL(test_get_function_list),
    PKCS11TEST_FUNC_NO_INIT_DECL(test_not_initialized),
    PKCS11TEST_FUNC_NO_TOKEN_DECL(test_no_token_init),
    PKCS11TEST_FUNC_TOKEN_DECL(test_get_info),
    PKCS11TEST_FUNC_TOKEN_DECL(test_slot),
    PKCS11TEST_FUNC_TOKEN_DECL(test_token),
#ifndef WOLFPKCS11_NSS
    PKCS11TEST_FUNC_TOKEN_DECL(test_open_close_session),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_login_logout),
    PKCS11TEST_FUNC_SESS_DECL(test_pin),
    PKCS11TEST_FUNC_SESS_DECL(test_session),
#ifndef NO_SHA256
    PKCS11TEST_FUNC_SESS_DECL(test_op_state_success),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_op_state_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_object),
#if ((defined(WOLFPKCS11_NSS)) && ((WP11_SESSION_CNT_MAX != 1) || \
    (WP11_SESSION_CNT_MIN != 1)))
    PKCS11TEST_FUNC_SESS_DECL(test_cross_session_object),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_attribute),
    PKCS11TEST_FUNC_SESS_DECL(test_attribute_types),
    PKCS11TEST_FUNC_SESS_DECL(test_attribute_get),
    PKCS11TEST_FUNC_SESS_DECL(test_attributes_secret),
#ifndef NO_RSA
    PKCS11TEST_FUNC_SESS_DECL(test_attributes_rsa),
#endif
#ifdef HAVE_ECC
    PKCS11TEST_FUNC_SESS_DECL(test_attributes_ecc),
#endif
#ifndef NO_DH
    PKCS11TEST_FUNC_SESS_DECL(test_attributes_dh),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_find_objects),
    PKCS11TEST_FUNC_SESS_DECL(test_private_object_access),
    PKCS11TEST_FUNC_SESS_DECL(test_encrypt_decrypt),
    PKCS11TEST_FUNC_SESS_DECL(test_digest_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_sign_verify),
    PKCS11TEST_FUNC_SESS_DECL(test_recover),
#ifndef NO_RSA
    PKCS11TEST_FUNC_SESS_DECL(test_verify_recover_pkcs),
    PKCS11TEST_FUNC_SESS_DECL(test_verify_recover_x509),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_encdec_digest),
    PKCS11TEST_FUNC_SESS_DECL(test_encdec_signverify),
    PKCS11TEST_FUNC_SESS_DECL(test_generate_key),
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    PKCS11TEST_FUNC_SESS_DECL(test_generate_key_pair),
#endif
#ifdef HAVE_AES_KEYWRAP
    PKCS11TEST_FUNC_SESS_DECL(test_aes_wrap_unwrap_key),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_wrap_unwrap_pad_key),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_wrap_unwrap_key),
#ifndef NO_DH
    PKCS11TEST_FUNC_SESS_DECL(test_derive_key),
#endif
#ifndef NO_RSA
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_no_modulus),
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_no_public_exponent),
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_fixed_keys_raw),
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_fixed_keys_pkcs15_enc),
#ifndef WC_NO_RSA_OAEP
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_fixed_keys_oaep),
#endif
#ifdef WC_RSA_DIRECT
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_fixed_keys_x_509_sig),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_fixed_keys_pkcs15_sig),
#ifdef WC_RSA_PSS
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_fixed_keys_pss),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_fixed_keys_store_token),
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_x_509_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_pkcs_encdec_fail),
#ifndef WC_NO_RSA_OAEP
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_pkcs_oaep_encdec_fail),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_pkcs_sig_fail),
#ifdef WC_RSA_PSS
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_pkcs_pss_sig_fail),
#endif
#ifdef WOLFSSL_KEY_GEN
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_gen_keys),
    PKCS11TEST_FUNC_SESS_DECL(test_rsa_gen_keys_id),
#endif
#ifndef NO_SHA256
    PKCS11TEST_FUNC_SESS_DECL(test_sha256_rsa_pkcs15),
#endif
#endif /* !NO_RSA */
#ifdef HAVE_ECC
#ifndef WOLFPKCS11_TPM
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_curve),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_key_erase_bug),
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_create_key_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_fixed_keys_ecdh),
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_fixed_keys_ecdsa),
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_gen_keys),
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_gen_keys_id),
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_gen_keys_token),
    PKCS11TEST_FUNC_SESS_DECL(test_ecc_token_keys_ecdsa),
    PKCS11TEST_FUNC_SESS_DECL(test_ecdsa_sig_fail),
#endif /* HAVE_ECC */
#ifndef NO_DH
    PKCS11TEST_FUNC_SESS_DECL(test_dh_fixed_keys),
    PKCS11TEST_FUNC_SESS_DECL(test_dh_gen_keys),
#endif
#ifndef NO_AES
#ifdef HAVE_AES_CBC
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_pad_len_test),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_fixed_key),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_gen_key),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_gen_key_id),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_pad_fixed_key),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_pad_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_pad_gen_key),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cbc_pad_gen_key_id),
#endif
#ifdef HAVE_AESCTR
    PKCS11TEST_FUNC_SESS_DECL(test_aes_ctr_fixed_key),
#endif
#ifdef HAVE_AESGCM
    PKCS11TEST_FUNC_SESS_DECL(test_aes_gcm_fixed_key),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_gcm_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_gcm_gen_key),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_gcm_gen_key_id),
#endif
#ifdef HAVE_AESCCM
    PKCS11TEST_FUNC_SESS_DECL(test_aes_ccm_gen_key),
#endif
#ifdef HAVE_AESCTS
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cts_fixed_key),
#endif
#ifdef HAVE_AESECB
    PKCS11TEST_FUNC_SESS_DECL(test_aes_ecb_gen_key),
    PKCS11TEST_FUNC_SESS_DECL(test_secret_key_check_value),
#endif
#ifdef HAVE_AESCMAC
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cmac),
    PKCS11TEST_FUNC_SESS_DECL(test_aes_cmac_general),
#endif
#endif /* !NO_AES */
#ifndef NOSHA256
    PKCS11TEST_FUNC_SESS_DECL(test_digest),
#endif
#ifndef WOLFSSL_NOSHA3_224
    PKCS11TEST_FUNC_SESS_DECL(test_digest_sha3_224),
#endif
#ifndef WOLFSSL_NOSHA3_256
    PKCS11TEST_FUNC_SESS_DECL(test_digest_sha3_256),
#endif
#ifndef WOLFSSL_NOSHA3_384
    PKCS11TEST_FUNC_SESS_DECL(test_digest_sha3_384),
#endif
#ifndef WOLFSSL_NOSHA3_512
    PKCS11TEST_FUNC_SESS_DECL(test_digest_sha3_512),
#endif
#ifndef NO_HMAC
#ifndef NO_MD5
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_md5),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_md5_fail),
#endif
#ifndef NO_SHA
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha1),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha1_fail),
#endif
#ifdef WOLFSSL_SHA224
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha224),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha224_fail),
#endif
#ifndef NO_SHA256
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha256),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha256_fail),
#endif
#ifdef WOLFSSL_SHA384
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha384),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha384_fail),
#endif
#ifdef WOLFSSL_SHA512
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha512),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha512_fail),
#endif
#ifndef WOLFSSL_NOSHA3_224
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha3_224),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha3_224_fail),
#endif
#ifndef WOLFSSL_NOSHA3_256
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha3_256),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha3_256_fail),
#endif
#ifndef WOLFSSL_NOSHA3_384
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha3_384),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha3_384_fail),
#endif
#ifndef WOLFSSL_NOSHA3_512
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha3_512),
    PKCS11TEST_FUNC_SESS_DECL(test_hmac_sha3_512_fail),
#endif
#endif
#ifdef WOLFPKCS11_HKDF
    PKCS11TEST_FUNC_SESS_DECL(test_hkdf_derive_extract_then_expand_salt_data),
    PKCS11TEST_FUNC_SESS_DECL(test_hkdf_derive_extract_with_expand_salt_data),
    PKCS11TEST_FUNC_SESS_DECL(test_hkdf_derive_expand_with_extract_null_salt),
    PKCS11TEST_FUNC_SESS_DECL(test_hkdf_derive_extract_with_expand_salt_key),
    PKCS11TEST_FUNC_SESS_DECL(test_hkdf_gen_key),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_tls_mac_tls_prf),
#ifndef NO_SHA256
    PKCS11TEST_FUNC_SESS_DECL(test_tls_mac_sha256),
#endif
#ifdef WOLFSSL_SHA384
    PKCS11TEST_FUNC_SESS_DECL(test_tls_mac_sha384),
#endif
#ifdef WOLFSSL_SHA512
    PKCS11TEST_FUNC_SESS_DECL(test_tls_mac_sha512),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_random),
    PKCS11TEST_FUNC_SESS_DECL(test_x509),
#ifndef NO_RSA
    PKCS11TEST_FUNC_SESS_DECL(test_x509_cert_find_fail),
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_x509_find_by_type),
#ifdef WOLFSSL_HAVE_PRF
    PKCS11TEST_FUNC_SESS_DECL(test_derive_tls12_master_key_dh),
    PKCS11TEST_FUNC_SESS_DECL(test_derive_tls12_key_and_mac),
    PKCS11TEST_FUNC_SESS_DECL(test_derive_tls12_master_key),
#ifdef WOLFPKCS11_NSS
    PKCS11TEST_FUNC_SESS_DECL(test_nss_trust_object),
    PKCS11TEST_FUNC_SESS_DECL(test_nss_trust_object_token_storage),
    PKCS11TEST_FUNC_SESS_DECL(test_nss_derive_tls12_master_key),
#endif
#endif
    PKCS11TEST_FUNC_SESS_DECL(test_x509_check_value),
};
static int testFuncCnt = sizeof(testFunc) / sizeof(*testFunc);

static CK_RV pkcs11_test(int slotId, int setPin, int onlySet, int closeDl)
{
    CK_RV ret;
    int i;
    int attempted = 0, passed = 0;
    int inited = 0;

    /* Set it global. */
    slot = slotId;

    /* Do tests before library initialization. */
    ret = run_tests(testFunc, testFuncCnt, onlySet, 0);

    /* Initialize library. */
    if (ret == CKR_OK)
        ret = pkcs11_lib_init();

    /* Do tests after library initialization but without SO PIN. */
    if (ret == CKR_OK) {
        inited = 1;
        ret = run_tests(testFunc, testFuncCnt, onlySet, TEST_FLAG_INIT);
    }

    if (ret == CKR_OK)
        ret = pkcs11_init_token();

    /* Do tests after library initialization but without session. */
    if (ret == CKR_OK) {
        ret = run_tests(testFunc, testFuncCnt, onlySet, TEST_FLAG_INIT |
                                                               TEST_FLAG_TOKEN);
    }

    /* Set user PIN. */
    if (ret == CKR_OK) {
        if (setPin)
            ret = pkcs11_set_user_pin(slotId);
    }
    /* Do tests with session. */
    if (ret == CKR_OK) {
        ret = run_tests(testFunc, testFuncCnt, onlySet, TEST_FLAG_INIT |
                                           TEST_FLAG_TOKEN | TEST_FLAG_SESSION);
    }

    /* Check for pass and fail. */
    for (i = 0; i < testFuncCnt; i++) {
        if (testFunc[i].attempted) {
            attempted++;
            if (testFunc[i].ret != CKR_OK) {
#ifdef DEBUG_WOLFPKCS11
                if (ret == CKR_OK)
                    fprintf(stderr, "\nFAILED tests:\n");
                fprintf(stderr, "%d: %s\n", i + 1, testFunc[i].name);
#endif
                ret = testFunc[i].ret;
            }
            else
                passed++;
        }
    }
    fprintf(stderr, "Result: %d / %d\n", passed, attempted);
    if (ret == CKR_OK)
        fprintf(stderr, "Success\n");
    else
        fprintf(stderr, "Failures\n");

    if (inited)
        pkcs11_final(closeDl);

    return ret;
}


static CK_RV pkcs11_init(const char* library)
{
    CK_RV ret = CKR_OK;
#ifndef HAVE_PKCS11_STATIC
    void* func;

    dlib = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        ret = -1;
    }

    if (ret == CKR_OK) {
        func = (void*)(CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
        if (func == NULL) {
            fprintf(stderr, "Failed to get function list function\n");
            ret = -1;
        }
    }

    if (ret == CKR_OK) {
        ret = ((CK_C_GetFunctionList)func)(&funcList);
        CHECK_CKR(ret, "Get Function List call");
    }

    if (ret != CKR_OK && dlib != NULL)
        dlclose(dlib);

#else
    ret = C_GetFunctionList(&funcList);
    (void)library;
#endif

    return ret;
}

/* Display the usage options of the benchmark program. */
static void Usage(void)
{
    printf("pkcs11test\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
    printf("-token <string>    Name of token\n");
    printf("-soPin <string>    Security Officer PIN\n");
    printf("-userPin <string>  User PIN\n");
    printf("-no-close          Do not close the PKCS#11 library before exit\n");
    printf("-list              List all tests that can be run\n");
    UnitUsage();
    printf("<num>              Test case number to try\n");
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int pkcs11test_test(int argc, char* argv[])
#endif
{
    int ret;
    CK_RV rv;
    int slotId = WOLFPKCS11_DLL_SLOT;
    const char* libName = WOLFPKCS11_DLL_FILENAME;
    int setPin = 1;
    int testCase;
    int onlySet = 0;
    int closeDl = 1;
    int i;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_NO_STORE", "1", 1);
#endif

    argc--;
    argv++;
    while (argc > 0) {
        if (string_matches(*argv, "-?")) {
            Usage();
            return 0;
        }
        UNIT_PARSE_ARGS(argc, argv)
        else if (string_matches(*argv, "-lib")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Library name not supplied\n");
                return 1;
            }
            libName = *argv;
        }
        else if (string_matches(*argv, "-case")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Test case number not supplied\n");
                return 1;
            }
            testCase = atoi(*argv);
            if (testCase <= 0 || testCase > testFuncCnt) {
                fprintf(stderr, "Test case out of range: %s\n", *argv);
                return 1;
            }
            testFunc[testCase - 1].run = 1;
            onlySet = 1;
        }
        else if (string_matches(*argv, "-token")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Token name not supplied\n");
                return 1;
            }
            tokenName = *argv;
        }
        else if (string_matches(*argv, "-soPin")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "SO PIN not supplied\n");
                return 1;
            }
            soPin = (byte*)*argv;
            soPinLen = (int)XSTRLEN((const char*)soPin);
        }
        else if (string_matches(*argv, "-userPin")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "User PIN not supplied\n");
                return 1;
            }
            userPin = (byte*)*argv;
        }
        else if (string_matches(*argv, "-no-close")) {
            closeDl = 0;
        }
        else if (string_matches(*argv, "-list")) {
            for (i = 0; i < testFuncCnt; i++)
                fprintf(stderr, "%d: %s\n", i + 1, testFunc[i].name);
            return 0;
        }
        else if (isdigit((int)argv[0][0])) {
            testCase = atoi(*argv);
            if (testCase <= 0 || testCase > testFuncCnt) {
                fprintf(stderr, "Test case out of range: %s\n", *argv);
                return 1;
            }
            testFunc[testCase - 1].run = 1;
            onlySet = 1;
        }
        else {
            for (i = 0; i < testFuncCnt; i++) {
                if (string_matches(*argv, testFunc[i].name)) {
                    testFunc[i].run = 1;
                    onlySet = 1;
                    break;
                }
            }
            if (i == testFuncCnt) {
                fprintf(stderr, "Test case name doesn't match: %s\n", *argv);
                return 1;
            }
        }

        argc--;
        argv++;
    }

    userPinLen = (int)XSTRLEN((const char*)userPin);

    rv = pkcs11_init(libName);
    if (rv == CKR_OK) {
        rv = pkcs11_test(slotId, setPin, onlySet, closeDl);
    }

    if (rv == CKR_OK)
        ret = 0;
    else
        ret = 1;
    return ret;
}
