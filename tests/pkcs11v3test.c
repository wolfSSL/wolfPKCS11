/* pkcs11v3test.c - unit tests
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


#ifdef WOLFPKCS11_PKCS11_V3_0

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;

#ifdef DEBUG_WOLFPKCS11
#ifndef HAVE_PKCS11_STATIC
void (*wolfPKCS11_Debugging_On_fp)(void) = NULL;
void (*wolfPKCS11_Debugging_Off_fp)(void) = NULL;
#endif
#endif
static int slot = 0;
static const char* tokenName = "wolfpkcs11";

/* FIPS requires pin to be at least 14 characters, since it is used for
 * the HMAC key */
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen;

static CK_RV test_get_interface_list(void* args)
{
    CK_RV ret = CKR_OK;
    CK_ULONG count = 0;
    CK_INTERFACE* interfaces = NULL;
#ifndef HAVE_PKCS11_STATIC
    void* func;
#endif

#ifdef WOLFPKCS11_PKCS11_V3_2
    static const CK_ULONG interfaceCount = 3;
#else
    static const CK_ULONG interfaceCount = 2;
#endif

    (void)args;

#ifndef HAVE_PKCS11_STATIC
    func = (void*)(CK_C_GetInterfaceList)dlsym(dlib, "C_GetInterfaceList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get interface list function\n");
        ret = -1;
    }

    if (ret == CKR_OK) {
        ret = ((CK_C_GetInterfaceList)func)(NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface List");
    }
    if (ret == CKR_OK) {
        ret = ((CK_C_GetInterfaceList)func)(NULL, &count);
        CHECK_CKR(ret, "Get Interface List");
        if (count != interfaceCount) {
            fprintf(stderr, "Expected %ld interfaces, got %ld\n",
                    interfaceCount, count);
            ret = -1;
        }
    }
#else
    if (ret == CKR_OK) {
        ret = C_GetInterfaceList(NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface List");
    }
    if (ret == CKR_OK) {
        ret = C_GetInterfaceList(NULL, &count);
        CHECK_CKR(ret, "Get Interface List");
        if (count != interfaceCount) {
            fprintf(stderr, "Expected %ld interfaces, got %ld\n",
                    interfaceCount, count);
            ret = -1;
        }
    }
#endif

    if (ret == CKR_OK) {
        interfaces = (CK_INTERFACE*)malloc(interfaceCount *
                                                          sizeof(CK_INTERFACE));
        if (interfaces == NULL) {
            fprintf(stderr, "Failed to allocate memory for interfaces\n");
            ret = -1;
        }
    }

#ifndef HAVE_PKCS11_STATIC
    if (ret == CKR_OK) {
        count = 1;
        ret = ((CK_C_GetInterfaceList)func)(interfaces, &count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "Get Interface List");
    }
    if (ret == CKR_OK) {
        count = interfaceCount;
        ret = ((CK_C_GetInterfaceList)func)(interfaces, &count);
        CHECK_CKR(ret, "Get Interface List");
    }
#else
    if (ret == CKR_OK) {
        count = 1;
        ret = C_GetInterfaceList(interfaces, &count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "Get Interface List");
    }
    if (ret == CKR_OK) {
        count = interfaceCount;
        ret = C_GetInterfaceList(interfaces, &count);
        CHECK_CKR(ret, "Get Interface List");
    }
#endif

    if (interfaces != NULL) {
        free(interfaces);
    }
    return ret;
}

static CK_RV test_get_interface(void* args)
{
    CK_RV ret = CKR_OK;
    CK_INTERFACE* interface = NULL;
    CK_VERSION version;
    CK_FLAGS flags = 0;
    CK_UTF8CHAR_PTR interfaceName = NULL;
#ifndef HAVE_PKCS11_STATIC
    void* func;
#endif

    (void)args;

#ifndef HAVE_PKCS11_STATIC
    func = (void*)(CK_C_GetInterface)dlsym(dlib, "C_GetInterface");
    if (func == NULL) {
        fprintf(stderr, "Failed to get interface function\n");
        ret = -1;
    }
    if (ret == CKR_OK) {
        ret = ((CK_C_GetInterface)func)(interfaceName, NULL, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        ret = ((CK_C_GetInterface)func)(interfaceName, NULL, &interface, 0);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        interfaceName = (CK_UTF8CHAR_PTR)"FAIL";
        ret = ((CK_C_GetInterface)func)(interfaceName, NULL, &interface, flags);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        interfaceName = (CK_UTF8CHAR_PTR)"PKCS 11";
        ret = ((CK_C_GetInterface)func)(interfaceName, NULL, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 40;
        ret = ((CK_C_GetInterface)func)(interfaceName, &version, &interface,
                                        flags);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 20;
        ret = ((CK_C_GetInterface)func)(interfaceName, &version, &interface,
                                        flags);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 0;
        ret = ((CK_C_GetInterface)func)(interfaceName, &version, &interface,
                                        flags);
        CHECK_CKR(ret, "Get Interface");
    }
#ifdef WOLFPKCS11_PKCS11_V3_2
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 2;
        ret = ((CK_C_GetInterface)func)(interfaceName, &version, &interface,
                                        flags);
        CHECK_CKR(ret, "Get Interface");
    }
#endif /* WOLFPKCS11_PKCS11_V3_2 */
#else
    if (ret == CKR_OK) {
        ret = C_GetInterface(interfaceName, NULL, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        ret = C_GetInterface(interfaceName, NULL, &interface, 0);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        interfaceName = (CK_UTF8CHAR_PTR)"FAIL";
        ret = C_GetInterface(interfaceName, NULL, &interface, flags);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        interfaceName = (CK_UTF8CHAR_PTR)"PKCS 11";
        ret = C_GetInterface(interfaceName, NULL, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 40;
        ret = C_GetInterface(interfaceName, &version, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 20;
        ret = C_GetInterface(interfaceName, &version, &interface, flags);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 0;
        ret = C_GetInterface(interfaceName, &version, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
#ifdef WOLFPKCS11_PKCS11_V3_2
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 2;
        ret = C_GetInterface(interfaceName, &version, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
#endif /* WOLFPKCS11_PKCS11_V3_2 */
#endif /* HAVE_PKCS11_STATIC */

    funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;
    if (funcList == NULL) {
        fprintf(stderr, "Failed to get function list\n");
        ret = -1;
    }
    return ret;
}

static CK_RV test_get_info(void* args)
{
    CK_RV ret = CKR_OK;
    CK_INFO info;
    CK_VERSION version;
    CK_INTERFACE* interface = NULL;
#ifndef HAVE_PKCS11_STATIC
    void* func;
#endif

    (void)args;

#ifndef HAVE_PKCS11_STATIC
    func = (void*)(CK_C_GetInterface)dlsym(dlib, "C_GetInterface");
    if (func == NULL) {
        fprintf(stderr, "Failed to get interface function\n");
        ret = -1;
    }
#endif
    /* Load V2.40 interface */
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 40;
#ifndef HAVE_PKCS11_STATIC
        ret = ((CK_C_GetInterface)func)((CK_UTF8CHAR_PTR)"PKCS 11", &version,
                                        &interface, (CK_FLAGS)0);
#else
        ret = C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version, &interface,
                             (CK_FLAGS)0);
#endif
        CHECK_CKR(ret, "Get Interface");
    }

    /* Check Get Info */
    if (ret == CKR_OK) {
        funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;
        ret = funcList->C_GetInfo(NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Info no pointer");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }
    if (ret == CKR_OK) {
        if (info.cryptokiVersion.major != 2 ||
            info.cryptokiVersion.minor != 40) {
            fprintf(stderr, "Expected version 2.40, got %d.%d\n",
                    info.cryptokiVersion.major, info.cryptokiVersion.minor);
            ret = -1;
        }
    }

    /* Load V3.0 interface */
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 0;
#ifndef HAVE_PKCS11_STATIC
        ret = ((CK_C_GetInterface)func)((CK_UTF8CHAR_PTR)"PKCS 11", &version,
                                        &interface, (CK_FLAGS)0);
#else
        ret = C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version, &interface,
                             (CK_FLAGS)0);
#endif
        CHECK_CKR(ret, "Get Interface");
    }

    /* Check Get Info */
    if (ret == CKR_OK) {
        funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;
        ret = funcList->C_GetInfo(NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Info no pointer");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }
    if (ret == CKR_OK) {
        if (info.cryptokiVersion.major != 3 ||
            info.cryptokiVersion.minor != 0) {
            fprintf(stderr, "Expected version 3.0, got %d.%d\n",
                    info.cryptokiVersion.major, info.cryptokiVersion.minor);
            ret = -1;
        }
    }

#ifdef WOLFPKCS11_PKCS11_V3_2
    /* Load V3.2 interface */
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 2;
#ifndef HAVE_PKCS11_STATIC
        ret = ((CK_C_GetInterface)func)((CK_UTF8CHAR_PTR)"PKCS 11", &version,
                                        &interface, (CK_FLAGS)0);
#else
        ret = C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version, &interface,
                             (CK_FLAGS)0);
#endif
        CHECK_CKR(ret, "Get Interface");
    }

    if (ret == CKR_OK) {
        funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;
        ret = funcList->C_GetInfo(NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Info no pointer");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }
    if (ret == CKR_OK) {
        if (info.cryptokiVersion.major != 3 ||
            info.cryptokiVersion.minor != 2) {
            fprintf(stderr, "Expected version 3.2, got %d.%d\n",
                    info.cryptokiVersion.major, info.cryptokiVersion.minor);
            ret = -1;
        }
    }
#endif

    return ret;
}

static CK_RV test_function_not_supported(void* args)
{
    CK_RV ret = CKR_OK;
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
#ifdef WOLFPKCS11_PKCS11_V3_2
    CK_FUNCTION_LIST_3_2* funcListExt = (CK_FUNCTION_LIST_3_2*)funcList;
#else
    CK_FUNCTION_LIST_3_0* funcListExt = (CK_FUNCTION_LIST_3_0*)funcList;
#endif

    if (ret == CKR_OK) {
        ret = funcListExt->C_SessionCancel(session, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "SessionCancel");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageEncryptInit(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageEncryptInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncryptMessage(session, NULL, 0, NULL, 0, NULL, 0,
                                            NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "EncryptMessage");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncryptMessageBegin(session, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "EncryptMessageBegin");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncryptMessageNext(session, NULL, 0, NULL, 0, NULL,
                                                0, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "EncryptMessageNext");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageEncryptFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageEncryptFinal");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageDecryptInit(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageDecryptInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecryptMessage(session, NULL, 0, NULL, 0, NULL, 0,
                                            NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "DecryptMessage");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecryptMessageBegin(session, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "DecryptMessageBegin");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecryptMessageNext(session, NULL, 0, NULL, 0, NULL,
                                                0, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "DecryptMessageNext");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageDecryptFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageDecryptFinal");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageSignInit(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageSignInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_SignMessage(session, NULL, 0, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "SignMessage");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_SignMessageBegin(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "SignMessageBegin");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_SignMessageNext(session, NULL, 0, NULL, 0,
                                             NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "SignMessageNext");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageSignFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageSignFinal");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageVerifyInit(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageVerifyInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifyMessage(session, NULL, 0, NULL, 0,
                                           NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifyMessage");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifyMessageBegin(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifyMessageBegin");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifyMessageNext(session, NULL, 0, NULL, 0,
                                               NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifyMessageNext");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageVerifyFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageVerifyFinal");
    }

#ifdef WOLFPKCS11_PKCS11_V3_2
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, NULL, 0, NULL, 0, NULL,
                                            NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "EncapsulateKey");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, NULL, 0, NULL, 0, NULL,
                                            0, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "DecapsulateKey");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifySignatureInit(session, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifySignatureInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifySignature(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifySignature");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifySignatureUpdate(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED,
                       "VerifySignatureUpdate");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifySignatureFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifySignatureFinal");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_GetSessionValidationFlags(session, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED,
                       "GetSessionValidationFlags");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_AsyncComplete(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "AsyncComplete");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_AsyncGetID(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "AsyncGetID");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_AsyncJoin(session, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "AsyncJoin");
    }
#endif

    return ret;
}

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
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
    }
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

static TEST_FUNC testFunc[] = {
    PKCS11TEST_FUNC_NO_INIT_DECL(test_get_interface_list),
    PKCS11TEST_FUNC_NO_INIT_DECL(test_get_interface),
    PKCS11TEST_FUNC_TOKEN_DECL(test_get_info),
    PKCS11TEST_FUNC_SESS_DECL(test_function_not_supported),
};
static int testFuncCnt = sizeof(testFunc) / sizeof(*testFunc);

static CK_RV pkcs11_test(int slotId, int setPin, int onlySet, int closeDl)
{
    CK_RV ret;
    int i;
    int attempted = 0, passed = 0, skipped = 0;
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
            if (testFunc[i].ret == CKR_SKIPPED) {
                skipped++;
            }
            else if (testFunc[i].ret != CKR_OK) {
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
    fprintf(stderr, "Result: attempted: %d, passed: %d", attempted, passed);
    if (skipped != 0) {
        fprintf(stderr, ", skipped %d", skipped);
    }
    fprintf(stderr, "\n");
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

    (void) library;

#ifndef HAVE_PKCS11_STATIC
    dlib = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        ret = -1;
    }

#ifdef DEBUG_WOLFPKCS11
    wolfPKCS11_Debugging_On_fp = (void (*)(void))dlsym(dlib,
                                                    "wolfPKCS11_Debugging_On");
    wolfPKCS11_Debugging_Off_fp = (void (*)(void))dlsym(dlib,
                                                "wolfPKCS11_Debugging_Off");
    /* These functions are optional, so don't fail if they're not found */
#endif

#endif

    return ret;
}

#endif /* WOLFPKCS11_PKCS11_V3_0 */

/* Display the usage options of the benchmark program. */
static void Usage(void)
{
    printf("pkcs11v3test\n");
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
int pkcs11v3test_test(int argc, char* argv[])
#endif
{
#ifdef WOLFPKCS11_PKCS11_V3_0
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
    XSETENV("WOLFPKCS11_TOKEN_PATH", "./store/pkcs11v3test", 1);
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
#else
    (void)argc;
    (void)argv;
    fprintf(stdout, "%s: PKCS#11 v3.0 not compiled in!\n", argv[0]);
    return 0;
#endif /* WOLFPKCS11_PKCS11_V3_0 */
}
