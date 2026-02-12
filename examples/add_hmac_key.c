/* add_hmac_key.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/types.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#ifndef WOLFPKCS11_NO_STORE

#ifdef DEBUG_WOLFPKCS11
    #define CHECK_CKR(rv, op)                       \
        fprintf(stderr, "%s: %ld\n", op, rv)
#else
    #define CHECK_CKR(rv, op)                       \
        if (ret != CKR_OK)                          \
            fprintf(stderr, "%s: %ld\n", op, rv)
#endif


/* DLL Location and slot */
#ifndef WOLFPKCS11_DLL_FILENAME
    #ifdef __MACH__
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
    #else
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
    #endif
#endif
#ifndef WOLFPKCS11_DLL_SLOT
    #define WOLFPKCS11_DLL_SLOT 1
#endif


#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList = NULL;
static CK_SLOT_ID slot = WOLFPKCS11_DLL_SLOT;

static byte* userPin = (byte*)"wolfpkcs11-test";
static CK_ULONG userPinLen;


static CK_RV pkcs11_init(const char* library, CK_SESSION_HANDLE* session)
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

    if (ret == CKR_OK) {
        ret = funcList->C_Initialize(NULL);
        CHECK_CKR(ret, "Initialize");
    }

    if (ret == CKR_OK) {
        CK_FLAGS sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
        CHECK_CKR(ret, "Open Session");
        if (ret == CKR_OK && userPinLen != 0) {
            ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
            CHECK_CKR(ret, "Login");
        }
    }

    return ret;
}


static void pkcs11_final(CK_SESSION_HANDLE session)
{
    if (funcList != NULL) {
        if (userPinLen != 0)
            funcList->C_Logout(session);
        funcList->C_CloseSession(session);
        funcList->C_Finalize(NULL);
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
    }
#endif
}


static CK_OBJECT_CLASS secretKeyClass    = CKO_SECRET_KEY;
static CK_BBOOL ckTrue  = CK_TRUE;
static CK_KEY_TYPE genericKeyType  = CKK_GENERIC_SECRET;

static unsigned char hmac_256_key[] = {
    0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
    0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0,
    0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4,
    0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
};

static CK_RV pkcs11_add_hmac_key(CK_SESSION_HANDLE session,
    unsigned char* privId, CK_ULONG privIdLen)
{
    CK_RV ret;
    CK_ATTRIBUTE hmac_256_secret_key[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)    },
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
        { CKA_SIGN,              &ckTrue,           sizeof(ckTrue)            },
        { CKA_VERIFY,            &ckTrue,           sizeof(ckTrue)            },
        { CKA_VALUE,             hmac_256_key,      sizeof(hmac_256_key)      },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_ID,                privId,            privIdLen                 },
    };
    CK_ULONG cnt = sizeof(hmac_256_secret_key)/sizeof(*hmac_256_secret_key);
    CK_OBJECT_HANDLE obj;

    if (privId == NULL)
        cnt -= 2;

    ret = funcList->C_CreateObject(session, hmac_256_secret_key, cnt, &obj);
    CHECK_CKR(ret, "CreateObject HMAC 256-bit key");

    return ret;
}


/* Match the command line argument with the string.
 *
 * arg  Command line argument.
 * str  String to check for.
 * return 1 if the command line argument matches the string, 0 otherwise.
 */
static int string_matches(const char* arg, const char* str)
{
    int len = (int)XSTRLEN(str) + 1;
    return XSTRNCMP(arg, str, len) == 0;
}


/* Display the usage options of the benchmark program. */
static void Usage(void)
{
    printf("add_hmac_key\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
    printf("-userPin <string>  User PIN\n");
    printf("-privId <string>   Private key identifier\n");
}


#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int add_hmac_key(int argc, char* argv[])
#endif
{
    int ret;
    CK_RV rv;
    const char* libName = WOLFPKCS11_DLL_FILENAME;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    unsigned char* privId = NULL;
    CK_ULONG privIdLen = 0;

#ifndef WOLFPKCS11_NO_ENV
    if (!XGETENV("WOLFPKCS11_TOKEN_PATH")) {
        XSETENV("WOLFPKCS11_TOKEN_PATH", "./store", 1);
    }
#endif

    argc--;
    argv++;
    while (argc > 0) {
        if (string_matches(*argv, "-?")) {
            Usage();
            return 0;
        }
        else if (string_matches(*argv, "-lib")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Library name not supplied\n");
                return 1;
            }
            libName = *argv;
        }
        else if (string_matches(*argv, "-slot")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Slot number not supplied\n");
                return 1;
            }
            slot = atoi(*argv);
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
        else if (string_matches(*argv, "-privId")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Private key identifier not supplied\n");
                return 1;
            }
            privId = (unsigned char*)*argv;
            privIdLen = (int)strlen(*argv);
        }
        else {
            fprintf(stderr, "Unrecognized command line argument\n  %s\n",
                argv[0]);
            return 1;
        }

        argc--;
        argv++;
    }

    userPinLen = (int)XSTRLEN((const char*)userPin);

    rv = pkcs11_init(libName, &session);
    if (rv == CKR_OK) {
        rv = pkcs11_add_hmac_key(session, privId, privIdLen);
    }
    pkcs11_final(session);

    if (rv == CKR_OK)
        ret = 0;
    else
        ret = 1;
    return ret;
}

#else

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int add_hmac_key(int argc, char* argv[])
#endif
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "Store disabled\n");
    return 0;
}

#endif

