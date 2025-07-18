/* add_cert.c
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

#if !defined(WOLFPKCS11_NO_STORE) && !defined(NO_FILESYSTEM)

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
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = WOLFPKCS11_DLL_SLOT;

static byte* userPin = (byte*)"wolfpkcs11-test";
static CK_ULONG userPinLen;

static CK_OBJECT_CLASS certClass    = CKO_CERTIFICATE;
static CK_BBOOL ckTrue  = CK_TRUE;
CK_CERTIFICATE_TYPE certType = CKC_X_509;


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
    if (userPinLen != 0)
        funcList->C_Logout(session);
    funcList->C_CloseSession(session);

    funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    dlclose(dlib);
#endif
}


static CK_RV load_cert(char* filename, unsigned char **certData,
                       CK_ULONG *certDataLen)
{
    int ret = 0;
    unsigned char *buffer = NULL;
    int len;
    XFILE file;

    file = XFOPEN(filename, "r");
    if (file == XBADFILE) {
        fprintf(stderr, "Unable to open file: %s\n", filename);
        ret = 1;
    }
    if (ret == 0) {
        XFSEEK(file, 0, XSEEK_END);
        len = (int)XFTELL(file);
        if (len == 0) {
            fprintf(stderr, "File: %s is empty\n", filename);
            ret = 1;
        }
    }
    if (ret == 0) {
        if (XFSEEK(file, 0, XSEEK_SET) != 0) {
            fprintf(stderr, "Error seeking file: %s\n", filename);
            ret = 1;
        }
    }
    if (ret == 0) {
        buffer = (unsigned char *)XMALLOC(len + 1, NULL, DYNAMIC_TYPE_FILE);
        if (buffer == NULL) {
            fprintf(stderr, "Malloc error on %d bytes\n", len);
            ret = 1;
        }
    }
    if (ret == 0) {
        len = (int)XFREAD(buffer, 1, len, file);
        if (len <= 0) {
            fprintf(stderr, ": %s\n", filename);
            ret = 1;
        }

        *certData = buffer;
        *certDataLen = (CK_ULONG)len;
        buffer = NULL;
    }

    if (file != XBADFILE) {
        XFCLOSE(file);
    }
    if (buffer != NULL) {
        XFREE(buffer, NULL, DYNAMIC_TYPE_FILE);
    }

    return ret;
}

static CK_RV pkcs11_add_cert(CK_SESSION_HANDLE session,
    unsigned char* privId, CK_ULONG privIdLen, char *label,
    unsigned char *certData, CK_ULONG certDataLen)
{
    CK_RV ret;
    CK_ATTRIBUTE certTmpl[6] = {
        { CKA_CLASS,             &certClass,        sizeof(certClass)         },
        { CKA_CERTIFICATE_TYPE,  &certType,         sizeof(certType)          },
        { CKA_VALUE,             certData,          certDataLen               },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
    };
    CK_ULONG cnt = 4;
    CK_OBJECT_HANDLE obj;

    if (privId != NULL && privIdLen > 0) {
        certTmpl[cnt].type = CKA_ID;
        certTmpl[cnt].pValue = privId;
        certTmpl[cnt].ulValueLen = privIdLen;
        cnt++;
    }

    if (label != NULL) {
        certTmpl[cnt].type = CKA_LABEL;
        certTmpl[cnt].pValue = label;
        certTmpl[cnt].ulValueLen = (CK_ULONG)(XSTRLEN(label));
        cnt++;
    }

    ret = funcList->C_CreateObject(session, certTmpl, cnt, &obj);
    CHECK_CKR(ret, "CreateObject Certificate");

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
    printf("add_cert\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
    printf("-userPin <string>  User PIN\n");
    printf("-privId <string>   Certificate identifier\n");
    printf("-label <string>    Certificate label\n");
    printf("-cert <file>       Certificate file in DER format\n");
}


#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int add_cert(int argc, char* argv[])
#endif
{
    int ret;
    CK_RV rv;
    const char* libName = WOLFPKCS11_DLL_FILENAME;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    unsigned char* privId = NULL;
    CK_ULONG privIdLen = 0;
    char *label = NULL;
    unsigned char *certData = NULL;
    CK_ULONG certDataLen = 0;
    char *filename = NULL;

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
                fprintf(stderr, "Certificate identifier not supplied\n");
                return 1;
            }
            privId = (unsigned char*)*argv;
            privIdLen = (int)strlen(*argv);
        }
        else if (string_matches(*argv, "-label")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Label not supplied\n");
                return 1;
            }
            label = (char*)*argv;
        }
        else if (string_matches(*argv, "-cert")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Certificate filename not supplied\n");
                return 1;
            }
            filename = (char*)*argv;
        }
        else {
            fprintf(stderr, "Unrecognized command line argument\n  %s\n",
                argv[0]);
            return 1;
        }

        argc--;
        argv++;
    }

    if (filename == NULL) {
        fprintf(stderr, "Must specify certificate filename!\n");
        return 1;
    }

    userPinLen = (int)XSTRLEN((const char*)userPin);

    rv = load_cert(filename, &certData, &certDataLen);
    if (rv != 0) {
        return 1;
    }

    rv = pkcs11_init(libName, &session);
    if (rv == CKR_OK) {
        rv = pkcs11_add_cert(session, privId, privIdLen, label,
                             certData, certDataLen);
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
int add_cert(int argc, char* argv[])
#endif
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "Store disabled\n");
    return 0;
}

#endif /* !WOLFPKCS11_NO_STORE && !NO_FILESYSTEM */
