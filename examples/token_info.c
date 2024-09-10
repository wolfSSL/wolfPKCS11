/* token_info.c
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


/* Load and initialize PKCS#11 library by name.
 *
 * library  Name of library file.
 * return CKR_OK on success, other value on failure.
 */
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

    if (ret == CKR_OK) {
        ret = funcList->C_Initialize(NULL);
        CHECK_CKR(ret, "Initialize");
    }

    return ret;
}


/* Finalize and close PKCS#11 library.
 */
static void pkcs11_final(void)
{
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
    }
#endif
}

/* Retrieve the token information and display as text.
 *
 * return CKR_OK on success, other value on failure.
 */
static CK_RV pkcs11_token_info(void)
{
    CK_RV ret = CKR_OK;
    CK_TOKEN_INFO tokenInfo;

    ret = funcList->C_GetTokenInfo(slot, &tokenInfo);
    CHECK_CKR(ret, "Get Token info");

    if (ret == CKR_OK) {
        printf("Label: %.32s\n", tokenInfo.label);
        printf("Serial: %.16s\n", tokenInfo.serialNumber);
        printf("UTC Time: %.14s\n", tokenInfo.utcTime);
        printf("Flags:\n");
        if (tokenInfo.flags & CKF_SO_PIN_COUNT_LOW) {
            printf("  SO PIN count low\n");
        }
        if (tokenInfo.flags & CKF_SO_PIN_FINAL_TRY) {
            printf("  SO PIN final try\n");
        }
        if (tokenInfo.flags & CKF_SO_PIN_LOCKED) {
            printf("  SO PIN locked\n");
        }
        if (tokenInfo.flags & CKF_USER_PIN_COUNT_LOW) {
            printf("  USER PIN locked\n");
        }
        if (tokenInfo.flags & CKF_USER_PIN_FINAL_TRY) {
            printf("  USER PIN final try\n");
        }
        if (tokenInfo.flags & CKF_USER_PIN_LOCKED) {
            printf("  USER PIN locked\n");
        }
        if (tokenInfo.flags & CKF_TOKEN_INITIALIZED) {
            printf("  Token initialized\n");
        }
        if (tokenInfo.flags & CKF_USER_PIN_INITIALIZED) {
            printf("  USER PIN initialized\n");
        }
        if (tokenInfo.flags == 0) {
            printf("  (No flags set)\n");
        }
    }

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
    printf("token_info\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
}


#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int token_info(int argc, char* argv[])
#endif
{
    int ret;
    CK_RV rv;
    const char* libName = WOLFPKCS11_DLL_FILENAME;

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
        else {
            fprintf(stderr, "Unrecognized command line argument\n  %s\n",
                argv[0]);
            return 1;
        }

        argc--;
        argv++;
    }

    rv = pkcs11_init(libName);
    if (rv == CKR_OK) {
        rv = pkcs11_token_info();
    }
    pkcs11_final();

    if (rv == CKR_OK)
        ret = 0;
    else
        ret = 1;
    return ret;
}


