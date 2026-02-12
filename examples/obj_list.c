/* obj_list.c
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

CK_SLOT_ID slot = WOLFPKCS11_DLL_SLOT;
static byte* userPin = (byte*)"wolfpkcs11-test";
static CK_ULONG userPinLen;


/* Load and initialize PKCS#11 library by name.
 *
 * library  Name of library file.
 * return CKR_OK on success, other value on failure.
 */
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


/* Finalize and close PKCS#11 library.
 */
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


static void pkcs11_print_class(CK_ULONG* objClass)
{
    const char* name = "Unknown";

    switch (*objClass) {
        case CKO_DATA:
            name = "Data";
            break;
        case CKO_CERTIFICATE:
            name = "Certificate";
            break;
        case CKO_PUBLIC_KEY:
            name = "Public Key";
            break;
        case CKO_PRIVATE_KEY:
            name = "Private Key";
            break;
        case CKO_SECRET_KEY:
            name = "Secret Key";
            break;
    }

    printf("     Class: %s\n", name);
}

static void pkcs11_print_key_type(CK_ULONG* keyType)
{
    const char* name = "Unknown";

    switch (*keyType) {
        case CKK_RSA:
            name = "RSA";
            break;
        case CKK_DH:
            name = "DH";
            break;
        case CKK_EC:
            name = "EC";
            break;
        case CKK_GENERIC_SECRET:
            name = "Generic Secret";
            break;
        case CKK_AES:
            name = "AES";
            break;
    }

    printf("  Key Type: %s\n", name);
}

static void pkcs11_print_num(const char* label, CK_ULONG* val)
{
    printf("%10s: %ld\n", label, *val);
}

static void pkcs11_print_boolean(const char* label, CK_BBOOL* val)
{
    printf("%10s: %s\n", label, (*val == CK_TRUE) ? "TRUE" : "FALSE");
}

static void pkcs11_print_boolean_on_true(const char* label, const char* name,
    CK_BBOOL* val)
{
    if (*val == CK_TRUE) {
        printf("%10s: %s\n", label, name);
    }
}

static void pkcs11_print_data(const char* label, byte* val, CK_ULONG len)
{
    CK_ULONG i;

    printf("%10s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", val[i]);
    }
    printf("\n");
}

static void pkcs11_print_string(const char* label, byte* val, CK_ULONG len)
{
    printf("%10s: %.*s\n", label, (int)len, val);
}

static CK_RV pkcs11_key_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
    CK_ULONG* keyType)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_KEY_TYPE,            NULL,   0    },
        { CKA_ENCRYPT,             NULL,   0    },
        { CKA_DECRYPT,             NULL,   0    },
        { CKA_SIGN,                NULL,   0    },
        { CKA_SIGN_RECOVER,        NULL,   0    },
        { CKA_VERIFY,              NULL,   0    },
        { CKA_VERIFY_RECOVER,      NULL,   0    },
        { CKA_WRAP,                NULL,   0    },
        { CKA_UNWRAP,              NULL,   0    },
        { CKA_DERIVE,              NULL,   0    },
        { CKA_ALWAYS_AUTHENTICATE, NULL,   0    },
        { CKA_SENSITIVE,           NULL,   0    },
        { CKA_ALWAYS_SENSITIVE,    NULL,   0    },
        { CKA_EXTRACTABLE,         NULL,   0    },
        { CKA_NEVER_EXTRACTABLE,   NULL,   0    },
    };
    CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(*getTmpl);
    CK_ULONG i;

    ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
    CHECK_CKR(ret, "Get Attribute Value sizes");

    for (i = 0; i < getTmplCnt; i++) {
        if (getTmpl[i].ulValueLen > 0) {
            getTmpl[i].pValue = malloc(getTmpl[i].ulValueLen * sizeof(byte));
            if (getTmpl[i].pValue == NULL)
                ret = CKR_DEVICE_MEMORY;
            CHECK_CKR(ret, "Allocate get attribute memory");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "Get Attribute Values");
    }

    if (ret == CKR_OK) {
        i = 0;
        pkcs11_print_key_type(getTmpl[i].pValue);
        *keyType = *(CK_ULONG*)getTmpl[i].pValue;
        i++;
        pkcs11_print_boolean_on_true("Usage", "Encrypt", getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Usage", "Decrypt", getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Usage", "Sign", getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Usage", "Sign Recover",
            getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Usage", "Verify", getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Usage", "Verify Recover",
            getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Usage", "Wrap", getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Usage", "Unwrap", getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Usage", "Derive", getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Access", "Always Authenticate",
            getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Access", "Sensitive", getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Access", "Always Sensitive",
            getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Access", "Extractable",
            getTmpl[i].pValue);
        i++;
        pkcs11_print_boolean_on_true("Access", "Never Extractable",
            getTmpl[i].pValue);
    }

    for (i = 0; i < getTmplCnt; i++) {
        free(getTmpl[i].pValue);
    }

    return ret;
}

static CK_RV pkcs11_rsa_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_MODULUS,             NULL,   0    },
        { CKA_PUBLIC_EXPONENT,     NULL,   0    },
        { CKA_MODULUS_BITS,        NULL,   0    },
    };
    CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(*getTmpl);
    CK_ULONG i;

    ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
    CHECK_CKR(ret, "Get Attribute Value sizes");

    for (i = 0; i < getTmplCnt; i++) {
        if (getTmpl[i].ulValueLen > 0) {
            getTmpl[i].pValue = malloc(getTmpl[i].ulValueLen * sizeof(byte));
            if (getTmpl[i].pValue == NULL)
                ret = CKR_DEVICE_MEMORY;
            CHECK_CKR(ret, "Allocate get attribute memory");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "Get Attribute Values");
    }

    if (ret == CKR_OK) {
        i = 0;
        pkcs11_print_data("Modulus", getTmpl[i].pValue, getTmpl[i].ulValueLen);
        i++;
        pkcs11_print_data("Pub Exp", getTmpl[i].pValue, getTmpl[i].ulValueLen);
        i++;
        pkcs11_print_num("Bits", getTmpl[i].pValue);
    }

    for (i = 0; i < getTmplCnt; i++) {
        free(getTmpl[i].pValue);
    }

    return ret;
}

static CK_RV pkcs11_cert_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_VALUE,             NULL,   0    },
    };
    CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(*getTmpl);
    CK_ULONG i;

    printf("Get cert attr\n");

    ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
    CHECK_CKR(ret, "Get Attribute Value sizes");

    for (i = 0; i < getTmplCnt; i++) {
        if (getTmpl[i].ulValueLen > 0) {
            printf("cert attr, templ[%d].len = %d\n", (int)i, (int)getTmpl[i].ulValueLen);
            getTmpl[i].pValue = malloc(getTmpl[i].ulValueLen * sizeof(byte));
            if (getTmpl[i].pValue == NULL)
                ret = CKR_DEVICE_MEMORY;
            CHECK_CKR(ret, "Allocate get attribute memory");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "Get Attribute Values");
    }

    if (ret == CKR_OK) {
        i = 0;
        pkcs11_print_data("Value", getTmpl[i].pValue, getTmpl[i].ulValueLen);
        i++;
    }

    for (i = 0; i < getTmplCnt; i++) {
        free(getTmpl[i].pValue);
    }

    return ret;
}

/* Retrieve the object attributes and display as text.
 *
 * return CKR_OK on success, other value on failure.
 */
static CK_RV pkcs11_obj_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{
    CK_RV ret = CKR_OK;
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_CLASS,               NULL,   0    },
        { CKA_ID,                  NULL,   0    },
        { CKA_LABEL,               NULL,   0    },
        { CKA_PRIVATE,             NULL,   0    },
    };
    CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(*getTmpl);
    CK_ULONG i;
    CK_ULONG objClass = 0;
    CK_ULONG keyType = 0;

    ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
    CHECK_CKR(ret, "Get Attribute Value sizes");

    for (i = 0; i < getTmplCnt; i++) {
        if (getTmpl[i].ulValueLen > 0) {
            getTmpl[i].pValue = malloc(getTmpl[i].ulValueLen * sizeof(byte));
            if (getTmpl[i].pValue == NULL)
                ret = CKR_DEVICE_MEMORY;
            CHECK_CKR(ret, "Allocate get attribute memory");
        }
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
        CHECK_CKR(ret, "Get Attribute Values");
    }

    if (ret == CKR_OK) {
        i = 0;
        pkcs11_print_class(getTmpl[i].pValue);
        objClass = *(CK_ULONG*)getTmpl[i].pValue;
        i++;
        pkcs11_print_string("Id", getTmpl[i].pValue, getTmpl[i].ulValueLen);
        i++;
        if (getTmpl[i].ulValueLen > 0) {
            pkcs11_print_string("Label", getTmpl[i].pValue,
                getTmpl[i].ulValueLen);
        }
        i++;
        pkcs11_print_boolean("Private", getTmpl[i].pValue);
    }

    if (ret == CKR_OK) {
        if (objClass == CKO_PUBLIC_KEY) {
            ret = pkcs11_key_attr(session, obj, &keyType);
            if ((ret == CKR_OK) && (keyType == CKK_RSA)) {
               ret = pkcs11_rsa_attr(session, obj);
            }
        }
        else if (objClass == CKO_PRIVATE_KEY) {
            ret = pkcs11_key_attr(session, obj, &keyType);
            if ((ret == CKR_OK) && (keyType == CKK_RSA)) {
               ret = pkcs11_rsa_attr(session, obj);
            }
        }
        else if (objClass == CKO_SECRET_KEY) {
            ret = pkcs11_key_attr(session, obj, &keyType);
        }
        else if (objClass == CKO_CERTIFICATE) {
            ret = pkcs11_cert_attr(session, obj);
        }
    }
    fprintf(stderr, "\n");

    for (i = 0; i < getTmplCnt; i++) {
        free(getTmpl[i].pValue);
    }

    return ret;
}

static CK_RV pkcs11_objs_attr(CK_SESSION_HANDLE session)
{
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE findTmpl;
    CK_ULONG cnt;

    /* Find all objects. */
    ret = funcList->C_FindObjectsInit(session, &findTmpl, 0);
    CHECK_CKR(ret, "Initialize Find");

    while (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, &obj, 1, &cnt);
        CHECK_CKR(ret, "Find Object");
        if (cnt == 1) {
            ret = pkcs11_obj_attr(session, obj);
        }
        else {
            ret = funcList->C_FindObjectsFinal(session);
            CHECK_CKR(ret, "Find Object Final");
            break;
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
    printf("obj_list\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
}


#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int obj_list(int argc, char* argv[])
#endif
{
    int ret;
    CK_RV rv;
    const char* libName = WOLFPKCS11_DLL_FILENAME;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

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
        else {
            fprintf(stderr, "Unrecognized command line argument\n  %s\n",
                argv[0]);
            return 1;
        }

        argc--;
        argv++;
    }

    userPinLen = (int)XSTRLEN((const char*)userPin);

    printf("Slot: %ld\n", slot);

    rv = pkcs11_init(libName, &session);
    if (rv == CKR_OK) {
        rv = pkcs11_objs_attr(session);
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
int obj_list(int argc, char* argv[])
#endif
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "Store disabled\n");
    return 0;
}

#endif /* !WOLFPKCS11_NO_STORE */

