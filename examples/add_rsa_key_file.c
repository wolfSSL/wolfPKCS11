/* add_rsa_key.c
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
#include <wolfssl/wolfcrypt/rsa.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#if !defined(WOLFPKCS11_NO_STORE) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)

#ifdef DEBUG_WOLFPKCS11
    #define CHECK_CKR(rv, op)                                   \
        fprintf(stderr, "%s: %ld\n", op, rv)
    #define CHECK_LEN(len, op)                                  \
        fprintf(stderr, "%s: %ld\n", op, (unsigned long)len)
#else
    #define CHECK_CKR(rv, op)                                   \
        if (ret != CKR_OK)                                      \
            fprintf(stderr, "%s: %ld\n", op, rv)
    #define CHECK_LEN(len, op)                                  \
        if (ret != CKR_OK)                                      \
            fprintf(stderr, "%s: %ld\n", op, (unsigned long)len)
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


static CK_RV load_rsa_key(char* filename, RsaKey* rsa)
{
    int ret = 0;
    unsigned char buffer[4096];
    int len;
    XFILE file;

    file = XFOPEN(filename, "r");
    if (file == XBADFILE) {
        fprintf(stderr, "Unable to open file: %s\n", filename);
        ret = 1;
    }
    if (ret == 0) {
        len = (int)XFREAD(buffer, 1, sizeof(buffer), file);
        if (len <= 0) {
            fprintf(stderr, ": %s\n", filename);
            ret = 1;
        }
        XFCLOSE(file);
    }
    if (ret == 0) {
        ret = wc_InitRsaKey(rsa, NULL);
        if (ret != 0) {
            fprintf(stderr, "Initialing key failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        word32 idx = 0;
        ret = wc_RsaPrivateKeyDecode(buffer, &idx, rsa, len);
        if (ret != 0) {
            fprintf(stderr, "Decoding RSA private key failed: %d\n", ret);
        }
    }

    return (CK_RV)ret;
}


static CK_OBJECT_CLASS privKeyClass    = CKO_PRIVATE_KEY;
static CK_BBOOL ckTrue  = CK_TRUE;
static CK_KEY_TYPE rsaKeyType  = CKK_RSA;

static CK_RV export_mp(mp_int* mp, unsigned char* buffer, CK_ULONG* len,
    const char* name)
{
    CK_RV ret;

    ret = mp_to_unsigned_bin(mp, buffer);
    if (ret != 0) {
        fprintf(stderr, "Failed to export %s: %d\n", name, (int)ret);
    }
    *len = mp_unsigned_bin_size(mp);

    return ret;
}

static CK_RV pkcs11_add_rsa_key(CK_SESSION_HANDLE session, RsaKey* rsa,
    unsigned char* privId, CK_ULONG privIdLen)
{
    CK_RV ret;
    unsigned char rsa_modulus[1024];
    unsigned char rsa_priv_exp[1024];
    unsigned char rsa_p[1024];
    unsigned char rsa_q[1024];
    unsigned char rsa_dP[1024];
    unsigned char rsa_dQ[1024];
    unsigned char rsa_u[1024];
    unsigned char rsa_pub_exp[1024];
    CK_ATTRIBUTE rsa_priv_key[] = {
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)      },
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)        },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,           rsa_modulus,       0                         },
        { CKA_PRIVATE_EXPONENT,  rsa_priv_exp,      0                         },
        { CKA_PRIME_1,           rsa_p,             0                         },
        { CKA_PRIME_2,           rsa_q,             0                         },
        { CKA_EXPONENT_1,        rsa_dP,            0                         },
        { CKA_EXPONENT_2,        rsa_dQ,            0                         },
        { CKA_COEFFICIENT,       rsa_u,             0                         },
        { CKA_PUBLIC_EXPONENT,   rsa_pub_exp,       0                         },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_ID,                privId,            privIdLen                 },
    };
    CK_ULONG cnt = sizeof(rsa_priv_key)/sizeof(*rsa_priv_key);
    CK_OBJECT_HANDLE obj;

    ret = export_mp(&rsa->n , rsa_modulus , &rsa_priv_key[ 3].ulValueLen,
        "modulus");
    if (ret != 0) return ret;
    ret = export_mp(&rsa->d , rsa_priv_exp, &rsa_priv_key[ 4].ulValueLen,
        "private exponent");
    if (ret != 0) return ret;
    ret = export_mp(&rsa->p , rsa_p       , &rsa_priv_key[ 5].ulValueLen,
        "p");
    if (ret != 0) return ret;
    ret = export_mp(&rsa->q , rsa_q       , &rsa_priv_key[ 6].ulValueLen,
        "q");
    if (ret != 0) return ret;
    ret = export_mp(&rsa->dP, rsa_dP      , &rsa_priv_key[ 7].ulValueLen,
        "dP");
    if (ret != 0) return ret;
    ret = export_mp(&rsa->dQ, rsa_dQ      , &rsa_priv_key[ 8].ulValueLen,
        "dQ");
    if (ret != 0) return ret;
    ret = export_mp(&rsa->u , rsa_u       , &rsa_priv_key[ 9].ulValueLen,
        "dQ");
    if (ret != 0) return ret;
    ret = export_mp(&rsa->e , rsa_pub_exp , &rsa_priv_key[10].ulValueLen,
        "dQ");
    if (ret != 0) return ret;

    if (privId == NULL)
        cnt -= 2;

    ret = funcList->C_CreateObject(session, rsa_priv_key, cnt, &obj);
    CHECK_CKR(ret, "CreateObject RSA 2048-bit key");

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
    printf("add_rsa_key_file\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-rsa <file>        RSA private key file\n");
    printf("-slot <num>        Slot number to use\n");
    printf("-userPin <string>  User PIN\n");
    printf("-privId <string>   Private key identifier\n");
}


#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int add_rsa_key_file(int argc, char* argv[])
#endif
{
    int ret;
    CK_RV rv;
    const char* libName = WOLFPKCS11_DLL_FILENAME;
    char* filename = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    RsaKey rsa;
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
        else if (string_matches(*argv, "-rsa")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "RSA filename not supplied\n");
                return 1;
            }
            filename = *argv;
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

    if (filename == NULL) {
        fprintf(stderr, "No file name specified\n");
        Usage();
        return 1;
    }

    userPinLen = (int)XSTRLEN((const char*)userPin);
    XMEMSET(&rsa, 0, sizeof(rsa));

    rv = load_rsa_key(filename, &rsa);
    if (rv == CKR_OK) {
        rv = pkcs11_init(libName, &session);
    }
    if (rv == CKR_OK) {
        rv = pkcs11_add_rsa_key(session, &rsa, privId, privIdLen);
    }
    pkcs11_final(session);

    wc_FreeRsaKey(&rsa);

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
int add_rsa_key_file(int argc, char* argv[])
#endif
{
    (void)argc;
    (void)argv;
#ifdef WOLFPKCS11_NO_STORE
    fprintf(stderr, "Store disabled\n");
#else
    fprintf(stderr, "RSA disabled\n");
#endif
    return 0;
}

#endif /* !WOLFPKCS11_NO_STORE && !NO_RSA && !NO_FILESYSTEM */
