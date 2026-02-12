/* mech_info.c
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

static const char* pkcs11_get_mech_name(CK_MECHANISM_TYPE mechType)
{
    const char* name = "Unknown";

    switch (mechType) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            name = "RSA PKCS Key Pair Generation";
            break;
        case CKM_RSA_PKCS:
            name = "RSA PKCS";
            break;
        case CKM_RSA_X_509:
            name = "RSA X.509";
            break;
        case CKM_RSA_PKCS_OAEP:
            name = "RSA PKCS OAEP";
            break;
        case CKM_RSA_PKCS_PSS:
            name = "RSA PKCS PSS";
            break;
        case CKM_DH_PKCS_KEY_PAIR_GEN:
            name = "DH PKCS Key Pair Generation";
            break;
        case CKM_DH_PKCS_DERIVE:
            name = "DH PKCS Derive";
            break;
        case CKM_MD5_HMAC:
            name = "MD5 HMAC";
            break;
        case CKM_SHA1:
            name = "SHA1";
            break;
        case CKM_SHA1_HMAC:
            name = "SHA1 HMAC";
            break;
        case CKM_SHA256:
            name = "SHA256";
            break;
        case CKM_SHA256_HMAC:
            name = "SHA256 HMAC";
            break;
        case CKM_SHA224:
            name = "SHA224";
            break;
        case CKM_SHA224_HMAC:
            name = "SHA224 HMAC";
            break;
        case CKM_SHA384:
            name = "SHA384";
            break;
        case CKM_SHA384_HMAC:
            name = "SHA384 HMAC";
            break;
        case CKM_SHA512:
            name = "SHA512";
            break;
        case CKM_SHA512_HMAC:
            name = "SHA512 HMAC";
            break;
        case CKM_GENERIC_SECRET_KEY_GEN:
            name = "Generic Secret Key Generation";
            break;
        case CKM_EC_KEY_PAIR_GEN:
            name = "Elliptic Curve Key Pair Generation";
            break;
        case CKM_ECDSA:
            name = "Elliptic Curve Digital Signature Algorithm (ECDSA)";
            break;
        case CKM_ECDH1_DERIVE:
            name = "Elliptic Curve Diffie-Hellman (ECDH) 1 Derive";
            break;
        case CKM_ECDH1_COFACTOR_DERIVE:
            name = "Elliptic Curve Diffie-Hellman (ECDH) 1 Cofactor Derive";
            break;
        case CKM_AES_KEY_GEN:
            name = "AES Key Generation";
            break;
        case CKM_AES_CBC:
            name = "AES CBC";
            break;
        case CKM_AES_CBC_PAD:
            name = "AES CBC PAD";
            break;
        case CKM_AES_GCM:
            name = "AES GCM";
            break;
    }

    return name;
}

struct mech_flag_t {
    CK_FLAGS flag;
    const char* name;
} mechFlags[] = {
    { CKF_HW                   , "Hardware"                    },
    { CKF_ENCRYPT              , "Encrypt"                     },
    { CKF_DECRYPT              , "Decrypt"                     },
    { CKF_DIGEST               , "Digest"                      },
    { CKF_SIGN                 , "Sign"                        },
    { CKF_SIGN_RECOVER         , "Sign Recover"                },
    { CKF_VERIFY               , "Verify"                      },
    { CKF_VERIFY_RECOVER       , "Verify Recover"              },
    { CKF_GENERATE             , "Generate"                    },
    { CKF_GENERATE_KEY_PAIR    , "Generate Key Pair"           },
    { CKF_WRAP                 , "Wrap"                        },
    { CKF_UNWRAP               , "Unwrap"                      },
    { CKF_DERIVE               , "Derive"                      },
    { CKF_EC_F_P               , "Elliptic Curve Field Prime"  },
    { CKF_EC_F_2M              , "Elliptic Curve Field Binary" },
    { CKF_EC_ECPARAMETERS      , "Elliptic Curve Parameters"   },
    { CKF_EC_NAMEDCURVE        , "Elliptic Curve Named Curve"  },
    { CKF_EC_UNCOMPRESS        , "Elliptic Curve Uncompress"   },
    { CKF_EC_COMPRESS          , "Elliptic Curve Compress"     },
};
#define MECH_FLAGS_CNT  ((int)(sizeof(mechFlags) / sizeof(*mechFlags)))

/* Retrieve the mechanism information and display as text.
 *
 * slotId    Slot identifier
 * mechType  Type of mechanism to show information on.
 * return CKR_OK on success, other value on failure.
 */
static CK_RV pkcs11_mech_info(CK_SLOT_ID slotId, CK_MECHANISM_TYPE mechType)
{
    CK_RV ret = CKR_OK;
    CK_MECHANISM_INFO mechInfo;

    ret = funcList->C_GetMechanismInfo(slotId, mechType, &mechInfo);
    CHECK_CKR(ret, "Get Mechanism info");

    if (ret == CKR_OK) {
        printf("Mechanism Type: %s\n", pkcs11_get_mech_name(mechType));
        printf("Key Size: %ld-%ld\n", mechInfo.ulMinKeySize,
            mechInfo.ulMaxKeySize);
        printf("Flags: ");
        if (mechInfo.flags == 0) {
            printf("(No flags set)\n");
        }
        else {
            int i;

            for (i = 0; i < MECH_FLAGS_CNT; i++) {
                if (mechInfo.flags & mechFlags[i].flag) {
                    if (mechInfo.flags & (mechFlags[i].flag - 1))
                        printf(", ");
                    printf("%s", mechFlags[i].name);
                }
            }
            printf("\n");
        }
        printf("\n");
    }

    return ret;
}

/* Retrieve all mechanism information and display as text.
 *
 * slotId    Slot identifier
 * return CKR_OK on success, other value on failure.
 */
static CK_RV pkcs11_mechs_info(CK_SLOT_ID slotId)
{
    CK_RV ret = CKR_OK;
    CK_MECHANISM_TYPE* mechTypes = NULL;
    CK_ULONG cnt = 0;
    CK_ULONG i;

    ret = funcList->C_GetMechanismList(slotId, CK_NULL_PTR, &cnt);
    CHECK_CKR(ret, "Get Mechanism List count");

    if (ret == CKR_OK) {
        mechTypes = malloc(cnt * sizeof(CK_MECHANISM_TYPE));
        if (mechTypes == NULL) {
            ret = 1;
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetMechanismList(slotId, mechTypes, &cnt);
        CHECK_CKR(ret, "Get Slot List");
    }

    for (i = 0; (ret == CKR_OK) && (i < cnt); i++) {
        ret = pkcs11_mech_info(slotId, mechTypes[i]);
    }

    free(mechTypes);
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
    printf("slot_info\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
}


#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int mech_info(int argc, char* argv[])
#endif
{
    int ret;
    CK_RV rv;
    const char* libName = WOLFPKCS11_DLL_FILENAME;
    CK_SLOT_ID slot = WOLFPKCS11_DLL_SLOT;

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
        rv = pkcs11_mechs_info(slot);
    }
    pkcs11_final();

    if (rv == CKR_OK)
        ret = 0;
    else
        ret = 1;
    return ret;
}


