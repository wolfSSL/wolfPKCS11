/* stm32_dhuk_aes_key.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/port/st/stm32.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

extern int uart_printf(const char* format, ...);
#undef printf
#define printf uart_printf

#ifdef DEBUG_WOLFPKCS11
    #define CHECK_CKR(rv, op)                       \
        fprintf(stderr, "%s: %ld\n", op, rv)
#else
    #define CHECK_CKR(rv, op)                       \
        if (ret != CKR_OK)                          \
            printf("%s: %ld\n", op, rv)
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

static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = WOLFPKCS11_DLL_SLOT;

static byte* userPin = (byte*)"wolfpkcs11-test";
static CK_ULONG userPinLen;


static CK_RV pkcs11_init(CK_SESSION_HANDLE* session)
{
    CK_RV ret = CKR_OK;

    ret = C_GetFunctionList(&funcList);

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
}


static CK_OBJECT_CLASS secretKeyClass    = CKO_SECRET_KEY;
static CK_BBOOL ckTrue  = CK_TRUE;
#ifndef NO_AES
static CK_KEY_TYPE aesKeyType  = CKK_AES;
#else
static CK_KEY_TYPE genericKeyType  = CKK_GENERIC_SECRET;
#endif

static unsigned char aes_256_key[] = {                           
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,                                
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,                                
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,                                
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 
 };


CK_RV pkcs11_add_aes_dhuk_key(CK_SESSION_HANDLE session);
CK_RV pkcs11_add_aes_dhuk_key(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    int devId = WOLFSSL_STM32U5_DHUK_DEVID; /* signal use of hardware key */
    CK_ATTRIBUTE aes_dhuk_secret_key[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)    },
#ifndef NO_AES
        { CKA_KEY_TYPE,          &aesKeyType,       sizeof(aesKeyType)        },
#else
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
#endif
        { CKA_WRAP,              &ckTrue,           sizeof(ckTrue)            },
        { CKA_UNWRAP,            &ckTrue,           sizeof(ckTrue)            },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_VALUE,             aes_256_key,       sizeof(aes_256_key)       },
        { CKA_DEVID,             &devId,            sizeof(devId)             },
    };
    CK_ULONG cnt = sizeof(aes_dhuk_secret_key)/sizeof(*aes_dhuk_secret_key);
    CK_OBJECT_HANDLE obj;

    ret = funcList->C_CreateObject(session, aes_dhuk_secret_key, cnt, &obj);
    CHECK_CKR(ret, "CreateObject AES DHUK key");

    return ret;
}

CK_RV pkcs11_add_aes_software_key(CK_SESSION_HANDLE session);
CK_RV pkcs11_add_aes_software_key(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    int devId = WOLFSSL_STM32U5_SAES_DEVID;
    CK_ATTRIBUTE aes_256_secret_key[] = {
        { CKA_CLASS,             &secretKeyClass,   sizeof(secretKeyClass)    },
#ifndef NO_AES
        { CKA_KEY_TYPE,          &aesKeyType,       sizeof(aesKeyType)        },
#else
        { CKA_KEY_TYPE,          &genericKeyType,   sizeof(genericKeyType)    },
#endif
        { CKA_ENCRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_VALUE,             aes_256_key,       sizeof(aes_256_key)       },
        { CKA_DEVID,             &devId,            sizeof(devId)             },
    };
    CK_ULONG cnt = sizeof(aes_256_secret_key)/sizeof(*aes_256_secret_key);
    CK_OBJECT_HANDLE obj;

    ret = funcList->C_CreateObject(session, aes_256_secret_key, cnt, &obj);
    CHECK_CKR(ret, "CreateObject AES 256-bit key");

    return ret;
}

CK_OBJECT_HANDLE find_key_type(CK_SESSION_HANDLE session, int devId);
CK_OBJECT_HANDLE find_key_type(CK_SESSION_HANDLE session, int devId)
{
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE obj, match = 0;
    CK_ATTRIBUTE findTmpl;
    CK_ULONG cnt;

    /* Find all objects. */
    ret = funcList->C_FindObjectsInit(session, &findTmpl, 0);
    CHECK_CKR(ret, "Initialize Find");

    while (ret == CKR_OK) {
        int devIdFound;
        CK_ULONG devIdLen = sizeof(devIdFound);
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_DEVID, &devIdFound, devIdLen },
        };
        CK_ULONG getTmplCnt = sizeof(getTmpl) / sizeof(CK_ATTRIBUTE);

        ret = funcList->C_FindObjects(session, &obj, 1, &cnt);
        CHECK_CKR(ret, "Find Object");
        if (cnt == 1) {
            /* check devId match */
            ret = funcList->C_GetAttributeValue(session, obj, getTmpl, getTmplCnt);
            printf("Return value from GetAttributeValue = %d, {%d, %d}\n", ret, devIdFound, getTmpl[0].ulValueLen);
            if (devIdFound == devId) {
                match = obj;
                break;
            }
        }
        else {
            break;
        }
    }
    ret = funcList->C_FindObjectsFinal(session);
    CHECK_CKR(ret, "Find Object Final");

    return match;
}

CK_OBJECT_HANDLE find_dhuk_key(CK_SESSION_HANDLE session);
CK_OBJECT_HANDLE find_dhuk_key(CK_SESSION_HANDLE session)
{
    CK_OBJECT_HANDLE ret;
    ret = find_key_type(session, WOLFSSL_STM32U5_DHUK_DEVID);
    if (ret == 0) {
        printf("Failed to find DHUK key\n");
    }
    else {
        printf("Found DHUK key\n");
    }
    return ret;
}

static CK_OBJECT_HANDLE find_software_key(CK_SESSION_HANDLE session)
{
    CK_OBJECT_HANDLE ret;
    ret = find_key_type(session, WOLFSSL_STM32U5_SAES_DEVID);
    if (ret == 0) {
        printf("Failed to find software key\n");
    }
    else {
        printf("Found software key\n");
    }
    return ret;
}

static CK_OBJECT_HANDLE find_wrapped_key(CK_SESSION_HANDLE session)
{
    CK_OBJECT_HANDLE ret;
    ret = find_key_type(session, WOLFSSL_STM32U5_DHUK_WRAPPED_DEVID);
    if (ret == 0) {
        printf("Failed to find wrapped key\n");
    }
    else {
        printf("Found wrapped key\n");
    }
    return ret;
}


CK_RV pkcs11_wrap_aes_key(CK_SESSION_HANDLE session);
CK_RV pkcs11_wrap_aes_key(CK_SESSION_HANDLE session)
{
    
    CK_OBJECT_HANDLE wrappedKey;
    CK_OBJECT_HANDLE dhuk;
    CK_OBJECT_HANDLE key;
    CK_BYTE wrappedKeyBuffer[32];
    CK_ULONG wrappedKeyBufferLen = sizeof(wrappedKeyBuffer);
    int devId = WOLFSSL_STM32U5_DHUK_WRAPPED_DEVID;
    CK_MECHANISM mech = {CKM_AES_ECB, NULL, 0};
    int i;
    CK_RV rv;

    key = find_software_key(session);
    if (key == 0) {
        return CKR_FUNCTION_FAILED;
    }

    // Wrap the key using the DHUK key
    dhuk = find_dhuk_key(session);
    if (dhuk == 0) {
        return CKR_FUNCTION_FAILED;
    }

    // Perform the wrapping operation
    rv = funcList->C_WrapKey(session, &mech, dhuk, key, wrappedKeyBuffer,
        &wrappedKeyBufferLen);
    if (rv != CKR_OK) {
        printf("Failed to wrap key, ret = %d\n", rv);
        return rv;
    }

    printf("DHUK wrapped key created : ");
    for (i = 0; i < wrappedKeyBufferLen; i++) {
        printf("%02X", wrappedKeyBuffer[i]);
    }
    printf("\n");

    /* Create a wrapped key object */
    CK_ATTRIBUTE wrapped_key_template[] = {
        { CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType) },
        { CKA_VALUE, wrappedKeyBuffer, wrappedKeyBufferLen },
        { CKA_ENCRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_DEVID, &devId, sizeof(devId) },
    };
    CK_ULONG wrapped_key_template_len = sizeof(wrapped_key_template) / sizeof(CK_ATTRIBUTE);

    rv = funcList->C_CreateObject(session, wrapped_key_template, wrapped_key_template_len, &wrappedKey);
    if (rv != CKR_OK) {
        return rv;
    }

    printf("Created a key wrapped with using the DHUK\n");

    return CKR_OK;
}


static CK_RV pkcs11_encrypt_with_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
    byte* data, CK_ULONG dataLen, byte* iv, byte* out, CK_ULONG_PTR outLen)
{
    CK_MECHANISM mech = {CKM_AES_CBC, iv, 16};
    //CK_MECHANISM mech = {CKM_AES_ECB, NULL, 0};
    CK_RV rv;

    rv = funcList->C_EncryptInit(session, &mech, key);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = funcList->C_Encrypt(session, data, dataLen, out, outLen);
    if (rv != CKR_OK) {
        return rv;
    }

    return CKR_OK;
}


static CK_RV pkcs11_decrypt_with_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
    byte* data, CK_ULONG dataLen, byte* iv, byte* out, CK_ULONG_PTR outLen)
{
    CK_MECHANISM mech = {CKM_AES_CBC, iv, 16};
    //CK_MECHANISM mech = {CKM_AES_ECB, NULL, 0};
    CK_RV rv;

    rv = funcList->C_DecryptInit(session, &mech, key);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = funcList->C_Decrypt(session, data, dataLen, out, outLen);
    if (rv != CKR_OK) {
        return rv;
    }

    return CKR_OK;
}


/* compare encryption using the wrapped AES key versus unwrapped one */
static CK_RV pkcs11_compare_results(CK_SESSION_HANDLE session)
{
    CK_RV ret = 0;
    byte plain[] = {                         
         0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,                                
         0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a                                 
     };
    byte cipher[16];
    byte output[16];
    byte expected[] = {                        
         0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,                                
         0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };
    byte iv[16];
    CK_ULONG cipherLen = sizeof(cipher);
    CK_ULONG plainLen = sizeof(plain);
    CK_ULONG outputLen = sizeof(output);
    CK_OBJECT_HANDLE key;
    int i;

    printf("Software key and wrapped key should produce the same results\n");

    /* in applications a random IV should be used, for this example it is constant */
    for (i = 0; i < 16; i++) {
        iv[i] = i;
    }

    /* Encrypt plain text using software only key */
    key = find_software_key(session);
    memset(cipher, 0, sizeof(cipher));
    ret = pkcs11_encrypt_with_key(session, key, plain, sizeof(plain), iv, cipher, &cipherLen);
    if (ret != CKR_OK) {
        return ret;
    }

    printf("\tSAES User Key [Encrypted]: ");
    for (i = 0; i < cipherLen; i++) {
        printf("%02X", cipher[i]);
    }
    printf("\n");

    /* encrypt using wrapped key */
    memset(cipher, 0, sizeof(cipher));
    key = find_wrapped_key(session);
    ret = pkcs11_encrypt_with_key(session, key, plain, sizeof(plain), iv, cipher, &cipherLen);
    if (ret != CKR_OK) {
        return ret;
    }

    printf("\tWrapped Key [Encrypted] : ");
    for (i = 0; i < cipherLen; i++) {
        printf("%02X", cipher[i]);
    }
    printf("\n");

    memset(output, 0, sizeof(output));
    ret = pkcs11_decrypt_with_key(session, key, cipher, cipherLen, iv, output, &outputLen);
        if (ret != CKR_OK) {
        return ret;
    }

    printf("\tWrapped Key [Decrypted] : ");
    for (i = 0; i < outputLen; i++) {
        printf("%02X", output[i]);
    }
    printf("\n");

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
    printf("add_aes_key\n");
    printf("-?                 Help, print this usage\n");
}


#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int stm32_dhuk_aes_key(int argc, char* argv[])
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
    printf("Testing PKCS11 DHUK AES use\n\r");
    
    argc--;
    argv++;
    while (argc > 0) {
        if (string_matches(*argv, "-?")) {
            Usage();
            return 0;
        }
        else {
            fprintf(stderr, "Unrecognized command line argument\n  %s\n",
                argv[0]);
            return 1;
        }

        argc--;
        argv++;
    }

    rv = pkcs11_init(&session);
    if (rv == CKR_OK) {
        rv = pkcs11_add_aes_dhuk_key(session);
    }
    if (rv == CKR_OK) {
        rv = pkcs11_add_aes_software_key(session);
    }
    if (rv == CKR_OK) {
        rv = pkcs11_wrap_aes_key(session);
    }
    if (rv == CKR_OK) {
        rv = pkcs11_compare_results(session);
    }
    pkcs11_final(session);

    if (rv == CKR_OK)
        ret = 0;
    else
        ret = 1;
    return ret;
}
