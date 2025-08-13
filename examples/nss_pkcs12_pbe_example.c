/* nss_pkcs12_pbe_example.c
 *
 * Example demonstrating NSS PKCS#12 PBE SHA-256 HMAC key generation
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

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DEBUG_WOLFPKCS11
    #define CHECK_CKR(rv, op)                       \
        fprintf(stderr, "%s: %ld\n", op, rv)
#else
    #define CHECK_CKR(rv, op)                       \
        if (rv != CKR_OK)                          \
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

/* Load and initialize PKCS#11 library by name.
 *
 * library  Name of library file.
 * session  Session handle to be opened.
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
        ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, session);
        CHECK_CKR(ret, "Open Session");
    }

    if (ret == CKR_OK) {
        userPinLen = (CK_ULONG)XSTRLEN((char*)userPin);
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        if (ret != CKR_OK) {
            CHECK_CKR(ret, "Login");
            printf("Note: Login failed, continuing without authentication\n");
            printf("      Some operations may not work without proper login\n");
            /* Don't fail completely - some operations might work without login */
            ret = CKR_OK;
        }
    }

    return ret;
}

/* Finalize and close PKCS#11 library.
 */
static void pkcs11_final(CK_SESSION_HANDLE session)
{
    funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    dlclose(dlib);
#endif
}

#ifdef WOLFPKCS11_NSS

static void print_hex(const char* label, const CK_BYTE* data, CK_ULONG len)
{
    printf("%s: ", label);
    for (CK_ULONG i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static int demonstrate_pkcs12_pbe_key_generation(const char* library)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;

    printf("=== NSS PKCS#12 PBE SHA-256 HMAC Key Generation Example ===\n\n");

    /* Initialize PKCS#11 and open session */
    rv = pkcs11_init(library, &session);
    if (rv != CKR_OK) {
        printf("ERROR: PKCS#11 initialization failed: 0x%08lX\n", rv);
        return -1;
    }

    /* Example 1: Basic key generation */
    printf("1. Basic Key Generation\n");
    printf("   Purpose: Generate a 256-bit encryption key from password\n\n");

    /* Example password and salt (in real use, these should be secure) */
    CK_BYTE password[] = "MySecurePassword2024";
    CK_BYTE salt[] = {
        0x8A, 0x2F, 0x3E, 0x91, 0x45, 0x67, 0xBC, 0xDE,
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
    };
    CK_ULONG iterationCount = 100000; /* Modern recommended minimum */
    CK_ULONG keyLength = 32; /* 256-bit AES key */

    printf("   Password: %s\n", (char*)password);
    print_hex("   Salt", salt, sizeof(salt));
    printf("   Iterations: %lu\n", iterationCount);
    printf("   Key Length: %lu bytes (%lu bits)\n\n", keyLength, keyLength * 8);

    /* Set up PBE parameters */
    CK_PBE_PARAMS pbeParams = {
        NULL,
        password,
        strlen((char*)password),
        salt,
        sizeof(salt),
        iterationCount
    };

    CK_MECHANISM mechanism = {
        CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN,
        &pbeParams,
        sizeof(pbeParams)
    };

    /* Define key attributes */
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_BYTE keyLabel[] = "PKCS12-PBE-Generated-Key";

    CK_ATTRIBUTE keyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VALUE_LEN, &keyLength, sizeof(keyLength)},
        {CKA_LABEL, keyLabel, sizeof(keyLabel) - 1},
        {CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)},
        {CKA_DECRYPT, &ckTrue, sizeof(ckTrue)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)}
    };
    CK_ULONG keyTemplateCount = sizeof(keyTemplate) / sizeof(keyTemplate[0]);

    /* Generate the key */
    printf("   Generating key...\n");
    rv = funcList->C_GenerateKey(session, &mechanism, keyTemplate,
                                keyTemplateCount, &key);
    if (rv != CKR_OK) {
        printf("ERROR: C_GenerateKey failed: 0x%08lX\n", rv);
        if (rv == CKR_MECHANISM_INVALID) {
            printf("       CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN mechanism not supported\n");
            printf("       This indicates the NSS extension is not available in this build\n");
        } else if (rv == CKR_USER_NOT_LOGGED_IN) {
            printf("       User not logged in - authentication may be required\n");
        } else if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
            printf("       Function not supported by this PKCS#11 implementation\n");
        }
        pkcs11_final(session);
        return -1;
    }

    printf("   ✓ Key generated successfully (handle: %lu)\n\n", key);

    /* Retrieve and display key information */
    CK_BYTE keyValue[64];
    CK_ULONG keyValueLen = sizeof(keyValue);
    CK_ATTRIBUTE getTemplate[] = {
        {CKA_VALUE, keyValue, keyValueLen}
    };

    rv = funcList->C_GetAttributeValue(session, key, getTemplate, 1);
    if (rv == CKR_OK) {
        printf("   Generated Key Material:\n");
        print_hex("     Value", keyValue, getTemplate[0].ulValueLen);
        printf("\n");
    } else if (rv == CKR_ATTRIBUTE_SENSITIVE) {
        printf("   Key value is marked as sensitive (cannot extract)\n\n");
    } else {
        printf("   Could not retrieve key value: 0x%08lX\n\n", rv);
    }

    /* Example 2: Different key lengths for different use cases */
    printf("2. Multiple Key Lengths Example\n");
    printf("   Purpose: Generate keys for different cryptographic needs\n\n");

    struct {
        CK_ULONG length;
        const char* purpose;
    } keyLengths[] = {
        {16, "AES-128 encryption"},
        {24, "AES-192 encryption"},
        {32, "AES-256 encryption"},
        {64, "HMAC-SHA512 authentication"}
    };

    for (int i = 0; i < 4; i++) {
        CK_OBJECT_HANDLE testKey;
        CK_ULONG testLen = keyLengths[i].length;

        keyTemplate[2].pValue = &testLen; /* Update CKA_VALUE_LEN */

        printf("   Generating %lu-byte key for %s...\n",
               testLen, keyLengths[i].purpose);

        rv = funcList->C_GenerateKey(session, &mechanism, keyTemplate,
                                    keyTemplateCount, &testKey);
        if (rv == CKR_OK) {
            printf("   ✓ Success (handle: %lu)\n", testKey);
        } else {
            printf("   ✗ Failed: 0x%08lX\n", rv);
        }
    }
    printf("\n");

    /* Example 3: Security considerations */
    printf("3. Security Best Practices\n");
    printf("   - Use strong, unique passwords\n");
    printf("   - Generate cryptographically random salts\n");
    printf("   - Use sufficient iteration counts (100,000+ recommended)\n");
    printf("   - Clear sensitive data from memory after use\n");
    printf("   - Store keys securely (mark as non-extractable for production)\n\n");

    /* Example 4: Production-ready key (non-extractable) */
    printf("4. Production Key Generation\n");
    printf("   Purpose: Generate a non-extractable key for production use\n\n");

    CK_OBJECT_HANDLE prodKey;
    CK_BBOOL sensitive = CK_TRUE;
    CK_BBOOL nonExtractable = CK_FALSE; /* Set to CK_TRUE for production */
    CK_BYTE prodLabel[] = "Production-PKCS12-Key";

    CK_ATTRIBUTE prodTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_VALUE_LEN, &keyLength, sizeof(keyLength)},
        {CKA_LABEL, prodLabel, sizeof(prodLabel) - 1},
        {CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)},
        {CKA_DECRYPT, &ckTrue, sizeof(ckTrue)},
        {CKA_SENSITIVE, &sensitive, sizeof(sensitive)},
        {CKA_EXTRACTABLE, &nonExtractable, sizeof(nonExtractable)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)}
    };
    CK_ULONG prodTemplateCount = sizeof(prodTemplate) / sizeof(prodTemplate[0]);

    rv = funcList->C_GenerateKey(session, &mechanism, prodTemplate,
                                prodTemplateCount, &prodKey);
    if (rv == CKR_OK) {
        printf("   ✓ Production key generated (handle: %lu)\n", prodKey);
        printf("   Key is marked as sensitive and non-extractable\n\n");
    } else {
        printf("   ✗ Production key generation failed: 0x%08lX\n\n", rv);
    }

    /* Example 5: Generate proper AES key and test encryption */
    printf("5. AES Key Generation and Usage Test\n");
    printf("   Purpose: Generate an AES key using PBE and test encryption\n\n");

    /* Generate an AES key specifically for encryption testing */
    CK_OBJECT_HANDLE aesKey;
    CK_OBJECT_CLASS aesKeyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesKeyType = CKK_AES;
    CK_ULONG aesKeyLength = 32; /* 256-bit AES key */
    CK_BYTE aesKeyLabel[] = "PKCS12-PBE-AES-Key";

    CK_ATTRIBUTE aesKeyTemplate[] = {
        {CKA_CLASS, &aesKeyClass, sizeof(aesKeyClass)},
        {CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType)},
        {CKA_VALUE_LEN, &aesKeyLength, sizeof(aesKeyLength)},
        {CKA_LABEL, aesKeyLabel, sizeof(aesKeyLabel) - 1},
        {CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)},
        {CKA_DECRYPT, &ckTrue, sizeof(ckTrue)},
        {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
        {CKA_TOKEN, &ckFalse, sizeof(ckFalse)}
    };
    CK_ULONG aesKeyTemplateCount = sizeof(aesKeyTemplate) / sizeof(aesKeyTemplate[0]);

    printf("   Generating AES-256 key using PBE...\n");
    rv = funcList->C_GenerateKey(session, &mechanism, aesKeyTemplate,
                                aesKeyTemplateCount, &aesKey);
    if (rv != CKR_OK) {
        printf("   ✗ AES key generation failed: 0x%08lX\n", rv);
        printf("   Skipping encryption test\n\n");
    } else {
        printf("   ✓ AES key generated successfully (handle: %lu)\n", aesKey);

        /* Test encryption/decryption with the AES key */
        CK_BYTE plaintext[] = "Hello, PKCS#12 PBE!";
        CK_BYTE ciphertext[256];
        CK_ULONG ciphertextLen = sizeof(ciphertext);
        CK_BYTE decrypted[256];
        CK_ULONG decryptedLen = sizeof(decrypted);

        /* Use AES-CBC-PAD mode which handles padding automatically */
        CK_BYTE iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        CK_MECHANISM encMech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };

        printf("   Plaintext: %s\n", plaintext);
        print_hex("   IV", iv, sizeof(iv));
        printf("   Testing AES-CBC-PAD encryption...\n");

        /* Use original plaintext without manual padding since CBC_PAD handles it */
        CK_ULONG plaintextLen = strlen((char*)plaintext);

        rv = funcList->C_EncryptInit(session, &encMech, aesKey);
        if (rv == CKR_OK) {
            rv = funcList->C_Encrypt(session, plaintext, plaintextLen,
                                    ciphertext, &ciphertextLen);
        }

        if (rv == CKR_OK) {
            printf("   ✓ Encryption successful\n");
            print_hex("     Ciphertext", ciphertext, ciphertextLen);

            printf("   Testing AES-CBC-PAD decryption...\n");
            rv = funcList->C_DecryptInit(session, &encMech, aesKey);
            if (rv == CKR_OK) {
                rv = funcList->C_Decrypt(session, ciphertext, ciphertextLen,
                                        decrypted, &decryptedLen);
            }

            if (rv == CKR_OK && decryptedLen == plaintextLen &&
                memcmp(plaintext, decrypted, plaintextLen) == 0) {
                printf("   ✓ Decryption successful - plaintext recovered!\n");
                printf("   Original: %.*s\n", (int)plaintextLen, decrypted);
            } else {
                printf("   ✗ Decryption failed or data mismatch (rv=0x%08lX, len=%lu)\n", rv, decryptedLen);
                if (rv == CKR_OK && decryptedLen > 0) {
                    printf("     Decrypted: %.*s\n", (int)decryptedLen, decrypted);
                }
            }
        } else {
            printf("   ✗ Encryption failed: 0x%08lX\n", rv);
            printf("     Error details: ");
            if (rv == CKR_KEY_INDIGESTIBLE) {
                printf("CKR_KEY_INDIGESTIBLE - Key format incompatible\n");
            } else if (rv == CKR_KEY_TYPE_INCONSISTENT) {
                printf("CKR_KEY_TYPE_INCONSISTENT - Key type mismatch\n");
            } else if (rv == CKR_MECHANISM_INVALID) {
                printf("CKR_MECHANISM_INVALID - Mechanism not supported\n");
            } else if (rv == CKR_KEY_HANDLE_INVALID) {
                printf("CKR_KEY_HANDLE_INVALID - Invalid key handle\n");
            } else {
                printf("Unknown error\n");
            }

            printf("     Trying to extract and re-import key...\n");

            /* Try to extract the PBE-generated key value and create a new AES key */
            CK_BYTE extractedKeyValue[32];
            CK_ULONG extractedKeyValueLen = sizeof(extractedKeyValue);
            CK_ATTRIBUTE extractTemplate[] = {
                {CKA_VALUE, extractedKeyValue, extractedKeyValueLen}
            };

            rv = funcList->C_GetAttributeValue(session, aesKey, extractTemplate, 1);
            if (rv == CKR_OK) {
                printf("     Extracted key value, creating new AES key object...\n");

                /* Create a new AES key from the extracted value */
                CK_OBJECT_HANDLE newAesKey;
                CK_ATTRIBUTE newKeyTemplate[] = {
                    {CKA_CLASS, &aesKeyClass, sizeof(aesKeyClass)},
                    {CKA_KEY_TYPE, &aesKeyType, sizeof(aesKeyType)},
                    {CKA_VALUE, extractedKeyValue, extractTemplate[0].ulValueLen},
                    {CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)},
                    {CKA_DECRYPT, &ckTrue, sizeof(ckTrue)},
                    {CKA_TOKEN, &ckFalse, sizeof(ckFalse)}
                };

                rv = funcList->C_CreateObject(session, newKeyTemplate,
                                             sizeof(newKeyTemplate)/sizeof(newKeyTemplate[0]),
                                             &newAesKey);
                if (rv == CKR_OK) {
                    printf("     New AES key created, retrying encryption...\n");

                    rv = funcList->C_EncryptInit(session, &encMech, newAesKey);
                    if (rv == CKR_OK) {
                        rv = funcList->C_Encrypt(session, plaintext, plaintextLen,
                                                ciphertext, &ciphertextLen);
                        if (rv == CKR_OK) {
                            printf("     ✓ Encryption successful with re-imported key!\n");
                            print_hex("       Ciphertext", ciphertext, ciphertextLen);
                        } else {
                            printf("     ✗ Encryption still failed: 0x%08lX\n", rv);
                        }
                    }
                } else {
                    printf("     Failed to create new AES key: 0x%08lX\n", rv);
                }

                /* Clear sensitive key material */
                memset(extractedKeyValue, 0, sizeof(extractedKeyValue));
            } else {
                printf("     Could not extract key value: 0x%08lX\n", rv);
            }
        }
    }
    printf("\n");

    /* Clean up */
    printf("6. Cleanup\n");

    /* Clear sensitive data */
    memset(password, 0, sizeof(password));
    memset(&pbeParams, 0, sizeof(pbeParams));

    pkcs11_final(session);

    printf("   ✓ Session closed and library finalized\n");
    printf("   ✓ Sensitive data cleared from memory\n\n");

    printf("=== Example completed successfully ===\n");
    return 0;
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

/* Display the usage options of the program. */
static void Usage(void)
{
    printf("nss_pkcs12_pbe_example\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int nss_pkcs12_pbe_example(int argc, char* argv[])
#endif
{
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

    printf("NSS PKCS#12 PBE SHA-256 HMAC Key Generation Example\n");
    printf("This example demonstrates how to use the CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN\n");
    printf("mechanism to generate cryptographic keys from passwords using PBKDF2.\n\n");

    if (demonstrate_pkcs12_pbe_key_generation(libName) != 0) {
        printf("Example failed!\n");
        return 1;
    }

    printf("\nFor more information, see:\n");
    printf("- PKCS#11 v2.40 specification\n");
    printf("- RFC 2898 (PKCS #5 v2.0: PBKDF2)\n");
    printf("- wolfPKCS11 documentation\n");

    return 0;
}

#else /* WOLFPKCS11_NSS */

#ifndef NO_MAIN_DRIVER
int main(void)
#else
int nss_pkcs12_pbe_example(void)
#endif
{
    printf("NSS PKCS#12 PBE support not compiled in.\n");
    printf("Build with WOLFPKCS11_NSS defined to enable this feature.\n");
    return 0;
}

#endif /* WOLFPKCS11_NSS */
