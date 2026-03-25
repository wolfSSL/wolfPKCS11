/* rsa_exponent_test.c
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
 *
 * Test for RSA exponent byte-order handling in key generation.
 * Verifies that big-endian CKA_PUBLIC_EXPONENT values are correctly
 * interpreted during C_GenerateKeyPair, especially for non-palindromic
 * exponents where a byte-reversal bug would produce the wrong value.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/rsa.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)

#undef HAVE_ECC
#define NO_AES
#define NO_DH
#include "testdata.h"

/* Minimal unit test macros */
#define CHECK_COND(cond, ret, msg)                                         \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "\n%s:%d - %s - FAIL\n",                       \
                    __FILE__, __LINE__, msg);                              \
            ret = -1;                                                      \
        }                                                                  \
    }                                                                      \
    while (0)
#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if (rv != CKR_OK) {                                                \
            fprintf(stderr, "\n%s:%d - %s: %lx - FAIL\n",                  \
                    __FILE__, __LINE__, msg, rv);                          \
        }                                                                  \
    }                                                                      \
    while (0)
#define CHECK_CKR_FAIL(rv, exp, msg)                                       \
    do {                                                                   \
        if (rv != exp) {                                                   \
            fprintf(stderr, "\n%s:%d - %s RETURNED %lx - FAIL\n",          \
                    __FILE__, __LINE__, msg, rv);                          \
            if (rv == CKR_OK)                                              \
                rv = -1;                                                   \
        }                                                                  \
        else                                                               \
            rv = CKR_OK;                                                   \
    }                                                                      \
    while (0)

static int verbose = 0;

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static const char* tokenName = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_BBOOL ckTrue = CK_TRUE;

/* Standard palindromic exponent: 65537 = 0x010001 */
static unsigned char exp_65537[] = { 0x01, 0x00, 0x01 };

/* Non-palindromic exponent: 65539 = 0x010003
 * If byte-order is reversed, this becomes 0x030001 = 196611.
 * The byte-reversal bug in GetRsaExponentValue would cause the wrong
 * exponent to be used during key generation, leading to a mismatch
 * between the public key's exponent (from the template) and the
 * private key's actual exponent (from the buggy conversion).
 */
static unsigned char exp_65539[] = { 0x01, 0x00, 0x03 };

static unsigned char testPlaintext[32] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6d,
    0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66,
    0x6f, 0x72, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79
};

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_INFO info;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return -1;
    }

    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return -1;
    }

    ret = func(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: %lx\n", ret);
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: %lx\n", ret);
        return ret;
    }
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    CHECK_CKR(ret, "Initialize");

    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_CKR(ret, "Get Slot List");
    }

    if (ret == CKR_OK && slotCount > 0) {
        slot = slotList[0];
    }
    else if (ret == CKR_OK) {
        fprintf(stderr, "No slots available\n");
        ret = CKR_GENERAL_ERROR;
    }

    return ret;
}

static CK_RV pkcs11_final(void)
{
    funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    if (dlib) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    return CKR_OK;
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

static CK_RV pkcs11_set_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session for PIN setup");

    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login as SO");

        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(session, userPin, userPinLen);
            CHECK_CKR(ret, "Set User PIN - Init PIN");
        }

        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }

    return ret;
}

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
    CHECK_CKR(ret, "Open Session");

    if (ret == CKR_OK) {
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login");
    }

    return ret;
}

static CK_RV pkcs11_close_session(CK_SESSION_HANDLE session)
{
    CK_RV ret;

    ret = funcList->C_Logout(session);
    CHECK_CKR(ret, "Logout");

    if (ret == CKR_OK) {
        ret = funcList->C_CloseSession(session);
        CHECK_CKR(ret, "Close Session");
    }

    return ret;
}

/* Generate an RSA key pair with the given public exponent, then verify
 * the exponent is preserved and the key pair works for encrypt/decrypt.
 *
 * Returns CKR_OK on success (key works correctly).
 * Returns non-CKR_OK if any step fails.
 */
static CK_RV generate_and_test_rsa_exponent(CK_SESSION_HANDLE session,
                                             unsigned char* pubExp,
                                             CK_ULONG pubExpLen,
                                             const char* testName)
{
    CK_RV ret;
    CK_OBJECT_HANDLE pubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privKey = CK_INVALID_HANDLE;
    CK_ULONG bits = 2048;
    CK_MECHANISM mech;
    unsigned char keyId[] = { 0xEE, 0x01 };
    unsigned char readExpBuf[8];
    CK_ULONG readExpLen = sizeof(readExpBuf);
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    CK_ULONG encLen = sizeof(encrypted);
    CK_ULONG decLen = sizeof(decrypted);
    CK_MECHANISM encMech;

    CK_ATTRIBUTE pubKeyTmpl[] = {
        { CKA_MODULUS_BITS,    &bits,   sizeof(bits)   },
        { CKA_ENCRYPT,         &ckTrue, sizeof(ckTrue) },
        { CKA_VERIFY,          &ckTrue, sizeof(ckTrue) },
        { CKA_PUBLIC_EXPONENT, pubExp,  pubExpLen       },
        { CKA_TOKEN,           &ckTrue, sizeof(ckTrue) },
        { CKA_ID,              keyId,   sizeof(keyId)  }
    };
    int pubTmplCnt = sizeof(pubKeyTmpl) / sizeof(*pubKeyTmpl);
    CK_ATTRIBUTE privKeyTmpl[] = {
        { CKA_DECRYPT,  &ckTrue, sizeof(ckTrue) },
        { CKA_SIGN,     &ckTrue, sizeof(ckTrue) },
        { CKA_TOKEN,    &ckTrue, sizeof(ckTrue) },
        { CKA_ID,       keyId,   sizeof(keyId)  }
    };
    int privTmplCnt = sizeof(privKeyTmpl) / sizeof(*privKeyTmpl);

    CK_ATTRIBUTE getExpTmpl[] = {
        { CKA_PUBLIC_EXPONENT, readExpBuf, readExpLen }
    };

    printf("  %s: Generating RSA key pair with exponent 0x", testName);
    {
        CK_ULONG j;
        for (j = 0; j < pubExpLen; j++)
            printf("%02x", pubExp[j]);
    }
    printf("...\n");

    /* Step 1: Generate key pair */
    mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl,
                       pubTmplCnt, privKeyTmpl, privTmplCnt, &pubKey, &privKey);
    CHECK_CKR(ret, "RSA Generate Key Pair");
    if (ret != CKR_OK) {
        fprintf(stderr, "  %s: Key generation failed\n", testName);
        return ret;
    }

    /* Step 2: Read back the public exponent from the generated public key */
    getExpTmpl[0].ulValueLen = sizeof(readExpBuf);
    ret = funcList->C_GetAttributeValue(session, pubKey, getExpTmpl, 1);
    CHECK_CKR(ret, "Get Public Exponent");
    if (ret != CKR_OK) {
        fprintf(stderr, "  %s: Failed to read back public exponent\n",
                testName);
        goto cleanup;
    }

    readExpLen = getExpTmpl[0].ulValueLen;

    /* Verify the exponent matches what we requested */
    if (readExpLen != pubExpLen ||
        XMEMCMP(readExpBuf, pubExp, pubExpLen) != 0) {
        fprintf(stderr, "  %s: Public exponent mismatch!\n", testName);
        fprintf(stderr, "    Expected: 0x");
        {
            CK_ULONG j;
            for (j = 0; j < pubExpLen; j++)
                fprintf(stderr, "%02x", pubExp[j]);
        }
        fprintf(stderr, "\n    Got:      0x");
        {
            CK_ULONG j;
            for (j = 0; j < readExpLen; j++)
                fprintf(stderr, "%02x", readExpBuf[j]);
        }
        fprintf(stderr, "\n");
        ret = CKR_GENERAL_ERROR;
        goto cleanup;
    }

    printf("  %s: Public exponent read back correctly\n", testName);

    /* Step 3: Encrypt with public key */
    encMech.mechanism = CKM_RSA_PKCS;
    encMech.pParameter = NULL;
    encMech.ulParameterLen = 0;

    ret = funcList->C_EncryptInit(session, &encMech, pubKey);
    CHECK_CKR(ret, "RSA Encrypt Init");
    if (ret != CKR_OK) {
        fprintf(stderr, "  %s: Encrypt init failed\n", testName);
        goto cleanup;
    }

    ret = funcList->C_Encrypt(session, testPlaintext, sizeof(testPlaintext),
                              encrypted, &encLen);
    CHECK_CKR(ret, "RSA Encrypt");
    if (ret != CKR_OK) {
        fprintf(stderr, "  %s: Encrypt failed\n", testName);
        goto cleanup;
    }

    /* Step 4: Decrypt with private key */
    ret = funcList->C_DecryptInit(session, &encMech, privKey);
    CHECK_CKR(ret, "RSA Decrypt Init");
    if (ret != CKR_OK) {
        fprintf(stderr, "  %s: Decrypt init failed\n", testName);
        goto cleanup;
    }

    ret = funcList->C_Decrypt(session, encrypted, encLen,
                              decrypted, &decLen);
    CHECK_CKR(ret, "RSA Decrypt");
    if (ret != CKR_OK) {
        fprintf(stderr, "  %s: Decrypt failed\n", testName);
        goto cleanup;
    }

    /* Step 5: Verify plaintext roundtrip */
    if (decLen != sizeof(testPlaintext) ||
        XMEMCMP(decrypted, testPlaintext, decLen) != 0) {
        fprintf(stderr, "  %s: Decrypted data doesn't match original!\n",
                testName);
        fprintf(stderr, "    Original length: %lu, decrypted length: %lu\n",
                (unsigned long)sizeof(testPlaintext), (unsigned long)decLen);
        ret = CKR_GENERAL_ERROR;
        goto cleanup;
    }

    printf("  %s: Encrypt/decrypt roundtrip PASSED\n", testName);

cleanup:
    if (pubKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pubKey);
    if (privKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, privKey);

    /* Suppress unused variable warnings from testdata.h */
    (void)rsa_2048_u;
    (void)rsa_2048_dQ;
    (void)rsa_2048_dP;
    (void)rsa_2048_q;
    (void)rsa_2048_p;
    (void)rsa_2048_priv_exp;
    (void)rsa_2048_modulus;
    (void)rsa_2048_pub_exp;

    return ret;
}

static CK_RV rsa_exponent_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    printf("RSA Exponent Byte-Order Test\n");
    printf("============================\n");

    /* Initialize PKCS#11 */
    ret = pkcs11_init();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize PKCS#11\n");
        return ret;
    }

    ret = pkcs11_init_token();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to initialize token\n");
        goto cleanup;
    }

    ret = pkcs11_set_user_pin();
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to set user PIN\n");
        goto cleanup;
    }

    ret = pkcs11_open_session(&session);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to open session\n");
        goto cleanup;
    }

    /* Test 1: Palindromic exponent 65537 (0x010001) - control test.
     * This should always pass regardless of byte-order handling because
     * the big-endian byte sequence {0x01, 0x00, 0x01} reads the same
     * forwards and backwards.
     */
    printf("\nTest 1: Palindromic exponent (65537 = 0x010001)\n");
    ret = generate_and_test_rsa_exponent(session, exp_65537,
                                         sizeof(exp_65537),
                                         "palindromic-65537");
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: Palindromic exponent test failed\n");
        goto cleanup;
    }
    printf("  PASSED\n");

    /* Test 2: Non-palindromic exponent 65539 (0x010003) - bug trigger.
     * If GetRsaExponentValue reads bytes in little-endian order (the bug),
     * it will interpret {0x01, 0x00, 0x03} as 0x030001 = 196611 instead
     * of the correct 0x010003 = 65539. The key will be generated with
     * exponent 196611 but the public key object retains exponent 65539,
     * causing encrypt/decrypt to fail.
     */
    printf("\nTest 2: Non-palindromic exponent (65539 = 0x010003)\n");
    ret = generate_and_test_rsa_exponent(session, exp_65539,
                                         sizeof(exp_65539),
                                         "non-palindromic-65539");
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: Non-palindromic exponent test failed\n");
        fprintf(stderr, "  This is the expected failure for bug #1311:\n");
        fprintf(stderr, "  GetRsaExponentValue reads big-endian data in "
                        "little-endian order.\n");
        fprintf(stderr, "  Exponent 65539 (0x010003) was likely interpreted "
                        "as 196611 (0x030001).\n");
        goto cleanup;
    }
    printf("  PASSED\n");

cleanup:
    if (session != CK_INVALID_HANDLE)
        pkcs11_close_session(session);
    pkcs11_final();
    return ret;
}

#endif /* !NO_RSA && WOLFSSL_KEY_GEN */

int main(int argc, char* argv[])
{
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    CK_RV ret;

#ifndef WOLFPKCS11_NO_ENV
    if (!XGETENV("WOLFPKCS11_TOKEN_PATH")) {
        XSETENV("WOLFPKCS11_TOKEN_PATH", "./store/rsa_exp_test", 1);
    }
#endif

    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        verbose = 1;
        printf("Verbose mode enabled.\n");
    }

    printf("wolfPKCS11 RSA Exponent Byte-Order Test\n");
    printf("========================================\n\n");

    ret = rsa_exponent_test();
    if (ret == CKR_OK) {
        printf("\nAll tests passed!\n");
        return 0;
    }
    else {
        printf("\nTest failed with error: %lx\n", ret);
        return 1;
    }
#else
    (void)argc;
    (void)argv;
    printf("RSA or KeyGen not compiled in, skipping.\n");
    return 77;
#endif
}
