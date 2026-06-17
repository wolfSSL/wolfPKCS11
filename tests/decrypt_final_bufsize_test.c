/* decrypt_final_bufsize_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 * Regression test for issue F-6050. The CKM_AES_CBC_PAD branch of
 * C_DecryptFinal handed WP11_AesCbcPad_DecryptFinal the buffered block length
 * (16) instead of the caller's output-buffer capacity, so the helper's
 * BUFFER_E guard could never fire and an undersized caller buffer was
 * overflowed by up to 15 bytes. C_DecryptFinal must return
 * CKR_BUFFER_TOO_SMALL for a too-small buffer like the GCM/CTS branches.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>

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

#include "testdata.h"

#define TEST_DIR "./store/decrypt_final_bufsize_test"

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_RV(rv, op, expected) do {                                       \
    if ((rv) != (expected)) {                                                 \
        fprintf(stderr, "FAIL: %s: expected 0x%lx, got 0x%lx\n", op,          \
                (unsigned long)(expected), (unsigned long)(rv));              \
        test_failed++;                                                        \
    } else {                                                                  \
        printf("PASS: %s\n", op);                                             \
        test_passed++;                                                        \
    }                                                                         \
} while (0)

#define CHECK_TRUE(cond, op) do {                                             \
    if (!(cond)) {                                                            \
        fprintf(stderr, "FAIL: %s\n", op);                                    \
        test_failed++;                                                        \
    } else {                                                                  \
        printf("PASS: %s\n", op);                                             \
        test_passed++;                                                        \
    }                                                                         \
} while (0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;

static CK_RV pkcs11_load(void)
{
    CK_RV ret;
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return CKR_GENERAL_ERROR;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK)
        return ret;
#endif
    return CKR_OK;
}

static void pkcs11_unload(void)
{
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    funcList = NULL;
}

static int run_test(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = 0;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_MECHANISM mech;
    byte iv[16];
    /* 15-byte plaintext -> one padded block; the held-back final block
     * unpads to 15 bytes, the maximum, maximising the overflow window. */
    byte plain[15];
    byte enc[32];
    byte upd[32];
    byte lastPart[32];
    CK_ULONG encSz = sizeof(enc);
    CK_ULONG updSz;
    CK_ULONG lastPartLen;
    int i;
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG aesTmplCnt = sizeof(aesTmpl) / sizeof(*aesTmpl);

    XMEMSET(iv, 9, sizeof(iv));
    XMEMSET(plain, 7, sizeof(plain));

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    CHECK_RV(rv, "C_GetSlotList", CKR_OK);
    if (rv != CKR_OK || slotCount == 0)
        goto out;
    slot = slotList[0];

    rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_RV(rv, "C_OpenSession", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, aesTmpl, aesTmplCnt, &aesKey);
    CHECK_RV(rv, "C_CreateObject(AES key)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    XMEMSET(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_AES_CBC_PAD;
    mech.pParameter = iv;
    mech.ulParameterLen = sizeof(iv);

    /* Encrypt: 15 bytes -> 16 bytes ciphertext. */
    rv = funcList->C_EncryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_EncryptInit", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    encSz = sizeof(enc);
    rv = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encSz);
    CHECK_RV(rv, "C_Encrypt", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    CHECK_TRUE(encSz == 16, "ciphertext is one block");

    /* Baseline: a complete multi-part decrypt with an adequate final buffer
     * still round-trips the plaintext after the fix. */
    rv = funcList->C_DecryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_DecryptInit (baseline)", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    updSz = sizeof(upd);
    rv = funcList->C_DecryptUpdate(session, enc, encSz, upd, &updSz);
    CHECK_RV(rv, "C_DecryptUpdate (baseline)", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    CHECK_TRUE(updSz == 0, "DecryptUpdate holds back final block");
    lastPartLen = sizeof(lastPart);
    rv = funcList->C_DecryptFinal(session, lastPart, &lastPartLen);
    CHECK_RV(rv, "C_DecryptFinal (adequate buffer)", CKR_OK);
    CHECK_TRUE(lastPartLen == sizeof(plain) &&
               XMEMCMP(lastPart, plain, sizeof(plain)) == 0,
               "plaintext round-trips with adequate buffer");

    /* Fresh decrypt that supplies an undersized final buffer: claim only 4
     * bytes of capacity and guard the rest with a canary. C_DecryptFinal must
     * return CKR_BUFFER_TOO_SMALL without writing past the 4 bytes. Pre-fix it
     * wrote up to 15 bytes and returned CKR_OK, overflowing the buffer. */
    rv = funcList->C_DecryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_DecryptInit (undersized)", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    updSz = sizeof(upd);
    rv = funcList->C_DecryptUpdate(session, enc, encSz, upd, &updSz);
    CHECK_RV(rv, "C_DecryptUpdate (undersized)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    /* Size query reports the maximum unpadded size (15). */
    lastPartLen = 0;
    rv = funcList->C_DecryptFinal(session, NULL, &lastPartLen);
    CHECK_RV(rv, "C_DecryptFinal size query", CKR_OK);
    CHECK_TRUE(lastPartLen == 15, "size query reports 15");

    XMEMSET(lastPart, 0xAB, sizeof(lastPart));
    lastPartLen = 4;
    rv = funcList->C_DecryptFinal(session, lastPart, &lastPartLen);
    CHECK_RV(rv, "C_DecryptFinal(undersized buffer)", CKR_BUFFER_TOO_SMALL);

    for (i = 4; i < (int)sizeof(lastPart); i++) {
        if (lastPart[i] != 0xAB)
            break;
    }
    CHECK_TRUE(i == (int)sizeof(lastPart),
               "no write past the caller-declared buffer length");

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 C_DecryptFinal CBC-PAD buffer-size test ===\n");
    run_test();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");

    return (test_failed == 0) ? 0 : 1;
}
