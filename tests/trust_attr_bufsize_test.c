/* trust_attr_bufsize_test.c
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
 * Regression test for issue F-4060. GetTrustAttr overwrote the caller's *len
 * with sizeof(CK_ULONG)/sizeof(CK_BBOOL) before delegating to GetULong/GetBool,
 * defeating their buffer-too-small check and overflowing an undersized caller
 * buffer for the NSS trust ULONG/BOOL attributes. C_GetAttributeValue must
 * report CKR_BUFFER_TOO_SMALL instead. NSS-only; skipped otherwise.
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

#define TEST_DIR "./store/trust_attr_bufsize_test"

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
#ifdef WOLFPKCS11_NSS
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS trustClass = CKO_NSS_TRUST;
    CK_BBOOL ckTrue = CK_TRUE;
    static byte issuer[] = "CN=Test,O=wolfSSL,C=US";
    static byte serial[] = { 0x02, 0x05, 0x00, 0xC6, 0xA7, 0x91, 0x84 };
    static byte sha1_hash[20] = { 0 };
    static byte md5_hash[16] = { 0 };
    CK_ULONG trustValue = 0xCE534352;
    CK_BBOOL stepUp = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,                  &ckTrue,     sizeof(ckTrue)      },
        { CKA_CLASS,                  &trustClass, sizeof(trustClass)  },
        { CKA_ISSUER,                 issuer,      sizeof(issuer) - 1  },
        { CKA_SERIAL_NUMBER,          serial,      sizeof(serial)      },
        { CKA_CERT_SHA1_HASH,         sha1_hash,   sizeof(sha1_hash)   },
        { CKA_CERT_MD5_HASH,          md5_hash,    sizeof(md5_hash)    },
        { CKA_TRUST_SERVER_AUTH,      &trustValue, sizeof(trustValue)  },
        { CKA_TRUST_CLIENT_AUTH,      &trustValue, sizeof(trustValue)  },
        { CKA_TRUST_CODE_SIGNING,     &trustValue, sizeof(trustValue)  },
        { CKA_TRUST_EMAIL_PROTECTION, &trustValue, sizeof(trustValue)  },
        { CKA_TRUST_STEP_UP_APPROVED, &stepUp,     sizeof(stepUp)      },
    };
    CK_ULONG tmplCnt = sizeof(tmpl) / sizeof(*tmpl);
    CK_ATTRIBUTE getAttr;
    byte buffer[sizeof(CK_ULONG)];
    int i;
#endif

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

#ifndef WOLFPKCS11_NSS
    /* Trust objects and the CKA_TRUST_* attributes only exist in NSS builds. */
    printf("SKIP: NSS trust objects not supported in this build\n");
    test_passed++;
#else
    rv = funcList->C_CreateObject(session, tmpl, tmplCnt, &obj);
    CHECK_RV(rv, "C_CreateObject(NSS trust)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    /* Size query reports sizeof(CK_ULONG). */
    getAttr.type = CKA_TRUST_SERVER_AUTH;
    getAttr.pValue = NULL;
    getAttr.ulValueLen = 0;
    rv = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
    CHECK_RV(rv, "size query CKA_TRUST_SERVER_AUTH", CKR_OK);
    CHECK_TRUE(getAttr.ulValueLen == sizeof(CK_ULONG),
               "size query reports sizeof(CK_ULONG)");

    /* Undersized buffer: claim only 4 bytes and guard the rest. Must report
     * CKR_BUFFER_TOO_SMALL without writing past the 4 bytes. Pre-fix this
     * wrote sizeof(CK_ULONG) bytes, overflowing the buffer. */
    XMEMSET(buffer, 0xAB, sizeof(buffer));
    getAttr.type = CKA_TRUST_SERVER_AUTH;
    getAttr.pValue = buffer;
    getAttr.ulValueLen = 4;
    rv = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
    CHECK_RV(rv, "undersized CKA_TRUST_SERVER_AUTH", CKR_BUFFER_TOO_SMALL);
    for (i = 4; i < (int)sizeof(buffer); i++) {
        if (buffer[i] != 0xAB)
            break;
    }
    CHECK_TRUE(i == (int)sizeof(buffer),
               "no write past the caller-declared buffer length");

    /* The STEP_UP boolean attribute has the same flaw via GetBool. */
    XMEMSET(buffer, 0xAB, sizeof(buffer));
    getAttr.type = CKA_TRUST_STEP_UP_APPROVED;
    getAttr.pValue = buffer;
    getAttr.ulValueLen = 0;
    rv = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
    CHECK_RV(rv, "undersized CKA_TRUST_STEP_UP_APPROVED",
             CKR_BUFFER_TOO_SMALL);
    CHECK_TRUE(buffer[0] == 0xAB, "no write into zero-length bool buffer");

    /* An adequately sized buffer still returns the value. */
    getAttr.type = CKA_TRUST_SERVER_AUTH;
    getAttr.pValue = buffer;
    getAttr.ulValueLen = sizeof(buffer);
    rv = funcList->C_GetAttributeValue(session, obj, &getAttr, 1);
    CHECK_RV(rv, "adequate CKA_TRUST_SERVER_AUTH", CKR_OK);
    CHECK_TRUE(getAttr.ulValueLen == sizeof(CK_ULONG),
               "adequate buffer returns sizeof(CK_ULONG)");
#endif

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

    printf("=== wolfPKCS11 NSS trust attribute buffer-size test ===\n");
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
