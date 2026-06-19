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
 * Regression test for issue F-6050: the CKM_AES_CBC_PAD branch of
 * C_DecryptFinal must report CKR_BUFFER_TOO_SMALL for an undersized output
 * buffer instead of overflowing it.
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
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/decrypt_final_bufsize_test"

static int run_test(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_MECHANISM mech;
    byte iv[16];
    /* 15-byte plaintext -> one padded block whose final block unpads to 15
     * bytes, the maximum unpadded size. */
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

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
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

    /* Baseline: a full multi-part decrypt with an adequate final buffer
     * round-trips the plaintext. */
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

    /* Undersized final buffer: claim 4 bytes and guard the rest with a
     * canary. C_DecryptFinal must report CKR_BUFFER_TOO_SMALL without writing
     * past the 4 bytes. */
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
    return pkcs11_test_summary();
}
