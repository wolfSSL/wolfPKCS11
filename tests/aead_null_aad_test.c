/* aead_null_aad_test.c
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
 * Regression test for issue F-5514: AES-GCM and AES-CCM C_EncryptInit must
 * reject a NULL AAD pointer paired with a non-zero AAD length with
 * CKR_MECHANISM_PARAM_INVALID.
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

#define TEST_DIR "./store/aead_null_aad_test"

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
    CK_GCM_PARAMS gcm;
    CK_CCM_PARAMS ccm;
    byte iv[12];
    byte aad[16];
    byte plain[32], enc[64];
    CK_ULONG encSz;
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG aesTmplCnt = sizeof(aesTmpl) / sizeof(*aesTmpl);

    XMEMSET(iv, 9, sizeof(iv));
    XMEMSET(aad, 5, sizeof(aad));
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

    /* GCM: NULL AAD pointer with a non-zero AAD length must be rejected. */
    XMEMSET(&gcm, 0, sizeof(gcm));
    gcm.pIv = iv;
    gcm.ulIvLen = sizeof(iv);
    gcm.pAAD = NULL;
    gcm.ulAADLen = sizeof(aad);
    gcm.ulTagBits = 128;
    mech.mechanism = CKM_AES_GCM;
    mech.pParameter = &gcm;
    mech.ulParameterLen = sizeof(gcm);
    rv = funcList->C_EncryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_EncryptInit GCM (NULL AAD, len 16)",
             CKR_MECHANISM_PARAM_INVALID);

    /* CCM: same mismatch; skip if AES-CCM is not built in. */
    XMEMSET(&ccm, 0, sizeof(ccm));
    ccm.ulDataLen = sizeof(plain);
    ccm.pIv = iv;
    ccm.ulIvLen = sizeof(iv) - 5; /* 7-byte nonce is valid for CCM */
    ccm.pAAD = NULL;
    ccm.ulAADLen = sizeof(aad);
    ccm.ulMacLen = 16;
    mech.mechanism = CKM_AES_CCM;
    mech.pParameter = &ccm;
    mech.ulParameterLen = sizeof(ccm);
    rv = funcList->C_EncryptInit(session, &mech, aesKey);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: AES-CCM not supported in this build\n");
        test_passed++;
    }
    else {
        CHECK_RV(rv, "C_EncryptInit CCM (NULL AAD, len 16)",
                 CKR_MECHANISM_PARAM_INVALID);
    }

    /* The canonical no-AAD form (NULL pointer, zero length) is still valid. */
    XMEMSET(&gcm, 0, sizeof(gcm));
    gcm.pIv = iv;
    gcm.ulIvLen = sizeof(iv);
    gcm.pAAD = NULL;
    gcm.ulAADLen = 0;
    gcm.ulTagBits = 128;
    mech.mechanism = CKM_AES_GCM;
    mech.pParameter = &gcm;
    mech.ulParameterLen = sizeof(gcm);
    rv = funcList->C_EncryptInit(session, &mech, aesKey);
    CHECK_RV(rv, "C_EncryptInit GCM (NULL AAD, len 0)", CKR_OK);
    if (rv == CKR_OK) {
        encSz = sizeof(enc);
        rv = funcList->C_Encrypt(session, plain, sizeof(plain), enc, &encSz);
        CHECK_RV(rv, "C_Encrypt GCM (no AAD) completes", CKR_OK);
    }

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

    printf("=== wolfPKCS11 AEAD NULL-AAD mismatch test ===\n");
    run_test();
    return pkcs11_test_summary();
}
