/* derive_key_type_test.c
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
 * Regression test for issue F-4065: C_DeriveKey must reject a base key whose
 * type does not match the derivation mechanism with
 * CKR_KEY_TYPE_INCONSISTENT.
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

#define TEST_DIR "./store/derive_key_type_test"

/* Derive with the given mechanism and wrong-typed base key, asserting
 * CKR_KEY_TYPE_INCONSISTENT, or skipping if the mechanism is not built in. */
static void check_wrong_type(CK_SESSION_HANDLE session, CK_MECHANISM* mech,
                             CK_OBJECT_HANDLE base, const char* op)
{
    CK_RV rv;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
    CK_ULONG valLen = 16;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_ATTRIBUTE outTmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_VALUE_LEN, &valLen,      sizeof(valLen)      },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
    };
    CK_OBJECT_HANDLE out = CK_INVALID_HANDLE;

    rv = funcList->C_DeriveKey(session, mech, base, outTmpl,
                               sizeof(outTmpl) / sizeof(*outTmpl), &out);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: %s (mechanism not supported)\n", op);
        test_passed++;
        return;
    }
    CHECK_RV(rv, op, CKR_KEY_TYPE_INCONSISTENT);
    if (rv == CKR_OK && out != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, out);
}

#ifdef WOLFPKCS11_NSS
/* NSS drives the TLS 1.3 key schedule by deriving from a CKO_DATA object. The
 * value it sends for that mechanism (PKCS#11 standard 0x402A) is the constant
 * wolfPKCS11 names CKM_HKDF_DERIVE, so the CKO_DATA base object reaches the
 * key-based derive case and must be accepted, not rejected as a key-type
 * mismatch. The CKA_DERIVE usage gate is skipped only in NSS builds, so this
 * path is reachable there. */
static void check_hkdf_data_object(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE hkdfType = CKK_HKDF;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    byte value[32];
    CK_ULONG valueLen = sizeof(value);
    CK_OBJECT_HANDLE dataObj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE out = CK_INVALID_HANDLE;
    CK_HKDF_PARAMS hkdf;
    CK_MECHANISM mech;
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS,   &dataClass, sizeof(dataClass) },
        { CKA_VALUE,   value,      sizeof(value)     },
        { CKA_PRIVATE, &ckFalse,   sizeof(ckFalse)   },
    };
    CK_ATTRIBUTE outTmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &hkdfType,    sizeof(hkdfType)    },
        { CKA_VALUE_LEN, &valueLen,    sizeof(valueLen)    },
        { CKA_DERIVE,    &ckTrue,      sizeof(ckTrue)      },
    };

    XMEMSET(value, 7, sizeof(value));
    rv = funcList->C_CreateObject(session, dataTmpl,
                                  sizeof(dataTmpl) / sizeof(*dataTmpl),
                                  &dataObj);
    CHECK_RV(rv, "C_CreateObject(CKO_DATA)", CKR_OK);
    if (rv != CKR_OK)
        return;

    XMEMSET(&hkdf, 0, sizeof(hkdf));
    hkdf.bExtract = CK_TRUE;
    hkdf.bExpand = CK_TRUE;
    hkdf.prfHashMechanism = CKM_SHA256;
    hkdf.ulSaltType = CKF_HKDF_SALT_NULL;
    hkdf.pInfo = value;
    hkdf.ulInfoLen = 8;
    mech.mechanism = CKM_HKDF_DERIVE;
    mech.pParameter = &hkdf;
    mech.ulParameterLen = sizeof(hkdf);
    rv = funcList->C_DeriveKey(session, &mech, dataObj, outTmpl,
                              sizeof(outTmpl) / sizeof(*outTmpl), &out);
    if (rv == CKR_MECHANISM_INVALID) {
        printf("SKIP: CKM_HKDF_DERIVE not supported in this build\n");
        test_passed++;
        return;
    }
    CHECK_RV(rv, "C_DeriveKey(CKM_HKDF_DERIVE, CKO_DATA base)", CKR_OK);
    if (rv == CKR_OK)
        funcList->C_DestroyObject(session, out);
}
#endif

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
    byte pub[65];
    byte param[32];
    CK_ECDH1_DERIVE_PARAMS ecdh;
    /* AES is the wrong base-key type for these mechanisms; CKA_DERIVE=TRUE so
     * the usage gate passes and the per-mechanism type check is exercised. */
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_VALUE,    aes_128_key,  sizeof(aes_128_key) },
        { CKA_DERIVE,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
    };
    CK_ULONG aesTmplCnt = sizeof(aesTmpl) / sizeof(*aesTmpl);

    XMEMSET(pub, 4, sizeof(pub));
    XMEMSET(param, 7, sizeof(param));

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    rv = pkcs11_open_session(&session);
    CHECK_RV(rv, "open session", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_CreateObject(session, aesTmpl, aesTmplCnt, &aesKey);
    CHECK_RV(rv, "C_CreateObject(AES base key)", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    /* ECDH derive expects a CKK_EC base key. */
    XMEMSET(&ecdh, 0, sizeof(ecdh));
    ecdh.kdf = CKD_NULL;
    ecdh.pPublicData = pub;
    ecdh.ulPublicDataLen = sizeof(pub);
    mech.mechanism = CKM_ECDH1_DERIVE;
    mech.pParameter = &ecdh;
    mech.ulParameterLen = sizeof(ecdh);
    check_wrong_type(session, &mech, aesKey, "ECDH1 derive with AES base key");

    /* DH derive expects a CKK_DH base key. */
    mech.mechanism = CKM_DH_PKCS_DERIVE;
    mech.pParameter = param;
    mech.ulParameterLen = sizeof(param);
    check_wrong_type(session, &mech, aesKey, "DH derive with AES base key");

#ifdef WOLFPKCS11_NSS
    check_hkdf_data_object(session);
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

    printf("=== wolfPKCS11 C_DeriveKey base-key-type test ===\n");
    run_test();
    return pkcs11_test_summary();
}
