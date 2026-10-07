/* object_policy_integrity_test.c
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
 * The policy attributes of a protected token key are only honored when they
 * match the policy the key material was stored under. Legitimate attribute
 * updates, PIN changes and stores written before the policy was bound must
 * keep working. Each reload runs in a child process.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>
#include <wolfpkcs11/internal.h>

#ifndef HAVE_PKCS11_STATIC
    #include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_TPM_STORE) && \
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_NO_ENV) && \
    !defined(_WIN32) && !defined(NO_AES) && defined(HAVE_AESGCM) && \
    defined(HAVE_AES_CBC)

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_DIR        "./store/object_policy_integrity_test"
#define MAX_OBJ_ID      8
#define MAX_FILE_SZ     16384

/* Offsets of the class and operational flags in a stored object record. */
#define OBJ_CLASS_OFF   (12 + sizeof(CK_ULONG))
#define OBJ_FLAGS_OFF   (12 + 3 * sizeof(CK_ULONG) + 1 + 1 + 4)
#define OBJ_IV_SZ       12
#define TAG_SZ          16
#define BLOCK_SZ        16

#define CHILD_PASS      0
#define CHILD_FAIL      1
#define CHILD_SETUP     2

static byte soPin[] = "password123456";
static byte userPin[] = "wolfpkcs11-test";
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static const char* storeKinds[] = {
    "obj", "data", "symmkey", "rsakey_priv", "rsakey_pub", "ecckey_priv",
    "ecckey_pub", "dhkey_priv", "dhkey_pub", "cert", "trust", "mldsakey_priv",
    "mldsakey_pub", "mlkemkey_priv", "mlkemkey_pub"
};

static byte aesKeyValue[32] = {
    0x2f, 0x91, 0x0c, 0x6a, 0xd3, 0x48, 0x75, 0xbe,
    0x13, 0xe0, 0x5c, 0x87, 0x29, 0xfa, 0x64, 0x0b,
    0xc8, 0x3d, 0x9e, 0x51, 0x06, 0xb7, 0x7a, 0x22,
    0xe4, 0x1f, 0x98, 0x6d, 0x30, 0xab, 0x55, 0xc1
};
static byte refPlain[BLOCK_SZ] = {
    0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2d, 0x72,
    0x65, 0x66, 0x2d, 0x62, 0x6c, 0x6f, 0x63, 0x6b
};
static byte refCipher[BLOCK_SZ];

/* Parameters of the current check, read by the child process. */
static CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
static CK_ATTRIBUTE_TYPE secretAttr = CKA_VALUE;
static const byte* secretNeedle = NULL;
static size_t secretNeedleSz = 0;
static int checkAesUse = 0;
static CK_MECHANISM_TYPE signMech = CKM_VENDOR_DEFINED;
static CK_BBOOL expSensitive = CK_TRUE;
static CK_BBOOL expExtractable = CK_FALSE;
static CK_BBOOL expDecrypt = CK_TRUE;

static void store_path(char* path, size_t sz, const char* kind, int objId)
{
    if (objId < 0) {
        (void)snprintf(path, sz, "%s/wp11_%s_%016lx", TEST_DIR, kind, 1UL);
    }
    else {
        (void)snprintf(path, sz, "%s/wp11_%s_%016lx_%016lx", TEST_DIR, kind,
                       1UL, (unsigned long)objId);
    }
}

static void cleanup_test_files(void)
{
    char path[256];
    size_t k;
    int i;

    for (k = 0; k < sizeof(storeKinds) / sizeof(*storeKinds); k++) {
        for (i = 0; i < MAX_OBJ_ID; i++) {
            store_path(path, sizeof(path), storeKinds[k], i);
            (void)remove(path);
        }
    }
    store_path(path, sizeof(path), "token", -1);
    (void)remove(path);
}

/* Locate the stored file of the given kind for its single object. */
static int find_store_file(const char* kind, char* path, size_t sz)
{
    FILE* f;
    int i;

    for (i = 0; i < MAX_OBJ_ID; i++) {
        store_path(path, sz, kind, i);
        f = fopen(path, "rb");
        if (f != NULL) {
            fclose(f);
            return 0;
        }
    }
    return -1;
}

static int read_file(const char* path, byte* data, size_t sz, size_t* readSz)
{
    FILE* f = fopen(path, "rb");

    if (f == NULL)
        return -1;
    *readSz = fread(data, 1, sz, f);
    if (ferror(f) || !feof(f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int write_file(const char* path, const byte* data, size_t sz)
{
    FILE* f = fopen(path, "wb");
    size_t written;

    if (f == NULL)
        return -1;
    written = fwrite(data, 1, sz, f);
    if (fclose(f) != 0 || written != sz)
        return -1;
    return 0;
}

static word32 get_be32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16) |
           ((word32)p[2] << 8) | (word32)p[3];
}

static void put_be32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)v;
}

static CK_ULONG get_be_ulong(const byte* p)
{
    CK_ULONG v = 0;
    size_t i;

    for (i = 0; i < sizeof(CK_ULONG); i++)
        v = (v << 8) | p[i];
    return v;
}

/* Rewrite the stored flags of the object of the checked class so they read as
 * exportable. */
static int mark_stored_key_exportable(void)
{
    static byte data[MAX_FILE_SZ];
    char path[256];
    size_t sz = 0;
    word32 flags;
    int i;
    int found = 0;

    for (i = 0; i < MAX_OBJ_ID && !found; i++) {
        store_path(path, sizeof(path), "obj", i);
        if (read_file(path, data, sizeof(data), &sz) == 0 &&
                sz >= OBJ_FLAGS_OFF + 4 &&
                get_be_ulong(data + OBJ_CLASS_OFF) == keyClass) {
            found = 1;
        }
    }
    if (!found)
        return -1;
    flags = get_be32(data + OBJ_FLAGS_OFF);
    if ((flags & WP11_FLAG_SENSITIVE) == 0 ||
            (flags & WP11_FLAG_EXTRACTABLE) != 0)
        return -1;
    flags &= ~(word32)WP11_FLAG_SENSITIVE;
    flags |= WP11_FLAG_EXTRACTABLE;
    put_be32(data + OBJ_FLAGS_OFF, flags);
    return write_file(path, data, sz);
}

static CK_RV init_slot(CK_SLOT_ID* slot)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slots[16];
    CK_ULONG count = sizeof(slots) / sizeof(*slots);

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    if (rv == CKR_OK)
        rv = funcList->C_GetSlotList(CK_TRUE, slots, &count);
    if (rv == CKR_OK && count == 0)
        rv = CKR_TOKEN_NOT_PRESENT;
    if (rv == CKR_OK)
        *slot = slots[0];
    return rv;
}

static CK_RV provision_token(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_UTF8CHAR label[32];
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "wolfpkcs11", 10);
    rv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    if (rv == CKR_OK)
        rv = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    if (rv == CKR_OK)
        rv = funcList->C_Login(session, CKU_SO, soPin, sizeof(soPin) - 1);
    if (rv == CKR_OK)
        rv = funcList->C_InitPIN(session, userPin, sizeof(userPin) - 1);
    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }
    return rv;
}

static CK_RV open_session(CK_SLOT_ID slot, int login,
                          CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    rv = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    if (rv == CKR_OK && login) {
        rv = funcList->C_Login(*session, CKU_USER, userPin,
                               (CK_ULONG)sizeof(userPin) - 1);
    }
    return rv;
}

static CK_RV find_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    CK_RV rv;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
    };

    rv = funcList->C_FindObjectsInit(session, tmpl, 1);
    if (rv == CKR_OK) {
        rv = funcList->C_FindObjects(session, obj, 1, &count);
        (void)funcList->C_FindObjectsFinal(session);
    }
    if (rv == CKR_OK && count != 1)
        rv = CKR_OBJECT_HANDLE_INVALID;
    return rv;
}

static CK_RV aes_encrypt_block(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                               byte* out)
{
    CK_RV rv;
    byte iv[BLOCK_SZ];
    CK_MECHANISM mech;
    CK_ULONG outSz = BLOCK_SZ;

    XMEMSET(iv, 0, sizeof(iv));
    mech.mechanism = CKM_AES_CBC;
    mech.pParameter = iv;
    mech.ulParameterLen = sizeof(iv);
    rv = funcList->C_EncryptInit(session, &mech, obj);
    if (rv == CKR_OK)
        rv = funcList->C_Encrypt(session, refPlain, sizeof(refPlain), out,
                                 &outSz);
    if (rv == CKR_OK && outSz != BLOCK_SZ)
        rv = CKR_FUNCTION_FAILED;
    return rv;
}

/* Sign a fixed digest-sized message with the key. */
static CK_RV sign_block(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{
    CK_RV rv;
    CK_MECHANISM mech;
    byte msg[32];
    static byte sig[8192];
    CK_ULONG sigSz = sizeof(sig);

    XMEMSET(msg, 0x5a, sizeof(msg));
    mech.mechanism = signMech;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    rv = funcList->C_SignInit(session, &mech, obj);
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, msg, sizeof(msg), sig, &sigSz);
    return rv;
}

static CK_RV get_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                      CK_ATTRIBUTE_TYPE type, CK_BBOOL* val)
{
    CK_ATTRIBUTE attr;

    attr.type = type;
    attr.pValue = val;
    attr.ulValueLen = sizeof(*val);
    return funcList->C_GetAttributeValue(session, obj, &attr, 1);
}

typedef CK_RV (*create_fn)(CK_SESSION_HANDLE session);

/* Provision a fresh token, create objects with 'create' and persist them. */
static CK_RV store_objects(create_fn create)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    cleanup_test_files();
    rv = pkcs11_load();
    if (rv != CKR_OK)
        return rv;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = provision_token(slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = create(session);
    if (session != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(session);
    (void)funcList->C_Finalize(NULL);
    pkcs11_unload();
    return rv;
}

typedef int (*child_fn)(void);

/* Run fn in a child process. Returns CHILD_PASS only when it exits normally
 * reporting that the invariant held. */
static int run_in_child(child_fn fn)
{
    pid_t pid;
    int status = 0;

    fflush(stdout);
    fflush(stderr);
    pid = fork();
    if (pid < 0)
        return CHILD_SETUP;
    if (pid == 0) {
        int res = fn();
        fflush(stdout);
        fflush(stderr);
        _exit(res);
    }
    if (waitpid(pid, &status, 0) != pid)
        return CHILD_SETUP;
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "  reload terminated by signal %d\n",
                WTERMSIG(status));
        return CHILD_FAIL;
    }
    if (!WIFEXITED(status))
        return CHILD_FAIL;
    return WEXITSTATUS(status);
}

/* After logging in, the key signs. */
static int child_key_signs(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK)
        rv = sign_block(session, obj);
    (void)funcList->C_Finalize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "  signing after reload failed: 0x%lx\n",
                (unsigned long)rv);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static int holds_secret(const byte* buf, size_t sz)
{
    size_t i;

    if (secretNeedle == NULL || sz < secretNeedleSz)
        return 0;
    for (i = 0; i + secretNeedleSz <= sz; i++) {
        if (XMEMCMP(buf + i, secretNeedle, secretNeedleSz) == 0)
            return 1;
    }
    return 0;
}

static CK_RV create_aes_key_ex(CK_SESSION_HANDLE session, CK_BBOOL priv,
                               CK_BBOOL sensitive, CK_BBOOL extractable)
{
    CK_RV rv;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &cls,        sizeof(cls)         },
        { CKA_KEY_TYPE,    &keyType,    sizeof(keyType)     },
        { CKA_TOKEN,       &ckTrue,     sizeof(ckTrue)      },
        { CKA_PRIVATE,     &priv,       sizeof(priv)        },
        { CKA_SENSITIVE,   &sensitive,  sizeof(sensitive)   },
        { CKA_EXTRACTABLE, &extractable, sizeof(extractable) },
        { CKA_ENCRYPT,     &ckTrue,     sizeof(ckTrue)      },
        { CKA_DECRYPT,     &ckTrue,     sizeof(ckTrue)      },
        { CKA_VALUE,       aesKeyValue, sizeof(aesKeyValue) },
    };

    rv = funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
    if (rv == CKR_OK)
        rv = aes_encrypt_block(session, obj, refCipher);
    return rv;
}

static CK_RV create_aes_key(CK_SESSION_HANDLE session)
{
    return create_aes_key_ex(session, CK_TRUE, CK_TRUE, CK_FALSE);
}

#ifdef HAVE_ECC
static CK_RV create_ecc_private_key(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &cls,            sizeof(cls)             },
        { CKA_KEY_TYPE,    &keyType,        sizeof(keyType)         },
        { CKA_TOKEN,       &ckTrue,         sizeof(ckTrue)          },
        { CKA_PRIVATE,     &ckTrue,         sizeof(ckTrue)          },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)          },
        { CKA_EXTRACTABLE, &ckFalse,        sizeof(ckFalse)         },
        { CKA_SIGN,        &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,       ecc_p256_priv,   sizeof(ecc_p256_priv)   },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
}
#endif

#ifndef NO_RSA
static CK_RV create_rsa_private_key(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,            &cls,              sizeof(cls)               },
        { CKA_KEY_TYPE,         &keyType,          sizeof(keyType)           },
        { CKA_TOKEN,            &ckTrue,           sizeof(ckTrue)            },
        { CKA_PRIVATE,          &ckTrue,           sizeof(ckTrue)            },
        { CKA_SENSITIVE,        &ckTrue,           sizeof(ckTrue)            },
        { CKA_EXTRACTABLE,      &ckFalse,          sizeof(ckFalse)           },
        { CKA_SIGN,             &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
}
#endif

#ifndef NO_DH
static CK_RV create_dh_private_key(CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_DH;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &cls,           sizeof(cls)            },
        { CKA_KEY_TYPE,    &keyType,       sizeof(keyType)        },
        { CKA_TOKEN,       &ckTrue,        sizeof(ckTrue)         },
        { CKA_PRIVATE,     &ckTrue,        sizeof(ckTrue)         },
        { CKA_SENSITIVE,   &ckTrue,        sizeof(ckTrue)         },
        { CKA_EXTRACTABLE, &ckFalse,       sizeof(ckFalse)        },
        { CKA_DERIVE,      &ckTrue,        sizeof(ckTrue)         },
        { CKA_PRIME,       dh_ffdhe2048_p, sizeof(dh_ffdhe2048_p) },
        { CKA_BASE,        dh_ffdhe2048_g, sizeof(dh_ffdhe2048_g) },
        { CKA_VALUE,       dh_2048_priv,   sizeof(dh_2048_priv)   },
    };

    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), &obj);
}
#endif

#ifdef WOLFPKCS11_MLDSA
static CK_RV create_mldsa_key_pair(CK_SESSION_HANDLE session)
{
    CK_MECHANISM mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
    CK_ULONG paramSet = CKP_ML_DSA_44;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
        { CKA_VERIFY,        &ckTrue,   sizeof(ckTrue)   },
        { CKA_TOKEN,         &ckTrue,   sizeof(ckTrue)   },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_SIGN,          &ckTrue,   sizeof(ckTrue)   },
        { CKA_TOKEN,         &ckTrue,   sizeof(ckTrue)   },
        { CKA_PRIVATE,       &ckTrue,   sizeof(ckTrue)   },
        { CKA_SENSITIVE,     &ckTrue,   sizeof(ckTrue)   },
        { CKA_EXTRACTABLE,   &ckFalse,  sizeof(ckFalse)  },
    };

    return funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
        sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
        sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
}
#endif

#if defined(WOLFPKCS11_MLDSA) || defined(WOLFPKCS11_MLKEM)
static byte pqValue[8192];
static CK_ULONG pqValueSz = 0;
static CK_MECHANISM_TYPE pqGenMech = CKM_VENDOR_DEFINED;
static CK_ULONG pqParamSet = 0;

/* Generate an exportable post-quantum key pair and record the private value. */
static CK_RV create_pq_exportable_key_pair(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_PARAMETER_SET, &pqParamSet, sizeof(pqParamSet) },
        { CKA_TOKEN,         &ckTrue,     sizeof(ckTrue)     },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,         &ckTrue,     sizeof(ckTrue)     },
        { CKA_PRIVATE,       &ckTrue,     sizeof(ckTrue)     },
        { CKA_SENSITIVE,     &ckFalse,    sizeof(ckFalse)    },
        { CKA_EXTRACTABLE,   &ckTrue,     sizeof(ckTrue)     },
    };
    CK_ATTRIBUTE attr;

    mech.mechanism = pqGenMech;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    rv = funcList->C_GenerateKeyPair(session, &mech, pubTmpl,
        sizeof(pubTmpl) / sizeof(*pubTmpl), privTmpl,
        sizeof(privTmpl) / sizeof(*privTmpl), &pub, &priv);
    if (rv == CKR_OK) {
        attr.type = CKA_VALUE;
        attr.pValue = pqValue;
        attr.ulValueLen = sizeof(pqValue);
        rv = funcList->C_GetAttributeValue(session, priv, &attr, 1);
        pqValueSz = attr.ulValueLen;
    }
    if (rv == CKR_OK && (pqValueSz == 0 || pqValueSz > sizeof(pqValue)))
        rv = CKR_FUNCTION_FAILED;
    return rv;
}

/* After logging in, the private key value reads back unchanged. */
static int child_pq_value_kept(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte buf[sizeof(pqValue)];
    CK_ATTRIBUTE attr;

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK) {
        attr.type = CKA_VALUE;
        attr.pValue = buf;
        attr.ulValueLen = sizeof(buf);
        rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
    }
    (void)funcList->C_Finalize(NULL);
    if (rv != CKR_OK || attr.ulValueLen != pqValueSz ||
            XMEMCMP(buf, pqValue, pqValueSz) != 0) {
        fprintf(stderr, "  private value not kept: 0x%lx\n",
                (unsigned long)rv);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static void check_pq_round_trip(const char* name, CK_MECHANISM_TYPE genMech,
                                CK_ULONG paramSet)
{
    CK_RV rv;
    char msg[160];
    int res = CHILD_SETUP;

    keyClass = CKO_PRIVATE_KEY;
    pqGenMech = genMech;
    pqParamSet = paramSet;
    rv = store_objects(create_pq_exportable_key_pair);
    (void)snprintf(msg, sizeof(msg), "store %s", name);
    CHECK_RV(rv, msg, CKR_OK);
    if (rv == CKR_OK)
        res = run_in_child(child_pq_value_kept);
    (void)snprintf(msg, sizeof(msg), "%s private value kept after reload",
                   name);
    CHECK_TRUE(res == CHILD_PASS, msg);
    cleanup_test_files();
}

static void test_pq_keys_round_trip(void)
{
    printf("\n--- post-quantum private keys round trip ---\n");
#ifdef WOLFPKCS11_MLDSA
    check_pq_round_trip("ML-DSA key pair", CKM_ML_DSA_KEY_PAIR_GEN,
                        CKP_ML_DSA_44);
#endif
#ifdef WOLFPKCS11_MLKEM
    check_pq_round_trip("ML-KEM key pair", CKM_ML_KEM_KEY_PAIR_GEN,
                        CKP_ML_KEM_768);
#endif
}
#endif

/* After logging in, the key must not be exported and, for an AES key, must not
 * work as the original key. */
static int child_key_not_exported(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    static byte buf[4096];
    byte out[BLOCK_SZ];
    CK_BBOOL derive = CK_FALSE;
    CK_ATTRIBUTE attr;
    int res = CHILD_PASS;

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv != CKR_OK) {
        fprintf(stderr, "  login failed: 0x%lx\n", (unsigned long)rv);
        res = CHILD_FAIL;
    }
    if (res == CHILD_PASS && find_key(session, &obj) == CKR_OK) {
        attr.type = secretAttr;
        attr.pValue = buf;
        attr.ulValueLen = sizeof(buf);
        rv = funcList->C_GetAttributeValue(session, obj, &attr, 1);
        if (rv == CKR_OK && (holds_secret(buf, attr.ulValueLen) ||
                (secretNeedle == NULL && attr.ulValueLen > 0))) {
            fprintf(stderr, "  key value was returned\n");
            res = CHILD_FAIL;
        }
        if (checkAesUse && aes_encrypt_block(session, obj, out) == CKR_OK &&
                XMEMCMP(out, refCipher, sizeof(out)) == 0) {
            fprintf(stderr, "  key still operates as the original key\n");
            res = CHILD_FAIL;
        }
        if (signMech != CKM_VENDOR_DEFINED &&
                sign_block(session, obj) == CKR_OK) {
            fprintf(stderr, "  key still signs\n");
            res = CHILD_FAIL;
        }
        if (get_bool(session, obj, CKA_DERIVE, &derive) == CKR_OK) {
            derive = (derive == CK_TRUE) ? CK_FALSE : CK_TRUE;
            attr.type = CKA_DERIVE;
            attr.pValue = &derive;
            attr.ulValueLen = sizeof(derive);
            rv = funcList->C_SetAttributeValue(session, obj, &attr, 1);
            if (rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN) {
                fprintf(stderr, "  policy update returned 0x%lx\n",
                        (unsigned long)rv);
                res = CHILD_FAIL;
            }
        }
    }
    (void)funcList->C_Finalize(NULL);
    return res;
}

/* After logging in, the AES key works as the original key and reports the
 * expected policy. */
static int child_key_intact(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    byte out[BLOCK_SZ];
    byte value[sizeof(aesKeyValue)];
    CK_BBOOL sensitive = CK_FALSE;
    CK_BBOOL extractable = CK_TRUE;
    CK_BBOOL decrypt = CK_FALSE;
    CK_ATTRIBUTE attr;
    int res = CHILD_PASS;

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK)
        rv = aes_encrypt_block(session, obj, out);
    if (rv == CKR_OK && XMEMCMP(out, refCipher, sizeof(out)) != 0)
        rv = CKR_FUNCTION_FAILED;
    if (rv == CKR_OK)
        rv = get_bool(session, obj, CKA_SENSITIVE, &sensitive);
    if (rv == CKR_OK)
        rv = get_bool(session, obj, CKA_EXTRACTABLE, &extractable);
    if (rv == CKR_OK)
        rv = get_bool(session, obj, CKA_DECRYPT, &decrypt);
    if (rv != CKR_OK) {
        fprintf(stderr, "  key unusable after reload: 0x%lx\n",
                (unsigned long)rv);
        res = CHILD_FAIL;
    }
    else if (sensitive != expSensitive || extractable != expExtractable ||
             decrypt != expDecrypt) {
        fprintf(stderr, "  policy not kept: sensitive %d extractable %d "
                "decrypt %d\n", sensitive, extractable, decrypt);
        res = CHILD_FAIL;
    }
    else if (sensitive == CK_TRUE) {
        attr.type = CKA_VALUE;
        attr.pValue = value;
        attr.ulValueLen = sizeof(value);
        if (funcList->C_GetAttributeValue(session, obj, &attr, 1) == CKR_OK) {
            fprintf(stderr, "  sensitive key value was returned\n");
            res = CHILD_FAIL;
        }
    }
    (void)funcList->C_Finalize(NULL);
    return res;
}

static void set_aes_check(void)
{
    keyClass = CKO_SECRET_KEY;
    secretAttr = CKA_VALUE;
    secretNeedle = aesKeyValue + sizeof(aesKeyValue) - 16;
    secretNeedleSz = 16;
    checkAesUse = 1;
    expSensitive = CK_TRUE;
    expExtractable = CK_FALSE;
    expDecrypt = CK_TRUE;
}

static void check_stored_policy(const char* name, create_fn create,
                                CK_OBJECT_CLASS cls, CK_ATTRIBUTE_TYPE type,
                                const byte* secret, size_t secretSz, int aes,
                                CK_MECHANISM_TYPE sign)
{
    CK_RV rv;
    char msg[160];
    int res = CHILD_SETUP;

    rv = store_objects(create);
    (void)snprintf(msg, sizeof(msg), "store %s", name);
    CHECK_RV(rv, msg, CKR_OK);
    if (rv != CKR_OK)
        return;
    keyClass = cls;
    secretAttr = type;
    secretNeedle = NULL;
    secretNeedleSz = 0;
    if (secret != NULL && secretSz >= 16) {
        secretNeedle = secret + secretSz - 16;
        secretNeedleSz = 16;
    }
    checkAesUse = aes;
    signMech = sign;
    if (sign != CKM_VENDOR_DEFINED) {
        res = run_in_child(child_key_signs);
        (void)snprintf(msg, sizeof(msg), "%s signs after reload", name);
        CHECK_TRUE(res == CHILD_PASS, msg);
        res = CHILD_SETUP;
    }
    if (mark_stored_key_exportable() == 0)
        res = run_in_child(child_key_not_exported);
    signMech = CKM_VENDOR_DEFINED;
    (void)snprintf(msg, sizeof(msg),
                   "%s keeps the policy it was stored under", name);
    CHECK_TRUE(res == CHILD_PASS, msg);
    cleanup_test_files();
}

static void test_stored_policy_is_authenticated(void)
{
    printf("\n--- stored key policy is authenticated ---\n");
    check_stored_policy("AES key", create_aes_key, CKO_SECRET_KEY, CKA_VALUE,
        aesKeyValue, sizeof(aesKeyValue), 1, CKM_VENDOR_DEFINED);
#ifdef HAVE_ECC
    check_stored_policy("ECC private key", create_ecc_private_key,
        CKO_PRIVATE_KEY, CKA_VALUE, ecc_p256_priv, sizeof(ecc_p256_priv), 0,
        CKM_ECDSA);
#endif
#ifndef NO_RSA
    check_stored_policy("RSA private key", create_rsa_private_key,
        CKO_PRIVATE_KEY, CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp,
        sizeof(rsa_2048_priv_exp), 0, CKM_RSA_PKCS);
#endif
#ifndef NO_DH
    check_stored_policy("DH private key", create_dh_private_key,
        CKO_PRIVATE_KEY, CKA_VALUE, dh_2048_priv, sizeof(dh_2048_priv), 0,
        CKM_VENDOR_DEFINED);
#endif
#ifdef WOLFPKCS11_MLDSA
    check_stored_policy("ML-DSA private key", create_mldsa_key_pair,
        CKO_PRIVATE_KEY, CKA_VALUE, NULL, 0, 0, CKM_ML_DSA);
#endif
}

/* Tighten the policy of an exportable key while logged in. */
static CK_RV create_and_restrict_aes_key(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_SENSITIVE,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
        { CKA_DECRYPT,     &ckFalse, sizeof(ckFalse) },
    };

    rv = create_aes_key_ex(session, CK_TRUE, CK_FALSE, CK_TRUE);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK) {
        rv = funcList->C_SetAttributeValue(session, obj, tmpl,
            sizeof(tmpl) / sizeof(*tmpl));
    }
    return rv;
}

/* Restrict the key while logged in, then persist the token by adding another
 * object and stop without finalizing. */
static int child_restrict_and_store(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    byte value[] = "stored";
    CK_ATTRIBUTE restrictTmpl[] = {
        { CKA_SENSITIVE,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
    };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, &ckTrue,    sizeof(ckTrue)    },
        { CKA_VALUE, value,      sizeof(value) - 1 },
    };

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK)
        rv = funcList->C_SetAttributeValue(session, obj, restrictTmpl, 2);
    if (rv == CKR_OK)
        rv = funcList->C_CreateObject(session, dataTmpl, 3, &data);
    if (rv != CKR_OK) {
        fprintf(stderr, "  restrict and store failed: 0x%lx\n",
                (unsigned long)rv);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static CK_RV create_exportable_aes_key(CK_SESSION_HANDLE session)
{
    return create_aes_key_ex(session, CK_TRUE, CK_FALSE, CK_TRUE);
}

static CK_RV create_public_aes_key(CK_SESSION_HANDLE session)
{
    return create_aes_key_ex(session, CK_FALSE, CK_TRUE, CK_FALSE);
}

/* Without the user logged in, a policy change cannot be bound to the stored
 * key and is refused, while a label change is accepted. */
static int child_unbound_update_refused(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    char label[] = "renamed";
    CK_ATTRIBUTE policy[] = {
        { CKA_DECRYPT, &ckFalse, sizeof(ckFalse) },
    };
    CK_ATTRIBUTE name[] = {
        { CKA_LABEL, label, sizeof(label) - 1 },
    };
    int res = CHILD_PASS;

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 0, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv != CKR_OK) {
        fprintf(stderr, "  public key not found: 0x%lx\n", (unsigned long)rv);
        res = CHILD_FAIL;
    }
    if (res == CHILD_PASS) {
        rv = funcList->C_SetAttributeValue(session, obj, policy, 1);
        if (rv != CKR_USER_NOT_LOGGED_IN) {
            fprintf(stderr, "  policy change returned 0x%lx\n",
                    (unsigned long)rv);
            res = CHILD_FAIL;
        }
        rv = funcList->C_SetAttributeValue(session, obj, name, 1);
        if (rv != CKR_OK) {
            fprintf(stderr, "  label change returned 0x%lx\n",
                    (unsigned long)rv);
            res = CHILD_FAIL;
        }
    }
    (void)funcList->C_Finalize(NULL);
    return res;
}

static void test_legitimate_updates_round_trip(void)
{
    CK_RV rv;
    int res = CHILD_SETUP;

    printf("\n--- legitimate policy updates survive a reload ---\n");
    set_aes_check();
    rv = store_objects(create_and_restrict_aes_key);
    CHECK_RV(rv, "restrict AES key policy while logged in", CKR_OK);
    if (rv == CKR_OK) {
        expDecrypt = CK_FALSE;
        res = run_in_child(child_key_intact);
    }
    CHECK_TRUE(res == CHILD_PASS, "restricted policy is kept after reload");
    res = CHILD_SETUP;
    if (rv == CKR_OK && mark_stored_key_exportable() == 0)
        res = run_in_child(child_key_not_exported);
    CHECK_TRUE(res == CHILD_PASS,
               "restricted policy cannot be undone in store");
    cleanup_test_files();

    res = CHILD_SETUP;
    set_aes_check();
    rv = store_objects(create_exportable_aes_key);
    CHECK_RV(rv, "store exportable AES key", CKR_OK);
    if (rv == CKR_OK)
        res = run_in_child(child_restrict_and_store);
    CHECK_TRUE(res == CHILD_PASS, "restrict key and store while logged in");
    if (res == CHILD_PASS)
        res = run_in_child(child_key_intact);
    CHECK_TRUE(res == CHILD_PASS, "policy stored while logged in is kept");
    if (res == CHILD_PASS && mark_stored_key_exportable() == 0)
        res = run_in_child(child_key_not_exported);
    else
        res = CHILD_SETUP;
    CHECK_TRUE(res == CHILD_PASS, "policy stored while logged in is bound");
    cleanup_test_files();

    res = CHILD_SETUP;
    set_aes_check();
    rv = store_objects(create_public_aes_key);
    CHECK_RV(rv, "store public AES key", CKR_OK);
    if (rv == CKR_OK)
        res = run_in_child(child_unbound_update_refused);
    CHECK_TRUE(res == CHILD_PASS, "policy change needs the user's key");
    res = CHILD_SETUP;
    if (rv == CKR_OK)
        res = run_in_child(child_key_intact);
    CHECK_TRUE(res == CHILD_PASS, "public key usable after refused change");
    cleanup_test_files();
}

#if (defined(WOLFPKCS11_PBKDF2) || defined(HAVE_SCRYPT)) && \
    !defined(WOLFSSL_STM32U5_DHUK) && \
    !(defined(HAVE_FIPS) && defined(WOLFPKCS11_NSS))
#define HAVE_LEGACY_STORE_TEST

/* Derive the token storage key from the user PIN and the stored token seed,
 * the way stores have always been keyed. */
static int derive_token_key(byte* key, word32 keySz)
{
    static byte data[MAX_FILE_SZ];
    char path[256];
    size_t sz = 0;
    size_t off = 32;
    byte* seed;

    store_path(path, sizeof(path), "token", -1);
    if (read_file(path, data, sizeof(data), &sz) != 0)
        return -1;
    /* label, SO PIN, SO seed, SO fail count and times */
    if (sz < off + 4)
        return -1;
    off += 4 + get_be32(data + off) + 16 + 4 + 2 * sizeof(time_t);
    /* user PIN, user seed, user fail count and times */
    if (sz < off + 4)
        return -1;
    off += 4 + get_be32(data + off) + 16 + 4 + 2 * sizeof(time_t);
    if (sz < off + 16)
        return -1;
    seed = data + off;
#ifdef WOLFPKCS11_PBKDF2
    return wc_PBKDF2(key, userPin, (int)sizeof(userPin) - 1, seed, 16,
                     PBKDF2_ITERATIONS, (int)keySz, WC_SHA256);
#else
    return wc_scrypt(key, userPin, (int)sizeof(userPin) - 1, seed, 16,
                     WP11_HASH_PIN_COST, WP11_HASH_PIN_BLOCKSIZE,
                     WP11_HASH_PIN_PARALLEL, (int)keySz);
#endif
}

static int read_stored_iv(byte* iv)
{
    static byte data[MAX_FILE_SZ];
    char path[256];
    size_t sz = 0;

    if (find_store_file("obj", path, sizeof(path)) != 0 ||
            read_file(path, data, sizeof(data), &sz) != 0 || sz < OBJ_IV_SZ)
        return -1;
    XMEMCPY(iv, data, OBJ_IV_SZ);
    return 0;
}

/* Replace the stored AES key with an encryption that binds no policy. */
static int write_unbound_key_record(void)
{
    byte key[32];
    byte iv[OBJ_IV_SZ];
    byte rec[4 + sizeof(aesKeyValue) + TAG_SZ];
    char path[256];
    Aes aes;
    int ret;

    ret = derive_token_key(key, sizeof(key));
    if (ret == 0)
        ret = read_stored_iv(iv);
    if (ret == 0)
        ret = find_store_file("symmkey", path, sizeof(path));
    if (ret == 0)
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, sizeof(key));
        if (ret == 0) {
            ret = wc_AesGcmEncrypt(&aes, rec + 4, aesKeyValue,
                sizeof(aesKeyValue), iv, sizeof(iv),
                rec + 4 + sizeof(aesKeyValue), TAG_SZ, NULL, 0);
        }
        wc_AesFree(&aes);
    }
    if (ret == 0) {
        put_be32(rec, (word32)(sizeof(aesKeyValue) + TAG_SZ));
        ret = write_file(path, rec, sizeof(rec));
    }
    wc_ForceZero(key, sizeof(key));
    return ret;
}

/* Returns 1 when the stored AES key record still verifies without a policy. */
static int stored_key_is_unbound(void)
{
    static byte data[MAX_FILE_SZ];
    byte key[32];
    byte iv[OBJ_IV_SZ];
    byte plain[sizeof(aesKeyValue)];
    char path[256];
    size_t sz = 0;
    Aes aes;
    int ret;
    int unbound = 0;

    ret = derive_token_key(key, sizeof(key));
    if (ret == 0)
        ret = read_stored_iv(iv);
    if (ret == 0)
        ret = find_store_file("symmkey", path, sizeof(path));
    if (ret == 0)
        ret = read_file(path, data, sizeof(data), &sz);
    if (ret == 0 && (sz != 4 + sizeof(aesKeyValue) + TAG_SZ ||
            get_be32(data) != sizeof(aesKeyValue) + TAG_SZ))
        ret = -1;
    if (ret == 0)
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, sizeof(key));
        if (ret == 0) {
            ret = wc_AesGcmDecrypt(&aes, plain, data + 4, sizeof(plain), iv,
                sizeof(iv), data + 4 + sizeof(plain), TAG_SZ, NULL, 0);
            unbound = (ret == 0);
        }
        wc_AesFree(&aes);
    }
    wc_ForceZero(key, sizeof(key));
    wc_ForceZero(plain, sizeof(plain));
    return unbound;
}

static void test_unbound_store_upgraded(void)
{
    CK_RV rv;
    int res = CHILD_SETUP;

    printf("\n--- store without bound policy loads and is upgraded ---\n");
    rv = store_objects(create_aes_key);
    CHECK_RV(rv, "store AES key", CKR_OK);
    if (rv == CKR_OK && write_unbound_key_record() == 0 &&
            stored_key_is_unbound()) {
        set_aes_check();
        res = run_in_child(child_key_intact);
    }
    CHECK_TRUE(res == CHILD_PASS, "unbound key record still loads");
    CHECK_TRUE(res == CHILD_PASS && !stored_key_is_unbound(),
               "key record is rebound to its policy after use");
    if (res == CHILD_PASS)
        res = run_in_child(child_key_intact);
    CHECK_TRUE(res == CHILD_PASS, "rebound key loads again");
    res = CHILD_SETUP;
    if (mark_stored_key_exportable() == 0)
        res = run_in_child(child_key_not_exported);
    CHECK_TRUE(res == CHILD_PASS, "rebound key keeps its policy");
    cleanup_test_files();
}
#endif

static byte otherUserPin[] = "wolfpkcs11-other";

/* Store passes that cannot start must leave the PIN and token in effect. */
static int child_failed_store_keeps_state(void)
{
    CK_RV rv;
    CK_RV setRv = CKR_OK;
    CK_RV initRv = CKR_OK;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_UTF8CHAR label[32];
    byte out[BLOCK_SZ];
    char lockPath[256];

    (void)snprintf(lockPath, sizeof(lockPath), "%s/wp11_txn_%016lx_lock",
                   TEST_DIR, 1UL);
    XMEMSET(label, ' ', sizeof(label));
    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    /* A directory at the lock file name makes every store pass fail. */
    (void)unlink(lockPath);
    if (rv == CKR_OK && mkdir(lockPath, 0700) != 0)
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK) {
        setRv = funcList->C_SetPIN(session, userPin, sizeof(userPin) - 1,
                                   otherUserPin, sizeof(otherUserPin) - 1);
        (void)funcList->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
        initRv = funcList->C_InitToken(slot, soPin, sizeof(soPin) - 1, label);
    }
    (void)rmdir(lockPath);
    if (rv == CKR_OK && (setRv == CKR_OK || initRv == CKR_OK))
        rv = CKR_GENERAL_ERROR;
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK)
        rv = aes_encrypt_block(session, obj, out);
    if (rv == CKR_OK && XMEMCMP(out, refCipher, sizeof(out)) != 0)
        rv = CKR_FUNCTION_FAILED;
    (void)funcList->C_Finalize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "  old PIN or key lost after failed stores: 0x%lx\n",
                (unsigned long)rv);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static void test_failed_store_keeps_state(void)
{
    CK_RV rv;

    printf("\n--- failed PIN change and token init keep stored state ---\n");
    set_aes_check();
    rv = store_objects(create_aes_key);
    CHECK_RV(rv, "store AES key", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(run_in_child(child_failed_store_keeps_state) == CHILD_PASS,
                   "old PIN and key work after failed stores");
    }
    cleanup_test_files();
}

#ifdef DEBUG_WOLFPKCS11
/* Matches WP11_TEST_STORE_EXIT_CODE in wolfpkcs11/internal.h. */
#define STORE_EXIT_CODE      75
#define CRASH_MAX_RENAMES    40

extern void WP11_Test_StoreExitAfterRenames(int renames);

static int crashAt = 0;

/* Restrict the key and store the token, ending after crashAt renames. */
static int child_restrict_and_crash(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;
    byte value[] = "stored";
    CK_ATTRIBUTE restrictTmpl[] = {
        { CKA_SENSITIVE,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
    };
    CK_ATTRIBUTE dataTmpl[] = {
        { CKA_CLASS, &dataClass, sizeof(dataClass) },
        { CKA_TOKEN, &ckTrue,    sizeof(ckTrue)    },
        { CKA_VALUE, value,      sizeof(value) - 1 },
    };

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK)
        rv = funcList->C_SetAttributeValue(session, obj, restrictTmpl, 2);
    if (rv == CKR_OK) {
        WP11_Test_StoreExitAfterRenames(crashAt);
        rv = funcList->C_CreateObject(session, dataTmpl, 3, &data);
        WP11_Test_StoreExitAfterRenames(0);
    }
    return (rv == CKR_OK) ? CHILD_PASS : CHILD_FAIL;
}

/* The key loads and encrypts as before, under the old or the new policy. */
static int child_key_old_or_new(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    byte out[BLOCK_SZ];
    CK_BBOOL sensitive = CK_FALSE;
    CK_BBOOL extractable = CK_FALSE;

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK)
        rv = aes_encrypt_block(session, obj, out);
    if (rv == CKR_OK && XMEMCMP(out, refCipher, sizeof(out)) != 0)
        rv = CKR_FUNCTION_FAILED;
    if (rv == CKR_OK)
        rv = get_bool(session, obj, CKA_SENSITIVE, &sensitive);
    if (rv == CKR_OK)
        rv = get_bool(session, obj, CKA_EXTRACTABLE, &extractable);
    if (rv == CKR_OK && sensitive == extractable)
        rv = CKR_GENERAL_ERROR;
    (void)funcList->C_Finalize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "  key not usable after crash at rename %d: 0x%lx\n",
                crashAt, (unsigned long)rv);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static void test_store_pass_is_atomic(void)
{
    CK_RV rv;
    int res;
    int done = 0;
    int bad = 0;

    printf("\n--- a store pass cut short at any rename keeps the key ---\n");
    for (crashAt = 1; !done && bad == 0 && crashAt <= CRASH_MAX_RENAMES;
            crashAt++) {
        set_aes_check();
        rv = store_objects(create_exportable_aes_key);
        if (rv != CKR_OK) {
            bad++;
            break;
        }
        res = run_in_child(child_restrict_and_crash);
        if (res == CHILD_PASS)
            done = 1;
        else if (res != STORE_EXIT_CODE)
            bad++;
        if (run_in_child(child_key_old_or_new) != CHILD_PASS)
            bad++;
    }
    CHECK_TRUE(done, "store pass runs to completion without the hook");
    CHECK_TRUE(bad == 0, "key is old or new after a crash at every rename");
    cleanup_test_files();
}

static byte newUserPin[] = "wolfpkcs11-new1";

/* Restrict the key and change the user PIN, ending after crashAt renames. */
static int child_rebind_and_change_pin(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ATTRIBUTE restrictTmpl[] = {
        { CKA_SENSITIVE,   &ckTrue,  sizeof(ckTrue)  },
        { CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse) },
    };

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 1, &session);
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK)
        rv = funcList->C_SetAttributeValue(session, obj, restrictTmpl, 2);
    if (rv == CKR_OK) {
        WP11_Test_StoreExitAfterRenames(crashAt);
        rv = funcList->C_SetPIN(session, userPin, sizeof(userPin) - 1,
                                newUserPin, sizeof(newUserPin) - 1);
        WP11_Test_StoreExitAfterRenames(0);
    }
    return (rv == CKR_OK) ? CHILD_PASS : CHILD_FAIL;
}

/* The key works after logging in with either the old or the new PIN. */
static int child_key_under_either_pin(void)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    byte out[BLOCK_SZ];

    if (pkcs11_load() != CKR_OK)
        return CHILD_SETUP;
    rv = init_slot(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, 0, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_Login(session, CKU_USER, userPin,
                               sizeof(userPin) - 1);
        if (rv == CKR_PIN_INCORRECT) {
            rv = funcList->C_Login(session, CKU_USER, newUserPin,
                                   sizeof(newUserPin) - 1);
        }
    }
    if (rv == CKR_OK)
        rv = find_key(session, &obj);
    if (rv == CKR_OK)
        rv = aes_encrypt_block(session, obj, out);
    if (rv == CKR_OK && XMEMCMP(out, refCipher, sizeof(out)) != 0)
        rv = CKR_FUNCTION_FAILED;
    (void)funcList->C_Finalize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "  key not usable after crash at rename %d: 0x%lx\n",
                crashAt, (unsigned long)rv);
        return CHILD_FAIL;
    }
    return CHILD_PASS;
}

static void test_pin_change_pass_is_atomic(void)
{
    CK_RV rv;
    int res;
    int done = 0;
    int bad = 0;

    printf("\n--- a PIN change cut short at any rename keeps the key ---\n");
    for (crashAt = 1; !done && bad == 0 && crashAt <= CRASH_MAX_RENAMES;
            crashAt++) {
        set_aes_check();
        rv = store_objects(create_exportable_aes_key);
        if (rv != CKR_OK) {
            bad++;
            break;
        }
        res = run_in_child(child_rebind_and_change_pin);
        if (res == CHILD_PASS)
            done = 1;
        else if (res != STORE_EXIT_CODE)
            bad++;
        if (run_in_child(child_key_under_either_pin) != CHILD_PASS)
            bad++;
    }
    CHECK_TRUE(done, "PIN change runs to completion without the hook");
    CHECK_TRUE(bad == 0, "key usable with old or new PIN after every crash");
    cleanup_test_files();
}
#endif

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);

    printf("=== wolfPKCS11 stored object policy integrity test ===\n");
    test_stored_policy_is_authenticated();
    test_legitimate_updates_round_trip();
    test_failed_store_keeps_state();
#ifdef DEBUG_WOLFPKCS11
    test_store_pass_is_atomic();
    test_pin_change_pass_is_atomic();
#endif
#if defined(WOLFPKCS11_MLDSA) || defined(WOLFPKCS11_MLKEM)
    test_pq_keys_round_trip();
#endif
#ifdef HAVE_LEGACY_STORE_TEST
    test_unbound_store_upgraded();
#endif

    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("File-backed token storage not available, skipping test\n");
    return 77;
}

#endif
