/* set_pin_rekey_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * Tests that protected token objects stay usable after C_SetPIN.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

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
#ifndef _WIN32
    #include <sys/stat.h>
    #include <sys/wait.h>
    #include <unistd.h>
#endif
#if defined(_POSIX_THREADS) && !defined(SINGLE_THREADED) && !defined(_WIN32)
    #include <pthread.h>
    #define SET_PIN_REKEY_THREADS
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#if !defined(NO_AES) && defined(HAVE_ECC) && !defined(WOLFPKCS11_NO_STORE)

#define TEST_DIR "." PATH_SEP "store" PATH_SEP "set_pin_rekey_test"
#define MAX_TEST_OBJS 64

static byte soPin[] = "password123456";
static byte pin1[] = "wolfpkcs11-test";
static byte pin2[] = "rotated-pin-5678";
static byte pin3[] = "rotated-again-90";
#ifndef _WIN32
static byte pin4[] = "after-crash-1234";
#endif
#if !defined(_WIN32) && !defined(WOLFPKCS11_TPM_STORE) && \
    !defined(WOLFPKCS11_CUSTOM_STORE) && !defined(WOLFPKCS11_NO_ENV)
    #define SET_PIN_STORE_FAIL
static byte pin5[] = "never-stored-123";
static byte pin6[] = "after-rollback-1";
#endif
static byte aesId[] = "rekey-aes";
static byte ecId[] = "rekey-ec";

static byte aesValue[16] = {
    0xC3, 0x03, 0xD1, 0x2B, 0xFE, 0x39, 0xA4, 0x32,
    0x45, 0x3B, 0x53, 0xC8, 0x84, 0x2B, 0x2A, 0x7C,
};

/* DER encoded OID for P-256. */
static byte ecParams[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

static void cleanup_test_files(void)
{
    static const char* prefixes[] = {
        "wp11_obj", "wp11_symmkey", "wp11_ecckey_priv", "wp11_ecckey_pub"
    };
    char name[160];
    size_t p;
    int i;

    for (p = 0; p < sizeof(prefixes) / sizeof(*prefixes); p++) {
        for (i = 0; i < MAX_TEST_OBJS; i++) {
            XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "%s_%016lx_%016lx",
                      TEST_DIR, prefixes[p], 1UL, (unsigned long)i);
            (void)remove(name);
        }
    }
    XSNPRINTF(name, sizeof(name), "%s" PATH_SEP "wp11_token_%016lx",
              TEST_DIR, 1UL);
    (void)remove(name);
}

static CK_RV initialize(CK_SLOT_ID* slot)
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

/* Load library and initialize, simulating a fresh process. */
static CK_RV restart(CK_SLOT_ID* slot)
{
    CK_RV rv;

    rv = pkcs11_load();
    if (rv == CKR_OK)
        rv = initialize(slot);
    return rv;
}

static void shutdown_lib(CK_SESSION_HANDLE session)
{
    if (session != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(session);
    (void)funcList->C_Finalize(NULL);
    pkcs11_unload();
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
        rv = funcList->C_InitPIN(session, pin1, sizeof(pin1) - 1);

    if (session != CK_INVALID_HANDLE) {
        (void)funcList->C_Logout(session);
        (void)funcList->C_CloseSession(session);
    }
    return rv;
}

static CK_RV open_session(CK_SLOT_ID slot, byte* pin, CK_ULONG pinLen,
                          CK_SESSION_HANDLE* session)
{
    CK_RV rv;
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    rv = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    if (rv == CKR_OK && pin != NULL)
        rv = funcList->C_Login(*session, CKU_USER, pin, pinLen);
    return rv;
}

static CK_RV create_token_keys(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_HANDLE aesKey, pubKey, privKey;
    CK_MECHANISM ecGen = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,       &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_ENCRYPT,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,       aesValue,     sizeof(aesValue)    },
        { CKA_ID,          aesId,        sizeof(aesId) - 1   },
    };
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_EC_PARAMS,   ecParams,     sizeof(ecParams)    },
        { CKA_TOKEN,       &ckTrue,      sizeof(ckTrue)      },
        { CKA_VERIFY,      &ckTrue,      sizeof(ckTrue)      },
        { CKA_ID,          ecId,         sizeof(ecId) - 1    },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,       &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_SIGN,        &ckTrue,      sizeof(ckTrue)      },
        { CKA_ID,          ecId,         sizeof(ecId) - 1    },
    };

    rv = funcList->C_CreateObject(session, aesTmpl,
        sizeof(aesTmpl) / sizeof(*aesTmpl), &aesKey);
    if (rv == CKR_OK) {
        rv = funcList->C_GenerateKeyPair(session, &ecGen,
            pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
            privTmpl, sizeof(privTmpl) / sizeof(*privTmpl),
            &pubKey, &privKey);
    }
    return rv;
}

static CK_RV find_key(CK_SESSION_HANDLE session, CK_OBJECT_CLASS objClass,
                      byte* id, CK_ULONG idLen, CK_OBJECT_HANDLE* key)
{
    CK_RV rv;
    CK_ULONG count = 0;
    CK_ATTRIBUTE findTmpl[] = {
        { CKA_CLASS, &objClass, sizeof(objClass) },
        { CKA_ID,    id,        idLen            },
    };

    rv = funcList->C_FindObjectsInit(session, findTmpl,
        sizeof(findTmpl) / sizeof(*findTmpl));
    if (rv == CKR_OK)
        rv = funcList->C_FindObjects(session, key, 1, &count);
    if (rv == CKR_OK)
        rv = funcList->C_FindObjectsFinal(session);
    if (rv == CKR_OK && count != 1)
        rv = CKR_GENERAL_ERROR;
    return rv;
}

/* Check the AES key value and that the EC private key signs. */
static CK_RV check_token_keys(CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    byte value[sizeof(aesValue)];
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_VALUE, value, sizeof(value) },
    };
    CK_MECHANISM ecdsa = { CKM_ECDSA, NULL, 0 };
    byte hash[32];
    byte sig[128];
    CK_ULONG sigLen = sizeof(sig);

    rv = find_key(session, CKO_SECRET_KEY, aesId, sizeof(aesId) - 1, &key);
    if (rv == CKR_OK)
        rv = funcList->C_GetAttributeValue(session, key, getTmpl, 1);
    if (rv == CKR_OK && (getTmpl[0].ulValueLen != sizeof(aesValue) ||
            XMEMCMP(value, aesValue, sizeof(aesValue)) != 0)) {
        rv = CKR_GENERAL_ERROR;
    }

    if (rv == CKR_OK)
        rv = find_key(session, CKO_PRIVATE_KEY, ecId, sizeof(ecId) - 1, &key);
    if (rv == CKR_OK) {
        XMEMSET(hash, 0x5a, sizeof(hash));
        rv = funcList->C_SignInit(session, &ecdsa, key);
    }
    if (rv == CKR_OK)
        rv = funcList->C_Sign(session, hash, sizeof(hash), sig, &sigLen);

    return rv;
}

static CK_RV login_rejected(CK_SLOT_ID slot, byte* pin, CK_ULONG pinLen)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = open_session(slot, pin, pinLen, &session);
    if (session != CK_INVALID_HANDLE)
        (void)funcList->C_CloseSession(session);
    return rv;
}

#ifndef _WIN32
/* Change the PIN in a child process that exits without C_Finalize. */
static CK_RV set_pin_then_crash(byte* oldPin, CK_ULONG oldLen, byte* newPin,
                                CK_ULONG newLen)
{
    pid_t pid;
    int status = 0;

    fflush(stdout);
    fflush(stderr);
    pid = fork();
    if (pid < 0)
        return CKR_GENERAL_ERROR;
    if (pid == 0) {
        CK_RV rv;
        CK_SLOT_ID slot = 0;
        CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

        rv = restart(&slot);
        if (rv == CKR_OK)
            rv = open_session(slot, oldPin, oldLen, &session);
        if (rv == CKR_OK) {
            rv = funcList->C_SetPIN(session, oldPin, oldLen, newPin, newLen);
        }
        _exit(rv == CKR_OK ? 0 : 1);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}
#endif

#ifdef SET_PIN_STORE_FAIL
/* C_SetPIN fails to store; the old PIN and keys must stay in effect.
 * Returns 1 when the PIN has been changed to pin6. */
static int run_store_fail_phase(byte* curPin, CK_ULONG curPinLen)
{
    CK_RV rv;
    int changed = 0;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int readOnly;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, NULL, 0, &session);
    CHECK_RV(rv, "open public session (store failure phase)", CKR_OK);
    if (rv != CKR_OK) {
        shutdown_lib(session);
        return 0;
    }

    readOnly = chmod(TEST_DIR, S_IRUSR | S_IXUSR) == 0 &&
               access(TEST_DIR, W_OK) != 0;
    if (!readOnly) {
        printf("Cannot make token directory read-only, skipping store "
               "failure phase\n");
        (void)chmod(TEST_DIR, S_IRWXU);
        shutdown_lib(session);
        return 0;
    }

    rv = funcList->C_SetPIN(session, curPin, curPinLen, pin5,
                            sizeof(pin5) - 1);
    CHECK_RV(rv, "C_SetPIN with read-only token directory",
             CKR_FUNCTION_FAILED);
    rv = funcList->C_Login(session, CKU_USER, curPin, curPinLen);
    CHECK_RV(rv, "old PIN still logs in after failed C_SetPIN", CKR_OK);
    if (rv == CKR_OK) {
        rv = check_token_keys(session);
        CHECK_RV(rv, "keys usable after failed C_SetPIN", CKR_OK);
        (void)funcList->C_Logout(session);
    }
    CHECK_RV(login_rejected(slot, pin5, sizeof(pin5) - 1),
             "PIN from failed C_SetPIN rejected", CKR_PIN_INCORRECT);

    (void)chmod(TEST_DIR, S_IRWXU);

    /* A full store after the rollback must still write every object. */
    rv = funcList->C_SetPIN(session, curPin, curPinLen, pin6,
                            sizeof(pin6) - 1);
    CHECK_RV(rv, "C_SetPIN after failed C_SetPIN", CKR_OK);
    changed = rv == CKR_OK;
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    CHECK_RV(rv, "initialize (after store failure phase)", CKR_OK);
    if (rv != CKR_OK)
        return changed;
    CHECK_RV(login_rejected(slot, pin5, sizeof(pin5) - 1),
             "PIN from failed C_SetPIN rejected after restart",
             CKR_PIN_INCORRECT);
    rv = open_session(slot, pin6, sizeof(pin6) - 1, &session);
    if (rv == CKR_OK)
        rv = check_token_keys(session);
    CHECK_RV(rv, "keys usable after failed then successful C_SetPIN",
             CKR_OK);
    shutdown_lib(session);
    return changed;
}
#endif /* SET_PIN_STORE_FAIL */

#ifdef SET_PIN_REKEY_THREADS
#define STRESS_PIN_CHANGES  20
#define STRESS_KEYS         45
#define STRESS_PIN_LEN      16
#define STRESS_PIN_BUF_SZ   32
#define STRESS_ID_SZ        32
#define STRESS_PIN_JITTER_US  8000
#define STRESS_KEY_DELAY_US   10000

/* Last PIN successfully set by the PIN-changing threads. */
static pthread_mutex_t stressLock = PTHREAD_MUTEX_INITIALIZER;
static byte stressPin[STRESS_PIN_BUF_SZ];
static int stressPinOk;
static int stressPinErr;
static int stressKeyErr;
static int stressDone;
/* Whether each stress key should exist once the threads are done. */
static int stressKeyLive[STRESS_KEYS];

typedef struct StressArgs {
    CK_SLOT_ID slot;
    char tag;
} StressArgs;

static void stress_key_id(int i, byte* id)
{
    XSNPRINTF((char*)id, STRESS_ID_SZ, "stress-%03d", i);
}

static void stress_key_value(int i, byte* value)
{
    XMEMSET(value, 0xA0 ^ i, sizeof(aesValue));
    value[0] = (byte)i;
}

/* Repeatedly change the shared PIN to a new PIN unique to this thread. */
static void* stress_change_pin(void* arg)
{
    StressArgs* args = (StressArgs*)arg;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    byte oldPin[STRESS_PIN_BUF_SZ];
    byte newPin[STRESS_PIN_BUF_SZ];
    CK_RV rv;
    unsigned int seed = (unsigned int)args->tag;
    int i;

    if (open_session(args->slot, NULL, 0, &session) != CKR_OK) {
        pthread_mutex_lock(&stressLock);
        stressPinErr++;
        pthread_mutex_unlock(&stressLock);
        return NULL;
    }
    for (i = 0; i < STRESS_PIN_CHANGES; i++) {
        usleep((useconds_t)(rand_r(&seed) % STRESS_PIN_JITTER_US));
        pthread_mutex_lock(&stressLock);
        XMEMCPY(oldPin, stressPin, sizeof(oldPin));
        pthread_mutex_unlock(&stressLock);
        XSNPRINTF((char*)newPin, sizeof(newPin), "stress-pin-%c-%03d",
                  args->tag, i);

        rv = funcList->C_SetPIN(session, oldPin, STRESS_PIN_LEN, newPin,
                                STRESS_PIN_LEN);
        pthread_mutex_lock(&stressLock);
        if (rv == CKR_OK) {
            XMEMCPY(stressPin, newPin, sizeof(stressPin));
            stressPinOk++;
        }
        else if (rv != CKR_PIN_INCORRECT && rv != CKR_FUNCTION_FAILED) {
            stressPinErr++;
        }
        pthread_mutex_unlock(&stressLock);
    }
    (void)funcList->C_CloseSession(session);
    return NULL;
}

/* Create token AES keys, destroying every third one. */
static void* stress_create_keys(void* arg)
{
    StressArgs* args = (StressArgs*)arg;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_HANDLE key;
    byte id[STRESS_ID_SZ];
    byte value[sizeof(aesValue)];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,       &ckTrue,      sizeof(ckTrue)      },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,       value,        sizeof(value)       },
        { CKA_ID,          id,           0                   },
    };
    CK_RV rv;
    int done = 0;
    int i;

    if (open_session(args->slot, NULL, 0, &session) != CKR_OK) {
        stressKeyErr++;
        return NULL;
    }
    for (i = 0; i < STRESS_KEYS && !done; i++) {
        stress_key_id(i, id);
        stress_key_value(i, value);
        tmpl[7].ulValueLen = (CK_ULONG)XSTRLEN((char*)id);
        rv = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &key);
        if (rv == CKR_OK && (i % 3) == 2)
            rv = funcList->C_DestroyObject(session, key);
        else if (rv == CKR_OK)
            stressKeyLive[i] = 1;
        if (rv != CKR_OK)
            stressKeyErr++;

        usleep(STRESS_KEY_DELAY_US);
        pthread_mutex_lock(&stressLock);
        done = stressDone;
        pthread_mutex_unlock(&stressLock);
    }
    (void)funcList->C_CloseSession(session);
    return NULL;
}

/* Every live stress key must exist with its value; destroyed ones must not. */
static CK_RV check_stress_keys(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE key;
    byte id[STRESS_ID_SZ];
    byte expected[sizeof(aesValue)];
    byte value[sizeof(aesValue)];
    CK_ATTRIBUTE getTmpl[] = {
        { CKA_VALUE, value, sizeof(value) },
    };
    int i;

    for (i = 0; rv == CKR_OK && i < STRESS_KEYS; i++) {
        stress_key_id(i, id);
        rv = find_key(session, CKO_SECRET_KEY, id,
                      (CK_ULONG)XSTRLEN((char*)id), &key);
        if (!stressKeyLive[i]) {
            rv = (rv == CKR_GENERAL_ERROR) ? CKR_OK : CKR_GENERAL_ERROR;
            continue;
        }
        if (rv == CKR_OK)
            rv = funcList->C_GetAttributeValue(session, key, getTmpl, 1);
        stress_key_value(i, expected);
        if (rv == CKR_OK && (getTmpl[0].ulValueLen != sizeof(expected) ||
                XMEMCMP(value, expected, sizeof(expected)) != 0)) {
            rv = CKR_GENERAL_ERROR;
        }
    }
    return rv;
}

/* Race PIN changes against each other and key creation, then verify. */
static void run_threaded_phase(byte* curPin, CK_ULONG curPinLen)
{
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    byte startPin[STRESS_PIN_BUF_SZ] = "stress-pin-start";
    StressArgs argsA, argsB, argsC;
    pthread_t threadA, threadB, threadC;
    int startedA, startedB, startedC;

    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, NULL, 0, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, curPin, curPinLen, startPin,
                                STRESS_PIN_LEN);
    }
    CHECK_RV(rv, "set PIN for threaded phase", CKR_OK);
    if (rv != CKR_OK) {
        shutdown_lib(session);
        return;
    }

    XMEMCPY(stressPin, startPin, sizeof(stressPin));
    argsA.slot = argsB.slot = argsC.slot = slot;
    argsA.tag = 'A';
    argsB.tag = 'B';
    argsC.tag = 'K';
    startedA = pthread_create(&threadA, NULL, stress_change_pin, &argsA) == 0;
    startedB = pthread_create(&threadB, NULL, stress_change_pin, &argsB) == 0;
    startedC = pthread_create(&threadC, NULL, stress_create_keys, &argsC) == 0;
    CHECK_TRUE(startedA && startedB && startedC, "start threads");
    if (startedA)
        pthread_join(threadA, NULL);
    if (startedB)
        pthread_join(threadB, NULL);
    pthread_mutex_lock(&stressLock);
    stressDone = 1;
    pthread_mutex_unlock(&stressLock);
    if (startedC)
        pthread_join(threadC, NULL);

    CHECK_TRUE(stressPinErr == 0, "concurrent C_SetPIN only lose races");
    CHECK_TRUE(stressPinOk > 0, "concurrent C_SetPIN made progress");
    CHECK_TRUE(stressKeyErr == 0, "keys created and destroyed concurrently");
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    rv = restart(&slot);
    if (rv == CKR_OK) {
        rv = open_session(slot, stressPin, STRESS_PIN_LEN, &session);
    }
    CHECK_RV(rv, "login with last successfully set PIN", CKR_OK);
    if (rv == CKR_OK)
        rv = check_token_keys(session);
    CHECK_RV(rv, "original keys usable after threaded phase", CKR_OK);
    if (rv == CKR_OK)
        rv = check_stress_keys(session);
    CHECK_RV(rv, "concurrently created keys usable after threaded phase",
             CKR_OK);
    shutdown_lib(session);
}
#endif /* SET_PIN_REKEY_THREADS */

static void run_test(void)
{
    byte* curPin = pin2;
    CK_ULONG curPinLen = sizeof(pin2) - 1;
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    cleanup_test_files();

    /* Phase 1: provision token and create persistent protected keys. */
    rv = restart(&slot);
    CHECK_RV(rv, "initialize (create phase)", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = provision_token(slot);
    CHECK_RV(rv, "provision token", CKR_OK);
    if (rv == CKR_OK)
        rv = open_session(slot, pin1, sizeof(pin1) - 1, &session);
    if (rv == CKR_OK)
        rv = create_token_keys(session);
    CHECK_RV(rv, "create persistent AES and EC keys", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;
    if (rv != CKR_OK)
        return;

    /* Phase 2: change the PIN while logged in as the user. */
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, pin1, sizeof(pin1) - 1, &session);
    if (rv == CKR_OK)
        rv = check_token_keys(session);
    CHECK_RV(rv, "keys usable with original PIN", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, pin1, sizeof(pin1) - 1,
                                pin2, sizeof(pin2) - 1);
    }
    CHECK_RV(rv, "C_SetPIN as logged-in user", CKR_OK);
    if (rv == CKR_OK)
        rv = check_token_keys(session);
    CHECK_RV(rv, "keys usable in same process after C_SetPIN", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    /* Phase 3: after restart only the new PIN works and keys still decrypt. */
    rv = restart(&slot);
    CHECK_RV(rv, "initialize (after user C_SetPIN)", CKR_OK);
    if (rv != CKR_OK)
        return;
    CHECK_RV(login_rejected(slot, pin1, sizeof(pin1) - 1),
             "old PIN rejected", CKR_PIN_INCORRECT);
    rv = open_session(slot, pin2, sizeof(pin2) - 1, &session);
    if (rv == CKR_OK)
        rv = check_token_keys(session);
    CHECK_RV(rv, "keys usable with new PIN after restart", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

#ifndef _WIN32
    /* Phase 3b: logged-in C_SetPIN followed by an unclean process exit. */
    rv = set_pin_then_crash(pin2, sizeof(pin2) - 1, pin4, sizeof(pin4) - 1);
    CHECK_RV(rv, "C_SetPIN as user, exit without C_Finalize", CKR_OK);
    if (rv == CKR_OK) {
        curPin = pin4;
        curPinLen = sizeof(pin4) - 1;
        rv = restart(&slot);
        if (rv == CKR_OK)
            rv = open_session(slot, curPin, curPinLen, &session);
        if (rv == CKR_OK)
            rv = check_token_keys(session);
        CHECK_RV(rv, "keys usable after C_SetPIN and unclean exit", CKR_OK);
        shutdown_lib(session);
        session = CK_INVALID_HANDLE;
    }
#endif

    /* Phase 4: change the PIN from a public R/W session. */
    rv = restart(&slot);
    if (rv == CKR_OK)
        rv = open_session(slot, NULL, 0, &session);
    if (rv == CKR_OK) {
        rv = funcList->C_SetPIN(session, curPin, curPinLen,
                                pin3, sizeof(pin3) - 1);
    }
    CHECK_RV(rv, "C_SetPIN from public R/W session", CKR_OK);
    shutdown_lib(session);
    session = CK_INVALID_HANDLE;

    /* Phase 5: keys decrypt with the PIN set from the public session. */
    rv = restart(&slot);
    CHECK_RV(rv, "initialize (after public C_SetPIN)", CKR_OK);
    if (rv != CKR_OK)
        return;
    rv = open_session(slot, pin3, sizeof(pin3) - 1, &session);
    if (rv == CKR_OK)
        rv = check_token_keys(session);
    CHECK_RV(rv, "keys usable after public-session C_SetPIN and restart",
             CKR_OK);
    shutdown_lib(session);
    curPin = pin3;
    curPinLen = sizeof(pin3) - 1;

#ifdef SET_PIN_STORE_FAIL
    /* Phase 6: C_SetPIN that fails to store leaves the old PIN in effect. */
    if (run_store_fail_phase(curPin, curPinLen)) {
        curPin = pin6;
        curPinLen = sizeof(pin6) - 1;
    }
#endif

#ifdef SET_PIN_REKEY_THREADS
    run_threaded_phase(curPin, curPinLen);
#endif

    cleanup_test_files();
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 C_SetPIN re-encryption test ===\n");
    run_test();
    return pkcs11_test_summary();
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("AES, ECC or token store not available, skipping test\n");
    return 77;
}

#endif
