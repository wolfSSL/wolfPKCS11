/* internal.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
#else
#include "user_settings.h"
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/kdf.h>

/* OS-specific includes for directory creation */
#if defined(_WIN32) || defined(_MSC_VER)
    #include <direct.h>
    #include <io.h>
    #define MKDIR(path) _mkdir(path)
#else
    #include <sys/stat.h>
    #include <errno.h>
    #define MKDIR(path) mkdir(path, 0700)
#endif

#include <wolfpkcs11/internal.h>
#include <wolfpkcs11/store.h>

#ifdef WOLFPKCS11_TPM
    #include <wolftpm/tpm2_wrap.h>
    #include <wolftpm/version.h>

    #ifndef WOLFPKCS11_TPM_CUST_IO
        #include <hal/tpm_io.h>
        #ifndef TPM2_IOCB_CTX
        #define TPM2_IOCB_CTX NULL
        #endif
    #endif
#endif

#ifdef WOLFSSL_MAXQ10XX_CRYPTO
#include <wolfpkcs11/port/maxim/MXQ_API.h>
#include <wolfssl/wolfcrypt/asn.h>
#define MAX_CERT_DATASIZE      2048
#define MAX_SIG_DATASIZE       64
#define ECC_KEYCOMPLEN         32
#endif /* WOLFSSL_MAXQ10XX_CRYPTO */

#if defined(WC_RSA_BLINDING) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
#define WOLFPKCS11_NEED_RSA_RNG
#endif

#if defined(WOLFPKCS11_TPM) && defined(WOLFSSL_MAXQ10XX_CRYPTO)
    #error "wolfTPM and MAXQ10XX are incompatible with each other."
#endif

/* Helper to get size of struct field */
#define FIELD_SIZE(type, field) (sizeof(((type *)0)->field))

/* Size of hash calculated from PIN. */
#define PIN_HASH_SZ                    32
/* Size of seed used when calculating hash from PIN. */
#define PIN_SEED_SZ                    16
/* Size of token's label. */
#define LABEL_SZ                       32

/* Length of seed from global random to seed local random. */
#define RNG_SEED_SZ                    32

/* Maximum size of storage for generated/derived DH key. */
#define WP11_MAX_DH_KEY_SZ             (4096/8)

/* Maximum size of storage for generated/derived symmetric key. */
#ifdef WOLFPKCS11_NSS
#define WP11_MAX_SYM_KEY_SZ            (2048)
#elif !defined(NO_DH)
#define WP11_MAX_SYM_KEY_SZ            (4096/8)
#elif defined(HAVE_ECC)
#define WP11_MAX_SYM_KEY_SZ            ((521+7)/8)
#else
#define WP11_MAX_SYM_KEY_SZ            64
#endif

#ifndef WP11_MAX_CERT_SZ
#define WP11_MAX_CERT_SZ              4096
#endif

#define PKCS11_CHECK_VALUE_SIZE       3

/* Sizes for storage. */
#define WP11_MAX_IV_SZ                 16
#define WP11_MAX_GCM_NONCE_SZ          16
#define WP11_MAX_GCM_TAG_SZ            16
#define WP11_MAX_GCM_TAG_BITS          128

/* wolfSSL ECC signatures are ASN.1 encoding - need to encode and decode. */
#define ASN_INTEGER                    0x02
#define ASN_OCTET_STRING               0x04
#define ASN_OBJECT_ID                  0x06
#define ASN_SEQUENCE                   0x10
#define ASN_CONSTRUCTED                0x20
#define ASN_LONG_LENGTH                0x80

/* Create a session handle from slot id and session id. */
#define SESS_HANDLE(slot, s)           (((slot) << 16) | (s))
/* Determine slot id from session handle. */
#define SESS_HANDLE_SLOT_ID(s)         ((CK_SLOT_ID)((s) >> 16))
/* Determine session id from session handle. */
#define SESS_HANDLE_SESS_ID(s)         ((s) & 0xffff)

/* Create an object handle from a onToken and object id. */
#define OBJ_HANDLE(on, i)              (((on) << 28) | (i))
/* Determine whether object is onToken from object handle. */
#define OBJ_HANDLE_ON_TOKEN(h)         ((int)((h) >> 28))
/* Determine object id from object handle. */
#define OBJ_HANDLE_OBJ_ID(h)           ((h) & 0xfffffff)

#ifdef SINGLE_THREADED
/* Disable locking. */
typedef int WP11_Lock;

#define WP11_Lock_Init(l)              ({ 0; })
#define WP11_Lock_Free(l)
#define WP11_Lock_LockRW(l)            ({ 0; })
#define WP11_Lock_UnlockRW(l)          ({ 0; })
#define WP11_Lock_LockRO(l)            ({ 0; })
#define WP11_Lock_UnlockRO(l)          ({ 0; })

#else
typedef struct WP11_Lock {
    wolfSSL_Mutex read;                /* Mutex for accessing count           */
    wolfSSL_Mutex write;               /* Mutex for writing                   */
    int cnt;                           /* Count of readers                    */
} WP11_Lock;
#endif

#ifdef DEBUG_WOLFPKCS11
int wolfpkcs11_debugging = 0;

void wolfPKCS11_Debugging_On(void)
{
    wolfpkcs11_debugging = 1;
    WOLFPKCS11_MSG("debug logging enabled");
}

void wolfPKCS11_Debugging_Off(void)
{
    WOLFPKCS11_MSG("debug logging disabled");
    wolfpkcs11_debugging = 0;
}
#endif


/* Symmetric key data. */
typedef struct WP11_Data {
    byte data[WP11_MAX_SYM_KEY_SZ];    /* Key data                            */
    word32 len;                        /* Length of key data in bytes         */
} WP11_Data;

/* Certificate */
typedef struct WP11_Cert {
    byte *data;                        /* Certificate data                    */
    word32 len;                        /* Length of certificate data in bytes */
    CK_CERTIFICATE_TYPE type;
} WP11_Cert;

typedef struct WP11_Trust {
    byte sha1Hash[WC_SHA_DIGEST_SIZE];
    byte md5Hash[WC_MD5_DIGEST_SIZE];
    CK_ULONG serverAuth;
    CK_ULONG clientAuth;
    CK_ULONG emailProtection;
    CK_ULONG codeSigning;
    CK_BBOOL stepUpApproved;
} WP11_Trust;

#ifndef NO_DH
typedef struct WP11_DhKey {
    byte key[WP11_MAX_DH_KEY_SZ];      /* Public or private key               */
    word32 len;                        /* Length of public key                */
    DhKey params;                      /* DH parameters object                */
} WP11_DhKey;
#endif

struct WP11_Object {
    union {
    #ifndef NO_RSA
        RsaKey* rsaKey;                /* RSA key object                      */
    #endif
    #ifdef HAVE_ECC
        ecc_key* ecKey;                /* EC key object                       */
    #endif
    #ifndef NO_DH
        WP11_DhKey* dhKey;             /* DH parameters object                */
    #endif
        WP11_Data* symmKey;            /* Symmetric key object                */
        WP11_Cert cert;                /* Certificate object                  */
    #ifdef WOLFPKCS11_NSS
        WP11_Trust trust;              /* Trust object                        */
    #endif
    } data;
#ifdef WOLFPKCS11_TPM
    WOLFTPM2_KEYBLOB* tpmKey;
#endif
    CK_KEY_TYPE type;                  /* Key type of this object             */
    word32 size;                       /* Size of the key in bits or bytes    */
#ifndef WOLFPKCS11_NO_STORE
    unsigned char* keyData;            /* Encoded key data                    */
    int keyDataLen;                    /* Length of encoded key data          */
    byte iv[GCM_NONCE_MID_SZ];         /* IV/nonce for encrypt/decrypt        */
    byte encoded:1;                    /* Key isn't in decoded form           */
#endif

    WP11_Session* session;             /* Session object belongs to           */
    WP11_Slot* slot;                   /* Slot object belongs to              */

    CK_OBJECT_HANDLE handle;           /* Handle of this object               */
    CK_OBJECT_CLASS objClass;          /* Object class                        */
    CK_MECHANISM_TYPE keyGenMech;      /* Key Gen mechanism created with      */
    byte onToken:1;                    /* Object on token or session          */
    byte local:1;                      /* Locally created object              */
    word32 opFlag;                     /* Flags of operations allowed         */

    char startDate[8];                 /* Start date of usage                 */
    char endDate[8];                   /* End data of usage                   */

    unsigned char* keyId;              /* Key identifier                      */
    int keyIdLen;                      /* Length of key identifier            */
    unsigned char* label;              /* Object label                        */
    int labelLen;                      /* Length of object label              */
    unsigned char* issuer;             /* Certificate issuer                  */
    int issuerLen;                     /* Length of certificate issuer        */
    unsigned char* serial;             /* Certificate serial number           */
    int serialLen;                     /* Length of certificate serial number */
    unsigned char* subject;            /* Subject of the object               */
    int subjectLen;                    /* Length of subject                   */

    word32 category;                   /* Category of certificate             */

    WP11_Lock* lock;                   /* Object specific lock                */

    WP11_Object* next;                 /* Next object in linked list          */
};

typedef struct WP11_Find {
    int state;                         /* Whether operation is initialized    */
    CK_OBJECT_HANDLE found[WP11_FIND_MAX];
                                       /* List of object handles found        */
    int count;                         /* Count of object handles             */
    int curr;                          /* Index of last object returned       */
} WP11_Find;

#ifndef NO_RSA
#ifndef WC_NO_RSA_OAEP
typedef struct WP11_OaepParams {
    enum wc_HashType hashType;         /* Type of hash algorithm              */
    int mgf;                           /* Mask Generation Function            */
    byte* label;                       /* Label or AAD                        */
    int labelSz;                       /* Size of label in bytes              */
} WP11_OaepParams;
#endif

#ifdef WC_RSA_PSS
typedef struct WP11_PssParams {
    enum wc_HashType hashType;
    int mgf;
    int saltLen;
} WP11_PssParams;
#endif
#endif

#ifndef NO_AES
#ifdef HAVE_AES_CBC
typedef struct WP11_CbcParams {
    unsigned char iv[WP11_MAX_IV_SZ];  /* IV of CBC operation                 */
    Aes aes;                           /* AES object from wolfCrypt           */
    unsigned char partial[AES_BLOCK_SIZE];
                                       /* Partial block when streaming        */
    byte partialSz;                    /* Size of partial block data          */
} WP11_CbcParams;
#endif

#ifdef HAVE_AESCTR
typedef struct WP11_CtrParams {
    Aes aes;                           /* AES object from wolfCrypt           */
} WP11_CtrParams;
#endif

#ifdef HAVE_AESGCM
typedef struct WP11_GcmParams {
    unsigned char iv[WP11_MAX_GCM_NONCE_SZ];
                                       /* IV/nonce data                       */
    int ivSz;                          /* IV/nonce size in bytes              */
    unsigned char* aad;                /* Additional Authentication Data      */
    int aadSz;                         /* AAD size in bytes                   */
    int tagBits;                       /* Authentication tag size in bits     */
    unsigned char authTag[WP11_MAX_GCM_TAG_SZ];
                                       /* Authentication tag calculated       */
    unsigned char* enc;                /* Encrypted data - cached for decrypt */
    int encSz;                         /* Size of encrypted data in bytes     */
} WP11_GcmParams;
#endif

#ifdef HAVE_AESCCM
typedef struct WP11_CcmParams {
    int dataSz;                        /* Data size in bytes                  */
    unsigned char iv[WP11_MAX_GCM_NONCE_SZ];
                                       /* IV/nonce data                       */
    int ivSz;                          /* IV/nonce size in bytes              */
    unsigned char* aad;                /* Additional Authentication Data      */
    int aadSz;                         /* AAD size in bytes                   */
    int macSz;                         /* Size of MAC data in bytes           */
} WP11_CcmParams;
#endif

#ifdef HAVE_AES_KEYWRAP
typedef struct WP11_KeyWrapParams {
    Aes aes;                           /* AES object from wolfCrypt           */
    unsigned char iv[8];               /* IV/nonce data                       */
    word32 ivSz;                       /* IV/nonce size in bytes              */
} WP11_KeyWrapParams;
#endif

#ifdef HAVE_AESCTS
typedef struct WP11_CtsParams {
    unsigned char iv[WP11_MAX_IV_SZ];  /* IV of CBC operation                 */
    Aes aes;                           /* AES object from wolfCrypt           */
} WP11_CtsParams;
#endif
#endif

#ifndef NO_HMAC
typedef struct WP11_Hmac {
    Hmac hmac;
    word32 hmacSz;
} WP11_Hmac;
#endif

typedef struct WP11_Digest {
    wc_HashAlg hash;
    enum wc_HashType hashType;
} WP11_Digest;

#ifdef HAVE_AESCMAC
typedef struct WP11_Cmac {
    Cmac cmac;
    byte sigLen;
} WP11_Cmac;
#endif

typedef struct WP11_TlsMacParams {
    enum wc_MACAlgorithm mac;
    word32 macSz;
    CK_OBJECT_HANDLE key;
    byte server:1;
    byte isTlsPrf:1;
} WP11_TlsMacParams;

struct WP11_Session {
    unsigned char inUse;               /* Indicates session has been opened   */
    CK_SESSION_HANDLE handle;          /* CryptoKi API session handle value   */
    CK_MECHANISM_TYPE mechanism;       /* Op that is being performed          */
    CK_SLOT_ID slotId;                 /* Id of slot that session is on       */
    WP11_Slot* slot;                   /* Slot that session is on             */
    WP11_Object* object;               /* Linked list of objects on session   */
    int objCnt;                        /* Count of objects in session         */
    WP11_Object* curr;                 /* Current object                      */
    WP11_Find find;                    /* Find data                           */
    int init;                          /* Which op is initialized             */
    union {
#ifndef NO_RSA
    #ifndef WC_NO_RSA_OAEP
        WP11_OaepParams oaep;          /* RSA-OAEP parameters                 */
    #endif
    #ifdef WC_RSA_PSS
        WP11_PssParams pss;            /* RSA-PSS parameters                  */
    #endif
#endif
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        WP11_CbcParams cbc;            /* AES-CBC parameters                  */
    #endif
    #ifdef HAVE_AESCTR
        WP11_CtrParams ctr;            /* AES-CTR parameters                  */
    #endif
    #ifdef HAVE_AESGCM
        WP11_GcmParams gcm;            /* AES-GCM parameters                  */
    #endif
    #ifdef HAVE_AESCCM
        WP11_CcmParams ccm;            /* AES-CCM parameters                  */
    #endif
    #ifdef HAVE_AESCTS
        WP11_CtsParams cts;            /* AES-CTS parameters                  */
    #endif
    #ifdef HAVE_AES_KEYWRAP
        WP11_KeyWrapParams kw;         /* AES-KW parameters                   */
    #endif
#endif
#ifndef NO_HMAC
        WP11_Hmac hmac;                /* HMAC parameters                     */
#endif
        WP11_Digest digest;            /* Digest parameters                   */
#ifdef HAVE_AESCMAC
        WP11_Cmac cmac;                /* CMAC parameters                     */
#endif
        WP11_TlsMacParams tlsMac;      /* TLS MAC parameters                  */
    } params;

    byte* data;                        /* Held data for one-shot mechs        */
    word32 dataSz;                     /* Size of held data                   */

    int devId;
    WP11_Session* next;                /* Next session for slot               */
};

typedef struct WP11_Token {
    char label[LABEL_SZ];              /* Token label                         */
    int state;                         /* Token initialize state              */
    byte soPin[PIN_HASH_SZ];           /* SO's PIN hashed with seed           */
    int soPinLen;                      /* Used to indicate PIN set            */
    byte soPinSeed[PIN_SEED_SZ];       /* Seed for calculating SO's PIN       */
    int soFailedLogin;                 /* Count of consecutive failed logins  */
    time_t soLastFailedLogin;          /* Time of last login if it failed     */
    time_t soFailLoginTimeout;         /* Timeout after max login fails       */
    byte userPin[PIN_HASH_SZ];         /* User's PIN hashed with seed         */
    int userPinLen;                    /* Used to indicate PIN set            */
    byte userPinSeed[PIN_SEED_SZ];     /* Seed for calculating user's PIN     */
    int userFailedLogin;               /* Count of consecutive failed logins  */
    time_t userLastFailedLogin;        /* Time of last login if it failed     */
    time_t userFailLoginTimeout;       /* Timeout after max login fails       */
#ifndef WOLFPKCS11_NO_STORE
    byte seed[PIN_SEED_SZ];            /* Seed used to calculate key          */
    byte key[AES_256_KEY_SIZE];        /* Key to en/decrypt private data      */
#endif
    WC_RNG rng;                        /* Random number generator             */
    WP11_Lock rngLock;                 /* Lock for random access              */
    WP11_Lock lock;                    /* Lock for object access              */
    int loginState;                    /* Login state of the token            */
    WP11_Object* object;               /* Linked list of token objects        */
    int objCnt;                        /* Count of objects on token           */
    int tokenFlags;                    /* Flags for token                     */
    int nextObjId;
} WP11_Token;

struct WP11_Slot {
    CK_SLOT_ID id;                     /* CryptoKi API slot id value          */
    WP11_Token token;                  /* Token information for slot          */
    WP11_Session* session;             /* Linked list of sessions             */
    WP11_Lock lock;                    /* Lock for access to slot info        */

    int devId;
#ifdef WOLFPKCS11_TPM
    WOLFTPM2_DEV tpmDev;
    WOLFTPM2_KEY tpmSrk;
    WOLFTPM2_SESSION tpmSession;
    TpmCryptoDevCtx  tpmCtx;
#endif
};


/* Number of slots. */
static int slotCnt = 1;
/* List of slot objects. */
static WP11_Slot slotList[1];
/* Global random used in random API, cryptographic operations and generating
 * seed when creating new hash of PIN.
 */
static WC_RNG globalRandom;
/* Count of times library has had init called. */
static int libraryInitCount = 0;
/* Lock for globals including global random. */
static WP11_Lock globalLock;


#ifndef SINGLE_THREADED
/**
 * Initialize a lock.
 *
 * @param  lock  [in]  Lock object.
 * @return  BAD_MUTEX_E on failure.
 *          0 on success.
 */
static int WP11_Lock_Init(WP11_Lock* lock)
{
    int ret;

    ret = wc_InitMutex(&lock->read);
    if (ret == 0) {
        ret = wc_InitMutex(&lock->write);
        if (ret != 0)
            wc_FreeMutex(&lock->read);
    }
    if (ret == 0)
        lock->cnt = 0;
    if (ret != 0)
        ret = BAD_MUTEX_E;

    return ret;
}

/**
 * Free a lock.
 *
 * @param  lock  [in]  Lock object.
 */
static void WP11_Lock_Free(WP11_Lock* lock)
{
    wc_FreeMutex(&lock->write);
    wc_FreeMutex(&lock->read);
}

/**
 * Lock for read/write.
 *
 * @param  lock  [in]  Lock object.
 * @return  BAD_MUTEX_E on failure.
 *          0 on success.
 */
static int WP11_Lock_LockRW(WP11_Lock* lock)
{
    int ret;

    ret = wc_LockMutex(&lock->write);
#ifdef DEBUG_LOCK
    fprintf(stderr, "LRW: %p - %d\n", &lock->write, lock->cnt);
#endif

    return ret;
}

/**
 * Unlock after read/write.
 *
 * @param  lock  [in]  Lock object.
 * @return  BAD_MUTEX_E on failure.
 *          0 on success.
 */
static int WP11_Lock_UnlockRW(WP11_Lock* lock)
{
    int ret;

#ifdef DEBUG_LOCK
    fprintf(stderr, "URW: %p - %d\n", &lock->write, lock->cnt);
#endif
    ret = wc_UnLockMutex(&lock->write);
    if (ret != 0)
        ret = BAD_MUTEX_E;

    return ret;
}

/**
 * Lock for read-only.
 *
 * @param  lock  [in]  Lock object.
 * @return  BAD_MUTEX_E on failure.
 *          0 on success.
 */
static int WP11_Lock_LockRO(WP11_Lock* lock)
{
    int ret;

    ret = wc_LockMutex(&lock->read);
    if (ret == 0) {
        if (++lock->cnt == 1)
            ret = wc_LockMutex(&lock->write);
#ifdef DEBUG_LOCK
        fprintf(stderr, "LRO: %p - %d\n", &lock->write, lock->cnt);
#endif
    }
    if (ret == 0)
        ret = wc_UnLockMutex(&lock->read);
    if (ret != 0)
        ret = BAD_MUTEX_E;

    return ret;
}

/**
 * Unlock after reading.
 *
 * @param  lock  [in]  Lock object.
 * @return  BAD_MUTEX_E on failure.
 *          0 on success.
 */
static int WP11_Lock_UnlockRO(WP11_Lock* lock)
{
    int ret;

    ret = wc_LockMutex(&lock->read);
    if (ret == 0) {
        if (--lock->cnt == 0)
            ret = wc_UnLockMutex(&lock->write);
#ifdef DEBUG_LOCK
        fprintf(stderr, "URO: %p - %d\n", &lock->write, lock->cnt);
#endif
    }
    if (ret == 0)
        ret = wc_UnLockMutex(&lock->read);
    if (ret != 0)
        ret = BAD_MUTEX_E;

    return ret;
}
#endif

static int Rng_New(WC_RNG* baseRng, WP11_Lock* lock, WC_RNG* rng)
{
    int ret;
    unsigned char seed[RNG_SEED_SZ];

    WP11_Lock_LockRW(lock);
    ret = wc_RNG_GenerateBlock(baseRng, seed, sizeof(seed));
    WP11_Lock_UnlockRW(lock);
    (void)lock;

    if (ret == 0)
        ret = wc_InitRngNonce_ex(rng, seed, sizeof(seed), NULL, INVALID_DEVID);

    return ret;
}

static void Rng_Free(WC_RNG* rng)
{
    wc_FreeRng(rng);
}


/**
 * Allocate and initialize a new session.
 *
 * @param  slot     [in]   Slot object session is connected with.
 * @param  handle   [in]   Session handle for the session object.
 * @param  session  [out]  New, initialized session object or NULL on error.
 * @return  MEMORY_E when dynamic memory allocation fails.
 *          0 on success.
 */
static int wp11_Session_New(WP11_Slot* slot, CK_OBJECT_HANDLE handle,
                            WP11_Session** session)
{
    int ret = 0;
    WP11_Session* sess;

    sess = (WP11_Session*)XMALLOC(sizeof(*sess), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sess == NULL)
        ret = MEMORY_E;

    if (ret == 0) {
        XMEMSET(sess, 0, sizeof(*sess));
        sess->slotId = slot->id;
        sess->slot = slot;
        sess->handle = handle;
        sess->devId = slot->devId;
        *session = sess;
    }

    return ret;
}

/**
 * Check if the slot has an empty user PIN.
 *
 * @param  slot     [in]   Slot object.
 * @return  1 if the slot has an empty user PIN.
 *          0 if the slot does not have an empty user PIN.
 */
int WP11_Slot_Has_Empty_Pin(WP11_Slot* slot)
{
    if (slot == NULL)
        return 0;

    if ((slot->token.tokenFlags & WP11_TOKEN_FLAG_USER_PIN_SET) &&
        (WP11_Slot_CheckUserPin(slot, (char*)"", 0) == 0))
        return 1;

    return 0;
}

/**
 * Check if the slot has an SO PIN set.
 *
 * @param  slot     [in]   Slot object.
 * @return  1 if the slot has an SO PIN set.
 *          0 if the slot does not have an SO PIN set.
 */
int WP11_Slot_SOPin_IsSet(WP11_Slot* slot)
{
    if (slot == NULL)
        return 0;

    return slot->token.tokenFlags & WP11_TOKEN_FLAG_SO_PIN_SET;
}

/**
 * Add a new session to the token in the slot.
 *
 * @param  slot     [in]   Slot object.
 * @param  session  [out]  New, initialized session object or NULL on error.
 * @return  MEMORY_E when out of memory.
 *          0 on success.
 */
static int wp11_Slot_AddSession(WP11_Slot* slot, WP11_Session** session)
{
    int ret;
    CK_OBJECT_HANDLE handle;

    /* Calculate session handle value. */
    if (slot->session != NULL)
        handle = slot->session->handle + 1;
    else
        handle = SESS_HANDLE(slot->id, 1);
    ret = wp11_Session_New(slot, handle, session);
    if (ret == 0) {
        /* Add to front of list */
        (*session)->next = slot->session;
        slot->session = *session;
    }

    return ret;
}

/**
 * Finalize a session - clean-up but don't clear out.
 *
 * @param  session  [in]  Session object.
 */
static void wp11_Session_Final(WP11_Session* session)
{
    WP11_Object* obj;

    if (session->inUse) {
        /* Free objects in session. */
        while ((obj = session->object) != NULL) {
            WP11_Session_RemoveObject(session, obj);
            WP11_Object_Free(obj);
        }
        session->inUse = 0;
    }
    session->curr = NULL;
    /* Finalize any find. */
    WP11_Session_FindFinal(session);

#if !defined(NO_RSA) && !defined(WC_NO_RSA_OAEP)
    if (session->mechanism == CKM_RSA_PKCS_OAEP &&
                                           session->params.oaep.label != NULL) {
        XFREE(session->params.oaep.label, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        session->params.oaep.label = NULL;
    }
#endif
#ifndef NO_RSA
#ifdef HAVE_AES_CBC
    if ((session->mechanism == CKM_AES_CBC ||
                      session->mechanism == CKM_AES_CBC_PAD) && session->init) {
        wc_AesFree(&session->params.cbc.aes);
        session->init = 0;
    }
#endif
#ifdef HAVE_AESCTR
    if (session->mechanism == CKM_AES_CTR && session->init) {
        wc_AesFree(&session->params.ctr.aes);
        session->init = 0;
    }
#endif
#ifdef HAVE_AESGCM
    if (session->mechanism == CKM_AES_GCM) {
        if (session->params.gcm.aad != NULL) {
            XFREE(session->params.gcm.aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            session->params.gcm.aad = NULL;
        }
        if (session->params.gcm.enc != NULL) {
            XFREE(session->params.gcm.enc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            session->params.gcm.enc = NULL;
        }
    }
#endif
#ifdef HAVE_AESCTS
    if (session->mechanism == CKM_AES_CTS && session->init) {
        wc_AesFree(&session->params.cts.aes);
        session->init = 0;
    }
#endif
#ifdef HAVE_AESCCM
    if (session->mechanism == CKM_AES_CCM) {
        if (session->params.ccm.aad != NULL) {
            XFREE(session->params.ccm.aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            session->params.ccm.aad = NULL;
        }
    }
#endif
#endif
}

#ifndef WOLFPKCS11_NO_STORE
#ifndef WOLFPKCS11_CUSTOM_STORE

#ifdef WOLFPKCS11_TPM_STORE

/* determine which hierarchy to store in platform or owner */
#ifndef WOLFPKCS11_TPM_AUTH_TYPE
    #define WOLFPKCS11_TPM_AUTH_TYPE  1 /* 1=TPM_RH_OWNER, 2=TPM_RH_PLATFORM */
#endif

#ifndef WOLFPKCS11_TPM_NV_BASE
    #if WOLFPKCS11_TPM_AUTH_TYPE == 1
        /* Owner Range: 0x1800000 -> 0x1c00000 */
        #undef  WOLFPKCS11_TPM_AUTH_TYPE
        #define WOLFPKCS11_TPM_AUTH_TYPE TPM_RH_OWNER
        #define WOLFPKCS11_TPM_NV_BASE TPM_20_OWNER_NV_SPACE
    #else
        /* Platform Range: 0x1400000 -> 0x1800000 */
        #undef  WOLFPKCS11_TPM_AUTH_TYPE
        #define WOLFPKCS11_TPM_AUTH_TYPE TPM_RH_PLATFORM
        #define WOLFPKCS11_TPM_NV_BASE TPM_20_PLATFORM_MFG_NV_SPACE
    #endif
#endif

typedef struct WP11_TpmStore {
    WOLFTPM2_DEV* dev;
    WOLFTPM2_NV nv;
    word32 offset;
} WP11_TpmStore;
static WP11_TpmStore tpmStores[1]; /* maximum of 1 open store */

/* Internal function to get maximum size for each store type */
static int wolfPKCS11_Store_GetMaxSize(int type, int variableSz)
{
    int maxSz = 0;
    switch (type) {
        case WOLFPKCS11_STORE_TOKEN:
            maxSz =
                FIELD_SIZE(WP11_Token, label) +
                sizeof(word32) + /* soPinLen */
                FIELD_SIZE(WP11_Token, soPinSeed) +
                FIELD_SIZE(WP11_Token, soFailedLogin) +
                FIELD_SIZE(WP11_Token, soLastFailedLogin) +
                FIELD_SIZE(WP11_Token, soFailLoginTimeout) +
                sizeof(word32) + /* userPinLen */
                FIELD_SIZE(WP11_Token, userPinSeed) +
                FIELD_SIZE(WP11_Token, userFailedLogin) +
                FIELD_SIZE(WP11_Token, userLastFailedLogin) +
                FIELD_SIZE(WP11_Token, userFailLoginTimeout) +
                FIELD_SIZE(WP11_Token, seed) +
                FIELD_SIZE(WP11_Token, objCnt) +
                FIELD_SIZE(WP11_Token, tokenFlags) +
                FIELD_SIZE(WP11_Token, nextObjId) +
                variableSz /* soPinLen + userPinLen + (objCnt * long) */
            ;
            break;
        case WOLFPKCS11_STORE_OBJECT:
            maxSz =
                FIELD_SIZE(WP11_Object, iv) +
                FIELD_SIZE(WP11_Object, handle) +
                FIELD_SIZE(WP11_Object, objClass) +
                FIELD_SIZE(WP11_Object, keyGenMech) +
                1 /* FIELD_SIZE(WP11_Object, onToken) */ +
                1 /* FIELD_SIZE(WP11_Object, local) */ +
                4 /* FIELD_SIZE(WP11_Object, flag) */ +
                FIELD_SIZE(WP11_Object, opFlag) +
                FIELD_SIZE(WP11_Object, startDate) +
                FIELD_SIZE(WP11_Object, endDate) +
                sizeof(word32) + /* keyIdLenSz */
                sizeof(word32) + /* labelLen */
                sizeof(word32) + /* issuerLen */
                sizeof(word32) + /* serialLen */
                sizeof(word32) + /* subjectLen */
                FIELD_SIZE(WP11_Object, category) +
                variableSz /* keyIdLen + labelLen + issuerLen + serialLen + subjectLen */
            ;
            break;
        case WOLFPKCS11_STORE_SYMMKEY:
        case WOLFPKCS11_STORE_RSAKEY_PRIV:
        case WOLFPKCS11_STORE_RSAKEY_PUB:
        case WOLFPKCS11_STORE_ECCKEY_PRIV:
        case WOLFPKCS11_STORE_ECCKEY_PUB:
        case WOLFPKCS11_STORE_DHKEY_PRIV:
        case WOLFPKCS11_STORE_DHKEY_PUB:
        case WOLFPKCS11_STORE_CERT:
        case WOLFPKCS11_STORE_TRUST:
            maxSz = sizeof(word32) + variableSz;
            break;

        default:
            maxSz = BAD_FUNC_ARG;
            break;
    }
    return maxSz;
}
#endif /* WOLFPKCS11_TPM_STORE */

/* Functions that handle storing data. */

int wolfPKCS11_Store_Remove(int type, CK_ULONG id1, CK_ULONG id2)
{
    int ret;
#ifndef WOLFPKCS11_NO_ENV
    const char* str = NULL;
#endif
#ifdef WOLFPKCS11_TPM_STORE
    WP11_TpmStore* tpmStore = &tpmStores[0];
    word32 nvIndex;
    WOLFTPM2_HANDLE parent;
#else
    void* storage = NULL;
#endif

#ifdef WOLFPKCS11_DEBUG_STORE
    printf("Store remove: Type %d, id1 %ld, id2 %ld\n", type, id1, id2);
#endif

#ifndef WOLFPKCS11_NO_ENV
    str = XGETENV("WOLFPKCS11_NO_STORE");
    if (str != NULL) {
        return NOT_AVAILABLE_E;
    }
#endif

#ifdef WOLFPKCS11_TPM_STORE
    /* Build unique handle */
    nvIndex = WOLFPKCS11_TPM_NV_BASE +
                ((type & 0x0F) << 16) +
         (((word32)id1 & 0xFF) << 8) +
          ((word32)id2 & 0xFF);

    XMEMSET(&parent, 0, sizeof(parent));
    parent.hndl = WOLFPKCS11_TPM_AUTH_TYPE;
    ret = wolfTPM2_NVDeleteAuth(tpmStore->dev, &parent, nvIndex);
    if (ret != 0) {
        printf("Error %d (%s) removing NV handle 0x%x: \n",
            ret, wolfTPM2_GetRCString(ret), nvIndex);
    }
#else
    /* truncate the storage file */
    ret = wolfPKCS11_Store_Open(type, id1, id2, 0, &storage);
    if (ret == 0) {
        wolfPKCS11_Store_Close(storage);
    }
#endif
    return ret;
}

/**
 * Opens access to location to read/write token data.
 *
 * @param [in]   type   Type of data to be stored. See WOLFPKCS11_STORE_*.
 * @param [in]   id1    Numeric identifier 1.
 * @param [in]   id2    Numeric identifier 2.
 * @param [in]   read   1 when opening for read and 0 for write.
 * @param [in]   variableSz additional size needed for type (needed on write)
 * @param [out]  store  Returns file pointer.
 * @return  0 on success.
 * @return  NOT_AVAILABLE_E when data not available.
 * @return  Other value to indicate failure.
 */
int wolfPKCS11_Store_OpenSz(int type, CK_ULONG id1, CK_ULONG id2, int read,
    int variableSz, void** store)
{
    int ret = 0;
#ifndef WOLFPKCS11_NO_ENV
    const char* str = NULL;
#endif
#ifdef WOLFPKCS11_TPM_STORE
    WP11_Slot* slot = &slotList[0];
    WP11_TpmStore* tpmStore = &tpmStores[0];
    word32 nvIndex;
    word32 nvAttributes;
    int maxSz;
    WOLFTPM2_HANDLE parent;
#else
    char name[120] = "\0";
    XFILE file = XBADFILE;
    char homePath[47]; /* Must fit within name buffer size limit */
#endif

#ifdef WOLFPKCS11_DEBUG_STORE
    printf("Store open: Type %d, id1 %ld, id2 %ld, read %d, variableSz %d\n",
        type, id1, id2, read, variableSz);
#endif

#ifndef WOLFPKCS11_NO_ENV
    str = XGETENV("WOLFPKCS11_NO_STORE");
    if (str != NULL) {
        return NOT_AVAILABLE_E;
    }
#endif

#ifdef WOLFPKCS11_TPM_STORE
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(tpmStore, 0, sizeof(*tpmStore));
    tpmStore->dev = &slot->tpmDev;

    /* Build unique handle */
    nvIndex = WOLFPKCS11_TPM_NV_BASE +
                ((type & 0x0F) << 16) +
         (((word32)id1 & 0xFF) << 8) +
          ((word32)id2 & 0xFF);

    maxSz = wolfPKCS11_Store_GetMaxSize(type, variableSz);
    if (maxSz <= 0) {
        ret = NOT_AVAILABLE_E;
    }
    if (ret == 0) {
        TPMS_NV_PUBLIC nvPublic;
        XMEMSET(&nvPublic, 0, sizeof(nvPublic));

        /* Get NV attributes */
        parent.hndl = WOLFPKCS11_TPM_AUTH_TYPE;
        (void)wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);

        /* If write check if handle is large enough */
        if (!read) {
            ret = wolfTPM2_NVReadPublic(tpmStore->dev, nvIndex, &nvPublic);
            if (ret == 0 && nvPublic.dataSize < maxSz) {
                /* NV is not large enough, delete and re-create */
                printf("Expanding TPM NV Handle 0x%x: %d -> %d\n",
                    nvIndex, nvPublic.dataSize, maxSz);

                ret = wolfTPM2_NVDeleteAuth(tpmStore->dev, &parent, nvIndex);
                if (ret != 0) {
                    printf("Error %d (%s) removing NV handle 0x%x: \n",
                        ret, wolfTPM2_GetRCString(ret), nvIndex);
                }
            }
        }
        /* Try and open handle */
        ret = wolfTPM2_NVOpen(tpmStore->dev, &tpmStore->nv, nvIndex, NULL, 0);
        if (ret != 0) {
            if (!read) {
                ret = wolfTPM2_NVCreateAuth(tpmStore->dev, &parent,
                    &tpmStore->nv, nvIndex, nvAttributes, maxSz, NULL, 0);
            }
            else {
                ret = NOT_AVAILABLE_E; /* read for handle that doesn't exist */
            }
        }
    }
    if (ret == 0) {
        /* place handle into pointer */
        *store = tpmStore;
    }
    #ifdef WOLFPKCS11_DEBUG_STORE
    printf("Store Open %p: ret %d, max size %d, handle 0x%x\n",
        *store, ret, maxSz, nvIndex);
    #endif

#else
    /* Path order:
     * 1. Environment variable WOLFPKCS11_TOKEN_PATH
     * 2. Home directory with .wolfPKCS11 (or APPDIR with wolfPKCS11 for
     * Windows)
     * 3. WOLFPKCS11_DEFAULT_TOKEN_PATH, if set
     * 4. /tmp in Linux, %TEMP% or C:\Windows\Temp in Windows
     */
    #ifndef WOLFPKCS11_NO_ENV
    str = XGETENV("WOLFPKCS11_TOKEN_PATH");
    #endif

    if (str == NULL) {
        const char* homeDir = NULL;

        #if defined(_WIN32) || defined(_MSC_VER)
        homeDir = XGETENV("%APPDIR%");
        if (homeDir != NULL && XSTRLEN(homeDir) <= sizeof(homePath) - 13) {
            int len = XSNPRINTF(homePath, sizeof(homePath), "%s\\wolfPKCS11",
                               homeDir);
            if (len > 0 && len < (int)sizeof(homePath)) {
                str = homePath;
            }
        }
        #else
        homeDir = XGETENV("HOME");
        if (homeDir != NULL && XSTRLEN(homeDir) <= sizeof(homePath) - 13) {
            int len = XSNPRINTF(homePath, sizeof(homePath), "%s/.wolfPKCS11",
                               homeDir);
            if (len > 0 && len < (int)sizeof(homePath)) {
                str = homePath;
            }
        }
        #endif
    }

    #ifdef WOLFPKCS11_DEFAULT_TOKEN_PATH
    if (str == NULL) {
        str = WC_STRINGIFY(WOLFPKCS11_DEFAULT_TOKEN_PATH);
    }
    #else
    if (str == NULL) {
        #if defined(_WIN32) || defined(_MSC_VER)
        str = XGETENV("%TEMP%");
        if (str == NULL) {
            str = "C:\\Windows\\Temp";
        }
        #else
        str = "/tmp";
        #endif
    }
    #endif


    /* 47 is maximum number of character to a filename and path separator. */
    if (str == NULL || (XSTRLEN(str) > sizeof(name) - 47)) {
       return -1;
    }

    /* Set different filename for each type of data and different ids. */
    switch (type) {
        case WOLFPKCS11_STORE_TOKEN:
            XSNPRINTF(name, sizeof(name), "%s/wp11_token_%016lx", str, id1);
            break;
        case WOLFPKCS11_STORE_OBJECT:
            XSNPRINTF(name, sizeof(name), "%s/wp11_obj_%016lx_%016lx", str, id1,
                      id2);
            break;
        case WOLFPKCS11_STORE_SYMMKEY:
            XSNPRINTF(name, sizeof(name), "%s/wp11_symmkey_%016lx_%016lx", str,
                      id1, id2);
            break;
        case WOLFPKCS11_STORE_RSAKEY_PRIV:
            XSNPRINTF(name, sizeof(name), "%s/wp11_rsakey_priv_%016lx_%016lx",
                      str, id1, id2);
            break;
        case WOLFPKCS11_STORE_RSAKEY_PUB:
            XSNPRINTF(name, sizeof(name), "%s/wp11_rsakey_pub_%016lx_%016lx",
                      str, id1, id2);
            break;
        case WOLFPKCS11_STORE_ECCKEY_PRIV:
            XSNPRINTF(name, sizeof(name), "%s/wp11_ecckey_priv_%016lx_%016lx",
                      str, id1, id2);
            break;
        case WOLFPKCS11_STORE_ECCKEY_PUB:
            XSNPRINTF(name, sizeof(name), "%s/wp11_ecckey_pub_%016lx_%016lx",
                      str, id1, id2);
            break;
        case WOLFPKCS11_STORE_DHKEY_PRIV:
            XSNPRINTF(name, sizeof(name), "%s/wp11_dhkey_priv_%016lx_%016lx",
                      str, id1, id2);
            break;
        case WOLFPKCS11_STORE_DHKEY_PUB:
            XSNPRINTF(name, sizeof(name), "%s/wp11_dhkey_pub_%016lx_%016lx",
                      str, id1, id2);
            break;
        case WOLFPKCS11_STORE_CERT:
            XSNPRINTF(name, sizeof(name), "%s/wp11_cert_%016lx_%016lx",
                      str, id1, id2);
            break;
        case WOLFPKCS11_STORE_TRUST:
            XSNPRINTF(name, sizeof(name), "%s/wp11_trust_%016lx_%016lx",
                      str, id1, id2);
            break;

        default:
            ret = -1;
            break;
    }

    /* Open file for read or write. */
    if (ret == 0) {
        if (read) {
            file = XFOPEN(name, "r");
            if (file == NULL) {
                ret = NOT_AVAILABLE_E;
            }
        }
        else {
            file = XFOPEN(name, "w");
            if (file == NULL) {
                /* Try to create directory if it doesn't exist */
                char* lastSlash = NULL;
                char dirPath[120];
                int i;

                /* Find the last directory separator */
                for (i = 0; name[i] != '\0'; i++) {
                    if (name[i] == '/' || name[i] == '\\') {
                        lastSlash = (char*)&name[i];
                    }
                }

                if (lastSlash != NULL) {
                    /* Extract directory path */
                    int dirLen = (int)(lastSlash - name);
                    if (dirLen > 0 && dirLen < (int)sizeof(dirPath)) {
                        XMEMCPY(dirPath, name, dirLen);
                        dirPath[dirLen] = '\0';

                        /* Try to create the directory */
                        if (MKDIR(dirPath) == 0 || errno == EEXIST) {
                            /* Directory created or already exists, try opening file again */
                            file = XFOPEN(name, "w");
                        }
                    }
                }

                if (file == NULL) {
                    ret = READ_ONLY_E;
                }
            }
        }
    }

    if (ret == 0) {
        /* Return the file pointer. */
        *store = file;
    }
    (void)variableSz; /* not used */
    #ifdef WOLFPKCS11_DEBUG_STORE
    printf("Store Open %p: ret %d, name %s\n", *store, ret, name);
    #endif
#endif
    return ret;
}

/**
 * Opens access to location to read/write token data.
 *
 * @param [in]   type   Type of data to be stored. See WOLFPKCS11_STORE_*.
 * @param [in]   id1    Numeric identifier 1.
 * @param [in]   id2    Numeric identifier 2.
 * @param [in]   read   1 when opening for read and 0 for write.
 * @param [out]  store  Returns file pointer.
 * @return  0 on success.
 * @return  NOT_AVAILABLE_E when data not available.
 * @return  Other value to indicate failure.
 */
int wolfPKCS11_Store_Open(int type, CK_ULONG id1, CK_ULONG id2, int read,
    void** store)
{
    return wolfPKCS11_Store_OpenSz(type, id1, id2, read, 0, store);
}

/**
 * Closes access to location being read or written.
 * Any dynamic memory associated with the store is freed here.
 *
 * @param [in]  store  Context for operation.
 */
void wolfPKCS11_Store_Close(void* store)
{
#ifdef WOLFPKCS11_TPM_STORE
    WP11_TpmStore* tpmStore = (WP11_TpmStore*)store;
#else
    XFILE file = (XFILE)store;
#endif

#ifdef WOLFPKCS11_DEBUG_STORE
    printf("Store close: %p\n", store);
#endif

#ifdef WOLFPKCS11_TPM_STORE
    /* nothing to do for TPM */
    (void)tpmStore;
#else
    /* Close a valid file pointer. */
    if (file != XBADFILE) {
        XFCLOSE(file);
    }
#endif
}

/**
 * Reads a specific number of bytes into buffer.
 *
 * @param [in]       store   Context for operation.
 * @param [in, out]  buffer  Buffer to hold data read.
 * @param [in]       len     Length of data required.
 * @return  Length of data read into buffer.
 * @return  -ve to indicate failure.
 */
int wolfPKCS11_Store_Read(void* store, unsigned char* buffer, int len)
{
    int ret = BUFFER_E;
#ifdef WOLFPKCS11_TPM_STORE
    WP11_TpmStore* tpmStore = (WP11_TpmStore*)store;
    word32 readSize;
#else
    XFILE file = (XFILE)store;
#endif

#ifdef WOLFPKCS11_DEBUG_STORE
    printf("Store %p read: buffer %p, len %d\n", store, buffer, len);
#endif
#ifdef WOLFPKCS11_TPM_STORE
    readSize = len;
    wolfTPM2_SetAuthHandle(tpmStore->dev, 0, &tpmStore->nv.handle);
    ret = wolfTPM2_NVReadAuth(tpmStore->dev, &tpmStore->nv,
        tpmStore->nv.handle.hndl, buffer, &readSize, tpmStore->offset);
    if (ret == 0) {
        tpmStore->offset += readSize;
        ret = readSize;
    }
    else {
        /* calling code expects BUFFER_E if the read is out of range */
        if (ret == TPM_RC_NV_RANGE)
            ret = BUFFER_E;
        else {
            /* log failure and make negative error code */
        #ifdef WOLFPKCS11_DEBUG_STORE
            printf("TPM NV Read Error 0x%x: %s\n", ret, wolfTPM2_GetRCString(ret));
        #endif
            ret = -ret;
        }
    }
#else
    /* Read from a valid file pointer. */
    if (file != XBADFILE) {
        ret = (int)XFREAD(buffer, 1, len, file);
    }
#endif
    return ret;
}

/**
 * Writes a specific number of bytes from buffer.
 *
 * @param [in]  store   Context for operation.
 * @param [in]  buffer  Data to write.
 * @param [in]  len     Length of data to write.
 * @return  Length of data written into buffer.
 * @return  -ve to indicate failure.
 */
int wolfPKCS11_Store_Write(void* store, unsigned char* buffer, int len)
{
    int ret = BUFFER_E;
#ifdef WOLFPKCS11_TPM_STORE
    WP11_TpmStore* tpmStore = (WP11_TpmStore*)store;
#else
    XFILE file = (XFILE)store;
#endif

#ifdef WOLFPKCS11_DEBUG_STORE
    printf("Store %p write: buffer %p, len %d\n", store, buffer, len);
#endif

#ifdef WOLFPKCS11_TPM_STORE
    ret = wolfTPM2_NVWriteAuth(tpmStore->dev, &tpmStore->nv,
        tpmStore->nv.handle.hndl, buffer, len, tpmStore->offset);
    if (ret == 0) {
        tpmStore->offset += len;
        ret = len;
    }
#else
    /* Write to a valid file pointer. */
    if (store != XBADFILE) {
        ret = (int)XFWRITE(buffer, 1, len, file);
        if (ret == len) {
           /* Ensure data makes it to storage. */
           (void)XFFLUSH(file);
        }
    }
#endif

    return ret;
}
#endif

/*
 * Opens access to location to read token data.
 *
 * @param [in]   type   Type of data to be stored. See WOLFPKCS11_STORE_*.
 * @param [in]   id1    Numeric identifier 1.
 * @param [in]   id2    Numeric identifier 2.
 * @param [in]   read   1 when opening for read and 0 for write.
 * @param [in]   variableSz additional size needed for type
 * @param [out]  store  Returns pointer to context data.
 * @return  0 on success.
 * @return  NOT_AVAILABLE_E when data not available.
 * @return  Other value to indicate failure.
 */
static int wp11_storage_open_readonly(int type, CK_ULONG id1, CK_ULONG id2,
                              void** storage)
{
    return wolfPKCS11_Store_Open(type, id1, id2, 1, storage);
}

/*
 * Opens access to location to write token data.
 *
 * @param [in]   type   Type of data to be stored. See WOLFPKCS11_STORE_*.
 * @param [in]   id1    Numeric identifier 1.
 * @param [in]   id2    Numeric identifier 2.
 * @param [in]   variableSz additional size needed for type
 * @param [out]  store  Returns pointer to context data.
 * @return  0 on success.
 * @return  NOT_AVAILABLE_E when data not available.
 * @return  Other value to indicate failure.
 */
static int wp11_storage_open(int type, CK_ULONG id1, CK_ULONG id2,
                             int variableSz, void** storage)
{
#ifdef WOLFPKCS11_TPM_STORE
    return wolfPKCS11_Store_OpenSz(type, id1, id2, 0, variableSz, storage);
#else
    (void)variableSz; /* not used */
    return wolfPKCS11_Store_Open(type, id1, id2, 0, storage);
#endif
}

static int wp11_storage_remove(int type, CK_ULONG id1, CK_ULONG id2)
{
    return wolfPKCS11_Store_Remove(type, id1, id2);
}

/*
 * Closes access to location being read or written.
 * Any dynamic memory associated with the store is freed here.
 *
 * @param [in]  store  Context for operation.
 */
static void wp11_storage_close(void* storage)
{
    wolfPKCS11_Store_Close(storage);
}

/**
 * Reads a specific number of bytes into buffer.
 *
 * @param [in]       store   Context for operation.
 * @param [in, out]  buffer  Buffer to hold data read.
 * @param [in]       len     Length of data required.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_read(void* storage, unsigned char* buffer, int len)
{
    int ret = 0;
    unsigned char* p = buffer;

    /* Keep reading until no data returned, error or full. */
    while (len > 0) {
        ret = wolfPKCS11_Store_Read(storage, p, len);
        if (ret <= 0) {
            break;
        }
        len -= ret;
        p += ret;
    }
    if (len == 0) {
        /* All read successfully. */
        ret = 0;
    }
    else if (ret == 0) {
        /* Failed to read all data. */
        ret = BUFFER_E;
    }

    return ret;
}

/**
 * Writes a specific number of bytes from buffer.
 *
 * @param [in]  store   Context for operation.
 * @param [in]  buffer  Data to write.
 * @param [in]  len     Length of data to write.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write(void* storage, unsigned char* buffer, int len)
{
    int ret = 0;
    unsigned char* p = buffer;

    /* Keep writing until no data written, error or all written. */
    while (len > 0) {
        ret = wolfPKCS11_Store_Write(storage, p, len);
        if (ret <= 0) {
            break;
        }
        len -= ret;
        p += ret;
    }
    if (len == 0) {
        /* All written successfully. */
        ret = 0;
    }
    else if (ret == 0) {
        /* Failed to write all data. */
        ret = BUFFER_E;
    }

    return ret;
}

/**
 * Read a boolean value.
 *
 * @param [in]       store  Context for operation.
 * @param [in, out]  val    Boolean value read.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_read_boolean(void* storage, byte* val)
{
    return wp11_storage_read(storage, val, sizeof(byte));
}

/**
 * Write a boolean value.
 *
 * @param [in]  store  Context for operation.
 * @param [in]  val    Boolean value to write.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write_boolean(void* storage, byte val)
{
     return wp11_storage_write(storage, &val, sizeof(byte));
}

/**
 * Read an integer value.
 *
 * @param [in]       store  Context for operation.
 * @param [in, out]  val    Integer value read.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_read_int(void* storage, int* val)
{
    int ret;
    unsigned char num[sizeof(int)];
    int i;

    /* Read big-endian byte array. */
    ret = wp11_storage_read(storage, num, sizeof(num));
    if (ret == 0) {
        /* Convert to integer. */
        *val = num[0];
        for (i = 1; i < (int)sizeof(num); i++) {
            *val <<= 8;
            *val += num[i];
        }
    }

    return ret;
}

/**
 * Write an integer value.
 *
 * @param [in]  store  Context for operation.
 * @param [in]  val    Integer value to write.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write_int(void* storage, int val)
{
    unsigned char num[sizeof(int)];
    int i;

    /* Convert integer to big-endian byte array. */
    for (i = 0; i < (int)sizeof(num); i++) {
        num[i] = val >> ((sizeof(num) - 1 - i) * 8);
    }

    /* Write big-endian byte array. */
    return wp11_storage_write(storage, num, sizeof(num));
}

/**
 * Read an unsigned 32-bit value.
 *
 * @param [in]       store  Context for operation.
 * @param [in, out]  val    Unsigned 32-bit value read.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_read_word32(void* storage, word32* val)
{
    int ret;
    unsigned char num[4];

    /* Read big-endian byte array. */
    ret = wp11_storage_read(storage, num, sizeof(num));
    if (ret == 0) {
        /* Convert to 32-bit value. */
        *val = ((int)num[0] << 24) |
               ((int)num[1] << 16) |
               ((int)num[2] <<  8) |
               ((int)num[3] <<  0);
    }

    return ret;
}

/**
 * Write an unsigned 32-bit value.
 *
 * @param [in]  store  Context for operation.
 * @param [in]  val    Unsigned 32-bit value to write.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write_word32(void* storage, word32 val)
{
    unsigned char num[sizeof(word32)];
    int i;

    /* Convert unsigned 32-bit number to big-endian byte array. */
    for (i = 0; i < (int)sizeof(num); i++) {
        num[i] = val >> ((sizeof(num) - 1 - i) * 8);
    }

    /* Write big-endian byte array. */
    return wp11_storage_write(storage, num, sizeof(num));
}

/**
 * Read an unsigned long value.
 *
 * @param [in]       store  Context for operation.
 * @param [in, out]  val    Unsigned long value read.
 * @return  0 on success.
 */
static int wp11_storage_read_ulong(void* storage, CK_ULONG* val)
{
    int ret;
    unsigned char num[sizeof(CK_ULONG)];
    int i;

    /* Read big-endian byte array. */
    ret = wp11_storage_read(storage, num, sizeof(num));
    if (ret == 0) {
        /* Convert to unsigned long value. */
        *val = num[0];
        for (i = 1; i < (int)sizeof(num); i++) {
            *val <<= 8;
            *val += num[i];
        }
    }

    return ret;
}

/**
 * Write an unsigned long value.
 *
 * @param [in]  store  Context for operation.
 * @param [in]  val    Unsigned long value to write.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write_ulong(void* storage, CK_ULONG val)
{
    unsigned char num[sizeof(CK_ULONG)];
    int i;

    /* Convert unsigned long number to big-endian byte array. */
    for (i = 0; i < (int)sizeof(num); i++) {
        num[i] = (unsigned char)(val >> ((sizeof(num) - 1 - i) * 8));
    }

    /* Write big-endian byte array. */
    return wp11_storage_write(storage, num, sizeof(num));
}

/**
 * Read a time_t value.
 *
 * @param [in]       store  Context for operation.
 * @param [in, out]  val    time_t value read.
 * @return  0 on success.
 */
static int wp11_storage_read_time(void* storage, time_t* timeVal)
{
    int ret;
    unsigned char num[sizeof(time_t)];
    int i;

    /* Read big-endian byte array. */
    ret = wp11_storage_read(storage, num, sizeof(num));
    if (ret == 0) {
        /* Convert to time_t value. */
        *timeVal = num[0];
        for (i = 1; i < (int)sizeof(num); i++) {
            *timeVal <<= 8;
            *timeVal += num[i];
        }
    }

    return ret;
}

/**
 * Write an unsigned long value.
 *
 * @param [in]  store  Context for operation.
 * @param [in]  val    Unsigned long value to write.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write_time(void* storage, time_t timeVal)
{
    unsigned char num[sizeof(time_t)];
    int i;

    /* Convert time_t number to big-endian byte array. */
    for (i = 0; i < (int)sizeof(num); i++) {
        num[i] = (unsigned char)(timeVal >> ((sizeof(num) - 1 - i) * 8));
    }

    /* Write big-endian byte array. */
    return wp11_storage_write(storage, num, sizeof(num));
}

/**
 * Read an array of bytes with a fixed length.
 *
 * @param [in]       store   Context for operation.
 * @param [in, out]  buffer  Buffer to hold data read.
 * @param [in]       len     Length of data to read.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_read_fixed_array(void* storage,
                                         unsigned char* buffer, int len)
{
    return wp11_storage_read(storage, buffer, len);
}

/**
 * Write an array of bytes with a fixed length.
 *
 * @param [in]  store   Context for operation.
 * @param [in]  buffer  Data to write.
 * @param [in]  len     Length of data to write.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write_fixed_array(void* storage,
                                          unsigned char* buffer, int len)
{
    return wp11_storage_write(storage, buffer, len);
}

/**
 * Read an array of bytes with variable length.
 *
 * @param [in]       store   Context for operation.
 * @param [in, out]  buffer  Buffer to hold data read.
 * @param [in, out]  len     Length of data read.
 * @param [in]       max     Length of buffer.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_read_array(void* storage, unsigned char* buffer,
                                   word32* len, word32 max)
{
    int ret;

    /* Read length of array. */
    ret = wp11_storage_read_word32(storage, len);
    if (ret == 0 && *len > max) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Read array data. */
        ret = wp11_storage_read(storage, buffer, *len);
    }

    return ret;
}

/**
 * Write an array of bytes with variable length.
 *
 * @param [in]  store   Context for operation.
 * @param [in]  buffer  Data to write.
 * @param [in]  len     Length of data to write.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write_array(void* storage,
                                    unsigned char* buffer, word32 len)
{
    int ret;

    /* Write length of array. */
    ret = wp11_storage_write_word32(storage, len);
    if (ret == 0) {
        /* Write array. */
        ret = wp11_storage_write(storage, buffer, len);
    }

    return ret;
}

/**
 * Read an array of bytes with variable length and allocate buffer to hold it.
 *
 * @param [in]       store   Context for operation.
 * @param [in, out]  buffer  Buffer to hold data read.
 * @param [in]       len     Length of data to read.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int wp11_storage_read_alloc_array(void* storage,
                                         unsigned char** buffer, int* len)
{
    int ret;

    /* Read length of array. */
    ret = wp11_storage_read_int(storage, len);
    if (ret == 0 && *len > 0) {
        /* Allocate buffer to hold data. */
        *buffer = (unsigned char*)XMALLOC(*len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*buffer == NULL)
            ret = MEMORY_E;

        if (ret == 0) {
            /* Read array data into allocated buffer. */
            ret = wp11_storage_read(storage, *buffer, *len);
            if (ret != 0) {
                XFREE(*buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                *buffer = NULL;
            }
        }
    }

    return ret;
}

/**
 * Read a string.
 *
 * @param [in]       store  Context for operation.
 * @param [in, out]  str    Buffer to hold string.
 * @param [in]       max    Maximum length allowed for string.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_read_string(void* storage, char* str, int max)
{
    return wp11_storage_read(storage, (unsigned char*)str, max);
}

/**
 * Write an array of bytes with variable length.
 *
 * @param [in]  store  Context for operation.
 * @param [in]  str    String to write.
 * @param [in]  max    Maximum length of string.
 * @return  0 on success.
 * @return  BUFFER_E to indicate failure.
 */
static int wp11_storage_write_string(void* storage, char* str, int max)
{
    return wp11_storage_write(storage, (unsigned char *)str, max);
}
#endif /* !WOLFPKCS11_NO_STORE */

/* check all length bytes for equality, return 1 on success and 0 on failure */
int WP11_ConstantCompare(const byte* a, const byte* b, int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ b[i];
    }

    return compareSum == 0 ? 1 : 0;
}

/**
 * Create a new Object object.
 *
 * @param  slot     [in]   Slot object.
 * @param  type     [in]   Type of Object.
 * @param  object   [out]  New Object object.
 * @return  MEMORY_E when dynamic memory allocation fails.
 *          0 on success.
 */
static int wp11_Object_New(WP11_Slot* slot, CK_KEY_TYPE type,
                           WP11_Object** object)
{
    int ret = 0;
    WP11_Object* obj;

    obj = (WP11_Object*)XMALLOC(sizeof(*obj), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (obj == NULL)
        ret = MEMORY_E;

    if (ret == 0) {
        XMEMSET(obj, 0, sizeof(*obj));
        obj->type = type;
        obj->onToken = 0;
        obj->slot = slot;
        obj->keyGenMech = CK_UNAVAILABLE_INFORMATION;
    #ifdef WOLFPKCS11_TPM
        if (type == CKK_EC || type == CKK_RSA) {
            obj->tpmKey = (WOLFTPM2_KEYBLOB*)XMALLOC(sizeof(WOLFTPM2_KEYBLOB),
                NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (obj->tpmKey == NULL) {
                ret = MEMORY_E;
            }
            else {
                XMEMSET(obj->tpmKey, 0, sizeof(WOLFTPM2_KEYBLOB));
                obj->tpmKey->handle.hndl = TPM_RH_NULL;
            }
        }
    #endif
    }

    if (ret == 0) {
        switch (type) {
            #ifdef HAVE_ECC
            case CKK_EC:
                obj->data.ecKey = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL,
                    DYNAMIC_TYPE_ECC);
                if (obj->data.ecKey == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMSET(obj->data.ecKey, 0, sizeof(ecc_key));
                }
                break;
            #endif
            #ifndef NO_RSA
            case CKK_RSA:
                obj->data.rsaKey = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL,
                    DYNAMIC_TYPE_RSA);
                if (obj->data.rsaKey == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMSET(obj->data.rsaKey, 0, sizeof(RsaKey));
                }
                break;
            #endif
            #ifndef NO_DH
            case CKK_DH:
                obj->data.dhKey = (WP11_DhKey*)XMALLOC(sizeof(WP11_DhKey), NULL,
                    DYNAMIC_TYPE_DH);
                if (obj->data.dhKey == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMSET(obj->data.dhKey, 0, sizeof(WP11_DhKey));
                }
                break;
            #endif
            #ifndef NO_AES
            case CKK_AES:
            #endif
            case CKK_GENERIC_SECRET:
                obj->data.symmKey = (WP11_Data*)XMALLOC(sizeof(WP11_Data), NULL,
                    DYNAMIC_TYPE_AES);
                if (obj->data.symmKey == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMSET(obj->data.symmKey, 0, sizeof(WP11_Data));
                }
                break;
            default:
                ret = NOT_AVAILABLE_E;
        }
    }

    if (ret != 0) {
        WP11_Object_Free(obj);
        obj = NULL;
    }

    *object = obj;

    return ret;
}

/**
 * Create a new Object object.
 *
 * @param  session  [in]   Session object.
 * @param  type     [in]   Type of Object.
 * @param  object   [out]  New Object object.
 * @return  MEMORY_E when dynamic memory allocation fails.
 *          0 on success.
 */
int WP11_Object_New(WP11_Session* session, CK_KEY_TYPE type,
                    WP11_Object** object)
{
    return wp11_Object_New(session->slot, type, object);
}

#ifndef NO_RSA
static long GetRsaExponentValue(unsigned char* eData, word32 eSz)
{
    int i;
    long e = 0;

    /* Convert big-endian data into number. */
    for (i = eSz - 1; i >= 0; i--) {
        e <<= 8;
        e |= eData[i];
    }
    return e;
}
#endif

#ifndef WOLFPKCS11_NO_STORE
/**
 * Encrypt the data with AES-GCM.
 *
 * The tag is append to the encrypted data.
 *
 * @param [out]  out    Output buffer to hold encrypted data and tag.
 * @param [in]   data   Data to be encrypted.
 * @param [in]   len    Length of data.
 * @param [in]   key    AES key.
 * @param [in]   keySz  Length of AES key in bytes.
 * @param [in]   iv     IV/nonce.
 * @param [in]   ivSz   Length of IV in bytes.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_EncryptData(byte* out, byte* data, int len, byte* key,
                            int keySz, byte* iv, int ivSz)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, out, data, len, iv, ivSz, out + len,
                                                       AES_BLOCK_SIZE, NULL, 0);
    }

    return ret;
}

/**
 * Decrypt the data with AES-GCM.
 *
 * The tag is append to the encrypted data.
 *
 * @param [out]  out    Output buffer to hold decrypted data.
 * @param [in]   data   Data and tag to be decrypted.
 * @param [in]   len    Length of data.
 * @param [in]   key    AES key.
 * @param [in]   keySz  Length of AES key in bytes.
 * @param [in]   iv     IV/nonce.
 * @param [in]   ivSz   Length of IV in bytes.
 * @return  0 on success.
 * @return  AES_GCM_AUTH_E when encrypted data could not be verified.
 * @return  Other -ve on failure.
 */
static int wp11_DecryptData(byte* out, byte* data, int len, byte* key,
                            int keySz, byte* iv, int ivSz)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, out, data, len, iv, ivSz, data + len,
                                                       AES_BLOCK_SIZE, NULL, 0);
    }

    return ret;
}

/**
 * "Decode" the certificate.
 *
 * Certificates are not encrypted.
 *
 * @param [in, out]  object  Certificate object.
 */
static void wp11_Object_Decode_Cert(WP11_Object* object)
{
    if (object->data.cert.data == NULL) {
        object->data.cert.data = object->keyData;
        object->data.cert.len = object->keyDataLen;
    }
    object->encoded = 0;
}

#ifdef WOLFPKCS11_NSS
/**
 * "Decode" the trust.
 *
 * Trust is not encrypted.
 *
 * @param [in, out]  object  Trust object.
 */
static void wp11_Object_Decode_Trust(WP11_Object* object)
{
    XMEMCPY((unsigned char*)&object->data.trust, object->keyData,
        object->keyDataLen);
    object->encoded = 0;
}
#endif

/**
 * Load a certificate from storage.
 *
 * @param [in, out]  object   Certificate object.
 * @param [in]       tokenId  Id of token this cert belongs to.
 * @param [in]       objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Object_Load_Cert(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    /* Open access to cert. */
    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_CERT, tokenId, objId,
        &storage);
    if (ret == 0) {
        /* Read certificate. */
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
        /* Decode without login needed */
        wp11_Object_Decode_Cert(object);
    }

    return ret;
}

#ifdef WOLFPKCS11_NSS
/**
 * Load trust object from storage.
 *
 * @param [in, out]  object   Trust object.
 * @param [in]       tokenId  Id of token this cert belongs to.
 * @param [in]       objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Object_Load_Trust(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    /* Open access to trust. */
    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_TRUST, tokenId, objId,
        &storage);
    if (ret == 0) {
        /* Read trust. */
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
        wp11_Object_Decode_Trust(object);
    }

    return ret;
}
#endif


#ifdef WOLFSSL_MAXQ10XX_CRYPTO
#ifdef MAXQ10XX_PRODUCTION_KEY
#include "maxq10xx_key.h"
#else
/* TEST KEY. This must be changed for production environments!! */
static mxq_u1 KeyPairImport[] = {
    0xd0,0x97,0x31,0xc7,0x63,0xc0,0x9e,0xe3,0x9a,0xb4,0xd0,0xce,0xa7,0x89,0xab,
    0x52,0xc8,0x80,0x3a,0x91,0x77,0x29,0xc3,0xa0,0x79,0x2e,0xe6,0x61,0x8b,0x2d,
    0x53,0x70,0xcc,0xa4,0x62,0xd5,0x4a,0x47,0x74,0xea,0x22,0xfa,0xa9,0xd4,0x95,
    0x4e,0xca,0x32,0x70,0x88,0xd6,0xeb,0x58,0x24,0xa3,0xc5,0xbf,0x29,0xdc,0xfd,
    0xe5,0xde,0x8f,0x48,0x19,0xe8,0xc6,0x4f,0xf2,0x46,0x10,0xe2,0x58,0xb9,0xb6,
    0x72,0x5e,0x88,0xaf,0xc2,0xee,0x8b,0x6f,0xe5,0x36,0xe3,0x60,0x7c,0xf8,0x2c,
    0xea,0x3a,0x4f,0xe3,0x6d,0x73
};
#endif /* MAXQ10XX_PRODUCTION_KEY */

static int crypto_sha256(const byte *buf, word32 len, byte *hash,
    word32 hashSz, word32 blkSz)
{
    int ret;
    word32 i = 0, chunk;
    wc_Sha256 sha256;

    /* validate arguments */
    if ((buf == NULL && len > 0) || hash == NULL ||
        hashSz < WC_SHA256_DIGEST_SIZE || blkSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* Init Sha256 structure */
    ret = wc_InitSha256(&sha256);
    if (ret != 0) {
        return ret;
    }

    sha256.maxq_ctx.soft_hash = 1;

    while (i < len) {
        chunk = blkSz;
        if ((chunk + i) > len) {
            chunk = len - i;
        }
        /* Perform chunked update */
        ret = wc_Sha256Update(&sha256, (buf + i), chunk);
        if (ret != 0) {
            break;
        }
        i += chunk;
    }

    if (ret == 0) {
        /* Get final digest result */
        ret = wc_Sha256Final(&sha256, hash);
    }
    return ret;
}

static int crypto_ecc_sign(const byte *key, word32 keySz,
    const byte *hash, word32 hashSz, byte *sig, word32* sigSz,
    word32 curveSz, int curveId, WC_RNG* rng)
{
    int ret;
    mp_int r, s;
    ecc_key ecc;

    /* validate arguments */
    if (key == NULL || hash == NULL || sig == NULL || sigSz == NULL ||
        curveSz == 0 || hashSz == 0 || keySz < curveSz ||
        *sigSz < (curveSz * 2)) {
        return BAD_FUNC_ARG;
    }

    /* Initialize signature result */
    XMEMSET(sig, 0, curveSz * 2);

    /* Setup the ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret < 0) {
        return ret;
    }

    ecc.maxq_ctx.hw_ecc = -1;

    /* Setup the signature r/s variables */
    ret = mp_init(&r);
    if (ret != MP_OKAY) {
        wc_ecc_free(&ecc);
        return ret;
    }

    ret = mp_init(&s);
    if (ret != MP_OKAY) {
        mp_clear(&r);
        wc_ecc_free(&ecc);
        return ret;
    }

    ret = wc_ecc_import_private_key_ex(key, keySz, /* private key "d" */
                                       NULL, 0,    /* public (optional) */
                                       &ecc, curveId);

    if (ret == 0) {
        ret = wc_ecc_sign_hash_ex(hash, hashSz, /* computed hash digest */
                                  rng, &ecc,    /* random and key context */
                                  &r, &s);
    }

    if (ret == 0) {
        /* export r/s */
        mp_to_unsigned_bin_len(&r, sig, curveSz);
        mp_to_unsigned_bin_len(&s, sig + curveSz, curveSz);
    }

    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&ecc);
    return ret;
}

static int ECDSA_sign(mxq_u1* dest, int* signlen, mxq_u1* key,
                      mxq_u1* data, mxq_length data_length, int curve)
{
    int ret;
    int hashlen = WC_SHA256_DIGEST_SIZE;
    unsigned char hash[WC_SHA256_DIGEST_SIZE];
    WC_RNG rng;
    int wc_curve_id = ECC_SECP256R1;
    int wc_curve_size = 32;
    word32 sigSz = 0;

    if (curve != MXQ_KEYPARAM_EC_P256R1) {
        return BAD_FUNC_ARG;
    }

    sigSz = (2 * wc_curve_size);
    if (*signlen < (int)sigSz) {
        return BAD_FUNC_ARG;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return ret;
    }

    ret = crypto_sha256(data, data_length, /* input message */
                        hash, hashlen,     /* hash digest result */
                        32                 /* configurable block/chunk size */
                       );

    if (ret == 0) {
        ret = crypto_ecc_sign(
            (key + (2 * wc_curve_size)), wc_curve_size,    /* private key */
            hash, hashlen,               /* computed hash digest */
            dest, &sigSz,                /* signature r/s */
            wc_curve_size,               /* curve size in bytes */
            wc_curve_id,                 /* curve id */
            &rng);

        *signlen = sigSz;
    }

    wc_FreeRng(&rng);
    return ret;
}

static int wp11_maxq10xx_store_cert(int objId, byte *data, word32 len)
{
    DecodedCert decodedCert;
    byte *certBody = NULL;

    int    signature_len = MAX_SIG_DATASIZE;
    mxq_u1 signature[MAX_SIG_DATASIZE];

    int           sign_key_curve = MXQ_KEYPARAM_EC_P256R1;
    int           sign_key_algo = ALGO_ECDSA_SHA_256;

    mxq_err_t mxq_rc;
    mxq_keyuse_t  uu1 = MXQ_KEYUSE_VERIFY_KEY_CERT;
    mxq_algo_id_t aa1 = ALGO_ECDSA_SHA_256;
    mxq_keyuse_t  uu2 = MXQ_KEYUSE_NONE;
    mxq_algo_id_t aa2 = ALGO_NONE;
    int verifkeyid = 0x1000;

    mxq_keytype_id_t key_type = MXQ_KEYTYPE_ECC;
    mxq_keyparam_id_t mxq_keytype = MXQ_KEYPARAM_EC_P256R1;
    int keycomplen = ECC_KEYCOMPLEN;

    mxq_length destlen = MAX_CERT_DATASIZE;
    mxq_u1     dest[MAX_CERT_DATASIZE];

    int ret = 0;

    /* We need the public key offset so we need to decode the cert. */
    InitDecodedCert(&decodedCert, data, len, 0);

    ret = ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
    #ifdef WOLFPKCS11_DEBUG_STORE
    fprintf(stderr, "ParseCert returned %d\n", ret);
    #endif

    if (ret == 0) {
        if (decodedCert.signatureOID != CTC_SHA256wECDSA) {
            #ifdef WOLFPKCS11_DEBUG_STORE
            fprintf(stderr, "MAXQ: signature algo not supported\n");
            #endif
            ret = BAD_FUNC_ARG;
        }

        if (decodedCert.keyOID != ECDSAk) {
            #ifdef WOLFPKCS11_DEBUG_STORE
            fprintf(stderr, "MAXQ: key algo not supported\n");
            #endif
            ret = BAD_FUNC_ARG;
        }

        if (decodedCert.pkCurveOID != ECC_SECP256R1_OID) {
            #ifdef WOLFPKCS11_DEBUG_STORE
            fprintf(stderr, "MAXQ: key curve not supported\n");
            #endif
            ret = BAD_FUNC_ARG;
        }

        certBody = (byte *)decodedCert.source;
    }

    if (ret == 0) {
        mxq_rc = MXQ_Build_EC_Cert(dest, &destlen, key_type, mxq_keytype,
            keycomplen, keycomplen, decodedCert.publicKeyIndex,
            decodedCert.certBegin, decodedCert.sigIndex - decodedCert.certBegin,
            decodedCert.maxIdx, 0, 0, uu1, aa1, uu2, aa2, certBody);
        if (mxq_rc) {
            #ifdef WOLFPKCS11_DEBUG_STORE
            fprintf(stderr, "MAXQ: MXQ_Build_EC_Cert failure\n");
            #endif
            ret = WC_HW_E;
        }
    }

    if (ret == 0) {
        ret = ECDSA_sign(signature, &signature_len, KeyPairImport,
            dest, destlen, sign_key_curve);
        if (ret != 0) {
            #ifdef WOLFPKCS11_DEBUG_STORE
            fprintf(stderr, "MAXQ: wolfssl signing failure\n");
            #endif
        }
    }

    if (ret == 0) {
        mxq_rc = MXQ_ImportRootCert(objId, sign_key_algo, verifkeyid,
            dest, destlen, signature, signature_len);
        if (mxq_rc) {
            #ifdef WOLFPKCS11_DEBUG_STORE
            fprintf(stderr, "MAXQ: MXQ_ImportRootCert failure\n");
            #endif
            ret = WC_HW_E;
        }
    }

    FreeDecodedCert(&decodedCert);
    return ret;
}
#endif /* WOLFSSL_MAXQ10XX_CRYPTO */

/**
 * Store an certificate to storage.
 *
 * @param [in]  object   Certificate object.
 * @param [in]  tokenId  Id of token this cert belongs to.
 * @param [in]  objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Object_Store_Cert(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    if (object->data.cert.len <= 0) {
        ret = BAD_FUNC_ARG;
        goto exit;
    }

    /* Open access to cert. */
    ret = wp11_storage_open(WOLFPKCS11_STORE_CERT, tokenId, objId,
        object->data.cert.len, &storage);
    if (ret == 0) {
        /* Write cert to storage. */
        ret = wp11_storage_write_array(storage, object->data.cert.data,
                                                         object->data.cert.len);
        wp11_storage_close(storage);
    }

#ifdef WOLFSSL_MAXQ10XX_CRYPTO
    /* Save to MAXQ10XX */
    if (ret == 0) {
        ret = wp11_maxq10xx_store_cert(objId, object->data.cert.data,
                                       object->data.cert.len);
    }
#endif /* WOLFSSL_MAXQ10XX_CRYPTO */

exit:
    return ret;
}

#ifdef WOLFPKCS11_NSS
/**
 * Store an trust object to storage.
 *
 * @param [in]  object   Trust object.
 * @param [in]  tokenId  Id of token this cert belongs to.
 * @param [in]  objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Object_Store_Trust(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    /* Open access to trust. */
    ret = wp11_storage_open(WOLFPKCS11_STORE_TRUST, tokenId, objId,
        sizeof(WP11_Trust), &storage);
    if (ret == 0) {
        /* Write trust to storage. */
        ret = wp11_storage_write_array(storage,
            (unsigned char*)&object->data.trust, sizeof(WP11_Trust));
        wp11_storage_close(storage);
    }

    return ret;
}
#endif /* WOLFPKCS11_NSS */

#ifdef WOLFPKCS11_TPM
#if !defined(NO_RSA) || defined(HAVE_ECC)
static int WP11_Object_DecodeTpmKey(WP11_Object* object)
{
    int ret = 0;
    word32 idx = 0;
    UINT16 pubAreaSize = 0;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];

    if (object == NULL || object->keyData == NULL || object->slot == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Extract public size */
    XMEMCPY(&pubAreaSize, object->keyData, sizeof(pubAreaSize));
    idx += sizeof(pubAreaSize);
    if (pubAreaSize <= (UINT16)sizeof(pubAreaBuffer)) {
        /* Parse public */
        /* TODO: pass: sizeof(UINT16) + pubAreaSize (see wolfTPM PR 419) */
        int parsedPubSize = pubAreaSize;
        ret = TPM2_ParsePublic(&object->tpmKey->pub, object->keyData + idx,
            sizeof(object->tpmKey->pub), &parsedPubSize);
        if (ret == 0) {
            idx += sizeof(UINT16) + pubAreaSize;

            XMEMCPY(&object->tpmKey->priv.size, object->keyData + idx,
                sizeof(object->tpmKey->priv.size));
            if (object->tpmKey->priv.size <
                                    (int)sizeof(object->tpmKey->priv.buffer)) {
                idx += sizeof(object->tpmKey->priv.size);
                /* Extract private size and private */
                XMEMCPY(object->tpmKey->priv.buffer, object->keyData + idx,
                    object->tpmKey->priv.size);
            }
            else {
                ret = BUFFER_E;
            }
        }
    }
    else {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        if (object->tpmKey->pub.publicArea.type == TPM_ALG_RSA) {
        #ifndef NO_RSA
            /* load public portion into wolf RsaKey structure */
            ret = wolfTPM2_RsaKey_TpmToWolf(&object->slot->tpmDev,
                (WOLFTPM2_KEY*)object->tpmKey, object->data.rsaKey);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
        else if (object->tpmKey->pub.publicArea.type == TPM_ALG_ECC) {
        #ifdef HAVE_ECC
            /* load public portion into wolf EccKey structure */
            ret = wolfTPM2_EccKey_TpmToWolf(&object->slot->tpmDev,
                (WOLFTPM2_KEY*)object->tpmKey, object->data.ecKey);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
        else {
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}

static int WP11_Object_WrapTpmKey(WP11_Object* object); /* forward declaration */

static int WP11_Object_EncodeTpmKey(WP11_Object* object, byte* keyData,
    int keyDataLen)
{
    int ret = 0;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize = 0;
    int idx = 0;

    if (object == NULL) {
        return BAD_FUNC_ARG;
    }


    /* if key is not already wrapped as a TPM key, wrap it */
    if ((object->opFlag & WP11_FLAG_TPM) == 0) {
        ret = WP11_Object_WrapTpmKey(object);
    }

    /* if this is not a TPM private key, return 0 and encode as DER */
    if (ret == 0 &&
        (object->tpmKey->pub.size == 0 ||
         object->tpmKey->priv.size == 0)) {
        return 0; /* not a TPM key */
    }

    if (ret == 0) {
        /* save off the public and private portion of the TPM key.
         * Private is encrypted by a symmetric key only known by the TPM.
         * Make publicArea in encoded format to eliminate empty fields */
        ret = TPM2_AppendPublic(pubAreaBuffer, (word32)sizeof(pubAreaBuffer),
            &pubAreaSize, &object->tpmKey->pub);
        if (ret == 0) {
            ret = sizeof(UINT16) +
                    sizeof(UINT16) + pubAreaSize +
                    sizeof(UINT16) + object->tpmKey->priv.size;
            if (keyData != NULL) {
                if (ret <= keyDataLen) {
                    /* Write size marker for the public part */
                    XMEMCPY(object->keyData, &pubAreaSize,
                            sizeof(UINT16));
                    idx += sizeof(UINT16);
                    /* Write the public part with bytes aligned */
                    XMEMCPY(object->keyData + idx, pubAreaBuffer,
                            sizeof(UINT16) + pubAreaSize);
                    idx += sizeof(UINT16) + pubAreaSize;
                    /* Write the private part, size marker is included */
                    XMEMCPY(object->keyData + idx, &object->tpmKey->priv,
                            sizeof(UINT16) + object->tpmKey->priv.size);
                    idx += sizeof(UINT16) + object->tpmKey->priv.size;

                    object->opFlag |= WP11_FLAG_TPM;
                }
                else {
                    ret = BUFFER_E;
                }
            }
            else {
                /* return size only */
            }
        }
    }
    return ret;
}
#endif /* !NO_RSA || HAVE_ECC */
#endif /* WOLFPKCS11_TPM */


#ifndef NO_RSA
/**
 * Decode the RSA key.
 *
 * Encoded private keys are encrypted.
 *
 * @param [in, out]  object  RSA key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Decode_RsaKey(WP11_Object* object)
{
    int ret = 0;
    word32 idx = 0;
    RsaKey* key = object->data.rsaKey;

    ret = wc_InitRsaKey_ex(key, NULL, object->slot->devId);
    if (ret != 0) {
        return ret;
    }

#ifdef WOLFPKCS11_TPM
    if (object->opFlag & WP11_FLAG_TPM) {
        ret = WP11_Object_DecodeTpmKey(object);
    }
    else
#endif
    if (object->objClass == CKO_PRIVATE_KEY) {
        unsigned char* der;
        int len = object->keyDataLen - AES_BLOCK_SIZE;

        der = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0) {
            ret = wp11_DecryptData(der, object->keyData, len,
                                    object->slot->token.key,
                                    sizeof(object->slot->token.key), object->iv,
                                    sizeof(object->iv));
        }
        if (ret == 0) {
            /* Decode RSA private key. */
            ret = wc_RsaPrivateKeyDecode(der, &idx, key, len);
            XMEMSET(der, 0, len);
        }
        if (der != NULL)
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    else {
        /* Decode RSA public key. */
        ret = wc_RsaPublicKeyDecode(object->keyData, &idx, key,
                                                            object->keyDataLen);
    }
    object->encoded = (ret != 0);

    return ret;
}

/**
 * Encode the RSA key.
 *
 * Private keys are encoded and then encrypted.
 *
 * @param [in, out]  object  RSA key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Encode_RsaKey(WP11_Object* object)
{
    int ret;

#ifdef WOLFPKCS11_TPM
    ret = WP11_Object_EncodeTpmKey(object, NULL, 0);
    if (ret > 0) {
        object->keyDataLen = ret;
        ret = 0;
    }
    else
#endif
    if (object->objClass == CKO_PRIVATE_KEY) {
    #if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA)
        /* Get length of encoded private key. */
        ret = wc_RsaKeyToDer(object->data.rsaKey, NULL, 0);
        if (ret >= 0) {
            object->keyDataLen = ret + AES_BLOCK_SIZE;
            ret = 0;
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else {
    #if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
        defined(WOLFSSL_CERT_GEN)
        /* Get length of encoded public key. */
        ret = wc_RsaKeyToPublicDer(object->data.rsaKey, NULL, 0);
        if (ret >= 0) {
            object->keyDataLen = ret;
            ret = 0;
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }

    if (ret == 0) {
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        /* Allocate buffer to hold encoded key. */
        object->keyData = (unsigned char*)XMALLOC(object->keyDataLen, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (object->keyData == NULL)
            ret = MEMORY_E;
    }

#ifdef WOLFPKCS11_TPM
    ret = WP11_Object_EncodeTpmKey(object, object->keyData, object->keyDataLen);
    if (ret > 0) {
        ret = 0;
    }
    else
#endif
    if (ret == 0 && object->objClass == CKO_PRIVATE_KEY) {
    #if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA)
        /* Encode private key. */
        ret = wc_RsaKeyToDer(object->data.rsaKey, object->keyData,
                                                            object->keyDataLen);
        if (ret >= 0) {
            ret = wp11_EncryptData(object->keyData, object->keyData, ret,
                                    object->slot->token.key,
                                    sizeof(object->slot->token.key), object->iv,
                                    sizeof(object->iv));
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else if (ret == 0 && object->objClass == CKO_PUBLIC_KEY) {
        /* Encode public key. */
        ret = wc_RsaKeyToPublicDer(object->data.rsaKey, object->keyData,
                                                            object->keyDataLen);
        if (ret >= 0) {
            ret = 0;
        }
    }

    if (ret != 0) {
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    }

    return ret;
}

/**
 * Export the RSA key.
 *
 * Keys are encoded in DER.
 *
 * @param [in, out]  object  RSA key object.
 * @param [out]  output  holds encoded key and can be null.
 * @param [in/out]  poutsz  in and out size of output buffer
 * @return  0 on success.
 * @return  -ve on failure.
 */
int WP11_Rsa_SerializeKey(WP11_Object* object, byte* output, word32* poutsz)
{
    int ret;
    word32 insz, outsz = 0;

    if (object == NULL || poutsz == NULL)
        return PARAM_E;

    insz = *poutsz;

    if (object->type != CKK_RSA)
        return OBJ_TYPE_E;

    if (object->objClass == CKO_PRIVATE_KEY) {
    #if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA)
        /* Get length of encoded private key. */
        ret = wc_RsaKeyToDer(object->data.rsaKey, output, insz);
        if (ret >= 0) {
            outsz = ret;
            ret = 0;
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else {
    #if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
        defined(WOLFSSL_CERT_GEN)
        /* Get length of encoded public key. */
        ret = wc_RsaKeyToPublicDer(object->data.rsaKey, output, insz);
        if (ret >= 0) {
            outsz = ret;
            ret = 0;
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    (void)output;
    (void)insz;

    if (ret == 0)
        *poutsz = outsz;

    return ret;
}

/**
 * Export the RSA key in plain-text PKCS8.
 *
 * Keys are encoded in PKCS8 w/o encryption
 *
 * @param [in, out]  object  RSA key object.
 * @param [out]  output  holds encoded key and can be null.
 * @param [in/out]  poutsz  in and out size of output buffer
 * @return  0 on success.
 * @return  -ve on failure.
 */
int WP11_Rsa_SerializeKeyPTPKC8(WP11_Object* object, byte* output, word32* poutsz)
{
    int ret;
    word32 dersz = 0;
    byte* der = NULL;

    if (object == NULL || poutsz == NULL)
        return PARAM_E;

    if (object->type != CKK_RSA)
        return OBJ_TYPE_E;

    if (object->objClass != CKO_PRIVATE_KEY)
        return OBJ_TYPE_E;

    ret = WP11_Rsa_SerializeKey(object, NULL, &dersz);
    if (ret != 0)
        return ret;

    der = (unsigned char*)XMALLOC(dersz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL)
        return MEMORY_E;

    ret = WP11_Rsa_SerializeKey(object, der, &dersz);

    if ( ret != 0) {
        goto end_func;
    }

    /* Get length of encoded private key. */
    ret = wc_CreatePKCS8Key(output, poutsz, der,
                            dersz, RSAk, NULL, 0);
    if ( ret == LENGTH_ONLY_E || ret > 0)
        ret = 0;

end_func:
    if (NULL != der)
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/**
 * Load an RSA key from storage.
 *
 * @param [in, out]  object   RSA key object.
 * @param [in]       tokenId  Id of token this key belongs to.
 * @param [in]       objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Object_Load_RsaKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;
    int storeType;

    /* Determine store type - private keys may be encrypted. */
    if (object->objClass == CKO_PRIVATE_KEY)
        storeType = WOLFPKCS11_STORE_RSAKEY_PRIV;
    else
        storeType = WOLFPKCS11_STORE_RSAKEY_PUB;

    /* Open access to RSA key. */
    ret = wp11_storage_open_readonly(storeType, tokenId, objId, &storage);
    if (ret == 0) {
        /* Read of DER encoded RSA key. */
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
                                            &object->keyDataLen);
        wp11_storage_close(storage);
    }

    return ret;
}

/**
 * Store an RSA key to storage.
 *
 * @param [in]  object   RSA key object.
 * @param [in]  tokenId  Id of token this key belongs to.
 * @param [in]  objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Object_Store_RsaKey(WP11_Object* object, int tokenId, int objId)
{
    int ret = 0;
    void* storage = NULL;
    int storeType;

    if (object->keyData == NULL) {
        ret = wp11_Object_Encode_RsaKey(object);
        if (ret != 0)
            return ret;
    }

    /* Determine store type - private keys may be encrypted. */
    if (object->objClass == CKO_PRIVATE_KEY)
        storeType = WOLFPKCS11_STORE_RSAKEY_PRIV;
    else
        storeType = WOLFPKCS11_STORE_RSAKEY_PUB;

    /* Open access to RSA key. */
    if (ret == 0)
        ret = wp11_storage_open(storeType, tokenId, objId, object->keyDataLen,
                            &storage);
    if (ret == 0) {
        /* Write encoded RSA key to storage. */
        ret = wp11_storage_write_array(storage, object->keyData,
                                                            object->keyDataLen);

        wp11_storage_close(storage);
    }

    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/**
 * Decode the ECC key.
 *
 * Encoded private keys are encrypted.
 *
 * @param [in, out]  object  ECC key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Decode_EccKey(WP11_Object* object)
{
    int ret = 0;
    word32 idx = 0;
    ecc_key* key = object->data.ecKey;

    ret = wc_ecc_init_ex(key, NULL, object->slot->devId);
    if (ret != 0) {
        return ret;
    }

#ifdef WOLFPKCS11_TPM
    if (object->opFlag & WP11_FLAG_TPM) {
        ret = WP11_Object_DecodeTpmKey(object);
    }
    else
#endif
    if (object->objClass == CKO_PRIVATE_KEY) {
        unsigned char* der;
        int len = object->keyDataLen - AES_BLOCK_SIZE;

        der = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0) {
            ret = wp11_DecryptData(der, object->keyData, len,
                                    object->slot->token.key,
                                    sizeof(object->slot->token.key), object->iv,
                                    sizeof(object->iv));
        }
        if (ret == 0) {
            ret = wc_ecc_init_ex(key, NULL, object->slot->devId);
        }
        if (ret == 0) {
            /* Decode ECC private key. */
            ret = wc_EccPrivateKeyDecode(der, &idx, key, len);
            XMEMSET(der, 0, len);
        }
        if (der != NULL)
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    else {
        /* Decode ECC public key. */
        ret = wc_EccPublicKeyDecode(object->keyData, &idx, key,
                                                            object->keyDataLen);
    }
    object->encoded = (ret != 0);

    return ret;
}

/**
 * Encode the ECC key.
 *
 * Private keys are encoded and then encrypted.
 *
 * @param [in, out]  object  ECC key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Encode_EccKey(WP11_Object* object)
{
    int ret;

#ifdef WOLFPKCS11_TPM
    ret = WP11_Object_EncodeTpmKey(object, NULL, 0);
    if (ret > 0) {
        object->keyDataLen = ret;
        ret = 0;
    }
    else
#endif
    if (object->objClass == CKO_PRIVATE_KEY) {
        /* Get length of encoded private key. */
        ret = wc_EccKeyDerSize(object->data.ecKey, 0);
        if (ret >= 0) {
            object->keyDataLen = ret + AES_BLOCK_SIZE;
            ret = 0;
        }
    }
    else {
        /* Get length of encoded public key. */
        ret = wc_EccPublicKeyToDer(object->data.ecKey, NULL, 0, 1);
        if (ret >= 0) {
            object->keyDataLen = ret;
            ret = 0;
        }
    }

    if (ret == 0) {
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        /* Allocate buffer to hold encoded key. */
        object->keyData = (unsigned char*)XMALLOC(object->keyDataLen, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (object->keyData == NULL)
            ret = MEMORY_E;
    }

#ifdef WOLFPKCS11_TPM
    ret = WP11_Object_EncodeTpmKey(object, object->keyData, object->keyDataLen);
    if (ret > 0) {
        ret = 0;
    }
    else
#endif
    if (ret == 0 && object->objClass == CKO_PRIVATE_KEY) {
        /* Encode private key. */
        ret = wc_EccPrivateKeyToDer(object->data.ecKey, object->keyData,
                                                            object->keyDataLen);
        if (ret >= 0) {
            ret = wp11_EncryptData(object->keyData, object->keyData, ret,
                                    object->slot->token.key,
                                    sizeof(object->slot->token.key), object->iv,
                                    sizeof(object->iv));
        }
    }
    else if (ret == 0 && object->objClass == CKO_PUBLIC_KEY) {
        /* Encode public key. */
        ret = wc_EccPublicKeyToDer(object->data.ecKey, object->keyData,
                                                         object->keyDataLen, 1);
        if (ret >= 0) {
            ret = 0;
        }
    }

    if (ret != 0) {
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    }

    return ret;
}

/**
 * Load an ECC key from storage.
 *
 * @param [in, out]  object   ECC key object.
 * @param [in]       tokenId  Id of token this key belongs to.
 * @param [in]       objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Object_Load_EccKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;
    int storeType;

    /* Determine store type - private keys may be encrypted. */
    if (object->objClass == CKO_PRIVATE_KEY)
        storeType = WOLFPKCS11_STORE_ECCKEY_PRIV;
    else
        storeType = WOLFPKCS11_STORE_ECCKEY_PUB;

    /* Open access to ECC key. */
    ret = wp11_storage_open_readonly(storeType, tokenId, objId, &storage);
    if (ret == 0) {
        /* Read DER encoded ECC key. */
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
                                                           &object->keyDataLen);
        wp11_storage_close(storage);
    }

    return ret;
}

/**
 * Store an ECC key to storage.
 *
 * @param [in]  object   ECC key object.
 * @param [in]  tokenId  Id of token this key belongs to.
 * @param [in]  objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Object_Store_EccKey(WP11_Object* object, int tokenId, int objId)
{
    int ret = 0;
    void* storage = NULL;
    int storeType;

    if (object->keyData == NULL) {
        ret = wp11_Object_Encode_EccKey(object);
        if (ret != 0)
            return ret;
    }

    /* Determine store type - private keys may be encrypted. */
    if (object->objClass == CKO_PRIVATE_KEY)
        storeType = WOLFPKCS11_STORE_ECCKEY_PRIV;
    else
        storeType = WOLFPKCS11_STORE_ECCKEY_PUB;

    /* Open access to ECC key. */
    if (ret == 0)
        ret = wp11_storage_open(storeType, tokenId, objId, object->keyDataLen,
                            &storage);
    if (ret == 0) {
        /* Write encoded ECC key to storage. */
        ret = wp11_storage_write_array(storage, object->keyData,
                                                            object->keyDataLen);

        wp11_storage_close(storage);
    }

    return ret;
}
#endif /* HAVE_ECC */

#ifndef NO_DH
/**
 * Decode the DH key.
 *
 * Encoded private keys are encrypted.
 *
 * @param [in, out]  object  DH key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Decode_DhKey(WP11_Object* object)
{
    int ret = 0;

    if (object->objClass == CKO_PRIVATE_KEY) {
        ret = wp11_DecryptData(object->data.dhKey->key, object->keyData,
                                    object->keyDataLen - AES_BLOCK_SIZE,
                                    object->slot->token.key,
                                    sizeof(object->slot->token.key), object->iv,
                                    sizeof(object->iv));
        if (ret == 0)
            object->data.dhKey->len = object->keyDataLen - AES_BLOCK_SIZE;
    }
    else {
        XMEMCPY(object->data.dhKey->key, object->keyData, object->keyDataLen);
        object->data.dhKey->len = object->keyDataLen;
    }
    object->encoded = (ret != 0);

    return ret;
}

/**
 * Encode the DH key.
 *
 * Private keys are encrypted.
 *
 * @param [in, out]  object  DH key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Encode_DhKey(WP11_Object* object)
{
    int ret = 0;

    object->keyDataLen = object->data.dhKey->len + AES_BLOCK_SIZE;
    XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    /* Allocate buffer to hold encoded key. */
    object->keyData = (unsigned char*)XMALLOC(object->keyDataLen, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (object->keyData == NULL)
        ret = MEMORY_E;

    if (ret == 0) {
        if (object->objClass == CKO_PRIVATE_KEY) {
            ret = wp11_EncryptData(object->keyData, object->data.dhKey->key,
                                    object->data.dhKey->len,
                                    object->slot->token.key,
                                    sizeof(object->slot->token.key), object->iv,
                                    sizeof(object->iv));
            if (ret == 0)
                object->keyDataLen = object->data.dhKey->len + AES_BLOCK_SIZE;
        }
        else {
            XMEMCPY(object->keyData, object->data.dhKey->key,
                                                        object->data.dhKey->len);
            object->keyDataLen = object->data.dhKey->len;
        }
    }

    return ret;
}

/**
 * Load an DH key from storage.
 *
 * @param [in, out]  object   DH key object.
 * @param [in]       tokenId  Id of token this key belongs to.
 * @param [in]       objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Object_Load_DhKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;
    unsigned char* der = NULL;
    int len;
    word32 idx = 0;
    int storeType;

    /* Determine store type - private keys may be encrypted. */
    if (object->objClass == CKO_PRIVATE_KEY)
        storeType = WOLFPKCS11_STORE_DHKEY_PRIV;
    else
        storeType = WOLFPKCS11_STORE_DHKEY_PUB;

    /* Open access to DH key. */
    ret = wp11_storage_open_readonly(storeType, tokenId, objId, &storage);
    if (ret == 0) {
        /* Read DH key. */
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        if (ret == 0) {
            /* Read DER encoded DH parameters. */
            ret = wp11_storage_read_alloc_array(storage, &der, &len);
        }
        if (ret == 0) {
            /* Decode DH parameters. */
            ret = wc_DhKeyDecode(der, &idx, &object->data.dhKey->params, len);
        }
        if (der != NULL) {
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        wp11_storage_close(storage);
    }

    return ret;
}

#if !defined(WOLFSSL_DH_EXTRA) || LIBWOLFSSL_VERSION_HEX < 0x04008000
/* Calculates the minimum number of bytes required to encode the value.
 *
 * @param [in] value  Value to be encoded.
 * @return  Number of bytes to encode value.
 */
static word32 wp11_BytePrecision(word32 value)
{
    word32 i;
    for (i = (word32)sizeof(value); i; --i)
        if (value >> ((i - 1) * 8))
            break;

    return i;
}

/* Encode a length for DER.
 *
 * @param [in]  length  Value to encode.
 * @param [out] output  Buffer to encode into.
 * @return  Number of bytes encoded.
 */
static word32 wp11_SetLength(word32 length, byte* output)
{
    /* Start encoding at start of buffer. */
    word32 i = 0;

    if (length < 0x80) {
        /* Only one byte needed to encode. */
        if (output) {
            /* Write out length value. */
            output[i] = (byte)length;
        }
        /* Skip over length. */
        i++;
    }
    else {
        /* Calculate the number of bytes required to encode value. */
        byte j = (byte)wp11_BytePrecision(length);

        if (output) {
            /* Encode count byte. */
            output[i] = j | 0x80;
        }
        /* Skip over count byte. */
        i++;

        /* Encode value as a big-endian byte array. */
        for (; j > 0; --j) {
            if (output) {
                /* Encode next most-significant byte. */
                output[i] = (byte)(length >> ((j - 1) * 8));
            }
            /* Skip over byte. */
            i++;
        }
    }

    /* Return number of bytes in encoded length. */
    return i;
}

/* Encode DH key parameters to DER format into output and setting len to outSz.
 *
 * If output is NULL then max expected size is set to outSz and LENGTH_ONLY_E is
 * returned.
 *
 * Assumes key and outSz are not NULL.
 *
 * @param [in]   key     Dh key with parameters.
 * @param [out]  output  Buffer to place DER data. May be NULL.
 * @param [out]  outSz   Length of DER data.
 *
 * @return  Number of bytes written on success
 * @return  LENGTH_ONLY_E when NULL output buffer passed in. outSz will be set.
 * @return  Other -ve on failure.
 */
static int wp11_DhParamsToDer(DhKey* key, byte* output, word32* outSz)
{
    int ret = 0;
    word32 len = 0, idx = 0, len2;

    len  = 5;                               /* Sequence */
    len += 1 + 4;                           /* Integer */
    len += mp_leading_bit(&key->p) ? 1 : 0;
    len += mp_unsigned_bin_size(&key->p);
    len += 1 + 4;                           /* Integer */
    len += mp_leading_bit(&key->g) ? 1 : 0;
    len += mp_unsigned_bin_size(&key->g);

    if (output == NULL) {
        *outSz = len;
        return LENGTH_ONLY_E;
    }

    if (ret == 0) {
        idx = len;
        len2 = mp_unsigned_bin_size(&key->g);
        idx -= len2;
        ret = mp_to_unsigned_bin(&key->g, output + idx);
    }
    if (ret >= 0) {
        if (mp_leading_bit(&key->g)) {
            output[--idx] = 0x00;
            len2++;
        }
        idx -= wp11_SetLength(len2, NULL);
        wp11_SetLength(len2, output + idx);
        output[--idx] = 0x02;

        len2 = mp_unsigned_bin_size(&key->p);
        idx -= len2;
        ret = mp_to_unsigned_bin(&key->p, output + idx);
    }
    if (ret >= 0) {
        if (mp_leading_bit(&key->p)) {
            output[--idx] = 0x00;
            len2++;
        }
        idx -= wp11_SetLength(len2, NULL);
        wp11_SetLength(len2, output + idx);
        output[--idx] = 0x02;

        len2 = len - idx;
        idx -= wp11_SetLength(len2, NULL);
        idx -= 1;
        output[idx] = 0x30;
        wp11_SetLength(len2, output + idx + 1);
    }
    if (ret >= 0) {
        XMEMMOVE(output, output + idx, len - idx);
        *outSz = len - idx;
    }

    return ret;
}

#define wc_DhParamsToDer    wp11_DhParamsToDer
#endif /* !WOLFSSL_DH_EXTRA || LIBWOLFSSL_VERSION_HEX < 0x04008000 */

/**
 * Store an DH key to storage.
 *
 * @param [in]  object   DH key object.
 * @param [in]  tokenId  Id of token this key belongs to.
 * @param [in]  objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Object_Store_DhKey(WP11_Object* object, int tokenId, int objId)
{
    int ret = 0;
    void* storage = NULL;
    unsigned char* der = NULL;
    word32 len = 0;
    int storeType;

    if (object->keyData == NULL) {
        ret = wp11_Object_Encode_DhKey(object);
    }
    if (ret == 0) {
        /* Get length of encoded DH parameters. */
        ret = wc_DhParamsToDer(&object->data.dhKey->params, NULL, &len);
        if (ret == LENGTH_ONLY_E) {
            ret = 0;
        }
    }
    if (ret == 0) {
        /* Allocate buffer to hold encoded key. */
        der = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        /* Encode DH parameters. */
        ret = wc_DhParamsToDer(&object->data.dhKey->params, der, &len);
        if (ret >= 0) {
            ret = 0;
        }
    }

    /* Determine store type - private keys may be encrypted. */
    if (object->objClass == CKO_PRIVATE_KEY)
        storeType = WOLFPKCS11_STORE_DHKEY_PRIV;
    else
        storeType = WOLFPKCS11_STORE_DHKEY_PUB;

    /* Open access to DH key. */
    if (ret == 0) {
        ret = wp11_storage_open(storeType, tokenId, objId,
            object->keyDataLen + len, &storage);
    }
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, object->keyData,
                                                            object->keyDataLen);
        if (ret == 0) {
            /* Write encoded DH parameters to storage. */
            ret = wp11_storage_write_array(storage, der, len);
        }

        wp11_storage_close(storage);
    }
    if (der != NULL) {
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}
#endif /* !NO_DH */

/**
 * Decode the symmetric key - requires decryption.
 *
 * @param [in, out]  object  Symmetric key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Decode_SymmKey(WP11_Object* object)
{
    int ret = 0;

    if (object->keyDataLen - AES_BLOCK_SIZE > WP11_MAX_SYM_KEY_SZ)
        ret = BUFFER_E;
    if (ret == 0) {
        ret = wp11_DecryptData(object->data.symmKey->data, object->keyData,
                                    object->keyDataLen - AES_BLOCK_SIZE,
                                    object->slot->token.key,
                                    sizeof(object->slot->token.key), object->iv,
                                    sizeof(object->iv));
    }
    if (ret == 0)
        object->data.symmKey->len = object->keyDataLen - AES_BLOCK_SIZE;
    object->encoded = (ret != 0);

    return ret;
}

/**
 * Encode the symmetric key - requires encryption.
 *
 * @param [in, out]  object  Symmetric key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Encode_SymmKey(WP11_Object* object)
{
    int ret = 0;

    object->keyDataLen = object->data.symmKey->len + AES_BLOCK_SIZE;
    XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    /* Allocate buffer to hold encoded key. */
    object->keyData = (unsigned char*)XMALLOC(object->keyDataLen, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (object->keyData == NULL)
        ret = MEMORY_E;

    if (ret == 0) {
        ret = wp11_EncryptData(object->keyData, object->data.symmKey->data,
                                    object->data.symmKey->len,
                                    object->slot->token.key,
                                    sizeof(object->slot->token.key), object->iv,
                                    sizeof(object->iv));
        if (ret == 0)
            object->keyDataLen = object->data.symmKey->len + AES_BLOCK_SIZE;
    }

    return ret;
}

/**
 * Load an symmetric key from storage.
 *
 * @param [in, out]  object   Symmetric key object.
 * @param [in]       tokenId  Id of token this key belongs to.
 * @param [in]       objId    Id of object for token.
 * @return  0 on success.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Object_Load_SymmKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    /* Open access to symmetric key. */
    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_SYMMKEY, tokenId, objId,
                                     &storage);
    if (ret == 0) {
        /* Read symmetric key from storage. */
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
    }

    return ret;
}

/**
 * Store a symmetric key to storage.
 *
 * @param [in]  object   Symmetric key object.
 * @param [in]  tokenId  Id of token this key belongs to.
 * @param [in]  objId    Id of object for token.
 * @return  0 on success.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Object_Store_SymmKey(WP11_Object* object, int tokenId,
                                     int objId)
{
    int ret = 0;
    void* storage = NULL;

    if (object->keyData == NULL) {
        ret = wp11_Object_Encode_SymmKey(object);
    }

    /* Open access to symmetric key. */
    if (ret == 0) {
        ret = wp11_storage_open(WOLFPKCS11_STORE_SYMMKEY, tokenId, objId,
                                object->keyDataLen, &storage);
    }
    if (ret == 0) {
        /* Write symmetric key to storage. */
        ret = wp11_storage_write_array(storage, object->keyData,
                                                            object->keyDataLen);

        wp11_storage_close(storage);
    }

    return ret;
}

static int wp11_Object_Load_Object(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;
    word32 dummy = 0;

    /* Open access to key object. */
    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_OBJECT, tokenId, objId,
        &storage);
    if (ret == 0) {
        /* Read the IV. (12) */
        ret = wp11_storage_read_fixed_array(storage, object->iv,
                                                            sizeof(object->iv));
        if (ret == 0) {
            /* Read handle value. (8) */
            ret = wp11_storage_read_ulong(storage, &object->handle);
        }
        if (ret == 0) {
            /* Read object class. (8) */
            ret = wp11_storage_read_ulong(storage, &object->objClass);
        }
        if (ret == 0) {
            /* Read key gen mechanism. (8) */
            ret = wp11_storage_read_ulong(storage, &object->keyGenMech);
        }
        if (ret == 0) {
            /* Read whether the object is on a token. (1) */
            byte onToken = 0;
            ret = wp11_storage_read_boolean(storage, &onToken);
            if (ret == 0) {
                object->onToken = (onToken != 0);
            }
        }
        if (ret == 0) {
            /* Read whether the object is local. (1) */
            byte local = 0;
            ret = wp11_storage_read_boolean(storage, &local);
            if (ret == 0) {
                object->local = (local != 0);
            }
        }
        if (ret == 0) {
            /* Unused word32. (4) */
            ret = wp11_storage_read_word32(storage, &dummy);
        }
        if (ret == 0) {
            /* Read the operational flags of the object. (4) */
            ret = wp11_storage_read_word32(storage, &object->opFlag);
        }
        if (ret == 0) {
            /* Read the start date. (8) */
            ret = wp11_storage_read_fixed_array(storage,
                  (unsigned char*)object->startDate, sizeof(object->startDate));
        }
        if (ret == 0) {
            /* Read the end date. (8) */
            ret = wp11_storage_read_fixed_array(storage,
                      (unsigned char*)object->endDate, sizeof(object->endDate));
        }

        if (ret == 0) {
            /* Read id for the object. (variable keyIdLen) */
            ret = wp11_storage_read_alloc_array(storage, &object->keyId,
                                                &object->keyIdLen);
        }
        if (ret == 0) {
            /* Read label for the object. (variable labelLen) */
            ret = wp11_storage_read_alloc_array(storage, &object->label,
                                                &object->labelLen);
        }
        if (ret == 0) {
            /* Read issuer of the object. (variable issuerLen) */
            ret = wp11_storage_read_alloc_array(storage, &object->issuer,
                                                &object->issuerLen);
            if (ret == 0) {
                /* Read serial number of the object. (variable serialLen) */
                ret = wp11_storage_read_alloc_array(storage,
                    &object->serial, &object->serialLen);

                if (ret == 0) {
                    /* Read subject of the object. (variable subjectLen) */
                    ret = wp11_storage_read_alloc_array(storage,
                       &object->subject, &object->subjectLen);
                }
                if (ret == 0) {
                    /* Read the category of the object. (4) */
                    ret = wp11_storage_read_word32(storage, &object->category);
                }
            }
            else if (ret == BUFFER_E) {
                /* Older version of the storage format, doesn't have these, so
                 * skip reading.
                 */
                ret = 0;
            }
        }

        wp11_storage_close(storage);
    }
    return ret;
}

/**
 * Load a key object from storage.
 *
 * @param [in, out]  object   Key object.
 * @param [in]       tokenId  Id of token this key belongs to.
 * @param [in]       objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Object_Load(WP11_Object* object, int tokenId, int objId)
{
    int ret;

    ret = wp11_Object_Load_Object(object, tokenId, objId);
    if (ret == 0) {
        if (object->objClass == CKO_CERTIFICATE) {
            ret = wp11_Object_Load_Cert(object, tokenId, objId);
        }
#ifdef WOLFPKCS11_NSS
        else if (object->objClass == CKO_NSS_TRUST) {
            ret = wp11_Object_Load_Trust(object, tokenId, objId);
        }
#endif
        else {
            /* Load separate key data. */
            switch (object->type) {
            #ifndef NO_RSA
                case CKK_RSA:
                    ret = wp11_Object_Load_RsaKey(object, tokenId, objId);
                    break;
            #endif
            #ifdef HAVE_ECC
                case CKK_EC:
                    ret = wp11_Object_Load_EccKey(object, tokenId, objId);
                    break;
            #endif
            #ifndef NO_DH
                case CKK_DH:
                    ret = wp11_Object_Load_DhKey(object, tokenId, objId);
                    break;
            #endif
            #ifndef NO_AES
                case CKK_AES:
            #endif
                case CKK_GENERIC_SECRET:
                    ret = wp11_Object_Load_SymmKey(object, tokenId, objId);
                    break;
                default:
                    ret = NOT_AVAILABLE_E;
            }
        }
    }

    return ret;
}

static int wp11_Object_Store_Object(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;
    word32 dummy = 0;
    int variableSz = (object->keyIdLen + object->labelLen +
        object->issuerLen + object->serialLen + object->subjectLen);

    /* Open access to key object. */
    ret = wp11_storage_open(WOLFPKCS11_STORE_OBJECT, tokenId, objId, variableSz,
        &storage);
    if (ret == 0) {
        /* Write the IV (12) */
        ret = wp11_storage_write_fixed_array(storage, object->iv,
                                             sizeof(object->iv));
        if (ret == 0) {
            /* Write handle value. (8) */
            ret = wp11_storage_write_ulong(storage, object->handle);
        }
        if (ret == 0) {
            /* Write object class. (8) */
            ret = wp11_storage_write_ulong(storage, object->objClass);
        }
        if (ret == 0) {
            /* Write key gen mechanism. (8) */
            ret = wp11_storage_write_ulong(storage, object->keyGenMech);
        }
        if (ret == 0) {
            /* Write whether the object is on a token. (1) */
            ret = wp11_storage_write_boolean(storage, object->onToken);
        }
        if (ret == 0) {
            /* Write whether the object is local. (1) */
            ret = wp11_storage_write_boolean(storage, object->local);
        }
        if (ret == 0) {
            /* Unused word32. (4) */
            ret = wp11_storage_write_word32(storage, dummy);
        }
        if (ret == 0) {
            /* Write the operational flags of the object. (4) */
            ret = wp11_storage_write_word32(storage, object->opFlag);
        }
        if (ret == 0) {
            /* Write the start date. (8) */
            ret = wp11_storage_write_fixed_array(storage,
                  (unsigned char*)object->startDate, sizeof(object->startDate));
        }
        if (ret == 0) {
            /* Write the end date. (8) */
            ret = wp11_storage_write_fixed_array(storage,
                      (unsigned char*)object->endDate, sizeof(object->endDate));
        }

        if (ret == 0) {
            /* Write id of the object. (variable keyIdLen) */
            ret = wp11_storage_write_array(storage, object->keyId,
                                                              object->keyIdLen);
        }
        if (ret == 0) {
            /* Write label of the object. (variable labelLen) */
            ret = wp11_storage_write_array(storage, object->label,
                                                              object->labelLen);
        }
        if (ret == 0) {
            /* Write issuer of the object. (variable issuerLen) */
            ret = wp11_storage_write_array(storage, object->issuer,
                                           object->issuerLen);
        }
        if (ret == 0) {
            /* Write serial of the object. (variable serialLen) */
            ret = wp11_storage_write_array(storage, object->serial,
                                           object->serialLen);
        }
        if (ret == 0) {
            /* Write subject of the object. (variable subjectLen) */
            ret = wp11_storage_write_array(storage, object->subject,
                                           object->subjectLen);
        }
        if (ret == 0) {
            /* Write the category of the object. (4) */
            ret = wp11_storage_write_word32(storage, object->category);
        }

        wp11_storage_close(storage);
    }
    return ret;
}

/**
 * Store a key object to storage.
 *
 * @param [in]  object   Key object.
 * @param [in]  tokenId  Id of token this key belongs to.
 * @param [in]  objId    Id of object for token.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Object_Store(WP11_Object* object, int tokenId, int objId)
{
    int ret;

    /* Open access to key object. */
    ret = wp11_Object_Store_Object(object, tokenId, objId);

    if (ret == 0 && object->keyData == NULL &&
            (object->objClass == CKO_PRIVATE_KEY ||
               object->type == CKK_AES ||
               object->type == CKK_GENERIC_SECRET)) {
        /* Generate new IV if needed */
        ret = wc_RNG_GenerateBlock(&object->slot->token.rng, object->iv,
                                                            sizeof(object->iv));
    }
    if (ret == 0) {
        if (object->objClass == CKO_CERTIFICATE) {
            ret = wp11_Object_Store_Cert(object, tokenId, objId);
        }
#ifdef WOLFPKCS11_NSS
        else if (object->objClass == CKO_NSS_TRUST) {
            ret = wp11_Object_Store_Trust(object, tokenId, objId);
        }
#endif
        else {
            /* Store key data separately. */
            switch (object->type) {
            #ifndef NO_RSA
                case CKK_RSA:
                    ret = wp11_Object_Store_RsaKey(object, tokenId, objId);
                    break;
            #endif
            #ifdef HAVE_ECC
                case CKK_EC:
                    ret = wp11_Object_Store_EccKey(object, tokenId, objId);
                    break;
            #endif
            #ifndef NO_DH
                case CKK_DH:
                    ret = wp11_Object_Store_DhKey(object, tokenId, objId);
                    break;
            #endif
            #ifndef NO_AES
                case CKK_AES:
            #endif
                case CKK_GENERIC_SECRET:
                    ret = wp11_Object_Store_SymmKey(object, tokenId, objId);
                    break;
                default:
                    ret = NOT_AVAILABLE_E;
            }
        }
    }

    return ret;
}

/**
 * Decode the key object. Private keys require decryption.
 *
 * When decryption authentication fails then the wrong user is trying to access
 * the private key.
 *
 * @param [in, out]  object  Key object.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Decode(WP11_Object* object)
{
    int ret;

    if (object->objClass == CKO_CERTIFICATE) {
        wp11_Object_Decode_Cert(object);
        ret = 0;
    }
#ifdef WOLFPKCS11_NSS
    else if (object->objClass == CKO_NSS_TRUST) {
        wp11_Object_Decode_Trust(object);
        ret = 0;
    }
#endif
    else {
        switch (object->type) {
        #ifndef NO_RSA
            case CKK_RSA:
                ret = wp11_Object_Decode_RsaKey(object);
                break;
        #endif
        #ifdef HAVE_ECC
            case CKK_EC:
                ret = wp11_Object_Decode_EccKey(object);
                break;
        #endif
        #ifndef NO_DH
            case CKK_DH:
                ret = wp11_Object_Decode_DhKey(object);
                break;
        #endif
        #ifndef NO_AES
            case CKK_AES:
        #endif
            case CKK_GENERIC_SECRET:
                ret = wp11_Object_Decode_SymmKey(object);
                break;
            default:
                ret = NOT_AVAILABLE_E;
        }
    }

    /* Authentication failure means this object isn't for this user. */
    if (ret == AES_GCM_AUTH_E)
        ret = 0;

    return ret;
}

/**
 * Encode the key object. Private keys require encryption.
 *
 * @param [in, out]  object   Key object.
 * @param [in]       protect  Unencrypted private key data is cleared.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp11_Object_Encode(WP11_Object* object, int protect)
{
    int ret;

#ifdef WOLFPKCS11_NSS
    if ((object->objClass == CKO_CERTIFICATE) ||
        (object->objClass == CKO_NSS_TRUST))
#else
    if (object->objClass == CKO_CERTIFICATE)
#endif
        ret = 0;
    else {
        switch (object->type) {
        #ifndef NO_RSA
            case CKK_RSA:
                ret = wp11_Object_Encode_RsaKey(object);
                if (protect && ret == 0 && object->objClass == CKO_PRIVATE_KEY) {
                    wc_FreeRsaKey(object->data.rsaKey);
                    object->encoded = 1;
                }
                break;
        #endif
        #ifdef HAVE_ECC
            case CKK_EC:
                ret = wp11_Object_Encode_EccKey(object);
                if (protect && ret == 0 && object->objClass == CKO_PRIVATE_KEY) {
                    wc_ecc_free(object->data.ecKey);
                    object->encoded = 1;
                }
                break;
        #endif
        #ifndef NO_DH
            case CKK_DH:
                ret = wp11_Object_Encode_DhKey(object);
                if (protect && ret == 0 && object->objClass == CKO_PRIVATE_KEY) {
                    XMEMSET(object->data.dhKey->key, 0, object->data.dhKey->len);
                    object->encoded = 1;
                }
                break;
        #endif
        #ifndef NO_AES
            case CKK_AES:
        #endif
            case CKK_GENERIC_SECRET:
                ret = wp11_Object_Encode_SymmKey(object);
                if (protect && ret == 0) {
                    XMEMSET(object->data.symmKey->data, 0, object->data.symmKey->len);
                    object->encoded = 1;
                }
                break;
            default:
                ret = NOT_AVAILABLE_E;
        }
    }

    return ret;
}

/**
 * Unstore a key object to storage.
 *
 * Empties the contents of the object.
 *
 * @param [in]  object   Key object.
 * @param [in]  tokenId  Id of token this key belongs to.
 * @param [in]  objId    Id of object for token.
 */
static void wp11_Object_Unstore(WP11_Object* object, int tokenId, int objId)
{
    int storeObjType = -1;

    /* Remove store and key object */
    wp11_storage_remove(WOLFPKCS11_STORE_OBJECT, tokenId, objId);

    /* CKK_* and CKC_* values overlap, check for cert separately */
    if (object->objClass == CKO_CERTIFICATE) {
        storeObjType = WOLFPKCS11_STORE_CERT;
    }
#ifdef WOLFPKCS11_NSS
    else if (object->objClass == CKO_NSS_TRUST) {
        storeObjType = WOLFPKCS11_STORE_TRUST;
    }
#endif
    else {
    /* Open access to symmetric key. */
    switch (object->type) {
    #ifndef NO_RSA
        case CKK_RSA:
            if (object->objClass == CKO_PRIVATE_KEY)
                storeObjType = WOLFPKCS11_STORE_RSAKEY_PRIV;
            else
                storeObjType = WOLFPKCS11_STORE_RSAKEY_PUB;
            break;
    #endif
    #ifdef HAVE_ECC
        case CKK_EC:
            if (object->objClass == CKO_PRIVATE_KEY)
                storeObjType = WOLFPKCS11_STORE_ECCKEY_PRIV;
            else
                storeObjType = WOLFPKCS11_STORE_ECCKEY_PUB;
            break;
    #endif
    #ifndef NO_DH
        case CKK_DH:
            if (object->objClass == CKO_PRIVATE_KEY)
                storeObjType = WOLFPKCS11_STORE_DHKEY_PRIV;
            else
                storeObjType = WOLFPKCS11_STORE_DHKEY_PUB;
            break;
    #endif
    #ifndef NO_AES
        case CKK_AES:
    #endif
        case CKK_GENERIC_SECRET:
            storeObjType = WOLFPKCS11_STORE_SYMMKEY;
            break;
        }
    }
    wp11_storage_remove(storeObjType, tokenId, objId);
}
#endif /* !WOLFPKCS11_NO_STORE */

/**
 * Initialize the token.
 *
 * @param  token  [in]  Token object.
 */
static int wp11_Token_Init(WP11_Token* token, const char* label)
{
    int ret;

    ret = WP11_Lock_Init(&token->lock);
    if (ret == 0)
        ret = WP11_Lock_Init(&token->rngLock);
    if (ret == 0)
        ret = Rng_New(&globalRandom, &globalLock, &token->rng);
    if (ret == 0) {
        token->state = WP11_TOKEN_STATE_INITIALIZED;
        token->loginState = WP11_APP_STATE_RW_PUBLIC;
        token->nextObjId = 1;
        XMEMCPY(token->label, label, sizeof(token->label));
    }

    return ret;
}

/**
 * Free the dynamic memory associated with the token.
 *
 * @param  token  [in]  Token object.
 */
static void wp11_Token_Final(WP11_Token* token)
{
    WP11_Object* obj = token->object;
    WP11_Object* next;

    while (obj != NULL) {
        next = obj->next;
        WP11_Object_Free(obj);
        obj = next;
    }
    Rng_Free(&token->rng);
    WP11_Lock_Free(&token->rngLock);
    WP11_Lock_Free(&token->lock);
    XMEMSET(token, 0, sizeof(*token));
}

#ifndef WOLFPKCS11_NO_STORE
/**
 * Load a token from storage.
 *
 * @param [in, out]  object   Token object.
 * @param [in]       tokenId  Id of token this key belongs to.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Token_Load(WP11_Slot* slot, int tokenId, WP11_Token* token)
{
    int ret;
    int i;
    void* storage = NULL;
    WP11_Object* object = NULL;
    WP11_Object** current;
    int objCnt = 0;
    word32 len;

    /* Open access to token object. */
    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_TOKEN, tokenId, 0,
        &storage);
    if (ret == 0) {
        /* Read label for token. (32) */
        ret = wp11_storage_read_string(storage, token->label,
                                       sizeof(token->label));
        if (ret == 0) {
            /* Read Security Officer's PIN. (32) */
            ret = wp11_storage_read_array(storage, token->soPin, &len,
                                          sizeof(token->soPin));
        }
        if (ret == 0) {
            /* Read Security Officer's PIN seed. (16) */
            token->soPinLen = len;
            ret = wp11_storage_read_fixed_array(storage, token->soPinSeed,
                                                sizeof(token->soPinSeed));
        }
        if (ret == 0) {
            /* Read Security Officer's failed login count. (4) */
            ret = wp11_storage_read_int(storage, &token->soFailedLogin);
        }
        if (ret == 0) {
            /* Read time of last failed login as Security Officer. (8) */
            ret = wp11_storage_read_time(storage, &token->soLastFailedLogin);
        }
        if (ret == 0) {
            /* Read failed login timeout for Security Officer. (8) */
            ret = wp11_storage_read_time(storage, &token->soFailLoginTimeout);
        }
        if (ret == 0) {
            /* Read User's PIN. (32) */
            ret = wp11_storage_read_array(storage, token->userPin, &len,
                                          sizeof(token->userPin));
        }
        if (ret == 0) {
            /* Read User's PIN seed. (16) */
            token->userPinLen = len;
            ret = wp11_storage_read_fixed_array(storage, token->userPinSeed,
                                                sizeof(token->userPinSeed));
        }
        if (ret == 0) {
            /* Read User's failed login count. (4)) */
            ret = wp11_storage_read_int(storage, &token->userFailedLogin);
        }
        if (ret == 0) {
            /* Read time of last failed login as User. (8) */
            ret = wp11_storage_read_time(storage, &token->userLastFailedLogin);
        }
        if (ret == 0) {
            /* Read failed login timeout for User. (8) */
            ret = wp11_storage_read_time(storage, &token->userFailLoginTimeout);
        }
        if (ret == 0) {
            /* Read seed used to calculate key. (16) */
            ret = wp11_storage_read_fixed_array(storage, token->seed,
                                                sizeof(token->seed));
        }
        if (ret == 0) {
            /* Read count of object on token. (4) */
            ret = wp11_storage_read_int(storage, &objCnt);
        }
        /* Create an objects. */
        current = &token->object;
        for (i = 0; (ret == 0) && (i < objCnt); i++) {
            CK_KEY_TYPE type;

            /* Read type of key object for creation of key object.
             * (variable objCnt * 8) */
            ret = wp11_storage_read_ulong(storage, &type);
            if (ret == 0) {
                object = NULL;
                ret = wp11_Object_New(slot, type, &object);
            }
            if (ret == 0) {
                object->lock = &token->lock;
                /* Add to end of list. */
                *current = object;
                current = &object->next;
                token->objCnt++;
            }
        }
        if (ret == 0) {
            /* Read token flags. This is a new variable, so might not exist on
             * an upgrade. If not set, it was from a version that doesn't
             * support empty pins. So, we can calculate it from the pin lengths.
             */
            ret = wp11_storage_read_int(storage, &token->tokenFlags);
            if (ret == BUFFER_E) {
                if (token->userPinLen > 0) {
                    token->tokenFlags |= WP11_TOKEN_FLAG_USER_PIN_SET;
                }
                if (token->soPinLen > 0) {
                    token->tokenFlags |= WP11_TOKEN_FLAG_SO_PIN_SET;
                }
                token->nextObjId = 1;
                ret = 0;
            }
            else {
                ret = wp11_storage_read_int(storage, &token->nextObjId);
                if (ret == BUFFER_E || token->nextObjId == 0) {
                    token->nextObjId = 1;
                    ret = 0;
                }
            }
        }

        wp11_storage_close(storage);

        object = token->object;
        for (i = token->objCnt - 1; (ret == 0) && (i >= 0); i--) {
            /* Load the objects. */
            ret = wp11_Object_Load(object, tokenId, i);
            object = object->next;
        }

        if (ret == 0) {
            /* Set to state of initialized. */
            token->state = WP11_TOKEN_STATE_INITIALIZED;
        }

        /* If there is no pin, there is no login, so decode now */
        if (WP11_Slot_Has_Empty_Pin(slot) && (ret == 0)) {
#ifndef WOLFPKCS11_NO_STORE
            object = token->object;
            while (ret == 0 && object != NULL) {
                ret = wp11_Object_Decode(object);
                object = object->next;
            }
#endif
        }

        if (ret != 0) {
            ret = CKR_DEVICE_ERROR;
        }
    }
    else if (ret == NOT_AVAILABLE_E) {
        /* No data to read. */
        ret = 0;
    }

    return ret;
}

/**
 * Store a token to storage.
 *
 * @param [in]  object   Token object.
 * @param [in]  tokenId  Id of token this key belongs to.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Token_Store(WP11_Token* token, int tokenId)
{
    int ret;
    int i;
    void* storage = NULL;
    WP11_Object* object;
    int variableSz;

#ifdef WOLFPKCS11_DEBUG_STORE
    printf("wp11_Token_Store: tokenId %d, objCnt %d\n", tokenId, token->objCnt);
#endif

    /* Reserve space for token object */
    variableSz = token->userPinLen + token->soPinLen +
        (token->objCnt * FIELD_SIZE(WP11_Object, type));
    ret = wp11_storage_open(WOLFPKCS11_STORE_TOKEN, tokenId, 0, variableSz,
        &storage);
    if (ret == 0) {
        wp11_storage_close(storage);
        storage = NULL;
    }

    /* Store the objects */
    object = token->object;
    for (i = token->objCnt - 1; i >= 0; i--) {
        /* Write the objects. */
        ret = wp11_Object_Store(object, tokenId, i);
        if (ret != 0) {
        #ifdef DEBUG_WOLFPKCS11
            printf("Failed to store object %d, token %d, ret: %d\n",
                i, tokenId, ret);
        #endif
            token->objCnt = i; /* mark number of objects actually stored */
        #ifdef WOLFPKCS11_TPM_STORE
            if ((ret & RC_MAX_FM0) == TPM_RC_NV_SPACE) {
                ret = 0; /* allow this error and continue */
            }
        #endif
            break;
        }
        object = object->next;
    }

    if (ret == 0) {
        variableSz = token->userPinLen + token->soPinLen +
            (token->objCnt * FIELD_SIZE(WP11_Object, type));
        ret = wp11_storage_open(WOLFPKCS11_STORE_TOKEN, tokenId, 0, variableSz,
            &storage);
    }
    if (ret == 0) {
        /* Write label of token. (32) */
        ret = wp11_storage_write_string(storage, token->label,
                                        sizeof(token->label));
        if (ret == 0) {
            /* Write Security Officer's PIN. (variable up to 32) */
            ret = wp11_storage_write_array(storage, token->soPin,
                                                               token->soPinLen);
        }
        if (ret == 0) {
            /* Write Security Officer's PIN seed. (16) */
            ret = wp11_storage_write_fixed_array(storage, token->soPinSeed,
                                                 sizeof(token->soPinSeed));
        }
        if (ret == 0) {
            /* Write Security Officer's failed login count. (4) */
            ret = wp11_storage_write_int(storage, token->soFailedLogin);
        }
        if (ret == 0) {
            /* Write time of last failed login as Security Officer. (8) */
            ret = wp11_storage_write_time(storage, token->soLastFailedLogin);
        }
        if (ret == 0) {
            /* Write failed login timeout for Security Officer. (8) */
            ret = wp11_storage_write_time(storage, token->soFailLoginTimeout);
        }
        if (ret == 0) {
            /* Write User's PIN. (variable up to 32) */
            ret = wp11_storage_write_array(storage, token->userPin,
                                                             token->userPinLen);
        }
        if (ret == 0) {
            /* Write User's PIN seed. (32) */
            ret = wp11_storage_write_fixed_array(storage, token->userPinSeed,
                                                 sizeof(token->userPinSeed));
        }
        if (ret == 0) {
            /* Write User's failed login count. (4) */
            ret = wp11_storage_write_int(storage, token->userFailedLogin);
        }
        if (ret == 0) {
            /* Write time of last failed login as User. (8) */
            ret = wp11_storage_write_time(storage, token->userLastFailedLogin);
        }
        if (ret == 0) {
            /* Write failed login timeout for User. (8) */
            ret = wp11_storage_write_time(storage, token->userFailLoginTimeout);
        }
        if (ret == 0) {
            /* Write seed used to calculate key. (16) */
            ret = wp11_storage_write_fixed_array(storage, token->seed,
                                                 sizeof(token->seed));
        }

        if (ret == 0) {
            /* Write count of object on token. (4) */
            ret = wp11_storage_write_int(storage, token->objCnt);
        }
        object = token->object;
        for (i = token->objCnt - 1; (ret == 0) && (i >= 0); i--) {
            /* Write type of key object for creation of key object.
             * (variable objCnt * 8) */
            ret = wp11_storage_write_ulong(storage, object->type);
            object = object->next;
        }

        if (ret == 0) {
            /* Write token flags. (4) */
            ret = wp11_storage_write_int(storage, token->tokenFlags);
        }

        if (ret == 0) {
            /* Write next object id. (4) */
            ret = wp11_storage_write_int(storage, token->nextObjId);
        }

        wp11_storage_close(storage);
    }
    else if (ret == NOT_AVAILABLE_E) {
        /* Not writing. */
        ret = 0;
    }

    return ret;
}
#endif /* !WOLFPKCS11_NO_STORE */

/**
 * Free first session in slot and any others not in use down to a minimum.
 *
 * @param  slot  [in]  Slot object.
 */
static void wp11_Slot_FreeSession(WP11_Slot* slot, WP11_Session* session)
{
    WP11_Session* curr;

    if (session == slot->session) {
        /* Free the first session as it is no longer required. */
        curr = slot->session;
        slot->session = curr->next;
        wp11_Session_Final(curr);
        XFREE(curr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* Free the leading unused sessions down to the minimum. */
    while (slot->session != NULL && !slot->session->inUse &&
            SESS_HANDLE_SESS_ID(slot->session->handle) > WP11_SESSION_CNT_MIN) {
        curr = slot->session;
        slot->session = slot->session->next;
        wp11_Session_Final(curr);
        XFREE(curr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
}


#ifdef WOLFPKCS11_TPM
static int wp11_TpmInit(WP11_Slot* slot)
{
    int ret;
    WOLFTPM2_CAPS caps;
    TPM_ALG_ID alg;

    ret = wolfTPM2_Init(&slot->tpmDev, TPM2_IoCb, TPM2_IOCB_CTX);
    if (ret == 0) {
        /* Get device capabilities + options */
        ret = wolfTPM2_GetCapabilities(&slot->tpmDev, &caps);
    }
    if (ret == 0) {
        printf("Mfg %s (%d), Vendor %s, Fw %u.%u (0x%x), "
            "FIPS 140-2 %d, CC-EAL4 %d\n",
            caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
            caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);
    }
    if (ret == 0) {
        ret = wolfTPM2_SetCryptoDevCb(&slot->tpmDev, wolfTPM2_CryptoDevCb,
            &slot->tpmCtx, &slot->devId);
    }
    if (ret == 0) {
        /* Create a primary storage key - no auth needed for param enc to work */
        /* Prefer ECC as its faster */
    #ifdef HAVE_ECC
        alg = TPM_ALG_ECC;
    #elif !defined(NO_RSA)
        alg = TPM_ALG_RSA;
    #else
        alg = TPM_ALG_NULL;
    #endif
        ret = wolfTPM2_CreateSRK(&slot->tpmDev, &slot->tpmSrk, alg, NULL, 0);
        if (ret == 0) {
            /* set values needed for crypto callback */
            slot->tpmCtx.dev = &slot->tpmDev;
            slot->tpmCtx.storageKey = &slot->tpmSrk;

            /* Setup a TPM session that can be used for parameter encryption */
            ret = wolfTPM2_StartSession(&slot->tpmDev, &slot->tpmSession,
                &slot->tpmSrk, NULL, TPM_SE_HMAC, TPM_ALG_CFB);
        }
        if (ret != 0) {
            printf("TPM Create SRK or Session error %d (%s)!\n",
                ret, wolfTPM2_GetRCString(ret));
        }
    }

    if (ret != 0) {
        printf("TPM Init failed! %d (%s)\n", ret, wolfTPM2_GetRCString(ret));
    }
    return ret;
}

static void wp11_TpmFinal(WP11_Slot* slot)
{
#ifdef WOLFPKCS11_TPM
    wolfTPM2_UnloadHandle(&slot->tpmDev, &slot->tpmSession.handle);
    wolfTPM2_UnloadHandle(&slot->tpmDev, &slot->tpmSrk.handle);
#endif

    wolfTPM2_Cleanup(&slot->tpmDev);
}
#endif /* WOLFPKCS11_TPM */


/**
 * Free dynamic memory associated with the slot.
 *
 * @param  slot  [in]  Slot object.
 */
static void wp11_Slot_Final(WP11_Slot* slot)
{
    if (slot == NULL) {
        return;
    }
    while (slot->session != NULL) {
        wp11_Slot_FreeSession(slot, slot->session);
    }
    wp11_Token_Final(&slot->token);
#ifdef WOLFPKCS11_TPM
    wp11_TpmFinal(slot);
#endif
    WP11_Lock_Free(&slot->lock);
}

/**
 * Initialize a slot.
 *
 * @param  slot  [in]  Slot object.
 * @param  id    [in]  Slot id for slot.
 * @return  MEMORY_E when failing to allocation session.
 *          BAD_MUTEX_E when the lock initialization failed.
 *          0 on success.
 */
static int wp11_Slot_Init(WP11_Slot* slot, int id)
{
    int ret = 0;
    int i;
    WP11_Session* curr;
    char label[LABEL_SZ] = { 0, };

    XMEMSET(slot, 0, sizeof(*slot));
    slot->id = id;
    slot->token.state = WP11_TOKEN_STATE_UNKNOWN;
    slot->token.tokenFlags = 0;

    ret = WP11_Lock_Init(&slot->lock);
    if (ret == 0) {
    #if defined(WOLFPKCS11_TPM)
        ret = wp11_TpmInit(slot);
    #elif defined (WOLFSSL_MAXQ10XX_CRYPTO)
        slot->devId = MAXQ_DEVICE_ID;
    #endif
        /* Create the minimum number of unused sessions. */
        for (i = 0; ret == 0 && i < WP11_SESSION_CNT_MIN; i++) {
            ret = wp11_Slot_AddSession(slot, &curr);
        }
        if (ret == 0) {
            ret = wp11_Token_Init(&slot->token, label);
        }

        if (ret != 0) {
            wp11_Slot_Final(slot);
        }
    }

    return ret;
}

#ifndef WOLFPKCS11_NO_STORE
/**
 * Load tokens in slot from storage.
 *
 * @param [in, out]  object  Slot object.
 * @param [in]       slotId  Id of slot this key belongs to.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when loading fails.
 * @return  NOT_AVAILABLE_E when unable to locate data.
 */
static int wp11_Slot_Load(WP11_Slot* slot, int id)
{
    return wp11_Token_Load(slot, id, &slot->token);
}

/**
 * Store tokens in slot to storage.
 *
 * @param [in]  object  Slot object.
 * @param [in]  slotId  Id of slot this key belongs to.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  BUFFER_E when storing fails.
 * @return  NOT_AVAILABLE_E when unable to write data.
 */
static int wp11_Slot_Store(WP11_Slot* slot, int id)
{
    return wp11_Token_Store(&slot->token, id);
}
#endif

/**
 * Initialize the globals for the library.
 * Multiple initializations allowed.
 *
 * @return  MEMORY_E when out of memory.
 *          BAD_MUTEX_E when initializing lock fails.
 *          0 on success.
 */
int WP11_Library_Init(void)
{
    int ret = 0;
    int i;

    if (libraryInitCount == 0) {
        ret = WP11_Lock_Init(&globalLock);
        if (ret == 0) {

            ret = wolfCrypt_Init();
#ifdef WC_RNG_SEED_CB
            if (ret == 0) {
                ret = wc_SetSeed_Cb(wc_GenerateSeed);
            }
#endif
            if (ret == 0) {
#ifdef WOLFSSL_MAXQ10XX_CRYPTO
                ret = wc_InitRng_ex(&globalRandom, NULL, MAXQ_DEVICE_ID);
#else
                ret = wc_InitRng(&globalRandom);
#endif
            }

        }
        for (i = 0; (ret == 0) && (i < slotCnt); i++) {
            ret = wp11_Slot_Init(&slotList[i], i + 1);
        }
#ifndef WOLFPKCS11_NO_STORE
        for (i = 0; (ret == 0) && (i < slotCnt); i++) {
            ret = wp11_Slot_Load(&slotList[i], i + 1);
        }
#endif
    }
    if (ret == 0) {
        WP11_Lock_LockRW(&globalLock);
        libraryInitCount++;
        WP11_Lock_UnlockRW(&globalLock);
    }

    return ret;
}

/**
 * Finalize the globals for the library.
 * Multiple finalizations allowed.
 */
void WP11_Library_Final(void)
{
    int i;
    int cnt;

    WP11_Lock_LockRW(&globalLock);
    cnt = --libraryInitCount;
    WP11_Lock_UnlockRW(&globalLock);
    if (cnt == 0) {
#ifndef WOLFPKCS11_NO_STORE
        /* Store the slots. */
        for (i = 0; i < slotCnt; i++) {
            int ret = wp11_Slot_Store(&slotList[i], i + 1);
        #ifdef DEBUG_WOLFPKCS11
            if (ret != 0) {
                printf("Failed to store slot %d, ret: %d\n", i + 1, ret);
            }
        #endif
            (void)ret; /* store failure cannot be returned, so log and ignore */
        }
#endif
        /* Cleanup the slots. */
        for (i = 0; i < slotCnt; i++)
            wp11_Slot_Final(&slotList[i]);

        wc_FreeRng(&globalRandom);
        WP11_Lock_Free(&globalLock);
        wolfCrypt_Cleanup();
    }
}

/**
 * Checks if the library is initialized.
 *
 * @return  0 when library is not initialized.
 *          1 when library is initialized.
 */
int WP11_Library_IsInitialized(void)
{
    int ret, locked = 0;
    if (libraryInitCount > 0) {
        /* cannot used globalLock before init */
        WP11_Lock_LockRO(&globalLock);
        locked = 1;
    }
    ret = libraryInitCount > 0;
    if (locked) {
        WP11_Lock_UnlockRO(&globalLock);
    }
    return ret;
}

/**
 * Check if slot id is valid.
 *
 * @param  slotid  [in]  Slot handle value.
 * @return  0 when not valid.
 *          1 when is valid.
 */
int WP11_SlotIdValid(CK_SLOT_ID slotId)
{
    return slotId > 0 && slotId <= (CK_SLOT_ID)slotCnt;
}

/**
 * Get the list of slots identifiers.
 * When slotIdList is NULL the count is returned.
 * Otherwise, the count must be equal to or larger than the number of slot
 * identifiers to be returned.
 *
 * @param  tokenIn     [in]       Whether the token must be in.
 * @param  slotIdList  [in]       Where the list of slot identifier is stored.
 * @param  count       [in, out]  On in, the number of entries in slotIdList.
 *                                On out, the number of entries put in
 *                                slotIdList.
 * @return  BUFFER_E when the count is too small.
 *          0 on success.
 */
int WP11_GetSlotList(int tokenIn, CK_SLOT_ID* slotIdList, CK_ULONG* count)
{
    int ret = 0;
    int i;

    /* All slots are assumed to have a token inserted. */
    (void)tokenIn;

    if (slotIdList == NULL)
        *count = slotCnt;
    else if ((int)*count < slotCnt)
        ret = BUFFER_E;
    else {
        for (i = 0; i < slotCnt && i < (int)*count; i++)
            slotIdList[i] = i + 1;
        *count = i;
    }

    return ret;
}

/**
 * Get the Slot object with the id.
 *
 * @param  slotid  [in]   Slot id.
 * @param  slot    [out]  Slot object.
 * @return  BAD_FUNC_ARG when the slot handle is not valid.
 *          0 on success.
 */
int WP11_Slot_Get(CK_SLOT_ID slotId, WP11_Slot** slot)
{
    int ret = 0;

    if (WP11_SlotIdValid(slotId))
        *slot = &slotList[slotId - 1];
    else
        ret = BAD_FUNC_ARG;

    return ret;
}

/**
 * Open a new session on the token in the slot.
 * Notification callback and application data ignored.
 *
 * @param  slot    [in]  Slot object.
 * @param  flags   [in]  Read/write or read-only session flag and others.
 * @param  app     [in]  Application data passed in notification callback.
 * @param  notify  [in]  Notification callback.
 * @return  BAD_FUNC_ARG when the slot handle is not valid.
 *          0 on success.
 */
int WP11_Slot_OpenSession(WP11_Slot* slot, unsigned long flags, void* app,
                          CK_NOTIFY notify, CK_SESSION_HANDLE* session)
{
    int ret = 0;
    WP11_Session* curr = NULL;

    WP11_Lock_LockRW(&slot->lock);
    /* Cannot open a read-only session if SO is logged in. */
    if ((flags & CKF_RW_SESSION) == 0) {
        if (slot->token.loginState == WP11_APP_STATE_RW_SO)
            ret = SESSION_EXISTS_E;
    }

    if (ret == 0) {
        /* Find and unused session. */
        curr = slot->session;
        for (curr = slot->session; curr != NULL; curr = curr->next) {
            if (!curr->inUse)
                break;
        }
        /* None found and already at max means cannot create a new session. */
        if (curr == NULL && slot->session != NULL &&
                                   SESS_HANDLE_SESS_ID(slot->session->handle) ==
                                                         WP11_SESSION_CNT_MAX) {
            ret = SESSION_COUNT_E;
        }
    }

    /* Add a new session. */
    if (ret == 0 && curr == NULL)
        ret = wp11_Slot_AddSession(slot, &curr);

    /* Return the handle of the session. */
    if (ret == 0) {
        /* Set slot read/write state. */
        if ((flags & CKF_RW_SESSION) == CKF_RW_SESSION)
            curr->inUse = WP11_SESSION_RW;
        else
            curr->inUse = WP11_SESSION_RO;
        *session = curr->handle;
    }
    WP11_Lock_UnlockRW(&slot->lock);

    /* Ignored at this time. */
    (void)app;
    (void)notify;

    return ret;
}

/**
 * Close a session associated with a slot.
 *
 * @param  slot     [in]  Slot of session.
 * @param  session  [in]  Session to close.
 */
void WP11_Slot_CloseSession(WP11_Slot* slot, WP11_Session* session)
{
    int dynamic;
    int noMore = 1;
    WP11_Session* curr;

    WP11_Lock_LockRW(&slot->lock);
    /* Only free the session object if it is on top and there is more than the
     * minimum number of sessions associated with the slot.
     */
    dynamic = slot->session == session &&
                    SESS_HANDLE_SESS_ID(session->handle) > WP11_SESSION_CNT_MIN;

    if (dynamic)
        wp11_Slot_FreeSession(slot, session);
    else
        wp11_Session_Final(session);
    WP11_Lock_UnlockRW(&slot->lock);

    WP11_Lock_LockRO(&slot->lock);
    for (curr = slot->session; curr != NULL; curr = curr->next) {
        if (curr->inUse) {
            noMore = 0;
            break;
        }
    }
    WP11_Lock_UnlockRO(&slot->lock);
    if (noMore)
        WP11_Slot_Logout(slot);
}

/**
 * Close all sessions associated with a slot.
 *
 * @param  slot  [in]  Slot object.
 */
void WP11_Slot_CloseSessions(WP11_Slot* slot)
{
    WP11_Session* curr;

    /* Free all sessions down to minimum. */
    while (slot->session != NULL &&
            SESS_HANDLE_SESS_ID(slot->session->handle) > WP11_SESSION_CNT_MIN) {
        wp11_Slot_FreeSession(slot, slot->session);
    }
    WP11_Lock_LockRW(&slot->lock);
    /* Finalize the rest. */
    for (curr = slot->session; curr != NULL; curr = curr->next)
        wp11_Session_Final(slot->session);
    WP11_Lock_UnlockRW(&slot->lock);
}

/**
 * Check for a session in use that is associated with the slot.
 *
 * @param  slot  [in]  Slot object.
 * @return  1 when a session is in use.
 *          0 when no sessions are in use.
 */
int WP11_Slot_HasSession(WP11_Slot* slot)
{
    int ret;
    WP11_Session* curr;

    WP11_Lock_LockRO(&slot->lock);
    /* Find a session in use. */
    curr = slot->session;
    while (curr != NULL) {
        if (curr->inUse)
            break;
        curr = curr->next;
    }
    ret = curr != NULL;
    WP11_Lock_UnlockRO(&slot->lock);

    return ret;
}

/**
 * Hash the PIN into a secret.
 * WP11_HASH_PIN_COST, WP11_HASH_PIN_BLOCKSIZE and WP11_HASH_PIN_PARALLEL have
 * default values but can be specified at compile time.
 *
 * @param  pin      [in]  PIN to hash.
 * @param  pinLen   [in]  PIN length in bytes.
 * @param  seed     [in]  Seed for hashing.
 * @param  seedLen  [in]  Seed length in bytes.
 * @param  hash     [in]  Buffer to hold hash result.
 * @param  hashlen  [in]  Size of buffer.
 * @return  0 on success.
 *          -ve on failure.
 */
static int HashPIN(char* pin, int pinLen, byte* seed, int seedLen, byte* hash,
                   int hashLen)
{
#ifdef HAVE_SCRYPT
    /* Convert PIN into secret using scrypt algorithm. */
    return wc_scrypt(hash, (byte*)pin, pinLen, seed, seedLen,
                                    WP11_HASH_PIN_COST, WP11_HASH_PIN_BLOCKSIZE,
                                    WP11_HASH_PIN_PARALLEL, hashLen);
#elif !defined(NO_SHA256)
    /* fallback to simple SHA2-256 hash of pin */
    (void)seed;
    (void)seedLen;
    XMEMSET(hash, 0, hashLen);
    return wc_Sha256Hash((const byte*)pin, pinLen, hash);
#else
    (void)pin;
    (void)pinLen;
    (void)seed;
    (void)seedLen;
    (void)hash;
    (void)hashLen;
    return NOT_COMPILED_IN;
#endif
}

/**
 * Reset the token.
 *
 * @param  slot    [in]  Slot object.
 * @param  pin     [in]  SO PIN to set.
 * @param  pinLen  [in]  Length of PIN in bytes.
 * @param  label   [in]  Name of token.
 * @return  0 on success.
 *          -ve on failure.
 */
int WP11_Slot_TokenReset(WP11_Slot* slot, char* pin, int pinLen, char* label)
{
    int ret;
    WP11_Token* token;

    WP11_Lock_LockRW(&slot->lock);
    /* Zeroizes token. */
    token = &slot->token;
    wp11_Token_Final(token);
    wp11_Token_Init(token, label);
    WP11_Lock_UnlockRW(&slot->lock);

    /* Locking used in setting SO PIN. */
    ret = WP11_Slot_SetSOPin(slot, pin, pinLen);

    return ret;
}

/**
 * Check the PIN is correct for SO (Security officer).
 *
 * @param  slot    [in]  Slot object.
 * @param  pin     [in]  PIN to check.
 * @param  pinLen  [in]  Length of PIN.
 * @return  PIN_NOT_SET_E when the token is not initialized.
 *          PIN_INVALID_E when the PIN is not correct.
 *          Other -ve value when hashing PIN fails.
 *          0 when PIN is correct.
 */
int WP11_Slot_CheckSOPin(WP11_Slot* slot, char* pin, int pinLen)
{
    int ret = 0;
    WP11_Token* token;
    byte hash[PIN_HASH_SZ];

    WP11_Lock_LockRO(&slot->lock);
    token = &slot->token;

    if (token->state != WP11_TOKEN_STATE_INITIALIZED)
        ret = PIN_NOT_SET_E;
    /* NSS PK11_InitPin tries to login with an empty pin before setting the pin.
     * This is effectively a public access, so should be OK.
     */
    if (!(token->tokenFlags & WP11_TOKEN_FLAG_SO_PIN_SET) && pinLen > 0)
        ret = PIN_NOT_SET_E;

    if (ret == 0) {
        WP11_Lock_UnlockRO(&slot->lock);

        /* Costly Operation done out of lock. */
        ret = HashPIN(pin, pinLen, token->soPinSeed, sizeof(token->soPinSeed),
                                                            hash, sizeof(hash));

        WP11_Lock_LockRO(&slot->lock);
    }
    if (ret == 0 && !WP11_ConstantCompare(hash, token->soPin, token->soPinLen))
        ret = PIN_INVALID_E;
    WP11_Lock_UnlockRO(&slot->lock);

    return ret;
}

/**
 * Check the PIN is correct for user.
 *
 * @param  slot    [in]  Slot object.
 * @param  pin     [in]  PIN to check.
 * @param  pinLen  [in]  Length of PIN.
 * @return  PIN_NOT_SET_E when the token is not initialized.
 *          PIN_INVALID_E when the PIN is not correct.
 *          Other -ve value when hashing PIN fails.
 *          0 when PIN is correct.
 */
int WP11_Slot_CheckUserPin(WP11_Slot* slot, char* pin, int pinLen)
{
    int ret = 0;
    WP11_Token* token;
    byte hash[PIN_HASH_SZ];

    WP11_Lock_LockRO(&slot->lock);
    token = &slot->token;
    if (token->state != WP11_TOKEN_STATE_INITIALIZED)
        ret = PIN_NOT_SET_E;
    if (!(token->tokenFlags & WP11_TOKEN_FLAG_USER_PIN_SET))
        ret = PIN_NOT_SET_E;

    if (ret == 0) {
        WP11_Lock_UnlockRO(&slot->lock);

        /* Costly Operation done out of lock. */
        ret = HashPIN(pin, pinLen, token->userPinSeed,
                                sizeof(token->userPinSeed), hash, sizeof(hash));

        WP11_Lock_LockRO(&slot->lock);
    }
    if (ret == 0 &&
            !WP11_ConstantCompare(hash, token->userPin, token->userPinLen))
        ret = PIN_INVALID_E;
    WP11_Lock_UnlockRO(&slot->lock);

    return ret;
}

/**
 * Log the SO (Security Officer) into the token.
 *
 * @param  slot    [in]  Slot object.
 * @param  pin     [in]  PIN to use to login.
 * @param  pinLen  [in]  Length of PIN.
 * @return  READ_ONLY_E when there is a read-only session open.
 *          PIN_NOT_SET_E when the token is not initialized.
 *          PIN_INVALID_E when the PIN is not correct.
 *          Other -ve value when hashing PIN fails.
 *          0 on success.
 */
int WP11_Slot_SOLogin(WP11_Slot* slot, char* pin, int pinLen)
{
    int ret = 0;
#ifndef WOLFPKCS11_NO_TIME
    time_t now;
    time_t allowed;
#endif
    int state;

#ifndef WOLFPKCS11_NO_TIME
    if (wc_GetTime(&now, sizeof(now)) != 0)
        ret = PIN_INVALID_E;
#endif

    WP11_Lock_LockRO(&slot->lock);
    if (ret == 0) {
        /* Have we already logged in? */
        state = slot->token.loginState;
        if (state == WP11_APP_STATE_RW_SO || state == WP11_APP_STATE_RO_USER ||
                                              state == WP11_APP_STATE_RW_USER) {
            ret = LOGGED_IN_E;
        }
    }
#ifndef WOLFPKCS11_NO_TIME
    /* Check for too many fails and timeout. */
    if (ret == 0 && slot->token.soFailedLogin == WP11_MAX_LOGIN_FAILS_SO) {
        allowed = slot->token.soLastFailedLogin +
                                                 slot->token.soFailLoginTimeout;
        if (allowed < now)
            slot->token.soFailedLogin = 0;
        else
            ret = PIN_INVALID_E;
    }
#else
    slot->token.soFailedLogin = 0;
#endif
#ifndef WOLFPKCS11_NSS
    /* NSS creates a read-only session at the start and doesn't close this,
     * so when the RW session is opened for this, it fails.
     */
    if (ret == 0) {
        WP11_Session* curr;
        for (curr = slot->session; curr != NULL;
             curr = curr->next) {
            if (curr->inUse == WP11_SESSION_RO)
                break;
        }
        if (curr != NULL)
            ret = READ_ONLY_E;
    }
#endif
    WP11_Lock_UnlockRO(&slot->lock);

    if (ret == 0) {
        ret = WP11_Slot_CheckSOPin(slot, pin, pinLen);
        WP11_Lock_LockRW(&slot->lock);
        /* PIN Failed - Update failure info. */
        if (ret == PIN_INVALID_E) {
#ifndef WOLFPKCS11_NO_TIME
            slot->token.soFailedLogin++;
            if (slot->token.soFailedLogin == WP11_MAX_LOGIN_FAILS_SO) {
                slot->token.soLastFailedLogin = now;
                slot->token.soFailLoginTimeout += WP11_SO_LOGIN_FAIL_TIMEOUT;
            }
#endif
        }
        /* Worked - clear failure info. */
        else if (ret == 0) {
            slot->token.soFailedLogin = 0;
            slot->token.soLastFailedLogin = 0;
            slot->token.soFailLoginTimeout = 0;
        }
        WP11_Lock_UnlockRW(&slot->lock);
    }

    if (ret == 0) {
        WP11_Lock_LockRW(&slot->lock);
        slot->token.loginState = WP11_APP_STATE_RW_SO;
        WP11_Lock_UnlockRW(&slot->lock);
    }

    return ret;
}

/**
 * Log the user into the token.
 *
 * @param  slot    [in]  Slot object.
 * @param  pin     [in]  PIN to use to login.
 * @param  pinLen  [in]  Length of PIN.
 * @return  READ_ONLY_E when there is a read-only session open.
 *          PIN_NOT_SET_E when the token is not initialized.
 *          PIN_INVALID_E when the PIN is not correct.
 *          Other -ve value when hashing PIN fails.
 *          0 on success.
 */
int WP11_Slot_UserLogin(WP11_Slot* slot, char* pin, int pinLen)
{
    int ret = 0;
#ifndef WOLFPKCS11_NO_TIME
    time_t now;
    time_t allowed;
#endif
    int state;
    WP11_Token* token = &slot->token;

#ifndef WOLFPKCS11_NO_TIME
    if (wc_GetTime(&now, sizeof(now)) != 0)
        ret = PIN_INVALID_E;
#endif

    WP11_Lock_LockRW(&slot->lock);
    /* Have we already logged in? */
    if (ret == 0) {
        /* Have we already logged in? */
        state = token->loginState;
        if (state == WP11_APP_STATE_RW_SO || state == WP11_APP_STATE_RO_USER ||
                                              state == WP11_APP_STATE_RW_USER) {
            ret = LOGGED_IN_E;
        }
    }
#ifndef WOLFPKCS11_NO_TIME
    /* Check for too many fails */
    if (ret == 0 && token->userFailedLogin == WP11_MAX_LOGIN_FAILS_USER) {
        allowed = token->userLastFailedLogin + token->userFailLoginTimeout;
        if (allowed < now)
            token->userFailedLogin = 0;
        else
            ret = PIN_INVALID_E;
    }
#else
    token->userFailedLogin = 0;
#endif
    WP11_Lock_UnlockRW(&slot->lock);

    if (ret == 0) {
        ret = WP11_Slot_CheckUserPin(slot, pin, pinLen);
    #ifndef WOLFPKCS11_NO_STORE
        if (ret == 0) {
            ret = HashPIN(pin, pinLen, token->seed, sizeof(token->seed),
                token->key, sizeof(token->key));
        }
    #endif
        WP11_Lock_LockRW(&slot->lock);
        /* PIN Failed - Update failure info. */
        if (ret == PIN_INVALID_E) {
#ifndef WOLFPKCS11_NO_TIME
            token->userFailedLogin++;
            if (token->userFailedLogin == WP11_MAX_LOGIN_FAILS_USER) {
                token->userLastFailedLogin = now;
                token->userFailLoginTimeout += WP11_USER_LOGIN_FAIL_TIMEOUT;
            }
#endif
        }
        /* Worked - clear failure info. */
        else if (ret == 0) {
        #ifndef WOLFPKCS11_NO_STORE
            WP11_Object* object;
        #endif

            token->userFailedLogin = 0;
            token->userLastFailedLogin = 0;
            token->userFailLoginTimeout = 0;

        #ifndef WOLFPKCS11_NO_STORE
            object = token->object;
            while (ret == 0 && object != NULL) {
                ret = wp11_Object_Decode(object);
                object = object->next;
            }
        #endif
        }
        WP11_Lock_UnlockRW(&slot->lock);
    }

    if (ret == 0) {
        WP11_Lock_LockRW(&slot->lock);
        token->loginState = WP11_APP_STATE_RW_USER;
        WP11_Lock_UnlockRW(&slot->lock);
    }

    return ret;

}

/**
 * Set the SO's (Security Officer's) PIN.
 * Store the hash of the PIN and new seed.
 *
 * @param  slot    [in]  Slot object.
 * @param  pin     [in]  PIN to set.
 * @param  pinLen  [in]  Length of PIN.
 * @return  -ve value when generating random or hashing PIN fails.
 *          0 on success.
 */
int WP11_Slot_SetSOPin(WP11_Slot* slot, char* pin, int pinLen)
{
    int ret = 0;
    WP11_Token* token;

    WP11_Lock_LockRW(&slot->lock);
    token = &slot->token;
    /* New seed each time. */
    WP11_Lock_LockRW(&slot->token.rngLock);
    ret = wc_RNG_GenerateBlock(&slot->token.rng, token->soPinSeed,
                                                      sizeof(token->soPinSeed));
    WP11_Lock_UnlockRW(&slot->token.rngLock);
    if (ret == 0) {
        WP11_Lock_UnlockRW(&slot->lock);
        /* Costly Operation done out of lock. */
        ret = HashPIN(pin, pinLen, token->soPinSeed,
                                         sizeof(token->soPinSeed), token->soPin,
                                         sizeof(token->soPin));
        WP11_Lock_LockRW(&slot->lock);
    }
    if (ret == 0) {
        token->soPinLen = sizeof(token->soPin);
        token->tokenFlags |= WP11_TOKEN_FLAG_SO_PIN_SET;
    #ifndef WOLFPKCS11_NO_STORE
        ret = wp11_Token_Store(token, (int)slot->id);
    #endif
    }
    WP11_Lock_UnlockRW(&slot->lock);

    return ret;
}

/**
 * Set the User's PIN.
 * Store the hash of the PIN and new seed.
 *
 * @param  slot    [in]  Slot object.
 * @param  pin     [in]  PIN to set.
 * @param  pinLen  [in]  Length of PIN.
 * @return  -ve value when generating random or hashing PIN fails.
 *          0 on success.
 */
int WP11_Slot_SetUserPin(WP11_Slot* slot, char* pin, int pinLen)
{
    int ret = 0;
    WP11_Token* token;

    WP11_Lock_LockRW(&slot->lock);
    token = &slot->token;
    /* New seed each time. */
    WP11_Lock_LockRW(&slot->token.rngLock);
    ret = wc_RNG_GenerateBlock(&slot->token.rng, token->userPinSeed,
                                                    sizeof(token->userPinSeed));
#ifndef WOLFPKCS11_NO_STORE
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&slot->token.rng, token->seed,
                                                           sizeof(token->seed));
    }
#endif
    WP11_Lock_UnlockRW(&slot->token.rngLock);
    if (ret == 0) {
        WP11_Lock_UnlockRW(&slot->lock);
        /* Costly Operation done out of lock. */
        ret = HashPIN(pin, pinLen, token->userPinSeed,
                                     sizeof(token->userPinSeed), token->userPin,
                                     sizeof(token->userPin));
    #ifndef WOLFPKCS11_NO_STORE
        if (ret == 0) {
            ret = HashPIN(pin, pinLen, token->seed, sizeof(token->seed),
                token->key, sizeof(token->key));
        }
    #endif
        WP11_Lock_LockRW(&slot->lock);
    }
    if (ret == 0) {
        token->userPinLen = sizeof(token->userPin);
        token->tokenFlags |= WP11_TOKEN_FLAG_USER_PIN_SET;
    #ifndef WOLFPKCS11_NO_STORE
        ret = wp11_Token_Store(token, (int)slot->id);
    #endif
    }
    WP11_Lock_UnlockRW(&slot->lock);

    return ret;
}

/**
 * Logout of the token.
 *
 * @param  slot  [in]  Slot object referencing token.
 */
void WP11_Slot_Logout(WP11_Slot* slot)
{
#ifndef WOLFPKCS11_NO_STORE
    int state;
    int ret = 0;
#endif

    WP11_Lock_LockRW(&slot->lock);

#ifndef WOLFPKCS11_NO_STORE
    state = slot->token.loginState;
    if (state == WP11_APP_STATE_RO_USER || state == WP11_APP_STATE_RW_USER) {
        WP11_Object* object = slot->token.object;
        while (ret == 0 && object != NULL) {
            ret = wp11_Object_Encode(object, 1);
            object = object->next;
        }
    }
#endif
    slot->token.loginState = WP11_APP_STATE_RW_PUBLIC;

    WP11_Lock_UnlockRW(&slot->lock);
}

/**
 * Retrieve the token's label.
 * A token's label is 32 bytes long.
 *
 * @param  slot   [in]  Slot object.
 * @param  label  [in]  Buffer to put label in.
 */
void WP11_Slot_GetTokenLabel(WP11_Slot* slot, char* label)
{
    char* tokenLabel;

    WP11_Lock_LockRO(&slot->lock);
    tokenLabel = slot->token.label;
    /* An unset label is all zeros - label is padded with ' ' and no NUL. */
    if (tokenLabel[0] == '\0') {
        XMEMSET(label, ' ', LABEL_SZ);
        XMEMCPY(label, "wolfPKCS11", 10);
    } else
        XMEMCPY(label, tokenLabel, LABEL_SZ);
    WP11_Lock_UnlockRO(&slot->lock);
}

/**
 * Check if token has been initialized.
 *
 * @param  slot  [in]  Slot object referencing token.
 * @return  1 when token is initialized.
 *          0 when token is not initialized.
 */
int WP11_Slot_IsTokenInitialized(WP11_Slot* slot)
{
    int ret;

    WP11_Lock_LockRO(&slot->lock);
    ret = slot->token.state != WP11_TOKEN_STATE_UNKNOWN;
    WP11_Lock_UnlockRO(&slot->lock);

    return ret;
}

/**
 * Get the number of failed logins on the slot/token for the login type.
 *
 * @param  slot   [in]  Slot object.
 * @param  login  [in]  Security officer or user.
 * @return  Count of consecutive failed logins.
 */
int WP11_Slot_TokenFailedLogin(WP11_Slot* slot, int login)
{
    if (login == WP11_LOGIN_SO)
        return slot->token.soFailedLogin;
    else
        return slot->token.userFailedLogin;
}

/**
 * Get the expiry time of failed login timeout on the slot/token for the login
 * type.
 *
 * @param  slot   [in]  Slot object.
 * @param  login  [in]  Security officer or user.
 * @return  Count of consecutive failed logins.
 */
time_t WP11_Slot_TokenFailedExpire(WP11_Slot* slot, int login)
{
    if (login == WP11_LOGIN_SO)
        return slot->token.soLastFailedLogin + slot->token.soFailLoginTimeout;
    else {
        return slot->token.userLastFailedLogin +
                                               slot->token.userFailLoginTimeout;
    }
}

/**
 * Check whether the User PIN has been initialized for this slot/token.
 *
 * @param  slot   [in]  Slot object.
 * @return  1 when PIN initialized.
 *          0 when PIN not initialized.
 */
int WP11_Slot_IsTokenUserPinInitialized(WP11_Slot* slot)
{
    return slot->token.tokenFlags & WP11_TOKEN_FLAG_USER_PIN_SET;
}

/**
 * Get the session object identified by the session handle.
 *
 * @param  sessionHandle  [in]   Session handle identifier.
 * @param  session        [out]  Session object with the session handle.
 * @return  BAD_FUNC_ARG when no session object found.
 *          0 when session object found.
 */
int WP11_Session_Get(CK_SESSION_HANDLE sessionHandle, WP11_Session** session)
{
    int ret = 0;
    CK_SLOT_ID slotHandle = SESS_HANDLE_SLOT_ID(sessionHandle);
    WP11_Slot* slot;
    WP11_Session *sess;

    ret = WP11_Slot_Get(slotHandle, &slot);
    if (ret == 0) {
        WP11_Lock_LockRO(&slot->lock);
        sess = slot->session;
        while (sess != NULL && sess->handle != sessionHandle)
            sess = sess->next;
        if (sess == NULL || !sess->inUse)
            ret = BAD_FUNC_ARG;
        else
            *session = sess;
        WP11_Lock_UnlockRO(&slot->lock);
    }

    return ret;
}

/**
 * Get the current state of the session.
 *
 * @param  session  [in]  Session object.
 * @return  The session state.
 */
int WP11_Session_GetState(WP11_Session* session)
{
    int ret;

    WP11_Lock_LockRO(&session->slot->lock);
    if (session->slot->token.loginState == WP11_APP_STATE_RW_SO)
        ret = WP11_APP_STATE_RW_SO;
    else if (session->slot->token.loginState == WP11_APP_STATE_RW_USER) {
        if (session->inUse == WP11_SESSION_RW)
            ret = WP11_APP_STATE_RW_USER;
        else
            ret = WP11_APP_STATE_RO_USER;
    }
    else {
        if (session->inUse == WP11_SESSION_RW)
            ret = WP11_APP_STATE_RW_PUBLIC;
        else
            ret = WP11_APP_STATE_RO_PUBLIC;
    }
    WP11_Lock_UnlockRO(&session->slot->lock);

    return ret;
}

/**
 * Return whether this session is in use.
 *
 * @param  session  [in]  Session object.
 * @return  1 when session is in used.
 *          0 when session is not in used.
 */
int WP11_Session_IsRW(WP11_Session* session)
{
#ifdef WOLFPKCS11_NSS
    (void) session;
    return 1;
#else
    return session->inUse == WP11_SESSION_RW;
#endif
}

/**
 * Return whether this session has been initialized for the operation.
 *
 * @param  session  [in]  Session object.
 * @param  init     [in]  Operation to check.
 * @return  1 when session is in used.
 *          0 when session is not in used.
 */
int WP11_Session_IsOpInitialized(WP11_Session* session, int init)
{
    return (session->init & ~WP11_INIT_DIGEST_MASK) == init;
}

int WP11_Session_UpdateData(WP11_Session *session, byte *data, word32 dataLen)
{
    byte* tmp = (byte*)XREALLOC(session->data, session->dataSz + dataLen, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL)
        return MEMORY_E;
    session->data = tmp;
    XMEMCPY(session->data + session->dataSz, data, dataLen);
    session->dataSz += dataLen;
    return 0;
}

void WP11_Session_GetData(WP11_Session *session, byte** data, word32* dataLen)
{
    *data = session->data;
    *dataLen = session->dataSz;
}

void WP11_Session_FreeData(WP11_Session *session)
{
    XFREE(session->data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    session->data = NULL;
    session->dataSz = 0;
    session->init = 0;
}

static int MechanismToHash(int mechanism)
{
    switch (mechanism) {
#ifdef HAVE_ECC
#ifndef NO_SHA
        case CKM_ECDSA_SHA1:
            return WP11_INIT_SHA1;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_ECDSA_SHA224:
            return WP11_INIT_SHA224;
#endif
#ifndef NO_SHA256
        case CKM_ECDSA_SHA256:
            return WP11_INIT_SHA256;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_ECDSA_SHA384:
            return WP11_INIT_SHA384;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_ECDSA_SHA512:
            return WP11_INIT_SHA512;
#endif
#endif
#ifndef NO_RSA
#ifdef WOLFSSL_SHA224
        case CKM_SHA224_RSA_PKCS:
        case CKM_SHA224_RSA_PKCS_PSS:
            return WP11_INIT_SHA224;
#endif
#ifndef NO_SHA256
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
            return WP11_INIT_SHA256;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS_PSS:
            return WP11_INIT_SHA384;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS_PSS:
            return WP11_INIT_SHA512;
#endif
#endif
#ifndef NO_MD5
        case CKM_MD5:
        case CKM_MD5_HMAC:
            return WP11_INIT_MD5;
#endif
#ifndef NO_SHA
        case CKM_SHA1:
        case CKM_SHA1_HMAC:
            return WP11_INIT_SHA1;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_SHA224:
        case CKM_SHA224_HMAC:
            return WP11_INIT_SHA224;
#endif
#ifndef NO_SHA256
        case CKM_SHA256:
        case CKM_SHA256_HMAC:
            return WP11_INIT_SHA256;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_SHA384:
        case CKM_SHA384_HMAC:
            return WP11_INIT_SHA384;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_SHA512:
        case CKM_SHA512_HMAC:
            return WP11_INIT_SHA512;
#endif
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
        case CKM_SHA3_224:
        case CKM_SHA3_224_HMAC:
            return WP11_INIT_SHA3_224;
#endif
#ifndef WOLFSSL_NOSHA3_256
        case CKM_SHA3_256:
        case CKM_SHA3_256_HMAC:
            return WP11_INIT_SHA3_256;
#endif
#ifndef WOLFSSL_NOSHA3_384
        case CKM_SHA3_384:
        case CKM_SHA3_384_HMAC:
            return WP11_INIT_SHA3_384;
#endif
#ifndef WOLFSSL_NOSHA3_512
        case CKM_SHA3_512:
        case CKM_SHA3_512_HMAC:
            return WP11_INIT_SHA3_512;
#endif
#endif
        default:
            return 0;
    }
}

/**
 * Return whether this session has been initialized for the hash operation.
 *
 * @param  session   [in]  Session object.
 * @param  mechanism [in]  Mechanism to check against.
 * @return  1 when session is in used.
 *          0 when session is not in used.
 */
int WP11_Session_IsHashOpInitialized(WP11_Session* session, int mechanism)
{
    return (session->init & WP11_INIT_DIGEST_MASK) ==
            MechanismToHash(mechanism);
}

enum wc_HashType WP11_Session_ToHashType(WP11_Session* session)
{
    switch (session->init & WP11_INIT_DIGEST_MASK) {
#ifndef NO_SHA
        case WP11_INIT_SHA1:
            return WC_HASH_TYPE_SHA;
#endif
#ifdef WOLFSSL_SHA224
        case WP11_INIT_SHA224:
            return WC_HASH_TYPE_SHA224;
#endif
#ifndef NO_SHA256
        case WP11_INIT_SHA256:
            return WC_HASH_TYPE_SHA256;
#endif
#ifdef WOLFSSL_SHA384
        case WP11_INIT_SHA384:
            return WC_HASH_TYPE_SHA384;
#endif
#ifdef WOLFSSL_SHA512
        case WP11_INIT_SHA512:
            return WC_HASH_TYPE_SHA512;
#endif
        default:
            return WC_HASH_TYPE_NONE;
    }
}

/**
 * Set the operation this session has been initialized for.
 *
 * @param  session  [in]  Session object.
 */
void WP11_Session_SetOpInitialized(WP11_Session* session, int init)
{
    session->init = init;
}

/**
 * Get the slot object associated with the session.
 *
 * @param  session  [in]  Session object.
 * @return  Slot object.
 */
WP11_Slot* WP11_Session_GetSlot(WP11_Session* session)
{
    return session->slot;
}

/**
 * Get the mechanism associated with the session.
 *
 * @param  session  [in]  Session object.
 * @return  Mechanism of the session.
 */
CK_MECHANISM_TYPE WP11_Session_GetMechanism(WP11_Session* session)
{
    return session->mechanism;
}

/**
 * Set the mechanism for this session.
 *
 * @param  session    [in]  Session object.
 * @param  mechanism  [in]  Mechanism value.
 */
void WP11_Session_SetMechanism(WP11_Session* session,
                               CK_MECHANISM_TYPE mechanism)
{
    session->mechanism = mechanism;
}

#if !defined(NO_RSA) || !defined(WC_NO_RSA_OAEP) || defined(WC_RSA_PSS) || \
    defined(WOLFPKCS11_HKDF)
/**
 * Convert the digest mechanism to a hash type for wolfCrypt.
 *
 * @param  hashMech  [in]   Digest mechanism.
 * @param  hashType  [out]  Hash type.
 * @return  BAD_FUNC_ARG when the digest mechanism is not recognized.
 *          0 on success.
 */
static int wp11_hash_type(CK_MECHANISM_TYPE hashMech,
                          enum wc_HashType *hashType)
{
    int ret = 0;

    switch (hashMech) {
        case CKM_SHA1:
        case CKM_SHA1_HMAC:
            *hashType = WC_HASH_TYPE_SHA;
            break;
        case CKM_SHA224:
        case CKM_SHA224_HMAC:
            *hashType = WC_HASH_TYPE_SHA224;
            break;
        case CKM_SHA256:
        case CKM_SHA256_HMAC:
            *hashType = WC_HASH_TYPE_SHA256;
            break;
        case CKM_SHA384:
        case CKM_SHA384_HMAC:
            *hashType = WC_HASH_TYPE_SHA384;
            break;
        case CKM_SHA512:
        case CKM_SHA512_HMAC:
            *hashType = WC_HASH_TYPE_SHA512;
            break;
        case CKM_SHA3_224:
            *hashType = WC_HASH_TYPE_SHA3_224;
            break;
        case CKM_SHA3_256:
            *hashType = WC_HASH_TYPE_SHA3_256;
            break;
        case CKM_SHA3_384:
            *hashType = WC_HASH_TYPE_SHA3_384;
            break;
        case CKM_SHA3_512:
            *hashType = WC_HASH_TYPE_SHA3_512;
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}
#endif

#if !defined(NO_RSA)
#if !defined(WC_NO_RSA_OAEP) || defined(WC_RSA_PSS)
/**
 * Convert the mask generation function id to a wolfCrypt MGF id.
 *
 * @param  mgfType  [in]   Mask generation function id.
 * @param  mgf      [out]  wolfCrypt MGF id.
 * @return  BAD_FUNC_ARG when the mask generation function id is not recognized.
 *          0 on success.
 */
static int wp11_mgf(CK_MECHANISM_TYPE mgfType, int *mgf)
{
    int ret = 0;

    switch (mgfType) {
        case CKG_MGF1_SHA1:
            *mgf = WC_MGF1SHA1;
            break;
        case CKG_MGF1_SHA224:
            *mgf = WC_MGF1SHA224;
            break;
        case CKG_MGF1_SHA256:
            *mgf = WC_MGF1SHA256;
            break;
        case CKG_MGF1_SHA384:
            *mgf = WC_MGF1SHA384;
            break;
        case CKG_MGF1_SHA512:
            *mgf = WC_MGF1SHA512;
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}
#endif /* !WC_NO_RSA_OAEP || WC_RSA_PSS */

#ifndef WC_NO_RSA_OAEP
/**
 * Set the parameters to use for an OAEP operation.
 *
 * @param  session  [in]  Session object.
 * @param  hashAlg  [in]  Digest algorithm id.
 * @param  mgf      [in]  Mask generation function id.
 * @param  label    [in]  Additional authentication data.
 * @param  labelSz  [in]  Length of data in bytes.
 * @return  MEMORY_E when dynamic memory allocation fails.
 *          BAD_FUNC_ARG when the digest algorithm id or the mask generation
 *          function id are not recognized.
 *          0 on success.
 */
int WP11_Session_SetOaepParams(WP11_Session* session, CK_MECHANISM_TYPE hashAlg,
                               CK_MECHANISM_TYPE mgf, byte* label, int labelSz)
{
    int ret;
    WP11_OaepParams* oaep = &session->params.oaep;

    XMEMSET(oaep, 0, sizeof(*oaep));
    ret = wp11_hash_type(hashAlg, &oaep->hashType);
    if (ret == 0)
        ret = wp11_mgf(mgf, &oaep->mgf);
    if (ret == 0 && label == NULL) {
        oaep->label = NULL;
        oaep->labelSz = 0;
    }
    if (ret == 0 && label != NULL) {
        oaep->label = (byte*)XMALLOC(labelSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (oaep->label == NULL)
            ret = MEMORY_E;
        else {
            XMEMCPY(oaep->label, label, labelSz);
            oaep->labelSz = labelSz;
        }
    }

    return ret;
}
#endif /* WC_NO_RSA_OAEP */

#ifdef WC_RSA_PSS
/**
 * Set the parameters to use for a PSS operation.
 *
 * @param  session  [in]  Session object.
 * @param  hashAlg  [in]  Digest algorithm id.
 * @param  mgf      [in]  Mask generation function id.
 * @param  sLen     [in]  Salt length.
 * @return  BAD_FUNC_ARG when the digest algorithm id or the mask generation
 *          function id are not recognized or salt length is too big.
 *          0 on success.
 */
int WP11_Session_SetPssParams(WP11_Session* session, CK_MECHANISM_TYPE hashAlg,
                              CK_MECHANISM_TYPE mgf, int sLen)
{
    int ret;
    WP11_PssParams* pss = &session->params.pss;

    XMEMSET(pss, 0, sizeof(*pss));
    ret = wp11_hash_type(hashAlg, &pss->hashType);
    if (ret == 0)
        ret = wp11_mgf(mgf, &pss->mgf);
    if (ret == 0 && sLen > RSA_PSS_SALT_MAX_SZ)
        ret = BAD_FUNC_ARG;
    else
        pss->saltLen = sLen;

    return ret;
}
#endif /* WC_RSA_PSS */
#endif /* !NO_RSA */

#ifndef NO_AES
#ifdef HAVE_AES_CBC
/**
 * Set the parameters to use for an AES-CBC operation.
 *
 * @param  session  [in]  Session object.
 * @param  iv       [in]  Initialization vector.
 * @param  enc      [in]  Whether operation is encryption.
 * @param  object   [in]  AES key object.
 * @return  -ve on failure.
 *          0 on success.
 */
int WP11_Session_SetCbcParams(WP11_Session* session, unsigned char* iv,
                              int enc, WP11_Object* object)
{
    int ret;
    WP11_CbcParams* cbc = &session->params.cbc;
    WP11_Data* key;

    /* AES object on session. */
    ret = wc_AesInit(&cbc->aes, NULL, session->devId);
    if (ret == 0) {
        if (object->onToken)
            WP11_Lock_LockRO(object->lock);
        key = object->data.symmKey;
        ret = wc_AesSetKey(&cbc->aes, key->data, key->len, iv,
                                         enc ? AES_ENCRYPTION : AES_DECRYPTION);
        if (object->onToken)
            WP11_Lock_UnlockRO(object->lock);
    }

    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESCTR
/**
 * Set the parameters to use for an AES-CTR operation.
 *
 * @param session       [in]  Session object.
 * @param ulCounterBits [in]  Number of bits of the counter block. wolfCrypt
 *                            does not have a way of setting the counter bits.
 * @param cb            [in]  Counter block.
 * @param enc           [in]  Whether operation is encryption.
 * @param object        [in]  AES key object.
 * @return -ve on failure.
 *           0 on success.
 */
int WP11_Session_SetCtrParams(WP11_Session* session, CK_ULONG ulCounterBits,
                              CK_BYTE* cb, WP11_Object* object)
{
    int ret = 0;
    WP11_CtrParams* ctr = &session->params.ctr;
    WP11_Data* key;

    if (ulCounterBits > 128 || ulCounterBits == 0)
        return BAD_FUNC_ARG;

    ret = wc_AesInit(&ctr->aes, NULL, session->devId);
    if (ret == 0) {
        if (object->onToken)
            WP11_Lock_LockRO(object->lock);
        key = &object->data.symmKey;
        ret = wc_AesSetKey(&ctr->aes, key->data, key->len, cb, AES_ENCRYPTION);
        if (object->onToken)
            WP11_Lock_UnlockRO(object->lock);
    }

    return ret;
}
#endif /* HAVE_AESCTR */

#ifdef HAVE_AES_KEYWRAP
int WP11_Session_SetAesWrapParams(WP11_Session* session, byte* iv, word32 ivLen,
        WP11_Object* object, int enc)
{
    int ret = 0;
    WP11_KeyWrapParams *wrap = &session->params.kw;
    WP11_Data *key;

    XMEMSET(wrap, 0, sizeof(*wrap));
    ret = wc_AesInit(&wrap->aes, NULL, session->devId);
    if (ret == 0) {
        if (object->onToken)
            WP11_Lock_LockRO(object->lock);
        key = &object->data.symmKey;
        ret = wc_AesSetKey(&wrap->aes, key->data, key->len, NULL,
                enc ? AES_ENCRYPTION : AES_DECRYPTION);
        if (object->onToken)
            WP11_Lock_UnlockRO(object->lock);
    }
    if (ret == 0) {
        XMEMCPY(wrap->iv, iv, ivLen);
        wrap->ivSz = ivLen;
    }

    return ret;
}
#endif

#ifdef HAVE_AESGCM
/**
 * Set the parameters to use for an AES-GCM operation.
 *
 * @param  session  [in]  Session object.
 * @param  iv       [in]  Initialization vector.
 * @param  ivSz     [in]  Length of initialization vector in bytes.
 * @param  aad      [in]  Additional authentication data.
 * @param  aadSz    [in]  Length of additional authentication data.
 * @param  tagBits  [in]  Number of bits to use as the authentication tag.
 * @return  BAD_FUNC_ARG if the IV/nonce or the tagBits are too big.
 *          Other -ve value on failure.
 *          0 on success.
 */
int WP11_Session_SetGcmParams(WP11_Session* session, unsigned char* iv,
                              int ivSz, unsigned char* aad, int aadLen,
                              int tagBits)
{
    int ret = 0;
    WP11_GcmParams* gcm = &session->params.gcm;

    if (tagBits > 128 || ivSz > WP11_MAX_GCM_NONCE_SZ)
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        XMEMSET(gcm, 0, sizeof(*gcm));
        XMEMCPY(gcm->iv, iv, ivSz);
        gcm->ivSz = ivSz;
        gcm->tagBits = tagBits;
        if (aad != NULL) {
            gcm->aad = (unsigned char*)XMALLOC(aadLen, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (gcm->aad == NULL)
                ret = MEMORY_E;
            if (ret == 0) {
                XMEMCPY(gcm->aad, aad, aadLen);
                gcm->aadSz = aadLen;
            }
        }
    }

    return ret;
}
#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM
/**
 * Set the parameters to use for an AES-CCM operation.
 *
 * @param  dataSz   [in]  Length of data in bytes.
 * @param  session  [in]  Session object.
 * @param  iv       [in]  Nonce.
 * @param  ivSz     [in]  Length of nonce in bytes.
 * @param  aad      [in]  Additional authentication data.
 * @param  aadSz    [in]  Length of additional authentication data.
 * @param  macSz    [in]  Length of the MAC in bytes.
 * @return  BAD_FUNC_ARG if the IV/nonce is too big.
 *          Other -ve value on failure.
 *          0 on success.
 */
int WP11_Session_SetCcmParams(WP11_Session* session, int dataSz,
                              unsigned char* iv, int ivSz,
                              unsigned char* aad, int aadSz,
                              int macSz)
{
    int ret = 0;
    WP11_CcmParams* ccm = &session->params.ccm;

    if (ivSz > WP11_MAX_GCM_NONCE_SZ)
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        ccm->dataSz = dataSz;
        XMEMSET(ccm, 0, sizeof(*ccm));
        XMEMCPY(ccm->iv, iv, ivSz);
        ccm->ivSz = ivSz;
        if (aad != NULL) {
            ccm->aad = (unsigned char*)XMALLOC(aadSz, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (ccm->aad == NULL) {
                ret = MEMORY_E;
            }
            if (ret == 0) {
                XMEMCPY(ccm->aad, aad, aadSz);
                ccm->aadSz = aadSz;
            }
        }
        ccm->macSz = macSz;
    }

    return ret;
}
#endif /* HAVE_AESCCM */


#ifdef HAVE_AESCTS
int WP11_Session_SetCtsParams(WP11_Session* session, unsigned char* iv,
                              int enc, WP11_Object* object)
{
    int ret;
    WP11_CtsParams* cts = &session->params.cts;
    WP11_Data* key;

    /* AES object on session. */
    ret = wc_AesInit(&cts->aes, NULL, session->devId);
    if (ret == 0) {
        if (object->onToken)
            WP11_Lock_LockRO(object->lock);
        key = &object->data.symmKey;
        ret = wc_AesSetKey(&cts->aes, key->data, key->len, iv,
                                         enc ? AES_ENCRYPTION : AES_DECRYPTION);
        if (object->onToken)
            WP11_Lock_UnlockRO(object->lock);
    }

    return ret;
}
#endif /* HAVE_AESCTS */
#endif /* !NO_AES */

/**
 * Add object to the session or token.
 *
 * @param  session  [in]  Session object.
 * @param  onToken  [in]  Whether to put object on token.
 * @param  object   [in]  Key Object object.
 * @return  0 on success.
 */
int WP11_Session_AddObject(WP11_Session* session, int onToken,
                           WP11_Object* object)
{
    int ret = 0;
    WP11_Object* next;
    WP11_Token* token;

    object->onToken = onToken;
    if (!onToken)
        object->session = session;

    token = &session->slot->token;
    WP11_Lock_LockRW(&token->lock);
    if (onToken) {
        if (token->objCnt >= WP11_TOKEN_OBJECT_CNT_MAX)
            ret = OBJ_COUNT_E;
    #ifndef WOLFPKCS11_NO_STORE
        if (ret == 0)
            ret = wp11_Object_Encode(object, 0);
    #endif
        if (ret == 0) {
            token->objCnt++;
            object->lock = &token->lock;
            /* Get next item in list after this object has been added. */
            next = token->object;
            /* Determine handle value */
            object->handle = OBJ_HANDLE(onToken, token->nextObjId++);
            object->next = next;
            token->object = object;
        }
    #ifndef WOLFPKCS11_NO_STORE
        if (ret == 0) {
            ret = wp11_Slot_Store(session->slot, (int)session->slotId);
        }
    #endif
    }
    else {
        if (session->objCnt >= WP11_SESSION_OBJECT_CNT_MAX)
            ret = OBJ_COUNT_E;
        if (ret == 0) {
            session->objCnt++;
            /* Get next item in list after this object has been added. */
            next = session->object;
            /* Determine handle value */
            object->handle = OBJ_HANDLE(onToken, token->nextObjId++);
            object->next = next;
            session->object = object;
            object->session = session;
        }
    }
    WP11_Lock_UnlockRW(&token->lock);

    return ret;
}

/**
 * Remove object to the session or token.
 *
 * @param  session  [in]  Session object.
 * @param  object   [in]  Key Object object.
 */
void WP11_Session_RemoveObject(WP11_Session* session, WP11_Object* object)
{
    WP11_Object** curr;
    WP11_Token* token;
    int id;
#ifdef WOLFPKCS11_NSS
    if (object->session && (session != object->session))
        session = object->session;
#endif

    /* Find the object in list and relink. */
    if (object->onToken) {
        WP11_Lock_LockRW(object->lock);
        token = &session->slot->token;
        token->objCnt--;
        /* Id of first object on token. */
        id = token->objCnt;
        curr = &token->object;
    }
    else {
        session->objCnt--;
        /* Id of first object in session. */
        id = session->objCnt;
        curr = &session->object;
        WP11_Lock_LockRW(&session->slot->token.lock);
    }

    while (*curr != NULL) {
        if (*curr == object) {
            *curr = object->next;
            break;
        }
        curr = &(*curr)->next;
        /* Id of next object as it isn't the one being removed. */
        id--;
    }
    if (object->onToken) {
#ifndef WOLFPKCS11_NO_STORE
        int ret;
        wp11_Object_Unstore(object, (int)session->slotId, id);
        ret = wp11_Slot_Store(session->slot, (int)session->slotId);
    #ifdef DEBUG_WOLFPKCS11
        if (ret != 0) {
            printf("Failed to store slot %d, ret: %d\n",
                (int)session->slotId, ret);
        }
    #endif
        (void)ret; /* store failure cannot be returned, so log and ignore */
#endif
        WP11_Lock_UnlockRW(object->lock);
    }
    else {
        WP11_Lock_UnlockRW(&session->slot->token.lock);
    }
}

/**
 * Get the current object of the session - key for operation.
 *
 * @param  session  [in]   Session object.
 * @param  object   [out]  Key Object object.
 */
void WP11_Session_GetObject(WP11_Session* session, WP11_Object** object)
{
    *object = session->curr;
}

/**
 * Set the current object on the session - key for operation.
 *
 * @param  session  [in]  Session object.
 * @param  object   [in]  Key Object object.
 */
void WP11_Session_SetObject(WP11_Session* session, WP11_Object* object)
{
    session->curr = object;
}

/**
 * Initialize a find operation for an object in the session or the token.
 *
 * @param  session  [in]  Session object.
 * @return  BAD_STATE_E when a find operation is already active on the session.
 *          0 on success.
 */
int WP11_Session_FindInit(WP11_Session* session)
{
    int ret = 0;

    if (session->find.state != WP11_FIND_STATE_NULL)
        ret = BAD_STATE_E;
    if (ret == 0) {
        session->find.state = WP11_FIND_STATE_INIT;
        session->find.count = 0;
        session->find.curr = 0;
    }

    return ret;
}

/**
 * Find the next object on the session or token.
 *
 * @param  session  [in]  Session object.
 * @param  onToken  [in]  Whether to look on token.
 * @param  object   [in]  Last object found.
 * @return  The next object in session or token.
 */
static WP11_Object* wp11_Session_FindNext(WP11_Session* session, int onToken,
                                          WP11_Object* object)
{
    WP11_Object* ret = NULL;

    while (ret == NULL) {
        if (object == NULL) {
            ret = session->object;
            if (ret == NULL && onToken) {
                ret = session->slot->token.object;
            }
        }
        else if (object != NULL) {
            if (object->next != NULL)
                ret = object->next;
            else if (!object->onToken && onToken) {
                ret = object->slot->token.object;
            }
        }

        if (ret == NULL)
            break;

   #ifndef WOLFPKCS11_NO_STORE
        if (ret->encoded) {
            object = ret;
            ret = NULL;
            continue;
        }
   #endif

        if ((ret->opFlag & WP11_FLAG_PRIVATE) == WP11_FLAG_PRIVATE) {
            if (!onToken)
                WP11_Lock_LockRO(&session->slot->token.lock);
            if (!WP11_Slot_Has_Empty_Pin(session->slot) &&
                (session->slot->token.loginState == WP11_APP_STATE_RW_PUBLIC ||
                 session->slot->token.loginState == WP11_APP_STATE_RO_PUBLIC)) {
                object = ret;
                ret = NULL;
            }
            if (!onToken)
                WP11_Lock_UnlockRO(&session->slot->token.lock);
        }
    }

    return ret;
}

/**
 * Store a match in the found list against the session.
 *
 * @param  session  [in]  Session object.
 * @param  object   [in]  Object object to store reference to.
 * @return  FIND_FULL_E when the found list is full.
 *          0 on success.
 */
static int wp11_Session_FindMatched(WP11_Session* session, WP11_Object* object)
{
    int ret = 0;

    if (session->find.count == WP11_FIND_MAX)
        ret = FIND_FULL_E;
    else {
        session->find.found[session->find.count++] = object->handle;
        session->find.state = WP11_FIND_STATE_FOUND;
    }

    return ret;
}

/**
 * Find objects on session or token with attributes matching template.
 *
 * @param  session    [in]  Session object.
 * @param  onToken    [in]  Whether to look on token.
 * @param  pTemplate  [in]  Array of attributes that must match.
 * @param  ulCount    [in]  Number of attributes in array.
 */
void WP11_Session_Find(WP11_Session* session, int onToken,
                       CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    WP11_Object* obj = NULL;
    int i;
    CK_ATTRIBUTE* attr;

    if (onToken)
        WP11_Lock_LockRO(&session->slot->token.lock);
    while ((obj = wp11_Session_FindNext(session, onToken, obj)) != NULL) {
        for (i = 0; i < (int)ulCount; i++) {
            attr = &pTemplate[i];
            if (!WP11_Object_MatchAttr(obj, attr->type, (byte*)attr->pValue,
                                                            attr->ulValueLen)) {
                break;
            }
        }

        if (i == (int)ulCount) {
            if (wp11_Session_FindMatched(session, obj) == FIND_FULL_E)
                break;
        }
    }
    if (onToken)
        WP11_Lock_UnlockRO(&session->slot->token.lock);
}

/**
 * Get the next object handle from list of objects identified during find
 * operation.
 *
 * @param  session  [in]   Session object.
 * @param  handle   [out]  Object handle.
 * @return  FIND_NO_MORE_E when all in the found list has been returned.
 *          0 on success.
 */
int WP11_Session_FindGet(WP11_Session* session, CK_OBJECT_HANDLE* handle)
{
    int ret = 0;

    if (session->find.curr == session->find.count)
        ret = FIND_NO_MORE_E;
    if (ret == 0)
        *handle = session->find.found[session->find.curr++];

    return ret;
}

/**
 * Finalize the find operation.
 *
 * @param  session  [in]  Session object.
 */
void WP11_Session_FindFinal(WP11_Session* session)
{
    session->find.state = WP11_FIND_STATE_NULL;
}


/**
 * Free the object and take it out of the linked list.
 *
 * @param  object  [in]  Object object.
 */
void WP11_Object_Free(WP11_Object* object)
{
    int certFreed = 0;
#ifdef WOLFPKCS11_TPM
    if (object->tpmKey != NULL) {
        wolfTPM2_UnloadHandle(&object->slot->tpmDev, &object->tpmKey->handle);
        XFREE(object->tpmKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    /* Release dynamic memory. */
    if (object->label != NULL)
        XFREE(object->label, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (object->keyId != NULL)
        XFREE(object->keyId, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (object->issuer != NULL)
        XFREE(object->issuer, NULL, DYNAMIC_TYPE_CERT);
    if (object->serial != NULL)
        XFREE(object->serial, NULL, DYNAMIC_TYPE_CERT);
    if (object->subject != NULL)
        XFREE(object->subject, NULL, DYNAMIC_TYPE_CERT);
    if (object->objClass == CKO_CERTIFICATE) {
        XFREE(object->data.cert.data, NULL, DYNAMIC_TYPE_CERT);
        certFreed = 1;
    }
    else {
    #ifndef NO_RSA
        if (object->type == CKK_RSA && object->data.rsaKey != NULL) {
            wc_FreeRsaKey(object->data.rsaKey);
            XFREE(object->data.rsaKey, NULL, DYNAMIC_TYPE_RSA);
            object->data.rsaKey = NULL;
        }
    #endif
    #ifdef HAVE_ECC
        if (object->type == CKK_EC && object->data.ecKey != NULL) {
            wc_ecc_free(object->data.ecKey);
            XFREE(object->data.ecKey, NULL, DYNAMIC_TYPE_ECC);
            object->data.ecKey = NULL;
        }
    #endif
    #ifndef NO_DH
        if (object->type == CKK_DH && object->data.dhKey != NULL) {
            wc_FreeDhKey(&object->data.dhKey->params);
            XFREE(object->data.dhKey, NULL, DYNAMIC_TYPE_DH);
            object->data.dhKey = NULL;
        }
    #endif
        if ((object->type == CKK_AES || object->type == CKK_GENERIC_SECRET) &&
            object->data.symmKey != NULL) {
            /* TODO: ForceZero */
            XMEMSET(object->data.symmKey->data, 0, object->data.symmKey->len);
            XFREE(object->data.symmKey, NULL, DYNAMIC_TYPE_AES);
            object->data.symmKey = NULL;
        }
    }

#ifndef WOLFPKCS11_NO_STORE
    if (object->keyData != NULL && certFreed == 0)
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)certFreed;
#endif

    /* Dispose of object. */
    XFREE(object, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/**
 * Get the object's handle.
 *
 * @param  object  [in]  Object object.
 * @return  Object's handle.
 */
CK_OBJECT_HANDLE WP11_Object_GetHandle(WP11_Object* object)
{
    return object->handle;
}

/**
 * Get the object's type - for example the key type.
 *
 * @param  object  [in]  Object object.
 * @return  Object's type.
 */
CK_KEY_TYPE WP11_Object_GetType(WP11_Object* object)
{
    return object->type;
}

/**
 * Get the object's class.
 *
 * @param  object  [in]  Object object.
 * @return  Object's class.
 */
CK_OBJECT_CLASS WP11_Object_GetClass(WP11_Object* object)
{
    return object->objClass;
}

#if !defined(NO_RSA) || defined(HAVE_ECC)
/**
 * Set the multi-precision integer from the data.
 *
 * @param  mpi   [in]  Multi-precision integer.
 * @param  data  [in]  Big-endian encoding of number.
 * @param  len   [in]  Length in bytes.
 * @return  -ve on failure.
 *          0 on success.
 */
static int SetMPI(mp_int* mpi, unsigned char* data, int len)
{
    int ret = 0;

    if (data != NULL) {
        ret = mp_init(mpi);
        if (ret == 0)
            ret = mp_read_unsigned_bin(mpi, data, len);
    }

    return ret;
}
#endif

#ifndef NO_RSA
/**
 * Set the RSA key data into the object.
 * Store the data in the wolfCrypt data structure.
 *
 * @param  object  [in]  Object object.
 * @param  data    [in]  Array of byte arrays.
 * @param  len     [in]  Array of lengths of byte arrays.
 * @return  -ve on failure.
 *          0 on success.
 */
int WP11_Object_SetRsaKey(WP11_Object* object, unsigned char** data,
                          CK_ULONG* len)
{
    int ret;
    RsaKey* key;

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    key = object->data.rsaKey;
    ret = wc_InitRsaKey_ex(key, NULL, object->slot->devId);
    if (ret == 0) {
        ret = SetMPI(&key->d, data[1], (int)len[1]);
        if (ret == 0)
        ret = SetMPI(&key->p, data[2], (int)len[2]);
        if (ret == 0)
        ret = SetMPI(&key->q, data[3], (int)len[3]);
        /* If modulus is not provided, calculate it */
        if (ret == 0) {
            if (data[0] == NULL || len[0] == 0) {
                ret = mp_mul(&key->p, &key->q, &key->n);
            } else {
                ret = SetMPI(&key->n, data[0], (int)len[0]);
            }
        }
        if (ret == 0)
        ret = SetMPI(&key->dP, data[4], (int)len[4]);
        if (ret == 0)
        ret = SetMPI(&key->dQ, data[5], (int)len[5]);
        if (ret == 0)
        ret = SetMPI(&key->u, data[6], (int)len[6]);
        if (ret == 0) {
            /* Public exponent defaults to 65537 in PKCS11 > 2.11 */
            if (len[7] > 0)
                ret = SetMPI(&key->e, data[7], (int)len[7]);
            else {
                byte defaultPublic[] = {0x01, 0x00, 0x01};
                ret = SetMPI(&key->e, defaultPublic, sizeof(defaultPublic));
            }
        }
        if (ret == 0) {
        if (len[8] == sizeof(CK_ULONG))
            object->size = (word32)*(CK_ULONG*)data[8];
        else if (len[8] != 0)
            ret = BUFFER_E;
        }
        if (ret == 0) {
            if (mp_iszero(&key->d) && mp_iszero(&key->p)) {
                key->type = RSA_PUBLIC;
            }
            else {
                key->type = RSA_PRIVATE;
            }
        }

        if (ret != 0) {
            wc_FreeRsaKey(key);
        }
    }

#ifdef WOLFPKCS11_TPM
    if (ret == 0) {
        ret = WP11_Object_WrapTpmKey(object);
    }
#endif

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);

    return ret;
}
#endif

#ifdef HAVE_ECC

#if defined(HAVE_FIPS) && \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION <= 2))
#define USE_LOCAL_CURVE_OID_LOOKUP
/* This function is not in the FIPS 140-2 version */
/* ecc_sets is exposed in ecc.h */
static int ecc_get_curve_id_from_oid(const byte* oid, word32 len)
{
    int curve_idx;

    if (oid == NULL)
        return BAD_FUNC_ARG;

    for (curve_idx = 0; ecc_sets[curve_idx].size != 0; curve_idx++) {
        if (
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            ecc_sets[curve_idx].oid &&
        #endif
            ecc_sets[curve_idx].oidSz == len &&
                XMEMCMP(ecc_sets[curve_idx].oid, oid, len) == 0
        ) {
            break;
        }
    }
    if (ecc_sets[curve_idx].size == 0) {
        return ECC_CURVE_INVALID;
    }

    return ecc_sets[curve_idx].id;
}

#endif
/**
 * Set the EC Parameters based on the DER encoding of the OID.
 *
 * @param  key  [in]  EC Key object.
 * @param  der  [in]  DER encoding of OID.
 * @param  len  [in]  Length of DER encoding.
 * @return  BUFFER_E when len is too short.
 *          ASN_PARSE_E when DER encoding is bad.
 *          BAD_FUNC_ARG when OID is not known.
 *          Other -ve on failure.
 *          0 on success.
 */
static int EcSetParams(ecc_key* key, byte* der, int len)
{
    int ret = 0;
    int keySize;
    int curveId;

    if (len < 2)
        ret = BUFFER_E;
    if (ret == 0 && der[0] != ASN_OBJECT_ID)
        ret = ASN_PARSE_E;
    if (ret == 0 && der[1] != len - 2)
        ret = BUFFER_E;
    if (ret == 0) {
        /* Find the curve matching the OID. */
    #ifdef USE_LOCAL_CURVE_OID_LOOKUP
        curveId = ecc_get_curve_id_from_oid(der + 2, der[1]);
    #else
        curveId = wc_ecc_get_curve_id_from_oid(der + 2, der[1]);
    #endif
        if (curveId == ECC_CURVE_INVALID)
            ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Set the curve into the EC key. */
        keySize = wc_ecc_get_curve_size_from_id(curveId);
        ret = wc_ecc_set_curve(key, keySize, curveId);
    }

    return ret;
}

/**
 * Set the EC Point, encoded in DER and X9.63, as the public key.
 *
 * @param  key  [in]  EC Key object.
 * @param  der  [in]  DER encoding of OID.
 * @param  len  [in]  Length of DER encoding.
 * @return  BUFFER_E when len is too short.
 *          ASN_PARSE_E when DER encoding is bad.
 *          Other -ve on failure.
 *          0 on success.
 */
static int EcSetPoint(ecc_key* key, byte* der, int len)
{
    int ret = 0;
    int dataLen;
    int i = 0;

    if (len < 3)
        ret = BUFFER_E;
    if (ret == 0 && der[i++] != ASN_OCTET_STRING)
        ret = ASN_PARSE_E;
    if (ret == 0 && der[i] >= ASN_LONG_LENGTH) {
        if (der[i] != (ASN_LONG_LENGTH | 1))
            ret = ASN_PARSE_E;
        else
            i++;
    }
    if (ret == 0) {
        dataLen = der[i++];
        if (dataLen != len - i)
            ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Now stripped of DER encoding. */
        ret = wc_ecc_import_x963_ex(der + i, len - i, key, key->dp->id);
    }

    return ret;
}

/**
 * Set the EC key data into the object.
 * Store the data in the wolfCrypt data structure.
 *
 * @param  object  [in]  Object object.
 * @param  data    [in]  Array of byte arrays.
 * @param  len     [in]  Array of lengths of byte arrays.
 * @return  -ve on failure.
 *          0 on success.
 */
int WP11_Object_SetEcKey(WP11_Object* object, unsigned char** data,
                         CK_ULONG* len)
{
    int ret;
    ecc_key* key;

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    key = object->data.ecKey;
    ret = wc_ecc_init_ex(key, NULL, object->slot->devId);
    if (ret == 0) {
        if (ret == 0 && data[0] != NULL)
            ret = EcSetParams(key, data[0], (int)len[0]);
        if (ret == 0 && data[1] != NULL) {
            key->type = ECC_PRIVATEKEY_ONLY;
#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION <= 5)
            ret = SetMPI(&key->k, data[1], (int)len[1]);
#else
            ret = SetMPI(key->k, data[1], (int)len[1]);
#endif
        }
        if (ret == 0 && data[2] != NULL) {
            if (key->type == ECC_PRIVATEKEY_ONLY)
                key->type = ECC_PRIVATEKEY;
            else
                key->type = ECC_PUBLICKEY;
            ret = EcSetPoint(key, data[2], (int)len[2]);
        }

        if (ret != 0)
            wc_ecc_free(key);
    }

#ifdef WOLFPKCS11_TPM
    if (ret == 0) {
        ret = WP11_Object_WrapTpmKey(object);
    }
#endif

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);

    return ret;
}
#endif /* HAVE_ECC */

#ifndef NO_DH
/**
 * Set the DH key data into the object.
 * Store the data in the wolfCrypt data structure.
 *
 * @param  object  [in]  Object object.
 * @param  data    [in]  Array of byte arrays.
 * @param  len     [in]  Array of lengths of byte arrays.
 * @return  BAD_FUNC_ARG when public key is larger than pre-allocated buffer.
 *          Other -ve on failure.
 *          0 on success.
 */
int WP11_Object_SetDhKey(WP11_Object* object, unsigned char** data,
                         CK_ULONG* len)
{
    int ret;
    WP11_DhKey* key;

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    key = object->data.dhKey;
    ret = wc_InitDhKey_ex(&key->params, NULL, INVALID_DEVID);
    if (ret == 0) {
        if (data[0] != NULL && data[1] != NULL)
            ret = wc_DhSetKey(&key->params, data[0], (int)len[0], data[1],
                                                                   (int)len[1]);
        if (ret == 0 && data[2] != NULL) {
            if (len[2] > (int)sizeof(key->key))
                ret = BAD_FUNC_ARG;
            else {
                XMEMCPY(key->key, data[2], len[2]);
                key->len = (word32)len[2];
            }
        }

        if (ret != 0)
            wc_FreeDhKey(&key->params);
    }

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);

    return ret;
}
#endif

/**
 * Set the DH key data into the object.
 *
 * @param  object  [in]  Object object.
 * @param  data    [in]  Array of byte arrays.
 * @param  len     [in]  Array of lengths of byte arrays.
 * @return  BAD_FUNC_ARG when key length data is not size of CK_ULONG or
 *          key length is not a valid size for the key type.
 *          BUFFER_E when key data length is less than key length data value.
 *          Other -ve on failure.
 *          0 on success.
 */
int WP11_Object_SetSecretKey(WP11_Object* object, unsigned char** data,
                             CK_ULONG* len)
{
    int ret = 0;
    WP11_Data* key;

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    key = object->data.symmKey;
    key->len = 0;
    XMEMSET(key->data, 0, sizeof(key->data));

    /* First item is the key's length. */
    if (ret == 0 && data[0] != NULL && len[0] != (int)sizeof(CK_ULONG))
        ret = BAD_FUNC_ARG;
#ifndef NO_AES
    if (ret == 0 && object->type == CKK_AES && data[0] != NULL) {
        if (*(CK_ULONG*)data[0] != AES_128_KEY_SIZE &&
            *(CK_ULONG*)data[0] != AES_192_KEY_SIZE &&
            *(CK_ULONG*)data[0] != AES_256_KEY_SIZE) {
            ret = BAD_FUNC_ARG;
        }
    }
#endif
    if (ret == 0 && data[0] != NULL)
        key->len = (word32)*(CK_ULONG*)data[0];

    /* Second item is the key data. */
    if (ret == 0 && data[1] != NULL) {
        if (key->len == 0)
            key->len = (word32)len[1];
        else if (len[1] != (CK_ULONG)key->len)
            ret = BUFFER_E;
    }
    if (ret == 0 && key->len > WP11_MAX_SYM_KEY_SZ)
        ret = BUFFER_E;
    if (ret == 0 && data[1] != NULL)
        XMEMCPY(key->data, data[1], key->len);

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);

    return ret;
}

#ifdef WOLFPKCS11_NSS
int WP11_Object_SetTrust(WP11_Object* object, unsigned char** data,
                         CK_ULONG* len)
{
    WP11_Trust* trust;

    if (data[0] == NULL && len[0] != WC_SHA_DIGEST_SIZE)
        return BAD_FUNC_ARG;

    if (data[1] == NULL && len[1] != WC_MD5_DIGEST_SIZE)
        return BAD_FUNC_ARG;

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    trust = &object->data.trust;

    XMEMCPY(trust->sha1Hash, data[0], WC_SHA_DIGEST_SIZE);
    XMEMCPY(trust->md5Hash, data[1], WC_MD5_DIGEST_SIZE);
    if (data[2] != NULL)
        trust->serverAuth = *(CK_ULONG*)data[2];
    if (data[3] != NULL)
        trust->clientAuth = *(CK_ULONG*)data[3];
    if (data[4] != NULL)
        trust->emailProtection = *(CK_ULONG*)data[4];
    if (data[5] != NULL)
        trust->codeSigning = *(CK_ULONG*)data[5];
    if (data[6] != NULL)
        trust->stepUpApproved = *(CK_BBOOL*)data[6];

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);

    return CKR_OK;
}
#endif

int WP11_Object_SetCert(WP11_Object* object, unsigned char** data,
                        CK_ULONG* len)
{
    int ret = 0;
    WP11_Cert* cert;

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    cert = &object->data.cert;
    cert->len = 0;

    /* First item is certificate type */
    if (ret == 0 && data[0] != NULL && len[0] != (int)sizeof(CK_ULONG))
        ret = BAD_FUNC_ARG;
    if (ret == 0 && data[0] != NULL)
        cert->type = (word32)*(CK_ULONG*)data[0];

    /* Second item is certificate data (CKA_VALUE) */
    if (ret == 0 && data[1] != NULL) {
        cert->len = (word32)len[1];
    }
    if (ret == 0 && data[1] != NULL) {
        if (cert->data != NULL) {
            XFREE(cert->data, NULL, DYNAMIC_TYPE_CERT);
        }
        cert->data = (byte *)XMALLOC(cert->len, NULL, DYNAMIC_TYPE_CERT);
        if (cert->data == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0 && data[1] != NULL) {
        XMEMCPY(cert->data, data[1], cert->len);
    }

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);

    return ret;
}


/**
 * Set the object's class.
 *
 * @param  object    [in]  Object object.
 * @param  objClass  [in]  Object's class.
 * @return  0 on success.
 */
int WP11_Object_SetClass(WP11_Object* object, CK_OBJECT_CLASS objClass)
{
    if (object->onToken)
        WP11_Lock_LockRW(object->lock);
    object->objClass = objClass;
    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);

    return 0;
}

/**
 * Find an object based on the handle.
 *
 * @param  session    [in]   Session object.
 * @param  objHandle  [in]   Object's handle id.
 * @param  object     [out]  Found Object object.
 * @return  BAD_FUNC_ARG when object not found.
 *          0 when object found.
 */
int WP11_Object_Find(WP11_Session* session, CK_OBJECT_HANDLE objHandle,
                     WP11_Object** object)
{
    int ret = BAD_FUNC_ARG;
    WP11_Object* obj;
#ifdef WOLFPKCS11_NSS
    WP11_Session* scan;
#endif
    int onToken = OBJ_HANDLE_ON_TOKEN(objHandle);

    if (!onToken) {
        obj = session->object;
        while (obj != NULL) {
            if (obj->handle == objHandle) {
                ret = 0;
                break;
            }
            obj = obj->next;
        }
#ifdef WOLFPKCS11_NSS
        if (ret == BAD_FUNC_ARG) {
            /* Token lock is needed in case remove object is run, slot lock is
             * needed in case remove session is run */
            WP11_Lock_LockRO(&session->slot->lock);
            WP11_Lock_LockRO(&session->slot->token.lock);
            for (scan = session->slot->session; scan != NULL && ret != 0;
                 scan = scan->next) {
                if (scan == session)
                    continue;
                for (obj = scan->object; obj != NULL; obj = obj->next) {
                    if (obj->handle == objHandle) {
                        ret = 0;
                        break;
                    }
                }
            }
            WP11_Lock_UnlockRO(&session->slot->token.lock);
            WP11_Lock_UnlockRO(&session->slot->lock);
        }
#endif
    }
    else {
        WP11_Lock_LockRO(&session->slot->token.lock);
        obj = session->slot->token.object;
        while (obj != NULL) {
            if (obj->handle == objHandle) {
                ret = 0;
                break;
            }
            obj = obj->next;
        }
        WP11_Lock_UnlockRO(&session->slot->token.lock);
    }

    if (obj && (obj->handle == objHandle))
        *object = obj;

    return ret;
}

#if !defined(NO_RSA) || defined(HAVE_ECC) || !defined(NO_DH)
/**
 * Get the data from a multi-precision integer.
 *
 * @param  mpi   [in]      Multi-precision integer.
 * @param  data  [in]      Buffer to hold big-endian encoding of number.
 * @param  len   [in,out]  On in, length of buffer in bytes.
 *                         On out, length of data in buffer.
 * @return  BUFFER_E when buffer is too small for number.
 *          0 on success.
 */
static int GetMPIData(mp_int* mpi, byte* data, CK_ULONG* len)
{
    int ret = 0;
    CK_ULONG dataLen = mp_unsigned_bin_size(mpi);

    if (data == NULL)
        *len = dataLen;
    else if (*len < dataLen)
        ret = BUFFER_E;
    else {
        *len = dataLen;
        ret = mp_to_unsigned_bin(mpi, data);
    }

    return ret;
}
#endif

/**
 * Get the data for a boolean.
 *
 * @param  value  [in]      Boolean value.
 * @param  data   [in]      Buffer to hold boolean.
 * @param  len    [in,out]  On in, length of buffer in bytes.
 *                          On out, length of data in buffer.
 * @return  BUFFER_E when buffer is too small for boolean.
 *          0 on success.
 */
static int GetBool(CK_BBOOL value, byte* data, CK_ULONG* len)
{
    int ret = 0;
    CK_ULONG dataLen = sizeof(value);

    if (data == NULL)
        *len = dataLen;
    else if (*len < dataLen)
        ret = BUFFER_E;
    else {
        *len = dataLen;
        *(CK_BBOOL*)data = value != 0;
    }

    return ret;
}

/**
 * Get the boolean data for operation flags.
 *
 * @param  value  [in]      Flags.
 * @param  flag   [in]      Flag to check for.
 * @param  data   [in]      Buffer to hold boolean.
 * @param  len    [in,out]  On in, length of buffer in bytes.
 *                          On out, length of data in buffer.
 * @return  BUFFER_E when buffer is too small for boolean.
 *          0 on success.
 */
static int GetOpFlagBool(CK_ULONG flags, CK_ULONG flag, byte* data,
    CK_ULONG* len)
{
    return GetBool((flags & flag) == flag, data, len);
}

/**
 * Get the data for a CK_ULONG.
 *
 * @param  value  [in]      CK_ULONG value.
 * @param  data   [in]      Buffer to hold CK_ULONG value.
 * @param  len    [in,out]  On in, length of buffer in bytes.
 *                          On out, length of data in buffer.
 * @return  BUFFER_E when buffer is too small for number.
 *          0 on success.
 */
static int GetULong(CK_ULONG value, byte* data, CK_ULONG* len)
{
    int ret = 0;
    CK_ULONG dataLen = sizeof(value);

    if (data == NULL)
        *len = dataLen;
    else if (*len < dataLen)
        ret = BUFFER_E;
    else {
        *len = dataLen;
        *(CK_ULONG*)data = value;
    }

    return ret;
}

/**
 * Get the data of a data array.
 *
 * @param  data      [in]      Data array.
 * @param  dataLen   [in]      Length of data in data array in bytes.
 * @param  out       [in]      Buffer to hold data.
 * @param  outLen    [in,out]  On in, length of buffer in bytes.
 *                             On out, length of data in buffer.
 * @return  BUFFER_E when buffer is too small for data.
 *          0 on success.
 */
static int GetData(byte* data, CK_ULONG dataLen, byte* out, CK_ULONG* outLen)
{
    int ret = 0;

    if (out == NULL)
        *outLen = dataLen;
    else if (*outLen < dataLen)
        ret = BUFFER_E;
    else {
        *outLen = dataLen;
        XMEMCPY(out, data, dataLen);
    }

    return ret;
}

static int GetCertAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type, byte* data,
                       CK_ULONG* len)
{
    int ret = 0;

    if (object == NULL || len == NULL)
        return BAD_FUNC_ARG;

    switch (type) {
        case CKA_VALUE:
            ret = GetData((byte*)object->data.cert.data, object->data.cert.len,
                data, len);
            break;
        case CKA_ISSUER:
            ret = GetData(object->issuer, object->issuerLen, data, len);
            break;
        case CKA_SERIAL_NUMBER:
            ret = GetData(object->serial, object->serialLen, data, len);
            break;
        case CKA_SUBJECT:
            ret = GetData(object->subject, object->subjectLen, data, len);
            break;
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }

    return ret;
}

#ifdef WOLFPKCS11_NSS
static int GetTrustAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                        byte* data, CK_ULONG* len)
{
    int ret = 0;

    if (object == NULL || len == NULL)
        return BAD_FUNC_ARG;

    switch (type) {
        case CKA_CERT_SHA1_HASH:
            if (*len < WC_SHA_DIGEST_SIZE)
                return BUFFER_E;
            *len = WC_SHA_DIGEST_SIZE;
            if (data != NULL)
                XMEMCPY(data, &object->data.trust.sha1Hash, WC_SHA_DIGEST_SIZE);
            break;
        case CKA_CERT_MD5_HASH:
            if (*len < WC_MD5_DIGEST_SIZE)
                return BUFFER_E;
            *len = WC_MD5_DIGEST_SIZE;
            if (data != NULL)
                XMEMCPY(data, &object->data.trust.md5Hash, WC_MD5_DIGEST_SIZE);
            break;
        case CKA_TRUST_SERVER_AUTH:
            *len = sizeof(CK_ULONG);
            if (data != NULL)
                ret = GetULong(object->data.trust.serverAuth, data, len);
            break;
        case CKA_TRUST_CLIENT_AUTH:
            *len = sizeof(CK_ULONG);
            if (data != NULL)
                ret = GetULong(object->data.trust.clientAuth, data, len);
            break;
        case CKA_TRUST_CODE_SIGNING:
            *len = sizeof(CK_ULONG);
            if (data != NULL)
                ret = GetULong(object->data.trust.codeSigning, data, len);
            break;
        case CKA_TRUST_EMAIL_PROTECTION:
            *len = sizeof(CK_ULONG);
            if (data != NULL)
                ret = GetULong(object->data.trust.emailProtection, data, len);
            break;
        case CKA_TRUST_STEP_UP_APPROVED:
            *len = sizeof(CK_BBOOL);
            if (data != NULL)
                ret = GetBool(object->data.trust.stepUpApproved, data, len);
            break;
        case CKA_ISSUER:
            ret = GetData(object->issuer, object->issuerLen, data, len);
            break;
        case CKA_SERIAL_NUMBER:
            ret = GetData(object->serial, object->serialLen, data, len);
            break;
        case CKA_SUBJECT:
            ret = GetData(object->subject, object->subjectLen, data, len);
            break;
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }

    return ret;
}
#endif

#ifndef NO_RSA
/**
 * Get an RSA object's data as an attribute.
 *
 * @param  object  [in]      Object object.
 * @param  type    [in]      Attribute type.
 * @param  data    [in]      Attribute data buffer.
 * @param  len     [in,out]  On in, length of attribute data buffer in bytes.
 *                           On out, length of attribute data in bytes.
 * @return  BUFFER_E when buffer is too small for data.
 *          NOT_AVAILABLE_E when attribute type is not supported.
 *          0 on success.
 */
static int RsaObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                             byte* data, CK_ULONG* len)
{
    int ret = 0;
    int noPriv = (((object->opFlag & WP11_FLAG_SENSITIVE) != 0) ||
                 ((object->opFlag & WP11_FLAG_EXTRACTABLE) == 0));

    if (mp_iszero(&object->data.rsaKey->d))
        noPriv = 1;

    switch (type) {
        case CKA_MODULUS:
            ret = GetMPIData(&object->data.rsaKey->n, data, len);
            break;
        case CKA_PRIVATE_EXPONENT:
            if (noPriv)
                *len = CK_UNAVAILABLE_INFORMATION;
            else
                ret = GetMPIData(&object->data.rsaKey->d, data, len);
            break;
        case CKA_PRIME_1:
            if (noPriv)
                *len = CK_UNAVAILABLE_INFORMATION;
            else
                ret = GetMPIData(&object->data.rsaKey->p, data, len);
            break;
        case CKA_PRIME_2:
            if (noPriv)
                *len = CK_UNAVAILABLE_INFORMATION;
            else
                ret = GetMPIData(&object->data.rsaKey->q, data, len);
            break;
        case CKA_EXPONENT_1:
            if (noPriv)
                *len = CK_UNAVAILABLE_INFORMATION;
            else
                ret = GetMPIData(&object->data.rsaKey->dP, data, len);
            break;
        case CKA_EXPONENT_2:
            if (noPriv)
                *len = CK_UNAVAILABLE_INFORMATION;
            else
                ret = GetMPIData(&object->data.rsaKey->dQ, data, len);
            break;
        case CKA_COEFFICIENT:
            if (noPriv)
                *len = CK_UNAVAILABLE_INFORMATION;
            else
                ret = GetMPIData(&object->data.rsaKey->u, data, len);
            break;
        case CKA_PUBLIC_EXPONENT:
            ret = GetMPIData(&object->data.rsaKey->e, data, len);
            break;
        case CKA_MODULUS_BITS:
            ret = GetULong(mp_count_bits(&object->data.rsaKey->n), data, len);
            break;
        case CKA_WRAP_TEMPLATE:
        case CKA_UNWRAP_TEMPLATE:
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }

    return ret;
}
#endif

#ifdef HAVE_ECC
/**
 * Get the DER encoded OID of the elliptic curve.
 *
 * @param  key   [in]      Elliptic curve key.
 * @param  data  [in]      Buffer to hold DER encoded OID.
 * @param  len   [in,out]  On in, the length of the buffer in bytes.
 *                         On out, the length of the data in bytes.
 * @return  BUFFER_E when buffer is too small for data.
 *          BAD_FUNC_ARG when OID is not known.
 *          BAD_MUTEX_E when ecc_oid_cache_lock can't be locked.
 *          NOT_COMPILED_IN when curve is not compiled in.
 *          0 on success.
 */
static int GetEcParams(ecc_key* key, byte* data, CK_ULONG* len)
{
    int ret = 0;
    const byte* oid = NULL;
    word32 oidSz = 0;

    ret = wc_ecc_get_oid(key->dp->oidSum, &oid, &oidSz);
    if (ret > 0) {
        ret = 0;
        if (data == NULL)
            *len = (CK_ULONG)oidSz + 2;
        else if (*len < (CK_ULONG)oidSz + 2)
            ret = BUFFER_E;
        else {
            *len = (CK_ULONG)oidSz + 2;
            data[0] = ASN_OBJECT_ID;
            data[1] = (byte)(oidSz);
            XMEMCPY(data + 2, oid, oidSz);
        }
    }

    return ret;
}

/**
 * Get the DER encoded EC public point.
 *
 * @param  key   [in]      Elliptic curve key.
 * @param  data  [in]      Buffer to hold DER encoded point.
 * @param  len   [in,out]  On in, the length of the buffer in bytes.
 *                         On out, the length of the data in bytes.
 * @return  BUFFER_E when buffer is too small for data.
 *          0 on success.
 */
static int GetEcPoint(ecc_key* key, byte* data, CK_ULONG* len)
{
    int ret = 0;
    word32 dataLen = key->dp->size * 2 + 1;
    int longLen = dataLen >= ASN_LONG_LENGTH;
    int i;

    if (data == NULL)
        *len = dataLen + 2 + longLen;
    else if (*len < (CK_ULONG)dataLen)
        ret = BUFFER_E;
    else {
        *len = dataLen + 2 + longLen;
        i = 0;
        data[i++] = ASN_OCTET_STRING;
        if (longLen)
            data[i++] = ASN_LONG_LENGTH | 1;
        data[i++] = dataLen;
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(key, data + i, &dataLen);
        PRIVATE_KEY_LOCK();
    }

    return ret;
}

/**
 * Get an EC object's data as an attribute.
 *
 * @param  object  [in]      Object object.
 * @param  type    [in]      Attribute type.
 * @param  data    [in]      Attribute data buffer.
 * @param  len     [in,out]  On in, length of attribute data buffer in bytes.
 *                           On out, length of attribute data in bytes.
 * @return  BUFFER_E when buffer is too small for data.
 *          NOT_AVAILABLE_E when attribute type is not supported.
 *          0 on success.
 */
static int EcObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                            byte* data, CK_ULONG* len)
{
    int ret = 0;
    int noPriv = (((object->opFlag & WP11_FLAG_SENSITIVE) != 0) ||
                 ((object->opFlag & WP11_FLAG_EXTRACTABLE) == 0));
    int noPub = 0;

    if (object->data.ecKey->type == ECC_PUBLICKEY)
        noPriv = 1;
    else if (object->data.ecKey->type == ECC_PRIVATEKEY_ONLY)
        noPub = 1;

    switch (type) {
        case CKA_EC_PARAMS:
            ret = GetEcParams(object->data.ecKey, data, len);
            break;
        case CKA_VALUE:
            if (noPriv)
                *len = CK_UNAVAILABLE_INFORMATION;
            else
#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION <= 5)
                ret = GetMPIData(object->data.ecKey->k, data, len);
#else
                ret = GetMPIData(object->data.ecKey->k, data, len);
#endif
            break;
        case CKA_EC_POINT:
            if (noPub)
                *len = CK_UNAVAILABLE_INFORMATION;
            else
                ret = GetEcPoint(object->data.ecKey, data, len);
            break;
        case CKA_WRAP_TEMPLATE:
        case CKA_UNWRAP_TEMPLATE:
        case CKA_DERIVE_TEMPLATE:
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }

    return ret;
}
#endif

#ifndef NO_DH
/**
 * Get a DH object's data as an attribute.
 *
 * @param  object  [in]      Object object.
 * @param  type    [in]      Attribute type.
 * @param  data    [in]      Attribute data buffer.
 * @param  len     [in,out]  On in, length of attribute data buffer in bytes.
 *                           On out, length of attribute data in bytes.
 * @return  BUFFER_E when buffer is too small for data.
 *          NOT_AVAILABLE_E when attribute type is not supported.
 *          0 on success.
 */
static int DhObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                            byte* data, CK_ULONG* len)
{
    int ret = 0;
    int noPriv = (((object->opFlag & WP11_FLAG_SENSITIVE) != 0) ||
                 ((object->opFlag & WP11_FLAG_EXTRACTABLE) == 0));

    switch (type) {
        case CKA_PRIME:
            ret = GetMPIData(&object->data.dhKey->params.p, data, len);
            break;
        case CKA_BASE:
            ret = GetMPIData(&object->data.dhKey->params.g, data, len);
            break;
        case CKA_VALUE:
            /* Public key held in key when object class is CKO_PUBLIC_KEY and
             * private key when object class is CKO_PRIVATE_KEY.
             */
            if (object->objClass != CKO_PRIVATE_KEY || !noPriv) {
                ret = GetData(object->data.dhKey->key, object->data.dhKey->len,
                                                                     data, len);
            }
            else
                *len = CK_UNAVAILABLE_INFORMATION;
            break;
        case CKA_WRAP_TEMPLATE:
        case CKA_UNWRAP_TEMPLATE:
        case CKA_DERIVE_TEMPLATE:
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }

    return ret;
}
#endif /* !NO_DH */

int WP11_Generic_SerializeKey(WP11_Object* object, byte* output, word32* poutsz)
{
    if (object == NULL || poutsz == NULL)
        return PARAM_E;

    if (object->type != CKK_AES && object->type != CKK_GENERIC_SECRET)
        return OBJ_TYPE_E;

    if (object->objClass != CKO_SECRET_KEY)
        return OBJ_TYPE_E;

    if (output != NULL) {
        if (*poutsz < object->data.symmKey->len)
            return PARAM_E;
        XMEMCPY(output, object->data.symmKey->data, object->data.symmKey->len);
        *poutsz = object->data.symmKey->len;
    }
    else {
        *poutsz = object->data.symmKey->len;
    }

    return 0;
}

/**
 * Get a secret object's data as an attribute.
 *
 * @param  object  [in]      Object object.
 * @param  type    [in]      Attribute type.
 * @param  data    [in]      Attribute data buffer.
 * @param  len     [in,out]  On in, length of attribute data buffer in bytes.
 *                           On out, length of attribute data in bytes.
 * @return  BUFFER_E when buffer is too small for data.
 *          NOT_AVAILABLE_E when attribute type is not supported.
 *          0 on success.
 */
static int SecretObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                                byte* data, CK_ULONG* len)
{
    int ret = 0;
    int noPriv = ((object->opFlag & WP11_FLAG_SENSITIVE) != 0 ||
                 (object->opFlag & WP11_FLAG_EXTRACTABLE) == 0);

    switch (type) {
        case CKA_VALUE:
            if (noPriv) {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = CKR_ATTRIBUTE_SENSITIVE;
            }
            else
                ret = GetData(object->data.symmKey->data,
                                           object->data.symmKey->len, data, len);
            break;
        case CKA_VALUE_LEN:
            ret = GetULong(object->data.symmKey->len, data, len);
            break;
        case CKA_WRAP_TEMPLATE:
        case CKA_UNWRAP_TEMPLATE:
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }

    return ret;
}

#ifndef NO_SHA
static int GetSha1CheckValue(const byte* dataIn, int inLen, byte* dataOut,
    CK_ULONG* outLen)
{
    int ret;
    byte hash[WC_SHA_DIGEST_SIZE];

    if (dataOut == NULL) {
        if (outLen != NULL) {
            *outLen = PKCS11_CHECK_VALUE_SIZE;
            return CKR_OK;
        }
        return BUFFER_E;
    }

    if (*outLen < PKCS11_CHECK_VALUE_SIZE) {
        *outLen = PKCS11_CHECK_VALUE_SIZE;
        return BUFFER_E;
    }

    ret = wc_Hash(WC_HASH_TYPE_SHA, dataIn, inLen, hash, WC_SHA_DIGEST_SIZE);
    if (ret == 0) {
        XMEMCPY(dataOut, hash, PKCS11_CHECK_VALUE_SIZE);
        *outLen = PKCS11_CHECK_VALUE_SIZE;
    }

    return CKR_OK;
}
#endif

#ifdef HAVE_AESECB
static int GetEcbCheckValue(WP11_Object* secret, byte* dataOut,
    CK_ULONG* outLen)
{
    int ret;
    byte* hash;
    byte* input;
    word32 inLen;
    WP11_Data* key = &secret->data.symmKey;

    if (dataOut == NULL) {
        if (outLen != NULL) {
            *outLen = PKCS11_CHECK_VALUE_SIZE;
            return CKR_OK;
        }
        return BUFFER_E;
    }

    if (*outLen < PKCS11_CHECK_VALUE_SIZE) {
        *outLen = PKCS11_CHECK_VALUE_SIZE;
        return BUFFER_E;
    }

    hash = XMALLOC(key->len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!hash)
        return MEMORY_E;
    input = XMALLOC(key->len, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    inLen = key->len;
    XMEMSET(input, 0, inLen);

    ret = WP11_AesEcb_Encrypt(input, inLen, hash, &inLen, secret,
        secret->session);

    if (ret == 0) {
        XMEMCPY(dataOut, hash, PKCS11_CHECK_VALUE_SIZE);
        *outLen = PKCS11_CHECK_VALUE_SIZE;
    }

    XFREE(hash, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return CKR_OK;
}
#endif

/**
 * Get the data for an attribute from the object.
 *
 * @param  object  [in]      Object object.
 * @param  type    [in]      Attribute type.
 * @param  data    [in]      Attribute data buffer.
 * @param  len     [in,out]  On in, length of data buffer in bytes.
 *                           On out, length of data in bytes.
 * @return  BUFFER_E when buffer is too small for data.
 *          NOT_AVAILABLE_E when attribute type is not supported.
 *          0 on success.
 */
int WP11_Object_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type, byte* data,
                        CK_ULONG* len)
{
    int ret = NOT_AVAILABLE_E;

    if (object->onToken)
        WP11_Lock_LockRO(object->lock);

    switch (type) {
        case CKA_CLASS:
            ret = GetULong(object->objClass, data, len);
            break;
        case CKA_LABEL:
            ret = GetData(object->label, object->labelLen, data, len);
            break;
        case CKA_TOKEN:
            ret = GetBool(object->onToken, data, len);
            break;
        case CKA_PRIVATE:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_PRIVATE, data, len);
            break;
        case CKA_SENSITIVE:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_SENSITIVE, data,
                                                                           len);
            break;
        case CKA_EXTRACTABLE:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_EXTRACTABLE, data,
                                                                           len);
            break;
        case CKA_MODIFIABLE:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_MODIFIABLE, data,
                                                                           len);
            break;
        case CKA_ALWAYS_SENSITIVE:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_ALWAYS_SENSITIVE,
                                                                     data, len);
            break;
        case CKA_NEVER_EXTRACTABLE:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_NEVER_EXTRACTABLE,
                                                                     data, len);
            break;
        case CKA_ALWAYS_AUTHENTICATE:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_ALWAYS_AUTHENTICATE,
                                                                     data, len);
            break;
        case CKA_WRAP_WITH_TRUSTED:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_WRAP_WITH_TRUSTED,
                                                                     data, len);
            break;
        case CKA_TRUSTED:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_TRUSTED, data, len);
            break;
        case CKA_COPYABLE:
            ret = GetBool(CK_FALSE, data, len);
            break;
        case CKA_DESTROYABLE:
            ret = GetBool(CK_TRUE, data, len);
            break;
        case CKA_APPLICATION:
            /* Not available */
            break;
        case CKA_ID:
            ret = GetData(object->keyId, object->keyIdLen, data, len);
            break;
        case CKA_KEY_TYPE:
            ret = GetULong(object->type, data, len);
            break;
        case CKA_START_DATE:
            if (object->startDate[0] == '\0') {
                *len = 0;
                ret = CKR_OK;
            }
            else
                ret = GetData((byte*)object->startDate,
                                          sizeof(object->startDate), data, len);
            break;
        case CKA_END_DATE:
            if (object->endDate[0] == '\0') {
                *len = 0;
                ret = CKR_OK;
            }
            else
                ret = GetData((byte*)object->endDate, sizeof(object->endDate),
                                                                     data, len);
            break;
        case CKA_LOCAL:
            ret = GetBool(object->local, data, len);
            break;
        case CKA_KEY_GEN_MECHANISM:
            ret = GetULong(object->keyGenMech, data, len);
            break;
        case CKA_ALLOWED_MECHANISMS:
            /* Not available */
            break;

        case CKA_ENCRYPT:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_ENCRYPT, data, len);
            break;
        case CKA_DECRYPT:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_DECRYPT, data, len);
            break;
        case CKA_VERIFY:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_VERIFY, data, len);
            break;
        case CKA_VERIFY_RECOVER:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_VERIFY_RECOVER, data,
                                len);
            break;
        case CKA_SIGN:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_SIGN, data, len);
            break;
        case CKA_SIGN_RECOVER:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_SIGN_RECOVER, data,
                                len);
            break;
        case CKA_WRAP:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_WRAP, data, len);
            break;
        case CKA_UNWRAP:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_UNWRAP, data, len);
            break;
        case CKA_DERIVE:
            ret = GetOpFlagBool(object->opFlag, WP11_FLAG_DERIVE, data, len);
            break;
        case CKA_CERTIFICATE_TYPE:
            if (object->objClass == CKO_CERTIFICATE)
                ret = GetULong(object->data.cert.type, data, len);
            else
                ret = CKR_ATTRIBUTE_TYPE_INVALID;
            break;
        case CKA_CHECK_VALUE:
            if (object->objClass == CKO_CERTIFICATE)
#ifndef NO_SHA
                ret = GetSha1CheckValue(object->data.cert.data,
                    object->data.cert.len, data, len);
#else
                ret = NOT_AVAILABLE_E;
#endif
            else if (object->objClass == CKO_SECRET_KEY)
#ifdef HAVE_AESECB
                ret = GetEcbCheckValue(object, data, len);
#else
                ret = NOT_AVAILABLE_E;
#endif
            else
                ret = NOT_AVAILABLE_E;
            break;

        default:
            {
                if (object->objClass == CKO_CERTIFICATE) {
                    ret = GetCertAttr(object, type, data, len);
                    break;
                }
                #if defined(WOLFPKCS11_NSS)
                else if (object->objClass == CKO_NSS_TRUST) {
                    ret = GetTrustAttr(object, type, data, len);
                    break;
                }
                #endif
                else {
                    switch (object->type) {
        #ifndef NO_RSA
                        case CKK_RSA:
                            ret = RsaObject_GetAttr(object, type, data, len);
                            break;
        #endif
        #ifdef HAVE_ECC
                        case CKK_EC:
                            ret = EcObject_GetAttr(object, type, data, len);
                            break;
        #endif
        #ifndef NO_DH
                        case CKK_DH:
                            ret = DhObject_GetAttr(object, type, data, len);
                            break;
        #endif
        #ifndef NO_AES
                        case CKK_AES:
        #endif
        #ifdef WOLFPKCS11_HKDF
                        case CKK_HKDF:
        #endif
                        case CKK_GENERIC_SECRET:
                            ret = SecretObject_GetAttr(object, type, data, len);
                            break;
                    }
                    break;
                }
            }
    }

    if (object->onToken)
        WP11_Lock_UnlockRO(object->lock);

    return ret;
}


/**
 * Set the operation flag against the object.
 *
 * @param  object  [in]  Object object.
 * @param  flag    [in]  Operation flag value.
 * @param  set     [in]  Whether the flag is to be set (or cleared).
 */
static void WP11_Object_SetOpFlag(WP11_Object* object, word32 flag, int set)
{
    if (set)
        object->opFlag |= flag;
    else
        object->opFlag &= ~flag;
}

/**
 * Set the key identifier against the object.
 *
 * @param  object    [in]  Object object.
 * @param  keyId     [in]  Key identifier data.
 * @param  keyIdLen  [in]  Length of key identifier in bytes.
 * @return  MEMORY_E when dynamic memory allocation fails.
 *          0 on success.
 */
static int WP11_Object_SetKeyId(WP11_Object* object, unsigned char* keyId,
                                int keyIdLen)
{
    int ret = 0;

    if (object->keyId != NULL)
        XFREE(object->keyId, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    object->keyId = (unsigned char*)XMALLOC(keyIdLen, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (object->keyId == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        XMEMCPY(object->keyId, keyId, keyIdLen);
        object->keyIdLen = keyIdLen;
    }

    return ret;
}

/**
 * Set the attribute against the object.
 *
 * @param  attribute    [out] Object attribute.
 * @param  attributeLen [out] Length of attribute in bytes.
 * @param  data         [in]  Data to be set.
 * @param  dataLen      [in]  Length of data in bytes.
 * @return  MEMORY_E when dynamic memory allocation fails.
 *          0 on success.
 */
static int WP11_Object_SetData(byte** attribute, int* attributeLen, byte* data,
                                int dataLen)
{
    int ret = 0;

    if (*attribute != NULL)
        XFREE(*attribute, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    *attribute = (byte*)XMALLOC(dataLen, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (*attribute == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        XMEMCPY(*attribute, data, dataLen);
        *attributeLen = dataLen;
    }

    return ret;
}

/**
 * Set the start date.
 *
 * @param  object     [in]  Object object.
 * @param  startDate  [in]  Start data as a string.
 * @param  len        [in]  Length of string.
 * @return  BUFFER_E when string is too small.
 *          0 on success.
 */
static int WP11_Object_SetStartDate(WP11_Object* object, char* startDate,
                                    int len)
{
    int ret = 0;

    if (len != sizeof(object->startDate))
        ret = BUFFER_E;
    if (ret == 0)
        XMEMCPY(object->startDate, startDate, sizeof(object->startDate));

    return ret;
}

/**
 * Set the end date.
 *
 * @param  object   [in]  Object object.
 * @param  endData  [in]  End data as a string.
 * @param  len      [in]  Length of string.
 * @return  BUFFER_E when string is too small.
 *          0 on success.
 */
static int WP11_Object_SetEndDate(WP11_Object* object, char* endDate, int len)
{
    int ret = 0;

    if (len != sizeof(object->endDate))
        ret = BUFFER_E;
    if (ret == 0)
        XMEMCPY(object->endDate, endDate, sizeof(object->endDate));

    return ret;
}


/**
 * Set an attribute against the object.
 *
 * @param  object  [in]  Object object.
 * @param  type    [in]  Attribute type.
 * @param  data    [in]  Attribute data to set.
 * @param  len     [in]  Length of attribute data in bytes.
 * @return  BUFFER_E when data is too small.
 *          BAD_FUNC_ARG when type is not supported with object.
 *          0 on success.
 */
int WP11_Object_SetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type, byte* data,
                        CK_ULONG len)
{
    int ret = 0;

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    switch (type) {
        case CKA_CLASS:
            object->objClass = *(CK_ULONG*)data;
            break;
        case CKA_DECRYPT:
            WP11_Object_SetOpFlag(object, WP11_FLAG_DECRYPT, *(CK_BBOOL*)data);
            break;
        case CKA_ENCRYPT:
            WP11_Object_SetOpFlag(object, WP11_FLAG_ENCRYPT, *(CK_BBOOL*)data);
            break;
        case CKA_SIGN:
            WP11_Object_SetOpFlag(object, WP11_FLAG_SIGN, *(CK_BBOOL*)data);
            break;
        case CKA_VERIFY:
            WP11_Object_SetOpFlag(object, WP11_FLAG_VERIFY, *(CK_BBOOL*)data);
            break;
        case CKA_SIGN_RECOVER:
            WP11_Object_SetOpFlag(object, WP11_FLAG_SIGN_RECOVER,
                                  *(CK_BBOOL*)data);
            break;
        case CKA_VERIFY_RECOVER:
            WP11_Object_SetOpFlag(object, WP11_FLAG_VERIFY_RECOVER,
                                  *(CK_BBOOL*)data);
            break;
        case CKA_WRAP:
            WP11_Object_SetOpFlag(object, WP11_FLAG_WRAP, *(CK_BBOOL*)data);
            break;
        case CKA_UNWRAP:
            WP11_Object_SetOpFlag(object, WP11_FLAG_UNWRAP, *(CK_BBOOL*)data);
            break;
        case CKA_DERIVE:
            WP11_Object_SetOpFlag(object, WP11_FLAG_DERIVE, *(CK_BBOOL*)data);
            break;
        case CKA_ID:
            ret = WP11_Object_SetKeyId(object, data, (int)len);
            break;
        case CKA_LABEL:
            ret = WP11_Object_SetData(&object->label, &object->labelLen, data,
                                       (int)len);
            break;
        case CKA_CERTIFICATE_CATEGORY:
            object->category = *(word32*)data;
            break;
        case CKA_PRIVATE:
            WP11_Object_SetOpFlag(object, WP11_FLAG_PRIVATE, *(CK_BBOOL*)data);
            break;
        case CKA_SENSITIVE:
            WP11_Object_SetOpFlag(object, WP11_FLAG_SENSITIVE,
                                  *(CK_BBOOL*)data);
            break;
        case CKA_EXTRACTABLE:
            WP11_Object_SetOpFlag(object, WP11_FLAG_EXTRACTABLE,
                                                              *(CK_BBOOL*)data);
            break;
        case CKA_MODIFIABLE:
            WP11_Object_SetOpFlag(object, WP11_FLAG_MODIFIABLE,
                                  *(CK_BBOOL*)data);
            break;
        case CKA_ALWAYS_SENSITIVE:
            WP11_Object_SetOpFlag(object, WP11_FLAG_ALWAYS_SENSITIVE,
                                  *(CK_BBOOL*)data);
            break;
        case CKA_NEVER_EXTRACTABLE:
            WP11_Object_SetOpFlag(object, WP11_FLAG_NEVER_EXTRACTABLE,
                                  *(CK_BBOOL*)data);
            break;
        case CKA_ALWAYS_AUTHENTICATE:
            WP11_Object_SetOpFlag(object, WP11_FLAG_ALWAYS_AUTHENTICATE,
                                  *(CK_BBOOL*)data);
            break;
        case CKA_WRAP_WITH_TRUSTED:
            WP11_Object_SetOpFlag(object, WP11_FLAG_WRAP_WITH_TRUSTED,
                                  *(CK_BBOOL*)data);
            break;
        case CKA_TRUSTED:
            WP11_Object_SetOpFlag(object, WP11_FLAG_TRUSTED, *(CK_BBOOL*)data);
            break;
        case CKA_START_DATE:
            ret = WP11_Object_SetStartDate(object, (char*)data, (int)len);
            break;
        case CKA_END_DATE:
            ret = WP11_Object_SetEndDate(object, (char*)data, (int)len);
            break;
        case CKA_MODULUS_BITS:
        case CKA_MODULUS:
        case CKA_PRIVATE_EXPONENT:
        case CKA_PRIME_1:
        case CKA_PRIME_2:
        case CKA_EXPONENT_1:
        case CKA_EXPONENT_2:
        case CKA_COEFFICIENT:
        case CKA_PUBLIC_EXPONENT:
#ifndef NO_RSA
            if (object->type != CKK_RSA)
#endif
                ret = BAD_FUNC_ARG;
            break;
        case CKA_EC_PARAMS:
        case CKA_EC_POINT:
#ifdef HAVE_ECC
            if (object->type != CKK_EC)
#endif
                ret = BAD_FUNC_ARG;
            break;
        case CKA_PRIME:
        case CKA_BASE:
#ifndef NO_DH
            if (object->type != CKK_DH)
#endif
                ret = BAD_FUNC_ARG;
            break;
        case CKA_VALUE_LEN:
            switch (object->type) {
#ifndef NO_DH
                case CKK_DH:
#endif
#ifndef NO_AES
                case CKK_AES:
#endif
#ifdef WOLFPKCS11_HKDF
                case CKK_HKDF:
#endif
                case CKK_GENERIC_SECRET:
                    break;
                default:
                    ret = BAD_FUNC_ARG;
                    break;
            }
            break;
        case CKA_VALUE:
            if (object->objClass == CKO_CERTIFICATE) {
                break; /* Handled in WP11_Object_SetCert */
            }
            switch (object->type) {
#ifdef HAVE_ECC
                case CKK_EC:
#endif
#ifndef NO_DH
                case CKK_DH:
#endif
#ifndef NO_AES
                case CKK_AES:
#endif
#ifdef WOLFPKCS11_HKDF
                case CKK_HKDF:
#endif
                case CKK_GENERIC_SECRET:
                   break;
                default:
                    ret = BAD_FUNC_ARG;
                    break;
            }
            break;
#ifdef WOLFPKCS11_NSS
        case CKA_CERT_SHA1_HASH:
        case CKA_CERT_MD5_HASH:
        case CKA_TRUST_SERVER_AUTH:
        case CKA_TRUST_CLIENT_AUTH:
        case CKA_TRUST_EMAIL_PROTECTION:
        case CKA_TRUST_CODE_SIGNING:
        case CKA_TRUST_STEP_UP_APPROVED:
            /* Handled in WP11_Object_SetTrust */
#endif
        case CKA_CERTIFICATE_TYPE:
            /* Handled in WP11_Object_SetCert */
        case CKA_KEY_TYPE:
            /* Handled in layer above */
        case CKA_TOKEN:
            /* Handled in layer above */
            break;
        case CKA_ISSUER:
            ret = WP11_Object_SetData(&object->issuer, &object->issuerLen,
                                      data, (int)len);
            break;
        case CKA_SERIAL_NUMBER:
            ret = WP11_Object_SetData(&object->serial, &object->serialLen,
                                      data, (int)len);
            break;
        case CKA_SUBJECT:
            ret = WP11_Object_SetData(&object->subject, &object->subjectLen,
                                      data, (int)len);
            break;

        case CKA_AC_ISSUER:
        case CKA_ATTR_TYPES:
        case CKA_JAVA_MIDP_SECURITY_DOMAIN:
        case CKA_URL:
        case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
        case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
        case CKA_NAME_HASH_ALGORITHM:
        case CKA_CHECK_VALUE:
            /* Fields are allowed, but not saved yet */
            if (object->objClass != CKO_CERTIFICATE) {
                ret = BAD_FUNC_ARG;
            }
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);

    return ret;
}

/**
 * Check whether the attribute matches in the object.
 *
 * @param  object  [in]  Object object.
 * @param  type    [in]  Attribute type.
 * @param  data    [in]  Attribute data.
 * @param  len     [in]  Length of attribute data.
 * @return  1 when attribute matches.
 *          0 when attribute doesn't match.
 */
int WP11_Object_MatchAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                          byte* data, CK_ULONG len)
{
    int ret = 0;
    byte attrData[8];
    byte* ptr;
    CK_ULONG attrLen = len;

    /* Get the attribute data into the stack buffer if big enough. */
    if (len <= (int)sizeof(attrData)) {
        if (WP11_Object_GetAttr(object, type, attrData, &attrLen) == 0)
            ret = (attrLen == len) && WP11_ConstantCompare(attrData, data, (int)len);
    }
    else {
        /* Allocate a buffer to hold data and then compare. */
        ptr = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (ptr != NULL) {
            if (WP11_Object_GetAttr(object, type, ptr, &attrLen) == 0)
                ret = (attrLen == len) && WP11_ConstantCompare(ptr, data, (int)len);
            XFREE(ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    return ret;
}

#ifdef WOLFPKCS11_TPM
#if !defined(NO_RSA) || defined(HAVE_ECC)

static int WP11_Object_WrapTpmKey(WP11_Object* object)
{
    int ret = 0;

    if (object == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (object->type) {
    #ifndef NO_RSA
        case CKK_RSA:
        {
            RsaKey* key = object->data.rsaKey;
            if (key->type == RSA_PRIVATE) {
            #if defined(LIBWOLFTPM_VERSION_HEX) && LIBWOLFTPM_VERSION_HEX > 0x03009000
                ret = wolfTPM2_CreateRsaKeyBlob(&object->slot->tpmDev,
                    &object->slot->tpmSrk, key, object->tpmKey);
            #else
                long    exponent;
                byte    e[sizeof(exponent)];
                byte    n[RSA_MAX_SIZE / 8];
                byte    d[RSA_MAX_SIZE / 8];
                byte    p[RSA_MAX_SIZE / 8];
                byte    q[RSA_MAX_SIZE / 8];
                word32  eSz = sizeof(e);
                word32  nSz = sizeof(n);
                word32  dSz = sizeof(d);
                word32  pSz = sizeof(p);
                word32  qSz = sizeof(q);

                XMEMSET(e, 0, sizeof(e));
                XMEMSET(n, 0, sizeof(n));
                XMEMSET(d, 0, sizeof(d));
                XMEMSET(p, 0, sizeof(p));
                XMEMSET(q, 0, sizeof(q));

                /* export the raw private and public RSA as unsigned binary */
                PRIVATE_KEY_UNLOCK();
                ret = wc_RsaExportKey(key, e, &eSz, n, &nSz,
                    d, &dSz, p, &pSz, q, &qSz);
                PRIVATE_KEY_LOCK();
                if (ret == 0) {
                    exponent = GetRsaExponentValue(e, eSz);

                    /* Create wrapped RSA private key */
                    ret = wolfTPM2_ImportRsaPrivateKey(&object->slot->tpmDev,
                        &object->slot->tpmSrk, object->tpmKey, n, nSz,
                        (word32)exponent, q, qSz, TPM_ALG_NULL, TPM_ALG_NULL);
                }
                (void)p;
            #endif
                if (ret == 0) {
                    /* set flag indicating this is TPM based key */
                    object->opFlag |= WP11_FLAG_TPM;
                }
            }
            break;
        }
    #endif
    #ifdef HAVE_ECC
        case CKK_EC:
        {
            ecc_key* key = object->data.ecKey;
            if (key->type == ECC_PRIVATEKEY_ONLY || key->type == ECC_PRIVATEKEY) {
            #if defined(LIBWOLFTPM_VERSION_HEX) && LIBWOLFTPM_VERSION_HEX > 0x03009000
                ret = wolfTPM2_CreateEccKeyBlob(&object->slot->tpmDev,
                    &object->slot->tpmSrk, key, object->tpmKey);
            #else
                int     curve_id = 0;
                byte    qx[MAX_ECC_BITS / 8];
                byte    qy[MAX_ECC_BITS / 8];
                byte    d[MAX_ECC_BITS / 8];
                word32  qxSz = sizeof(qx);
                word32  qySz = sizeof(qy);
                word32  dSz = sizeof(d);

                XMEMSET(qx, 0, sizeof(qx));
                XMEMSET(qy, 0, sizeof(qy));
                XMEMSET(d, 0, sizeof(d));

                if (key->dp)
                    curve_id = key->dp->id;

                ret = TPM2_GetTpmCurve(curve_id);
                if (ret < 0)
                    return ret;
                curve_id = ret;
                ret = 0;

                if (key->type == ECC_PRIVATEKEY_ONLY) {
                    /* compute public point without modifying incoming wolf key */
                    int keySz = wc_ecc_size(key);
                    ecc_point* point = wc_ecc_new_point();
                    if (point == NULL) {
                        ret = MEMORY_E;
                    }
                    if (ret == 0) {
                    #ifdef ECC_TIMING_RESISTANT
                        ret = wc_ecc_make_pub_ex(key, point, key->rng);
                    #else
                        ret = wc_ecc_make_pub(key, point);
                    #endif
                        if (ret == 0)
                            ret = wc_export_int(point->x, qx, &qxSz, keySz,
                                WC_TYPE_UNSIGNED_BIN);
                        if (ret == 0)
                            ret = wc_export_int(point->y, qy, &qySz, keySz,
                                WC_TYPE_UNSIGNED_BIN);
                        if (ret == 0) {
                            PRIVATE_KEY_UNLOCK();
                            ret = wc_ecc_export_private_only(key, d, &dSz);
                            PRIVATE_KEY_LOCK();
                        }
                        wc_ecc_del_point(point);
                    }
                }
                else {
                    /* export the raw private/public ECC portions */
                    PRIVATE_KEY_UNLOCK();
                    ret = wc_ecc_export_private_raw(key,
                        qx, &qxSz,
                        qy, &qySz,
                        d, &dSz);
                    PRIVATE_KEY_LOCK();
                }

                if (ret == 0) {
                    /* Create wrapped ECC private key */
                    ret = wolfTPM2_ImportEccPrivateKey(&object->slot->tpmDev,
                        &object->slot->tpmSrk, object->tpmKey, curve_id,
                        qx, qxSz, qy, qySz, d, dSz);
                }
        #endif
                if (ret == 0) {
                    /* set flag indicating this is TPM based key */
                    object->opFlag |= WP11_FLAG_TPM;
                }
            }
            break;
        }
    #endif
        default:
            /* not supported on TPM, don't load and return success to use software key */
            ret = 0;
            break;
    }
    return ret;
}

static int WP11_Object_LoadTpmKey(WP11_Object* object)
{
    int ret = 0;

    if (object == NULL) {
        return BAD_FUNC_ARG;
    }

    if (object->opFlag & WP11_FLAG_TPM) {
        ret = wolfTPM2_LoadKey(&object->slot->tpmDev, object->tpmKey,
            &object->slot->tpmCtx.storageKey->handle);
        if (ret == 0) {
            if (object->tpmKey->pub.publicArea.type == TPM_ALG_RSA) {
        #ifndef NO_RSA
                /* tell crypto callback which RsaKey to use */
                object->slot->tpmCtx.rsaKey = (WOLFTPM2_KEY*)object->tpmKey;
        #endif
            }
            else if (object->tpmKey->pub.publicArea.type == TPM_ALG_ECC) {
        #ifdef HAVE_ECC
                /* tell crypto callback which EccKey to use */
            #if defined(LIBWOLFTPM_VERSION_HEX) && LIBWOLFTPM_VERSION_HEX > 0x03009000
                object->slot->tpmCtx.ecdsaKey = object->tpmKey;
            #else
                object->slot->tpmCtx.eccKey = (WOLFTPM2_KEY*)object->tpmKey;
            #endif
        #endif
            }
        }
    }

    return ret;
}

#endif /* !NO_RSA || HAVE_ECC */
#endif /* WOLFPKCS11_TPM */

#ifndef NO_RSA

/**
 * Internalize an RSA private key from DER form.
 *
 * @param  data   [in]  Buffer to parse
 * @param  dataLen [in] size of buffer
 * @param  privKey  [in/out]  Private key object.
 * @return  -ve when key parse fails.
 *          0 on success.
 */
int WP11_Rsa_ParsePrivKey(byte* data, word32 dataLen, WP11_Object* privKey)
{
    int ret = 0;
    word32 idx = 0;

    ret = wc_InitRsaKey_ex(privKey->data.rsaKey, NULL, privKey->slot->devId);
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(data, &idx, privKey->data.rsaKey, dataLen);
    }
    return ret;
}

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_CERT_GEN)
/**
 * Transfer public parts to RSA public key.
 *
 * @param  privKey   [in] holds modulus and pub exponent
 * @param  pubKey [in/out] to be populated
 * @param  workbuf  [in/out] used to serialize/parse.
 * @param  worksz  [in] size of workbuf.
 * @return  -ve when key parse fails.
 *          0 on success.
 */
int WP11_Rsa_PrivKey2PubKey(WP11_Object* privKey, WP11_Object* pubKey,
    byte* workbuf, word32 worksz)
{
    int ret;
    word32 idx = 0;

    ret = wc_InitRsaKey_ex(pubKey->data.rsaKey, NULL, pubKey->slot->devId);
    if (ret == 0) {
        ret = wc_RsaKeyToPublicDer(privKey->data.rsaKey, workbuf, worksz);
        if (ret >= 0) {
            worksz = (word32)ret;
            ret = 0;
        }
    }
    if (ret == 0) {
        ret = wc_RsaPublicKeyDecode(workbuf, &idx, pubKey->data.rsaKey, worksz);
    }

    return ret;
}
#endif

#ifdef WOLFSSL_KEY_GEN
/**
 * Generate an RSA key pair.
 *
 * @param  pub   [in]  Public key object.
 * @param  priv  [in]  Private key object.
 * @param  slot  [in]  Slot operation is performed on.
 * @return  -ve when key generation fails.
 *          0 on success.
 */
int WP11_Rsa_GenerateKeyPair(WP11_Object* pub, WP11_Object* priv,
                             WP11_Slot* slot)
{
    int ret = 0;
    unsigned char eData[sizeof(long)];
    int eSz;
    long e = 0;
    WC_RNG rng;

    /* Use public exponent if public key has one set. */
    if (!mp_iszero(&pub->data.rsaKey->e)) {
        XMEMSET(eData, 0, sizeof(eData));
        /* Public exponent must be size of a long for API. */
        eSz = mp_unsigned_bin_size(&pub->data.rsaKey->e);
        if (eSz > (int)sizeof(eData))
            ret = BAD_FUNC_ARG;
        if (ret == 0)
            ret = mp_to_unsigned_bin_len(&pub->data.rsaKey->e, eData, eSz);
        if (ret == 0) {
            e = GetRsaExponentValue(eData, eSz);
        }
    }
    else {
        e = WC_RSA_EXPONENT;
        ret = mp_set_int(&pub->data.rsaKey->e, e);
    }

    if (ret == 0) {
        ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
        if (ret == 0) {
            ret = wc_InitRsaKey_ex(priv->data.rsaKey, NULL, priv->slot->devId);
            if (ret == 0) {
            #ifdef WOLFPKCS11_TPM
                priv->slot->tpmCtx.rsaKeyGen = priv->tpmKey;
                priv->slot->tpmCtx.rsaKey = (WOLFTPM2_KEY*)priv->tpmKey;
            #endif

                /* Generate into the private key. */
                ret = wc_MakeRsaKey(priv->data.rsaKey, pub->size, e, &rng);
            #ifdef WOLFPKCS11_TPM
                if (ret == 0) {
                    /* set flag indicating this is TPM based key */
                    priv->opFlag |= WP11_FLAG_TPM;

                    /* unload handle and reload when used */
                    wolfTPM2_UnloadHandle(&priv->slot->tpmDev, &priv->tpmKey->handle);
                }
            #endif
                if (ret != 0) {
                    wc_FreeRsaKey(priv->data.rsaKey);
                }
            }
            Rng_Free(&rng);
        }
    }
    if (ret == 0) {
        /* Copy in the rest of public key from private key. */
        ret = mp_copy(&priv->data.rsaKey->n, &pub->data.rsaKey->n);
    }
    if (ret == 0) {
        priv->local = 1;
        pub->local = 1;
        priv->keyGenMech = CKM_RSA_PKCS_KEY_PAIR_GEN;
        pub->keyGenMech = CKM_RSA_PKCS_KEY_PAIR_GEN;
    }

    return ret;
}
#endif /* WOLFSSL_KEY_GEN */

/**
 * Return the length of the RSA key in bytes.
 *
 * @param  key  [in]  Key object.
 * @return RSA key length in bytes.
 */
word32 WP11_Rsa_KeyLen(WP11_Object* key)
{
    return mp_unsigned_bin_size(&key->data.rsaKey->n);
}

/**
 * Encrypt data with public key.
 * Raw encryption - exponentiate with public exponent.
 *
 * @param  in      [in]      Data to encrypt.
 * @param  inLen   [in]      Length of data to encrypt.
 * @param  out     [in]      Buffer to hold encrypted data.
 * @param  outLen  [in,out]  On in, length of buffer.
 *                           On out, length data in buffer.
 * @param  pub     [in]      Public key object.
 * @param  slot    [in]      Slot operation is performed on.
 * @return  BUFFER_E when outLen is too small for decrypted data.
 *          Other -ve when encryption fails.
 *          0 on success.
 */
int WP11_Rsa_PublicEncrypt(unsigned char* in, word32 inLen, unsigned char* out,
                           word32* outLen, WP11_Object* pub, WP11_Slot* slot)
{
    int ret;
    WC_RNG rng;

    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
    if (ret == 0) {
        ret = wc_RsaFunction(in, inLen, out, outLen, RSA_PUBLIC_ENCRYPT,
                                                       pub->data.rsaKey, &rng);
        Rng_Free(&rng);
    }
    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);

    return ret;
}

/**
 * Decrypt data with private key.
 * Raw encryption - exponentiate with private exponent.
 *
 * @param  in      [in]      Data to decrypt.
 * @param  inLen   [in]      Length of data to decrypt.
 * @param  out     [in]      Buffer to hold decrypted data.
 * @param  outLen  [in,out]  On in, length of buffer.
 *                           On out, length data in buffer.
 * @param  priv    [in]      Private key object.
 * @param  slot    [in]      Slot operation is performed on.
 * @return  -ve when decryption fails.
 *          0 on success.
 */
int WP11_Rsa_PrivateDecrypt(unsigned char* in, word32 inLen, unsigned char* out,
                            word32* outLen, WP11_Object* priv, WP11_Slot* slot)
{
    int ret;
    WC_RNG rng;

    if (priv->onToken)
        WP11_Lock_LockRO(priv->lock);
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
    if (ret == 0) {
    #ifdef WOLFPKCS11_TPM
        ret = WP11_Object_LoadTpmKey(priv);
        if (ret == 0)
    #endif
        {
            ret = wc_RsaFunction(in, inLen, out, outLen, RSA_PRIVATE_DECRYPT,
                                                      priv->data.rsaKey, &rng);
        #ifdef WOLFPKCS11_TPM
            wolfTPM2_UnloadHandle(&slot->tpmDev, &priv->tpmKey->handle);
        #endif
        }
        Rng_Free(&rng);
    }
    if (priv->onToken)
        WP11_Lock_UnlockRO(priv->lock);

    return ret;
}

/**
 * PKCS#1.5 encrypt data with public key.
 *
 * @param  in      [in]      Data to encrypt.
 * @param  inLen   [in]      Length of data to encrypt.
 * @param  out     [in]      Buffer to hold encrypted data.
 * @param  outLen  [in,out]  On in, length of buffer.
 *                           On out, length data in buffer.
 * @param  pub     [in]      Public key object.
 * @param  slot    [in]      Slot operation is performed on.
 * @return  -ve when encryption fails.
 *          0 on success.
 */
int WP11_RsaPkcs15_PublicEncrypt(unsigned char* in, word32 inLen,
                                 unsigned char* out, word32* outLen,
                                 WP11_Object* pub, WP11_Slot* slot)
{
    int ret;
    WC_RNG rng;

    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
    if (ret == 0) {
        ret = wc_RsaPublicEncrypt_ex(in, inLen, out, *outLen, pub->data.rsaKey,
                                       &rng, WC_RSA_PKCSV15_PAD,
                                       WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0);
        Rng_Free(&rng);
    }
    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);

    if (ret >= 0) {
        *outLen = ret;
        ret = 0;
    }

    return ret;
}

/**
 * PKCS#1.5 decrypt data with private key.
 *
 * @param  in      [in]      Data to decrypt.
 * @param  inLen   [in]      Length of data to decrypt.
 * @param  out     [in]      Buffer to hold decrypted data.
 * @param  outLen  [in,out]  On in, length of buffer.
 *                           On out, length data in buffer.
 * @param  priv    [in]      Private key object.
 * @param  slot    [in]      Slot operation is performed on.
 * @return  -ve when decryption fails.
 *          0 on success.
 */
int WP11_RsaPkcs15_PrivateDecrypt(unsigned char* in, word32 inLen,
                                  unsigned char* out, word32* outLen,
                                  WP11_Object* priv, WP11_Slot* slot)
{
    int ret = 0;
#ifdef WOLFPKCS11_NEED_RSA_RNG
    WC_RNG rng;
#endif
    /* A random number generator is needed for blinding. */
    if (priv->onToken)
        WP11_Lock_LockRW(priv->lock);

#ifdef WOLFPKCS11_NEED_RSA_RNG
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
#endif
    if (ret == 0) {
    #ifdef WOLFPKCS11_NEED_RSA_RNG
        priv->data.rsaKey->rng = &rng;
    #endif

    #ifdef WOLFPKCS11_TPM
        ret = WP11_Object_LoadTpmKey(priv);
        if (ret == 0)
    #endif
        {
            ret = wc_RsaPrivateDecrypt_ex(in, inLen, out, *outLen,
                                          priv->data.rsaKey, WC_RSA_PKCSV15_PAD,
                                          WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0);
            if (ret >= 0) {
                *outLen = ret;
                ret = 0;
            }

        #ifdef WOLFPKCS11_TPM
            wolfTPM2_UnloadHandle(&slot->tpmDev, &priv->tpmKey->handle);
        #endif
        }

    #ifdef WOLFPKCS11_NEED_RSA_RNG
        priv->data.rsaKey->rng = NULL;
        Rng_Free(&rng);
    #endif
    }

    if (priv->onToken)
        WP11_Lock_UnlockRW(priv->lock);

    (void)slot;

    return ret;
}

#ifndef WC_NO_RSA_OAEP
/**
 * PKCS#1 OAEP encrypt data with public key.
 *
 * @param  in       [in]      Data to encrypt.
 * @param  inLen    [in]      Length of data to encrypt.
 * @param  out      [in]      Buffer to hold encrypted data.
 * @param  outLen   [in,out]  On in, length of buffer.
 *                            On out, length data in buffer.
 * @param  pub      [in]      Public key object.
 * @param  session  [in]      Session object holding OAEP parameters.
 * @return  -ve when encryption fails.
 *          0 on success.
 */
int WP11_RsaOaep_PublicEncrypt(unsigned char* in, word32 inLen,
                               unsigned char* out, word32* outLen,
                               WP11_Object* pub, WP11_Session* session)
{
    int ret;
    WP11_OaepParams* oaep = &session->params.oaep;
    WP11_Slot* slot = WP11_Session_GetSlot(session);
    WC_RNG rng;

    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
    if (ret == 0) {
        ret = wc_RsaPublicEncrypt_ex(in, inLen, out, *outLen, pub->data.rsaKey,
                                         &rng, WC_RSA_OAEP_PAD, oaep->hashType,
                                         oaep->mgf, oaep->label, oaep->labelSz);
        Rng_Free(&rng);
    }
    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);

    if (ret >= 0) {
        *outLen = ret;
        ret = 0;

        if (oaep->label != NULL) {
            XFREE(oaep->label, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            oaep->label = NULL;
        }
    }

    return ret;
}

/**
 * PKCS#1 OAEP decrypt data with private key.
 *
 * @param  in      [in]      Data to decrypt.
 * @param  inLen   [in]      Length of data to decrypt.
 * @param  out     [in]      Buffer to hold decrypted data.
 * @param  outLen  [in,out]  On in, length of buffer.
 *                           On out, length data in buffer.
 * @param  priv    [in]      Private key object.
 * @param  session  [in]     Session object holding OAEP parameters.
 * @return  -ve when decryption fails.
 *          0 on success.
 */
int WP11_RsaOaep_PrivateDecrypt(unsigned char* in, word32 inLen,
                                unsigned char* out, word32* outLen,
                                WP11_Object* priv, WP11_Session* session)
{
    int ret = 0;
    WP11_OaepParams* oaep = &session->params.oaep;
    WP11_Slot* slot = WP11_Session_GetSlot(session);
#ifdef WOLFPKCS11_NEED_RSA_RNG
    WC_RNG rng;
#endif

    /* A random number generator is needed for blinding. */
    if (priv->onToken)
        WP11_Lock_LockRW(priv->lock);
#ifdef WOLFPKCS11_NEED_RSA_RNG
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
#endif
    if (ret == 0) {
    #ifdef WOLFPKCS11_NEED_RSA_RNG
        priv->data.rsaKey->rng = &rng;
    #endif

    #ifdef WOLFPKCS11_TPM
        ret = WP11_Object_LoadTpmKey(priv);
        if (ret == 0)
    #endif
        {
            ret = wc_RsaPrivateDecrypt_ex(in, inLen, out, *outLen,
                                          priv->data.rsaKey, WC_RSA_OAEP_PAD,
                                          oaep->hashType, oaep->mgf,
                                          oaep->label, oaep->labelSz);
            if (ret >= 0) {
                *outLen = ret;
                ret = 0;
            }

        #ifdef WOLFPKCS11_TPM
            wolfTPM2_UnloadHandle(&slot->tpmDev, &priv->tpmKey->handle);
        #endif
        }

    #ifdef WOLFPKCS11_NEED_RSA_RNG
        priv->data.rsaKey->rng = NULL;
        Rng_Free(&rng);
    #endif
    }

    if (priv->onToken)
        WP11_Lock_UnlockRW(priv->lock);

    if (ret == 0) {
        if (oaep->label != NULL) {
            XFREE(oaep->label, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            oaep->label = NULL;
        }
    }
    (void)slot;

    return ret;
}
#endif /* !WC_NO_RSA_OAEP */

#ifdef WC_RSA_DIRECT
/**
 * RSA sign data with private key.
 *
 * @param  in      [in]      Data to sign.
 * @param  inLen   [in]      Length of data.
 * @param  sig     [in]      Buffer to hold signature data.
 * @param  sigLen  [in,out]  On in, length of buffer.
 *                           On out, length data in buffer.
 * @param  priv    [in]      Private key object.
 * @param  slot    [in]      Slot operation is performed on.
 * @return  RSA_BUFFER_E or BUFFER_E when sigLen is too small.
 *          Other -ve when signing fails.
 *          0 on success.
 */
int WP11_Rsa_Sign(unsigned char* in, word32 inLen, unsigned char* sig,
                  word32* sigLen, WP11_Object* priv, WP11_Slot* slot)
{
    int ret;
    WC_RNG rng;
    byte data[RSA_MAX_SIZE / 8];
    word32 keyLen;

    keyLen = wc_RsaEncryptSize(priv->data.rsaKey);
    if (inLen < keyLen) {
        XMEMSET(data, 0, keyLen - inLen);
        XMEMCPY(data + keyLen - inLen, in, inLen);
        in = data;
        inLen = keyLen;
    }

    if (priv->onToken)
        WP11_Lock_LockRO(priv->lock);
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
    if (ret == 0) {
    #ifdef WOLFPKCS11_TPM
        ret = WP11_Object_LoadTpmKey(priv);
        if (ret == 0)
    #endif
        {
            ret = wc_RsaDirect(in, inLen, sig, sigLen, priv->data.rsaKey,
                           RSA_PRIVATE_ENCRYPT, &rng);
            if (ret > 0) {
                *sigLen = ret;
                ret = 0;
            }

        #ifdef WOLFPKCS11_TPM
            wolfTPM2_UnloadHandle(&slot->tpmDev, &priv->tpmKey->handle);
        #endif
        }

        Rng_Free(&rng);
    }

    if (priv->onToken)
        WP11_Lock_UnlockRO(priv->lock);

    return ret;
}

/**
 * RSA verify the signature where the data is recovered from the signature.
 *
 * @param  sig     [in]   Signature data.
 * @param  sigLen  [in]   Length of buffer.
 * @param  in      [in]   Data to verify.
 * @param  inLen   [in]   Length of data.
 * @param  stat    [out]  Status of verification. 1 on success, otherwise 0.
 * @param  pub     [in]   Public key object.
 * @return  -ve when verifying fails.
 *          0 on success.
 */
int WP11_Rsa_Verify_Recover(CK_MECHANISM_TYPE mechanism, unsigned char* sig,
                            word32 sigLen, unsigned char* out,
                            CK_ULONG_PTR outLen, WP11_Object* pub)
{
    int ret;
    byte* data_out = NULL;

    switch (mechanism) {
        case CKM_RSA_PKCS:
            ret = wc_RsaSSL_VerifyInline(sig, sigLen, &data_out,
                                         pub->data.rsaKey);
            if (ret < 0)
                return ret;

            *outLen = ret;
            if (out == NULL) {
                return CKR_OK;
            }
            else {
                if (*outLen < (CK_ULONG)ret) {
                    return CKR_BUFFER_TOO_SMALL;
                }
                else {
                    XMEMCPY(out, data_out, ret);
                }
            }
            break;

        case CKM_RSA_X_509:
        {
            byte* pos;

            ret = wc_RsaDirect(sig, sigLen, out, (word32*)outLen,
                               pub->data.rsaKey, RSA_PUBLIC_DECRYPT, NULL);
            if (ret < 0)
                return ret;

            /* Result is front padded with 0x00 */
            for (pos = out; pos < out + *outLen; pos++) {
                if (*pos != 0x00) {
                    data_out = pos;
                    break;
                }
            }
            if (data_out != NULL) {
                *outLen = (out + *outLen) - data_out;
                XMEMMOVE(out, data_out, *outLen);
            }
            break;
        }
        default:
            /* Should never happen */
            return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/**
 * RSA verify data with public key.
 *
 * @param  sig     [in]   Signature data.
 * @param  sigLen  [in]   Length of buffer.
 * @param  in      [in]   Data to verify.
 * @param  inLen   [in]   Length of data.
 * @param  stat    [out]  Status of verification. 1 on success, otherwise 0.
 * @param  pub     [in]   Public key object.
 * @return  -ve when verifying fails.
 *          0 on success.
 */
int WP11_Rsa_Verify(unsigned char* sig, word32 sigLen, unsigned char* in,
                    word32 inLen, int* stat, WP11_Object* pub)
{
    byte decSig[RSA_MAX_SIZE / 8];
    word32 decSigLen;
    int ret = 0;

    *stat = 0;

    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);
    decSigLen = wc_RsaEncryptSize(pub->data.rsaKey);
    if (inLen > decSigLen)
        return BUFFER_E;
    ret = wc_RsaDirect(sig, sigLen, decSig, &decSigLen, pub->data.rsaKey,
                       RSA_PUBLIC_DECRYPT, NULL);
    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);

    if (ret > 0)
        ret = 0;

    if (ret == 0)
        *stat = WP11_ConstantCompare(in, decSig + (decSigLen - inLen), inLen);

    return ret;
}
#endif /* WC_RSA_DIRECT */

/**
 * PKCS#1.5 sign encoded hash with private key.
 *
 * @param  encHash     [in]      Encoded hash to sign.
 * @param  encHashLen  [in]      Length of encoded hash.
 * @param  sig         [in]      Buffer to hold signature data.
 * @param  sigLen      [in,out]  On in, length of buffer.
 *                               On out, length data in buffer.
 * @param  priv        [in]      Private key object.
 * @param  slot        [in]      Slot operation is performed on.
 * @return  RSA_BUFFER_E or BUFFER_E when sigLen is too small.
 *          Other -ve when signing fails.
 *          0 on success.
 */
int WP11_RsaPkcs15_Sign(unsigned char* encHash, word32 encHashLen,
                        unsigned char* sig, word32* sigLen, WP11_Object* priv,
                        WP11_Slot* slot)
{
    int ret;
    WC_RNG rng;

    if (priv->onToken)
        WP11_Lock_LockRO(priv->lock);
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
    if (ret == 0) {
    #ifdef WOLFPKCS11_TPM
        ret = WP11_Object_LoadTpmKey(priv);
        if (ret == 0)
    #endif
        {
            ret = wc_RsaSSL_Sign(encHash, encHashLen, sig, *sigLen,
                                                      priv->data.rsaKey, &rng);
            if (ret > 0) {
                *sigLen = ret;
                ret = 0;
            }
        #ifdef WOLFPKCS11_TPM
            wolfTPM2_UnloadHandle(&slot->tpmDev, &priv->tpmKey->handle);
        #endif
        }
        Rng_Free(&rng);
    }

    if (priv->onToken)
        WP11_Lock_UnlockRO(priv->lock);

    return ret;
}

/**
 * PKCS#1.5 verify encoded hash with public key.
 *
 * @param  sig         [in]   Signature data.
 * @param  sigLen      [in]   Length of buffer.
 * @param  encHash     [in]   Encoded hash to verify.
 * @param  encHashLen  [in]   Length of encoded hash.
 * @param  stat        [out]  Status of verification. 1 on success, otherwise 0.
 * @param  pub         [in]   Public key object.
 * @return  -ve when verifying fails.
 *          0 on success.
 */
int WP11_RsaPkcs15_Verify(unsigned char* sig, word32 sigLen,
                          unsigned char* encHash, word32 encHashLen, int* stat,
                          WP11_Object* pub)
{
    byte decSig[RSA_MAX_SIZE / 8];
    word32 decSigLen;
    int ret;

    *stat = 0;

    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);
    decSigLen = ret = wc_RsaSSL_Verify(sig, sigLen, decSig, sizeof(decSig),
                                                             pub->data.rsaKey);
    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);

    if (ret > 0)
        ret = 0;

    if (ret == 0) {
        *stat = encHashLen == decSigLen &&
                WP11_ConstantCompare(encHash, decSig, decSigLen);
    }

    return ret;
}

#ifdef WC_RSA_PSS
/**
 * PKCS#1 PSS sign data with private key.
 *
 * @param  hash     [in]      Hash to sign.
 * @param  hashLen  [in]      Length of hash.
 * @param  sig      [in]      Buffer to hold signature data.
 * @param  sigLen   [in]      Length of buffer.
 * @param  sigLen   [in,out]  On in, length of buffer.
 *                            On out, length data in buffer.
 * @param  priv     [in]      Private key object.
 * @param  session  [in]      Session object holding PSS parameters.
 * @return  RSA_BUFFER_E or BUFFER_E when sigLen is too small.
 *          Other -ve when signing fails.
 *          0 on success.
 */
int WP11_RsaPKCSPSS_Sign(unsigned char* hash, word32 hashLen,
                         unsigned char* sig, word32* sigLen,
                         WP11_Object* priv, WP11_Session* session)
{
    int ret;
    WP11_PssParams* pss = &session->params.pss;
    WP11_Slot* slot = WP11_Session_GetSlot(session);
    WC_RNG rng;

    if (priv->onToken)
        WP11_Lock_LockRO(priv->lock);
    ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
    if (ret == 0) {
    #ifdef WOLFPKCS11_TPM
        ret = WP11_Object_LoadTpmKey(priv);
        if (ret == 0)
    #endif
        {
            ret = wc_RsaPSS_Sign_ex(hash, hashLen, sig, *sigLen, pss->hashType,
                                    pss->mgf, pss->saltLen, priv->data.rsaKey,
                                    &rng);
            if (ret > 0) {
                *sigLen = ret;
                ret = 0;
            }
        #ifdef WOLFPKCS11_TPM
            wolfTPM2_UnloadHandle(&slot->tpmDev, &priv->tpmKey->handle);
        #endif
        }
        Rng_Free(&rng);
    }
    if (priv->onToken)
        WP11_Lock_UnlockRO(priv->lock);

    return ret;
}

/**
 * PKCS#1 PSS verify encoded hash with public key.
 *
 * @param  sig      [in]   Signature data.
 * @param  sigLen   [in]   Length of buffer.
 * @param  hsh      [in]   Encoded hash to verify.
 * @param  hashLen  [in]   Length of encoded hash.
 * @param  stat     [out]  Status of verification. 1 on success, otherwise 0.
 * @param  pub      [in]   Public key object.
 * @param  session  [in]   Session object holding PSS parameters.
 * @return  -ve when verifying fails.
 *          0 on success.
 */
int WP11_RsaPKCSPSS_Verify(unsigned char* sig, word32 sigLen,
                           unsigned char* hash, word32 hashLen, int* stat,
                           WP11_Object* pub, WP11_Session* session)
{
    byte decSig[RSA_MAX_SIZE / 8];
    int decSz;
    int ret;
    WP11_PssParams* pss = &session->params.pss;

    *stat = 0;

    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);
    decSz = ret = wc_RsaPSS_Verify_ex(sig, sigLen, decSig, sizeof(decSig),
                                 pss->hashType, pss->mgf, pss->saltLen,
                                 pub->data.rsaKey);
    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);
    if (ret >= 0)
        ret = 0;

    if (ret == 0) {
        ret = wc_RsaPSS_CheckPadding_ex(hash, hashLen, decSig, decSz,
                                          pss->hashType, pss->saltLen, 0);
        if (ret == 0) {
            *stat = 1;
        }
    }
    /* Make sure bad padding returns success, but verify failed.
     * Calling code expects this. */
    if (ret == BAD_PADDING_E) {
        ret = 0;
        *stat = 0;
    }

    return ret;
}
#endif /* WC_RSA_PSS */
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/**
 * Generate an EC key pair.
 *
 * @param  pub   [in]  Public key object.
 * @param  priv  [in]  Private key object.
 * @param  slot  [in]  Slot operation is performed on.
 * @return  -ve when key generation fails.
 *          0 on success.
 */
int WP11_Ec_GenerateKeyPair(WP11_Object* pub, WP11_Object* priv,
                            WP11_Slot* slot)
{
    int ret = 0;
    WC_RNG rng;

    ret = wc_ecc_init_ex(priv->data.ecKey, NULL, priv->slot->devId);
    if (ret == 0) {
    #ifdef WOLFPKCS11_TPM
        CK_BBOOL isSign = CK_FALSE;
        CK_ULONG len = sizeof(isSign);
        ret = WP11_Object_GetAttr(priv, CKA_SIGN, &isSign, &len);
        if (ret == 0 && isSign) {
        #if defined(LIBWOLFTPM_VERSION_HEX) && LIBWOLFTPM_VERSION_HEX > 0x03009000
            priv->slot->tpmCtx.ecdsaKey = priv->tpmKey;
        #else
            priv->slot->tpmCtx.eccKey = (WOLFTPM2_KEY*)priv->tpmKey;
        #endif
        }
        else {
            priv->slot->tpmCtx.ecdhKey = (WOLFTPM2_KEY*)priv->tpmKey;
        }
    #endif

        /* Copy parameters from public key into private key. */
        priv->data.ecKey->dp = pub->data.ecKey->dp;

        /* Generate into the private key. */
        ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
        if (ret == 0) {
            ret = wc_ecc_make_key_ex(&rng, priv->data.ecKey->dp->size,
                                    priv->data.ecKey, priv->data.ecKey->dp->id);
        #ifdef WOLFPKCS11_TPM
            if (ret == 0) {
                /* set flag indicating this is TPM based key */
                priv->opFlag |= WP11_FLAG_TPM;

                /* unload handle and reload when used */
                wolfTPM2_UnloadHandle(&slot->tpmDev, &priv->tpmKey->handle);
            }
        #endif
            Rng_Free(&rng);
        }
        if (ret == 0) {
            /* Copy the public part into public key. */
            ret = wc_ecc_copy_point(&priv->data.ecKey->pubkey,
                                                       &pub->data.ecKey->pubkey);
        }
        if (ret != 0) {
            wc_ecc_free(priv->data.ecKey);
        }
    }

    if (ret == 0) {
        priv->data.ecKey->type = ECC_PRIVATEKEY;
        pub->data.ecKey->type = ECC_PUBLICKEY;
        priv->local = 1;
        pub->local = 1;
        priv->keyGenMech = CKM_EC_KEY_PAIR_GEN;
        pub->keyGenMech = CKM_EC_KEY_PAIR_GEN;
    }

    return ret;
}

/**
 * ASN.1 encode the ECDSA signature.
 *
 * @param  sig     [in]  Raw signature data.
 * @param  sigSz   [in]  Length of raw signature.
 * @param  encSig  [in]  Buffer to hold encoded signature.
 * @return  Length of encoded signature.
 */
static word32 Pkcs11ECDSASig_Encode(byte* sig, word32 sigSz, byte* encSig)
{
    word32 rHigh, sHigh, seqLen;
    word32 rStart = 0, sStart = 0;
    word32 sz, rSz, rLen, sSz, sLen;
    word32 i;

    /* Ordinate size. */
    sz = sigSz / 2;

    /* Find first byte of data in r and s. */
    while (sig[rStart] == 0x00 && rStart < sz - 1)
        rStart++;
    while (sig[sz + sStart] == 0x00 && sStart < sz - 1)
        sStart++;
    /* Check if 0 needs to be prepended to make integer a positive number. */
    rHigh = sig[rStart] >> 7;
    sHigh = sig[sz + sStart] >> 7;
    /* Calculate length of integer to put into ASN.1 encoding. */
    rLen = sz - rStart;
    sLen = sz - sStart;
    /* r and s: INT (2 bytes) + [ 0x00 ] + integer */
    rSz = 2 + rHigh + rLen;
    sSz = 2 + sHigh + sLen;
    /* Calculate the complete ASN.1 DER encoded size. */
    sigSz = rSz + sSz;
    if (sigSz >= ASN_LONG_LENGTH)
        seqLen = 3;
    else
        seqLen = 2;

    /* Move s and then r integers into their final places. */
    XMEMCPY(encSig + seqLen + rSz + (sSz - sLen), sig + sz + sStart, sLen);
    XMEMCPY(encSig + seqLen       + (rSz - rLen), sig      + rStart, rLen);

    /* Put the ASN.1 DER encoding around data. */
    i = 0;
    encSig[i++] = ASN_CONSTRUCTED | ASN_SEQUENCE;
    if (seqLen == 3)
        encSig[i++] = ASN_LONG_LENGTH | 0x01;
    encSig[i++] = sigSz;
    encSig[i++] = ASN_INTEGER;
    encSig[i++] = rHigh + (sz - rStart);
    if (rHigh)
        encSig[i++] = 0x00;
    i += sz - rStart;
    encSig[i++] = ASN_INTEGER;
    encSig[i++] = sHigh + (sz - sStart);
    if (sHigh)
        encSig[i] = 0x00;

    return seqLen + sigSz;
}

/**
 * Decode ASN.1 encoded ECDSA signature.
 *
 * @param  in     [in]  Encode signature data.
 * @param  inSz   [in]  Length of encoded signature in bytes.
 * @param  sig    [in]  Buffer to hold raw signature data.
 * @param  sigSz  [in]  Length of ordinate in bytes.
 * @return  ASN_PARSE_E when the ASN.1 encoding is invalid.
 *          0 on success.
 */
static int Pkcs11ECDSASig_Decode(const byte* in, word32 inSz, byte* sig,
                                 word32 sz)
{
    int ret = 0;
    word32 i = 0;
    int len, seqLen = 2;

    /* Make sure zeros in place when decoding short integers. */
    XMEMSET(sig, 0, sz * 2);

    /* Check min data for: SEQ + INT. */
    if (inSz < 5)
        ret = ASN_PARSE_E;
    /* Check SEQ */
    if (ret == 0 && in[i++] != (ASN_CONSTRUCTED | ASN_SEQUENCE))
        ret = ASN_PARSE_E;
    if (ret == 0 && in[i] >= ASN_LONG_LENGTH) {
        if (in[i] != (ASN_LONG_LENGTH | 0x01))
            ret = ASN_PARSE_E;
        else {
            i++;
            seqLen++;
        }
    }
    if (ret == 0 && in[i++] != inSz - seqLen)
        ret = ASN_PARSE_E;

    /* Check INT */
    if (ret == 0 && in[i++] != ASN_INTEGER)
        ret = ASN_PARSE_E;
    if (ret == 0 && (len = in[i++]) > (int)sz + 1)
        ret = ASN_PARSE_E;
    /* Check there is space for INT data */
    if (ret == 0 && i + len > inSz)
        ret = ASN_PARSE_E;
    if (ret == 0) {
        /* Skip leading zero */
        if (in[i] == 0x00) {
            i++;
            len--;
        }
        /* Copy r into sig. */
        XMEMCPY(sig + sz - len, in + i, len);
        i += len;
    }

    /* Check min data for: INT. */
    if (ret == 0 && i + 2 > inSz)
        ret = ASN_PARSE_E;
    /* Check INT */
    if (ret == 0 && in[i++] != ASN_INTEGER)
        ret = ASN_PARSE_E;
    if (ret == 0 && (len = in[i++]) > (int)sz + 1)
        ret = ASN_PARSE_E;
    /* Check there is space for INT data */
    if (ret == 0 && i + len > inSz)
        ret = ASN_PARSE_E;
    if (ret == 0) {
        /* Skip leading zero */
        if (in[i] == 0x00) {
            i++;
            len--;
        }
        /* Copy s into sig. */
        XMEMCPY(sig + sz + sz - len, in + i, len);
    }

    return ret;
}

/**
 * Return the length of a signature in bytes.
 *
 * @param  key  [in]  EC key object.
 * @return  Length of ECDSA signature in bytes.
 */
int WP11_Ec_SigLen(WP11_Object* key)
{
    return wc_ecc_size(key->data.ecKey) * 2;
}

/**
 * ECDSA sign data with private key.
 *
 * @param  hash     [in]      Hash to sign.
 * @param  hashLen  [in]      Length of hash in bytes.
 * @param  sig      [in]      Buffer to hold signature data.
 * @param  sigLen   [in]      Length of buffer in bytes.
 * @param  sigLen   [in,out]  On in, length of buffer.
 *                            On out, length data in buffer.
 * @param  priv     [in]      Private key object.
 * @param  slot     [in]      Slot operation is performed on.
 * @return  BUFFER_E when sigLen is too small.
 *          Other -ve when signing fails.
 *          0 on success.
 */
int WP11_Ec_Sign(unsigned char* hash, word32 hashLen, unsigned char* sig,
                 word32* sigLen, WP11_Object* priv, WP11_Slot* slot)
{
    int ret = 0;
    byte encSig[ECC_MAX_SIG_SIZE];
    word32 encSigLen;
    word32 ordSz;
    WC_RNG rng;

    if (priv->onToken)
        WP11_Lock_LockRO(priv->lock);
    ordSz = priv->data.ecKey->dp->size;
    if (priv->onToken)
        WP11_Lock_UnlockRO(priv->lock);

    if (*sigLen < ordSz * 2)
        ret = BUFFER_E;
    if (ret == 0) {
        encSigLen = sizeof(encSig);

        if (priv->onToken)
            WP11_Lock_LockRO(priv->lock);

        ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
        if (ret == 0) {
        #ifdef WOLFPKCS11_TPM
            ret = WP11_Object_LoadTpmKey(priv);
            if (ret == 0)
        #endif
            {
                ret = wc_ecc_sign_hash(hash, hashLen, encSig, &encSigLen, &rng,
                                                        priv->data.ecKey);

            #ifdef WOLFPKCS11_TPM
                wolfTPM2_UnloadHandle(&slot->tpmDev, &priv->tpmKey->handle);
            #endif
            }
            Rng_Free(&rng);
        }

        if (priv->onToken)
            WP11_Lock_UnlockRO(priv->lock);

        if (ret == 0) {
            ret = Pkcs11ECDSASig_Decode(encSig, encSigLen, sig, ordSz);
        }
        if (ret == 0)
            *sigLen = ordSz * 2;
    }

    return ret;
}

/**
 * ECDSA verify encoded hash with public key.
 *
 * @param  sig      [in]   Signature data.
 * @param  sigLen   [in]   Length of buffer in bytes.
 * @param  hash     [in]   Encoded hash to verify.
 * @param  hashLen  [in]   Length of encoded hash in bytes.
 * @param  pub      [in]   Public key object.
 * @param  stat     [out]  Status of verification. 1 on success, otherwise 0.
 * @param  pub      [in]   Public key object.
 * @return  -ve when verifying fails.
 *          0 on success.
 */
int WP11_Ec_Verify(unsigned char* sig, word32 sigLen, unsigned char* hash,
                   word32 hashLen, int* stat, WP11_Object* pub)
{
    int ret = 0;
    byte encSig[ECC_MAX_SIG_SIZE];
    word32 encSigLen;

    *stat = 0;
    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);
    if (sigLen != (word32)(2 * pub->data.ecKey->dp->size))
        ret = BAD_FUNC_ARG;
    if (ret == 0) {
        encSigLen = Pkcs11ECDSASig_Encode(sig, sigLen, encSig);
        ret = wc_ecc_verify_hash(encSig, encSigLen, hash, hashLen, stat,
                                                              pub->data.ecKey);
    }
    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);

    return ret;
}


/**
 * Derive the secret from the private key and peer's point with ECDH.
 *
 * @param  point     [in]  Peer's point data.
 * @param  pointLen  [in]  Length of point data in bytes.
 * @param  key       [in]  Buffer to hold secret key.
 * @param  keyLen    [in]  Length of buffer in bytes.
 * @param  priv      [in]  The private key.
 * @return  -ve when derivation fails.
 *          0 on success.
 */
int WP11_EC_Derive(unsigned char* point, word32 pointLen, unsigned char* key,
                   word32 keyLen, WP11_Object* priv)
{
    int ret;
    ecc_key pubKey;
    unsigned char* x963Data = point;
    word32 x963Len = pointLen;
    int dataLen;
    int i = 0;
#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    WC_RNG rng;
#endif

    /* Check if the point data is DER-encoded (starts with OCTET STRING tag) */
    if (pointLen >= 3 && point[0] == ASN_OCTET_STRING) {
        /* Strip DER encoding - similar to EcSetPoint function */
        i = 1;
        if (point[i] >= ASN_LONG_LENGTH) {
            if (point[i] == (ASN_LONG_LENGTH | 1)) {
                i++;
            }
            else {
                ret = ASN_PARSE_E;
                goto cleanup;
            }
        }
        dataLen = point[i++];
        if (dataLen == (int)(pointLen - i)) {
            x963Data = point + i;
            x963Len = dataLen;
        }
    }

    ret = wc_ecc_init_ex(&pubKey, NULL, priv->slot->devId);
    if (ret == 0) {
        if (priv->data.ecKey->dp) {
            ret = wc_ecc_import_x963_ex(x963Data, x963Len, &pubKey,
                                        priv->data.ecKey->dp->id);
        }
        else {
            ret = wc_ecc_import_x963(x963Data, x963Len, &pubKey);
        }
    }
#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    if (ret == 0) {
        ret = Rng_New(&priv->slot->token.rng, &priv->slot->token.rngLock, &rng);
        wc_ecc_set_rng(priv->data.ecKey, &rng);
    }
#endif
    if (ret == 0) {
        if (priv->onToken)
            WP11_Lock_LockRO(priv->lock);
    #ifdef WOLFPKCS11_TPM
        ret = WP11_Object_LoadTpmKey(priv);
        if (ret == 0)
    #endif
        {
            PRIVATE_KEY_UNLOCK();
            ret = wc_ecc_shared_secret(priv->data.ecKey, &pubKey, key, &keyLen);
            PRIVATE_KEY_LOCK();

        #ifdef WOLFPKCS11_TPM
            wolfTPM2_UnloadHandle(&priv->slot->tpmDev, &priv->tpmKey->handle);
        #endif
        }
        if (priv->onToken)
            WP11_Lock_UnlockRO(priv->lock);
#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
        Rng_Free(&rng);
#endif
    }

cleanup:
    wc_ecc_free(&pubKey);

    return ret;
}
#endif /* HAVE_ECC */

#if defined(WOLFPKCS11_HKDF) || !defined(NO_AES)
/**
 * Generate a secret key.
 *
 * @param  secret  [in]  Secret object.
 * @param  slot    [in]  Slot operation is performed on.
 * @return  -ve on random number generation failure.
 *          0 on success.
 */
int WP11_GenerateRandomKey(WP11_Object* secret, WP11_Slot* slot)
{
    int ret;
    WP11_Data* key = secret->data.symmKey;

    WP11_Lock_LockRW(&slot->token.rngLock);
    ret = wc_RNG_GenerateBlock(&slot->token.rng, key->data, key->len);
    WP11_Lock_UnlockRW(&slot->token.rngLock);

    return ret;
}
#endif /* WOLFPKCS11_HKDF || !NO_AES */

#ifdef WOLFPKCS11_HKDF

/**
 * Derive the secret from the private key with HKDF.
 *
 * @param  params     [in]  The salt and info parameters.
 * @param  key        [in]  Buffer to hold the secret key.
 * @param  keyLen     [in]  Buffer length in bytes.
 * @param  priv       [in]  The private key.
 * @return  -ve when derivation fails.
 *          0 on success
 */

int WP11_KDF_Derive(WP11_Session* session, CK_HKDF_PARAMS_PTR params,
                    unsigned char* key, word32* keyLen, WP11_Object* priv)
{
    int ret = 0;
    byte* salt = NULL;
    unsigned long saltLen = 0;
    WP11_Object* saltKey = NULL;
    enum wc_HashType hashType;
    word32 hashLen;

    ret = wp11_hash_type(params->prfHashMechanism, &hashType);

    if (ret != 0) {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    hashLen = wc_HashGetDigestSize(hashType);

    if (params->bExtract) {
        switch (params->ulSaltType) {
            case CKF_HKDF_SALT_NULL:
                break;

            case CKF_HKDF_SALT_DATA:
                salt = params->pSalt;
                saltLen = params->ulSaltLen;
                break;

            case CKF_HKDF_SALT_KEY:
                ret = WP11_Object_Find(session, params->hSaltKey, &saltKey);
                if (ret != 0)
                    return CKR_OBJECT_HANDLE_INVALID;
                salt = saltKey->data.symmKey->data;
                saltLen = saltKey->data.symmKey->len;
                break;

            default:
                return CKR_MECHANISM_PARAM_INVALID;
                break;
        }
    }

    PRIVATE_KEY_UNLOCK();
    if (params->bExtract && !params->bExpand) {
        ret = wc_HKDF_Extract(hashType, salt, (word32)saltLen,
            priv->data.symmKey->data, priv->data.symmKey->len, key);

        if (!ret)
            *keyLen = hashLen;
    }
    else if (!params->bExtract && params->bExpand) {
        ret = wc_HKDF_Expand(hashType, priv->data.symmKey->data,
            priv->data.symmKey->len, params->pInfo, (word32)params->ulInfoLen,
            key, *keyLen);
    }
    else {
        /* Both */
        ret = wc_HKDF(hashType, priv->data.symmKey->data,
            priv->data.symmKey->len,
            salt, (word32)saltLen, params->pInfo, (word32)params->ulInfoLen,
            key, *keyLen);
    }
    PRIVATE_KEY_LOCK();

    return ret;
}

#endif

#ifndef NO_DH
/**
 * Generate an DH key pair.
 *
 * @param  pub   [in]  Public key object.
 * @param  priv  [in]  Private key object.
 * @param  slot  [in]  Slot operation is performed on.
 * @return  -ve when key generation fails.
 *          0 on success.
 */
int WP11_Dh_GenerateKeyPair(WP11_Object* pub, WP11_Object* priv,
                            WP11_Slot* slot)
{
    int ret;
    WC_RNG rng;

    /* Copy the parameters from the public key into the private key. */
    ret = mp_copy(&pub->data.dhKey->params.p, &priv->data.dhKey->params.p);
    if (ret == 0)
        ret = mp_copy(&pub->data.dhKey->params.g, &priv->data.dhKey->params.g);
    if (ret == 0) {
        ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
        if (ret == 0) {
            priv->data.dhKey->len = (word32)sizeof(priv->data.dhKey->key);
            pub->data.dhKey->len = (word32)sizeof(pub->data.dhKey->key);
            PRIVATE_KEY_UNLOCK();
            ret = wc_DhGenerateKeyPair(&pub->data.dhKey->params, &rng,
                                    priv->data.dhKey->key, &priv->data.dhKey->len,
                                    pub->data.dhKey->key, &pub->data.dhKey->len);
            PRIVATE_KEY_LOCK();
            Rng_Free(&rng);
        }
    }
    if (ret == 0) {
        priv->local = 1;
        pub->local = 1;
        priv->keyGenMech = CKM_DH_PKCS_KEY_PAIR_GEN;
        pub->keyGenMech = CKM_DH_PKCS_KEY_PAIR_GEN;
    }

    return ret;
}

/**
 * Derive the secret from the private key and peer's public value with DH.
 *
 * @param  point     [in]  Peer's point data.
 * @param  pointLen  [in]  Length of point data in bytes.
 * @param  key       [in]  Buffer to hold secret key.
 * @param  keyLen    [in]  Length of buffer in bytes.
 * @param  priv      [in]  The private key.
 * @return  -ve when derivation fails.
 *          0 on success.
 */
int WP11_Dh_Derive(unsigned char* pub, word32 pubLen, unsigned char* key,
                   word32* keyLen, WP11_Object* priv)
{
    int ret;

    if (priv->onToken)
        WP11_Lock_LockRO(priv->lock);
    PRIVATE_KEY_UNLOCK();
    ret = wc_DhAgree(&priv->data.dhKey->params, key, keyLen,
                       priv->data.dhKey->key, priv->data.dhKey->len, pub, pubLen);
    PRIVATE_KEY_LOCK();
    if (priv->onToken)
        WP11_Lock_UnlockRO(priv->lock);

    return ret;
}
#endif /* !NO_DH */

#ifndef NO_AES

#ifdef HAVE_AES_CBC
/**
 * Return the amount of data not yet processed.
 *
 * @param  session  [in]  Session object.
 * @return  Unprocessed amount in bytes.
 */
int WP11_AesCbc_PartLen(WP11_Session* session)
{
    WP11_CbcParams* cbc = &session->params.cbc;

    return cbc->partialSz;
}


int WP11_AesCbc_DeriveKey(unsigned char* plain, word32 plainSz,
                        unsigned char* enc, byte* iv,
                        WP11_Object* key)
{
    Aes aes;
    int ret = 0;

    if (key->type != CKK_AES && key->type != CKK_GENERIC_SECRET)
        return BAD_FUNC_ARG;

    XMEMSET(&aes, 0, sizeof(aes));
    ret = wc_AesInit(&aes, NULL, key->slot->devId);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, key->data.symmKey->data, key->data.symmKey->len,
                iv, AES_ENCRYPTION);
    }
    if (ret == 0)
        ret = wc_AesCbcEncrypt(&aes, enc, plain, plainSz);
    wc_AesFree(&aes);

    return ret;
}

#ifdef WOLFSSL_HAVE_PRF
/* Used for wc_PRF_TLS, less than sha256_mac not possible */
static enum wc_MACAlgorithm MechToMac(CK_MECHANISM_TYPE mech)
{
    switch (mech)
    {
        case CKM_SHA256:
        case CKM_SHA256_HMAC:
            return sha256_mac;
        case CKM_SHA384:
        case CKM_SHA384_HMAC:
            return sha384_mac;
        case CKM_SHA512:
        case CKM_SHA512_HMAC:
            return sha512_mac;
        default:
            return no_mac;
    }
}

int WP11_Tls12_Master_Key_Derive(CK_SSL3_RANDOM_DATA* random,
                                 CK_MECHANISM_TYPE mech, const char* label,
                                 CK_ULONG ulLabelLen, byte* enc,
                                 CK_ULONG encLen, CK_BBOOL clientFirst,
                                 WP11_Object* key)
{
    int ret = 0;
    CK_ULONG ulSeedLen = 0;
    byte* pSeed = NULL;
    enum wc_MACAlgorithm macType;

    macType = MechToMac(mech);

    if (macType == no_mac) {
        return BAD_FUNC_ARG;
    }

    ulSeedLen = random->ulClientRandomLen + random->ulServerRandomLen;
    if (ulSeedLen == 0) {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    pSeed = (byte*)XMALLOC(ulSeedLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pSeed == NULL) {
        return CKR_HOST_MEMORY;
    }
    if (clientFirst) {
        XMEMCPY(pSeed, random->pClientRandom, random->ulClientRandomLen);
        XMEMCPY(pSeed + random->ulClientRandomLen, random->pServerRandom,
                random->ulServerRandomLen);
    }
    else {
        XMEMCPY(pSeed, random->pServerRandom, random->ulServerRandomLen);
        XMEMCPY(pSeed + random->ulServerRandomLen, random->pClientRandom,
                random->ulClientRandomLen);
    }

    PRIVATE_KEY_UNLOCK();
    ret = wc_PRF_TLS(enc, (word32)encLen, key->data.symmKey->data,
                     key->data.symmKey->len, (const byte*)label,
                     (word32)ulLabelLen, pSeed, (word32)ulSeedLen,
                     1, macType, NULL, 0);
    PRIVATE_KEY_LOCK();

    if (pSeed) {
        XFREE(pSeed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        pSeed = NULL;
    }


    return ret;
}
#ifdef WOLFPKCS11_NSS
int WP11_Nss_Tls12_Master_Key_Derive(CK_BYTE_PTR pSessionHash,
                                     CK_ULONG ulSessionHashLen,
                                     CK_MECHANISM_TYPE mech, const char* label,
                                     CK_ULONG ulLabelLen, byte* enc,
                                     CK_ULONG encLen, WP11_Object* key)
{
    int ret = 0;
    enum wc_MACAlgorithm macType;

    macType = MechToMac(mech);

    if (macType == no_mac) {
        return BAD_FUNC_ARG;
    }

    PRIVATE_KEY_UNLOCK();
    ret = wc_PRF_TLS(enc, (word32)encLen, key->data.symmKey->data,
                     key->data.symmKey->len, (const byte*)label,
                     (word32)ulLabelLen, pSessionHash, (word32)ulSessionHashLen,
                     1, macType, NULL, 0);
    PRIVATE_KEY_LOCK();

    return ret;
}
#endif
#endif /* WOLFSSL_HAVE_PRF */

/**
 * Encrypt plain text with AES-CBC.
 * Output buffer must be large enough to hold all data.
 * No padding performed - plain text must be a multiple of the block size.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCbc_Encrypt(unsigned char* plain, word32 plainSz,
                        unsigned char* enc, word32* encSz,
                        WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;

    ret = wc_AesCbcEncrypt(&cbc->aes, enc, plain, plainSz);
    if (ret == 0)
        *encSz = plainSz;

    wc_AesFree(&cbc->aes);
    session->init = 0;

    return ret;
}

/**
 * Encrypt more plain text with AES-CBC.
 * Data not filling a block is cached.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCbc_EncryptUpdate(unsigned char* plain, word32 plainSz,
                              unsigned char* enc, word32* encSz,
                              WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;
    int sz = 0;
    int outSz = 0;

    if (cbc->partialSz > 0) {
        sz = AES_BLOCK_SIZE - cbc->partialSz;
        if (sz > (int)plainSz)
            sz = plainSz;
        XMEMCPY(cbc->partial + cbc->partialSz, plain, sz);
        cbc->partialSz += sz;
        plain += sz;
        plainSz -= sz;
        if (cbc->partialSz == AES_BLOCK_SIZE) {
            ret = wc_AesCbcEncrypt(&cbc->aes, enc, cbc->partial,
                                                                AES_BLOCK_SIZE);
            enc += AES_BLOCK_SIZE;
            outSz += AES_BLOCK_SIZE;
            cbc->partialSz = 0;
            XMEMSET(cbc->partial, 0, AES_BLOCK_SIZE);
        }
    }
    if (ret == 0 && plainSz > 0) {
        sz = plainSz & (~(AES_BLOCK_SIZE - 1));
        if (sz > 0) {
            ret = wc_AesCbcEncrypt(&cbc->aes, enc, plain, sz);
            outSz += sz;
            plain += sz;
            plainSz -= sz;
        }
    }
    if (ret == 0 && plainSz > 0) {
        XMEMCPY(cbc->partial, plain, plainSz);
        cbc->partialSz = plainSz;
    }
    if (ret == 0)
        *encSz = outSz;

    return ret;
}

/**
 * Finalize encryption with AES-CBC.
 * No encrypted data to be returned as no padding is performed.
 *
 * @param  session  [in]      Session object holding Aes object.
 * @return  0 on success.
 */
int WP11_AesCbc_EncryptFinal(WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;

    wc_AesFree(&cbc->aes);
    cbc->partialSz = 0;
    session->init = 0;

    return ret;
}

/**
 * Decrypt data with AES-CBC.
 * Output buffer must be large enough to hold all data.
 * No check for padding is performed.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCbc_Decrypt(unsigned char* enc, word32 encSz, unsigned char* dec,
                        word32* decSz, WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;

    ret = wc_AesCbcDecrypt(&cbc->aes, dec, enc, encSz);
    if (ret == 0)
        *decSz = encSz;

    wc_AesFree(&cbc->aes);
    session->init = 0;

    return ret;
}

/**
 * Decrypt more data with AES-CBC.
 * No check for padding is performed.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCbc_DecryptUpdate(unsigned char* enc, word32 encSz,
                              unsigned char* dec, word32* decSz,
                              WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;
    int sz = 0;
    int outSz = 0;

    if (cbc->partialSz > 0) {
        sz = AES_BLOCK_SIZE - cbc->partialSz;
        if (sz > (int)encSz)
            sz = encSz;
        XMEMCPY(cbc->partial + cbc->partialSz, enc, sz);
        cbc->partialSz += sz;
        enc += sz;
        encSz -= sz;
        if (cbc->partialSz == AES_BLOCK_SIZE) {
            ret = wc_AesCbcDecrypt(&cbc->aes, dec, cbc->partial,
                                                                AES_BLOCK_SIZE);
            dec += AES_BLOCK_SIZE;
            outSz += AES_BLOCK_SIZE;
            cbc->partialSz = 0;
        }
    }
    if (ret == 0 && encSz > 0) {
        sz = encSz & (~(AES_BLOCK_SIZE - 1));
        if (sz > 0) {
            ret = wc_AesCbcDecrypt(&cbc->aes, dec, enc, sz);
            outSz += sz;
            enc += sz;
            encSz -= sz;
        }
    }
    if (ret == 0 && encSz > 0) {
        XMEMCPY(cbc->partial, enc, encSz);
        cbc->partialSz = encSz;
    }
    if (ret == 0)
        *decSz = outSz;

    return ret;
}

/**
 * Finalize decryption with AES-CBC.
 * No decrypted data is returned as no check for padding is performed.
 *
 * @param  session  [in]      Session object holding Aes object.
 * @return  0 on success.
 */
int WP11_AesCbc_DecryptFinal(WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;

    wc_AesFree(&cbc->aes);
    cbc->partialSz = 0;
    session->init = 0;

    return ret;
}

/**
 * Encrypt plain text with AES-CBC and PKCS#5/7 padding.
 * Output buffer must be large enough to hold all data and padding.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCbcPad_Encrypt(unsigned char* plain, word32 plainSz,
                          unsigned char* enc, word32* encSz,
                          WP11_Session* session)
{
    int ret;
    word32 sz = *encSz;
    word32 finalSz;

    ret = WP11_AesCbcPad_EncryptUpdate(plain, plainSz, enc, &sz, session);
    if (ret == 0) {
        finalSz = *encSz - sz;
        ret = WP11_AesCbcPad_EncryptFinal(enc + sz, &finalSz, session);
        if (ret == 0) {
            *encSz = sz + finalSz;
        }
    }

    return ret;
}

/**
 * Encrypt more plain text with AES-CBC.
 * Data not filling a block is cached.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCbcPad_EncryptUpdate(unsigned char* plain, word32 plainSz,
                                unsigned char* enc, word32* encSz,
                                WP11_Session* session)
{
    return WP11_AesCbc_EncryptUpdate(plain, plainSz, enc, encSz, session);
}

/**
 * Finalize encryption with AES-CBC and PKCS#5/7 padding.
 * A block of encrypted data is returned due to padding.
 *
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  0 on success.
 */
int WP11_AesCbcPad_EncryptFinal(unsigned char* enc, word32* encSz,
                                WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;
    int padCnt = AES_BLOCK_SIZE - cbc->partialSz;
    int i;

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        byte mask = 0 - (i >= AES_BLOCK_SIZE - padCnt);
        cbc->partial[i] &= ~mask;
        cbc->partial[i] |= padCnt & mask;
    }
    ret = wc_AesCbcEncrypt(&cbc->aes, enc, cbc->partial, AES_BLOCK_SIZE);
    if (ret == 0)
        *encSz = AES_BLOCK_SIZE;

    wc_AesFree(&cbc->aes);
    cbc->partialSz = 0;
    session->init = 0;

    return ret;
}

/**
 * Decrypt data with AES-CBC that has PKCS#5/7 padding.
 * Output buffer must be large enough to hold all decrypted data.
 * Padding is removed.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCbcPad_Decrypt(unsigned char* enc, word32 encSz, unsigned char* dec,
                           word32* decSz, WP11_Session* session)
{
    int ret;
    word32 sz = *decSz;
    word32 finalSz;

    ret = WP11_AesCbcPad_DecryptUpdate(enc, encSz, dec, &sz, session);
    if (ret == 0) {
        finalSz = *decSz - sz;
        ret = WP11_AesCbcPad_DecryptFinal(dec + sz, &finalSz, session);
        if (ret == 0) {
            *decSz = sz + finalSz;
        }
    }

    return ret;
}

/**
 * Decrypt more data with AES-CBC. Keep data for padding.
 * Data not filling a block or last block is cached.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCbcPad_DecryptUpdate(unsigned char* enc, word32 encSz,
                                 unsigned char* dec, word32* decSz,
                                 WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;
    int sz = 0;
    int outSz = 0;

    if (cbc->partialSz > 0) {
        sz = AES_BLOCK_SIZE - cbc->partialSz;
        if (sz > (int)encSz)
            sz = encSz;
        XMEMCPY(cbc->partial + cbc->partialSz, enc, sz);
        cbc->partialSz += sz;
        enc += sz;
        encSz -= sz;
        if (cbc->partialSz == AES_BLOCK_SIZE && encSz > 0) {
            ret = wc_AesCbcDecrypt(&cbc->aes, dec, cbc->partial,
                                                                AES_BLOCK_SIZE);
            dec += AES_BLOCK_SIZE;
            outSz += AES_BLOCK_SIZE;
            cbc->partialSz = 0;
        }
    }
    if (ret == 0 && encSz > AES_BLOCK_SIZE) {
        sz = encSz - (encSz & (AES_BLOCK_SIZE - 1));
        if (sz == (int)encSz)
            sz -= AES_BLOCK_SIZE;
        ret = wc_AesCbcDecrypt(&cbc->aes, dec, enc, sz);
        outSz += sz;
        enc += sz;
        encSz -= sz;
    }
    if (ret == 0 && encSz > 0) {
        XMEMCPY(cbc->partial, enc, encSz);
        cbc->partialSz = encSz;
    }
    if (ret == 0)
        *decSz = outSz;

    return ret;
}

/**
 * Finalize decryption with AES-CBC and remove PKCS#5/7 padding.
 * Decrypted data without padding is returned.
 *
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  0 on success.
 */
int WP11_AesCbcPad_DecryptFinal(unsigned char* dec, word32* decSz,
                                WP11_Session* session)
{
    int ret = 0;
    WP11_CbcParams* cbc = &session->params.cbc;
    int i;
    byte padCnt;
    byte outSz;
    unsigned char tmp[AES_BLOCK_SIZE];
    unsigned char* p = dec;
    size_t mask;

    ret = wc_AesCbcDecrypt(&cbc->aes, cbc->partial, cbc->partial,
                                                                cbc->partialSz);
    if (ret == 0) {
        padCnt = cbc->partial[AES_BLOCK_SIZE-1];
        outSz = AES_BLOCK_SIZE - (padCnt & (0 - (padCnt <= AES_BLOCK_SIZE)));
        for (i = 0; i < AES_BLOCK_SIZE; i++) {
            mask = (size_t)0 - (i != outSz);
            p = (unsigned char*)((size_t)p & mask);
            p = (unsigned char*)((size_t)p | ((size_t)tmp & (~mask)));
            *p = cbc->partial[i];
            p++;
        }
        *decSz = outSz;
    }

    wc_AesFree(&cbc->aes);
    cbc->partialSz = 0;
    session->init = 0;

    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESCTR
/**
 * Encrypt or decrypt data with AES-CTR.
 * Output buffer must be large enough to hold all data.
 *
 * @param  in     [in]      Input data (plain text for encryption, encrypted
 *                          text for decryption).
 * @param  inSz   [in]      Length of input data in bytes.
 * @param  out    [out]     Buffer to hold output data (encrypted or decrypted).
 * @param  outSz  [in,out]  On in, length of buffer in bytes. On out, length of
 *                          output data in bytes.
 * @param  session[in]      Session object holding CTR parameters.
 * @return  -ve on encryption/decryption failure.
 *          0 on success.
 */
int WP11_AesCtr_Do(unsigned char* in, word32 inSz, unsigned char* out,
        word32* outSz, WP11_Session* session)
{
    int ret = 0;
    WP11_CtrParams* ctr = &session->params.ctr;

    ret = WP11_AesCtr_Update(in, inSz, out, outSz, session);

    wc_AesFree(&ctr->aes);
    session->init = 0;
    return ret;
}

/**
 * Encrypt or decrypt more data with AES-CTR.
 *
 * @param  in     [in]      Input data (plain text for encryption, encrypted
 *                          text for decryption).
 * @param  inSz   [in]      Length of input data in bytes.
 * @param  out    [out]     Buffer to hold output data (encrypted or decrypted).
 * @param  outSz  [in,out]  On in, length of buffer in bytes. On out, length of
 *                          output data in bytes.
 * @param  session[in]      Session object holding CTR parameters.
 * @return  BUFFER_E when out buffer is too small.
 *          0 on success.
 */
int WP11_AesCtr_Update(unsigned char* in, word32 inSz, unsigned char* out,
        word32* outSz, WP11_Session* session)
{
    int ret = 0;
    WP11_CtrParams* ctr = &session->params.ctr;

    if (*outSz < inSz)
        return BUFFER_E;
    ret = wc_AesCtrEncrypt(&ctr->aes, out, in, inSz);
    if (ret == 0)
        *outSz = inSz;

    return ret;
}

/**
 * Finalize encryption or decryption with AES-CTR.
 *
 * @param  session[in]      Session object holding CTR parameters.
 * @return  0 on success.
 */
int WP11_AesCtr_Final(WP11_Session* session)
{
    WP11_CtrParams* ctr = &session->params.ctr;

    wc_AesFree(&ctr->aes);
    session->init = 0;

    return 0;
}
#endif /* HAVE_AESCTR */

#ifdef HAVE_AESGCM
/**
 * Return the tag bits of the GCM parameters.
 *
 * @param  session  [in]  Session object.
 * @return  GCM tag bits.
 */
int WP11_AesGcm_GetTagBits(WP11_Session* session)
{
    WP11_GcmParams* gcm = &session->params.gcm;

    return gcm->tagBits;
}

/**
 * Return the number of encrypted data bytes to decrypt from GCM parameters.
 *
 * @param  session  [in]  Session object.
 * @return  Encrypted data bytes length.
 */
int WP11_AesGcm_EncDataLen(WP11_Session* session)
{
    WP11_GcmParams* gcm = &session->params.gcm;

    return gcm->encSz;
}

/**
 * Encrypt plain text with AES-GCM placing authentication tag on end.
 * Output buffer must be large enough to hold all data.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data including
 *                            authentication tag in bytes.
 * @param  secret   [in]      Secret key object.
 * @param  session  [in]      Session object holding GCM parameters.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesGcm_Encrypt(unsigned char* plain, word32 plainSz,
                        unsigned char* enc, word32* encSz, WP11_Object* secret,
                        WP11_Session* session)
{
    int ret;
    Aes aes;
    WP11_Data* key;
    WP11_GcmParams* gcm = &session->params.gcm;
    word32 authTagSz = gcm->tagBits / 8;
    unsigned char* authTag = enc + plainSz;

    ret = wc_AesInit(&aes, NULL, session->devId);
    if (ret == 0) {
        if (secret->onToken)
            WP11_Lock_LockRO(secret->lock);
        key = secret->data.symmKey;
        ret = wc_AesGcmSetKey(&aes, key->data, key->len);
        if (secret->onToken)
            WP11_Lock_UnlockRO(secret->lock);

        if (ret == 0)
            ret = wc_AesGcmEncrypt(&aes, enc, plain, plainSz, gcm->iv,
                                        gcm->ivSz, authTag, authTagSz, gcm->aad,
                                        gcm->aadSz);
        if (ret == 0)
            *encSz = plainSz + authTagSz;

        if (gcm->aad != NULL) {
            XFREE(gcm->aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            gcm->aad = NULL;
        }

        wc_AesFree(&aes);
    }

    return ret;
}

/**
 * Encrypt plain text with AES-GCM.
 * Does not output authentication tag.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  secret   [in]      Secret key object.
 * @param  session  [in]      Session object holding GCM parameters.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesGcm_EncryptUpdate(unsigned char* plain, word32 plainSz,
                              unsigned char* enc, word32* encSz,
                              WP11_Object* secret, WP11_Session* session)
{
    int ret;
    Aes aes;
    WP11_Data* key;
    WP11_GcmParams* gcm = &session->params.gcm;
    word32 authTagSz = gcm->tagBits / 8;
    unsigned char* authTag = gcm->authTag;

    ret = wc_AesInit(&aes, NULL, session->devId);
    if (ret == 0) {
        if (secret->onToken)
            WP11_Lock_LockRO(secret->lock);
        key = secret->data.symmKey;
        ret = wc_AesGcmSetKey(&aes, key->data, key->len);
        if (secret->onToken)
            WP11_Lock_UnlockRO(secret->lock);

        if (ret == 0)
            ret = wc_AesGcmEncrypt(&aes, enc, plain, plainSz, gcm->iv,
                                        gcm->ivSz, authTag, authTagSz, gcm->aad,
                                        gcm->aadSz);
        if (ret == 0)
            *encSz = plainSz;

        if (gcm->aad != NULL) {
            XFREE(gcm->aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            gcm->aad = NULL;
        }

        wc_AesFree(&aes);
    }

    return ret;
}

/**
 * Finalize encryption with AES-GCM.
 * Returns the authentication tag.
 *
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding GCM parameters.
 * @return  BUFFER_E when encSz is too small for authentication tag.
 *          0 on success.
 */
int WP11_AesGcm_EncryptFinal(unsigned char* enc, word32* encSz,
                             WP11_Session* session)
{
    int ret = 0;
    WP11_GcmParams* gcm = &session->params.gcm;
    word32 authTagSz = gcm->tagBits / 8;

    if (*encSz < authTagSz)
        ret = BUFFER_E;
    if (ret == 0) {
        XMEMCPY(enc, gcm->authTag, authTagSz);
        *encSz = authTagSz;
    }

    return ret;
}

/**
 * Decrypt data, including authentication tag, with AES-GCM.
 * Output buffer must be large enough to hold all decrypted data.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  AES_GCM_AUTH_E when data does not authenticate.
 *          Other -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesGcm_Decrypt(unsigned char* enc, word32 encSz, unsigned char* dec,
                        word32* decSz, WP11_Object* secret,
                        WP11_Session* session)
{
    int ret;
    Aes aes;
    WP11_Data* key;
    WP11_GcmParams* gcm = &session->params.gcm;
    word32 authTagSz = gcm->tagBits / 8;
    unsigned char* authTag = enc + encSz - authTagSz;

    ret = wc_AesInit(&aes, NULL, session->devId);
    if (ret == 0) {
        if (secret->onToken) {
            WP11_Lock_LockRO(secret->lock);
        }

        key = secret->data.symmKey;
        ret = wc_AesGcmSetKey(&aes, key->data, key->len);
        if (secret->onToken) {
            WP11_Lock_UnlockRO(secret->lock);
        }

        if (ret == 0) {
            encSz -= authTagSz;
            ret = wc_AesGcmDecrypt(&aes, dec, enc, encSz, gcm->iv, gcm->ivSz,
                                      authTag, authTagSz, gcm->aad, gcm->aadSz);
        }

        if (ret == 0) {
            *decSz = encSz;
        }

        if (gcm->aad != NULL) {
            XFREE(gcm->aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            gcm->aad = NULL;
        }

        wc_AesFree(&aes);
    }

    return ret;
}

/**
 * Decrypt more data with AES-GCM.
 * Authentication tag is at the end of the encrypted data.
 * All data is cached.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  AES_GCM_AUTH_E when data does not authenticate.
 *          Other -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesGcm_DecryptUpdate(unsigned char* enc, word32 encSz,
                              WP11_Session* session)
{
    int ret = 0;
    unsigned char* newEnc;
    WP11_GcmParams* gcm = &session->params.gcm;

#ifdef XREALLOC
    newEnc = (unsigned char*)XREALLOC(gcm->enc, gcm->encSz + encSz, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (newEnc == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        gcm->enc = newEnc;
        XMEMCPY(gcm->enc + gcm->encSz, enc, encSz);
        gcm->encSz += encSz;
    }
#else
    newEnc = (unsigned char*)XMALLOC(gcm->encSz + encSz, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (newEnc == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        if (gcm->enc != NULL)
            XMEMCPY(newEnc, gcm->enc, gcm->encSz);
        XFREE(gcm->enc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        gcm->enc = newEnc;
        XMEMCPY(gcm->enc + gcm->encSz, enc, encSz);
        gcm->encSz += encSz;
    }
#endif /* !XREALLOC */

    return ret;
}

/**
 * Finalize decryption with AES-GCM.
 * Output buffer must be large enough to hold all decrypted data.
 *
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  AES_GCM_AUTH_E when data does not authenticate.
 *          Other -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesGcm_DecryptFinal(unsigned char* dec, word32* decSz,
                             WP11_Object* secret, WP11_Session* session)
{
    int ret;
    WP11_GcmParams* gcm = &session->params.gcm;

    /* Auth tag on end of encrypted data. */
    ret = WP11_AesGcm_Decrypt(gcm->enc, gcm->encSz, dec, decSz, secret,
                                                                       session);
    XFREE(gcm->enc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    gcm->enc = NULL;
    gcm->encSz = 0;

    return ret;
}
#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM
/**
 * Return the number of data bytes from CCM parameters.
 *
 * @param  session  [in]  Session object.
 * @return  Data byte length.
 */
int WP11_AesCcm_DataLen(WP11_Session* session)
{
    WP11_CcmParams* ccm = &session->params.ccm;

    return ccm->dataSz;
}

/**
 * Return the MAC size from the CCM parameters.
 *
 * @param  session  [in]  Session object.
 * @return  MAC byte length.
 */
int WP11_AesCcm_GetMacLen(WP11_Session* session)
{
    WP11_CcmParams* ccm = &session->params.ccm;

    return ccm->macSz;
}

/**
 * Encrypt plain text with AES-CCM placing authentication tag on end.
 * Output buffer must be large enough to hold all data.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data including
 *                            authentication tag in bytes.
 * @param  secret   [in]      Secret key object.
 * @param  session  [in]      Session object holding CCM parameters.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCcm_Encrypt(unsigned char* plain, word32 plainSz,
                        unsigned char* enc, word32* encSz, WP11_Object* secret,
                        WP11_Session* session)
{
    int ret;
    Aes aes;
    WP11_Data* key;
    WP11_CcmParams* ccm = &session->params.ccm;
    word32 authTagSz = ccm->macSz;
    unsigned char* authTag = enc + plainSz;

    ret = wc_AesInit(&aes, NULL, session->devId);
    if (ret == 0) {
        if (secret->onToken)
            WP11_Lock_LockRO(secret->lock);
        key = &secret->data.symmKey;
        ret = wc_AesCcmSetKey(&aes, key->data, key->len);
        if (secret->onToken)
            WP11_Lock_UnlockRO(secret->lock);

        if (ret == 0)
            ret = wc_AesCcmEncrypt(&aes, enc, plain, plainSz,
                                   ccm->iv, ccm->ivSz,
                                   authTag, authTagSz,
                                   ccm->aad, ccm->aadSz);
        if (ret == 0)
            *encSz = plainSz + authTagSz;

        if (ccm->aad != NULL) {
            XFREE(ccm->aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            ccm->aad = NULL;
            ccm->aadSz = 0;
        }

        wc_AesFree(&aes);
    }

    return ret;
}

/**
 * Decrypt data, including authentication tag, with AES-CCM
 * Output buffer must be large enough to hold all decrypted data.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  AES_CCM_AUTH_E when data does not authenticate.
 *          Other -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCcm_Decrypt(unsigned char* enc, word32 encSz, unsigned char* dec,
                        word32* decSz, WP11_Object* secret,
                        WP11_Session* session)
{
    int ret;
    Aes aes;
    WP11_Data* key;
    WP11_CcmParams* ccm = &session->params.ccm;
    word32 authTagSz = ccm->macSz;
    unsigned char* authTag = enc + encSz - authTagSz;
    encSz -= authTagSz;

    ret = wc_AesInit(&aes, NULL, session->devId);
    if (ret == 0) {
        if (secret->onToken)
            WP11_Lock_LockRO(secret->lock);
        key = &secret->data.symmKey;
        ret = wc_AesCcmSetKey(&aes, key->data, key->len);
        if (secret->onToken)
            WP11_Lock_UnlockRO(secret->lock);

        if (ret == 0)
            ret = wc_AesCcmDecrypt(&aes, dec, enc, encSz,
                                   ccm->iv, ccm->ivSz,
                                   authTag, authTagSz,
                                   ccm->aad, ccm->aadSz);

        if (ret == 0) {
            *decSz = encSz;
        }

        if (ccm->aad != NULL) {
            XFREE(ccm->aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            ccm->aad = NULL;
            ccm->aadSz = 0;
        }

        wc_AesFree(&aes);
    }

    return ret;
}
#endif /* HAVE_AESCCM */

#ifdef HAVE_AESECB
/**
 * Encrypt plain text with AES-ECB.
 * Output buffer must be large enough to hold all data.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data including
 *                            authentication tag in bytes.
 * @param  secret   [in]      Secret key object.
 * @param  session  [in]      Session object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesEcb_Encrypt(unsigned char* plain, word32 plainSz,
                        unsigned char* enc, word32* encSz, WP11_Object* secret,
                        WP11_Session* session)
{
    int ret;
    Aes aes;
    WP11_Data* key;

    ret = wc_AesInit(&aes, NULL, session->devId);
    if (ret == 0) {
        if (secret->onToken)
            WP11_Lock_LockRO(secret->lock);
        key = &secret->data.symmKey;
        ret = wc_AesSetKey(&aes, key->data, key->len, NULL, AES_ENCRYPTION);
        if (secret->onToken)
            WP11_Lock_UnlockRO(secret->lock);

        if (ret == 0)
            ret = wc_AesEcbEncrypt(&aes, enc, plain, plainSz);
        if (ret == 0)
            *encSz = plainSz;

        wc_AesFree(&aes);
    }

    return ret;
}

/**
 * Decrypt data with AES-ECB.
 * Output buffer must be large enough to hold all decrypted data.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on decryption failure.
 *          0 on success.
 */
int WP11_AesEcb_Decrypt(unsigned char* enc, word32 encSz, unsigned char* dec,
                        word32* decSz, WP11_Object* secret,
                        WP11_Session* session)
{
    int ret;
    Aes aes;
    WP11_Data* key;

    ret = wc_AesInit(&aes, NULL, session->devId);
    if (ret == 0) {
        if (secret->onToken)
            WP11_Lock_LockRO(secret->lock);
        key = &secret->data.symmKey;
        ret = wc_AesSetKey(&aes, key->data, key->len, NULL, AES_DECRYPTION);
        if (secret->onToken)
            WP11_Lock_UnlockRO(secret->lock);

        if (ret == 0)
            ret = wc_AesEcbDecrypt(&aes, dec, enc, encSz);

        if (ret == 0) {
            *decSz = encSz;
        }

        wc_AesFree(&aes);
    }

    return ret;
}
#endif /* HAVE_AESECB */

#ifdef HAVE_AES_KEYWRAP
int WP11_AesKeyWrap_Encrypt(unsigned char* plain, word32 plainSz,
        unsigned char* enc, word32* encSz, WP11_Session* session)
{
    int ret = 0;
    WP11_KeyWrapParams *wrap = &session->params.kw;

    ret = wc_AesKeyWrap_ex(&wrap->aes, plain, plainSz, enc, *encSz,
            wrap->ivSz != 0 ? wrap->iv : NULL);
    session->init = 0;
    if (ret < 0)
        return ret;
    *encSz = ret;
    return 0;
}

int WP11_AesKeyWrap_Decrypt(unsigned char* enc, word32 encSz,
        unsigned char* dec, word32* decSz, WP11_Session* session)
{
    int ret = 0;
    WP11_KeyWrapParams *wrap = &session->params.kw;

    ret = wc_AesKeyUnWrap_ex(&wrap->aes, enc, encSz, dec, *decSz,
            wrap->ivSz != 0 ? wrap->iv : NULL);
    session->init = 0;
    if (ret < 0)
        return ret;
    *decSz = ret;
    return 0;
}
#endif /* HAVE_AES_KEYWRAP */

#ifdef HAVE_AESCTS
/**
 * Encrypt plain text with AES-CTS.
 * Output buffer must be large enough to hold all data.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCts_Encrypt(unsigned char* plain, word32 plainSz,
                        unsigned char* enc, word32* encSz,
                        WP11_Session* session)
{
    int ret = 0;
    WP11_CtsParams* cts = &session->params.cts;
    word32 outSz = 0;
    word32 tmpSz = *encSz;

    ret = wc_AesCtsEncryptUpdate(&cts->aes, enc, &tmpSz, plain, plainSz);
    if (ret == 0) {
        outSz += tmpSz;
        tmpSz = *encSz - outSz;
        ret = wc_AesCtsEncryptFinal(&cts->aes, enc + outSz, &tmpSz);
    }
    if (ret == 0)
        *encSz = outSz + tmpSz;

    wc_AesFree(&cts->aes);
    session->init = 0;
    return ret;
}

/**
 * Encrypt more plain text with AES-CTS.
 *
 * @param  plain    [in]      Plain text.
 * @param  plainSz  [in]      Length of plain text in bytes.
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCts_EncryptUpdate(unsigned char* plain, word32 plainSz,
                              unsigned char* enc, word32* encSz,
                              WP11_Session* session)
{
    WP11_CtsParams* cts = &session->params.cts;

    return wc_AesCtsEncryptUpdate(&cts->aes, enc, encSz, plain, plainSz);
}

/**
 * Finalize encryption with AES-CTS.
 *
 * @param  enc      [in]      Buffer to hold encrypted data.
 * @param  encSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of encrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  0 on success.
 */
int WP11_AesCts_EncryptFinal(unsigned char* enc, word32* encSz,
                             WP11_Session* session)
{
    int ret = 0;
    WP11_CtsParams* cts = &session->params.cts;

    ret = wc_AesCtsEncryptFinal(&cts->aes, enc, encSz);

    wc_AesFree(&cts->aes);
    session->init = 0;

    return ret;
}

/**
 * Decrypt data with AES-CTS.
 * Output buffer must be large enough to hold all data.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCts_Decrypt(unsigned char* enc, word32 encSz, unsigned char* dec,
                        word32* decSz, WP11_Session* session)
{
    int ret = 0;
    WP11_CtsParams* cts = &session->params.cts;
    word32 outSz = 0;
    word32 tmpSz = *decSz;

    ret = wc_AesCtsDecryptUpdate(&cts->aes, dec, &tmpSz, enc, encSz);
    if (ret == 0) {
        outSz += tmpSz;
        tmpSz = *decSz - outSz;
        ret = wc_AesCtsDecryptFinal(&cts->aes, dec + outSz, &tmpSz);
    }
    if (ret == 0)
        *decSz = outSz + tmpSz;

    wc_AesFree(&cts->aes);
    session->init = 0;
    return ret;
}

/**
 * Decrypt more data with AES-CTS.
 *
 * @param  enc      [in]      Encrypted data.
 * @param  encSz    [in]      Length of encrypted data in bytes.
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_AesCts_DecryptUpdate(unsigned char* enc, word32 encSz,
                              unsigned char* dec, word32* decSz,
                              WP11_Session* session)
{
    WP11_CtsParams* cts = &session->params.cts;

    return wc_AesCtsDecryptUpdate(&cts->aes, dec, decSz, enc, encSz);
}

/**
 * Finalize decryption with AES-CTS.
 * No decrypted data is returned as no check for padding is performed.
 *
 * @param  dec      [in]      Buffer to hold decrypted data.
 * @param  decSz    [in,out]  On in, length of buffer in bytes.
 *                            On out, length of decrypted data in bytes.
 * @param  session  [in]      Session object holding Aes object.
 * @return  0 on success.
 */
int WP11_AesCts_DecryptFinal(unsigned char* dec, word32* decSz,
                             WP11_Session* session)
{
    int ret = 0;
    WP11_CtsParams* cts = &session->params.cts;

    ret = wc_AesCtsDecryptFinal(&cts->aes, dec, decSz);

    wc_AesFree(&cts->aes);
    session->init = 0;

    return ret;
}
#endif /* HAVE_AESCTS */

#ifdef HAVE_AESCMAC
int WP11_Aes_Cmac_Init(WP11_Object* secret, WP11_Session* session,
        word32 sigLen)
{
    int ret;
    WP11_Cmac* cmac = &session->params.cmac;
    WP11_Data* key;

    if (sigLen > WC_CMAC_TAG_MAX_SZ || sigLen < WC_CMAC_TAG_MIN_SZ)
        return BAD_FUNC_ARG;
    cmac->sigLen = (byte)sigLen;
    if (secret->onToken)
        WP11_Lock_LockRO(secret->lock);
    key = &secret->data.symmKey;
    ret = wc_InitCmac_ex(&cmac->cmac, key->data, key->len, WC_CMAC_AES, NULL,
            NULL, secret->slot->devId);
    if (secret->onToken)
        WP11_Lock_UnlockRO(secret->lock);

    return ret;
}

int WP11_Aes_Cmac_Check_Len(CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen, WP11_Session* session)
{
    WP11_Cmac* cmac = &session->params.cmac;

    if (pSignature == NULL) {
        *pulSignatureLen = cmac->sigLen;
        return CKR_OK;
    }
    if (*pulSignatureLen < cmac->sigLen)
        return CKR_BUFFER_TOO_SMALL;

    return CKR_OK;
}

int WP11_Aes_Cmac_Sign(unsigned char* data, word32 dataLen, unsigned char* sig,
        word32* sigLen, WP11_Session* session)
{
    int ret = 0;
    WP11_Cmac* cmac = &session->params.cmac;
    int doFree = 1;

    if (*sigLen < cmac->sigLen)
        return BAD_FUNC_ARG;
    *sigLen = (word32)cmac->sigLen;
    ret = wc_CmacUpdate(&cmac->cmac, data, dataLen);
    if (ret == 0) {
        ret = wc_CmacFinal(&cmac->cmac, sig, sigLen);
        doFree = 0;
    }
    if (doFree) {
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3))
        (void)wc_CmacFree(&cmac->cmac);
#endif
    }
    session->init = 0;

    return ret;
}

int WP11_Aes_Cmac_Sign_Update(unsigned char* data, word32 dataLen,
        WP11_Session* session)
{
    WP11_Cmac* cmac = &session->params.cmac;

    return wc_CmacUpdate(&cmac->cmac, data, dataLen);
}

int WP11_Aes_Cmac_Sign_Final(unsigned char* sig, word32* sigLen,
        WP11_Session* session)
{
    int ret = 0;
    WP11_Cmac* cmac = &session->params.cmac;

    if (*sigLen < cmac->sigLen)
        return BAD_FUNC_ARG;
    *sigLen = (word32)cmac->sigLen;
    ret = wc_CmacFinal(&cmac->cmac, sig, sigLen);
    session->init = 0;

    return ret;
}

int WP11_Aes_Cmac_Verify(unsigned char* data, word32 dataLen,
        unsigned char* sig, word32 sigLen, int* stat, WP11_Session* session)
{
    byte resSig[WC_CMAC_TAG_MAX_SZ];
    word32 resSigLen = sigLen;
    int ret = 0;
    WP11_Cmac* cmac = &session->params.cmac;

    if (sigLen != (word32)cmac->sigLen || sigLen > sizeof(resSig))
        ret = BUFFER_E;
    if (ret == 0)
        ret = WP11_Aes_Cmac_Sign(data, dataLen, resSig, &resSigLen, session);
    if (ret == 0)
        *stat = resSigLen == sigLen && WP11_ConstantCompare(resSig, sig, sigLen);

    return ret;
}

int WP11_Aes_Cmac_Verify_Final(unsigned char* sig, word32 sigLen, int* stat,
        WP11_Session* session)
{
    int ret = 0;
    byte resSig[WC_CMAC_TAG_MAX_SZ];
    word32 resSigLen = sigLen;
    WP11_Cmac* cmac = &session->params.cmac;

    if (sigLen != (word32)cmac->sigLen || sigLen > sizeof(resSig))
        ret = BUFFER_E;
    if (ret == 0)
        ret = WP11_Aes_Cmac_Sign_Final(resSig, &resSigLen, session);
    if (ret == 0)
        *stat = resSigLen == sigLen && WP11_ConstantCompare(resSig, sig, sigLen);

    return ret;
}
#endif /* HAVE_AESCMAC */
#endif /* !NO_AES */

/**
 * Convert the Digest mechanism to a wolfCrypt hash type.
 *
 * @param  digestMech  [in]   Digest mechanism.
 * @param  hashType    [out]  Hash type.
 * @return  BAD_FUNC_ARG when mechanism is not supported.
 *          0 on success.
 */
static int wp11_digest_hash_type(CK_MECHANISM_TYPE digestMech, int* hashType)
{
    int ret = 0;

    switch (digestMech) {
        case CKM_MD5:
            *hashType = WC_HASH_TYPE_MD5;
            break;
        case CKM_SHA1:
            *hashType = WC_HASH_TYPE_SHA;
            break;
        case CKM_SHA224:
            *hashType = WC_HASH_TYPE_SHA224;
            break;
        case CKM_SHA256:
            *hashType = WC_HASH_TYPE_SHA256;
            break;
        case CKM_SHA384:
            *hashType = WC_HASH_TYPE_SHA384;
            break;
        case CKM_SHA512:
            *hashType = WC_HASH_TYPE_SHA512;
            break;
        case CKM_SHA3_224:
            *hashType = WC_HASH_TYPE_SHA3_224;
            break;
        case CKM_SHA3_256:
            *hashType = WC_HASH_TYPE_SHA3_256;
            break;
        case CKM_SHA3_384:
            *hashType = WC_HASH_TYPE_SHA3_384;
            break;
        case CKM_SHA3_512:
            *hashType = WC_HASH_TYPE_SHA3_512;
            break;
        default:
            ret = CKR_MECHANISM_INVALID;
            break;
    }

    return ret;
}


/**
 * Initialize the Digest operation
 *
 * @param mechanism   [in] Digest mechanism.
 * @param session     [in] Session object with the Digest object.
 * @return CKR_MECHANISM_INVALID when the mechanism is not supported.
 *         Other -ve value when initialization fails.
 *         0 on success.
 */
int WP11_Digest_Init(CK_MECHANISM_TYPE mechanism, WP11_Session* session)
{
    int ret = 0;
    int hashType = WC_HASH_TYPE_NONE;

    WP11_Digest* digest = &session->params.digest;

    ret = wp11_digest_hash_type(mechanism, &hashType);

    if (ret == 0) {
        digest->hashType = hashType;
        ret = wc_HashInit(&digest->hash, hashType);
    }

    return ret;
}

/**
* Update Digest operation with more data.
*
* @param  data     [in]  Data to be digested.
* @param  dataLen  [in]  Length of data in bytes.
* @param  session  [in]  Session object with the Digest object.
* @return  -ve on failure.
*          0 on success.
*/
int WP11_Digest_Update(unsigned char* data, word32 dataLen,
                       WP11_Session* session)
{
    int ret;
    WP11_Digest* digest = &session->params.digest;

    ret = wc_HashUpdate(&digest->hash, digest->hashType, data, dataLen);

    return ret;
}

/**
* Update Digest operation with secret key data.
*
* @param  key      [in]  Key to be digested.
* @param  session  [in]  Session object with the Digest object.
* @return  -ve on failure.
*          0 on success.
*/
int WP11_Digest_Key(WP11_Object* key, WP11_Session* session)
{
    int ret;
#ifndef WOLFPKCS11_NO_STORE
    WP11_Digest* digest = &session->params.digest;
    ret = wc_HashUpdate(&digest->hash, digest->hashType, key->keyData,
                        key->keyDataLen);
#else
    (void) session;
    (void) key;
    ret = CKR_FUNCTION_NOT_SUPPORTED;
#endif
    return ret;
}

/**
 * Finalize the Digest operation and get output.
 *
 * @param  data     [in]       Output data.
 * @param  dataLen  [in, out]  Length of data in bytes.
 * @param  session  [in]       Session object with the Digest object.
 * @return  -ve on failure.
 *          0 on success.
 */
int WP11_Digest_Final(unsigned char* data, word32* dataLen,
                      WP11_Session* session)
{
    int ret;
    int blockLen;
    WP11_Digest* digest = &session->params.digest;

    blockLen = wc_HashGetDigestSize(digest->hashType);

    /* If a NULL is provided, callee wants the expected output length only */
    if (data == NULL) {
        *dataLen = blockLen;
        return CKR_OK;
    }

    if (*dataLen < (word32)blockLen) {
        return BUFFER_E;
    }

    ret = wc_HashFinal(&digest->hash, digest->hashType, data);
    *dataLen = blockLen;
    wc_HashFree(&digest->hash, digest->hashType);

    return ret;
}

/**
 * Single Digest operation.
 *
 * @param  data        [in]       Input data to be digested.
 * @param  dataLen     [in]       Length of data in bytes.
 * @param  dataOut     [in]       Output data.
 * @param  dataOutLen  [in, out]  Lenget of dataOut in bytes.
 * @param  session     [in]       Session object with the Digest object.
 * @return  -ve on failure.
 *          0 on success.
 */

int WP11_Digest_Single(unsigned char* data, word32 dataLen,
                       unsigned char* dataOut, word32* dataOutLen,
                       WP11_Session* session)
{
    int ret;
    int blockLen;
    WP11_Digest* digest = &session->params.digest;

    blockLen = wc_HashGetDigestSize(digest->hashType);

    if (data == NULL) {
        *dataOutLen = (word32)blockLen;
        return CKR_OK;
    }
    if (*dataOutLen < (word32)blockLen) {
        return BUFFER_E;
    }
    ret = wc_Hash(digest->hashType, data, dataLen, dataOut, *dataOutLen);

    wc_HashFree(&digest->hash, digest->hashType);

    return ret;
}

#ifndef NO_HMAC
/**
 * Convert the HMAC mechanism to a wolfCrypt hash type.
 *
 * @param  hmacMech  [in]   HMAC mechanism.
 * @param  hashType  [out]  Hash type.
 * @return  BAD_FUNC_ARG when mechanism is not supported.
 *          0 on success.
 */
static int wp11_hmac_hash_type(CK_MECHANISM_TYPE hmacMech, int* hashType)
{
    int ret = 0;

    switch (hmacMech) {
        case CKM_MD5_HMAC:
            *hashType = WC_MD5;
            break;
        case CKM_SHA1_HMAC:
            *hashType = WC_SHA;
            break;
        case CKM_SHA224_HMAC:
            *hashType = WC_SHA224;
            break;
        case CKM_SHA256_HMAC:
            *hashType = WC_SHA256;
            break;
        case CKM_SHA384_HMAC:
            *hashType = WC_SHA384;
            break;
        case CKM_SHA512_HMAC:
            *hashType = WC_SHA512;
            break;
        case CKM_SHA3_224_HMAC:
            *hashType = WC_SHA3_224;
            break;
        case CKM_SHA3_256_HMAC:
            *hashType = WC_SHA3_256;
            break;
        case CKM_SHA3_384_HMAC:
            *hashType = WC_SHA3_384;
            break;
        case CKM_SHA3_512_HMAC:
            *hashType = WC_SHA3_512;
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

/**
 * Return the length of a signature in bytes.
 *
 * @param  session  [in]  Session object.
 * @return  Length of HMAC signature in bytes.
 */
int WP11_Hmac_SigLen(WP11_Session* session)
{
    WP11_Hmac* hmac = &session->params.hmac;

    return hmac->hmacSz;
}


/**
 * Initialize the HMAC operation.
 *
 * @param  mechanism  [in]  HMAC mechanism.
 * @param  secret     [in]  Secret key object.
 * @param  session    [in]  Session object with the Hmac object.
 * @return  BAD_FUNC_ARG when the mechanism is not supported.
 *          Other -ve value when hashing PIN fails.
 *          0 on success.
 */
int WP11_Hmac_Init(CK_MECHANISM_TYPE mechanism, WP11_Object* secret,
                   WP11_Session* session, CK_ULONG digestSize)
{
    int ret;
    int hashType = WC_HASH_TYPE_NONE;
    WP11_Hmac* hmac = &session->params.hmac;
    WP11_Data* key;

    ret = wp11_hmac_hash_type(mechanism, &hashType);
    if (ret == 0)
        hmac->hmacSz = wc_HmacSizeByType(hashType);
    if (ret == 0 && digestSize != 0 && hmac->hmacSz != (word32)digestSize)
        ret = BAD_FUNC_ARG;
    if (ret == 0)
        ret = wc_HmacInit(&hmac->hmac, NULL, secret->slot->devId);
    if (ret == 0) {
        if (secret->onToken)
            WP11_Lock_LockRO(secret->lock);
        key = secret->data.symmKey;
        ret = wc_HmacSetKey(&hmac->hmac, hashType, key->data, key->len);
        if (secret->onToken)
            WP11_Lock_UnlockRO(secret->lock);
    }

    return ret;
}

/**
 * Sign the data using HMAC.
 *
 * @param  data     [in]      Data to sign.
 * @param  dataLen  [in]      Length of data in bytes.
 * @param  sig      [in]      Buffer to hold signature.
 * @param  sigLen   [in,out]  On in, the length of the buffer in bytes.
 *                            On out, the length of the signature in bytes.
 * @param  session  [in]      Session object with the Hmac object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_Hmac_Sign(unsigned char* data, word32 dataLen, unsigned char* sig,
                   word32* sigLen, WP11_Session* session)
{
    int ret = 0;
    WP11_Hmac* hmac = &session->params.hmac;

    if (*sigLen < hmac->hmacSz)
        ret = BUFFER_E;
    if (ret == 0)
        ret = wc_HmacUpdate(&hmac->hmac, data, dataLen);
    if (ret == 0)
        ret = wc_HmacFinal(&hmac->hmac, sig);
    if (ret == 0)
        *sigLen = hmac->hmacSz;
    wc_HmacFree(&hmac->hmac);
    session->init = 0;

    return ret;
}

/**
 * Verify the data using HMAC.
 *
 * @param  data     [in]   Data to verify.
 * @param  dataLen  [in]   Length of data in bytes.
 * @param  sig      [in]   Signature data.
 * @param  sigLen   [in]   Length of the signature in bytes.
 * @param  stat     [out]  Status of verification. 1 on success, otherwise 0.
 * @param  session  [in]   Session object with the Hmac object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_Hmac_Verify(unsigned char* sig, word32 sigLen, unsigned char* data,
                     word32 dataLen, int* stat, WP11_Session* session)
{
    int ret = 0;
    unsigned char genSig[WC_MAX_DIGEST_SIZE];
    word32 genSigLen = sizeof(genSig);

    if (ret == 0)
        ret = WP11_Hmac_Sign(data, dataLen, genSig, &genSigLen, session);
    if (ret == 0)
        *stat = genSigLen == sigLen && WP11_ConstantCompare(sig, genSig, sigLen);

    return ret;
}

/**
 * Update HMAC sign/verify operation with more data.
 *
 * @param  data     [in]  Data to sign.
 * @param  dataLen  [in]  Length of data in bytes.
 * @param  session  [in]  Session object with the Hmac object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_Hmac_Update(unsigned char* data, word32 dataLen, WP11_Session* session)
{
    int ret;
    WP11_Hmac* hmac = &session->params.hmac;

    ret = wc_HmacUpdate(&hmac->hmac, data, dataLen);

    return ret;
}

/**
 * Finalize HMAC signing.
 *
 * @param  sig      [in]      Buffer to hold signature.
 * @param  sigLen   [in,out]  On in, the length of the buffer in bytes.
 *                            On out, the length of the signature in bytes.
 * @param  session  [in]      Session object with the Hmac object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_Hmac_SignFinal(unsigned char* sig, word32* sigLen,
                        WP11_Session* session)
{
    int ret = 0;
    WP11_Hmac* hmac = &session->params.hmac;

    if (*sigLen < hmac->hmacSz)
        ret = BUFFER_E;
    if (ret == 0)
        ret = wc_HmacFinal(&hmac->hmac, sig);
    if (ret == 0)
        *sigLen = hmac->hmacSz;
    wc_HmacFree(&hmac->hmac);
    session->init = 0;

    return ret;
}

/**
 * Verify the data using HMAC.
 *
 * @param  sig      [in]   Signature data.
 * @param  sigLen   [in]   Length of the signature in bytes.
 * @param  stat     [out]  Status of verification. 1 on success, otherwise 0.
 * @param  session  [in]   Session object with the Hmac object.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_Hmac_VerifyFinal(unsigned char* sig, word32 sigLen, int* stat,
                          WP11_Session* session)
{
    int ret;
    unsigned char genSig[WC_MAX_DIGEST_SIZE];
    word32 genSigLen = sizeof(genSig);

    ret = WP11_Hmac_SignFinal(genSig, &genSigLen, session);
    if (ret == 0)
        *stat = genSigLen == sigLen && WP11_ConstantCompare(sig, genSig, sigLen);

    return ret;
}
#endif /* !NO_HMAC */

#ifdef WOLFSSL_HAVE_PRF
int WP11_TLS_MAC_init(unsigned long hashType, unsigned long macLen, byte server,
                      CK_OBJECT_HANDLE hKey, WP11_Session *session)
{
    int ret = 0;
    WP11_TlsMacParams *mac = &session->params.tlsMac;

    XMEMSET(mac, 0, sizeof(*mac));
    if (hashType == CKM_TLS_PRF) {
        mac->isTlsPrf = 1;
    }
    else {
        if ((mac->mac = MechToMac(hashType)) == no_mac)
            return BAD_FUNC_ARG;
    }
    mac->server = server;
    mac->macSz = (word32)macLen;
    mac->key = hKey;


    return ret;
}


word32 WP11_TLS_MAC_get_len(WP11_Session *session)
{
    WP11_TlsMacParams *mac = &session->params.tlsMac;

    return mac->macSz;
}

int WP11_TLS_MAC_sign(byte* data, word32 dataLen, byte* sig, word32* sigLen,
                      WP11_Session *session)
{
    int ret = 0;
    WP11_TlsMacParams *mac = &session->params.tlsMac;
    const byte* label = (const byte*)(mac->server ?
            "server finished" : "client finished");
    WP11_Data* key = NULL;
    WP11_Object* secret = NULL;

    if (mac->macSz > *sigLen)
        return BAD_FUNC_ARG;

    ret = WP11_Object_Find(session, mac->key, &secret);
    if (ret != 0)
        return BAD_FUNC_ARG;
    if (secret->type != CKK_GENERIC_SECRET)
        return BAD_FUNC_ARG;

    if (secret->onToken)
        WP11_Lock_LockRO(secret->lock);
    key = secret->data.symmKey;

    PRIVATE_KEY_UNLOCK();
    if (mac->isTlsPrf) {
        ret = wc_PRF_TLSv1(sig, mac->macSz, key->data, key->len, label, 15,
                data, dataLen, NULL, secret->slot->devId);
    }
    else {
        ret = wc_PRF_TLS(sig, mac->macSz, key->data, key->len, label, 15,
                data, dataLen, 1, mac->mac, NULL, secret->slot->devId);
    }
    PRIVATE_KEY_LOCK();

    if (secret->onToken)
        WP11_Lock_UnlockRO(secret->lock);

    if (ret == 0)
        *sigLen = mac->macSz;

    session->init = 0;
    return ret;
}

int WP11_TLS_MAC_verify(byte* data, word32 dataLen, byte* sig, word32 sigLen,
        int* stat, WP11_Session *session)
{
    int ret = 0;
    byte* genSig;
    word32 genSigLen = sigLen;
    WP11_TlsMacParams *mac = &session->params.tlsMac;

    if (sigLen != mac->macSz)
        return BUFFER_E;

    genSig = (byte*)XMALLOC(genSigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (genSig == NULL)
        return MEMORY_E;

    ret = WP11_TLS_MAC_sign(data, dataLen, genSig, &genSigLen, session);
    if (ret == 0) {
        *stat = genSigLen == sigLen
                && WP11_ConstantCompare(sig, genSig, sigLen);
    }

    XFREE(genSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    session->init = 0;
    return ret;
}
#endif /* WOLFSSL_HAVE_PRF */

/**
 * Seed the random number generator of the token in the slot.
 *
 * @param  slot     [in]  Slot object with token that has random number
 *                        generator.
 * @param  seed     [in]  Seed data.
 * @param  seedLen  [in]  Length of seed data.
 * @return  -ve on encryption failure.
 *          0 on success.
 */
int WP11_Slot_SeedRandom(WP11_Slot* slot, unsigned char* seed, int seedLen)
{
    int ret;

    WP11_Lock_LockRW(&slot->token.rngLock);
    wc_FreeRng(&slot->token.rng);
    ret = wc_InitRngNonce_ex(&slot->token.rng, seed, seedLen, NULL,
                                                                 INVALID_DEVID);
    WP11_Lock_UnlockRW(&slot->token.rngLock);

    return ret;
}

/**
 * Generate random data using random number generator of the token in the slot.
 *
 * @param  slot  [in]  Slot object with token that has random number generator.
 * @param  data  [in]  Buffer to hold random data.
 * @param  len   [in]  Amount of random data to generate in bytes.
 */
int WP11_Slot_GenerateRandom(WP11_Slot* slot, unsigned char* data, int len)
{
    int ret;

    WP11_Lock_LockRW(&slot->token.rngLock);
    ret = wc_RNG_GenerateBlock(&slot->token.rng, data, len);
    WP11_Lock_UnlockRW(&slot->token.rngLock);

    return ret;
}

int WP11_GetOperationState(WP11_Session* session, unsigned char* stateData,
                           unsigned long* stateDataLen)
{
    unsigned long bufferAvailable = *stateDataLen;
    unsigned long mechSize = 0;
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05007004
    wc_HashAlg* hashAlg;
#else
    wc_Hashes* hashAlg;
#endif

    *stateDataLen = sizeof(session->mechanism);

    switch (session->mechanism) {
#ifndef NO_SHA
        case CKM_SHA1:
            mechSize = sizeof(wc_Sha);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_SHA224:
            mechSize = sizeof(wc_Sha224);
            break;
#endif
#ifndef NO_SHA256
        case CKM_SHA256:
            mechSize = sizeof(wc_Sha256);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_SHA384:
            mechSize = sizeof(wc_Sha384);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_SHA512:
            mechSize = sizeof(wc_Sha512);
            break;
#endif
        default:
            return CKR_STATE_UNSAVEABLE;
    }
    *stateDataLen += mechSize;

    if (bufferAvailable < *stateDataLen)
        return CKR_BUFFER_TOO_SMALL;

    if (stateData == NULL)
        return CKR_OK;

    XMEMCPY(stateData, &session->mechanism, sizeof(session->mechanism));
    stateData += sizeof(session->mechanism);

#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05007004
    hashAlg = &session->params.digest.hash;
#else
    hashAlg = &session->params.digest.hash.alg;
#endif


    switch (session->mechanism) {
#ifndef NO_SHA
        case CKM_SHA1:
            wc_ShaCopy(&hashAlg->sha, (wc_Sha*)stateData);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_SHA224:
            wc_Sha224Copy(&hashAlg->sha224, (wc_Sha224*)stateData);
            break;
#endif
#ifndef NO_SHA256
        case CKM_SHA256:
            wc_Sha256Copy(&hashAlg->sha256, (wc_Sha256*)stateData);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_SHA384:
            wc_Sha384Copy(&hashAlg->sha384, (wc_Sha384*)stateData);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_SHA512:
            wc_Sha512Copy(&hashAlg->sha512, (wc_Sha512*)stateData);
            break;
#endif
    }

    return CKR_OK;
}

int WP11_SetOperationState(WP11_Session* session, unsigned char* stateData,
                           unsigned long stateDataLen)
{
    unsigned long mechSize = 0;
    int hashType = WC_HASH_TYPE_NONE;
    int ret;
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05007004
    wc_HashAlg* hashAlg;
#else
    wc_Hashes* hashAlg;
#endif

    if (stateDataLen < sizeof(session->mechanism))
        return CKR_SAVED_STATE_INVALID;

    XMEMCPY(&session->mechanism, stateData, sizeof(session->mechanism));
    switch (session->mechanism) {
#ifndef NO_SHA
        case CKM_SHA1:
            mechSize = sizeof(wc_Sha);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_SHA224:
            mechSize = sizeof(wc_Sha224);
            break;
#endif
#ifndef NO_SHA256
        case CKM_SHA256:
            mechSize = sizeof(wc_Sha256);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_SHA384:
            mechSize = sizeof(wc_Sha384);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_SHA512:
            mechSize = sizeof(wc_Sha512);
            break;
#endif
        default:
            return CKR_SAVED_STATE_INVALID;
    }

    if (stateDataLen < (sizeof(session->mechanism) + mechSize))
        return CKR_SAVED_STATE_INVALID;

    stateData += sizeof(session->mechanism);

    ret = wp11_digest_hash_type(session->mechanism, &hashType);

    if (ret != CKR_OK)
        return ret;

    session->params.digest.hashType = hashType;
    ret = wc_HashInit(&session->params.digest.hash, hashType);

    if (ret != CKR_OK)
        return ret;

    #if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05007004
        hashAlg = &session->params.digest.hash;
    #else
        hashAlg = &session->params.digest.hash.alg;
    #endif

    switch (session->mechanism) {
#ifndef NO_SHA
        case CKM_SHA1:
            wc_ShaCopy((wc_Sha*)stateData, &hashAlg->sha);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case CKM_SHA224:
            wc_Sha224Copy((wc_Sha224*)stateData, &hashAlg->sha224);
            break;
#endif
#ifndef NO_SHA256
        case CKM_SHA256:
            wc_Sha256Copy((wc_Sha256*)stateData, &hashAlg->sha256);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case CKM_SHA384:
            wc_Sha384Copy((wc_Sha384*)stateData, &hashAlg->sha384);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case CKM_SHA512:
            wc_Sha512Copy((wc_Sha512*)stateData, &hashAlg->sha512);
            break;
#endif
    }

    return CKR_OK;
}
