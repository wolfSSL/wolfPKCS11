/* wp11_types.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* Layout of the objects that wolfpkcs11/internal.h keeps opaque. */

#ifndef WOLFPKCS11_WP11_TYPES_H
#define WOLFPKCS11_WP11_TYPES_H

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif
#include "wolfpkcs11/pkcs11.h"

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
#ifdef WOLFPKCS11_MLKEM
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif

#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_CUSTOM_STORE)
/* OS-specific includes for directory creation */
#if defined(_WIN32) || defined(_MSC_VER)
    #include <direct.h>
    #include <io.h>
    #define MKDIR(path) _mkdir(path)
#else
    #include <sys/stat.h>
    #define MKDIR(path) mkdir(path, 0700)
#endif
#endif

#if !defined(WOLFPKCS11_NO_STORE) && !defined(WOLFPKCS11_CUSTOM_STORE)
    #include <errno.h>
    #include <time.h>
    #if defined(_WIN32) || defined(_MSC_VER)
        #include <windows.h>
        #include <fcntl.h>
        #include <sys/stat.h>
        #include <process.h>
    #else
        #include <sys/types.h>
        #include <fcntl.h>
        #include <unistd.h>
    #endif
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



#ifndef WP11_MAX_CERT_SZ
#define WP11_MAX_CERT_SZ              4096
#endif

/* Initial allocation when reading a variable-length array from storage. */
#ifndef WP11_STORE_READ_CHUNK_SZ
#define WP11_STORE_READ_CHUNK_SZ      4096
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

/* Largest object id. The id is the low 28 bits of an object handle and the
 * onToken flag is bit 28, so a larger id would change the flag. */
#define OBJ_ID_MAX                     0x0fffffff
/* Create an object handle from a onToken and object id. */
#define OBJ_HANDLE(on, i)              (((on) << 28) | (i))
/* Determine whether object is onToken from object handle. */
#define OBJ_HANDLE_ON_TOKEN(h)         ((int)((h) >> 28))
/* Determine object id from object handle. */
#define OBJ_HANDLE_OBJ_ID(h)           ((h) & OBJ_ID_MAX)

/* SINGLE_THREADED alters wolfSSL struct layouts; only wolfSSL sets it. */
#if defined(SINGLE_THREADED) || defined(WOLFPKCS11_SINGLE_THREADED)
    #define WP11_NO_LOCKING
#endif

#ifdef WP11_NO_LOCKING
/* Disable locking. */
typedef int WP11_Lock;

#define WP11_Lock_Init(l)              ({ 0; })
#define WP11_Lock_Free(l)
#define WP11_Lock_LockRW(l)            ({ 0; })
#define WP11_Lock_UnlockRW(l)          ({ 0; })
#define WP11_Lock_LockRO(l)            ({ 0; })
#define WP11_Lock_UnlockRO(l)          ({ 0; })

#elif defined(WOLFSSL_PTHREADS) || (defined(USE_WINDOWS_API) && \
      !defined(_WIN32_WCE) && defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600)
/* Reader/writer lock built from a mutex and a condition variable. The mutex
 * only guards the counters and is never held while the lock itself is held,
 * so the last reader out can release the lock without unlocking a mutex it
 * does not own. As with the two-mutex lock below, a waiting writer does not
 * stop new readers, so a thread may take the read lock again while holding
 * it. Uses the same threading API as wolfSSL_Mutex: pthreads, or a critical
 * section and condition variable on Windows (Vista and later). */
#define WP11_LOCK_COND

#ifdef WOLFSSL_PTHREADS
typedef pthread_mutex_t WP11_LockMutex;
typedef pthread_cond_t WP11_LockCond;
#else
typedef CRITICAL_SECTION WP11_LockMutex;
typedef CONDITION_VARIABLE WP11_LockCond;
#endif

typedef struct WP11_Lock {
    WP11_LockMutex mutex;              /* Mutex for accessing counters        */
    WP11_LockCond cond;                /* Signalled when lock may be free     */
    int cnt;                           /* Count of readers                    */
    int writer;                        /* Whether a writer holds the lock     */
} WP11_Lock;
#elif defined(USE_WINDOWS_API)
/* The fallback below leaves a critical section from a thread that did not
 * enter it, which is undefined behaviour on Windows. */
#error "wolfPKCS11 locking needs Windows Vista or later (_WIN32_WINNT >= 0x0600, not Windows CE); set _WIN32_WINNT or build single threaded"
#else
/* Fallback for threading APIs without a condition variable. The first reader
 * locks the write mutex and the last reader unlocks it, which may be a
 * different thread: only correct where wolfSSL_Mutex may be released by a
 * thread that did not lock it (e.g. a binary semaphore). */
typedef struct WP11_Lock {
    wolfSSL_Mutex read;                /* Mutex for accessing count           */
    wolfSSL_Mutex write;               /* Mutex for writing                   */
    int cnt;                           /* Count of readers                    */
} WP11_Lock;
#endif

/* Symmetric key data. */
typedef struct WP11_Data {
    byte data[WP11_MAX_SYM_KEY_SZ];    /* Key data                            */
    word32 len;                        /* Length of key data in bytes         */
} WP11_Data;

typedef struct WP11_GenericData {
    byte *data;
    word32 dataLen;
    byte *application;
    word32 applicationLen;
    byte *objectId;                    /* CKA_OBJECT_ID, a DER encoded ID     */
    word32 objectIdLen;
} WP11_GenericData;

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

#ifdef WOLFSSL_HAVE_PRF
/* How a secret is tied to TLS 1.2 key material. */
typedef struct WP11_Tls12KeyMat {
    CK_ULONG macBits;                  /* MAC secret size in bits             */
    CK_ULONG keyBits;                  /* Cipher key size in bits             */
    CK_ULONG ivBits;                   /* IV size in bits                     */
    word32 running;                    /* Derives running with the sizes      */
    int prf;                           /* MAC algorithm of the PRF hash       */
    byte tlsOnly:1;                    /* Kept to the TLS mechanisms          */
    byte sized:1;                      /* Sizes have been recorded            */
    byte used:1;                       /* Keys or IVs were made with sizes    */
} WP11_Tls12KeyMat;
#endif

/* When adding/modifying new members, add support in WP11_Object_Copy */
struct WP11_Object {
    union {
    #ifndef NO_RSA
        RsaKey* rsaKey;                /* RSA key object                      */
    #endif
    #ifdef HAVE_ECC
        ecc_key* ecKey;                /* EC key object                       */
    #endif
    #ifdef WOLFPKCS11_MLDSA
        wc_MlDsaKey* mldsaKey;            /* ML-DSA key object                   */
    #endif
    #ifndef NO_DH
        WP11_DhKey* dhKey;             /* DH parameters object                */
    #endif
    #ifdef WOLFPKCS11_MLKEM
        MlKemKey* mlKemKey;            /* ML-KEM key object                   */
    #endif
    #ifdef WOLFPKCS11_LMS
        LmsKey* lmsKey;                /* LMS/HSS key object (verify)         */
    #endif
    #ifdef WOLFPKCS11_XMSS
        XmssKey* xmssKey;              /* XMSS/XMSS^MT key object (verify)    */
    #endif
        WP11_Data* symmKey;            /* Symmetric key object                */
        WP11_GenericData genericData;  /* Generic data object                 */
        WP11_Cert cert;                /* Certificate object                  */
    #ifdef WOLFPKCS11_NSS
        WP11_Trust trust;              /* Trust object                        */
    #endif
    } data;
#ifdef WOLFPKCS11_TPM
    WOLFTPM2_KEYBLOB* tpmKey;
#endif
#ifdef WOLFSSL_STM32U5_DHUK
    unsigned char* dhukIv; /* IV used with wrapping and unwrapping AES key.  */
    int dhukIvLen;
#endif
    CK_KEY_TYPE type;                  /* Key type of this object             */
    word32 size;                       /* Size of the key in bits or bytes    */
#ifndef WOLFPKCS11_NO_STORE
    unsigned char* keyData;            /* Encoded key data                    */
    int keyDataLen;                    /* Length of encoded key data          */
    byte iv[GCM_NONCE_MID_SZ];         /* IV/nonce for encrypt/decrypt        */
    byte encoded:1;                    /* Key isn't in decoded form           */
    byte undecoded:1;                  /* Loaded key data not yet decoded     */
    byte unbound:1;                    /* Key data not bound to the policy    */
#endif

    WP11_Session* session;             /* Session object belongs to           */
    WP11_Slot* slot;                   /* Slot object belongs to              */

    CK_OBJECT_HANDLE handle;           /* Handle of this object               */
    CK_OBJECT_CLASS objClass;          /* Object class                        */
    CK_MECHANISM_TYPE keyGenMech;      /* Key Gen mechanism created with      */
    byte onToken:1;                    /* Object on token or session          */
    byte local:1;                      /* Locally created object              */
    word32 opFlag;                     /* Flags of operations allowed         */
    word32 freeEpoch;                  /* Call epoch the object was unlinked */
    word32 logoutCnt;                  /* Slot logouts when it was removed    */
    word32 addLogoutCnt;               /* User logouts when it was created    */
    byte unlinked;                     /* Destroyed or retired by logout      */
    byte replaced;                     /* Unlinked by a reload of the token,
                                        * with the key unchanged              */

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
#ifdef WOLFPKCS11_NSS
    unsigned char* email;              /* Certificate email (NSS extension)   */
    int emailLen;                      /* Length of certificate email         */
#endif
    unsigned char* attrTmpl;           /* Encoded attribute-array templates   */
    int attrTmplLen;                   /* Length of encoded templates         */

    word32 category;                   /* Category of certificate             */
#ifdef WOLFSSL_HAVE_PRF
    WP11_Tls12KeyMat tlsKeyMat;        /* TLS 1.2 key material tie            */
#endif

    WP11_Lock* lock;                   /* Object specific lock                */

    int devId;
    WP11_Object* next;                 /* Next object in linked list          */
};

typedef struct WP11_Find {
    int state;                         /* Whether operation is initialized    */
    CK_OBJECT_HANDLE* found;
                                       /* List of object handles found        */
    int count;                         /* Count of object handles             */
    int curr;                          /* Index of last object returned       */
    int capacity;                      /* Allocated entries in found          */
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

#ifdef WOLFPKCS11_MLDSA
typedef struct WP11_MldsaParams {
    enum wc_HashType preHashType;
    word32 hedgeType;
    byte ctx[256];
    byte ctxSz;
} WP11_MldsaParams;
#endif

#ifndef NO_AES
#ifdef HAVE_AES_CBC
typedef struct WP11_CbcParams {
    unsigned char iv[WP11_MAX_IV_SZ];  /* IV of CBC operation                 */
    Aes aes;                           /* AES object from wolfCrypt           */
    unsigned char partial[AES_BLOCK_SIZE];
                                       /* Partial block when streaming        */
    unsigned char final[AES_BLOCK_SIZE];
                                       /* Decrypted final block for retry     */
    byte partialSz;                    /* Size of partial block data          */
    byte finalReady;                   /* Final block has been decrypted      */
} WP11_CbcParams;
#endif

#ifdef HAVE_AESCTR
typedef struct WP11_CtrParams {
    Aes aes;                           /* AES object from wolfCrypt           */
    unsigned char counter[AES_BLOCK_SIZE];
                                       /* Next counter block to use           */
    byte counterBits;                  /* Bits in counter field               */
    byte offset;                       /* Bytes used in current stream block  */
    byte exhausted;                    /* Counter field has wrapped           */
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
    unsigned char* enc;                /* Cached data for multi-part: buffered */
                                       /* ciphertext (decrypt) or, without     */
                                       /* streaming GCM, plaintext (encrypt)   */
    int encSz;                         /* Size of cached data in bytes         */
#ifdef WOLFSSL_AESGCM_STREAM
    Aes aes;                           /* Streaming context for multi-part    */
                                       /* encrypt                             */
    int streamInit;                    /* Streaming context is initialized    */
#endif
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

#ifdef HAVE_AESECB
typedef struct WP11_EcbParams {
    unsigned char partial[AES_BLOCK_SIZE];
                                       /* Partial block when streaming        */
    byte partialSz;                    /* Size of partial block data          */
} WP11_EcbParams;
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
    byte keyDigested;                  /* Key material fed by C_DigestKey     */
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
    word32 createLogoutCnt;            /* User logouts when a create call
                                        * checked the login                   */
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
#ifdef WOLFPKCS11_MLDSA
        WP11_MldsaParams mldsa;        /* ML-DSA parameters                   */
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
    #ifdef HAVE_AESECB
        WP11_EcbParams ecb;            /* AES-ECB parameters                  */
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
    word32 dataCap;                    /* Allocated size of held data         */

    int devId;
    WP11_Session* next;                /* Next session for slot               */
    WP11_Object* retired;              /* Private objects invalidated by logout
                                        * and freed once nothing uses them    */
    byte opUpdated;                    /* Multi-part update called on op      */
    wc_HashAlg signHash;               /* Running hash for hash-and-sign      */
    enum wc_HashType signHashType;     /* Type of signHash, NONE when unused  */
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
    int soPinInFlight;                 /* SO PIN checks in progress           */
    byte userPin[PIN_HASH_SZ];         /* User's PIN hashed with seed         */
    int userPinLen;                    /* Used to indicate PIN set            */
    byte userPinSeed[PIN_SEED_SZ];     /* Seed for calculating user's PIN     */
    int userFailedLogin;               /* Count of consecutive failed logins  */
    time_t userLastFailedLogin;        /* Time of last login if it failed     */
    time_t userFailLoginTimeout;       /* Timeout after max login fails       */
    int userPinInFlight;               /* User PIN checks in progress         */
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
    int nextObjId;                     /* Id for the next token object        */
    byte userPinEmpty:2;               /* Indicates user PIN is empty
                                        * 0 = not set
                                        * 1 = empty
                                        * 2 = not empty                       */
#ifndef WOLFPKCS11_NO_STORE
    byte storeDirty;                   /* A store pass was skipped or failed,
                                        * so the next one writes everything.
                                        * Not a bit-field: guarded by the
                                        * token lock, unlike userPinEmpty.   */
    byte storePurge;                   /* Records the token does not use are
                                        * still to be removed                 */
    byte storeLoginDirty;              /* Failed login counts changed since
                                        * the token record was stored         */
    int storeSoFailBase;               /* SO failed logins last stored        */
    int storeUserFailBase;             /* User failed logins last stored      */
    WP11_Object* storeUnstoreObj;      /* Object a destroy removes            */
    WP11_Object* storeUnstoreMoved;    /* Object moved into the freed id      */
    int storeUnstoreId;                /* Store id of the destroyed object    */
    int storeUnstoreRet;               /* Result of removing its records      */
    byte storeUnstorePending;          /* Records to remove after the pass    */
    word64 storeGen;                   /* Committed store passes when loaded  */
    byte storeGenKnown;                /* storeGen was read from storage      */
    byte storeGenAdopt;                /* Next pass takes the stored count    */
    byte storeReset;                   /* Next pass stores a token reset      */
    byte storeStale;                   /* Another process changed the store   */
    byte storeKeepGen;                 /* Pass rewrites what is stored        */
#endif
} WP11_Token;

struct WP11_ObjectCalls {
    WP11_Slot* slot;                   /* Slot the calls are made on          */
    int cnt;                           /* Calls in progress from this epoch   */
};

struct WP11_Slot {
    CK_SLOT_ID id;                     /* CryptoKi API slot id value          */
    WP11_Token token;                  /* Token information for slot          */
    WP11_Session* session;             /* Linked list of sessions             */
    WP11_Lock lock;                    /* Lock for access to slot info        */
    int nextSessObjId;                 /* Id for the next session object,
                                        * guarded by the token lock           */

    int devId;
#ifdef WOLFPKCS11_TPM
    WOLFTPM2_DEV tpmDev;
    WOLFTPM2_KEY tpmSrk;
    WOLFTPM2_SESSION tpmSession;
    TpmCryptoDevCtx  tpmCtx;
#endif
    WP11_ObjectCalls calls[2];         /* Object calls of the last two epochs */
    word32 epoch;                      /* Current object call epoch           */
    WP11_Object* discarded;            /* Destroyed objects awaiting free     */
    word32 logoutCnt;                  /* Logouts, guarded by the token lock  */
    word32 userLogoutCnt;              /* User logouts and dropped keys,
                                        * guarded by the token lock           */
    word32 soPinCnt;                   /* SO PIN changes, guarded by the slot
                                        * lock                                */
    WP11_Lock callLock;                /* Lock for object call epochs         */
    byte reclaim:1;                    /* Unlinked objects await free         */
#ifndef WOLFPKCS11_NO_STORE
    WP11_Lock storeLock;               /* Held for a whole token store pass   */
#endif
};

/* Helpers implemented in internal.c. */

#ifndef WP11_NO_LOCKING
WP11_LOCAL int WP11_Lock_LockRW(WP11_Lock* lock);
WP11_LOCAL int WP11_Lock_UnlockRW(WP11_Lock* lock);
WP11_LOCAL int WP11_Lock_LockRO(WP11_Lock* lock);
WP11_LOCAL int WP11_Lock_UnlockRO(WP11_Lock* lock);
#endif

#ifndef WOLFPKCS11_NO_STORE
WP11_LOCAL int wp11_storage_open_readonly(int type, CK_ULONG id1, CK_ULONG id2,
                                          void** storage);
WP11_LOCAL int wp11_storage_open(int type, CK_ULONG id1, CK_ULONG id2,
                                 int variableSz, void** storage);
WP11_LOCAL void wp11_storage_close(void* storage);
WP11_LOCAL int wp11_storage_close_write(void* storage, int ret);
WP11_LOCAL int wp11_storage_read_alloc_array(void* storage,
                                             unsigned char** buffer, int* len);
WP11_LOCAL int wp11_storage_write_array(void* storage, unsigned char* buffer,
                                        word32 len);

WP11_LOCAL void wp11_Object_EncodeDone(WP11_Object* object,
                                       unsigned char* oldData, int oldLen,
                                       word32 newLen, int ret);

#endif /* !WOLFPKCS11_NO_STORE */

#endif /* WOLFPKCS11_WP11_TYPES_H */
