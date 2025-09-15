/**
 * \file data_structures.h
 * \brief PKCS#11 data structures for Doxygen indexing (documentation-only).
 *
 * This header mirrors the PKCS#11 (Cryptoki) data structures supported by
 * wolfPKCS11 so they appear in Doxygen's "Data Structure Index" and
 * "Data Structure Documentation". It is not used by the library build.
 *
 * Notes:
 * - Types and structures here are reduced to the fields needed for documentation.
 * - For normative definitions, refer to the official PKCS#11 specification.
 * - NSS-specific structures are documented in nss_extensions.h.
 */
 
/** \addtogroup pkcs11_structs
 *  @{
 */

#ifndef WOLFPKCS11_DOC_DATA_STRUCTURES_H
#define WOLFPKCS11_DOC_DATA_STRUCTURES_H

/*----------------------------------------------------------------------------
 * Base scalar and pointer types (documentation facsimiles)
 *---------------------------------------------------------------------------*/

/*! Unsigned 8-bit byte. */
typedef unsigned char CK_BYTE;
/*! Signed 8-bit character. */
typedef char CK_CHAR;
/*! Unsigned 8-bit UTF-8 character. */
typedef unsigned char CK_UTF8CHAR;
/*! Unsigned long integer (platform-sized as per PKCS#11). */
typedef unsigned long CK_ULONG;
/*! Signed long integer (platform-sized as per PKCS#11). */
typedef long CK_LONG;
/*! Boolean (CK_FALSE=0, CK_TRUE!=0). */
typedef CK_BYTE CK_BBOOL;
/*! Flags bitfield type. */
typedef CK_ULONG CK_FLAGS;
/*! Generic return value type. */
typedef CK_ULONG CK_RV;

/*! Generic void pointer. */
typedef void* CK_VOID_PTR;
/*! Pointer to generic void pointer. */
typedef CK_VOID_PTR* CK_VOID_PTR_PTR;
/*! Pointer to byte. */
typedef CK_BYTE* CK_BYTE_PTR;
/*! Pointer to char. */
typedef CK_CHAR* CK_CHAR_PTR;
/*! Pointer to UTF-8 char. */
typedef CK_UTF8CHAR* CK_UTF8CHAR_PTR;
/*! Pointer to unsigned long. */
typedef CK_ULONG* CK_ULONG_PTR;

/*! Certificate type enumeration (as integer). */
typedef CK_ULONG CK_CERTIFICATE_TYPE;
/*! Object handle. */
typedef CK_ULONG CK_OBJECT_HANDLE;
/*! Pointer to object handle. */
typedef CK_OBJECT_HANDLE* CK_OBJECT_HANDLE_PTR;
/*! Object class (e.g., CKO_DATA, CKO_SECRET_KEY). */
typedef CK_ULONG CK_OBJECT_CLASS;
/*! Pointer to object class. */
typedef CK_OBJECT_CLASS* CK_OBJECT_CLASS_PTR;
/*! Key type (e.g., CKK_RSA, CKK_AES). */
typedef CK_ULONG CK_KEY_TYPE;
/*! Attribute type (e.g., CKA_LABEL, CKA_VALUE). */
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
/*! Mechanism type (e.g., CKM_AES_GCM). */
typedef CK_ULONG CK_MECHANISM_TYPE;
/*! Pointer to mechanism type. */
typedef CK_MECHANISM_TYPE* CK_MECHANISM_TYPE_PTR;
/*! Mechanism flags (info struct). */
typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;            /* MGF type for RSA-PSS/OAEP */
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;    /* OAEP source type */

/*! Slot identifier. */
typedef CK_ULONG CK_SLOT_ID;
/*! Pointer to slot identifier. */
typedef CK_SLOT_ID* CK_SLOT_ID_PTR;
/*! Session handle. */
typedef CK_ULONG CK_SESSION_HANDLE;
/*! Pointer to session handle. */
typedef CK_SESSION_HANDLE* CK_SESSION_HANDLE_PTR;
/*! User type (CKU_SO, CKU_USER, CKU_CONTEXT_SPECIFIC). */
typedef CK_ULONG CK_USER_TYPE;
/*! Session state. */
typedef CK_ULONG CK_STATE;
/*! Notification code. */
typedef CK_ULONG CK_NOTIFICATION;

/*----------------------------------------------------------------------------
 * Data structures
 *---------------------------------------------------------------------------*/

/*!
 * \ingroup pkcs11_structs
 * \brief Cryptoki version structure.
 */
typedef struct CK_VERSION {
    CK_BYTE major; /*!< Major version number. */
    CK_BYTE minor; /*!< Minor version number. */
} CK_VERSION;
/*! Pointer to CK_VERSION. */
typedef CK_VERSION* CK_VERSION_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief General information about the Cryptoki library.
 */
typedef struct CK_INFO {
    CK_VERSION  cryptokiVersion;                 /*!< Cryptoki interface version. */
    CK_UTF8CHAR manufacturerID[32];              /*!< Space-padded string. */
    CK_FLAGS    flags;                           /*!< Must be 0 (reserved). */
    CK_UTF8CHAR libraryDescription[32];          /*!< Space-padded string. */
    CK_VERSION  libraryVersion;                  /*!< Library version. */
} CK_INFO;
/*! Pointer to CK_INFO. */
typedef CK_INFO* CK_INFO_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief Information about a slot.
 */
typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR   slotDescription[64];           /*!< Space-padded description. */
    CK_UTF8CHAR   manufacturerID[32];            /*!< Space-padded manufacturer. */
    CK_FLAGS      flags;                         /*!< Slot flags (CKF_TOKEN_PRESENT, etc). */
    CK_VERSION    hardwareVersion;               /*!< Slot hardware version. */
    CK_VERSION    firmwareVersion;               /*!< Slot firmware version. */
} CK_SLOT_INFO;
/*! Pointer to CK_SLOT_INFO. */
typedef CK_SLOT_INFO* CK_SLOT_INFO_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief Information about a token.
 */
typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR   label[32];                     /*!< Space-padded token label. */
    CK_UTF8CHAR   manufacturerID[32];            /*!< Space-padded manufacturer. */
    CK_UTF8CHAR   model[16];                     /*!< Space-padded model. */
    CK_CHAR       serialNumber[16];              /*!< Space-padded serial (ASCII). */
    CK_FLAGS      flags;                         /*!< Token flags. */
    CK_ULONG      ulMaxSessionCount;             /*!< Max open sessions or CK_UNAVAILABLE_INFORMATION. */
    CK_ULONG      ulSessionCount;                /*!< Current open sessions or CK_UNAVAILABLE_INFORMATION. */
    CK_ULONG      ulMaxRwSessionCount;           /*!< Max R/W sessions. */
    CK_ULONG      ulRwSessionCount;              /*!< Current R/W sessions. */
    CK_ULONG      ulMaxPinLen;                   /*!< Max PIN length. */
    CK_ULONG      ulMinPinLen;                   /*!< Min PIN length. */
    CK_ULONG      ulTotalPublicMemory;           /*!< Total public memory or unavailable. */
    CK_ULONG      ulFreePublicMemory;            /*!< Free public memory or unavailable. */
    CK_ULONG      ulTotalPrivateMemory;          /*!< Total private memory or unavailable. */
    CK_ULONG      ulFreePrivateMemory;           /*!< Free private memory or unavailable. */
    CK_VERSION    hardwareVersion;               /*!< Token hardware version. */
    CK_VERSION    firmwareVersion;               /*!< Token firmware version. */
    CK_CHAR       utcTime[16];                   /*!< UTC time (YYYYMMDDhhmmssxx) or blanks. */
} CK_TOKEN_INFO;
/*! Pointer to CK_TOKEN_INFO. */
typedef CK_TOKEN_INFO* CK_TOKEN_INFO_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief Information about a session.
 */
typedef struct CK_SESSION_INFO {
    CK_SLOT_ID    slotID;                        /*!< Slot that owns the session. */
    CK_STATE      state;                         /*!< Session state (RO/RW + user/SO). */
    CK_FLAGS      flags;                         /*!< Session flags (CKF_RW_SESSION, CKF_SERIAL_SESSION). */
    CK_ULONG      ulDeviceError;                 /*!< Last device error (token-specific). */
} CK_SESSION_INFO;
/*! Pointer to CK_SESSION_INFO. */
typedef CK_SESSION_INFO* CK_SESSION_INFO_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief Attribute template entry.
 */
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;                      /*!< Attribute type (CKA_*). */
    CK_VOID_PTR       pValue;                    /*!< Pointer to value or NULL for size query. */
    CK_ULONG          ulValueLen;                /*!< Value length in bytes or CK_UNAVAILABLE_INFORMATION. */
} CK_ATTRIBUTE;
/*! Pointer to CK_ATTRIBUTE. */
typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief Calendar date (YYYY-MM-DD).
 */
typedef struct CK_DATE {
    CK_CHAR year[4];                             /*!< 4 ASCII chars, no terminator. */
    CK_CHAR month[2];                            /*!< 2 ASCII chars, no terminator. */
    CK_CHAR day[2];                              /*!< 2 ASCII chars, no terminator. */
} CK_DATE;

/*!
 * \ingroup pkcs11_structs
 * \brief Mechanism descriptor for operations.
 */
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;                 /*!< Mechanism type (CKM_*). */
    CK_VOID_PTR       pParameter;                /*!< Optional mechanism parameters. */
    CK_ULONG          ulParameterLen;            /*!< Length of parameters. */
} CK_MECHANISM;
/*! Pointer to CK_MECHANISM. */
typedef CK_MECHANISM* CK_MECHANISM_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief Mechanism information (capabilities and key sizes).
 */
typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;                       /*!< Minimum key size in bits. */
    CK_ULONG ulMaxKeySize;                       /*!< Maximum key size in bits. */
    CK_FLAGS flags;                              /*!< Mechanism flags (CKF_ENCRYPT, etc). */
} CK_MECHANISM_INFO;
/*! Pointer to CK_MECHANISM_INFO. */
typedef CK_MECHANISM_INFO* CK_MECHANISM_INFO_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief RSA-PSS mechanism parameters.
 */
typedef struct CK_RSA_PKCS_PSS_PARAMS {
    CK_MECHANISM_TYPE      hashAlg;              /*!< Hash algorithm for PSS (e.g., CKM_SHA256). */
    CK_RSA_PKCS_MGF_TYPE   mgf;                  /*!< Mask generation function (e.g., CKG_MGF1_SHA256). */
    CK_ULONG               sLen;                 /*!< Salt length in bytes. */
} CK_RSA_PKCS_PSS_PARAMS;

/*!
 * \ingroup pkcs11_structs
 * \brief RSA-OAEP mechanism parameters.
 */
typedef struct CK_RSA_PKCS_OAEP_PARAMS {
    CK_MECHANISM_TYPE            hashAlg;        /*!< Hash algorithm (e.g., CKM_SHA256). */
    CK_RSA_PKCS_MGF_TYPE         mgf;            /*!< Mask generation function (e.g., CKG_MGF1_SHA256). */
    CK_RSA_PKCS_OAEP_SOURCE_TYPE source;         /*!< Label source (e.g., CKZ_DATA_SPECIFIED). */
    CK_VOID_PTR                  pSourceData;    /*!< Label data pointer. */
    CK_ULONG                     ulSourceDataLen;/*!< Label data length. */
} CK_RSA_PKCS_OAEP_PARAMS;

/*!
 * \ingroup pkcs11_structs
 * \brief C_Initialize optional threading callbacks and flags.
 */
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event,
                           CK_VOID_PTR pApplication);
typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR_PTR ppMutex);
typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX CreateMutex;                  /*!< Create a mutex. */
    CK_DESTROYMUTEX DestroyMutex;                /*!< Destroy a mutex. */
    CK_LOCKMUTEX   LockMutex;                    /*!< Lock a mutex. */
    CK_UNLOCKMUTEX UnlockMutex;                  /*!< Unlock a mutex. */
    CK_FLAGS       flags;                        /*!< CKF_OS_LOCKING_OK, etc. */
    /* NSS extension note: LibraryParameters may be present when enabled. */
    CK_VOID_PTR    pReserved;                    /*!< Reserved (must be NULL). */
} CK_C_INITIALIZE_ARGS;
/*! Pointer to CK_C_INITIALIZE_ARGS. */
typedef CK_C_INITIALIZE_ARGS* CK_C_INITIALIZE_ARGS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief ECDH1 derive mechanism parameters.
 */
typedef CK_ULONG CK_EC_KDF_TYPE; /* KDF type for ECDH (e.g., CKD_NULL). */

typedef struct CK_ECDH1_DERIVE_PARAMS {
    CK_EC_KDF_TYPE kdf;                          /*!< KDF to use. */
    CK_ULONG       ulSharedDataLen;              /*!< Length of shared data. */
    CK_BYTE_PTR    pSharedData;                  /*!< Optional shared data. */
    CK_ULONG       ulPublicDataLen;              /*!< Length of peer public data. */
    CK_BYTE_PTR    pPublicData;                  /*!< Peer public data (EC point). */
} CK_ECDH1_DERIVE_PARAMS;
/*! Pointer to CK_ECDH1_DERIVE_PARAMS. */
typedef CK_ECDH1_DERIVE_PARAMS* CK_ECDH1_DERIVE_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief AES CBC Encrypt Data mechanism parameters.
 */
typedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE     iv[16];                          /*!< 16-byte IV for AES-CBC. */
    CK_BYTE_PTR pData;                           /*!< Data pointer. */
    CK_ULONG    length;                          /*!< Data length in bytes. */
} CK_AES_CBC_ENCRYPT_DATA_PARAMS;
/*! Pointer to CK_AES_CBC_ENCRYPT_DATA_PARAMS. */
typedef CK_AES_CBC_ENCRYPT_DATA_PARAMS* CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief MAC General parameters (e.g., for CMAC general).
 */
typedef CK_ULONG CK_MAC_GENERAL_PARAMS;
/*! Pointer to CK_MAC_GENERAL_PARAMS. */
typedef CK_MAC_GENERAL_PARAMS* CK_MAC_GENERAL_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief HKDF mechanism parameters.
 */
typedef struct CK_HKDF_PARAMS {
    CK_BBOOL          bExtract;                  /*!< Perform extract stage. */
    CK_BBOOL          bExpand;                   /*!< Perform expand stage. */
    CK_MECHANISM_TYPE prfHashMechanism;          /*!< Underlying HMAC hash (e.g., CKM_SHA256). */
    CK_ULONG          ulSaltType;                /*!< CKF_HKDF_SALT_* selector. */
    CK_BYTE_PTR       pSalt;                     /*!< Salt data (if CKF_HKDF_SALT_DATA). */
    CK_ULONG          ulSaltLen;                 /*!< Salt length. */
    CK_OBJECT_HANDLE  hSaltKey;                  /*!< Salt key handle (if CKF_HKDF_SALT_KEY). */
    CK_BYTE_PTR       pInfo;                     /*!< Info/context data. */
    CK_ULONG          ulInfoLen;                 /*!< Info length. */
} CK_HKDF_PARAMS;
/*! Pointer to CK_HKDF_PARAMS. */
typedef CK_HKDF_PARAMS* CK_HKDF_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief AES CTR mechanism parameters.
 */
typedef struct CK_AES_CTR_PARAMS {
    CK_ULONG ulCounterBits;                      /*!< Counter bits (e.g., 128). */
    CK_BYTE  cb[16];                             /*!< Counter block. */
} CK_AES_CTR_PARAMS;
/*! Pointer to CK_AES_CTR_PARAMS. */
typedef CK_AES_CTR_PARAMS* CK_AES_CTR_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief AES GCM mechanism parameters.
 */
typedef struct CK_GCM_PARAMS {
    CK_BYTE_PTR pIv;                             /*!< IV/nonce pointer. */
    CK_ULONG    ulIvLen;                         /*!< IV length in bytes. */
    CK_ULONG    ulIvBits;                        /*!< IV size in bits (optional). */
    CK_BYTE_PTR pAAD;                            /*!< Additional authenticated data. */
    CK_ULONG    ulAADLen;                        /*!< AAD length in bytes. */
    CK_ULONG    ulTagBits;                       /*!< Auth tag size in bits. */
} CK_GCM_PARAMS;
/*! Pointer to CK_GCM_PARAMS. */
typedef CK_GCM_PARAMS* CK_GCM_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief AES CCM mechanism parameters.
 */
typedef struct CK_CCM_PARAMS {
    CK_ULONG    ulDataLen;                       /*!< Data length in bytes. */
    CK_BYTE_PTR pIv;                             /*!< Nonce pointer. */
    CK_ULONG    ulIvLen;                         /*!< Nonce length in bytes. */
    CK_BYTE_PTR pAAD;                            /*!< Additional authenticated data. */
    CK_ULONG    ulAADLen;                        /*!< AAD length in bytes. */
    CK_ULONG    ulMacLen;                        /*!< MAC length in bytes. */
} CK_CCM_PARAMS;
/*! Pointer to CK_CCM_PARAMS. */
typedef CK_CCM_PARAMS* CK_CCM_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief SSL3/TLS random data container.
 */
typedef struct CK_SSL3_RANDOM_DATA {
    CK_BYTE_PTR pClientRandom;                   /*!< Client random. */
    CK_ULONG    ulClientRandomLen;               /*!< Client random length. */
    CK_BYTE_PTR pServerRandom;                   /*!< Server random. */
    CK_ULONG    ulServerRandomLen;               /*!< Server random length. */
} CK_SSL3_RANDOM_DATA;

/*!
 * \ingroup pkcs11_structs
 * \brief TLS 1.2 master key derive parameters.
 */
typedef struct CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
    CK_SSL3_RANDOM_DATA RandomInfo;              /*!< Client/server randoms. */
    CK_VERSION_PTR      pVersion;                /*!< Optional negotiated version. */
    CK_MECHANISM_TYPE   prfHashMechanism;        /*!< PRF hash mechanism (e.g., CKM_SHA256). */
} CK_TLS12_MASTER_KEY_DERIVE_PARAMS;
/*! Pointer to CK_TLS12_MASTER_KEY_DERIVE_PARAMS. */
typedef CK_TLS12_MASTER_KEY_DERIVE_PARAMS*
    CK_TLS12_MASTER_KEY_DERIVE_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief SSL3/TLS key material output container.
 */
typedef struct CK_SSL3_KEY_MAT_OUT {
    CK_OBJECT_HANDLE hClientMacSecret;           /*!< Client MAC secret handle. */
    CK_OBJECT_HANDLE hServerMacSecret;           /*!< Server MAC secret handle. */
    CK_OBJECT_HANDLE hClientKey;                 /*!< Client key handle. */
    CK_OBJECT_HANDLE hServerKey;                 /*!< Server key handle. */
    CK_BYTE_PTR      pIVClient;                  /*!< Client IV pointer. */
    CK_BYTE_PTR      pIVServer;                  /*!< Server IV pointer. */
} CK_SSL3_KEY_MAT_OUT;
/*! Pointer to CK_SSL3_KEY_MAT_OUT. */
typedef CK_SSL3_KEY_MAT_OUT* CK_SSL3_KEY_MAT_OUT_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief TLS 1.2 key and MAC derive parameters.
 */
typedef struct CK_TLS12_KEY_MAT_PARAMS {
    CK_ULONG               ulMacSizeInBits;      /*!< MAC size in bits. */
    CK_ULONG               ulKeySizeInBits;      /*!< Key size in bits. */
    CK_ULONG               ulIVSizeInBits;       /*!< IV size in bits. */
    CK_BBOOL               bIsExport;            /*!< Export flag (typically CK_FALSE). */
    CK_SSL3_RANDOM_DATA    RandomInfo;           /*!< Client/server randoms. */
    CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;/*!< Output key material. */
    CK_MECHANISM_TYPE      prfHashMechanism;     /*!< PRF hash mechanism. */
} CK_TLS12_KEY_MAT_PARAMS;

/*!
 * \ingroup pkcs11_structs
 * \brief PKCS#5 PBKDF2 pseudo-random function type.
 */
typedef CK_ULONG CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE;
/*! Pointer to PRF type. */
typedef CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE*
    CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief PKCS#5 PBKDF2 salt source type.
 */
typedef CK_ULONG CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE;
/*! Pointer to salt source type. */
typedef CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE*
    CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief PKCS#5 PBKDF2 parameters (legacy variant with ulPasswordLen pointer).
 */
typedef struct CK_PKCS5_PBKD2_PARAMS {
    CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE              saltSource;        /*!< Salt source selector. */
    CK_VOID_PTR                                   pSaltSourceData;   /*!< Salt data pointer. */
    CK_ULONG                                      ulSaltSourceDataLen;/*!< Salt data length. */
    CK_ULONG                                      iterations;        /*!< Iteration count. */
    CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE    prf;               /*!< PRF selector. */
    CK_VOID_PTR                                   pPrfData;          /*!< PRF data pointer. */
    CK_ULONG                                      ulPrfDataLen;      /*!< PRF data length. */
    CK_UTF8CHAR_PTR                               pPassword;         /*!< Password pointer. */
    CK_ULONG_PTR                                  ulPasswordLen;     /*!< Pointer to password length. */
} CK_PKCS5_PBKD2_PARAMS;

/*!
 * \ingroup pkcs11_structs
 * \brief PKCS#5 PBKDF2 parameters (v2.40 variant with ulPasswordLen by value).
 */
typedef struct CK_PKCS5_PBKD2_PARAMS2 {
    CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE              saltSource;        /*!< Salt source selector. */
    CK_VOID_PTR                                   pSaltSourceData;   /*!< Salt data pointer. */
    CK_ULONG                                      ulSaltSourceDataLen;/*!< Salt data length. */
    CK_ULONG                                      iterations;        /*!< Iteration count. */
    CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE    prf;               /*!< PRF selector. */
    CK_VOID_PTR                                   pPrfData;          /*!< PRF data pointer. */
    CK_ULONG                                      ulPrfDataLen;      /*!< PRF data length. */
    CK_UTF8CHAR_PTR                               pPassword;         /*!< Password pointer. */
    CK_ULONG                                      ulPasswordLen;     /*!< Password length. */
} CK_PKCS5_PBKD2_PARAMS2;

/*!
 * \ingroup pkcs11_structs
 * \brief TLS MAC mechanism parameters.
 */
typedef struct CK_TLS_MAC_PARAMS {
    CK_MECHANISM_TYPE prfHashMechanism;          /*!< PRF hash mechanism for MAC. */
    CK_ULONG          ulMacLength;               /*!< MAC length in bytes. */
    CK_ULONG          ulServerOrClient;          /*!< Side selector. */
} CK_TLS_MAC_PARAMS;
/*! Pointer to CK_TLS_MAC_PARAMS. */
typedef CK_TLS_MAC_PARAMS* CK_TLS_MAC_PARAMS_PTR;

/*!
 * \ingroup pkcs11_structs
 * \brief Function list table containing pointers to PKCS#11 API entry points.
 *
 * Note: This is a documentation-only summary. Individual function pointers
 * are omitted for brevity.
 */
typedef struct CK_FUNCTION_LIST {
    CK_VERSION version; /*!< Cryptoki version of this function list. */
    /* Function pointers omitted; see PKCS#11 specification for full list. */
} CK_FUNCTION_LIST;

/*! Pointer to CK_FUNCTION_LIST. */
typedef CK_FUNCTION_LIST* CK_FUNCTION_LIST_PTR;
/*! Pointer to pointer to CK_FUNCTION_LIST. */
typedef CK_FUNCTION_LIST_PTR* CK_FUNCTION_LIST_PTR_PTR;

/*! Prototype for C_GetFunctionList. */
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/** @} */ /* end of pkcs11_structs group */
#endif /* WOLFPKCS11_DOC_DATA_STRUCTURES_H */