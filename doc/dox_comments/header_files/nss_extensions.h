/**
 * \page pkcs11_nss_extensions_overview wolfPKCS11 NSS Extensions
 * wolfPKCS11 NSS-specific extensions and enhancements for Mozilla NSS compatibility.
 * 
 * wolfPKCS11 provides several extensions specifically designed for compatibility
 * with Mozilla NSS (Network Security Services). These extensions enable wolfPKCS11
 * to be used as a drop-in replacement for NSS's PKCS#11 module in various
 * applications including Firefox, Thunderbird, and other NSS-based software.
 * 
 * All NSS extensions are enabled using the `--enable-nss` configure flag and are
 * conditionally compiled based on the `WOLFPKCS11_NSS` preprocessor definition.
 * 
 * - \ref pkcs11_nss_mechanisms
 * - \ref pkcs11_nss_objects
 * - \ref pkcs11_nss_attributes
 * - \ref pkcs11_nss_examples
 * 
 * \section pkcs11_nss_build Building with NSS Extensions
 * 
 * To enable NSS extensions in wolfPKCS11, configure with the NSS flag:
 * 
 * \code
 * ./configure --enable-nss [other options]
 * make
 * make install
 * \endcode
 * 
 * When building manually, define the WOLFPKCS11_NSS preprocessor symbol:
 * 
 * \code
 * gcc -DWOLFPKCS11_NSS -o myapp myapp.c -lwolfpkcs11
 * \endcode
 */

/*!
 * \defgroup pkcs11_nss_mechanisms NSS Cryptographic Mechanisms
 * \ingroup pkcs11_nss_extensions_overview
 * \brief NSS-specific cryptographic mechanisms supported by wolfPKCS11.
 * 
 * These mechanisms provide compatibility with NSS-specific cryptographic
 * operations, particularly for TLS and PKCS#12 operations.
 * 
 * @{
 */

/*!
 * \brief NSS TLS PRF General SHA256 mechanism.
 * 
 * This mechanism (CKM_NSS_TLS_PRF_GENERAL_SHA256) implements the TLS 
 * Pseudo-Random Function (PRF) using SHA-256 as specified by NSS.
 * It is used for TLS key derivation and MAC operations.
 * 
 * \note This mechanism is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Supported Operations:**
 * - C_SignInit/C_Sign/C_SignUpdate/C_SignFinal
 * - C_VerifyInit/C_Verify/C_VerifyUpdate/C_VerifyFinal
 * 
 * **Key Types:** CKK_GENERIC_SECRET
 * 
 * _Example Usage_
 * \code
 * CK_MECHANISM mechanism = {CKM_NSS_TLS_PRF_GENERAL_SHA256, NULL, 0};
 * CK_RV rv = C_SignInit(hSession, &mechanism, hKey);
 * if (rv == CKR_OK) {
 *     // Perform TLS PRF signing operations
 *     rv = C_Sign(hSession, data, dataLen, signature, &signatureLen);
 * }
 * \endcode
 * 
 * \sa CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE
 * \sa CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH
 */
#define CKM_NSS_TLS_PRF_GENERAL_SHA256

/*!
 * \brief NSS TLS Extended Master Key Derive mechanism.
 * 
 * This mechanism (CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE) implements the 
 * TLS Extended Master Secret derivation as defined in RFC 7627. It enhances
 * TLS security by binding the master secret to the handshake transcript.
 * 
 * \note This mechanism is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Parameters:** CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS
 * 
 * **Key Types:** Derives CKK_GENERIC_SECRET keys
 * 
 * _Example Usage_
 * \code
 * CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS params;
 * params.prfHashMechanism = CKM_SHA256_HMAC;
 * params.pSessionHash = sessionHashData;
 * params.ulSessionHashLen = sessionHashLength;
 * params.pVersion = &tlsVersion;
 * 
 * CK_MECHANISM mechanism = {
 *     CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE, 
 *     &params, 
 *     sizeof(params)
 * };
 * 
 * CK_RV rv = C_DeriveKey(hSession, &mechanism, hBaseKey, template, 
 *                       templateCount, &hDerivedKey);
 * \endcode
 * 
 * \sa CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH
 * \sa CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS
 */
#define CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE

/*!
 * \brief NSS TLS Extended Master Key Derive DH mechanism.
 * 
 * This mechanism (CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH) is similar to
 * CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE but specifically designed for use
 * with Diffie-Hellman key exchanges in TLS connections.
 * 
 * \note This mechanism is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Parameters:** CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS
 * 
 * **Key Types:** Derives CKK_GENERIC_SECRET keys
 * 
 * \sa CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE
 */
#define CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH

/*!
 * \brief NSS PKCS#12 PBE SHA-224 HMAC Key Generation mechanism.
 * 
 * This mechanism (CKM_NSS_PKCS12_PBE_SHA224_HMAC_KEY_GEN) implements
 * PKCS#12 Password-Based Encryption key derivation using SHA-224 HMAC
 * as specified by NSS for PKCS#12 operations.
 * 
 * \note This mechanism is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Parameters:** Requires PKCS#12 PBE parameters structure
 * 
 * **Generated Key Type:** CKK_GENERIC_SECRET
 * 
 * **Key Length:** 28 bytes (SHA-224 digest size)
 * 
 * _Example Usage_
 * \code
 * // PKCS#12 PBE parameters would be set up here
 * CK_MECHANISM mechanism = {CKM_NSS_PKCS12_PBE_SHA224_HMAC_KEY_GEN, 
 *                          &pbeParams, sizeof(pbeParams)};
 * 
 * CK_RV rv = C_GenerateKey(hSession, &mechanism, template, 
 *                         templateCount, &hKey);
 * \endcode
 * 
 * \sa CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN
 * \sa CKM_NSS_PKCS12_PBE_SHA384_HMAC_KEY_GEN
 * \sa CKM_NSS_PKCS12_PBE_SHA512_HMAC_KEY_GEN
 */
#define CKM_NSS_PKCS12_PBE_SHA224_HMAC_KEY_GEN

/*!
 * \brief NSS PKCS#12 PBE SHA-256 HMAC Key Generation mechanism.
 * 
 * This mechanism (CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN) implements
 * PKCS#12 Password-Based Encryption key derivation using SHA-256 HMAC.
 * 
 * \note This mechanism is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Generated Key Type:** CKK_GENERIC_SECRET
 * 
 * **Key Length:** 32 bytes (SHA-256 digest size)
 * 
 * \sa CKM_NSS_PKCS12_PBE_SHA224_HMAC_KEY_GEN
 */
#define CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN

/*!
 * \brief NSS PKCS#12 PBE SHA-384 HMAC Key Generation mechanism.
 * 
 * This mechanism (CKM_NSS_PKCS12_PBE_SHA384_HMAC_KEY_GEN) implements
 * PKCS#12 Password-Based Encryption key derivation using SHA-384 HMAC.
 * 
 * \note This mechanism is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Generated Key Type:** CKK_GENERIC_SECRET
 * 
 * **Key Length:** 48 bytes (SHA-384 digest size)
 * 
 * \sa CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN
 */
#define CKM_NSS_PKCS12_PBE_SHA384_HMAC_KEY_GEN

/*!
 * \brief NSS PKCS#12 PBE SHA-512 HMAC Key Generation mechanism.
 * 
 * This mechanism (CKM_NSS_PKCS12_PBE_SHA512_HMAC_KEY_GEN) implements
 * PKCS#12 Password-Based Encryption key derivation using SHA-512 HMAC.
 * 
 * \note This mechanism is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Generated Key Type:** CKK_GENERIC_SECRET
 * 
 * **Key Length:** 64 bytes (SHA-512 digest size)
 * 
 * \sa CKM_NSS_PKCS12_PBE_SHA384_HMAC_KEY_GEN
 */
#define CKM_NSS_PKCS12_PBE_SHA512_HMAC_KEY_GEN

/*!
 * \brief SSL 3.0 Master Key Derive mechanism (advertised only).
 * 
 * This mechanism (CKM_SSL3_MASTER_KEY_DERIVE) is advertised for NSS
 * compatibility but is not implemented. It represents the SSL 3.0
 * master key derivation process.
 * 
 * \note This mechanism is advertised only and will return an error if used.
 * \note Only available when wolfPKCS11 is compiled with NSS extensions.
 * 
 * \warning This mechanism is not implemented and should not be used.
 */
#define CKM_SSL3_MASTER_KEY_DERIVE

/*! @} */ /* end of pkcs11_nss_mechanisms group */

/*!
 * \defgroup pkcs11_nss_objects NSS Object Types
 * \ingroup pkcs11_nss_extensions_overview
 * \brief NSS-specific object types supported by wolfPKCS11.
 * 
 * @{
 */

/*!
 * \brief NSS Trust object type.
 * 
 * This object class (CKO_NSS_TRUST) represents trust settings for certificates
 * as used by NSS. Trust objects store information about how a certificate
 * should be trusted for various purposes such as server authentication,
 * client authentication, email protection, and code signing.
 * 
 * \note This object type is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Required Attributes for Creation:**
 * - CKA_ISSUER - Certificate issuer name
 * - CKA_SERIAL_NUMBER - Certificate serial number  
 * - CKA_CERT_SHA1_HASH - SHA-1 hash of the certificate
 * - CKA_CERT_MD5_HASH - MD5 hash of the certificate
 * 
 * **Associated Key Type:** CKK_NSS_TRUST
 * 
 * _Example Creation_
 * \code
 * CK_OBJECT_CLASS objClass = CKO_NSS_TRUST;
 * CK_KEY_TYPE keyType = CKK_NSS_TRUST;
 * CK_ULONG serverAuth = CKT_NSS_TRUSTED;
 * CK_ULONG clientAuth = CKT_NSS_TRUSTED_DELEGATOR;
 * 
 * CK_ATTRIBUTE template[] = {
 *     {CKA_CLASS,              &objClass,    sizeof(objClass)},
 *     {CKA_KEY_TYPE,           &keyType,     sizeof(keyType)},
 *     {CKA_ISSUER,             issuerDN,     issuerDNLen},
 *     {CKA_SERIAL_NUMBER,      serialNum,    serialNumLen},
 *     {CKA_CERT_SHA1_HASH,     sha1Hash,     20},
 *     {CKA_CERT_MD5_HASH,      md5Hash,      16},
 *     {CKA_TRUST_SERVER_AUTH,  &serverAuth,  sizeof(serverAuth)},
 *     {CKA_TRUST_CLIENT_AUTH,  &clientAuth,  sizeof(clientAuth)}
 * };
 * 
 * CK_RV rv = C_CreateObject(hSession, template, 
 *                          sizeof(template)/sizeof(template[0]), 
 *                          &hTrustObject);
 * \endcode
 * 
 * \sa CKK_NSS_TRUST
 * \sa CKA_TRUST_SERVER_AUTH
 * \sa CKA_TRUST_CLIENT_AUTH
 */
#define CKO_NSS_TRUST

/*! @} */ /* end of pkcs11_nss_objects group */

/*!
 * \defgroup pkcs11_nss_keytypes NSS Key Types
 * \ingroup pkcs11_nss_extensions_overview
 * \brief NSS-specific key types supported by wolfPKCS11.
 * 
 * @{
 */

/*!
 * \brief NSS Trust key type.
 * 
 * This key type (CKK_NSS_TRUST) is used with trust objects (CKO_NSS_TRUST)
 * to specify that the object contains trust settings rather than actual
 * cryptographic key material.
 * 
 * \note This key type is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * \sa CKO_NSS_TRUST
 */
#define CKK_NSS_TRUST

/*! @} */ /* end of pkcs11_nss_keytypes group */

/*!
 * \defgroup pkcs11_nss_attributes NSS Attributes
 * \ingroup pkcs11_nss_extensions_overview
 * \brief NSS-specific attributes supported by wolfPKCS11.
 * 
 * @{
 */

/*!
 * \brief Certificate SHA-1 hash attribute.
 * 
 * This attribute (CKA_CERT_SHA1_HASH) stores the SHA-1 hash of a certificate.
 * It is commonly used by NSS for certificate identification and is required
 * for creating trust objects.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Data Type:** CK_BYTE array (20 bytes)
 * 
 * **Used With:** CKO_NSS_TRUST, CKO_CERTIFICATE
 * 
 * _Example Usage_
 * \code
 * CK_BYTE sha1Hash[20];
 * // Calculate SHA-1 hash of certificate...
 * 
 * CK_ATTRIBUTE attr = {CKA_CERT_SHA1_HASH, sha1Hash, sizeof(sha1Hash)};
 * \endcode
 * 
 * \sa CKA_CERT_MD5_HASH
 */
#define CKA_CERT_SHA1_HASH

/*!
 * \brief Certificate MD5 hash attribute.
 * 
 * This attribute (CKA_CERT_MD5_HASH) stores the MD5 hash of a certificate.
 * While MD5 is cryptographically weak, it is still used by NSS for legacy
 * compatibility and certificate identification purposes.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Data Type:** CK_BYTE array (16 bytes)
 * 
 * **Used With:** CKO_NSS_TRUST, CKO_CERTIFICATE
 * 
 * \sa CKA_CERT_SHA1_HASH
 */
#define CKA_CERT_MD5_HASH

/*!
 * \brief Certificate email address attribute.
 * 
 * This attribute (CKA_NSS_EMAIL) stores the email address associated with
 * a certificate. This is typically extracted from the certificate's
 * Subject Alternative Name extension or Subject Distinguished Name.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Data Type:** CK_BYTE array (UTF-8 string)
 * 
 * **Used With:** CKO_CERTIFICATE
 * 
 * _Example Usage_
 * \code
 * const char* email = "user@example.com";
 * CK_ATTRIBUTE attr = {CKA_NSS_EMAIL, (CK_BYTE*)email, strlen(email)};
 * \endcode
 */
#define CKA_NSS_EMAIL

/*!
 * \brief NSS database attribute (legacy).
 * 
 * This attribute (CKA_NSS_DB) is a legacy attribute used for NSS database
 * compatibility. It is not stored by wolfPKCS11 but is recognized and ignored
 * to maintain compatibility with NSS-based applications.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * \note This attribute is not stored - it is ignored when set.
 * 
 * **Data Type:** CK_BYTE array
 */
#define CKA_NSS_DB

/*!
 * \brief Trust server authentication attribute.
 * 
 * This attribute (CKA_TRUST_SERVER_AUTH) specifies the trust level for
 * server authentication purposes. It is used with trust objects to indicate
 * whether a certificate should be trusted for TLS server authentication.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Data Type:** CK_ULONG
 * 
 * **Used With:** CKO_NSS_TRUST
 * 
 * **Possible Values:**
 * - CKT_NSS_UNTRUSTED - Certificate is not trusted
 * - CKT_NSS_TRUSTED - Certificate is trusted  
 * - CKT_NSS_TRUSTED_DELEGATOR - Certificate can delegate trust
 * 
 * \sa CKA_TRUST_CLIENT_AUTH
 * \sa CKA_TRUST_EMAIL_PROTECTION
 * \sa CKA_TRUST_CODE_SIGNING
 */
#define CKA_TRUST_SERVER_AUTH

/*!
 * \brief Trust client authentication attribute.
 * 
 * This attribute (CKA_TRUST_CLIENT_AUTH) specifies the trust level for
 * client authentication purposes. It is used with trust objects to indicate
 * whether a certificate should be trusted for TLS client authentication.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Data Type:** CK_ULONG
 * 
 * **Used With:** CKO_NSS_TRUST
 * 
 * \sa CKA_TRUST_SERVER_AUTH
 */
#define CKA_TRUST_CLIENT_AUTH

/*!
 * \brief Trust email protection attribute.
 * 
 * This attribute (CKA_TRUST_EMAIL_PROTECTION) specifies the trust level for
 * email protection (S/MIME) purposes. It indicates whether a certificate
 * should be trusted for email signing and encryption operations.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Data Type:** CK_ULONG
 * 
 * **Used With:** CKO_NSS_TRUST
 * 
 * \sa CKA_TRUST_SERVER_AUTH
 * \sa CKA_TRUST_CODE_SIGNING
 */
#define CKA_TRUST_EMAIL_PROTECTION

/*!
 * \brief Trust code signing attribute.
 * 
 * This attribute (CKA_TRUST_CODE_SIGNING) specifies the trust level for
 * code signing purposes. It indicates whether a certificate should be
 * trusted for verifying code signatures.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Data Type:** CK_ULONG
 * 
 * **Used With:** CKO_NSS_TRUST
 * 
 * \sa CKA_TRUST_EMAIL_PROTECTION
 */
#define CKA_TRUST_CODE_SIGNING

/*!
 * \brief Trust step-up approved attribute.
 * 
 * This attribute (CKA_TRUST_STEP_UP_APPROVED) is a boolean attribute that
 * indicates whether a certificate is approved for step-up authentication
 * in certain protocols and applications.
 * 
 * \note This attribute is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * **Data Type:** CK_BBOOL
 * 
 * **Used With:** CKO_NSS_TRUST
 */
#define CKA_TRUST_STEP_UP_APPROVED

/*! @} */ /* end of pkcs11_nss_attributes group */

/*!
 * \defgroup pkcs11_nss_structures NSS Parameter Structures
 * \ingroup pkcs11_nss_extensions_overview
 * \brief Parameter structures for NSS-specific mechanisms.
 * 
 * @{
 */

/*!
 * \brief NSS TLS Extended Master Key Derive parameters.
 * 
 * This structure (CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS) contains
 * the parameters required for the NSS TLS Extended Master Key derivation
 * mechanisms. It implements the RFC 7627 extended master secret calculation.
 * 
 * \note This structure is only available when wolfPKCS11 is compiled with
 *       NSS extensions enabled (--enable-nss).
 * 
 * _Example Usage_
 * \code
 * CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS params;
 * params.prfHashMechanism = CKM_SHA256_HMAC;
 * params.pSessionHash = handshakeHash;
 * params.ulSessionHashLen = handshakeHashLen;
 * params.pVersion = &clientVersion;
 * 
 * CK_MECHANISM mechanism = {
 *     CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE,
 *     &params,
 *     sizeof(params)
 * };
 * \endcode
 * 
 * \sa CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE
 * \sa CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH
 */
typedef struct CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
    /*! Hash mechanism to use for PRF (e.g., CKM_SHA256_HMAC) */
    CK_MECHANISM_TYPE prfHashMechanism;
    /*! Pointer to session hash data from TLS handshake */
    CK_BYTE_PTR pSessionHash;
    /*! Length of session hash data in bytes */
    CK_ULONG ulSessionHashLen;
    /*! Pointer to TLS version structure */
    CK_VERSION_PTR pVersion;
} CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS;

/*! @} */ /* end of pkcs11_nss_structures group */

/*!
 * \defgroup pkcs11_nss_examples NSS Extension Examples
 * \ingroup pkcs11_nss_extensions_overview
 * \brief Code examples demonstrating NSS extension usage.
 * 
 * @{
 */

/*!
 * \brief Example: Creating an NSS Trust Object
 * 
 * This example demonstrates how to create a trust object using NSS extensions.
 * Trust objects store information about certificate trust settings for various
 * purposes.
 * 
 * \code
 * #ifdef WOLFPKCS11_NSS
 * CK_RV create_trust_object_example(CK_SESSION_HANDLE hSession) {
 *     CK_OBJECT_CLASS objClass = CKO_NSS_TRUST;
 *     CK_KEY_TYPE keyType = CKK_NSS_TRUST;
 *     CK_ULONG serverAuth = CKT_NSS_TRUSTED;
 *     CK_ULONG clientAuth = CKT_NSS_TRUSTED_DELEGATOR;
 *     CK_ULONG emailProtection = CKT_NSS_TRUSTED;
 *     CK_ULONG codeSigning = CKT_NSS_UNTRUSTED;
 *     CK_BBOOL stepUpApproved = CK_TRUE;
 *     
 *     // These would be populated with actual certificate data
 *     CK_BYTE issuerDN[] = "CN=Example CA,O=Example Corp,C=US";
 *     CK_BYTE serialNum[] = {0x01, 0x02, 0x03, 0x04};
 *     CK_BYTE sha1Hash[20] = {0}; // SHA-1 hash of certificate
 *     CK_BYTE md5Hash[16] = {0};  // MD5 hash of certificate
 *     
 *     CK_ATTRIBUTE template[] = {
 *         {CKA_CLASS,                  &objClass,        sizeof(objClass)},
 *         {CKA_KEY_TYPE,               &keyType,         sizeof(keyType)},
 *         {CKA_ISSUER,                 issuerDN,         sizeof(issuerDN)-1},
 *         {CKA_SERIAL_NUMBER,          serialNum,        sizeof(serialNum)},
 *         {CKA_CERT_SHA1_HASH,         sha1Hash,         sizeof(sha1Hash)},
 *         {CKA_CERT_MD5_HASH,          md5Hash,          sizeof(md5Hash)},
 *         {CKA_TRUST_SERVER_AUTH,      &serverAuth,      sizeof(serverAuth)},
 *         {CKA_TRUST_CLIENT_AUTH,      &clientAuth,      sizeof(clientAuth)},
 *         {CKA_TRUST_EMAIL_PROTECTION, &emailProtection, sizeof(emailProtection)},
 *         {CKA_TRUST_CODE_SIGNING,     &codeSigning,     sizeof(codeSigning)},
 *         {CKA_TRUST_STEP_UP_APPROVED, &stepUpApproved,  sizeof(stepUpApproved)}
 *     };
 *     
 *     CK_OBJECT_HANDLE hTrustObject;
 *     CK_RV rv = C_CreateObject(hSession, template, 
 *                              sizeof(template)/sizeof(template[0]), 
 *                              &hTrustObject);
 *     
 *     if (rv == CKR_OK) {
 *         printf("Trust object created successfully\n");
 *     } else {
 *         printf("Failed to create trust object: 0x%08lX\n", rv);
 *     }
 *     
 *     return rv;
 * }
 * #endif // WOLFPKCS11_NSS
 * \endcode
 */

/*!
 * \brief Example: Using NSS TLS Extended Master Key Derivation
 * 
 * This example shows how to use the NSS TLS Extended Master Key derivation
 * mechanism for TLS 1.2 connections with extended master secret support.
 * 
 * \code
 * #ifdef WOLFPKCS11_NSS
 * CK_RV derive_extended_master_key_example(CK_SESSION_HANDLE hSession,
 *                                          CK_OBJECT_HANDLE hPreMasterKey) {
 *     // TLS handshake hash (this would come from actual handshake)
 *     CK_BYTE sessionHash[32] = {0}; // SHA-256 hash of handshake messages
 *     CK_VERSION tlsVersion = {1, 2}; // TLS 1.2
 *     
 *     // Set up extended master key derive parameters
 *     CK_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_PARAMS params;
 *     params.prfHashMechanism = CKM_SHA256_HMAC;
 *     params.pSessionHash = sessionHash;
 *     params.ulSessionHashLen = sizeof(sessionHash);
 *     params.pVersion = &tlsVersion;
 *     
 *     CK_MECHANISM mechanism = {
 *         CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE,
 *         &params,
 *         sizeof(params)
 *     };
 *     
 *     // Template for the derived master key
 *     CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
 *     CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
 *     CK_ULONG keyLen = 48; // TLS master key is 48 bytes
 *     CK_BBOOL ckTrue = CK_TRUE;
 *     
 +     CK_ATTRIBUTE template[] = {
 +         {CKA_CLASS,       &keyClass, sizeof(keyClass)},
 +         {CKA_KEY_TYPE,    &keyType,  sizeof(keyType)},
 +         {CKA_VALUE_LEN,   &keyLen,   sizeof(keyLen)},
 +         {CKA_EXTRACTABLE, &ckTrue,   sizeof(ckTrue)}
 +     };
 + *     
 + *     CK_OBJECT_HANDLE hMasterKey;
 + *     CK_RV rv = C_DeriveKey(hSession, &mechanism, hPreMasterKey, 
 + *                           template, sizeof(template)/sizeof(template[0]), 
 + *                           &hMasterKey);
 + *     
 + *     if (rv == CKR_OK) {
 + *         printf("Extended master key derived successfully\n");
 + *     } else {
 + *         printf("Failed to derive extended master key: 0x%08lX\n", rv);
 + *     }
 + *     
 + *     return rv;
 + * }
 + * #endif // WOLFPKCS11_NSS
 + * \endcode
 + */
 +
 +/*!
 + * \brief Example: PKCS#12 PBE Key Generation
 + * 
 + * This example demonstrates how to generate PKCS#12 Password-Based Encryption
 + * keys using the NSS PKCS#12 PBE mechanisms.
 + * 
 + * \code
 + * #ifdef WOLFPKCS11_NSS
 + * CK_RV generate_pkcs12_pbe_key_example(CK_SESSION_HANDLE hSession) {
 + *     // PKCS#12 PBE parameters (simplified - actual implementation 
 + *     // would need proper PKCS#12 parameter structure)
 + *     CK_BYTE salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
 + *     CK_ULONG iterations = 2048;
 + *     
 + *     // This would be replaced with actual PKCS#12 PBE parameter structure
 + *     struct {
 + *         CK_BYTE* pSalt;
 + *         CK_ULONG ulSaltLen;
 + *         CK_ULONG ulIteration;
 + *     } pbeParams;
 + *     
 + *     pbeParams.pSalt = salt;
 + *     pbeParams.ulSaltLen = sizeof(salt);
 + *     pbeParams.ulIteration = iterations;
 + *     
 + *     CK_MECHANISM mechanism = {
 + *         CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN,
 + *         &pbeParams,
 + *         sizeof(pbeParams)
 + *     };
 + *     
 + *     // Template for the generated key
 + *     CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
 + *     CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
 + *     CK_ULONG keyLen = 32; // SHA-256 produces 32-byte keys
 + *     CK_BBOOL ckTrue = CK_TRUE;
 + *     CK_BBOOL ckFalse = CK_FALSE;
 + *     
 + *     CK_ATTRIBUTE template[] = {
 + *         {CKA_CLASS,       &keyClass, sizeof(keyClass)},
 + *         {CKA_KEY_TYPE,    &keyType,  sizeof(keyType)},
 + *         {CKA_VALUE_LEN,   &keyLen,   sizeof(keyLen)},
 + *         {CKA_TOKEN,       &ckFalse,  sizeof(ckFalse)},
 + *         {CKA_PRIVATE,     &ckTrue,   sizeof(ckTrue)},
 + *         {CKA_SENSITIVE,   &ckTrue,   sizeof(ckTrue)},
 + *         {CKA_EXTRACTABLE, &ckFalse,  sizeof(ckFalse)}
 + *     };
 + *     
 + *     CK_OBJECT_HANDLE hKey;
 + *     CK_RV rv = C_GenerateKey(hSession, &mechanism, template, 
 + *                             sizeof(template)/sizeof(template[0]), &hKey);
 + *     
 + *     if (rv == CKR_OK) {
 + *         printf("PKCS#12 PBE key generated successfully\n");
 + *     } else if (rv == CKR_MECHANISM_INVALID) {
 + *         printf("NSS extensions not available - compile with --enable-nss\n");
 + *     } else {
 + *         printf("Failed to generate PKCS#12 PBE key: 0x%08lX\n", rv);
 + *     }
 + *     
 + *     return rv;
 + * }
 + * #endif // WOLFPKCS11_NSS
 + * \endcode
 + */
 +
 +/*!
 + * \brief Example: Using NSS TLS PRF for Signing
 + * 
 + * This example shows how to use the NSS TLS PRF General SHA256 mechanism
 + * for signing operations in TLS contexts.
 + * 
 + * \code
 + * #ifdef WOLFPKCS11_NSS
 + * CK_RV tls_prf_sign_example(CK_SESSION_HANDLE hSession, 
 + *                            CK_OBJECT_HANDLE hKey) {
 + *     CK_MECHANISM mechanism = {CKM_NSS_TLS_PRF_GENERAL_SHA256, NULL, 0};
 + *     
 + *     // Initialize signing operation
 + *     CK_RV rv = C_SignInit(hSession, &mechanism, hKey);
 + *     if (rv != CKR_OK) {
 + *         if (rv == CKR_MECHANISM_INVALID) {
 + *             printf("NSS TLS PRF mechanism not available\n");
 + *         }
 + *         return rv;
 + *     }
 + *     
 + *     // Data to be signed (TLS context specific)
 + *     CK_BYTE data[] = "TLS PRF signing test data";
 + *     CK_ULONG dataLen = sizeof(data) - 1;
 + *     
 + *     // Get signature length
 + *     CK_ULONG sigLen = 0;
 + *     rv = C_Sign(hSession, data, dataLen, NULL, &sigLen);
 + *     if (rv != CKR_OK) {
 + *         return rv;
 + *     }
 + *     
 + *     // Allocate buffer and get signature
 + *     CK_BYTE* signature = malloc(sigLen);
 + *     if (!signature) {
 + *         return CKR_HOST_MEMORY;
 + *     }
 + *     
 + *     rv = C_Sign(hSession, data, dataLen, signature, &sigLen);
 + *     if (rv == CKR_OK) {
 + *         printf("TLS PRF signature generated successfully (%lu bytes)\n", sigLen);
 + *         // Use signature...
 + *     } else {
 + *         printf("Failed to generate TLS PRF signature: 0x%08lX\n", rv);
 + *     }
 + *     
 + *     free(signature);
 + *     return rv;
 + * }
 + * #endif // WOLFPKCS11_NSS
 + * \endcode
 + */
 +
 +/*! @} */ /* end of pkcs11_nss_examples group */
 +
 +/*!
 + * \defgroup pkcs11_nss_compatibility NSS Compatibility Notes
 + * \ingroup pkcs11_nss_extensions_overview
 + * \brief Important compatibility information for NSS extensions.
 + * 
 + * @{
 + */
 +
 +/*!
 + * \brief Key Size Limitations with NSS Extensions
 + * 
 + * When NSS extensions are enabled, wolfPKCS11 adjusts certain size limitations
 + * to be compatible with NSS expectations:
 + * 
 + * - **DH Key Size**: Increased from 4096 bits to 8192 bits maximum
 + * - **Symmetric Key Size**: Increased from 512 bytes to 2048 bytes maximum
 + * 
 + * These changes ensure compatibility with NSS applications that may require
 + * larger key sizes than the standard wolfPKCS11 configuration.
 + * 
 + * \note These size increases only apply when compiled with `--enable-nss`.
 + */
 +
 +/*!
 + * \brief Trust Object Storage
 + * 
 + * NSS trust objects (CKO_NSS_TRUST) are stored and managed differently than
 + * other PKCS#11 objects:
 + * 
 + * - Trust objects are identified by certificate issuer and serial number
 + * - SHA-1 and MD5 hashes are stored for certificate identification
 + * - Trust settings are preserved across token operations
 + * - Email addresses from certificates are extracted and stored
 + * 
 + * Trust objects work in conjunction with certificate objects to provide
 + * complete NSS-compatible certificate and trust management.
 + */
 +
 +/*!
 + * \brief NSS Database Compatibility
 + * 
 + * wolfPKCS11 with NSS extensions can be used as a drop-in replacement for
 + * NSS's PKCS#11 module in many applications:
 + * 
 + * **Supported Applications:**
 + * - Mozilla Firefox
 + * - Mozilla Thunderbird  
 + * - NSS command-line tools (certutil, pk12util, cmsutil)
 + * - Applications using NSS SSL/TLS stack
 + * 
 + * **Configuration Example:**
 + * \code
 + * # Add to NSS database configuration
 + * library=/usr/local/lib/libwolfpkcs11.so
 + * name=wolfPKCS11
 + * NSS=Flags=internal,critical slotParams={0x00000001=[slotFlags=ECC,RSA,AES]}
 + * \endcode
 + * 
 + * \warning Some advanced NSS features may not be fully supported. 
 + *          Test thoroughly in your specific environment.
 + */
 +
 +/*! @} */ /* end of pkcs11_nss_compatibility group */