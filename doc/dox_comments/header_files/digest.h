/**
 * \page pkcs11_digest_overview Digest
 * Message digest operations (hashing), single-part and multi-part. See PKCS#11
 * v2.40 Section 11.5 "Message Digests".
 * - \ref pkcs11_07_digest
 */

/*!
 * \ingroup pkcs11_07_digest
 * \brief Initialize a digest operation.
 * 
 * Initializes a message digest operation with the specified mechanism (e.g.,
 * CKM_SHA256). See PKCS#11 v2.40 Section 11.5.1.
 * 
 * \return CKR_OK on success; CKR_MECHANISM_INVALID if unsupported.
 * \return CKR_OPERATION_ACTIVE if another operation is active.
 * \param hSession The session handle.
 * \param pMechanism Digest mechanism.
 */
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);

/*!
 * \ingroup pkcs11_07_digest
 * \brief Compute a digest in a single operation.
 * 
 * Computes the message digest of the input data in a single call. Use the
 * two-call pattern to size the output buffer. See Section 11.5.2.
 * 
 * \return CKR_OK on success; CKR_BUFFER_TOO_SMALL if pDigest too small.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_DigestInit not called.
 * \param hSession The session handle.
 * \param pData Input data buffer.
 * \param ulDataLen Input length.
 * \param pDigest Output buffer (may be NULL_PTR to query size).
 * \param pulDigestLen Pointer to digest length.
 * 
 * _Example_
 * \code
 * CK_MECHANISM mech = {CKM_SHA256, NULL_PTR, 0};
 * CK_BYTE data[] = "abc";
 * CK_ULONG dgstLen = 0;
 * C_DigestInit(hSession, &mech);
 * C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &dgstLen);
 * CK_BYTE* dgst = malloc(dgstLen);
 * C_Digest(hSession, data, sizeof(data)-1, dgst, &dgstLen);
 * free(dgst);
 * \endcode
 */
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);

/*!
 * \ingroup pkcs11_07_digest
 * \brief Add data to a multi-part digest operation.
 * 
 * Updates the digest operation with another chunk of data. See Section 11.5.3.
 * 
 * \return CKR_OK on success; CKR_OPERATION_NOT_INITIALIZED otherwise.
 * \param hSession The session handle.
 * \param pPart Input data part.
 * \param ulPartLen Length of input data part.
 */
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

/*!
 * \ingroup pkcs11_07_digest
 * \brief Digest a secret key (if supported).
 * 
 * Mixes the value of a secret key into the digest operation. See Section 11.5.4.
 * 
 * \return CKR_OK on success; CKR_KEY_INDIGESTIBLE if not allowed.
 * \param hSession The session handle.
 * \param hKey Secret key handle.
 */
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);

/*!
 * \ingroup pkcs11_07_digest
 * \brief Finalize a multi-part digest operation.
 * 
 * Completes a digest operation and returns the result. Use the two-call
 * pattern to size the output. See Section 11.5.5.
 * 
 * \return CKR_OK on success; CKR_BUFFER_TOO_SMALL if output too small.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_DigestInit not called.
 * \param hSession The session handle.
 * \param pDigest Output buffer (may be NULL_PTR).
 * \param pulDigestLen Pointer to digest length.
 */
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
