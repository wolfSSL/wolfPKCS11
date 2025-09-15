/**
 * \page pkcs11_sign_overview Sign and Verify
 * Digital signature generation and verification, including single-part and
 * recover operations. See PKCS#11 v2.40 Section 11.10 "Signature and MAC Functions"
 * and Section 11.11 "Verification Functions".
 * 
 * Signing operations produce a signature or MAC over data using a private key
 * or secret key. Verification operations check a signature or MAC using the
 * corresponding public or secret key. Multi-part operations support streaming.
 * - \ref pkcs11_09_sign_verify
 */

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Initialize a signature or MAC operation.
 * 
 * Initializes a signature or MAC operation with the specified mechanism and key.
 * See PKCS#11 v2.40 Section 11.10.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID.
 * \return CKR_OPERATION_ACTIVE if an operation is already active.
 * \return CKR_KEY_HANDLE_INVALID, CKR_KEY_TYPE_INCONSISTENT.
 * \return CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID.
 * \return CKR_KEY_FUNCTION_NOT_PERMITTED if key cannot be used to sign/MAC.
 * \return CKR_ARGUMENTS_BAD if pMechanism is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pMechanism Pointer to CK_MECHANISM specifying signature/MAC mechanism.
 * \param hKey Handle of the signing/MAC key.
 * 
 * _Example_
 * \code
 * CK_MECHANISM mech = {CKM_ECDSA, NULL_PTR, 0};
 * CK_RV rv = C_SignInit(hSession, &mech, hPrivKey);
 * \endcode
 * 
 * \sa C_Sign, C_SignUpdate, C_SignFinal
 */
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Sign data in a single operation.
 * 
 * Signs data in a single part. Use the two-call pattern to size the output
 * buffer. See PKCS#11 v2.40 Section 11.10.2.
 * 
 * \return CKR_OK on success.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_SignInit not called.
 * \return CKR_BUFFER_TOO_SMALL if signature buffer too small.
 * \return CKR_DATA_LEN_RANGE if data length invalid for mechanism.
 * \return CKR_ARGUMENTS_BAD if inputs are NULL_PTR when required.
 * 
 * \param hSession The session handle.
 * \param pData Input data to sign.
 * \param ulDataLen Length of input data.
 * \param pSignature Output buffer for signature (may be NULL_PTR).
 * \param pulSignatureLen Pointer to signature length.
 * 
 * _Example_
 * \code
 * CK_MECHANISM mech = {CKM_ECDSA, NULL_PTR, 0};
 * CK_BYTE msg[] = "hello";
 * CK_BYTE_PTR sig = NULL;
 * CK_ULONG sigLen = 0;
 * CK_RV rv = C_SignInit(hSession, &mech, hPrivKey);
 * if (rv == CKR_OK) {
 *     rv = C_Sign(hSession, msg, sizeof(msg)-1, NULL_PTR, &sigLen);
 *     if (rv == CKR_OK) {
 *         sig = malloc(sigLen);
 *         if (sig) {
 *             rv = C_Sign(hSession, msg, sizeof(msg)-1, sig, &sigLen);
 *             free(sig);
 *         }
 *     }
 * }
 * \endcode
 * 
 * \sa C_SignInit
 */
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Add data to a multi-part signing/MAC operation.
 * 
 * Updates a multi-part signature/MAC operation with another chunk of data.
 * See PKCS#11 v2.40 Section 11.10.3.
 * 
 * \return CKR_OK on success.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_SignInit not called.
 * \return CKR_ARGUMENTS_BAD if pPart is NULL_PTR and ulPartLen > 0.
 * 
 * \param hSession The session handle.
 * \param pPart Data part to add.
 * \param ulPartLen Length of data part.
 * 
 * \sa C_SignFinal
 */
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Finish a multi-part signature/MAC operation.
 * 
 * Completes a multi-part sign/MAC operation and returns the signature/MAC.
 * Use two-call pattern to size the output. See PKCS#11 v2.40 Section 11.10.4.
 * 
 * \return CKR_OK on success.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_SignInit not called.
 * \return CKR_BUFFER_TOO_SMALL if output buffer too small.
 * 
 * \param hSession The session handle.
 * \param pSignature Output buffer for signature/MAC (may be NULL_PTR).
 * \param pulSignatureLen Pointer to signature/MAC length.
 * 
 * _Example_
 * \code
 * CK_BYTE sig[64];
 * CK_ULONG sigLen = sizeof(sig);
 * CK_RV rv = C_SignFinal(hSession, sig, &sigLen);
 * \endcode
 * 
 * \sa C_SignUpdate
 */
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Initialize a sign-recover operation.
 * 
 * Initializes a sign-recover operation where data can be recovered from
 * the signature (mechanism dependent). See PKCS#11 v2.40 Section 11.10.5.
 * 
 * \return CKR_OK on success or mechanism-specific errors.
 * \param hSession The session handle.
 * \param pMechanism Mechanism for sign-recover.
 * \param hKey Signing key handle.
 */
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Perform a single-part sign-recover operation.
 * 
 * Signs input data and returns the recovered data/signature as per the
 * mechanism. See PKCS#11 v2.40 Section 11.10.6.
 * 
 * \return CKR_OK on success; CKR_BUFFER_TOO_SMALL if output too small.
 * \param hSession The session handle.
 * \param pData Input data.
 * \param ulDataLen Input length.
 * \param pSignature Output buffer.
 * \param pulSignatureLen Output length.
 */
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Initialize a verification operation.
 * 
 * Initializes a verification operation with the specified mechanism and key.
 * See PKCS#11 v2.40 Section 11.11.1.
 * 
 * \return CKR_OK on success; CKR_MECHANISM_INVALID or CKR_KEY_HANDLE_INVALID on error.
 * \param hSession The session handle.
 * \param pMechanism Mechanism for verification.
 * \param hKey Verification key handle.
 * 
 * _Example_
 * \code
 * CK_MECHANISM mech = {CKM_ECDSA, NULL_PTR, 0};
 * CK_RV rv = C_VerifyInit(hSession, &mech, hPubKey);
 * \endcode
 * 
 * \sa C_Verify, C_VerifyUpdate, C_VerifyFinal
 */
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Verify a signature in a single operation.
 * 
 * Verifies a signature over input data in a single call.
 * See PKCS#11 v2.40 Section 11.11.2.
 * 
 * \return CKR_OK if signature is valid.
 * \return CKR_SIGNATURE_INVALID if signature verification fails.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_VerifyInit not called.
 * \return CKR_ARGUMENTS_BAD for invalid pointers.
 * 
 * \param hSession The session handle.
 * \param pData Input data that was signed.
 * \param ulDataLen Length of input data.
 * \param pSignature Signature bytes to verify.
 * \param ulSignatureLen Length of signature.
 * 
 * _Example_
 * \code
 * CK_BYTE msg[] = "hello";
 * CK_BYTE sig[64]; CK_ULONG sigLen = sizeof(sig);
 * CK_MECHANISM mech = {CKM_ECDSA, NULL_PTR, 0};
 * CK_RV rv = C_VerifyInit(hSession, &mech, hPubKey);
 * if (rv == CKR_OK) {
 *     rv = C_Verify(hSession, msg, sizeof(msg)-1, sig, sigLen);
 *     if (rv == CKR_OK) {
 *         printf("Signature valid\n");
 *     }
 * }
 * \endcode
 * 
 * \sa C_VerifyInit
 */
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Add data to a multi-part verification operation.
 * 
 * Updates a multi-part verification operation with another chunk of data.
 * See PKCS#11 v2.40 Section 11.11.3.
 * 
 * \return CKR_OK on success; CKR_OPERATION_NOT_INITIALIZED otherwise.
 * \param hSession The session handle.
 * \param pPart Data part to verify.
 * \param ulPartLen Length of data part.
 * 
 * \sa C_VerifyFinal
 */
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Finish a multi-part verification operation.
 * 
 * Completes a multi-part verification operation using the provided signature.
 * See PKCS#11 v2.40 Section 11.11.4.
 * 
 * \return CKR_OK if signature is valid; CKR_SIGNATURE_INVALID otherwise.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_VerifyInit not called.
 * 
 * \param hSession The session handle.
 * \param pSignature Signature bytes to verify.
 * \param ulSignatureLen Length of signature.
 * 
 * _Example_
 * \code
 * CK_BYTE sig[64]; CK_ULONG sigLen = sizeof(sig);
 * CK_RV rv = C_VerifyFinal(hSession, sig, sigLen);
 * \endcode
 * 
 * \sa C_VerifyUpdate
 */
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Initialize a verify-recover operation.
 * 
 * Initializes a verify-recover operation for mechanisms supporting recovery.
 * See PKCS#11 v2.40 Section 11.11.5.
 * 
 * \return CKR_OK on success or mechanism-specific errors.
 * \param hSession The session handle.
 * \param pMechanism Mechanism for verify-recover.
 * \param hKey Verification key handle.
 */
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

/*!
 * \ingroup pkcs11_09_sign_verify
 * \brief Perform a single-part verify-recover operation.
 * 
 * Verifies and recovers data from a signature per the mechanism.
 * See PKCS#11 v2.40 Section 11.11.6.
 * 
 * \return CKR_OK if recovery successful; CKR_SIGNATURE_INVALID otherwise.
 * \param hSession The session handle.
 * \param pSignature Input signature bytes.
 * \param ulSignatureLen Length of signature.
 * \param pData Output buffer for recovered data.
 * \param pulDataLen Pointer to recovered data length.
 */
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
