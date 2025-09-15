/**
 * \page pkcs11_encrypt_overview Encryption and Decryption
 * Symmetric/asymmetric encryption and decryption operations, including
 * single-part and multi-part. See PKCS#11 v2.40 Section 11.8 "Encryption Functions"
 * and Section 11.9 "Decryption Functions".
 * 
 * Encryption operations transform plaintext into ciphertext using a key and
 * mechanism. Both single-part (all data at once) and multi-part (streaming)
 * operations are supported. Use the two-call pattern for output sizing.
 * - \ref pkcs11_08_encrypt_decrypt
 */

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Initialize an encryption operation.
 * 
 * Initializes an encryption operation with the specified mechanism and key.
 * The mechanism determines the encryption algorithm and parameters.
 * See PKCS#11 v2.40 Section 11.8.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_ACTIVE if an operation is already active.
 * \return CKR_KEY_HANDLE_INVALID if hKey is invalid.
 * \return CKR_MECHANISM_INVALID if mechanism is not supported.
 * \return CKR_MECHANISM_PARAM_INVALID if mechanism parameters are invalid.
 * \return CKR_KEY_FUNCTION_NOT_PERMITTED if key cannot be used for encryption.
 * \return CKR_KEY_TYPE_INCONSISTENT if key type doesn't match mechanism.
 * \return CKR_ARGUMENTS_BAD if pMechanism is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pMechanism Pointer to CK_MECHANISM structure specifying encryption mechanism.
 * \param hKey Handle of the encryption key.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hKey;
 * CK_MECHANISM mechanism = {CKM_AES_CBC, NULL_PTR, 0};
 * CK_RV rv;
 * 
 * rv = C_EncryptInit(hSession, &mechanism, hKey);
 * if (rv == CKR_OK) {
 *     // Encryption initialized, ready to encrypt data
 * }
 * \endcode
 * 
 * \sa C_Encrypt
 * \sa C_EncryptUpdate
 * \sa C_EncryptFinal
 */
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Encrypt data in a single operation.
 * 
 * Encrypts data in a single operation. Use the two-call pattern: first call
 * with pEncryptedData=NULL_PTR to get required buffer size, then call again
 * with allocated buffer. See PKCS#11 v2.40 Section 11.8.2.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_EncryptInit was not called.
 * \return CKR_DATA_LEN_RANGE if data length is invalid for mechanism.
 * \return CKR_DATA_INVALID if input data is invalid.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if pData or pulEncryptedDataLen is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pData Input data to encrypt.
 * \param ulDataLen Length of input data in bytes.
 * \param pEncryptedData Output buffer for encrypted data (may be NULL_PTR to query size).
 * \param pulEncryptedDataLen Pointer to encrypted data length.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hKey;
 * CK_BYTE plaintext[] = "Hello, World!";
 * CK_BYTE_PTR ciphertext = NULL;
 * CK_ULONG ciphertextLen = 0;
 * CK_MECHANISM mechanism = {CKM_AES_CBC, NULL_PTR, 0};
 * CK_RV rv;
 * 
 * rv = C_EncryptInit(hSession, &mechanism, hKey);
 * if (rv == CKR_OK) {
 *     // Get required buffer size
 *     rv = C_Encrypt(hSession, plaintext, sizeof(plaintext) - 1, 
 *                    NULL_PTR, &ciphertextLen);
 *     if (rv == CKR_OK) {
 *         ciphertext = malloc(ciphertextLen);
 *         if (ciphertext) {
 *             rv = C_Encrypt(hSession, plaintext, sizeof(plaintext) - 1,
 *                            ciphertext, &ciphertextLen);
 *             if (rv == CKR_OK) {
 *                 printf("Encryption successful, %lu bytes\n", ciphertextLen);
 *             }
 *             free(ciphertext);
 *         }
 *     }
 * }
 * \endcode
 * 
 * \sa C_EncryptInit
 * \sa C_EncryptUpdate
 */
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Continue a multi-part encryption operation.
 * 
 * Continues a multi-part encryption operation, processing another chunk of
 * data. Can be called multiple times to encrypt large amounts of data.
 * See PKCS#11 v2.40 Section 11.8.3.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_EncryptInit was not called.
 * \return CKR_DATA_LEN_RANGE if data length is invalid.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if pPart or pulEncryptedPartLen is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pPart Input data part to encrypt.
 * \param ulPartLen Length of input data part.
 * \param pEncryptedPart Output buffer for encrypted data part (may be NULL_PTR).
 * \param pulEncryptedPartLen Pointer to encrypted part length.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_BYTE data[1024];
 * CK_BYTE encrypted[1024];
 * CK_ULONG encryptedLen = sizeof(encrypted);
 * CK_RV rv;
 * 
 * // ... initialize encryption ...
 * 
 * rv = C_EncryptUpdate(hSession, data, sizeof(data), 
 *                      encrypted, &encryptedLen);
 * if (rv == CKR_OK) {
 *     printf("Encrypted %lu bytes\n", encryptedLen);
 * }
 * \endcode
 * 
 * \sa C_EncryptInit
 * \sa C_EncryptFinal
 */
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Finish a multi-part encryption operation.
 * 
 * Finishes a multi-part encryption operation, returning any remaining
 * encrypted data. This includes final padding if required by the mechanism.
 * See PKCS#11 v2.40 Section 11.8.4.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_EncryptInit was not called.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if pulLastEncryptedPartLen is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pLastEncryptedPart Output buffer for final encrypted data (may be NULL_PTR).
 * \param pulLastEncryptedPartLen Pointer to final encrypted data length.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_BYTE finalData[64];
 * CK_ULONG finalLen = sizeof(finalData);
 * CK_RV rv;
 * 
 * // ... perform EncryptUpdate operations ...
 * 
 * rv = C_EncryptFinal(hSession, finalData, &finalLen);
 * if (rv == CKR_OK) {
 *     printf("Final encrypted data: %lu bytes\n", finalLen);
 * }
 * \endcode
 * 
 * \sa C_EncryptInit
 * \sa C_EncryptUpdate
 */
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Initialize a decryption operation.
 * 
 * Initializes a decryption operation with the specified mechanism and key.
 * The mechanism must match the one used for encryption.
 * See PKCS#11 v2.40 Section 11.9.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_ACTIVE if an operation is already active.
 * \return CKR_KEY_HANDLE_INVALID if hKey is invalid.
 * \return CKR_MECHANISM_INVALID if mechanism is not supported.
 * \return CKR_MECHANISM_PARAM_INVALID if mechanism parameters are invalid.
 * \return CKR_KEY_FUNCTION_NOT_PERMITTED if key cannot be used for decryption.
 * \return CKR_KEY_TYPE_INCONSISTENT if key type doesn't match mechanism.
 * \return CKR_ARGUMENTS_BAD if pMechanism is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pMechanism Pointer to CK_MECHANISM structure specifying decryption mechanism.
 * \param hKey Handle of the decryption key.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hKey;
 * CK_MECHANISM mechanism = {CKM_AES_CBC, NULL_PTR, 0};
 * CK_RV rv;
 * 
 * rv = C_DecryptInit(hSession, &mechanism, hKey);
 * if (rv == CKR_OK) {
 *     // Decryption initialized, ready to decrypt data
 * }
 * \endcode
 * 
 * \sa C_Decrypt
 * \sa C_DecryptUpdate
 * \sa C_DecryptFinal
 */
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Decrypt data in a single operation.
 * 
 * Decrypts data in a single operation. Use the two-call pattern: first call
 * with pData=NULL_PTR to get required buffer size, then call again with
 * allocated buffer. See PKCS#11 v2.40 Section 11.9.2.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_DecryptInit was not called.
 * \return CKR_ENCRYPTED_DATA_LEN_RANGE if encrypted data length is invalid.
 * \return CKR_ENCRYPTED_DATA_INVALID if encrypted data is invalid.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if pEncryptedData or pulDataLen is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pEncryptedData Input encrypted data to decrypt.
 * \param ulEncryptedDataLen Length of encrypted data in bytes.
 * \param pData Output buffer for decrypted data (may be NULL_PTR to query size).
 * \param pulDataLen Pointer to decrypted data length.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hKey;
 * CK_BYTE ciphertext[64];
 * CK_BYTE_PTR plaintext = NULL;
 * CK_ULONG plaintextLen = 0;
 * CK_MECHANISM mechanism = {CKM_AES_CBC, NULL_PTR, 0};
 * CK_RV rv;
 * 
 * rv = C_DecryptInit(hSession, &mechanism, hKey);
 * if (rv == CKR_OK) {
 *     // Get required buffer size
 *     rv = C_Decrypt(hSession, ciphertext, sizeof(ciphertext),
 *                    NULL_PTR, &plaintextLen);
 *     if (rv == CKR_OK) {
 *         plaintext = malloc(plaintextLen);
 *         if (plaintext) {
 *             rv = C_Decrypt(hSession, ciphertext, sizeof(ciphertext),
 *                            plaintext, &plaintextLen);
 *             if (rv == CKR_OK) {
 *                 printf("Decryption successful, %lu bytes\n", plaintextLen);
 *             }
 *             free(plaintext);
 *         }
 *     }
 * }
 * \endcode
 * 
 * \sa C_DecryptInit
 * \sa C_DecryptUpdate
 */
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Continue a multi-part decryption operation.
 * 
 * Continues a multi-part decryption operation, processing another chunk of
 * encrypted data. Can be called multiple times to decrypt large amounts of data.
 * See PKCS#11 v2.40 Section 11.9.3.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_DecryptInit was not called.
 * \return CKR_ENCRYPTED_DATA_LEN_RANGE if encrypted data length is invalid.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if pEncryptedPart or pulPartLen is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pEncryptedPart Input encrypted data part to decrypt.
 * \param ulEncryptedPartLen Length of encrypted data part.
 * \param pPart Output buffer for decrypted data part (may be NULL_PTR).
 * \param pulPartLen Pointer to decrypted part length.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_BYTE encryptedData[1024];
 * CK_BYTE decrypted[1024];
 * CK_ULONG decryptedLen = sizeof(decrypted);
 * CK_RV rv;
 * 
 * // ... initialize decryption ...
 * 
 * rv = C_DecryptUpdate(hSession, encryptedData, sizeof(encryptedData),
 *                      decrypted, &decryptedLen);
 * if (rv == CKR_OK) {
 *     printf("Decrypted %lu bytes\n", decryptedLen);
 * }
 * \endcode
 * 
 * \sa C_DecryptInit
 * \sa C_DecryptFinal
 */
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Finish a multi-part decryption operation.
 * 
 * Finishes a multi-part decryption operation, returning any remaining
 * decrypted data. This includes removing final padding if required.
 * See PKCS#11 v2.40 Section 11.9.4.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_DecryptInit was not called.
 * \return CKR_ENCRYPTED_DATA_INVALID if final encrypted data is invalid.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if pulLastPartLen is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pLastPart Output buffer for final decrypted data (may be NULL_PTR).
 * \param pulLastPartLen Pointer to final decrypted data length.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_BYTE finalData[64];
 * CK_ULONG finalLen = sizeof(finalData);
 * CK_RV rv;
 * 
 * // ... perform DecryptUpdate operations ...
 * 
 * rv = C_DecryptFinal(hSession, finalData, &finalLen);
 * if (rv == CKR_OK) {
 *     printf("Final decrypted data: %lu bytes\n", finalLen);
 * }
 * \endcode
 * 
 * \sa C_DecryptInit
 * \sa C_DecryptUpdate
 */
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Combined decrypt and digest update operation.
 * 
 * Continues a multi-part combined decrypt and digest operation. The decrypted
 * data is automatically fed into an active digest operation. Both operations
 * must be initialized separately. See PKCS#11 v2.40 Section 11.12.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if operations are not initialized.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if required pointers are NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pEncryptedPart Input encrypted data part.
 * \param ulEncryptedPartLen Length of encrypted data part.
 * \param pPart Output buffer for decrypted data part.
 * \param pulPartLen Pointer to decrypted part length.
 * 
 * \sa C_DecryptInit
 * \sa C_DigestInit
 */
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Combined digest and encrypt update operation.
 * 
 * Continues a multi-part combined digest and encrypt operation. The input data
 * is automatically fed into an active digest operation and then encrypted. Both
 * operations must be initialized separately. See PKCS#11 v2.40 Section 11.12.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if operations are not initialized.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if required pointers are NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pPart Input data part to digest and encrypt.
 * \param ulPartLen Length of input data part.
 * \param pEncryptedPart Output buffer for encrypted data part.
 * \param pulEncryptedPartLen Pointer to encrypted part length.
 * 
 * \sa C_DigestInit
 * \sa C_EncryptInit
 */
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);



/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Combined sign and encrypt update operation.
 * 
 * Continues a multi-part combined sign and encrypt operation. The input data
 * is fed into an active signature operation and then encrypted. Both operations
 * must be initialized separately. See PKCS#11 v2.40 Section 11.12.2.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if operations are not initialized.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if required pointers are NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pPart Input data part to sign and encrypt.
 * \param ulPartLen Length of input data part.
 * \param pEncryptedPart Output buffer for encrypted data part.
 * \param pulEncryptedPartLen Pointer to encrypted part length.
 * 
 * \sa C_SignInit
 * \sa C_EncryptInit
 */
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);

/*!
 * \ingroup pkcs11_08_encrypt_decrypt
 * \brief Combined decrypt and verify update operation.
 * 
 * Continues a multi-part combined decrypt and verify operation. The encrypted
 * data is decrypted and then fed into an active verification operation. Both
 * operations must be initialized separately. See PKCS#11 v2.40 Section 11.12.3.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if operations are not initialized.
 * \return CKR_BUFFER_TOO_SMALL if output buffer is too small.
 * \return CKR_ARGUMENTS_BAD if required pointers are NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pEncryptedPart Input encrypted data part.
 * \param ulEncryptedPartLen Length of encrypted data part.
 * \param pPart Output buffer for decrypted data part.
 * \param pulPartLen Pointer to decrypted part length.
 * 
 * \sa C_DecryptInit
 * \sa C_VerifyInit
 */
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
