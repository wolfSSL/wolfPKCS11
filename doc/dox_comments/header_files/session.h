/**
 * \page pkcs11_session_overview Sessions and Login
 * Create and manage sessions, and handle user authentication. See PKCS#11 v2.40
 * Section 11.6 "Session Management" and Section 11.7 "User Authentication".
 * 
 * Sessions provide the context for cryptographic operations. A session can be
 * read-only or read-write, and users can log in as either a normal user (CKU_USER)
 * or security officer (CKU_SO) to access private objects and perform privileged
 * operations.
 * - \ref pkcs11_03_session
 */

/*!
 * \ingroup pkcs11_03_session
 * \brief Open a new session with a token.
 * 
 * Opens a session between an application and a token in a particular slot.
 * The session can be read-only or read-write. All sessions must include the
 * CKF_SERIAL_SESSION flag. See PKCS#11 v2.40 Section 11.6.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SLOT_ID_INVALID if slotID is invalid.
 * \return CKR_TOKEN_NOT_PRESENT if no token is present in the slot.
 * \return CKR_TOKEN_NOT_RECOGNIZED if token is not recognized.
 * \return CKR_TOKEN_WRITE_PROTECTED if read-write session requested on write-protected token.
 * \return CKR_SESSION_COUNT if too many sessions are open.
 * \return CKR_ARGUMENTS_BAD if phSession is NULL_PTR.
 * \return CKR_HOST_MEMORY if memory allocation fails.
 * 
 * \param slotID The ID of the slot containing the token.
 * \param flags Session flags: CKF_SERIAL_SESSION (required) and optionally CKF_RW_SESSION.
 * \param pApplication Application-defined pointer passed to notification callback.
 * \param Notify Notification callback function (may be NULL_PTR).
 * \param phSession Pointer to receive the new session handle.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_RV rv;
 * 
 * // Open read-write session
 * rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
 *                    NULL_PTR, NULL_PTR, &hSession);
 * if (rv == CKR_OK) {
 *     printf("Session opened: %lu\n", hSession);
 *     
 *     // ... perform operations ...
 *     
 *     C_CloseSession(hSession);
 * }
 * \endcode
 * 
 * \sa C_CloseSession
 * \sa C_GetSessionInfo
 */
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);

/*!
 * \ingroup pkcs11_03_session
 * \brief Close a session.
 * 
 * Closes a session between an application and a token. All active operations
 * in the session are terminated. See PKCS#11 v2.40 Section 11.6.2.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * 
 * \param hSession The session handle to close.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_RV rv;
 * 
 * rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
 * if (rv == CKR_OK) {
 *     // ... perform operations ...
 *     
 *     rv = C_CloseSession(hSession);
 *     if (rv != CKR_OK) {
 *         printf("Failed to close session: 0x%08lX\n", rv);
 *     }
 * }
 * \endcode
 * 
 * \sa C_OpenSession
 * \sa C_CloseAllSessions
 */
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);

/*!
 * \ingroup pkcs11_03_session
 * \brief Close all sessions on a slot.
 * 
 * Closes all sessions an application has with a token in a particular slot.
 * All active operations in all sessions are terminated. See PKCS#11 v2.40
 * Section 11.6.3.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SLOT_ID_INVALID if slotID is invalid.
 * \return CKR_TOKEN_NOT_PRESENT if no token is present in the slot.
 * 
 * \param slotID The ID of the slot whose sessions should be closed.
 * 
 * _Example_
 * \code
 * CK_RV rv;
 * 
 * // Close all sessions on slot 0
 * rv = C_CloseAllSessions(0);
 * if (rv == CKR_OK) {
 *     printf("All sessions closed on slot 0\n");
 * }
 * \endcode
 * 
 * \sa C_OpenSession
 * \sa C_CloseSession
 */
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);

/*!
 * \ingroup pkcs11_03_session
 * \brief Get information about a session.
 * 
 * Returns information about a session including slot ID, session state,
 * flags, and device error code. See PKCS#11 v2.40 Section 11.6.4.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_ARGUMENTS_BAD if pInfo is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pInfo Pointer to CK_SESSION_INFO structure to receive session information.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_SESSION_INFO info;
 * CK_RV rv;
 * 
 * rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
 * if (rv == CKR_OK) {
 *     rv = C_GetSessionInfo(hSession, &info);
 *     if (rv == CKR_OK) {
 *         printf("Session state: %lu\n", info.state);
 *         printf("Session flags: 0x%08lX\n", info.flags);
 *     }
 *     C_CloseSession(hSession);
 * }
 * \endcode
 * 
 * \sa C_OpenSession
 */
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

/*!
 * \ingroup pkcs11_03_session
 * \brief Log in a user to a token.
 * 
 * Logs a user into a token. The user type can be CKU_SO (Security Officer)
 * or CKU_USER (normal user). Logging in affects the session state and
 * determines which objects are accessible. See PKCS#11 v2.40 Section 11.7.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_USER_TYPE_INVALID if userType is invalid.
 * \return CKR_USER_ALREADY_LOGGED_IN if user is already logged in.
 * \return CKR_USER_PIN_NOT_INITIALIZED if user PIN has not been initialized.
 * \return CKR_PIN_INCORRECT if PIN is incorrect.
 * \return CKR_PIN_LEN_RANGE if PIN length is out of range.
 * \return CKR_ARGUMENTS_BAD if pPin is NULL_PTR and ulPinLen is non-zero.
 * 
 * \param hSession The session handle.
 * \param userType The user type: CKU_SO or CKU_USER.
 * \param pPin Pointer to the user's PIN (may be NULL_PTR if ulPinLen is 0).
 * \param ulPinLen Length of the PIN in bytes.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_UTF8CHAR userPin[] = "1234";
 * CK_RV rv;
 * 
 * rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
 *                    NULL_PTR, NULL_PTR, &hSession);
 * if (rv == CKR_OK) {
 *     rv = C_Login(hSession, CKU_USER, userPin, sizeof(userPin) - 1);
 *     if (rv == CKR_OK) {
 *         printf("User logged in successfully\n");
 *         
 *         // ... perform authenticated operations ...
 *         
 *         C_Logout(hSession);
 *     }
 *     C_CloseSession(hSession);
 * }
 * \endcode
 * 
 * \sa C_Logout
 * \sa C_OpenSession
 */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

/*!
 * \ingroup pkcs11_03_session
 * \brief Log out the current user.
 * 
 * Logs out the user from the token. After logout, the session returns to
 * the public session state and private objects become inaccessible.
 * See PKCS#11 v2.40 Section 11.7.2.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_USER_NOT_LOGGED_IN if no user is logged in.
 * 
 * \param hSession The session handle.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_UTF8CHAR userPin[] = "1234";
 * CK_RV rv;
 * 
 * rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
 * if (rv == CKR_OK) {
 *     rv = C_Login(hSession, CKU_USER, userPin, sizeof(userPin) - 1);
 *     if (rv == CKR_OK) {
 *         // ... perform operations ...
 *         
 *         rv = C_Logout(hSession);
 *         if (rv == CKR_OK) {
 *             printf("User logged out\n");
 *         }
 *     }
 *     C_CloseSession(hSession);
 * }
 * \endcode
 * 
 * \sa C_Login
 */
CK_RV C_Logout(CK_SESSION_HANDLE hSession);

/*!
 * \ingroup pkcs11_03_session
 * \brief Get the current cryptographic operation state.
 * 
 * Saves the state of the cryptographic operation in a session. This allows
 * the operation to be continued later using C_SetOperationState. Not all
 * operations support state saving. See PKCS#11 v2.40 Section 11.6.5.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if no operation is active.
 * \return CKR_OPERATION_STATE_UNSAVEABLE if operation state cannot be saved.
 * \return CKR_BUFFER_TOO_SMALL if pOperationState buffer is too small.
 * \return CKR_ARGUMENTS_BAD if pulOperationStateLen is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pOperationState Buffer to receive operation state (may be NULL_PTR to query size).
 * \param pulOperationStateLen Pointer to size of operation state buffer.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_BYTE_PTR pState = NULL;
 * CK_ULONG stateLen = 0;
 * CK_RV rv;
 * 
 * // ... initialize session and start operation ...
 * 
 * // Get required buffer size
 * rv = C_GetOperationState(hSession, NULL_PTR, &stateLen);
 * if (rv == CKR_OK && stateLen > 0) {
 *     pState = malloc(stateLen);
 *     if (pState) {
 *         rv = C_GetOperationState(hSession, pState, &stateLen);
 *         if (rv == CKR_OK) {
 *             // State saved successfully
 *         }
 *         free(pState);
 *     }
 * }
 * \endcode
 * 
 * \sa C_SetOperationState
 */
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);

/*!
 * \ingroup pkcs11_03_session
 * \brief Restore a previously saved operation state.
 * 
 * Restores the cryptographic operation state in a session from data
 * previously saved with C_GetOperationState. The operation can then
 * be continued. See PKCS#11 v2.40 Section 11.6.6.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_ACTIVE if an operation is already active.
 * \return CKR_SAVED_STATE_INVALID if operation state is invalid.
 * \return CKR_KEY_HANDLE_INVALID if key handle is invalid.
 * \return CKR_ARGUMENTS_BAD if pOperationState is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param pOperationState Buffer containing saved operation state.
 * \param ulOperationStateLen Length of operation state data.
 * \param hEncryptionKey Handle to encryption key (if needed for state).
 * \param hAuthenticationKey Handle to authentication key (if needed for state).
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_BYTE_PTR pState;
 * CK_ULONG stateLen;
 * CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
 * CK_RV rv;
 * 
 * // ... save state with C_GetOperationState ...
 * 
 * // Restore state
 * rv = C_SetOperationState(hSession, pState, stateLen, hKey, hKey);
 * if (rv == CKR_OK) {
 *     // Operation state restored, can continue operation
 * }
 * \endcode
 * 
 * \sa C_GetOperationState
 */
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
