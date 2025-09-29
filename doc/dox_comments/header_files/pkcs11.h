/**
 * \file pkcs11.h
 * \brief Consolidated PKCS#11 API documentation for wolfPKCS11.
 *
 * This header-aligned documentation file aggregates the public PKCS#11 API
 * groups. Content is included from the existing group documentation to keep
 * navigation intact while aligning the file name with the installed header.
 */

/* Core: initialization and general info */
/**
 * \page pkcs11_core_overview Core: Initialization and General Info
 * Core lifecycle and general information functions. Initialize the library,
 * query info, and finalize when done. See PKCS#11 v2.40, Section 11.4
 * "General-Purpose Functions".
 * 
 * The typical application flow is: C_Initialize -> C_GetSlotList -> 
 * C_OpenSession -> [cryptographic operations] -> C_CloseSession -> C_Finalize.
 * - \ref pkcs11_01_core
 */

/*!
 * \ingroup pkcs11_01_core
 * \brief Initialize the PKCS#11 library.
 * 
 * Initializes the Cryptoki library. This function must be called before
 * any other PKCS#11 function except C_GetFunctionList. If pInitArgs is
 * NULL_PTR, the library uses default settings for threading and memory
 * allocation. See PKCS#11 v2.40 Section 11.4.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_ALREADY_INITIALIZED if already initialized.
 * \return CKR_ARGUMENTS_BAD if pInitArgs contains invalid values.
 * \return CKR_HOST_MEMORY if memory allocation fails.
 * \return CKR_GENERAL_ERROR for other initialization failures.
 * 
 * \param pInitArgs Optional pointer to CK_C_INITIALIZE_ARGS structure
 *                  containing threading and memory allocation settings.
 *                  Pass NULL_PTR for default behavior.
 * 
 * _Example_
 * \code
 * CK_RV rv;
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv != CKR_OK) {
 *     printf("C_GetFunctionList failed: 0x%08lX\n", rv);
 *     return rv;
 * }
 * 
 * // Initialize with default settings
 * rv = p11->C_Initialize(NULL_PTR);
 * if (rv != CKR_OK) {
 *     printf("C_Initialize failed: 0x%08lX\n", rv);
 *     return rv;
 * }
 * 
 * // ... perform PKCS#11 operations ...
 * 
 * p11->C_Finalize(NULL_PTR);
 * \endcode
 * 
 * \sa C_Finalize
 * \sa C_GetFunctionList
 */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);

/*!
 * \ingroup pkcs11_01_core
 * \brief Finalize the PKCS#11 library and release resources.
 * 
 * Cleans up the Cryptoki library and releases all resources. All sessions
 * are automatically closed. After calling this function, only C_Initialize
 * and C_GetFunctionList may be called. See PKCS#11 v2.40 Section 11.4.2.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_ARGUMENTS_BAD if pReserved is not NULL_PTR.
 * 
 * \param pReserved Reserved for future use; must be NULL_PTR.
 * 
 * _Example_
 * \code
 * CK_RV rv;
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv == CKR_OK) {
 *     rv = p11->C_Initialize(NULL_PTR);
 *     if (rv == CKR_OK) {
 *         // ... perform operations ...
 *         rv = p11->C_Finalize(NULL_PTR);
 *         if (rv != CKR_OK) {
 *             printf("C_Finalize failed: 0x%08lX\n", rv);
 *         }
 *     }
 * }
 * \endcode
 * 
 * \sa C_Initialize
 */
CK_RV C_Finalize(CK_VOID_PTR pReserved);

/*!
 * \ingroup pkcs11_01_core
 * \brief Get general information about the PKCS#11 library.
 * 
 * Returns general information about the Cryptoki library, including
 * version numbers, manufacturer, and library description. See PKCS#11
 * v2.40 Section 11.4.3.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_ARGUMENTS_BAD if pInfo is NULL_PTR.
 * 
 * \param pInfo Pointer to CK_INFO structure to receive library information.
 * 
 * _Example_
 * \code
 * CK_INFO info;
 * CK_RV rv;
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv == CKR_OK) {
 *     rv = p11->C_Initialize(NULL_PTR);
 *     if (rv == CKR_OK) {
 *         rv = p11->C_GetInfo(&info);
 *         if (rv == CKR_OK) {
 *             printf("Library: %.32s\n", info.libraryDescription);
 *             printf("Version: %d.%d\n", info.libraryVersion.major,
 *                                        info.libraryVersion.minor);
 *         }
 *         p11->C_Finalize(NULL_PTR);
 *     }
 * }
 * \endcode
 * 
 * \sa C_Initialize
 */
CK_RV C_GetInfo(CK_INFO_PTR pInfo);

/*!
 * \ingroup pkcs11_01_core
 * \brief Get the PKCS#11 function list.
 * 
 * Returns a pointer to the library's CK_FUNCTION_LIST structure containing
 * function pointers for all PKCS#11 functions. This is the only function
 * that can be called before C_Initialize. See PKCS#11 v2.40 Section 11.4.4.
 * 
 * \return CKR_OK on success.
 * \return CKR_ARGUMENTS_BAD if ppFunctionList is NULL_PTR.
 * 
 * \param ppFunctionList Pointer to receive the function list pointer.
 * 
 * _Example_
 * \code
 * CK_FUNCTION_LIST_PTR pFunctionList;
 * CK_RV rv;
 * 
 * rv = C_GetFunctionList(&pFunctionList);
 * if (rv == CKR_OK) {
 *     // Use function pointers from pFunctionList
 *     rv = pFunctionList->C_Initialize(NULL_PTR);
 *     // ... other operations ...
 *     pFunctionList->C_Finalize(NULL_PTR);
 * }
 * \endcode
 * 
 * \sa C_Initialize
 */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/*!
 * \ingroup pkcs11_01_core
 * \brief Legacy function for operation status (deprecated).
 * 
 * This function is deprecated in PKCS#11 v2.x and later. It was intended
 * to return the status of a parallel cryptographic operation but is not
 * implemented in most modern PKCS#11 libraries.
 * 
 * \return CKR_FUNCTION_NOT_PARALLEL typically.
 * 
 * \param hSession Session handle (unused in most implementations).
 * 
 * \sa C_CancelFunction
 */
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);

/*!
 * \ingroup pkcs11_01_core
 * \brief Legacy function for operation cancellation (deprecated).
 * 
 * This function is deprecated in PKCS#11 v2.x and later. It was intended
 * to cancel a parallel cryptographic operation but is not implemented
 * in most modern PKCS#11 libraries.
 * 
 * \return CKR_FUNCTION_NOT_PARALLEL typically.
 * 
 * \param hSession Session handle (unused in most implementations).
 * 
 * \sa C_GetFunctionStatus
 */
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);

/* Slots and tokens */
/**
 * \page pkcs11_slots_tokens_overview Slots and Tokens
 * Enumerate slots and tokens, retrieve slot/token information, list supported
 * mechanisms, and initialize token/PIN. See PKCS#11 v2.40 Section 11.3 and 11.4.
 * - \ref pkcs11_02_slot_token
 */

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Get the list of slots.
 * 
 * Retrieves a list of slot IDs. Use the two-call pattern: first call with
 * pSlotList=NULL_PTR to get required count, then allocate and call again.
 * See Section 11.3.1.
 * 
 * \return CKR_OK on success; CKR_BUFFER_TOO_SMALL if list too small.
 * \param tokenPresent If CK_TRUE, only return slots with a token present.
 * \param pSlotList Output array of slot IDs (may be NULL_PTR).
 * \param pulCount Input/output: number of slots.
 * 
 * _Example_
 * \code
 * CK_FUNCTION_LIST_PTR p11;
 * CK_RV rv = C_GetFunctionList(&p11);
 * if (rv != CKR_OK) {
 *     // handle error
 * }
 * CK_ULONG count = 0;
 * rv = p11->C_GetSlotList(CK_TRUE, NULL_PTR, &count);
 * CK_SLOT_ID* slots = malloc(count * sizeof(CK_SLOT_ID));
 * rv = p11->C_GetSlotList(CK_TRUE, slots, &count);
 * free(slots);
 * \endcode
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Get information about a slot.
 * 
 * Retrieves general information about a slot. See Section 11.3.2.
 * 
 * \return CKR_OK on success; CKR_SLOT_ID_INVALID if slotID invalid.
 * \param slotID The slot ID.
 * \param pInfo Output slot info.
 */
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Get information about a token.
 * 
 * Retrieves information about the token in the given slot. See Section 11.3.3.
 * 
 * \return CKR_OK on success; CKR_TOKEN_NOT_PRESENT if no token in slot.
 * \param slotID The slot ID.
 * \param pInfo Output token info.
 */
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Get the list of mechanisms supported by a token.
 * 
 * Retrieves the supported mechanisms for a token. Two-call pattern for sizing.
 * See Section 11.3.4.
 * 
 * \return CKR_OK on success; CKR_BUFFER_TOO_SMALL if list too small.
 * \param slotID The slot ID.
 * \param pMechanismList Output array of mechanism types (may be NULL_PTR).
 * \param pulCount Input/output: number of mechanisms.
 */
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Get information about a mechanism.
 * 
 * Retrieves information (min/max key sizes, flags) for a mechanism.
 * See Section 11.3.5.
 * 
 * \return CKR_OK on success; CKR_MECHANISM_INVALID otherwise.
 * \param slotID The slot ID.
 * \param type Mechanism type.
 * \param pInfo Output mechanism info.
 */
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Initialize a token.
 * 
 * Initializes a token, setting the Security Officer (SO) PIN and label.
 * See Section 11.3.6.
 * 
 * \return CKR_OK on success; CKR_PIN_LEN_RANGE on invalid PIN length.
 * \param slotID The slot ID.
 * \param pPin SO PIN buffer.
 * \param ulPinLen SO PIN length.
 * \param pLabel 32-byte label buffer.
 */
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Initialize the normal user's PIN.
 * 
 * Initializes the user PIN (SO must be logged in). See Section 11.3.7.
 * 
 * \return CKR_OK on success; CKR_PIN_LEN_RANGE on invalid PIN length.
 * \param hSession RW session handle.
 * \param pPin User PIN buffer.
 * \param ulPinLen User PIN length.
 */
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Change the current user's PIN.
 * 
 * Changes the PIN for the currently logged-in role. See Section 11.3.8.
 * 
 * \return CKR_OK on success; CKR_PIN_INCORRECT if old PIN wrong.
 * \param hSession Session handle.
 * \param pOldPin Old PIN buffer.
 * \param ulOldLen Old PIN length.
 * \param pNewPin New PIN buffer.
 * \param ulNewLen New PIN length.
 */
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

/*!
 * \ingroup pkcs11_02_slot_token
 * \brief Wait for a slot event.
 * 
 * Blocks until a slot event occurs or returns immediately if the flag
 * CKF_DONT_BLOCK is set in flags. See Section 11.3.9.
 * 
 * \return CKR_OK on success; CKR_NO_EVENT if non-blocking and no event.
 * \param flags Either 0 or CKF_DONT_BLOCK.
 * \param pSlot Output slot ID where event occurred.
 * \param pReserved Reserved; must be NULL_PTR.
 */
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

/* Sessions and login */
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
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv != CKR_OK) {
 *     // handle error
 * }
 * 
 * // Open read-write session
 * rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
 *                         NULL_PTR, NULL_PTR, &hSession);
 * if (rv == CKR_OK) {
 *     printf("Session opened: %lu\n", hSession);
 *     
 *     // ... perform operations ...
 *     
 *     rv = p11->C_CloseSession(hSession);
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
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv == CKR_OK) {
 *     rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
 *     if (rv == CKR_OK) {
 *         // ... perform operations ...
 *         rv = p11->C_CloseSession(hSession);
 *         if (rv != CKR_OK) {
 *             printf("Failed to close session: 0x%08lX\n", rv);
 *         }
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
 * rv = p11->C_CloseAllSessions(0);
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
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv == CKR_OK) {
 *     rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
 *     if (rv == CKR_OK) {
 *         rv = p11->C_GetSessionInfo(hSession, &info);
 *         if (rv == CKR_OK) {
 *         printf("Session state: %lu\n", info.state);
 *         printf("Session flags: 0x%08lX\n", info.flags);
 *     }
 *     p11->C_CloseSession(hSession);
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
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv == CKR_OK) {
 *     rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
 *                             NULL_PTR, NULL_PTR, &hSession);
 *     if (rv == CKR_OK) {
 *         rv = p11->C_Login(hSession, CKU_USER, userPin, sizeof(userPin) - 1);
 *         if (rv == CKR_OK) {
 *         printf("User logged in successfully\n");
 *         
 *         // ... perform authenticated operations ...
 *         
 *         p11->C_Logout(hSession);
 *     }
 *     p11->C_CloseSession(hSession);
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
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv == CKR_OK) {
 *     rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
 *     if (rv == CKR_OK) {
 *         rv = p11->C_Login(hSession, CKU_USER, userPin, sizeof(userPin) - 1);
 *         if (rv == CKR_OK) {
 *         // ... perform operations ...
 *         
 *         rv = p11->C_Logout(hSession);
 *         if (rv == CKR_OK) {
 *             printf("User logged out\n");
 *         }
 *     }
 *     p11->C_CloseSession(hSession);
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
 * rv = p11->C_GetOperationState(hSession, NULL_PTR, &stateLen);
 * if (rv == CKR_OK && stateLen > 0) {
 *     pState = malloc(stateLen);
 *     if (pState) {
 *         rv = p11->C_GetOperationState(hSession, pState, &stateLen);
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
 * rv = p11->C_SetOperationState(hSession, pState, stateLen, hKey, hKey);
 * if (rv == CKR_OK) {
 *     // Operation state restored, can continue operation
 * }
 * \endcode
 * 
 * \sa C_GetOperationState
 */
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);

/* Objects and attributes */
/**
 * \page pkcs11_objects_overview Objects and Attributes
 * Create, copy, destroy, and search for objects, and get/set attributes.
 * See PKCS#11 v2.40 Section 11.7 "Objects".
 * 
 * Objects represent keys, certificates, and data stored on the token or in
 * session memory. Each object has a set of attributes that define its properties
 * and usage. Objects can be searched using attribute templates, and their
 * attributes can be queried and modified (if permitted).
 * - \ref pkcs11_04_object
 */

/*!
 * \ingroup pkcs11_04_object
 * \brief Create a new object.
 * 
 * Creates a new object with the specified attributes. The object can be
 * created as a token object (persistent) or session object (temporary).
 * See PKCS#11 v2.40 Section 11.7.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_TEMPLATE_INCOMPLETE if required attributes are missing.
 * \return CKR_TEMPLATE_INCONSISTENT if attributes conflict.
 * \return CKR_ATTRIBUTE_TYPE_INVALID if attribute type is invalid.
 * \return CKR_ATTRIBUTE_VALUE_INVALID if attribute value is invalid.
 * \return CKR_USER_NOT_LOGGED_IN if creating private object without login.
 * \return CKR_SESSION_READ_ONLY if creating token object in read-only session.
 * \return CKR_ARGUMENTS_BAD if pTemplate or phObject is NULL_PTR.
 * \return CKR_HOST_MEMORY if memory allocation fails.
 * 
 * \param hSession The session handle.
 * \param pTemplate Array of CK_ATTRIBUTE structures defining the object.
 * \param ulCount Number of attributes in the template.
 * \param phObject Pointer to receive the new object handle.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hKey;
 * CK_BYTE keyValue[32] = {0}; // AES-256 key
 * CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
 * CK_KEY_TYPE keyType = CKK_AES;
 * CK_BBOOL ckTrue = CK_TRUE;
 * CK_RV rv;
 * 
 * CK_ATTRIBUTE template[] = {
 *     {CKA_CLASS, &keyClass, sizeof(keyClass)},
 *     {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
 *     {CKA_VALUE, keyValue, sizeof(keyValue)},
 *     {CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)},
 *     {CKA_DECRYPT, &ckTrue, sizeof(ckTrue)}
 * };
 * 
 * rv = p11->C_CreateObject(hSession, template, 5, &hKey);
 * if (rv == CKR_OK) {
 *     printf("AES key created: %lu\n", hKey);
 * }
 * \endcode
 * 
 * \sa C_DestroyObject
 * \sa C_GetAttributeValue
 * \sa C_SetAttributeValue
 */
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);

/*!
 * \ingroup pkcs11_04_object
 * \brief Copy an existing object.
 * 
 * Creates a copy of an existing object, optionally modifying some attributes.
 * The new object inherits all attributes from the original except those
 * specified in the template. See PKCS#11 v2.40 Section 11.7.2.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OBJECT_HANDLE_INVALID if hObject is invalid.
 * \return CKR_TEMPLATE_INCONSISTENT if attributes conflict.
 * \return CKR_ATTRIBUTE_TYPE_INVALID if attribute type is invalid.
 * \return CKR_ATTRIBUTE_VALUE_INVALID if attribute value is invalid.
 * \return CKR_ATTRIBUTE_READ_ONLY if trying to modify read-only attribute.
 * \return CKR_ACTION_PROHIBITED if object cannot be copied.
 * \return CKR_ARGUMENTS_BAD if phNewObject is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param hObject Handle of the object to copy.
 * \param pTemplate Array of attributes to modify in the copy (may be NULL_PTR).
 * \param ulCount Number of attributes in the template.
 * \param phNewObject Pointer to receive the new object handle.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hOriginal, hCopy;
 * CK_BBOOL ckFalse = CK_FALSE;
 * CK_RV rv;
 * 
 * // Modify the copy to be non-extractable
 * CK_ATTRIBUTE template[] = {
 *     {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)}
 * };
 * 
 * rv = p11->C_CopyObject(hSession, hOriginal, template, 1, &hCopy);
 * if (rv == CKR_OK) {
 *     printf("Object copied: %lu -> %lu\n", hOriginal, hCopy);
 * }
 * \endcode
 * 
 * \sa C_CreateObject
 * \sa C_DestroyObject
 */
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);

/*!
 * \ingroup pkcs11_04_object
 * \brief Destroy an object.
 * 
 * Destroys an object. Session objects are automatically destroyed when
 * the session is closed, but token objects persist until explicitly
 * destroyed. See PKCS#11 v2.40 Section 11.7.3.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OBJECT_HANDLE_INVALID if hObject is invalid.
 * \return CKR_ACTION_PROHIBITED if object cannot be destroyed.
 * \return CKR_SESSION_READ_ONLY if destroying token object in read-only session.
 * 
 * \param hSession The session handle.
 * \param hObject Handle of the object to destroy.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hObject;
 * CK_RV rv;
 * 
 * // ... create or find object ...
 * 
 * rv = p11->C_DestroyObject(hSession, hObject);
 * if (rv == CKR_OK) {
 *     printf("Object %lu destroyed\n", hObject);
 * } else {
 *     printf("Failed to destroy object: 0x%08lX\n", rv);
 * }
 * \endcode
 * 
 * \sa C_CreateObject
 * \sa C_FindObjects
 */
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

/*!
 * \ingroup pkcs11_04_object
 * \brief Get the size of an object in bytes.
 * 
 * Returns the amount of storage space occupied by an object on the token.
 * This is implementation-dependent and may include metadata overhead.
 * See PKCS#11 v2.40 Section 11.7.4.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OBJECT_HANDLE_INVALID if hObject is invalid.
 * \return CKR_INFORMATION_SENSITIVE if size information is sensitive.
 * \return CKR_ARGUMENTS_BAD if pulSize is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param hObject Handle of the object.
 * \param pulSize Pointer to receive the object size in bytes.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hObject;
 * CK_ULONG objectSize;
 * CK_RV rv;
 * 
 * rv = p11->C_GetObjectSize(hSession, hObject, &objectSize);
 * if (rv == CKR_OK) {
 *     printf("Object %lu size: %lu bytes\n", hObject, objectSize);
 * }
 * \endcode
 * 
 * \sa C_CreateObject
 */
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);

/*!
 * \ingroup pkcs11_04_object
 * \brief Get attribute values from an object.
 * 
 * Retrieves the values of one or more attributes from an object. Use the
 * two-call pattern: first call with pValue=NULL_PTR to get the required
 * buffer size, then call again with allocated buffer. See PKCS#11 v2.40
 * Section 11.7.5.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OBJECT_HANDLE_INVALID if hObject is invalid.
 * \return CKR_ATTRIBUTE_TYPE_INVALID if attribute type is invalid.
 * \return CKR_ATTRIBUTE_SENSITIVE if attribute is sensitive.
 * \return CKR_BUFFER_TOO_SMALL if buffer is too small.
 * \return CKR_ARGUMENTS_BAD if pTemplate is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param hObject Handle of the object.
 * \param pTemplate Array of CK_ATTRIBUTE structures specifying attributes to retrieve.
 * \param ulCount Number of attributes in the template.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hKey;
 * CK_ULONG keyLen;
 * CK_OBJECT_CLASS keyClass;
 * CK_RV rv;
 * 
 * CK_ATTRIBUTE template[] = {
 *     {CKA_CLASS, &keyClass, sizeof(keyClass)},
 *     {CKA_VALUE_LEN, &keyLen, sizeof(keyLen)}
 * };
 * 
 * rv = p11->C_GetAttributeValue(hSession, hKey, template, 2);
 * if (rv == CKR_OK) {
 *     printf("Key class: %lu, length: %lu bits\n", keyClass, keyLen * 8);
 * }
 * \endcode
 * 
 * \sa C_SetAttributeValue
 * \sa C_CreateObject
 */
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/*!
 * \ingroup pkcs11_04_object
 * \brief Set attribute values on an object.
 * 
 * Modifies the values of one or more attributes of an object. Only certain
 * attributes can be modified after object creation, and some require special
 * permissions. See PKCS#11 v2.40 Section 11.7.6.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OBJECT_HANDLE_INVALID if hObject is invalid.
 * \return CKR_ATTRIBUTE_TYPE_INVALID if attribute type is invalid.
 * \return CKR_ATTRIBUTE_VALUE_INVALID if attribute value is invalid.
 * \return CKR_ATTRIBUTE_READ_ONLY if attribute cannot be modified.
 * \return CKR_SESSION_READ_ONLY if modifying token object in read-only session.
 * \return CKR_ARGUMENTS_BAD if pTemplate is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param hObject Handle of the object to modify.
 * \param pTemplate Array of CK_ATTRIBUTE structures with new values.
 * \param ulCount Number of attributes in the template.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE hKey;
 * CK_UTF8CHAR label[] = "My Updated Key";
 * CK_RV rv;
 * 
 * CK_ATTRIBUTE template[] = {
 *     {CKA_LABEL, label, sizeof(label) - 1}
 * };
 * 
 * rv = p11->C_SetAttributeValue(hSession, hKey, template, 1);
 * if (rv == CKR_OK) {
 *     printf("Key label updated\n");
 * }
 * \endcode
 * 
 * \sa C_GetAttributeValue
 * \sa C_CreateObject
 */
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/*!
 * \ingroup pkcs11_04_object
 * \brief Initialize an object search operation.
 * 
 * Initializes a search for objects matching the specified attribute template.
 * The search must be completed with C_FindObjects and terminated with
 * C_FindObjectsFinal. See PKCS#11 v2.40 Section 11.7.7.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_ACTIVE if a find operation is already active.
 * \return CKR_ATTRIBUTE_TYPE_INVALID if attribute type is invalid.
 * \return CKR_ATTRIBUTE_VALUE_INVALID if attribute value is invalid.
 * \return CKR_ARGUMENTS_BAD if pTemplate is NULL_PTR and ulCount > 0.
 * 
 * \param hSession The session handle.
 * \param pTemplate Array of CK_ATTRIBUTE structures defining search criteria (may be NULL_PTR).
 * \param ulCount Number of attributes in the template.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
 * CK_KEY_TYPE keyType = CKK_AES;
 * CK_RV rv;
 * 
 * CK_ATTRIBUTE template[] = {
 *     {CKA_CLASS, &keyClass, sizeof(keyClass)},
 *     {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
 * };
 * 
 * rv = p11->C_FindObjectsInit(hSession, template, 2);
 * if (rv == CKR_OK) {
 *     // Search initialized, now call C_FindObjects
 * }
 * \endcode
 * 
 * \sa C_FindObjects
 * \sa C_FindObjectsFinal
 */
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/*!
 * \ingroup pkcs11_04_object
 * \brief Continue an object search operation.
 * 
 * Continues a search operation initialized with C_FindObjectsInit, returning
 * handles of objects that match the search criteria. May be called multiple
 * times to retrieve all matching objects. See PKCS#11 v2.40 Section 11.7.8.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_FindObjectsInit was not called.
 * \return CKR_ARGUMENTS_BAD if phObject or pulObjectCount is NULL_PTR.
 * 
 * \param hSession The session handle.
 * \param phObject Array to receive object handles.
 * \param ulMaxObjectCount Maximum number of handles to return.
 * \param pulObjectCount Pointer to receive actual number of handles returned.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_OBJECT_HANDLE objects[10];
 * CK_ULONG objectCount;
 * CK_RV rv;
 * 
 * // ... initialize search with C_FindObjectsInit ...
 * 
 * rv = p11->C_FindObjects(hSession, objects, 10, &objectCount);
 * if (rv == CKR_OK) {
 *     printf("Found %lu objects\n", objectCount);
 *     for (CK_ULONG i = 0; i < objectCount; i++) {
 *         printf("Object handle: %lu\n", objects[i]);
 *     }
 * }
 * 
 * p11->C_FindObjectsFinal(hSession);
 * \endcode
 * 
 * \sa C_FindObjectsInit
 * \sa C_FindObjectsFinal
 */
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);

/*!
 * \ingroup pkcs11_04_object
 * \brief Terminate an object search operation.
 * 
 * Terminates a search operation and releases any resources associated with
 * the search. Must be called after C_FindObjectsInit, even if no objects
 * were found. See PKCS#11 v2.40 Section 11.7.9.
 * 
 * \return CKR_OK on success.
 * \return CKR_CRYPTOKI_NOT_INITIALIZED if C_Initialize was not called.
 * \return CKR_SESSION_HANDLE_INVALID if hSession is invalid.
 * \return CKR_OPERATION_NOT_INITIALIZED if C_FindObjectsInit was not called.
 * 
 * \param hSession The session handle.
 * 
 * _Example_
 * \code
 * CK_SESSION_HANDLE hSession;
 * CK_RV rv;
 * 
 * // ... initialize and perform search ...
 * 
 * rv = p11->C_FindObjectsFinal(hSession);
 * if (rv == CKR_OK) {
 *     printf("Search operation completed\n");
 * }
 * \endcode
 * 
 * \sa C_FindObjectsInit
 * \sa C_FindObjects
 */
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

/* Keys */
/**
 * \page pkcs11_key_overview Key Management
 * Key pair generation, derivation, wrap/unwrap. See PKCS#11 v2.40
 * Section 11.12 "Key Management Functions".
 * - \ref pkcs11_05_key
 */

/*!
 * \ingroup pkcs11_05_key
 * \brief Generate a secret key.
 * 
 * Generates a secret key using the specified mechanism and attributes.
 * See PKCS#11 v2.40 Section 11.12.1.
 * 
 * \return CKR_OK on success.
 * \return CKR_MECHANISM_INVALID or CKR_MECHANISM_PARAM_INVALID if mechanism not supported.
 * \return CKR_TEMPLATE_INCONSISTENT/INCOMPLETE for invalid attributes.
 * \return CKR_SESSION_READ_ONLY for token object in RO session.
 * 
 * \param hSession The session handle.
 * \param pMechanism Mechanism specifying key generation.
 * \param pTemplate Attributes for the new key (e.g., CKA_CLASS, CKA_KEY_TYPE).
 * \param ulCount Number of attributes.
 * \param phKey Output: handle of generated key.
 * 
 * _Example_
 * \code
 * CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
 * CK_KEY_TYPE kt = CKK_AES; CK_BBOOL t = CK_TRUE;
 * CK_ATTRIBUTE tmpl[] = {
 *   {CKA_CLASS, &cls, sizeof(cls)},
 *   {CKA_KEY_TYPE, &kt, sizeof(kt)},
 *   {CKA_TOKEN, &t, sizeof(t)},
 *   {CKA_ENCRYPT, &t, sizeof(t)}, {CKA_DECRYPT, &t, sizeof(t)}
 * };
 * CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL_PTR, 0};
 * CK_OBJECT_HANDLE hKey;
 * CK_RV rv = p11->C_GenerateKey(hSession, &mech, tmpl, sizeof(tmpl)/sizeof(tmpl[0]), &hKey);
 * \endcode
 */
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);

/*!
 * \ingroup pkcs11_05_key
 * \brief Generate a public/private key pair.
 * 
 * Generates a key pair with separate attribute templates for public and
 * private keys. See Section 11.12.2.
 * 
 * \return CKR_OK on success; template/mechanism errors otherwise.
 * \param hSession The session handle.
 * \param pMechanism Mechanism specifying key pair generation (e.g., CKM_EC_KEY_PAIR_GEN).
 * \param pPublicKeyTemplate Public key attributes.
 * \param ulPublicKeyAttributeCount Number of public attributes.
 * \param pPrivateKeyTemplate Private key attributes.
 * \param ulPrivateKeyAttributeCount Number of private attributes.
 * \param phPublicKey Output public key handle.
 * \param phPrivateKey Output private key handle.
 * 
 * _Example_
 * \code
 * CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
 * CK_BBOOL t = CK_TRUE;
 * CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};
 * CK_UTF8CHAR curve[] = "P-256";
 * CK_ATTRIBUTE pubTmpl[] = {
 *   {CKA_CLASS, &pubClass, sizeof(pubClass)},
 *   {CKA_EC_PARAMS, curve, sizeof(curve)-1},
 *   {CKA_VERIFY, &t, sizeof(t)}
 * };
 * CK_ATTRIBUTE privTmpl[] = {
 *   {CKA_CLASS, &privClass, sizeof(privClass)},
 *   {CKA_TOKEN, &t, sizeof(t)},
 *   {CKA_PRIVATE, &t, sizeof(t)},
 *   {CKA_SIGN, &t, sizeof(t)}
 * };
 * CK_OBJECT_HANDLE hPub, hPriv;
 * CK_RV rv = p11->C_GenerateKeyPair(hSession, &mech,
 *     pubTmpl, sizeof(pubTmpl)/sizeof(pubTmpl[0]),
 *     privTmpl, sizeof(privTmpl)/sizeof(privTmpl[0]),
 *     &hPub, &hPriv);
 * \endcode
 */
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);

/*!
 * \ingroup pkcs11_05_key
 * \brief Wrap (export) a key with another key.
 * 
 * Wraps a key using a wrapping key and mechanism, returning wrapped bytes.
 * Use two-call pattern to size the output. See Section 11.12.3.
 * 
 * \return CKR_OK on success; CKR_BUFFER_TOO_SMALL if output too small.
 * \return CKR_KEY_HANDLE_INVALID; CKR_WRAP_MODE_INVALID; CKR_WRAPPING_KEY_SIZE_RANGE.
 * 
 * \param hSession The session handle.
 * \param pMechanism Wrapping mechanism (e.g., CKM_AES_KEY_WRAP).
 * \param hWrappingKey Wrapping key handle.
 * \param hKey Key handle to wrap (must be CKA_EXTRACTABLE).
 * \param pWrappedKey Output buffer for wrapped bytes (may be NULL_PTR).
 * \param pulWrappedKeyLen Pointer to wrapped length.
 */
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);

/*!
 * \ingroup pkcs11_05_key
 * \brief Unwrap (import) a key using another key.
 * 
 * Creates a key object from wrapped bytes using the unwrapping key and
 * attributes. See Section 11.12.4.
 * 
 * \return CKR_OK on success; CKR_WRAPPED_KEY_INVALID on parse/verify failure.
 * \param hSession The session handle.
 * \param pMechanism Unwrap mechanism.
 * \param hUnwrappingKey Unwrapping key handle.
 * \param pWrappedKey Wrapped bytes.
 * \param ulWrappedKeyLen Length of wrapped bytes.
 * \param pTemplate Attributes for the unwrapped key.
 * \param ulAttributeCount Number of attributes.
 * \param phKey Output unwrapped key handle.
 */
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);

/*!
 * \ingroup pkcs11_05_key
 * \brief Derive a key from a base key.
 * 
 * Derives a key using the specified derivation mechanism and attributes.
 * See Section 11.12.5.
 * 
 * \return CKR_OK on success; CKR_MECHANISM_PARAM_INVALID otherwise.
 * \param hSession The session handle.
 * \param pMechanism Derivation mechanism (e.g., CKM_ECDH1_DERIVE).
 * \param hBaseKey Base key handle.
 * \param pTemplate Attributes for the derived key.
 * \param ulAttributeCount Number of attributes.
 * \param phKey Output derived key handle.
 * 
 * _Example_
 * \code
 * CK_ECDH1_DERIVE_PARAMS params = {CKD_NULL, NULL, 0, otherPub, otherPubLen};
 * CK_MECHANISM mech = {CKM_ECDH1_DERIVE, &params, sizeof(params)};
 * CK_OBJECT_HANDLE hDerived;
 * CK_ATTRIBUTE_PTR tmpl = NULL;
 * CK_ULONG tmplCount = 0;
 * CK_RV rv = C_DeriveKey(hSession, &mech, hPrivKey, tmpl, tmplCount, &hDerived);
 * \endcode
 */
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);

/* Random */
/**
 * \page pkcs11_random_overview Random Number Generation
 * Seed and generate random data using the token's RNG. See PKCS#11 v2.40
 * Section 11.13 "Random Number Generation Functions".
 * - \ref pkcs11_06_random
 */

/*!
 * \ingroup pkcs11_06_random
 * \brief Mix additional seed material into the RNG.
 * 
 * Mixes externally supplied seed into the token's RNG state if supported.
 * 
 * \return CKR_OK on success; CKR_RANDOM_SEED_NOT_SUPPORTED otherwise.
 * \param hSession The session handle.
 * \param pSeed Seed buffer.
 * \param ulSeedLen Length of seed buffer.
 */
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);

/*!
 * \ingroup pkcs11_06_random
 * \brief Generate random data.
 * 
 * Fills the output buffer with random bytes from the token's RNG.
 * 
 * \return CKR_OK on success; CKR_RANDOM_NO_RNG if RNG not available.
 * \param hSession The session handle.
 * \param RandomData Output buffer for random bytes.
 * \param ulRandomLen Number of bytes to generate.
 * 
 * _Example_
 * \code
 * CK_BYTE buf[32];
 * CK_RV rv = C_GenerateRandom(hSession, buf, sizeof(buf));
 * \endcode
 */
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);

/* Digest */
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
 * CK_FUNCTION_LIST_PTR p11;
 * CK_RV rv = C_GetFunctionList(&p11);
 * if (rv != CKR_OK) {
 *     // handle error
 * }
 * p11->C_DigestInit(hSession, &mech);
 * p11->C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &dgstLen);
 * CK_BYTE* dgst = malloc(dgstLen);
 * p11->C_Digest(hSession, data, sizeof(data)-1, dgst, &dgstLen);
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

/* Encrypt/Decrypt */
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
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv == CKR_OK) {
 *     rv = p11->C_EncryptInit(hSession, &mechanism, hKey);
 *     if (rv == CKR_OK) {
 *         // Encryption initialized, ready to encrypt data
 *     }
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
 * CK_FUNCTION_LIST_PTR p11;
 * 
 * rv = C_GetFunctionList(&p11);
 * if (rv == CKR_OK) {
 *     rv = p11->C_EncryptInit(hSession, &mechanism, hKey);
 *     if (rv == CKR_OK) {
 *         // Get required buffer size
 *         rv = p11->C_Encrypt(hSession, plaintext, sizeof(plaintext) - 1, 
 *                             NULL_PTR, &ciphertextLen);
 *         if (rv == CKR_OK) {
 *             ciphertext = malloc(ciphertextLen);
 *             if (ciphertext) {
 *                 rv = p11->C_Encrypt(hSession, plaintext, sizeof(plaintext) - 1,
 *                                      ciphertext, &ciphertextLen);
 *                 if (rv == CKR_OK) {
 *                     printf("Encryption successful, %lu bytes\n", ciphertextLen);
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
 * rv = p11->C_EncryptUpdate(hSession, data, sizeof(data), 
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
 * rv = p11->C_EncryptFinal(hSession, finalData, &finalLen);
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
 * rv = p11->C_DecryptInit(hSession, &mechanism, hKey);
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
 * rv = p11->C_DecryptInit(hSession, &mechanism, hKey);
 * if (rv == CKR_OK) {
 *     // Get required buffer size
 *     rv = p11->C_Decrypt(hSession, ciphertext, sizeof(ciphertext),
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
 * rv = p11->C_DecryptUpdate(hSession, encryptedData, sizeof(encryptedData),
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
 * rv = p11->C_DecryptFinal(hSession, finalData, &finalLen);
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

/* Sign/Verify */
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
 * CK_RV rv = p11->C_SignInit(hSession, &mech, hPrivKey);
 * if (rv == CKR_OK) {
 *     rv = p11->C_Sign(hSession, msg, sizeof(msg)-1, NULL_PTR, &sigLen);
 *     if (rv == CKR_OK) {
 *         sig = malloc(sigLen);
 *         if (sig) {
 *             rv = p11->C_Sign(hSession, msg, sizeof(msg)-1, sig, &sigLen);
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
 * CK_RV rv = p11->C_VerifyInit(hSession, &mech, hPubKey);
 * if (rv == CKR_OK) {
 *     rv = p11->C_Verify(hSession, msg, sizeof(msg)-1, sig, sigLen);
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

/**
 * \page pkcs11_extensions_overview wolfPKCS11 Extensions
 * wolfPKCS11-specific extensions and enhancements to the standard PKCS#11 API.
 * 
 * wolfPKCS11 provides several extensions beyond the standard PKCS#11 specification
 * to enable better integration with wolfSSL, enhanced debugging capabilities, and
 * additional configuration options.
 * - \ref pkcs11_10_extensions
 */

/*!
 * \ingroup pkcs11_10_extensions
 * \brief Enable debug logging for wolfPKCS11.
 * 
 * Enables detailed debug output from wolfPKCS11 operations. This function
 * activates internal logging that can help with troubleshooting and development.
 * Debug output is sent to stderr by default.
 * 
 * \note This function is only available when wolfPKCS11 is compiled with
 *       DEBUG_WOLFPKCS11 defined. When debug support is disabled, this
 *       function becomes a no-op macro.
 * 
 * \note Debug logging may expose sensitive information including key material
 *       and should only be enabled in development environments.
 * 
 * _Example_
 * \code
 * #ifdef DEBUG_WOLFPKCS11
 * // Enable debug logging before initializing PKCS#11
 * wolfPKCS11_Debugging_On();
 * #endif
 * 
 * CK_RV rv = C_Initialize(NULL_PTR);
 * if (rv != CKR_OK) {
 *     printf("C_Initialize failed: 0x%08lX\n", rv);
 * }
 * 
 * // ... perform operations with debug output ...
 * 
 * #ifdef DEBUG_WOLFPKCS11
 * wolfPKCS11_Debugging_Off();
 * #endif
 * \endcode
 * 
 * \sa wolfPKCS11_Debugging_Off
 */
void wolfPKCS11_Debugging_On(void);

/*!
 * \ingroup pkcs11_10_extensions
 * \brief Disable debug logging for wolfPKCS11.
 * 
 * Disables debug output from wolfPKCS11 operations. This function turns off
 * internal logging that was previously enabled with wolfPKCS11_Debugging_On().
 * 
 * \note This function is only available when wolfPKCS11 is compiled with
 *       DEBUG_WOLFPKCS11 defined. When debug support is disabled, this
 *       function becomes a no-op macro.
 * 
 * _Example_
 * \code
 * #ifdef DEBUG_WOLFPKCS11
 * wolfPKCS11_Debugging_On();
 * #endif
 * 
 * // ... perform operations with debug output ...
 * 
 * #ifdef DEBUG_WOLFPKCS11
 * // Disable debug logging when done
 * wolfPKCS11_Debugging_Off();
 * #endif
 * 
 * p11->C_Finalize(NULL_PTR);
 * \endcode
 * 
 * \sa wolfPKCS11_Debugging_On
 */
void wolfPKCS11_Debugging_Off(void);

/*!
 * \ingroup pkcs11_10_extensions
 * \brief wolfSSL device ID attribute for crypto callbacks.
 * 
 * This vendor-defined attribute (CKA_WOLFSSL_DEVID) allows setting a specific
 * wolfSSL crypto callback device ID to be used with cryptographic objects.
 * This enables integration with hardware acceleration and custom crypto
 * implementations through wolfSSL's crypto callback framework.
 * 
 * The attribute value should be a CK_ULONG containing the device ID.
 * 
 * _Example_
 * \code
 * CK_ATTRIBUTE template[] = {
 *     {CKA_CLASS,          &keyClass,    sizeof(keyClass)},
 *     {CKA_KEY_TYPE,       &keyType,     sizeof(keyType)},
 *     {CKA_WOLFSSL_DEVID,  &deviceId,    sizeof(deviceId)},
 *     // ... other attributes
 * };
 * 
 * CK_RV rv = C_CreateObject(hSession, template, 
 *                          sizeof(template)/sizeof(template[0]), 
 *                          &hKey);
 * \endcode
 * 
 * \sa CKA_WOLFSSL_DHUK_IV
 */
#define CKA_WOLFSSL_DEVID

/*!
 * \ingroup pkcs11_10_extensions
 * \brief STM32U5 DHUK initialization vector attribute.
 * 
 * This vendor-defined attribute (CKA_WOLFSSL_DHUK_IV) is specific to STM32U5
 * devices and allows setting the initialization vector for DHUK (Device
 * Hardware Unique Key) operations.
 * 
 * \note This attribute is only available when compiled with WOLFSSL_STM32U5_DHUK
 *       defined, which enables STM32U5-specific DHUK functionality.
 * 
 * _Example_
 * \code
 * #ifdef WOLFSSL_STM32U5_DHUK
 * // IV bytes here
 * CK_BYTE dhukIv[16] = { 0 };
 * CK_ATTRIBUTE template[] = {
 *     {CKA_CLASS,           &keyClass,  sizeof(keyClass)},
 *     {CKA_WOLFSSL_DHUK_IV, dhukIv,     sizeof(dhukIv)},
 *     // other attributes
 * };
 * #endif
 * \endcode
 * 
 * \sa CKA_WOLFSSL_DEVID
 */
#define CKA_WOLFSSL_DHUK_IV

/*!
 * \ingroup pkcs11_10_extensions
 * \brief wolfSSL vendor ID for vendor-defined extensions.
 * 
 * This constant (CK_VENDOR_WOLFSSL_DEVID = 0x574F4C46L) defines the vendor ID
 * used by wolfSSL for all vendor-defined PKCS#11 extensions. The value spells
 * "WOLF" in ASCII when viewed as bytes.
 * 
 * This vendor ID is used as the base for constructing vendor-defined attribute
 * and mechanism type identifiers according to the PKCS#11 specification.
 * 
 * \sa CKA_WOLFSSL_DEVID
 * \sa CKA_WOLFSSL_DHUK_IV
 */
#define CK_VENDOR_WOLFSSL_DEVID
/**
 * \page pkcs11_nss_extensions_overview wolfPKCS11 NSS Extensions
 * wolfPKCS11 NSS-specific extensions and enhancements for Mozilla NSS compatibility.
 * 
 * wolfPKCS11 provides several extensions specifically designed for compatibility
 * with Mozilla NSS (Network Security Services). These extensions enable wolfPKCS11
 * to be used as a drop-in replacement for NSS's PKCS#11 module in various
 * applications including Firefox, Thunderbird, and other NSS-based software.
 * 
 * All NSS extensions are enabled using the --enable-nss configure flag and are
 * conditionally compiled based on the WOLFPKCS11_NSS preprocessor definition.
 */

/*!
 * \defgroup pkcs11_nss_mechanisms NSS Cryptographic Mechanisms
 * \ingroup pkcs11_nss_extensions_overview
 * \brief NSS-specific cryptographic mechanisms supported by wolfPKCS11.
 * @{
 */

/*! \brief NSS TLS PRF General SHA256 mechanism. */
#define CKM_NSS_TLS_PRF_GENERAL_SHA256

/*! \brief NSS TLS Extended Master Key Derive mechanism. */
#define CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE

/*! \brief NSS TLS Extended Master Key Derive DH mechanism. */
#define CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH

/*! \brief NSS PKCS#12 PBE SHA-224 HMAC Key Generation mechanism. */
#define CKM_NSS_PKCS12_PBE_SHA224_HMAC_KEY_GEN

/*! \brief NSS PKCS#12 PBE SHA-256 HMAC Key Generation mechanism. */
#define CKM_NSS_PKCS12_PBE_SHA256_HMAC_KEY_GEN

/*! \brief NSS PKCS#12 PBE SHA-384 HMAC Key Generation mechanism. */
#define CKM_NSS_PKCS12_PBE_SHA384_HMAC_KEY_GEN

/*! \brief NSS PKCS#12 PBE SHA-512 HMAC Key Generation mechanism. */
#define CKM_NSS_PKCS12_PBE_SHA512_HMAC_KEY_GEN

/*! \brief SSL 3.0 Master Key Derive mechanism (advertised only). */
#define CKM_SSL3_MASTER_KEY_DERIVE

/*! @} */

/*!
 * \defgroup pkcs11_nss_objects NSS Object Types
 * \ingroup pkcs11_nss_extensions_overview
 * \brief NSS-specific object types supported by wolfPKCS11.
 * @{
 */

/*! \brief NSS Trust object type. */
#define CKO_NSS_TRUST

/*! @} */

/*!
 * \defgroup pkcs11_nss_keytypes NSS Key Types
 * \ingroup pkcs11_nss_extensions_overview
 * \brief NSS-specific key types supported by wolfPKCS11.
 * @{
 */

/*! \brief NSS Trust key type. */
#define CKK_NSS_TRUST

/*! @} */

/*!
 * \defgroup pkcs11_nss_attributes NSS Attributes
 * \ingroup pkcs11_nss_extensions_overview
 * \brief NSS-specific attributes supported by wolfPKCS11.
 * @{
 */

/*! \brief Certificate SHA-1 hash attribute. */
#define CKA_CERT_SHA1_HASH

/*! \brief Certificate MD5 hash attribute. */
#define CKA_CERT_MD5_HASH

/*! \brief Certificate email address attribute. */
#define CKA_NSS_EMAIL

/*! \brief NSS database attribute (legacy, ignored). */
#define CKA_NSS_DB

/*! \brief Trust server authentication attribute. */
#define CKA_TRUST_SERVER_AUTH

/*! \brief Trust client authentication attribute. */
#define CKA_TRUST_CLIENT_AUTH

/*! \brief Trust email protection attribute. */
#define CKA_TRUST_EMAIL_PROTECTION

/*! \brief Trust code signing attribute. */
#define CKA_TRUST_CODE_SIGNING

/*! @} */
