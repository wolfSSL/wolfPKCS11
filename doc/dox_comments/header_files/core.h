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
 * 
 * // Initialize with default settings
 * rv = C_Initialize(NULL_PTR);
 * if (rv != CKR_OK) {
 *     printf("C_Initialize failed: 0x%08lX\n", rv);
 *     return rv;
 * }
 * 
 * // ... perform PKCS#11 operations ...
 * 
 * C_Finalize(NULL_PTR);
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
 * 
 * rv = C_Initialize(NULL_PTR);
 * if (rv == CKR_OK) {
 *     // ... perform operations ...
 *     
 *     rv = C_Finalize(NULL_PTR);
 *     if (rv != CKR_OK) {
 *         printf("C_Finalize failed: 0x%08lX\n", rv);
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
 * 
 * rv = C_Initialize(NULL_PTR);
 * if (rv == CKR_OK) {
 *     rv = C_GetInfo(&info);
 *     if (rv == CKR_OK) {
 *         printf("Library: %.32s\n", info.libraryDescription);
 *         printf("Version: %d.%d\n", info.libraryVersion.major,
 *                                    info.libraryVersion.minor);
 *     }
 *     C_Finalize(NULL_PTR);
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
