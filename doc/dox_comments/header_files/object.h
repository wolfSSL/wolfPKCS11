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
 * rv = C_CreateObject(hSession, template, 5, &hKey);
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
 * rv = C_CopyObject(hSession, hOriginal, template, 1, &hCopy);
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
 * rv = C_DestroyObject(hSession, hObject);
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
 * rv = C_GetObjectSize(hSession, hObject, &objectSize);
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
 * rv = C_GetAttributeValue(hSession, hKey, template, 2);
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
 * rv = C_SetAttributeValue(hSession, hKey, template, 1);
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
 * rv = C_FindObjectsInit(hSession, template, 2);
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
 * rv = C_FindObjects(hSession, objects, 10, &objectCount);
 * if (rv == CKR_OK) {
 *     printf("Found %lu objects\n", objectCount);
 *     for (CK_ULONG i = 0; i < objectCount; i++) {
 *         printf("Object handle: %lu\n", objects[i]);
 *     }
 * }
 * 
 * C_FindObjectsFinal(hSession);
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
 * rv = C_FindObjectsFinal(hSession);
 * if (rv == CKR_OK) {
 *     printf("Search operation completed\n");
 * }
 * \endcode
 * 
 * \sa C_FindObjectsInit
 * \sa C_FindObjects
 */
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
