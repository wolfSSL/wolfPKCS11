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
 * CK_ULONG count = 0;
 * C_GetSlotList(CK_TRUE, NULL_PTR, &count);
 * CK_SLOT_ID* slots = malloc(count * sizeof(CK_SLOT_ID));
 * C_GetSlotList(CK_TRUE, slots, &count);
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
