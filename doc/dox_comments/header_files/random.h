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
