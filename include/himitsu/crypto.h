#ifndef HIMITSU_CRYPTO_H
#define HIMITSU_CRYPTO_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate a new ECDH key pair
 * 
 * @param public_key Output buffer for public key (caller must free)
 * @param private_key Output buffer for private key (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_generate_keypair(char** public_key, char** private_key);

/**
 * @brief Encrypt payload using recipient's public key
 * 
 * @param plaintext Input plaintext to encrypt
 * @param recipient_pub_key Recipient's public key
 * @param ciphertext Output encrypted data (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_encrypt_payload(const char* plaintext, 
                                       const char* recipient_pub_key, 
                                       char** ciphertext);

/**
 * @brief Decrypt payload using private key
 * 
 * @param ciphertext Input encrypted data
 * @param private_key Private key for decryption
 * @param plaintext Output decrypted data (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_decrypt_payload(const char* ciphertext, 
                                       const char* private_key, 
                                       char** plaintext);

/**
 * @brief Perform ECDH key exchange to derive shared secret
 * 
 * @param private_key Our private key
 * @param peer_public_key Peer's public key
 * @param shared_secret Output shared secret (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_derive_shared_secret(const char* private_key,
                                            const char* peer_public_key,
                                            char** shared_secret);

/**
 * @brief Compute SHA-256 hash of input data
 * 
 * @param data Input data to hash
 * @param data_len Length of input data
 * @param hash Output hash (must be at least HIMITSU_HASH_SIZE bytes)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_sha256(const uint8_t* data, size_t data_len, uint8_t* hash);

/**
 * @brief Compute HMAC-SHA256
 * 
 * @param key HMAC key
 * @param key_len Length of HMAC key
 * @param data Input data
 * @param data_len Length of input data
 * @param hmac Output HMAC (must be at least HIMITSU_HASH_SIZE bytes)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_hmac_sha256(const uint8_t* key, size_t key_len,
                                   const uint8_t* data, size_t data_len,
                                   uint8_t* hmac);

/**
 * @brief Generate cryptographically secure random bytes
 * 
 * @param buffer Output buffer for random bytes
 * @param len Number of random bytes to generate
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_random_bytes(uint8_t* buffer, size_t len);

/**
 * @brief Secure memory clearing to prevent data from remaining in memory
 * 
 * @param ptr Pointer to memory to clear
 * @param len Length of memory to clear
 */
void himitsu_secure_memzero(void* ptr, size_t len);

/**
 * @brief Convenience function to hash a message and return hex string
 * 
 * @param message Input message to hash
 * @param hash_output Output hash as hex string (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_hash_message(const char* message, char** hash_output);

/**
 * @brief Convenience function to generate HMAC and return hex string
 * 
 * @param message Input message
 * @param key HMAC key
 * @param hmac_output Output HMAC as hex string (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_generate_hmac(const char* message, const char* key, char** hmac_output);

/**
 * @brief Convenience function to verify HMAC
 * 
 * @param message Input message
 * @param key HMAC key
 * @param expected_hmac Expected HMAC as hex string
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_verify_hmac(const char* message, const char* key, const char* expected_hmac);

#ifdef __cplusplus
}
#endif

#endif /* HIMITSU_CRYPTO_H */
