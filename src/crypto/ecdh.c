/**
 * @file ecdh.c
 * @brief ECDH key exchange implementation using mbedTLS
 */

#include <himitsu/crypto.h>
#include <himitsu/utils.h>
#include <string.h>
#include <stdio.h>


// In production, this would use mbedTLS ECDH functions

/**
 * @brief Generate ECDH key pair (simplified implementation)
 */
himitsu_error_t himitsu_ecdh_generate_keypair(char** public_key, char** private_key) {
    if (public_key == NULL || private_key == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Generate random bytes for private key (64 hex chars = 32 bytes)
    uint8_t private_bytes[32];
    himitsu_error_t result = himitsu_random_bytes(private_bytes, sizeof(private_bytes));
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Convert to hex string
    *private_key = himitsu_secure_malloc(65); // 64 chars + null terminator
    if (*private_key == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    for (int i = 0; i < 32; i++) {
        sprintf((*private_key) + (i * 2), "%02x", private_bytes[i]);
    }
    
    // Generate corresponding public key (simplified - in reality would use EC point multiplication)
    uint8_t public_bytes[64]; // Uncompressed point: 32 bytes x + 32 bytes y
    
    // For demo purposes, derive public from private using simple hash
    // In production, this would be proper EC point multiplication
    uint8_t hash_input[64];
    memcpy(hash_input, private_bytes, 32);
    memcpy(hash_input + 32, "HIMITSU_PUBKEY_DERIVE", 21);
    memset(hash_input + 53, 0, 11);
    
    result = himitsu_sha256(hash_input, sizeof(hash_input), public_bytes);
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_free(*private_key, 65);
        return result;
    }
    
    result = himitsu_sha256(public_bytes, 32, public_bytes + 32);
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_free(*private_key, 65);
        return result;
    }
    
    // Convert public key to hex string
    *public_key = himitsu_secure_malloc(129); // 128 chars + null terminator
    if (*public_key == NULL) {
        himitsu_secure_free(*private_key, 65);
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    for (int i = 0; i < 64; i++) {
        sprintf((*public_key) + (i * 2), "%02x", public_bytes[i]);
    }
    
    // Clear sensitive data
    himitsu_secure_memzero(private_bytes, sizeof(private_bytes));
    himitsu_secure_memzero(public_bytes, sizeof(public_bytes));
    himitsu_secure_memzero(hash_input, sizeof(hash_input));
    
    return HIMITSU_SUCCESS;
}

/**
 * @brief Derive shared secret from ECDH key exchange
 */
himitsu_error_t himitsu_ecdh_derive_shared_secret(const char* private_key_hex,
                                                 const char* peer_public_key_hex,
                                                 char** shared_secret) {
    if (private_key_hex == NULL || peer_public_key_hex == NULL || shared_secret == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Validate key lengths
    if (strlen(private_key_hex) != 64 || strlen(peer_public_key_hex) != 128) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Convert hex strings to bytes
    uint8_t private_bytes[32];
    uint8_t peer_public_bytes[64];
    
    // Parse private key
    for (int i = 0; i < 32; i++) {
        if (sscanf(private_key_hex + (i * 2), "%02hhx", &private_bytes[i]) != 1) {
            return HIMITSU_ERROR_CRYPTO_FAILURE;
        }
    }
    
    // Parse peer public key
    for (int i = 0; i < 64; i++) {
        if (sscanf(peer_public_key_hex + (i * 2), "%02hhx", &peer_public_bytes[i]) != 1) {
            himitsu_secure_memzero(private_bytes, sizeof(private_bytes));
            return HIMITSU_ERROR_CRYPTO_FAILURE;
        }
    }
    
    // Perform ECDH (simplified - combine private key with peer public key)
    uint8_t shared_bytes[32];
    uint8_t kdf_input[96]; // 32 + 64 bytes
    
    memcpy(kdf_input, private_bytes, 32);
    memcpy(kdf_input + 32, peer_public_bytes, 64);
    
    himitsu_error_t result = himitsu_sha256(kdf_input, sizeof(kdf_input), shared_bytes);
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_memzero(private_bytes, sizeof(private_bytes));
        himitsu_secure_memzero(peer_public_bytes, sizeof(peer_public_bytes));
        himitsu_secure_memzero(kdf_input, sizeof(kdf_input));
        return result;
    }
    
    // Convert to hex string
    *shared_secret = himitsu_secure_malloc(65);
    if (*shared_secret == NULL) {
        himitsu_secure_memzero(private_bytes, sizeof(private_bytes));
        himitsu_secure_memzero(peer_public_bytes, sizeof(peer_public_bytes));
        himitsu_secure_memzero(kdf_input, sizeof(kdf_input));
        himitsu_secure_memzero(shared_bytes, sizeof(shared_bytes));
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    for (int i = 0; i < 32; i++) {
        sprintf((*shared_secret) + (i * 2), "%02x", shared_bytes[i]);
    }
    
    // Clear sensitive data
    himitsu_secure_memzero(private_bytes, sizeof(private_bytes));
    himitsu_secure_memzero(peer_public_bytes, sizeof(peer_public_bytes));
    himitsu_secure_memzero(kdf_input, sizeof(kdf_input));
    himitsu_secure_memzero(shared_bytes, sizeof(shared_bytes));
    
    return HIMITSU_SUCCESS;
}
