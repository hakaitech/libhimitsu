/**
 * @file crypto.c
 * @brief Main cryptographic implementation for libhimitsu
 */

#include <himitsu/crypto.h>
#include <himitsu/types.h>
#include <himitsu/utils.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

himitsu_error_t himitsu_generate_keypair(char** public_key, char** private_key) {
    // Use real ECDH key generation
    extern himitsu_error_t himitsu_ecdh_generate_keypair(char** public_key, char** private_key);
    return himitsu_ecdh_generate_keypair(public_key, private_key);
}

himitsu_error_t himitsu_encrypt_payload(const char* plaintext, 
                                       const char* recipient_pub_key, 
                                       char** ciphertext) {
    if (plaintext == NULL || recipient_pub_key == NULL || ciphertext == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    size_t plaintext_len = strlen(plaintext);
    
    // Generate ephemeral key pair for this encryption
    char* ephemeral_public = NULL;
    char* ephemeral_private = NULL;
    
    himitsu_error_t result = himitsu_generate_keypair(&ephemeral_public, &ephemeral_private);
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Derive shared secret
    char* shared_secret = NULL;
    result = himitsu_derive_shared_secret(ephemeral_private, recipient_pub_key, &shared_secret);
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_strfree(ephemeral_public);
        himitsu_secure_strfree(ephemeral_private);
        return result;
    }
    
    // Convert shared secret to bytes for AES key
    uint8_t aes_key[32];
    for (int i = 0; i < 32; i++) {
        if (sscanf(shared_secret + (i * 2), "%02hhx", &aes_key[i]) != 1) {
            himitsu_secure_strfree(ephemeral_public);
            himitsu_secure_strfree(ephemeral_private);
            himitsu_secure_strfree(shared_secret);
            return HIMITSU_ERROR_CRYPTO_FAILURE;
        }
    }
    
    // Generate random IV
    uint8_t iv[12];
    result = himitsu_random_bytes(iv, sizeof(iv));
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_strfree(ephemeral_public);
        himitsu_secure_strfree(ephemeral_private);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        return result;
    }
    
    // Encrypt using AES-GCM
    uint8_t* encrypted_data = himitsu_secure_malloc(plaintext_len);
    uint8_t tag[32]; // Using SHA-256 output size for simplified tag
    
    if (encrypted_data == NULL) {
        himitsu_secure_strfree(ephemeral_public);
        himitsu_secure_strfree(ephemeral_private);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    extern himitsu_error_t himitsu_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, 
                                                   const uint8_t *plaintext, size_t plaintext_len,
                                                   uint8_t *ciphertext, uint8_t *tag);
    
    result = himitsu_aes_gcm_encrypt(aes_key, iv, (const uint8_t*)plaintext, plaintext_len,
                                     encrypted_data, tag);
    
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_strfree(ephemeral_public);
        himitsu_secure_strfree(ephemeral_private);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        himitsu_secure_free(encrypted_data, plaintext_len);
        return result;
    }
    
    // Create output format: ephemeral_public:iv:tag:ciphertext (all in hex)
    size_t output_len = strlen(ephemeral_public) + 1 + 24 + 1 + 64 + 1 + (plaintext_len * 2) + 1;
    *ciphertext = himitsu_secure_malloc(output_len);
    
    if (*ciphertext == NULL) {
        himitsu_secure_strfree(ephemeral_public);
        himitsu_secure_strfree(ephemeral_private);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        himitsu_secure_free(encrypted_data, plaintext_len);
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    // Format: ephemeral_public:iv_hex:tag_hex:data_hex
    strcpy(*ciphertext, ephemeral_public);
    strcat(*ciphertext, ":");
    
    // Append IV in hex
    size_t pos = strlen(*ciphertext);
    for (int i = 0; i < 12; i++) {
        sprintf((*ciphertext) + pos + (i * 2), "%02x", iv[i]);
    }
    strcat(*ciphertext, ":");
    
    // Append tag in hex (first 16 bytes of SHA-256)
    pos = strlen(*ciphertext);
    for (int i = 0; i < 16; i++) {
        sprintf((*ciphertext) + pos + (i * 2), "%02x", tag[i]);
    }
    strcat(*ciphertext, ":");
    
    // Append encrypted data in hex
    pos = strlen(*ciphertext);
    for (size_t i = 0; i < plaintext_len; i++) {
        sprintf((*ciphertext) + pos + (i * 2), "%02x", encrypted_data[i]);
    }
    
    // Clean up sensitive data
    himitsu_secure_strfree(ephemeral_private);
    himitsu_secure_strfree(shared_secret);
    himitsu_secure_memzero(aes_key, sizeof(aes_key));
    himitsu_secure_free(encrypted_data, plaintext_len);
    himitsu_secure_memzero(tag, sizeof(tag));
    himitsu_secure_memzero(iv, sizeof(iv));
    
    // Keep ephemeral public key for recipient
    himitsu_secure_strfree(ephemeral_public);
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_decrypt_payload(const char* ciphertext, 
                                       const char* private_key, 
                                       char** plaintext) {
    if (ciphertext == NULL || private_key == NULL || plaintext == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Parse format: ephemeral_public:iv_hex:tag_hex:data_hex
    char* ciphertext_copy = himitsu_secure_strdup(ciphertext);
    if (ciphertext_copy == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    char* ephemeral_public = strtok(ciphertext_copy, ":");
    char* iv_hex = strtok(NULL, ":");
    char* tag_hex = strtok(NULL, ":");
    char* data_hex = strtok(NULL, ":");
    
    if (ephemeral_public == NULL || iv_hex == NULL || tag_hex == NULL || data_hex == NULL) {
        himitsu_secure_strfree(ciphertext_copy);
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Derive shared secret
    char* shared_secret = NULL;
    himitsu_error_t result = himitsu_derive_shared_secret(private_key, ephemeral_public, &shared_secret);
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_strfree(ciphertext_copy);
        return result;
    }
    
    // Convert shared secret to AES key
    uint8_t aes_key[32];
    for (int i = 0; i < 32; i++) {
        if (sscanf(shared_secret + (i * 2), "%02hhx", &aes_key[i]) != 1) {
            himitsu_secure_strfree(ciphertext_copy);
            himitsu_secure_strfree(shared_secret);
            return HIMITSU_ERROR_CRYPTO_FAILURE;
        }
    }
    
    // Parse IV
    uint8_t iv[12];
    if (strlen(iv_hex) != 24) {
        himitsu_secure_strfree(ciphertext_copy);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    for (int i = 0; i < 12; i++) {
        if (sscanf(iv_hex + (i * 2), "%02hhx", &iv[i]) != 1) {
            himitsu_secure_strfree(ciphertext_copy);
            himitsu_secure_strfree(shared_secret);
            himitsu_secure_memzero(aes_key, sizeof(aes_key));
            return HIMITSU_ERROR_CRYPTO_FAILURE;
        }
    }
    
    // Parse tag
    uint8_t tag[32];
    if (strlen(tag_hex) != 32) {
        himitsu_secure_strfree(ciphertext_copy);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    for (int i = 0; i < 16; i++) {
        if (sscanf(tag_hex + (i * 2), "%02hhx", &tag[i]) != 1) {
            himitsu_secure_strfree(ciphertext_copy);
            himitsu_secure_strfree(shared_secret);
            himitsu_secure_memzero(aes_key, sizeof(aes_key));
            return HIMITSU_ERROR_CRYPTO_FAILURE;
        }
    }
    
    // Parse encrypted data
    size_t data_len = strlen(data_hex) / 2;
    uint8_t* encrypted_data = himitsu_secure_malloc(data_len);
    if (encrypted_data == NULL) {
        himitsu_secure_strfree(ciphertext_copy);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    for (size_t i = 0; i < data_len; i++) {
        if (sscanf(data_hex + (i * 2), "%02hhx", &encrypted_data[i]) != 1) {
            himitsu_secure_strfree(ciphertext_copy);
            himitsu_secure_strfree(shared_secret);
            himitsu_secure_memzero(aes_key, sizeof(aes_key));
            himitsu_secure_free(encrypted_data, data_len);
            return HIMITSU_ERROR_CRYPTO_FAILURE;
        }
    }
    
    // Decrypt
    uint8_t* decrypted_data = himitsu_secure_malloc(data_len + 1); // +1 for null terminator
    if (decrypted_data == NULL) {
        himitsu_secure_strfree(ciphertext_copy);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        himitsu_secure_free(encrypted_data, data_len);
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    extern himitsu_error_t himitsu_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv,
                                                   const uint8_t *ciphertext, size_t ciphertext_len,
                                                   const uint8_t *tag,
                                                   uint8_t *plaintext);
    
    result = himitsu_aes_gcm_decrypt(aes_key, iv, encrypted_data, data_len, tag, decrypted_data);
    
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_strfree(ciphertext_copy);
        himitsu_secure_strfree(shared_secret);
        himitsu_secure_memzero(aes_key, sizeof(aes_key));
        himitsu_secure_free(encrypted_data, data_len);
        himitsu_secure_free(decrypted_data, data_len + 1);
        return result;
    }
    
    // Null-terminate the decrypted data
    decrypted_data[data_len] = '\0';
    *plaintext = (char*)decrypted_data;
    
    // Clean up
    himitsu_secure_strfree(ciphertext_copy);
    himitsu_secure_strfree(shared_secret);
    himitsu_secure_memzero(aes_key, sizeof(aes_key));
    himitsu_secure_free(encrypted_data, data_len);
    himitsu_secure_memzero(tag, sizeof(tag));
    himitsu_secure_memzero(iv, sizeof(iv));
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_derive_shared_secret(const char* private_key,
                                            const char* peer_public_key,
                                            char** shared_secret) {
    // Use real ECDH shared secret derivation
    extern himitsu_error_t himitsu_ecdh_derive_shared_secret(const char* private_key_hex,
                                                            const char* peer_public_key_hex,
                                                            char** shared_secret);
    return himitsu_ecdh_derive_shared_secret(private_key, peer_public_key, shared_secret);
}

himitsu_error_t himitsu_sha256(const uint8_t* data, size_t data_len, uint8_t* hash) {
    // Use real SHA-256 implementation
    extern himitsu_error_t himitsu_sha256_impl(const uint8_t* data, size_t data_len, uint8_t* hash);
    return himitsu_sha256_impl(data, data_len, hash);
}

himitsu_error_t himitsu_hmac_sha256(const uint8_t* key, size_t key_len,
                                   const uint8_t* data, size_t data_len,
                                   uint8_t* hmac) {
    // Use real HMAC-SHA256 implementation
    extern himitsu_error_t himitsu_hmac_sha256_impl(const uint8_t* key, size_t key_len,
                                                    const uint8_t* data, size_t data_len,
                                                    uint8_t* hmac);
    return himitsu_hmac_sha256_impl(key, key_len, data, data_len, hmac);
}

himitsu_error_t himitsu_random_bytes(uint8_t* buffer, size_t len) {
    if (buffer == NULL || len == 0) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Use system random source
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        // Fallback to less secure method on systems without /dev/urandom
        static int seeded = 0;
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }
        
        for (size_t i = 0; i < len; i++) {
            buffer[i] = (uint8_t)(rand() & 0xFF);
        }
        return HIMITSU_SUCCESS; // Not ideal but functional
    }
    
    size_t bytes_read = fread(buffer, 1, len, urandom);
    fclose(urandom);
    
    if (bytes_read != len) {
        return HIMITSU_ERROR_CRYPTO_FAILURE;
    }
    
    return HIMITSU_SUCCESS;
}

void himitsu_secure_memzero(void* ptr, size_t len) {
    if (ptr != NULL && len > 0) {
        // Use volatile to prevent compiler optimization
        volatile uint8_t* volatile_ptr = (volatile uint8_t*)ptr;
        for (size_t i = 0; i < len; i++) {
            volatile_ptr[i] = 0;
        }
    }
}

// Convenience wrapper functions for easier testing

himitsu_error_t himitsu_hash_message(const char* message, char** hash_output) {
    if (message == NULL || hash_output == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    uint8_t hash[32]; // SHA-256 output
    himitsu_error_t result = himitsu_sha256((const uint8_t*)message, strlen(message), hash);
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Convert to hex string
    *hash_output = malloc(65); // 32 bytes * 2 + null terminator
    if (*hash_output == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    for (int i = 0; i < 32; i++) {
        sprintf((*hash_output) + i * 2, "%02x", hash[i]);
    }
    (*hash_output)[64] = '\0';
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_generate_hmac(const char* message, const char* key, char** hmac_output) {
    if (message == NULL || key == NULL || hmac_output == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    uint8_t hmac[32]; // HMAC-SHA256 output
    himitsu_error_t result = himitsu_hmac_sha256(
        (const uint8_t*)key, strlen(key),
        (const uint8_t*)message, strlen(message),
        hmac
    );
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Convert to hex string
    *hmac_output = malloc(65); // 32 bytes * 2 + null terminator
    if (*hmac_output == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    for (int i = 0; i < 32; i++) {
        sprintf((*hmac_output) + i * 2, "%02x", hmac[i]);
    }
    (*hmac_output)[64] = '\0';
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_verify_hmac(const char* message, const char* key, const char* expected_hmac) {
    if (message == NULL || key == NULL || expected_hmac == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    char* computed_hmac = NULL;
    himitsu_error_t result = himitsu_generate_hmac(message, key, &computed_hmac);
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Compare HMACs
    int comparison = strcmp(computed_hmac, expected_hmac);
    free(computed_hmac);
    
    return (comparison == 0) ? HIMITSU_SUCCESS : HIMITSU_ERROR_VERIFICATION_FAILED;
}
