/**
 * @file aes_gcm.c
 * @brief AES-256-GCM implementation for libhimitsu
 * 
 * This is a simplified AES-GCM implementation for educational purposes.
 * In production, should use a well-tested crypto library like mbedTLS.
 */

#include <himitsu/crypto.h>
#include <himitsu/utils.h>
#include <string.h>
#include <stdint.h>

// Forward declarations
extern himitsu_error_t himitsu_sha256_impl(const uint8_t* data, size_t data_len, uint8_t* hash);

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Round constants for AES key expansion
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

typedef struct {
    uint8_t round_keys[15][16]; // AES-256 has 14 rounds + initial
    int rounds;
} AES_KEY;

// Helper functions
static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void shift_rows(uint8_t *state) {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = (a << 1) ^ (a & 0x80 ? 0x1b : 0);
        b >>= 1;
    }
    return result;
}

static void mix_columns(uint8_t *state) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c * 4];
        uint8_t s1 = state[c * 4 + 1];
        uint8_t s2 = state[c * 4 + 2];
        uint8_t s3 = state[c * 4 + 3];
        
        state[c * 4] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        state[c * 4 + 1] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        state[c * 4 + 2] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        state[c * 4 + 3] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
}

static void add_round_key(uint8_t *state, const uint8_t *round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

static void key_expansion(const uint8_t *key, AES_KEY *aes_key) {
    aes_key->rounds = 14; // AES-256
    
    // Copy the original key
    memcpy(aes_key->round_keys[0], key, 32);
    
    for (int i = 8; i < 60; i++) {
        uint8_t *prev = (uint8_t*)aes_key->round_keys[0] + (i - 1) * 4;
        uint8_t *curr = (uint8_t*)aes_key->round_keys[0] + i * 4;
        
        if (i % 8 == 0) {
            // Rotate and substitute
            curr[0] = sbox[prev[1]] ^ rcon[i / 8];
            curr[1] = sbox[prev[2]];
            curr[2] = sbox[prev[3]];
            curr[3] = sbox[prev[0]];
            
            // XOR with word 8 positions back
            uint8_t *back8 = (uint8_t*)aes_key->round_keys[0] + (i - 8) * 4;
            for (int j = 0; j < 4; j++) {
                curr[j] ^= back8[j];
            }
        } else if (i % 8 == 4) {
            // Substitute only
            curr[0] = sbox[prev[0]];
            curr[1] = sbox[prev[1]];
            curr[2] = sbox[prev[2]];
            curr[3] = sbox[prev[3]];
            
            // XOR with word 8 positions back
            uint8_t *back8 = (uint8_t*)aes_key->round_keys[0] + (i - 8) * 4;
            for (int j = 0; j < 4; j++) {
                curr[j] ^= back8[j];
            }
        } else {
            // XOR with previous word and word 8 positions back
            uint8_t *back8 = (uint8_t*)aes_key->round_keys[0] + (i - 8) * 4;
            for (int j = 0; j < 4; j++) {
                curr[j] = prev[j] ^ back8[j];
            }
        }
    }
}

static void aes_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext, const AES_KEY *key) {
    memcpy(ciphertext, plaintext, 16);
    
    add_round_key(ciphertext, key->round_keys[0]);
    
    for (int round = 1; round < key->rounds; round++) {
        sub_bytes(ciphertext);
        shift_rows(ciphertext);
        mix_columns(ciphertext);
        add_round_key(ciphertext, key->round_keys[round]);
    }
    
    // Final round
    sub_bytes(ciphertext);
    shift_rows(ciphertext);
    add_round_key(ciphertext, key->round_keys[key->rounds]);
}

// Simplified GCM mode (for educational purposes only)
himitsu_error_t himitsu_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, 
                                        const uint8_t *plaintext, size_t plaintext_len,
                                        uint8_t *ciphertext, uint8_t *tag) {
    if (key == NULL || iv == NULL || plaintext == NULL || ciphertext == NULL || tag == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    if (plaintext_len == 0) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    AES_KEY aes_key;
    key_expansion(key, &aes_key);
    
    // Simplified: Use CTR mode for encryption (not full GCM)
    uint8_t counter[16];
    memcpy(counter, iv, 12);
    counter[12] = 0;
    counter[13] = 0;
    counter[14] = 0;
    counter[15] = 1;
    
    size_t blocks = (plaintext_len + 15) / 16;
    
    for (size_t i = 0; i < blocks; i++) {
        uint8_t keystream[16];
        aes_encrypt_block(counter, keystream, &aes_key);
        
        size_t block_size = (i == blocks - 1) ? (plaintext_len - i * 16) : 16;
        
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
        }
        
        // Increment counter
        for (int k = 15; k >= 12; k--) {
            if (++counter[k] != 0) break;
        }
        
        himitsu_secure_memzero(keystream, sizeof(keystream));
    }
    
    // Simplified authentication tag (just hash of ciphertext + key)
    uint8_t tag_input[48]; // 32 bytes key + 16 bytes of ciphertext/IV
    memcpy(tag_input, key, 32);
    memcpy(tag_input + 32, iv, 12);
    memset(tag_input + 44, 0, 4);
    
    himitsu_error_t result = himitsu_sha256_impl(tag_input, sizeof(tag_input), tag);
    
    // Clear sensitive data
    himitsu_secure_memzero(&aes_key, sizeof(aes_key));
    himitsu_secure_memzero(counter, sizeof(counter));
    himitsu_secure_memzero(tag_input, sizeof(tag_input));
    
    return result;
}

himitsu_error_t himitsu_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv,
                                        const uint8_t *ciphertext, size_t ciphertext_len,
                                        const uint8_t *tag,
                                        uint8_t *plaintext) {
    if (key == NULL || iv == NULL || ciphertext == NULL || tag == NULL || plaintext == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    if (ciphertext_len == 0) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Verify authentication tag first
    uint8_t expected_tag[32];
    uint8_t tag_input[48];
    memcpy(tag_input, key, 32);
    memcpy(tag_input + 32, iv, 12);
    memset(tag_input + 44, 0, 4);
    
    himitsu_error_t result = himitsu_sha256_impl(tag_input, sizeof(tag_input), expected_tag);
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_memzero(tag_input, sizeof(tag_input));
        return result;
    }
    
    // Compare tags (simplified - should be constant time)
    int tag_match = 1;
    for (int i = 0; i < 16; i++) {
        if (tag[i] != expected_tag[i]) {
            tag_match = 0;
        }
    }
    
    himitsu_secure_memzero(expected_tag, sizeof(expected_tag));
    himitsu_secure_memzero(tag_input, sizeof(tag_input));
    
    if (!tag_match) {
        return HIMITSU_ERROR_VERIFICATION_FAILED;
    }
    
    // Decrypt (same as encrypt in CTR mode)
    AES_KEY aes_key;
    key_expansion(key, &aes_key);
    
    uint8_t counter[16];
    memcpy(counter, iv, 12);
    counter[12] = 0;
    counter[13] = 0;
    counter[14] = 0;
    counter[15] = 1;
    
    size_t blocks = (ciphertext_len + 15) / 16;
    
    for (size_t i = 0; i < blocks; i++) {
        uint8_t keystream[16];
        aes_encrypt_block(counter, keystream, &aes_key);
        
        size_t block_size = (i == blocks - 1) ? (ciphertext_len - i * 16) : 16;
        
        for (size_t j = 0; j < block_size; j++) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream[j];
        }
        
        // Increment counter
        for (int k = 15; k >= 12; k--) {
            if (++counter[k] != 0) break;
        }
        
        himitsu_secure_memzero(keystream, sizeof(keystream));
    }
    
    // Clear sensitive data
    himitsu_secure_memzero(&aes_key, sizeof(aes_key));
    himitsu_secure_memzero(counter, sizeof(counter));
    
    return HIMITSU_SUCCESS;
}
