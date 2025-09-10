/**
 * @file protocol.c
 * @brief Node-Synchronized Handshake Protocol Implementation
 * 
 * Implements the core protocol logic for secure challenge-based handshakes
 * using HMAC-based challenges with epoch keys and shared secrets.
 */

#include <himitsu/protocol.h>
#include <himitsu/crypto.h>
#include <himitsu/utils.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Session structure implementation */
struct himitsu_session {
    himitsu_keypair_t local_keypair;
    char* peer_public_key;
    char* shared_secret;
    int is_established;
    char* peer_id;
    uint64_t session_id;
    time_t created_at;
    time_t last_activity;
};

/* Internal helper functions */
static himitsu_error_t create_challenge_data(const char* epoch_key, 
                                            const char* shared_secret,
                                            uint64_t timestamp,
                                            uint32_t nonce,
                                            char** challenge_data);

static himitsu_error_t parse_challenge_data(const char* challenge,
                                           char** epoch_key,
                                           char** shared_secret_hash,
                                           uint64_t* timestamp,
                                           uint32_t* nonce);

himitsu_error_t himitsu_create_handshake_challenge(const char* epoch_key,
                                                  const char* shared_secret,
                                                  char** challenge) {
    if (epoch_key == NULL || shared_secret == NULL || challenge == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    himitsu_error_t result;
    
    // Generate timestamp and nonce for uniqueness
    uint64_t timestamp = (uint64_t)time(NULL);
    uint32_t nonce;
    result = himitsu_random_bytes((uint8_t*)&nonce, sizeof(nonce));
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Create challenge data structure
    char* challenge_data = NULL;
    result = create_challenge_data(epoch_key, shared_secret, timestamp, nonce, &challenge_data);
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Generate HMAC of the challenge data using shared secret as key
    char* hmac = NULL;
    result = himitsu_generate_hmac(challenge_data, shared_secret, &hmac);
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_strfree(challenge_data);
        return result;
    }
    
    // Format final challenge: challenge_data:hmac
    size_t total_len = strlen(challenge_data) + strlen(hmac) + 2; // +2 for ':' and null terminator
    *challenge = himitsu_secure_malloc(total_len);
    if (*challenge == NULL) {
        himitsu_secure_strfree(challenge_data);
        himitsu_secure_strfree(hmac);
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    snprintf(*challenge, total_len, "%s:%s", challenge_data, hmac);
    
    himitsu_secure_strfree(challenge_data);
    himitsu_secure_strfree(hmac);
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_verify_handshake_challenge(const char* received_challenge,
                                                  const char* epoch_key,
                                                  const char* shared_secret) {
    if (received_challenge == NULL || epoch_key == NULL || shared_secret == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    himitsu_error_t result;
    
    // Parse the received challenge: challenge_data:hmac
    char* challenge_copy = himitsu_secure_malloc(strlen(received_challenge) + 1);
    if (challenge_copy == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    strcpy(challenge_copy, received_challenge);
    
    // Find the last ':' to separate challenge data from HMAC
    char* hmac_start = strrchr(challenge_copy, ':');
    if (hmac_start == NULL) {
        himitsu_secure_strfree(challenge_copy);
        return HIMITSU_ERROR_VERIFICATION_FAILED;
    }
    
    *hmac_start = '\0'; // Split the string
    hmac_start++; // Point to the HMAC part
    
    char* challenge_data = challenge_copy;
    char* received_hmac = hmac_start;
    
    // Parse challenge data to extract epoch key and validate structure
    char* extracted_epoch = NULL;
    char* extracted_secret_hash = NULL;
    uint64_t timestamp;
    uint32_t nonce;
    
    result = parse_challenge_data(challenge_data, &extracted_epoch, &extracted_secret_hash, &timestamp, &nonce);
    if (result != HIMITSU_SUCCESS) {
        himitsu_secure_strfree(challenge_copy);
        return result;
    }
    
    // Verify epoch key matches
    if (strcmp(extracted_epoch, epoch_key) != 0) {
        himitsu_secure_strfree(challenge_copy);
        himitsu_secure_strfree(extracted_epoch);
        himitsu_secure_strfree(extracted_secret_hash);
        return HIMITSU_ERROR_VERIFICATION_FAILED;
    }
    
    // Verify timestamp is recent (within 5 minutes)
    uint64_t current_time = (uint64_t)time(NULL);
    if (current_time - timestamp > 300) { // 5 minutes
        himitsu_secure_strfree(challenge_copy);
        himitsu_secure_strfree(extracted_epoch);
        himitsu_secure_strfree(extracted_secret_hash);
        return HIMITSU_ERROR_VERIFICATION_FAILED;
    }
    
    // Verify HMAC
    result = himitsu_verify_hmac(challenge_data, shared_secret, received_hmac);
    
    himitsu_secure_strfree(challenge_copy);
    himitsu_secure_strfree(extracted_epoch);
    himitsu_secure_strfree(extracted_secret_hash);
    
    return result;
}

himitsu_error_t himitsu_session_create(himitsu_session_t** session,
                                      const himitsu_keypair_t* local_keypair) {
    if (session == NULL || local_keypair == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    *session = himitsu_secure_malloc(sizeof(himitsu_session_t));
    if (*session == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    // Copy local keypair
    (*session)->local_keypair.public_key = himitsu_secure_strdup(local_keypair->public_key);
    (*session)->local_keypair.private_key = himitsu_secure_strdup(local_keypair->private_key);
    (*session)->peer_public_key = NULL;
    (*session)->shared_secret = NULL;
    (*session)->is_established = 0;
    (*session)->peer_id = NULL;
    
    if ((*session)->local_keypair.public_key == NULL || 
        (*session)->local_keypair.private_key == NULL) {
        himitsu_session_destroy(*session);
        *session = NULL;
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    return HIMITSU_SUCCESS;
}

void himitsu_session_destroy(himitsu_session_t* session) {
    if (session == NULL) {
        return;
    }
    
    // Clear sensitive data
    if (session->local_keypair.public_key) {
        himitsu_secure_free(session->local_keypair.public_key, 
                           strlen(session->local_keypair.public_key));
    }
    if (session->local_keypair.private_key) {
        himitsu_secure_free(session->local_keypair.private_key, 
                           strlen(session->local_keypair.private_key));
    }
    if (session->peer_public_key) {
        himitsu_secure_free(session->peer_public_key, strlen(session->peer_public_key));
    }
    if (session->shared_secret) {
        himitsu_secure_free(session->shared_secret, strlen(session->shared_secret));
    }
    if (session->peer_id) {
        himitsu_secure_free(session->peer_id, strlen(session->peer_id));
    }
    
    himitsu_secure_free(session, sizeof(himitsu_session_t));
}

himitsu_error_t himitsu_session_handshake(himitsu_session_t* session,
                                         const char* peer_public_key,
                                         const char* epoch_key) {
    if (session == NULL || peer_public_key == NULL || epoch_key == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    session->peer_public_key = himitsu_secure_strdup(peer_public_key);
    if (session->peer_public_key == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    char* challenge = NULL;
    himitsu_error_t result = himitsu_create_handshake_challenge(epoch_key, peer_public_key, &challenge);
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    result = himitsu_verify_handshake_challenge(challenge, epoch_key, peer_public_key);
    free(challenge);
    
    if (result != HIMITSU_SUCCESS) {
        return HIMITSU_ERROR_HANDSHAKE_FAILED;
    }
    
    result = himitsu_derive_shared_secret(
        session->local_keypair.private_key,
        peer_public_key,
        &session->shared_secret
    );
    
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    char peer_id_buffer[32];
    snprintf(peer_id_buffer, sizeof(peer_id_buffer), "peer_%.16s", peer_public_key);
    session->peer_id = himitsu_secure_strdup(peer_id_buffer);
    if (session->peer_id == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    session->is_established = 1;
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_session_get_info(const himitsu_session_t* session,
                                        int* is_established,
                                        char** peer_id) {
    if (session == NULL || is_established == NULL || peer_id == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    *is_established = session->is_established;
    
    if (session->peer_id != NULL) {
        *peer_id = himitsu_secure_strdup(session->peer_id);
        if (*peer_id == NULL) {
            return HIMITSU_ERROR_MEMORY_ALLOCATION;
        }
    } else {
        *peer_id = NULL;
    }
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_session_encrypt_message(himitsu_session_t* session,
                                               const char* plaintext,
                                               char** ciphertext) {
    if (session == NULL || plaintext == NULL || ciphertext == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    if (!session->is_established) {
        return HIMITSU_ERROR_HANDSHAKE_FAILED;
    }
    
    return himitsu_encrypt_payload(plaintext, session->peer_public_key, ciphertext);
}

himitsu_error_t himitsu_session_decrypt_message(himitsu_session_t* session,
                                               const char* ciphertext,
                                               char** plaintext) {
    if (session == NULL || ciphertext == NULL || plaintext == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    if (!session->is_established) {
        return HIMITSU_ERROR_HANDSHAKE_FAILED;
    }
    
    return himitsu_decrypt_payload(ciphertext, session->local_keypair.private_key, plaintext);
}

/* Internal helper function implementations */

static himitsu_error_t create_challenge_data(const char* epoch_key, 
                                            const char* shared_secret,
                                            uint64_t timestamp,
                                            uint32_t nonce,
                                            char** challenge_data) {
    if (epoch_key == NULL || shared_secret == NULL || challenge_data == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Create a hash of the shared secret for inclusion (don't include raw secret)
    char* secret_hash = NULL;
    himitsu_error_t result = himitsu_hash_message(shared_secret, &secret_hash);
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Format: epoch_key|secret_hash|timestamp|nonce
    size_t max_len = strlen(epoch_key) + strlen(secret_hash) + 50; // 50 for numbers and separators
    *challenge_data = himitsu_secure_malloc(max_len);
    if (*challenge_data == NULL) {
        himitsu_secure_strfree(secret_hash);
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    snprintf(*challenge_data, max_len, "%s|%s|%llu|%u", 
             epoch_key, secret_hash, (unsigned long long)timestamp, nonce);
    
    himitsu_secure_strfree(secret_hash);
    return HIMITSU_SUCCESS;
}

static himitsu_error_t parse_challenge_data(const char* challenge,
                                           char** epoch_key,
                                           char** shared_secret_hash,
                                           uint64_t* timestamp,
                                           uint32_t* nonce) {
    if (challenge == NULL || epoch_key == NULL || shared_secret_hash == NULL || 
        timestamp == NULL || nonce == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    char* challenge_copy = himitsu_secure_malloc(strlen(challenge) + 1);
    if (challenge_copy == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    strcpy(challenge_copy, challenge);
    
    // Parse format: epoch_key|secret_hash|timestamp|nonce
    char* token1 = strtok(challenge_copy, "|");
    char* token2 = strtok(NULL, "|");
    char* token3 = strtok(NULL, "|");
    char* token4 = strtok(NULL, "|");
    
    if (token1 == NULL || token2 == NULL || token3 == NULL || token4 == NULL) {
        himitsu_secure_strfree(challenge_copy);
        return HIMITSU_ERROR_VERIFICATION_FAILED;
    }
    
    *epoch_key = himitsu_secure_strdup(token1);
    *shared_secret_hash = himitsu_secure_strdup(token2);
    *timestamp = strtoull(token3, NULL, 10);
    *nonce = strtoul(token4, NULL, 10);
    
    himitsu_secure_strfree(challenge_copy);
    
    if (*epoch_key == NULL || *shared_secret_hash == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    return HIMITSU_SUCCESS;
}
