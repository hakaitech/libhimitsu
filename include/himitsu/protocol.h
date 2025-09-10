#ifndef HIMITSU_PROTOCOL_H
#define HIMITSU_PROTOCOL_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a handshake challenge based on epoch key and shared secret
 * 
 * @param epoch_key Current epoch key from the node
 * @param shared_secret Pairwise shared secret
 * @param challenge Output challenge string (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_create_handshake_challenge(const char* epoch_key,
                                                  const char* shared_secret,
                                                  char** challenge);

/**
 * @brief Verify a received handshake challenge
 * 
 * @param received_challenge Challenge received from peer
 * @param epoch_key Current epoch key
 * @param shared_secret Pairwise shared secret
 * @return himitsu_error_t HIMITSU_SUCCESS if valid, error code otherwise
 */
himitsu_error_t himitsu_verify_handshake_challenge(const char* received_challenge,
                                                  const char* epoch_key,
                                                  const char* shared_secret);

/**
 * @brief Initialize a new session
 * 
 * @param session Output session handle (caller must free with himitsu_session_destroy)
 * @param local_keypair Local key pair for this session
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_session_create(himitsu_session_t** session,
                                      const himitsu_keypair_t* local_keypair);

/**
 * @brief Destroy a session and free associated resources
 * 
 * @param session Session to destroy
 */
void himitsu_session_destroy(himitsu_session_t* session);

/**
 * @brief Perform handshake with a peer
 * 
 * @param session Session handle
 * @param peer_public_key Peer's public key
 * @param epoch_key Current epoch key from node
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_session_handshake(himitsu_session_t* session,
                                         const char* peer_public_key,
                                         const char* epoch_key);

/**
 * @brief Get session state information
 * 
 * @param session Session handle
 * @param is_established Output: whether handshake is complete
 * @param peer_id Output: peer identifier (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_session_get_info(const himitsu_session_t* session,
                                        int* is_established,
                                        char** peer_id);

/**
 * @brief Encrypt a message for this session
 * 
 * @param session Session handle
 * @param plaintext Message to encrypt
 * @param ciphertext Output encrypted message (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_session_encrypt_message(himitsu_session_t* session,
                                               const char* plaintext,
                                               char** ciphertext);

/**
 * @brief Decrypt a message for this session
 * 
 * @param session Session handle
 * @param ciphertext Encrypted message
 * @param plaintext Output decrypted message (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_session_decrypt_message(himitsu_session_t* session,
                                               const char* ciphertext,
                                               char** plaintext);

#ifdef __cplusplus
}
#endif

#endif /* HIMITSU_PROTOCOL_H */
