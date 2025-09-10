#ifndef HIMITSU_TYPES_H
#define HIMITSU_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes for all libhimitsu operations */
typedef enum {
    HIMITSU_SUCCESS = 0,
    HIMITSU_ERROR_INVALID_PARAMETER,
    HIMITSU_ERROR_MEMORY_ALLOCATION,
    HIMITSU_ERROR_CRYPTO_FAILURE,
    HIMITSU_ERROR_PROTOCOL_VIOLATION,
    HIMITSU_ERROR_SERIALIZATION_FAILED,
    HIMITSU_ERROR_INVALID_MESSAGE,
    HIMITSU_ERROR_SESSION_NOT_FOUND,
    HIMITSU_ERROR_HANDSHAKE_FAILED,
    HIMITSU_ERROR_VERIFICATION_FAILED,
    HIMITSU_ERROR_BUFFER_TOO_SMALL,
    HIMITSU_ERROR_NOT_IMPLEMENTED
} himitsu_error_t;

/* Opaque structure for user session state */
typedef struct himitsu_session himitsu_session_t;

/* Standardized message structure */
typedef struct {
    char* type;
    char* to;
    char* from;
    char* payload;
    char* signature;
    /* Extensible - additional fields can be added */
    char* timestamp;
    char* message_id;
} himitsu_message_t;

/* Key pair structure */
typedef struct {
    char* public_key;
    char* private_key;
} himitsu_keypair_t;

/* Constants */
#define HIMITSU_MAX_KEY_SIZE 1024
#define HIMITSU_MAX_MESSAGE_SIZE 65536
#define HIMITSU_HASH_SIZE 32  /* SHA-256 */
#define HIMITSU_AES_KEY_SIZE 32  /* AES-256 */
#define HIMITSU_AES_IV_SIZE 12   /* GCM IV */
#define HIMITSU_AES_TAG_SIZE 16  /* GCM authentication tag */

#ifdef __cplusplus
}
#endif

#endif /* HIMITSU_TYPES_H */
