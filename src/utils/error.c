/**
 * @file error.c  
 * @brief Error handling utilities for libhimitsu
 */

#include <himitsu/utils.h>

const char* himitsu_error_string(himitsu_error_t error) {
    switch (error) {
        case HIMITSU_SUCCESS:
            return "Success";
        case HIMITSU_ERROR_INVALID_PARAMETER:
            return "Invalid parameter";
        case HIMITSU_ERROR_MEMORY_ALLOCATION:
            return "Memory allocation failed";
        case HIMITSU_ERROR_CRYPTO_FAILURE:
            return "Cryptographic operation failed";
        case HIMITSU_ERROR_PROTOCOL_VIOLATION:
            return "Protocol violation";
        case HIMITSU_ERROR_SERIALIZATION_FAILED:
            return "Serialization failed";
        case HIMITSU_ERROR_INVALID_MESSAGE:
            return "Invalid message format";
        case HIMITSU_ERROR_SESSION_NOT_FOUND:
            return "Session not found";
        case HIMITSU_ERROR_HANDSHAKE_FAILED:
            return "Handshake failed";
        case HIMITSU_ERROR_VERIFICATION_FAILED:
            return "Verification failed";
        case HIMITSU_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case HIMITSU_ERROR_NOT_IMPLEMENTED:
            return "Function not implemented";
        default:
            return "Unknown error";
    }
}
