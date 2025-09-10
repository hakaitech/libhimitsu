#ifndef HIMITSU_SERIALIZATION_H
#define HIMITSU_SERIALIZATION_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Serialize a message structure to JSON string
 * 
 * @param message Message structure to serialize
 * @param json_string Output JSON string (caller must free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_serialize_message(const himitsu_message_t* message,
                                         char** json_string);

/**
 * @brief Deserialize a JSON string to message structure
 * 
 * @param json_string Input JSON string
 * @param message Output message structure (caller must free with himitsu_message_free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_deserialize_message(const char* json_string,
                                           himitsu_message_t** message);

/**
 * @brief Create a new message structure
 * 
 * @param message Output message structure (caller must free with himitsu_message_free)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_message_create(himitsu_message_t** message);

/**
 * @brief Free a message structure and all its fields
 * 
 * @param message Message to free
 */
void himitsu_message_free(himitsu_message_t* message);

/**
 * @brief Set a field in the message structure
 * 
 * @param message Message structure
 * @param field Field name ("type", "to", "from", "payload", etc.)
 * @param value Field value (will be copied)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_message_set_field(himitsu_message_t* message,
                                         const char* field,
                                         const char* value);

/**
 * @brief Get a field from the message structure
 * 
 * @param message Message structure
 * @param field Field name
 * @param value Output field value (do not free - points to internal data)
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_message_get_field(const himitsu_message_t* message,
                                         const char* field,
                                         const char** value);

/**
 * @brief Validate message structure
 * 
 * @param message Message to validate
 * @return himitsu_error_t HIMITSU_SUCCESS if valid, error code otherwise
 */
himitsu_error_t himitsu_message_validate(const himitsu_message_t* message);

/**
 * @brief Destroy message and free all associated memory
 * 
 * @param message Message to destroy
 */
void himitsu_message_destroy(himitsu_message_t* message);

/**
 * @brief Parse newline-delimited JSON stream
 * 
 * @param json_stream Input JSON stream
 * @param messages Output array of messages (caller must free each message and array)
 * @param message_count Output number of messages parsed
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_parse_json_stream(const char* json_stream,
                                         himitsu_message_t*** messages,
                                         size_t* message_count);

#ifdef __cplusplus
}
#endif

#endif /* HIMITSU_SERIALIZATION_H */
