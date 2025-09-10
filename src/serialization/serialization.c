/**
 * @file serialization.c
 * @brief Lightweight JSON serialization engine for libhimitsu
 * 
 * Implements memory-efficient JSON parsing and generation specifically
 * for Himitsu message formats with newline-delimited JSON support.
 */

#include <himitsu/serialization.h>
#include <himitsu/types.h>
#include <himitsu/utils.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Internal helper functions */
static char* json_unescape_string(const char* str, size_t len);
static himitsu_error_t parse_json_field(const char* json, const char* field_name, char** value);
static himitsu_error_t validate_json_structure(const char* json);
static size_t calculate_serialized_size(const himitsu_message_t* message);

himitsu_error_t himitsu_serialize_message(const himitsu_message_t* message,
                                         char** json_string) {
    if (message == NULL || json_string == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Calculate required buffer size
    size_t buffer_size = calculate_serialized_size(message);
    if (buffer_size == 0) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    *json_string = himitsu_secure_malloc(buffer_size);
    if (*json_string == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    

    int written = snprintf(*json_string, buffer_size,
        "{"
        "\"type\":%s%s%s,"
        "\"to\":%s%s%s,"
        "\"from\":%s%s%s,"
        "\"payload\":%s%s%s,"
        "\"signature\":%s%s%s,"
        "\"timestamp\":%s%s%s,"
        "\"message_id\":%s%s%s"
        "}",
        message->type ? "\"" : "null",
        message->type ? message->type : "",
        message->type ? "\"" : "",
        message->to ? "\"" : "null",
        message->to ? message->to : "",
        message->to ? "\"" : "",
        message->from ? "\"" : "null",
        message->from ? message->from : "",
        message->from ? "\"" : "",
        message->payload ? "\"" : "null",
        message->payload ? message->payload : "",
        message->payload ? "\"" : "",
        message->signature ? "\"" : "null",
        message->signature ? message->signature : "",
        message->signature ? "\"" : "",
        message->timestamp ? "\"" : "null",
        message->timestamp ? message->timestamp : "",
        message->timestamp ? "\"" : "",
        message->message_id ? "\"" : "null",
        message->message_id ? message->message_id : "",
        message->message_id ? "\"" : ""
    );
    
    // Check for buffer overflow
    if (written >= (int)buffer_size) {
        himitsu_secure_strfree(*json_string);
        *json_string = NULL;
        return HIMITSU_ERROR_BUFFER_TOO_SMALL;
    }
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_deserialize_message(const char* json_string,
                                           himitsu_message_t** message) {
    if (json_string == NULL || message == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Validate JSON structure
    himitsu_error_t result = validate_json_structure(json_string);
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Create message structure
    result = himitsu_message_create(message);
    if (result != HIMITSU_SUCCESS) {
        return result;
    }
    
    // Parse each field
    char* field_value = NULL;
    
    result = parse_json_field(json_string, "type", &field_value);
    if (result == HIMITSU_SUCCESS && field_value != NULL) {
        (*message)->type = field_value;
        field_value = NULL;
    }
    
    result = parse_json_field(json_string, "to", &field_value);
    if (result == HIMITSU_SUCCESS && field_value != NULL) {
        (*message)->to = field_value;
        field_value = NULL;
    }
    
    result = parse_json_field(json_string, "from", &field_value);
    if (result == HIMITSU_SUCCESS && field_value != NULL) {
        (*message)->from = field_value;
        field_value = NULL;
    }
    
    result = parse_json_field(json_string, "payload", &field_value);
    if (result == HIMITSU_SUCCESS && field_value != NULL) {
        (*message)->payload = field_value;
        field_value = NULL;
    }
    
    result = parse_json_field(json_string, "signature", &field_value);
    if (result == HIMITSU_SUCCESS && field_value != NULL) {
        (*message)->signature = field_value;
        field_value = NULL;
    }
    
    result = parse_json_field(json_string, "timestamp", &field_value);
    if (result == HIMITSU_SUCCESS && field_value != NULL) {
        (*message)->timestamp = field_value;
        field_value = NULL;
    }
    
    result = parse_json_field(json_string, "message_id", &field_value);
    if (result == HIMITSU_SUCCESS && field_value != NULL) {
        (*message)->message_id = field_value;
        field_value = NULL;
    }
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_message_create(himitsu_message_t** message) {
    if (message == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    *message = himitsu_secure_malloc(sizeof(himitsu_message_t));
    if (*message == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    // Initialize all fields to NULL
    (*message)->type = NULL;
    (*message)->to = NULL;
    (*message)->from = NULL;
    (*message)->payload = NULL;
    (*message)->signature = NULL;
    (*message)->timestamp = NULL;
    (*message)->message_id = NULL;
    
    return HIMITSU_SUCCESS;
}

void himitsu_message_free(himitsu_message_t* message) {
    if (message == NULL) {
        return;
    }
    
    // Free all string fields
    if (message->type) {
        himitsu_secure_free(message->type, strlen(message->type));
    }
    if (message->to) {
        himitsu_secure_free(message->to, strlen(message->to));
    }
    if (message->from) {
        himitsu_secure_free(message->from, strlen(message->from));
    }
    if (message->payload) {
        himitsu_secure_free(message->payload, strlen(message->payload));
    }
    if (message->signature) {
        himitsu_secure_free(message->signature, strlen(message->signature));
    }
    if (message->timestamp) {
        himitsu_secure_free(message->timestamp, strlen(message->timestamp));
    }
    if (message->message_id) {
        himitsu_secure_free(message->message_id, strlen(message->message_id));
    }
    
    // Free the message structure itself
    himitsu_secure_free(message, sizeof(himitsu_message_t));
}

himitsu_error_t himitsu_message_set_field(himitsu_message_t* message,
                                         const char* field,
                                         const char* value) {
    if (message == NULL || field == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    char** target_field = NULL;
    
    // Find the target field
    if (strcmp(field, "type") == 0) {
        target_field = &message->type;
    } else if (strcmp(field, "to") == 0) {
        target_field = &message->to;
    } else if (strcmp(field, "from") == 0) {
        target_field = &message->from;
    } else if (strcmp(field, "payload") == 0) {
        target_field = &message->payload;
    } else if (strcmp(field, "signature") == 0) {
        target_field = &message->signature;
    } else if (strcmp(field, "timestamp") == 0) {
        target_field = &message->timestamp;
    } else if (strcmp(field, "message_id") == 0) {
        target_field = &message->message_id;
    } else {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Free existing value if any
    if (*target_field != NULL) {
        himitsu_secure_free(*target_field, strlen(*target_field));
        *target_field = NULL;
    }
    
    // Set new value
    if (value != NULL) {
        *target_field = himitsu_secure_strdup(value);
        if (*target_field == NULL) {
            return HIMITSU_ERROR_MEMORY_ALLOCATION;
        }
    }
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_message_get_field(const himitsu_message_t* message,
                                         const char* field,
                                         const char** value) {
    if (message == NULL || field == NULL || value == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    // Find and return the field value
    if (strcmp(field, "type") == 0) {
        *value = message->type;
    } else if (strcmp(field, "to") == 0) {
        *value = message->to;
    } else if (strcmp(field, "from") == 0) {
        *value = message->from;
    } else if (strcmp(field, "payload") == 0) {
        *value = message->payload;
    } else if (strcmp(field, "signature") == 0) {
        *value = message->signature;
    } else if (strcmp(field, "timestamp") == 0) {
        *value = message->timestamp;
    } else if (strcmp(field, "message_id") == 0) {
        *value = message->message_id;
    } else {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_message_validate(const himitsu_message_t* message) {
    if (message == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    if (message->type == NULL || strlen(message->type) == 0) {
        return HIMITSU_ERROR_INVALID_MESSAGE;
    }
    
    return HIMITSU_SUCCESS;
}

himitsu_error_t himitsu_parse_json_stream(const char* json_stream,
                                         himitsu_message_t*** messages,
                                         size_t* message_count) {
    if (json_stream == NULL || messages == NULL || message_count == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    *messages = NULL;
    *message_count = 0;
    
    return HIMITSU_ERROR_NOT_IMPLEMENTED;
}

void himitsu_message_destroy(himitsu_message_t* message) {
    if (message == NULL) return;
    
    if (message->type) himitsu_secure_strfree(message->type);
    if (message->to) himitsu_secure_strfree(message->to);
    if (message->from) himitsu_secure_strfree(message->from);
    if (message->payload) himitsu_secure_strfree(message->payload);
    if (message->signature) himitsu_secure_strfree(message->signature);
    if (message->timestamp) himitsu_secure_strfree(message->timestamp);
    if (message->message_id) himitsu_secure_strfree(message->message_id);
    
    himitsu_secure_free(message, sizeof(himitsu_message_t));
}

/* Helper function implementations */

static char* json_unescape_string(const char* str, size_t len) {
    if (str == NULL || len == 0) return NULL;
    
    char* unescaped = himitsu_secure_malloc(len + 1);
    if (unescaped == NULL) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '\\' && i + 1 < len) {
            switch (str[i + 1]) {
                case '"':
                    unescaped[j++] = '"';
                    i++;
                    break;
                case '\\':
                    unescaped[j++] = '\\';
                    i++;
                    break;
                case 'b':
                    unescaped[j++] = '\b';
                    i++;
                    break;
                case 'f':
                    unescaped[j++] = '\f';
                    i++;
                    break;
                case 'n':
                    unescaped[j++] = '\n';
                    i++;
                    break;
                case 'r':
                    unescaped[j++] = '\r';
                    i++;
                    break;
                case 't':
                    unescaped[j++] = '\t';
                    i++;
                    break;
                default:
                    unescaped[j++] = str[i];
                    break;
            }
        } else {
            unescaped[j++] = str[i];
        }
    }
    unescaped[j] = '\0';
    
    return unescaped;
}

static himitsu_error_t parse_json_field(const char* json, const char* field_name, char** value) {
    if (json == NULL || field_name == NULL || value == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    
    *value = NULL;
    
    // Create search pattern: "field_name":
    size_t pattern_len = strlen(field_name) + 4; // "":
    char* pattern = malloc(pattern_len);
    if (pattern == NULL) return HIMITSU_ERROR_MEMORY_ALLOCATION;
    snprintf(pattern, pattern_len, "\"%s\":", field_name);
    
    // Find the field in JSON
    char* field_start = strstr(json, pattern);
    free(pattern);
    
    if (field_start == NULL) {
        return HIMITSU_SUCCESS; // Field not found, but that's okay
    }
    
    // Move past the field name and colon
    char* value_start = field_start + strlen(field_name) + 3;
    
    // Skip whitespace
    while (*value_start && isspace(*value_start)) {
        value_start++;
    }
    
    // Handle null values
    if (strncmp(value_start, "null", 4) == 0) {
        return HIMITSU_SUCCESS; // Null value, leave *value as NULL
    }
    
    // Expect string value starting with quote
    if (*value_start != '"') {
        return HIMITSU_ERROR_INVALID_MESSAGE;
    }
    
    value_start++; // Skip opening quote
    
    // Find closing quote
    char* value_end = value_start;
    while (*value_end && *value_end != '"') {
        if (*value_end == '\\' && *(value_end + 1)) {
            value_end += 2; // Skip escaped character
        } else {
            value_end++;
        }
    }
    
    if (*value_end != '"') {
        return HIMITSU_ERROR_INVALID_MESSAGE;
    }
    
    // Extract and unescape the value
    size_t value_len = value_end - value_start;
    *value = json_unescape_string(value_start, value_len);
    if (*value == NULL) {
        return HIMITSU_ERROR_MEMORY_ALLOCATION;
    }
    
    return HIMITSU_SUCCESS;
}

static himitsu_error_t validate_json_structure(const char* json) {
    if (json == NULL) {
        return HIMITSU_ERROR_INVALID_PARAMETER;
    }
    

    size_t len = strlen(json);
    if (len < 2) {
        return HIMITSU_ERROR_INVALID_MESSAGE;
    }
    
    // Should start with { and end with }
    if (json[0] != '{' || json[len - 1] != '}') {
        return HIMITSU_ERROR_INVALID_MESSAGE;
    }
    
    // Count braces to ensure they're balanced
    int brace_count = 0;
    for (size_t i = 0; i < len; i++) {
        if (json[i] == '{') brace_count++;
        if (json[i] == '}') brace_count--;
    }
    
    if (brace_count != 0) {
        return HIMITSU_ERROR_INVALID_MESSAGE;
    }
    
    return HIMITSU_SUCCESS;
}

static size_t calculate_serialized_size(const himitsu_message_t* message) {
    if (message == NULL) return 0;
    
    size_t size = 100; // Base JSON structure overhead
    
    // Add size for each field (with escaping overhead)
    if (message->type) size += strlen(message->type) * 2 + 20;
    if (message->to) size += strlen(message->to) * 2 + 20;
    if (message->from) size += strlen(message->from) * 2 + 20;
    if (message->payload) size += strlen(message->payload) * 2 + 20;
    if (message->signature) size += strlen(message->signature) * 2 + 20;
    if (message->timestamp) size += strlen(message->timestamp) * 2 + 20;
    if (message->message_id) size += strlen(message->message_id) * 2 + 20;
    
    return size;
}
