/**
 * @file test_serialization.c
 * @brief Comprehensive serialization tests for libhimitsu Phase 4
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <himitsu/himitsu.h>
#include <himitsu/serialization.h>
#include <himitsu/types.h>
#include <himitsu/utils.h>

void test_message_creation() {
    printf("Testing message creation and field setting...\n");
    
    himitsu_error_t result = himitsu_init();
    assert(result == HIMITSU_SUCCESS);
    
    himitsu_message_t* message = NULL;
    result = himitsu_message_create(&message);
    assert(result == HIMITSU_SUCCESS);
    assert(message != NULL);
    
    // Set fields
    result = himitsu_message_set_field(message, "type", "text");
    assert(result == HIMITSU_SUCCESS);
    
    result = himitsu_message_set_field(message, "from", "alice");
    assert(result == HIMITSU_SUCCESS);
    
    result = himitsu_message_set_field(message, "to", "bob");
    assert(result == HIMITSU_SUCCESS);
    
    result = himitsu_message_set_field(message, "payload", "Hello, Bob!");
    assert(result == HIMITSU_SUCCESS);
    
    // Get fields back
    const char* field_value = NULL;
    result = himitsu_message_get_field(message, "type", &field_value);
    assert(result == HIMITSU_SUCCESS);
    assert(field_value != NULL);
    assert(strcmp(field_value, "text") == 0);
    
    result = himitsu_message_get_field(message, "from", &field_value);
    assert(result == HIMITSU_SUCCESS);
    assert(strcmp(field_value, "alice") == 0);
    
    printf("  ✓ Message created and fields set successfully\n");
    printf("  ✓ Type: %s, From: %s, To: %s\n", message->type, message->from, message->to);
    
    himitsu_message_destroy(message);
    himitsu_cleanup();
    printf("  ✓ Message creation test passed\n");
}

void test_message_serialization() {
    printf("Testing JSON message serialization...\n");
    
    himitsu_error_t result = himitsu_init();
    assert(result == HIMITSU_SUCCESS);
    
    // Create a test message
    himitsu_message_t* message = NULL;
    result = himitsu_message_create(&message);
    assert(result == HIMITSU_SUCCESS);
    
    // Set all fields
    message->type = himitsu_secure_strdup("handshake");
    message->from = himitsu_secure_strdup("node_alice");
    message->to = himitsu_secure_strdup("node_bob");
    message->payload = himitsu_secure_strdup("challenge_data_here");
    message->signature = himitsu_secure_strdup("hmac_signature_123");
    message->timestamp = himitsu_secure_strdup("2024-01-10T15:30:00Z");
    message->message_id = himitsu_secure_strdup("msg_001");
    
    // Serialize to JSON
    char* json_string = NULL;
    result = himitsu_serialize_message(message, &json_string);
    assert(result == HIMITSU_SUCCESS);
    assert(json_string != NULL);
    assert(strlen(json_string) > 0);
    
    printf("  ✓ Serialized JSON: %s\n", json_string);
    
    // Check that JSON contains expected fields
    assert(strstr(json_string, "\"type\":\"handshake\"") != NULL);
    assert(strstr(json_string, "\"from\":\"node_alice\"") != NULL);
    assert(strstr(json_string, "\"to\":\"node_bob\"") != NULL);
    assert(strstr(json_string, "\"payload\":\"challenge_data_here\"") != NULL);
    
    printf("  ✓ JSON contains all expected fields\n");
    
    himitsu_secure_strfree(json_string);
    himitsu_message_destroy(message);
    himitsu_cleanup();
    printf("  ✓ Message serialization test passed\n");
}

void test_message_deserialization() {
    printf("Testing JSON message deserialization...\n");
    
    himitsu_error_t result = himitsu_init();
    assert(result == HIMITSU_SUCCESS);
    
    // Test JSON string
    const char* test_json = "{"
        "\"type\":\"response\","
        "\"from\":\"server\","
        "\"to\":\"client\","
        "\"payload\":\"success\","
        "\"signature\":\"abc123\","
        "\"timestamp\":\"2024-01-10T16:00:00Z\","
        "\"message_id\":\"resp_001\""
        "}";
    
    // Deserialize from JSON
    himitsu_message_t* message = NULL;
    result = himitsu_deserialize_message(test_json, &message);
    assert(result == HIMITSU_SUCCESS);
    assert(message != NULL);
    
    // Verify deserialized fields
    assert(message->type != NULL);
    assert(strcmp(message->type, "response") == 0);
    
    assert(message->from != NULL);
    assert(strcmp(message->from, "server") == 0);
    
    assert(message->to != NULL);
    assert(strcmp(message->to, "client") == 0);
    
    assert(message->payload != NULL);
    assert(strcmp(message->payload, "success") == 0);
    
    printf("  ✓ Parsed Type: %s\n", message->type);
    printf("  ✓ Parsed From: %s\n", message->from);
    printf("  ✓ Parsed To: %s\n", message->to);
    printf("  ✓ Parsed Payload: %s\n", message->payload);
    
    himitsu_message_destroy(message);
    himitsu_cleanup();
    printf("  ✓ Message deserialization test passed\n");
}

void test_round_trip_serialization() {
    printf("Testing round-trip serialization (serialize -> deserialize)...\n");
    
    himitsu_error_t result = himitsu_init();
    assert(result == HIMITSU_SUCCESS);
    
    // Create original message
    himitsu_message_t* original = NULL;
    result = himitsu_message_create(&original);
    assert(result == HIMITSU_SUCCESS);
    
    original->type = himitsu_secure_strdup("test");
    original->from = himitsu_secure_strdup("sender");
    original->to = himitsu_secure_strdup("receiver");
    original->payload = himitsu_secure_strdup("test payload");
    
    // Serialize
    char* json = NULL;
    result = himitsu_serialize_message(original, &json);
    assert(result == HIMITSU_SUCCESS);
    assert(json != NULL);
    
    // Deserialize
    himitsu_message_t* deserialized = NULL;
    result = himitsu_deserialize_message(json, &deserialized);
    assert(result == HIMITSU_SUCCESS);
    assert(deserialized != NULL);
    
    // Compare original and deserialized
    assert(strcmp(original->type, deserialized->type) == 0);
    assert(strcmp(original->from, deserialized->from) == 0);
    assert(strcmp(original->to, deserialized->to) == 0);
    assert(strcmp(original->payload, deserialized->payload) == 0);
    
    printf("  ✓ Round-trip successful: all fields match\n");
    
    himitsu_secure_strfree(json);
    himitsu_message_destroy(original);
    himitsu_message_destroy(deserialized);
    himitsu_cleanup();
    printf("  ✓ Round-trip serialization test passed\n");
}

void test_null_field_handling() {
    printf("Testing null field handling in serialization...\n");
    
    himitsu_error_t result = himitsu_init();
    assert(result == HIMITSU_SUCCESS);
    
    // Create message with some null fields
    himitsu_message_t* message = NULL;
    result = himitsu_message_create(&message);
    assert(result == HIMITSU_SUCCESS);
    
    message->type = himitsu_secure_strdup("minimal");
    message->from = himitsu_secure_strdup("test");
    // Leave other fields as NULL
    
    // Serialize
    char* json = NULL;
    result = himitsu_serialize_message(message, &json);
    assert(result == HIMITSU_SUCCESS);
    assert(json != NULL);
    
    printf("  ✓ JSON with nulls: %s\n", json);
    
    // Should contain null values for unset fields
    assert(strstr(json, "\"type\":\"minimal\"") != NULL);
    assert(strstr(json, "\"from\":\"test\"") != NULL);
    assert(strstr(json, "null") != NULL); // Should have null values
    
    himitsu_secure_strfree(json);
    himitsu_message_destroy(message);
    himitsu_cleanup();
    printf("  ✓ Null field handling test passed\n");
}

void test_error_handling() {
    printf("Testing serialization error handling...\n");
    
    himitsu_error_t result = himitsu_init();
    assert(result == HIMITSU_SUCCESS);
    
    char* json = NULL;
    himitsu_message_t* message = NULL;
    
    // Test null parameters
    result = himitsu_serialize_message(NULL, &json);
    assert(result == HIMITSU_ERROR_INVALID_PARAMETER);
    
    result = himitsu_deserialize_message(NULL, &message);
    assert(result == HIMITSU_ERROR_INVALID_PARAMETER);
    
    result = himitsu_deserialize_message("{}", NULL);
    assert(result == HIMITSU_ERROR_INVALID_PARAMETER);
    
    // Test malformed JSON
    result = himitsu_deserialize_message("{invalid json", &message);
    assert(result == HIMITSU_ERROR_INVALID_MESSAGE);
    
    result = himitsu_deserialize_message("not json at all", &message);
    assert(result == HIMITSU_ERROR_INVALID_MESSAGE);
    
    printf("  ✓ NULL parameter checks working\n");
    printf("  ✓ Malformed JSON correctly rejected\n");
    
    himitsu_cleanup();
    printf("  ✓ Error handling test passed\n");
}

int main() {
    printf("=== libhimitsu Serialization Test Suite (Phase 4) ===\n\n");
    
    test_message_creation();
    printf("\n");
    
    test_message_serialization();
    printf("\n");
    
    test_message_deserialization();
    printf("\n");
    
    test_round_trip_serialization();
    printf("\n");
    
    test_null_field_handling();
    printf("\n");
    
    test_error_handling();
    printf("\n");
    
    printf("All serialization tests passed!\n");
    printf("Phase 4 (Serialization Module) is complete!\n");
    
    return 0;
}
