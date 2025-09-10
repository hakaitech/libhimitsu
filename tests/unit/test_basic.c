/**
 * @file test_basic.c
 * @brief Basic functionality test for libhimitsu
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <himitsu/himitsu.h>

void test_library_init() {
    printf("Testing library initialization...\n");
    
    himitsu_error_t result = himitsu_init();
    assert(result == HIMITSU_SUCCESS);
    
    const char* version = himitsu_version();
    assert(version != NULL);
    printf("  Library version: %s\n", version);
    
    himitsu_cleanup();
    printf("  ✓ Library initialization test passed\n");
}

void test_error_strings() {
    printf("Testing error string conversion...\n");
    
    const char* success_str = himitsu_error_string(HIMITSU_SUCCESS);
    assert(success_str != NULL);
    printf("  Success: %s\n", success_str);
    
    const char* error_str = himitsu_error_string(HIMITSU_ERROR_INVALID_PARAMETER);
    assert(error_str != NULL);
    printf("  Invalid parameter: %s\n", error_str);
    
    printf("  ✓ Error string test passed\n");
}

void test_message_creation() {
    printf("Testing message creation...\n");
    
    himitsu_message_t* message = NULL;
    himitsu_error_t result = himitsu_message_create(&message);
    assert(result == HIMITSU_SUCCESS);
    assert(message != NULL);
    
    // Set some fields
    result = himitsu_message_set_field(message, "type", "test");
    assert(result == HIMITSU_SUCCESS);
    
    result = himitsu_message_set_field(message, "from", "test_sender");
    assert(result == HIMITSU_SUCCESS);
    
    // Get fields back
    const char* type = NULL;
    result = himitsu_message_get_field(message, "type", &type);
    assert(result == HIMITSU_SUCCESS);
    assert(type != NULL);
    printf("  Message type: %s\n", type);
    
    // Validate message
    result = himitsu_message_validate(message);
    assert(result == HIMITSU_SUCCESS);
    
    himitsu_message_free(message);
    printf("  ✓ Message creation test passed\n");
}

void test_key_generation() {
    printf("Testing key generation...\n");
    
    himitsu_error_t result = himitsu_init();
    assert(result == HIMITSU_SUCCESS);
    
    char* public_key = NULL;
    char* private_key = NULL;
    
    result = himitsu_generate_keypair(&public_key, &private_key);
    // Should return SUCCESS now that we have real implementation
    assert(result == HIMITSU_SUCCESS);
    assert(public_key != NULL);
    assert(private_key != NULL);
    
    // Keys should be non-empty
    assert(strlen(public_key) > 0);
    assert(strlen(private_key) > 0);
    
    printf("  Generated public key: %.30s...\n", public_key);
    printf("  Generated private key: %.30s...\n", private_key);
    
    free(public_key);
    free(private_key);
    
    himitsu_cleanup();
    printf("  ✓ Key generation test passed\n");
}

int main() {
    printf("=== libhimitsu Basic Test Suite ===\n\n");
    
    test_library_init();
    printf("\n");
    
    test_error_strings();
    printf("\n");
    
    test_message_creation();
    printf("\n");
    
    test_key_generation();
    printf("\n");
    
    printf("All basic tests passed!\n");
    printf("Note: Cryptographic module now has real implementations.\n");
    
    return 0;
}
