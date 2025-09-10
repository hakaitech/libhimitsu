/* 
 * libhimitsu Basic Usage Example
 * 
 * This example demonstrates fundamental operations:
 * - Library initialization
 * - Key generation
 * - Message creation and serialization
 * - Cryptographic operations
 * - Session management
 * - Memory cleanup
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <himitsu/himitsu.h>

void print_usage() {
    printf("Usage: basic_usage [demo|keygen|message|session]\n");
    printf("  demo    - Full workflow demonstration\n");
    printf("  keygen  - Generate and display keypair\n");
    printf("  message - Create and serialize message\n");
    printf("  session - Basic session management\n");
}

int demo_keygen() {
    printf("=== Key Generation Demo ===\n");
    
    char* public_key = NULL;
    char* private_key = NULL;
    
    himitsu_error_t result = himitsu_generate_keypair(&public_key, &private_key);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to generate keypair: %s\n", himitsu_error_string(result));
        return 1;
    }
    
    printf("Generated ECDH P-256 Keypair:\n");
    printf("Public Key:  %s\n", public_key);
    printf("Private Key: %s\n", private_key);
    
    // Secure cleanup
    free(public_key);
    free(private_key);
    
    return 0;
}
int demo_message() {
    printf("=== Message Serialization Demo ===\n");
    
    // Create message
    himitsu_message_t* message = NULL;
    himitsu_error_t result = himitsu_message_create(&message);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to create message: %s\n", himitsu_error_string(result));
        return 1;
    }
    
    // Populate message fields
    himitsu_message_set_field(message, "type", "text");
    himitsu_message_set_field(message, "from", "alice@example.com");
    himitsu_message_set_field(message, "to", "bob@example.com");
    himitsu_message_set_field(message, "payload", "Hello, Bob! This is a secure message.");
    himitsu_message_set_field(message, "timestamp", "2024-01-15T10:30:00Z");
    himitsu_message_set_field(message, "message_id", "msg_001");
    
    const char* type_val, *from_val, *to_val, *payload_val;
    himitsu_message_get_field(message, "type", &type_val);
    himitsu_message_get_field(message, "from", &from_val);
    himitsu_message_get_field(message, "to", &to_val);
    himitsu_message_get_field(message, "payload", &payload_val);
    
    printf("Created message:\n");
    printf("  Type: %s\n", type_val);
    printf("  From: %s\n", from_val);
    printf("  To: %s\n", to_val);
    printf("  Payload: %s\n", payload_val);
    
    // Serialize to JSON
    char* json_string = NULL;
    result = himitsu_serialize_message(message, &json_string);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to serialize message: %s\n", himitsu_error_string(result));
        himitsu_message_destroy(message);
        return 1;
    }
    
    printf("\nSerialized JSON:\n%s\n", json_string);
    
    // Parse JSON back to message
    himitsu_message_t* parsed_message = NULL;
    result = himitsu_deserialize_message(json_string, &parsed_message);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to deserialize message: %s\n", himitsu_error_string(result));
        free(json_string);
        himitsu_message_destroy(message);
        return 1;
    }
    
    const char* parsed_type, *parsed_from, *parsed_payload;
    himitsu_message_get_field(parsed_message, "type", &parsed_type);
    himitsu_message_get_field(parsed_message, "from", &parsed_from);
    himitsu_message_get_field(parsed_message, "payload", &parsed_payload);
    
    printf("\nParsed message:\n");
    printf("  Type: %s\n", parsed_type);
    printf("  From: %s\n", parsed_from);
    printf("  Payload: %s\n", parsed_payload);
    
    // Cleanup
    free(json_string);
    himitsu_message_destroy(message);
    himitsu_message_destroy(parsed_message);
    
    return 0;
}

int demo_session() {
    printf("=== Session Management Demo ===\n");
    
    // Generate keypair for session
    char* public_key = NULL;
    char* private_key = NULL;
    himitsu_error_t result = himitsu_generate_keypair(&public_key, &private_key);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to generate session keypair: %s\n", himitsu_error_string(result));
        return 1;
    }
    
    // Create keypair structure
    himitsu_keypair_t keypair;
    keypair.public_key = public_key;
    keypair.private_key = private_key;
    
    // Create session
    himitsu_session_t* session = NULL;
    result = himitsu_session_create(&session, &keypair);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to create session: %s\n", himitsu_error_string(result));
        free(public_key);
        free(private_key);
        return 1;
    }
    
    printf("Session created successfully\n");
    
    // Get session info
    int is_established = 0;
    char* peer_id = NULL;
    result = himitsu_session_get_info(session, &is_established, &peer_id);
    if (result == HIMITSU_SUCCESS) {
        printf("Session established: %s\n", is_established ? "Yes" : "No");
        if (peer_id) {
            printf("Peer ID: %s\n", peer_id);
            free(peer_id);
        }
    }
    
    // Cleanup
    himitsu_session_destroy(session);
    free(public_key);
    free(private_key);
    
    return 0;
}

int demo_crypto() {
    printf("=== Cryptographic Operations Demo ===\n");
    
    const char* test_message = "This is a test message for hashing and HMAC";
    const char* secret_key = "super_secret_key_123";
    
    // Hash the message
    char* hash = NULL;
    himitsu_error_t result = himitsu_hash_message(test_message, &hash);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to hash message: %s\n", himitsu_error_string(result));
        return 1;
    }
    
    printf("Message: %s\n", test_message);
    printf("SHA-256: %s\n", hash);
    
    // Generate HMAC
    char* hmac = NULL;
    result = himitsu_generate_hmac(test_message, secret_key, &hmac);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to generate HMAC: %s\n", himitsu_error_string(result));
        free(hash);
        return 1;
    }
    
    printf("HMAC-SHA256: %s\n", hmac);
    
    // Verify HMAC
    result = himitsu_verify_hmac(test_message, secret_key, hmac);
    if (result == HIMITSU_SUCCESS) {
        printf("HMAC verification: ✓ SUCCESS\n");
    } else {
        printf("HMAC verification: ✗ FAILED (%s)\n", himitsu_error_string(result));
    }
    
    // Test with wrong HMAC
    result = himitsu_verify_hmac(test_message, secret_key, "wrong_hmac_value");
    if (result == HIMITSU_ERROR_VERIFICATION_FAILED) {
        printf("Wrong HMAC rejection: ✓ SUCCESS\n");
    } else {
        printf("Wrong HMAC rejection: ✗ FAILED (should have been rejected)\n");
    }
    
    // Cleanup
    free(hash);
    free(hmac);
    
    return 0;
}

int demo_handshake() {
    printf("=== Handshake Protocol Demo ===\n");
    
    const char* epoch_key = "epoch_2024_q1";
    const char* shared_secret = "node_pair_secret_key";
    
    // Create handshake challenge
    char* challenge = NULL;
    himitsu_error_t result = himitsu_create_handshake_challenge(epoch_key, shared_secret, &challenge);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to create handshake challenge: %s\n", himitsu_error_string(result));
        return 1;
    }
    
    printf("Epoch Key: %s\n", epoch_key);
    printf("Challenge (first 80 chars): %.80s...\n", challenge);
    
    // Verify the challenge
    result = himitsu_verify_handshake_challenge(challenge, epoch_key, shared_secret);
    if (result == HIMITSU_SUCCESS) {
        printf("Challenge verification: ✓ SUCCESS\n");
    } else {
        printf("Challenge verification: ✗ FAILED (%s)\n", himitsu_error_string(result));
    }
    
    // Test with wrong epoch key
    result = himitsu_verify_handshake_challenge(challenge, "wrong_epoch", shared_secret);
    if (result == HIMITSU_ERROR_VERIFICATION_FAILED) {
        printf("Wrong epoch rejection: ✓ SUCCESS\n");
    } else {
        printf("Wrong epoch rejection: ✗ FAILED (should have been rejected)\n");
    }
    
    // Cleanup
    free(challenge);
    
    return 0;
}

int demo_full_workflow() {
    printf("=== Full Workflow Demo ===\n");
    printf("This demonstrates a complete secure communication workflow.\n\n");
    
    int result = 0;
    
    // Run all sub-demos
    result |= demo_keygen();
    printf("\n");
    
    result |= demo_crypto();
    printf("\n");
    
    result |= demo_handshake();
    printf("\n");
    
    result |= demo_message();
    printf("\n");
    
    result |= demo_session();
    printf("\n");
    
    if (result == 0) {
        printf("✓ All demos completed successfully!\n");
    } else {
        printf("✗ Some demos failed. Check output above.\n");
    }
    
    return result;
}

int main(int argc, char* argv[]) {
    // Initialize library
    himitsu_error_t result = himitsu_init();
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to initialize libhimitsu: %s\n", himitsu_error_string(result));
        return 1;
    }
    
    printf("libhimitsu version: %s\n", himitsu_version());
    printf("Initialization: ✓ SUCCESS\n\n");
    
    int exit_code = 0;
    
    if (argc < 2) {
        exit_code = demo_full_workflow();
    } else if (strcmp(argv[1], "demo") == 0) {
        exit_code = demo_full_workflow();
    } else if (strcmp(argv[1], "keygen") == 0) {
        exit_code = demo_keygen();
    } else if (strcmp(argv[1], "message") == 0) {
        exit_code = demo_message();
    } else if (strcmp(argv[1], "session") == 0) {
        exit_code = demo_session();
    } else if (strcmp(argv[1], "crypto") == 0) {
        exit_code = demo_crypto();
    } else if (strcmp(argv[1], "handshake") == 0) {
        exit_code = demo_handshake();
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", argv[1]);
        print_usage();
        exit_code = 1;
    }
    
    // Cleanup library
    himitsu_cleanup();
    
    return exit_code;
}
