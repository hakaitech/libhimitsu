/*
 * Node Implementation Example for libhimitsu
 * 
 * This demonstrates a practical implementation of a Himitsu Protocol node
 * that can communicate with other nodes in a secure network.
 * 
 * Features demonstrated:
 * - Node configuration and initialization
 * - Network peer discovery and connection
 * - Secure handshake protocol
 * - Message encryption and transmission
 * - Session management
 * - Error handling and recovery
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <himitsu/himitsu.h>

// Node configuration structure
typedef struct {
    char* node_id;
    char* public_key;
    char* private_key;
    char* epoch_key;
    int port;
    int max_connections;
} himitsu_node_config_t;

// Network peer structure
typedef struct {
    char* peer_id;
    char* public_key;
    char* address;
    int port;
    himitsu_session_t* session;
    int is_connected;
    time_t last_seen;
} himitsu_peer_t;

// Node state structure
typedef struct {
    himitsu_node_config_t config;
    himitsu_peer_t* peers;
    int peer_count;
    int max_peers;
    int is_running;
} himitsu_node_t;

// Function prototypes
int node_init(himitsu_node_t* node, const char* node_id, int port);
void node_cleanup(himitsu_node_t* node);
int node_add_peer(himitsu_node_t* node, const char* peer_id, const char* address, int port);
int node_connect_to_peer(himitsu_node_t* node, const char* peer_id);
int node_send_message(himitsu_node_t* node, const char* peer_id, const char* message);
int node_broadcast_message(himitsu_node_t* node, const char* message);
void node_print_status(const himitsu_node_t* node);

// Utility function to generate current timestamp
char* get_current_timestamp() {
    time_t now;
    struct tm* tm_info;
    char* timestamp = malloc(32);
    
    time(&now);
    tm_info = gmtime(&now);
    
    strftime(timestamp, 32, "%Y-%m-%dT%H:%M:%SZ", tm_info);
    return timestamp;
}

// Initialize a node with basic configuration
int node_init(himitsu_node_t* node, const char* node_id, int port) {
    printf("=== Initializing Node '%s' ===\n", node_id);
    
    // Clear node structure
    memset(node, 0, sizeof(himitsu_node_t));
    
    // Set basic configuration
    node->config.node_id = strdup(node_id);
    node->config.port = port;
    node->config.max_connections = 10;
    node->max_peers = 20;
    node->peers = malloc(sizeof(himitsu_peer_t) * node->max_peers);
    
    // Generate node keypair
    himitsu_error_t result = himitsu_generate_keypair(&node->config.public_key, &node->config.private_key);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to generate node keypair: %s\n", himitsu_error_string(result));
        return -1;
    }
    
    // Set epoch key (in real implementation, this would be synchronized across network)
    node->config.epoch_key = strdup("network_epoch_2024_q4");
    
    printf("✓ Node initialized successfully\n");
    printf("  Node ID: %s\n", node->config.node_id);
    printf("  Port: %d\n", node->config.port);
    printf("  Public Key: %.40s...\n", node->config.public_key);
    
    return 0;
}

// Add a peer to the node's peer list
int node_add_peer(himitsu_node_t* node, const char* peer_id, const char* address, int port) {
    if (node->peer_count >= node->max_peers) {
        fprintf(stderr, "Maximum number of peers reached\n");
        return -1;
    }
    
    himitsu_peer_t* peer = &node->peers[node->peer_count];
    peer->peer_id = strdup(peer_id);
    peer->address = strdup(address);
    peer->port = port;
    peer->is_connected = 0;
    peer->session = NULL;
    peer->public_key = NULL;
    time(&peer->last_seen);
    
    node->peer_count++;
    
    printf("✓ Added peer '%s' at %s:%d\n", peer_id, address, port);
    return 0;
}

// Simulate connection to a peer (in real implementation, this would involve network I/O)
int node_connect_to_peer(himitsu_node_t* node, const char* peer_id) {
    printf("=== Connecting to Peer '%s' ===\n", peer_id);
    
    // Find peer in list
    himitsu_peer_t* peer = NULL;
    for (int i = 0; i < node->peer_count; i++) {
        if (strcmp(node->peers[i].peer_id, peer_id) == 0) {
            peer = &node->peers[i];
            break;
        }
    }
    
    if (!peer) {
        fprintf(stderr, "Peer '%s' not found in peer list\n", peer_id);
        return -1;
    }
    
    // Simulate peer public key exchange (in real implementation, this would be part of discovery)
    char* peer_public_key = NULL;
    char* peer_private_key = NULL;
    himitsu_error_t result = himitsu_generate_keypair(&peer_public_key, &peer_private_key);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to simulate peer keypair: %s\n", himitsu_error_string(result));
        return -1;
    }
    
    peer->public_key = peer_public_key;
    free(peer_private_key); // Peer keeps their private key
    
    // Create session for this peer
    himitsu_keypair_t node_keypair = {
        .public_key = node->config.public_key,
        .private_key = node->config.private_key
    };
    
    result = himitsu_session_create(&peer->session, &node_keypair);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to create session for peer '%s': %s\n", peer_id, himitsu_error_string(result));
        return -1;
    }
    
    // Perform handshake
    char* challenge = NULL;
    result = himitsu_create_handshake_challenge(node->config.epoch_key, 
                                               peer->public_key, &challenge);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to create handshake challenge: %s\n", himitsu_error_string(result));
        return -1;
    }
    
    // Verify handshake (simulate peer verification)
    result = himitsu_verify_handshake_challenge(challenge, node->config.epoch_key, 
                                               peer->public_key);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Handshake verification failed: %s\n", himitsu_error_string(result));
        free(challenge);
        return -1;
    }
    
    peer->is_connected = 1;
    time(&peer->last_seen);
    
    printf("✓ Successfully connected to peer '%s'\n", peer_id);
    printf("  Peer Public Key: %.40s...\n", peer->public_key);
    printf("  Handshake: SUCCESSFUL\n");
    
    free(challenge);
    return 0;
}

// Send a secure message to a specific peer
int node_send_message(himitsu_node_t* node, const char* peer_id, const char* message) {
    printf("=== Sending Message to '%s' ===\n", peer_id);
    
    // Find connected peer
    himitsu_peer_t* peer = NULL;
    for (int i = 0; i < node->peer_count; i++) {
        if (strcmp(node->peers[i].peer_id, peer_id) == 0 && node->peers[i].is_connected) {
            peer = &node->peers[i];
            break;
        }
    }
    
    if (!peer) {
        fprintf(stderr, "Connected peer '%s' not found\n", peer_id);
        return -1;
    }
    
    // Create message structure
    himitsu_message_t* msg = NULL;
    himitsu_error_t result = himitsu_message_create(&msg);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to create message: %s\n", himitsu_error_string(result));
        return -1;
    }
    
    // Set message fields
    msg->type = strdup("text");
    msg->from = strdup(node->config.node_id);
    msg->to = strdup(peer_id);
    msg->payload = strdup(message);
    msg->timestamp = get_current_timestamp();
    
    // Generate message ID
    char message_id[32];
    snprintf(message_id, sizeof(message_id), "msg_%ld_%d", time(NULL), rand() % 1000);
    msg->message_id = strdup(message_id);
    
    // Generate HMAC signature
    char* serialized_content = NULL;
    char temp_buffer[1024];
    snprintf(temp_buffer, sizeof(temp_buffer), "%s|%s|%s|%s|%s", 
             msg->type, msg->from, msg->to, msg->payload, msg->timestamp);
    
    result = himitsu_generate_hmac(temp_buffer, node->config.private_key, &msg->signature);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to generate message signature: %s\n", himitsu_error_string(result));
        himitsu_message_destroy(msg);
        return -1;
    }
    
    // Serialize message
    char* json_message = NULL;
    result = himitsu_serialize_message(msg, &json_message);
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to serialize message: %s\n", himitsu_error_string(result));
        himitsu_message_destroy(msg);
        return -1;
    }
    
    printf("✓ Message created and signed\n");
    printf("  Message ID: %s\n", msg->message_id);
    printf("  Content: %s\n", message);
    printf("  JSON Size: %zu bytes\n", strlen(json_message));
    
    // In a real implementation, this would send over network
    printf("✓ Message sent to peer '%s' (simulated)\n", peer_id);
    
    // Update peer last seen time
    time(&peer->last_seen);
    
    // Cleanup
    free(json_message);
    himitsu_message_destroy(msg);
    
    return 0;
}

// Broadcast a message to all connected peers
int node_broadcast_message(himitsu_node_t* node, const char* message) {
    printf("=== Broadcasting Message ===\n");
    printf("Message: %s\n", message);
    
    int sent_count = 0;
    for (int i = 0; i < node->peer_count; i++) {
        if (node->peers[i].is_connected) {
            if (node_send_message(node, node->peers[i].peer_id, message) == 0) {
                sent_count++;
            }
        }
    }
    
    printf("✓ Broadcast sent to %d peers\n", sent_count);
    return sent_count;
}

// Print current node status
void node_print_status(const himitsu_node_t* node) {
    printf("=== Node Status ===\n");
    printf("Node ID: %s\n", node->config.node_id);
    printf("Port: %d\n", node->config.port);
    printf("Peers: %d/%d\n", node->peer_count, node->max_peers);
    
    int connected_count = 0;
    for (int i = 0; i < node->peer_count; i++) {
        if (node->peers[i].is_connected) {
            connected_count++;
        }
    }
    
    printf("Connected Peers: %d\n", connected_count);
    
    if (node->peer_count > 0) {
        printf("\nPeer List:\n");
        for (int i = 0; i < node->peer_count; i++) {
            himitsu_peer_t* peer = &node->peers[i];
            printf("  %s - %s:%d [%s]\n", 
                   peer->peer_id, 
                   peer->address, 
                   peer->port,
                   peer->is_connected ? "CONNECTED" : "DISCONNECTED");
        }
    }
}

// Cleanup node resources
void node_cleanup(himitsu_node_t* node) {
    printf("=== Cleaning up Node '%s' ===\n", node->config.node_id);
    
    // Cleanup peers
    for (int i = 0; i < node->peer_count; i++) {
        himitsu_peer_t* peer = &node->peers[i];
        if (peer->session) {
            himitsu_session_destroy(peer->session);
        }
        free(peer->peer_id);
        free(peer->address);
        free(peer->public_key);
    }
    
    free(node->peers);
    
    // Cleanup configuration
    free(node->config.node_id);
    free(node->config.public_key);
    free(node->config.private_key);
    free(node->config.epoch_key);
    
    printf("✓ Node cleanup completed\n");
}

// Main demonstration function
int main(void) {
    printf("=== Himitsu Protocol Node Implementation Example ===\n\n");
    
    // Initialize libhimitsu
    himitsu_error_t result = himitsu_init();
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to initialize libhimitsu: %s\n", himitsu_error_string(result));
        return 1;
    }
    
    printf("libhimitsu version: %s\n\n", himitsu_version());
    
    // Create two nodes for demonstration
    himitsu_node_t alice_node, bob_node;
    
    // Initialize Alice's node
    if (node_init(&alice_node, "alice_node", 8080) != 0) {
        fprintf(stderr, "Failed to initialize Alice's node\n");
        return 1;
    }
    
    printf("\n");
    
    // Initialize Bob's node
    if (node_init(&bob_node, "bob_node", 8081) != 0) {
        fprintf(stderr, "Failed to initialize Bob's node\n");
        node_cleanup(&alice_node);
        return 1;
    }
    
    printf("\n");
    
    // Alice adds Bob as a peer
    node_add_peer(&alice_node, "bob_node", "127.0.0.1", 8081);
    
    // Bob adds Alice as a peer  
    node_add_peer(&bob_node, "alice_node", "127.0.0.1", 8080);
    
    printf("\n");
    
    // Establish connections
    if (node_connect_to_peer(&alice_node, "bob_node") != 0) {
        fprintf(stderr, "Failed to connect Alice to Bob\n");
        goto cleanup;
    }
    
    printf("\n");
    
    if (node_connect_to_peer(&bob_node, "alice_node") != 0) {
        fprintf(stderr, "Failed to connect Bob to Alice\n");
        goto cleanup;
    }
    
    printf("\n");
    
    // Show node status
    node_print_status(&alice_node);
    printf("\n");
    node_print_status(&bob_node);
    printf("\n");
    
    // Send messages between nodes
    node_send_message(&alice_node, "bob_node", "Hello Bob! This is Alice.");
    printf("\n");
    
    node_send_message(&bob_node, "alice_node", "Hi Alice! Bob here. Nice to meet you!");
    printf("\n");
    
    // Demonstrate broadcast (Alice adds Charlie as a peer for broadcast demo)
    node_add_peer(&alice_node, "charlie_node", "127.0.0.1", 8082);
    // Simulate Charlie connection (normally Charlie would connect back)
    printf("Simulating Charlie connection...\n");
    alice_node.peers[alice_node.peer_count-1].is_connected = 1;
    
    node_broadcast_message(&alice_node, "This is a broadcast message from Alice!");
    printf("\n");
    
    printf("=== Node Implementation Demo Completed Successfully! ===\n");
    
cleanup:
    // Cleanup resources
    node_cleanup(&alice_node);
    node_cleanup(&bob_node);
    himitsu_cleanup();
    
    return 0;
}
