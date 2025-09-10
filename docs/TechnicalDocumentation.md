# libhimitsu Documentation

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [API Reference](#api-reference)
4. [Build Instructions](#build-instructions)
5. [Architecture](#architecture)
6. [Development Status](#development-status)

## Overview

libhimitsu is a C99 library implementing the Himitsu Protocol for secure node-to-node communication. It provides cryptographic primitives, protocol logic, and message serialization in a single, portable library.

### Key Features

- **ECDH P-256**: Elliptic curve key exchange for secure communication
- **AES-256-GCM**: Authenticated encryption with associated data
- **SHA-256 + HMAC**: Secure hashing and message authentication
- **JSON Serialization**: Lightweight message format processing
- **Node-Synchronized Handshake**: Custom protocol for node authentication
- **Cross-Platform**: Support for Linux, macOS, Windows, and embedded systems

## Getting Started

### Quick Build

```bash
git clone https://github.com/your-org/libhimitsu.git
cd libhimitsu/build
make -f Makefile.simple
```

### Basic Usage

```c
#include <himitsu/himitsu.h>

int main() {
    himitsu_error_t result = himitsu_init();
    if (result != HIMITSU_SUCCESS) {
        fprintf(stderr, "Failed to initialize libhimitsu\n");
        return 1;
    }
    
    char* public_key = NULL;
    char* private_key = NULL;
    result = himitsu_generate_keypair(&public_key, &private_key);
    
    if (result == HIMITSU_SUCCESS) {
        printf("Public key: %s\n", public_key);
        free(public_key);
        free(private_key);
    }
    
    himitsu_cleanup();
    return 0;
}
```

## API Reference

### Library Initialization

```c
himitsu_error_t himitsu_init(void);
void himitsu_cleanup(void);
const char* himitsu_version(void);
int himitsu_is_debug_build(void);
```

### Cryptographic Functions

#### Key Generation
```c
himitsu_error_t himitsu_generate_keypair(char** public_key, char** private_key);
```

#### Hashing
```c
himitsu_error_t himitsu_sha256(const uint8_t* data, size_t data_len, uint8_t* hash);
himitsu_error_t himitsu_hash_message(const char* message, char** hash_output);
```

#### HMAC
```c
himitsu_error_t himitsu_hmac_sha256(const uint8_t* key, size_t key_len,
                                   const uint8_t* data, size_t data_len,
                                   uint8_t* hmac);
himitsu_error_t himitsu_generate_hmac(const char* message, const char* key, char** hmac_output);
himitsu_error_t himitsu_verify_hmac(const char* message, const char* key, const char* expected_hmac);
```

#### Encryption
```c
himitsu_error_t himitsu_aes_gcm_encrypt(const uint8_t* key, const uint8_t* iv,
                                       const uint8_t* plaintext, size_t plaintext_len,
                                       uint8_t* ciphertext, uint8_t* tag);
himitsu_error_t himitsu_aes_gcm_decrypt(const uint8_t* key, const uint8_t* iv,
                                       const uint8_t* ciphertext, size_t ciphertext_len,
                                       const uint8_t* tag, uint8_t* plaintext);
```

### Protocol Functions

#### Handshake Protocol
```c
himitsu_error_t himitsu_create_handshake_challenge(const char* epoch_key,
                                                  const char* shared_secret,
                                                  char** challenge);
himitsu_error_t himitsu_verify_handshake_challenge(const char* received_challenge,
                                                  const char* epoch_key,
                                                  const char* shared_secret);
```

#### Session Management
```c
himitsu_error_t himitsu_session_create(himitsu_session_t** session,
                                      const himitsu_keypair_t* local_keypair);
himitsu_error_t himitsu_session_handshake(himitsu_session_t* session,
                                         const char* peer_public_key,
                                         const char* epoch_key);
himitsu_error_t himitsu_session_get_info(const himitsu_session_t* session,
                                        int* is_established,
                                        char** peer_id);
void himitsu_session_destroy(himitsu_session_t* session);
```

### Message Serialization

#### Message Structure
```c
typedef struct {
    char* type;
    char* to;
    char* from;
    char* payload;
    char* signature;
    char* timestamp;
    char* message_id;
} himitsu_message_t;
```

#### Message Functions
```c
himitsu_error_t himitsu_message_create(himitsu_message_t** message);
himitsu_error_t himitsu_message_set_field(himitsu_message_t* message,
                                         const char* field,
                                         const char* value);
himitsu_error_t himitsu_message_get_field(const himitsu_message_t* message,
                                         const char* field,
                                         const char** value);
void himitsu_message_destroy(himitsu_message_t* message);
```

#### JSON Serialization
```c
himitsu_error_t himitsu_serialize_message(const himitsu_message_t* message,
                                         char** json_string);
himitsu_error_t himitsu_deserialize_message(const char* json_string,
                                           himitsu_message_t** message);
```

### Error Handling

```c
typedef enum {
    HIMITSU_SUCCESS = 0,
    HIMITSU_ERROR_INVALID_PARAMETER,
    HIMITSU_ERROR_MEMORY_ALLOCATION,
    HIMITSU_ERROR_CRYPTO_FAILURE,
    HIMITSU_ERROR_INVALID_MESSAGE,
    HIMITSU_ERROR_SESSION_NOT_FOUND,
    HIMITSU_ERROR_HANDSHAKE_FAILED,
    HIMITSU_ERROR_VERIFICATION_FAILED,
    HIMITSU_ERROR_BUFFER_TOO_SMALL,
    HIMITSU_ERROR_NOT_IMPLEMENTED
} himitsu_error_t;

const char* himitsu_error_string(himitsu_error_t error);
```

## Build Instructions

### Requirements

- C99-compatible compiler (GCC 4.9+, Clang 3.5+, MSVC 2015+)
- POSIX-compatible system (Linux, macOS, *BSD)
- Make utility

### Build Process

```bash
# Simple build
cd build
make -f Makefile.simple

# This creates:
# - libhimitsu.a (static library)
# - test executables
```

### Build Targets

```bash
make -f Makefile.simple lib      # Library only
make -f Makefile.simple test     # Run all tests
make -f Makefile.simple clean    # Clean build artifacts
make -f Makefile.simple examples # Build example programs
```

### Cross-Platform Building

#### Linux
```bash
make -f Makefile.simple
```

#### macOS
```bash
xcode-select --install
make -f Makefile.simple
```

#### Windows (MinGW/MSYS2)
```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
make -f Makefile.simple
```

### Integration Methods

#### Static Linking
```bash
gcc your_program.c -lhimitsu -o your_program
```

#### Source Integration
```makefile
HIMITSU_SOURCES = src/crypto/*.c src/protocol/*.c src/serialization/*.c src/utils/*.c
your_program: your_program.c $(HIMITSU_SOURCES)
	gcc -std=c99 -Iinclude $^ -o $@
```

## Architecture

### Project Structure
```
libhimitsu/
├── include/himitsu/     # Public headers
│   ├── himitsu.h       # Main header
│   ├── crypto.h        # Crypto functions
│   ├── protocol.h      # Protocol functions
│   ├── serialization.h # JSON functions
│   ├── types.h         # Type definitions
│   └── utils.h         # Utility functions
├── src/                # Source files
│   ├── crypto/         # Crypto implementations
│   ├── protocol/       # Protocol logic
│   ├── serialization/  # JSON engine
│   └── utils/          # Utility functions
├── tests/              # Test suites
├── examples/           # Example programs
├── build/              # Build files
└── docs/               # Documentation
```

### Technical Specifications

#### Cryptographic Standards
- **ECDH**: P-256 curve (secp256r1) per FIPS 186-4
- **AES**: 256-bit key with GCM mode for authenticated encryption
- **SHA-256**: Per FIPS PUB 180-4
- **HMAC**: HMAC-SHA256 per RFC 2104
- **Random**: Cryptographically secure random number generation

#### Protocol Specification
- **Handshake Format**: `epoch_key|sha256_hash|timestamp|random_nonce:hmac_signature`
- **Message Structure**: JSON with fields: type, to, from, payload, signature, timestamp, message_id
- **Session Management**: Stateful sessions with peer tracking and timeout handling
- **Timestamp Validation**: 300-second window for replay attack prevention

#### Build Requirements
- **C Standard**: C99 compliance for maximum portability
- **Compiler**: GCC 4.9+, Clang 3.5+, MSVC 2015+
- **Dependencies**: No external dependencies (self-contained)
- **Platforms**: Linux, macOS, Windows, ESP32, Raspberry Pi

## Development Status

### Implementation Status

**Phase 1: Foundation** - Complete
- Project structure and build system
- Core type definitions and error handling
- Memory management utilities
- Basic test framework

**Phase 2: Cryptographic Module** - Complete
- ECDH P-256 implementation
- SHA-256 hashing functionality
- HMAC-SHA256 authentication
- AES-256-GCM encryption

**Phase 3: Protocol Module** - Complete
- Node-Synchronized Handshake protocol
- Session management system
- Challenge/response mechanism
- Timestamp validation

**Phase 4: Serialization Module** - Complete
- Lightweight JSON parser/serializer
- Message structure handling
- String escaping and validation
- Memory-efficient processing

**Phase 5: Integration Testing** - Complete
- Comprehensive integration tests
- End-to-end workflow validation
- Memory management verification
- Error condition testing

**Phase 6: Documentation & Examples** - Complete
- API documentation
- Build and integration guides
- Example applications
- Usage demonstrations

### Build Status
- **Library**: Builds cleanly on all target platforms
- **Tests**: All test suites pass
- **Examples**: Working demonstration programs
- **Memory**: Secure memory management throughout

### Test Coverage
- Unit tests for all modules
- Integration tests for complete workflows
- Error condition testing
- Memory leak detection

### Known Limitations
- JSON stream parsing not implemented (single message focus)
- Hardware security module integration not included
- Network transport layer is application responsibility

### Future Enhancements
- Network transport layer integration
- Advanced key management
- Performance optimizations for high-throughput scenarios
- Language bindings (Python, JavaScript, Go)
- Hardware security module integration

---

**Project Status: Production Ready**
**Code Quality: Secure and well-tested**
**Documentation: Complete**
