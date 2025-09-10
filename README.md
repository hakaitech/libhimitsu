# libhimitsu

A C99 library implementing the Himitsu Protocol for secure node-to-node communication.

## Features

- **ECDH P-256** key exchange
- **AES-256-GCM** authenticated encryption  
- **SHA-256 + HMAC** message authentication
- **JSON** message serialization
- **Node-synchronized handshake** protocol
- **Cross-platform** (Linux, macOS, Windows, embedded)

## Quick Start

```bash
git clone https://github.com/hakaitech/libhimitsu.git
cd libhimitsu
make
make test         # Run test suite
make examples     # Build example programs
make install      # Install to system
```

#### Using CMake
```bash
mkdir build && cd build
cmake ..
make
make test
sudo make install
```

## Usage

```c
#include <himitsu/himitsu.h>

int main() {
    himitsu_init();
    
    char* public_key = NULL;
    char* private_key = NULL;
    himitsu_generate_keypair(&public_key, &private_key);
    
    printf("Public key: %s\n", public_key);
    
    free(public_key);
    free(private_key);
    himitsu_cleanup();
    return 0;
}
```

## Documentation

See [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md) for complete API reference and build instructions.

## License

MIT License. See [LICENSE](LICENSE) for details.
