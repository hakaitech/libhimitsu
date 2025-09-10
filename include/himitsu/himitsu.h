#ifndef HIMITSU_H
#define HIMITSU_H

/**
 * @file himitsu.h
 * @brief Main header for libhimitsu - The Himitsu Protocol Core Library
 * 
 * This library provides the core functionality for the Himitsu Protocol,
 * a secure, anonymous communication system. It includes cryptographic
 * primitives, protocol logic, and message serialization.
 * 
 * @version 2.0
 * @date September 10, 2025
 */

#include "types.h"
#include "crypto.h"
#include "protocol.h"
#include "serialization.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Library version information */
#define HIMITSU_VERSION_MAJOR 2
#define HIMITSU_VERSION_MINOR 0
#define HIMITSU_VERSION_PATCH 0
#define HIMITSU_VERSION_STRING "2.0.0"

/**
 * @brief Initialize the libhimitsu library
 * 
 * This function must be called before using any other library functions.
 * It initializes the cryptographic subsystem and other global state.
 * 
 * @return himitsu_error_t HIMITSU_SUCCESS on success, error code otherwise
 */
himitsu_error_t himitsu_init(void);

/**
 * @brief Cleanup the libhimitsu library
 * 
 * This function should be called when the library is no longer needed.
 * It cleans up global state and releases resources.
 */
void himitsu_cleanup(void);

/**
 * @brief Get the library version string
 * 
 * @return const char* Version string (e.g., "2.0.0")
 */
const char* himitsu_version(void);

/**
 * @brief Get a human-readable error string
 * 
 * @param error Error code
 * @return const char* Error description string
 */
const char* himitsu_error_string(himitsu_error_t error);

/**
 * @brief Check if the library was compiled with debug information
 * 
 * @return int 1 if debug build, 0 if release build
 */
int himitsu_is_debug_build(void);

#ifdef __cplusplus
}
#endif

#endif /* HIMITSU_H */
