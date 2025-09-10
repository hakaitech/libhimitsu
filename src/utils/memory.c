/**
 * @file memory.c
 * @brief Memory management utilities for libhimitsu
 */

#include <stdlib.h>
#include <string.h>
#include <himitsu/utils.h>

/**
 * @brief Secure memory allocation with zero initialization
 */
void* himitsu_secure_malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    void* ptr = malloc(size);
    if (ptr != NULL) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/**
 * @brief Secure memory reallocation
 */
void* himitsu_secure_realloc(void* ptr, size_t old_size, size_t new_size) {
    if (new_size == 0) {
        himitsu_secure_free(ptr, old_size);
        return NULL;
    }
    
    void* new_ptr = realloc(ptr, new_size);
    if (new_ptr != NULL && new_size > old_size) {
        // Zero out the new memory region
        memset((char*)new_ptr + old_size, 0, new_size - old_size);
    }
    return new_ptr;
}

/**
 * @brief Secure memory deallocation with clearing
 */
void himitsu_secure_free(void* ptr, size_t size) {
    if (ptr != NULL) {
        // Clear memory before freeing
        himitsu_secure_memzero(ptr, size);
        free(ptr);
    }
}

/**
 * @brief Secure string duplication
 */
char* himitsu_secure_strdup(const char* str) {
    if (str == NULL) {
        return NULL;
    }
    
    size_t len = strlen(str) + 1;
    char* dup = himitsu_secure_malloc(len);
    if (dup != NULL) {
        memcpy(dup, str, len);
    }
    return dup;
}

/**
 * @brief Secure string free
 */
void himitsu_secure_strfree(char* str) {
    if (str != NULL) {
        size_t len = strlen(str);
        himitsu_secure_free(str, len);
    }
}
