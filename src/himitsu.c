/**
 * @file himitsu.c
 * @brief Main library entry point for libhimitsu
 */

#include <himitsu/himitsu.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Global library state */
static int g_himitsu_initialized = 0;

/* Forward declarations for utility functions */
extern const char* himitsu_error_string(himitsu_error_t error);

himitsu_error_t himitsu_init(void) {
    if (g_himitsu_initialized) {
        return HIMITSU_SUCCESS;
    }
    
    srand((unsigned int)time(NULL));
    g_himitsu_initialized = 1;
    return HIMITSU_SUCCESS;
}

void himitsu_cleanup(void) {
    if (!g_himitsu_initialized) {
        return;
    }
    
    g_himitsu_initialized = 0;
}

const char* himitsu_version(void) {
    return HIMITSU_VERSION_STRING;
}

int himitsu_is_debug_build(void) {
#ifdef DEBUG
    return 1;
#else
    return 0;
#endif
}
