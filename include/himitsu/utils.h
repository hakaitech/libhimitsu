#ifndef HIMITSU_UTILS_H
#define HIMITSU_UTILS_H

#include <stddef.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Memory management utilities */
void* himitsu_secure_malloc(size_t size);
void* himitsu_secure_realloc(void* ptr, size_t old_size, size_t new_size);
void himitsu_secure_free(void* ptr, size_t size);
char* himitsu_secure_strdup(const char* str);
void himitsu_secure_strfree(char* str);

/* Error handling */
const char* himitsu_error_string(himitsu_error_t error);

#ifdef __cplusplus
}
#endif

#endif /* HIMITSU_UTILS_H */
