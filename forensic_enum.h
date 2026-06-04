#ifndef FORENSIC_ENUM_H
#define FORENSIC_ENUM_H

#include <stddef.h>

typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
} forensic_path_list_t;

/* Initialize an empty list (optional helper) */
static inline void forensic_path_list_init(forensic_path_list_t *list) {
    if (!list) return;
    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* Recursively enumerate all regular files under root.
 * Returns 0 on success, non-zero on error.
 */
int forensic_enum_paths(const char *root, forensic_path_list_t *out);

/* Free all memory associated with the list. */
void forensic_path_list_free(forensic_path_list_t *list);

#endif /* FORENSIC_ENUM_H */

