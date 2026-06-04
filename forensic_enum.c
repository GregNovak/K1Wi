#define _XOPEN_SOURCE 700
#include "forensic_enum.h"

#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int forensic_enum_add_path(forensic_path_list_t *list, const char *path) {
    if (!list || !path) return -1;

    if (list->count == list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 16 : list->capacity * 2;
        char **new_paths = realloc(list->paths, new_cap * sizeof(char *));
        if (!new_paths) {
            return -1;
        }
        list->paths = new_paths;
        list->capacity = new_cap;
    }

    char *copy = strdup(path);
    if (!copy) {
        return -1;
    }

    list->paths[list->count++] = copy;
    return 0;
}

/* Global-ish context for nftw callback */
typedef struct {
    forensic_path_list_t *list;
    int error;
} forensic_enum_ctx_t;

static forensic_enum_ctx_t g_enum_ctx;

static int forensic_enum_nftw_cb(const char *fpath, const struct stat *sb,
                                 int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;

    if (g_enum_ctx.error != 0) {
        return 1; /* stop traversal */
    }

    /* Only collect regular files and symlinks to files if desired */
    if (typeflag == FTW_F || typeflag == FTW_SL) {
        if (forensic_enum_add_path(g_enum_ctx.list, fpath) != 0) {
            g_enum_ctx.error = errno ? errno : -1;
            return 1; /* stop traversal */
        }
    }

    return 0; /* continue */
}

int forensic_enum_paths(const char *root, forensic_path_list_t *out) {
    if (!root || !out) {
        return EINVAL;
    }

    forensic_path_list_init(out);

    g_enum_ctx.list = out;
    g_enum_ctx.error = 0;

    /* FTW_PHYS: do not follow symlinks; adjust flags if you want different behavior */
    int flags = FTW_PHYS;
    int max_fd = 16;

    if (nftw(root, forensic_enum_nftw_cb, max_fd, flags) == -1) {
        int err = errno ? errno : -1;
        return (g_enum_ctx.error != 0) ? g_enum_ctx.error : err;
    }

    if (g_enum_ctx.error != 0) {
        return g_enum_ctx.error;
    }

    return 0;
}

void forensic_path_list_free(forensic_path_list_t *list) {
    if (!list) return;
    if (list->paths) {
        for (size_t i = 0; i < list->count; ++i) {
            free(list->paths[i]);
        }
        free(list->paths);
    }
    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}

