#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "state.h"   // for cipher_t
#include "logging.h"

int opus_load_cipher(const char *path, cipher_t *out)
{
    if (!path || !out)
        return -1;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        log_error("opus_load_cipher: cannot open %s", path);
        return -1;
    }


	// Read entire file
	if (fseek(fp, 0, SEEK_END) != 0) {
	    fclose(fp);
	    return -1;
	}

	long sz = ftell(fp);
	if (sz < 0) {
	    fclose(fp);
	    return -1;
	}

	rewind(fp);

	size_t file_size = (size_t)sz;

	char *buf = malloc(file_size + 1);
	if (!buf) {
	    fclose(fp);
	    return -1;
	}

	size_t nread = fread(buf, 1, file_size, fp);
	fclose(fp);
	buf[nread] = '\0';

    // Normalize: keep only A–Z
    char *norm = malloc(nread + 1);
    if (!norm) {
        free(buf);
        return -1;
    }

    size_t j = 0;
    for (size_t i = 0; i < nread; i++) {
        unsigned char ch = (unsigned char)buf[i];
        if (isalpha(ch))
            norm[j++] = (char)toupper(ch);
    }
    norm[j] = '\0';

    free(buf);

    if (j == 0) {
        free(norm);
        return -1;
    }

    out->text = norm;
    out->length  = j;
    return 0;
}

