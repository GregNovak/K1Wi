#include <stdio.h>
#include <stdlib.h>
#include <jpeglib.h>
#include "dct_analysis.h"

int opus_dct_analyze_file(const char *path, dct_summary_t *out)
{
    if (!path || !out) return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("opus_dct_analyze_file fopen");
        return -1;
    }

    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr jerr;

    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, fp);

    /* Read header; we only want the DCT coefficients, not pixel data. */
    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        fclose(fp);
        return -1;
    }

    /* Directly read the DCT coefficient arrays. No start_decompress here. */
    jvirt_barray_ptr *coef_arrays = jpeg_read_coefficients(&cinfo);
    if (!coef_arrays) {
        jpeg_destroy_decompress(&cinfo);
        fclose(fp);
        return -1;
    }

    size_t total_blocks = 0;
    size_t total_coeffs = 0;
    size_t zeros = 0;
    size_t nonzero = 0;
    size_t odd_nonzero = 0;
    size_t lsb1 = 0;

    int num_components = cinfo.num_components;
    for (int comp = 0; comp < num_components; comp++) {
        jpeg_component_info *ci = &cinfo.comp_info[comp];

        JDIMENSION width_in_blocks  = ci->width_in_blocks;
        JDIMENSION height_in_blocks = ci->height_in_blocks;

        for (JDIMENSION by = 0; by < height_in_blocks; by++) {
            JBLOCKARRAY row_ptr = (cinfo.mem->access_virt_barray)(
                (j_common_ptr)&cinfo, coef_arrays[comp], by, 1, FALSE
            );

            for (JDIMENSION bx = 0; bx < width_in_blocks; bx++) {
                JCOEFPTR block = row_ptr[0][bx];

                total_blocks++;
                for (int k = 0; k < DCTSIZE2; k++) { /* 64 coeffs per block */
                    short v = block[k];
                    total_coeffs++;

                    if (v == 0) {
                        zeros++;
                        continue;
                    }
                    nonzero++;

                    int av = (v < 0) ? -v : v;
                    if (av & 1) {
                        odd_nonzero++;
                        lsb1++;
                    }
                }
            }
        }
    }

    jpeg_destroy_decompress(&cinfo);
    fclose(fp);

    out->blocks    = total_blocks;
    out->coeffs    = total_coeffs;
    out->zero_frac = (total_coeffs > 0) ? (double)zeros / (double)total_coeffs : 0.0;
    out->odd_frac  = (nonzero > 0) ? (double)odd_nonzero / (double)nonzero   : 0.0;
    out->lsb1_frac = (total_coeffs > 0) ? (double)lsb1 / (double)total_coeffs : 0.0;

    return 0;
}

void opus_dct_print_summary(const dct_summary_t *s)
{
    if (!s) return;

    printf("\n--- JPEG DCT Coefficient Analysis ---\n");
    printf("Blocks analyzed:       %zu\n", s->blocks);
    printf("Total coefficients:    %zu\n", s->coeffs);
    printf("Zero coefficient frac: %.4f\n", s->zero_frac);
    printf("Odd (non-zero) frac:   %.4f\n", s->odd_frac);
    printf("LSB(1) frac (|coeff|): %.4f\n", s->lsb1_frac);

    if (s->coeffs == 0) {
        printf("Assessment:            Not a valid JPEG DCT stream.\n");
        return;
    }

    /* First-wave heuristic; we’ll tune this with data later. */
    if (s->odd_frac > 0.52 && s->odd_frac < 0.60) {
        printf("Assessment:            Possible DCT-domain stego (Steghide/F5-like).\n");
    } else {
        printf("Assessment:            DCT coefficients look roughly natural.\n");
    }
}

