#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <strings.h>   // for strcasecmp
#include <math.h>
#include "forensic_enum.h"   // your new enumerator module
#include "secure_delete_core.h"
#include "forensic_cmds.h"

static const char *LOOP_IMG  = "opus_loop.img";
static const char *MOUNT_DIR = "/mnt/opus_forensic";
static int detect_all_zero(const unsigned char *buf, size_t len);
static int detect_all_ff(const unsigned char *buf, size_t len);
static int detect_alternating(const unsigned char *buf, size_t len);

/* ---------------------------------------------------------
 * Helpers
 * --------------------------------------------------------- */

static double compute_entropy(const uint8_t *buf, size_t len);

static int detect_all_zero(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0x00)
            return 0;
    }
    return 1;
}

static int detect_all_ff(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0xFF)
            return 0;
    }
    return 1;
}

static int detect_alternating(const unsigned char *buf, size_t len)
{
    if (len < 2)
        return 0;

    for (size_t i = 1; i < len; i++) {
        if (buf[i] == buf[i - 1])
            return 0;
    }
    return 1;
}



/* Parse blockmap.txt and extract the first physical block. */
static int forensic_parse_blockmap(const char *path, uint64_t *block_out)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen blockmap");
        return -1;
    }

    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        char *colon = strchr(line, ':');
        if (!colon)
            continue;

        char *p = colon + 1;
        while (*p == ' ' || *p == '\t')
            p++;

        char *end = NULL;
        uint64_t blk = strtoull(p, &end, 10);
        if (end == p)
            continue;

        *block_out = blk;
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return -1;
}

/* Read N blocks from the loop image starting at block_start. */
static int forensic_read_blocks(const char *img_path,
                                uint64_t block_start,
                                size_t block_count,
                                const char *out_path)
{
    FILE *in = fopen(img_path, "rb");
    if (!in) {
        perror("fopen img");
        return -1;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("fopen out");
        fclose(in);
        return -1;
    }

    const size_t block_size = 4096;
    uint8_t buf[4096];

    off_t offset = (off_t)(block_start * block_size);

	if (fseeko(in, offset, SEEK_SET) != 0) {
        perror("fseeko");
        fclose(in);
        fclose(out);
        return -1;
    }

    for (size_t i = 0; i < block_count; i++) {
        size_t r = fread(buf, 1, block_size, in);
        if (r != block_size) {
            fprintf(stderr, "Short read at block %zu\n", i);
            break;
        }
        fwrite(buf, 1, block_size, out);
    }

    fclose(in);
    fclose(out);
    return 0;
}

/* Run a shell command and return exit code */
static int run_cmd(const char *cmd)
{
    fprintf(stderr, "[FORENSIC] $ %s\n", cmd);
    int rc = system(cmd);
    if (rc == -1) return -1;
    return WEXITSTATUS(rc);
}

/* ---------------------------------------------------------
 * FORENSIC INIT <size_mb>
 * --------------------------------------------------------- */
static void forensic_init(const char *size_str)
{
    int size_mb = size_str ? atoi(size_str) : 64;
    if (size_mb <= 0) size_mb = 64;

    char cmd[2048];

    snprintf(cmd, sizeof(cmd),
             "dd if=/dev/zero of=%s bs=1M count=%d",
             LOOP_IMG, size_mb);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "INIT: dd failed\n");
        return;
    }

    snprintf(cmd, sizeof(cmd), "mkfs.ext4 -F %s", LOOP_IMG);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "INIT: mkfs failed\n");
        return;
    }

    mkdir(MOUNT_DIR, 0755);

    snprintf(cmd, sizeof(cmd),
             "mount -o loop %s %s",
             LOOP_IMG, MOUNT_DIR);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "INIT: mount failed\n");
        return;
    }

    fprintf(stderr, "FORENSIC INIT complete. Mounted at %s\n", MOUNT_DIR);
}

/* ---------------------------------------------------------
 * FORENSIC TEST-DEL
 * Synthetic test inside loopback FS
 * --------------------------------------------------------- */
static void forensic_test_del(void)
{
    char cmd[4096];

    /* 1. Create test file (1 MiB of random) */
    snprintf(cmd, sizeof(cmd),
             "dd if=/dev/urandom of=\"%s/test.bin\" bs=1M count=1",
             MOUNT_DIR);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "TEST-DEL: create failed\n");
        return;
    }

    /* 2. Generate blockmap.txt using filefrag */
    snprintf(cmd, sizeof(cmd),
             "filefrag -v \"%s/test.bin\" > \"%s/blockmap.txt\"",
             MOUNT_DIR, MOUNT_DIR);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "TEST-DEL: filefrag failed\n");
        return;
    }

    fprintf(stderr, "Block map written to %s/blockmap.txt\n", MOUNT_DIR);

    /* 3. BEFORE-capture: read file content before deletion */
    snprintf(cmd, sizeof(cmd),
             "dd if=\"%s/test.bin\" of=\"%s/before.bin\" bs=4096",
             MOUNT_DIR, MOUNT_DIR);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "TEST-DEL: dd before failed\n");
        return;
    }

    /* 4. Secure delete using Opus engine */
    opus_sd_policy_t policy;
    opus_sd_policy_preset(OPUS_SD_MODE_DOD3, &policy);

    char testfile[512];
    snprintf(testfile, sizeof(testfile), "%s/test.bin", MOUNT_DIR);

    if (opus_secure_delete_file(testfile, &policy) != 0) {
        fprintf(stderr, "TEST-DEL: secure delete failed: %s\n",
                strerror(errno));
        return;
    }

    /* 5. BLOCK-LEVEL AFTER-CAPTURE */
    char blockmap_path[512];
    snprintf(blockmap_path, sizeof(blockmap_path),
             "%s/blockmap.txt", MOUNT_DIR);

    char after_path[512];
    snprintf(after_path, sizeof(after_path),
             "%s/after.bin", MOUNT_DIR);

    uint64_t blk = 0;

    if (forensic_parse_blockmap(blockmap_path, &blk) == 0) {
        printf("[FORENSIC] First block = %llu\n",
               (unsigned long long)blk);

        /* 1 MiB file = 256 blocks of 4096 bytes */
        if (forensic_read_blocks(LOOP_IMG,
                                 blk,
                                 256,
                                 after_path) == 0) {
            printf("[FORENSIC] Raw after-capture written to after.bin\n");
        } else {
            printf("[FORENSIC] Failed to read raw blocks\n");
        }
    } else {
        printf("[FORENSIC] Failed to parse blockmap\n");
    }

    fprintf(stderr, "FORENSIC TEST-DEL complete.\n");
}

/* ---------------------------------------------------------
 * FORENSIC CLEANUP
 * --------------------------------------------------------- */
static void forensic_cleanup(void)
{
    char cmd[4096];

    snprintf(cmd, sizeof(cmd), "umount %s", MOUNT_DIR);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd), "rm -f %s", LOOP_IMG);
    run_cmd(cmd);

    fprintf(stderr, "FORENSIC CLEANUP complete.\n");
}

/* ---------------------------------------------------------
 * FORENSIC SELFTEST
 * --------------------------------------------------------- */
static void forensic_selftest(void)
{
    forensic_init("64");
    forensic_test_del();
    forensic_cleanup();
}

/* ---------------------------------------------------------
 * Entropy helper
 * --------------------------------------------------------- */
static double compute_entropy(const uint8_t *buf, size_t len)
{
    size_t freq[256] = {0};
    for (size_t i = 0; i < len; i++)
        freq[buf[i]]++;

    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        H -= p * log2(p);
    }
    return H;
}

/* ---------------------------------------------------------
 * FORENSIC VERIFY
 *
 * Verifies that secure deletion actually overwrote the
 * physical blocks that previously held the file whose
 * content is in before.bin / after.bin.
 *
 * Works for any file size.
 * --------------------------------------------------------- */
int forensic_verify(void)
{
    unsigned char *before_buf = NULL;
    unsigned char *after_buf  = NULL;
    size_t before_size = 0, after_size = 0;

    /* Load BEFORE.bin */
    FILE *fb = fopen("/mnt/opus_forensic/before.bin", "rb");
    if (!fb) {
        printf("VERIFY: could not open before.bin\n");
        return -1;
    }

	if (fseek(fb, 0, SEEK_END) != 0) {
	    fclose(fb);
	    return -1;
	}

	long before_pos = ftell(fb);
	if (before_pos < 0) {
	    fclose(fb);
	    return -1;
	}

	before_size = (size_t)before_pos;

	if (fseek(fb, 0, SEEK_SET) != 0) {
	    fclose(fb);
	    return -1;
	}
    before_buf = malloc(before_size);
    if (!before_buf) {
        fclose(fb);
        printf("VERIFY: memory allocation failed\n");
        return -1;
    }
    fread(before_buf, 1, before_size, fb);
    fclose(fb);

    /* Load AFTER.bin */
    FILE *fa = fopen("/mnt/opus_forensic/after.bin", "rb");
    if (!fa) {
        printf("VERIFY: could not open after.bin\n");
        free(before_buf);
        return -1;
    }

	if (fseek(fa, 0, SEEK_END) != 0) {
	    fclose(fa);
	    free(before_buf);
	    return -1;
	}

	long after_pos = ftell(fa);
	if (after_pos < 0) {
	    fclose(fa);
	    free(before_buf);
	    return -1;
	}

	after_size = (size_t)after_pos;

	if (fseek(fa, 0, SEEK_SET) != 0) {
	    fclose(fa);
	    free(before_buf);
	    return -1;
	}
    after_buf = malloc(after_size);
    if (!after_buf) {
        fclose(fa);
        free(before_buf);
        printf("VERIFY: memory allocation failed\n");
        return -1;
    }
    fread(after_buf, 1, after_size, fa);
    fclose(fa);

    printf("\n========== FORENSIC VERIFY REPORT ==========\n");

    /* Determine overlapping region */
    size_t compare_len = before_size;
    if (after_size < compare_len)
        compare_len = after_size;

    if (before_size != after_size) {
        printf("Note: BEFORE (%zu bytes) and AFTER (%zu bytes) differ in size.\n",
               before_size, after_size);
        printf("Comparing first %zu bytes (overlapping region).\n", compare_len);
    }

    /* Compute byte difference ratio */
    size_t diff_count = 0;
    for (size_t i = 0; i < compare_len; i++) {
        if (before_buf[i] != after_buf[i])
            diff_count++;
    }

    double diff_ratio = (compare_len > 0)
        ? ((double)diff_count / (double)compare_len)
        : 0.0;

    /* Compute entropy */
    double H_before = compute_entropy(before_buf, before_size);
    double H_after  = compute_entropy(after_buf,  after_size);

    /* Pattern detection */
    int all_zero = detect_all_zero(after_buf, after_size);
    int all_ff   = detect_all_ff(after_buf, after_size);
    int alternating_00_ff = detect_alternating(after_buf, after_size);

    /* Print metrics */
    printf("File size (before) : %zu bytes\n", before_size);
    printf("File size (after)  : %zu bytes\n", after_size);
    printf("Compared region    : %zu bytes\n", compare_len);
    printf("Before entropy     : %.4f bits/byte\n", H_before);
    printf("After entropy      : %.4f bits/byte\n", H_after);
    printf("Byte difference    : %.2f%% (%zu / %zu)\n",
           diff_ratio * 100.0, diff_count, compare_len);

    /* PASS/FAIL logic */
    int pass = 1;

    if (diff_ratio < 0.90) {
        printf("Verdict: FAIL (insufficient overwrite: low diff ratio)\n");
        pass = 0;
    }

    if (all_zero || all_ff || alternating_00_ff) {
        if (pass)
            printf("Verdict: PASS (deterministic overwrite detected)\n");
        printf("============================================\n\n");
        free(before_buf);
        free(after_buf);
        return 0;
    }

    if (H_after < 0.5 && diff_ratio >= 0.90) {
        printf("Verdict: PASS (low-entropy deterministic overwrite detected)\n");
        printf("============================================\n\n");
        free(before_buf);
        free(after_buf);
        return 0;
    }

    double epsilon = 0.10;
    if (H_after + epsilon >= H_before && diff_ratio >= 0.90) {
        printf("Verdict: PASS (random-like overwrite validated)\n");
    } else {
        printf("Verdict: FAIL (overwrite pattern unclear or insufficient)\n");
    }

    printf("============================================\n\n");

    free(before_buf);
    free(after_buf);
    return 0;
}

/* ---------------------------------------------------------
 * FORENSIC TARGET <path>
 *
 * Host-wide: take any file anywhere on the system,
 * copy it into the loopback FS, capture BEFORE,
 * securely delete the original file using Opus,
 * capture AFTER from the loopback image, then VERIFY.
 * --------------------------------------------------------- */
static void forensic_del_verify(const char *path)
{
    if (!path || !*path) {
        fprintf(stderr, "TARGET: missing path\n");
        return;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "TARGET: file '%s' not found\n", path);
        return;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "TARGET: '%s' is not a regular file\n", path);
        return;
    }

    /* Ensure loopback is mounted */
    struct stat mnt_st;
    if (stat(MOUNT_DIR, &mnt_st) != 0) {
        fprintf(stderr, "TARGET: mount dir %s not available; run FORENSIC INIT first\n",
                MOUNT_DIR);
        return;
    }

    char loop_file[512];
    snprintf(loop_file, sizeof(loop_file), "%s/target.bin", MOUNT_DIR);

    char cmd[4096];

    /* 1. Copy host file into loopback FS as target.bin */
    snprintf(cmd, sizeof(cmd),
             "dd if=\"%s\" of=\"%s\" bs=4096 conv=fsync",
             path, loop_file);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "TARGET: dd copy into loopback failed\n");
        return;
    }

    /* 2. Generate blockmap.txt for target.bin inside loopback */
    snprintf(cmd, sizeof(cmd),
             "filefrag -v \"%s\" > \"%s/blockmap.txt\"",
             loop_file, MOUNT_DIR);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "TARGET: filefrag failed\n");
        return;
    }

    fprintf(stderr, "Block map written to %s/blockmap.txt\n", MOUNT_DIR);

	 /* 3. BEFORE-capture: copy target.bin content */
	snprintf(cmd, sizeof(cmd),
		 "dd if=\"%s\" of=\"%s/before.bin\" bs=4096 conv=fsync",
		 loop_file, MOUNT_DIR);
	if (run_cmd(cmd) != 0) {
	    fprintf(stderr, "TARGET: dd before failed\n");
	    return;
	}

	/* === USER CONFIRMATION BEFORE DELETION === */
	printf("[!] This operation will permanently delete:\n    %s\n", path);
	printf("[?] Proceed with forensic delete + verify? (Y/N): ");
	fflush(stdout);

	char answer[8] = {0};
	if (!fgets(answer, sizeof(answer), stdin)) {
	    printf("[!] Aborted (input error)\n");
	    return;
	}

	if (answer[0] != 'y' && answer[0] != 'Y') {
	    printf("[*] Operation cancelled by user.\n");
	    return;
	}
	/* ========================================= */

	/* 4. Secure delete the ORIGINAL host file using Opus engine */
	opus_sd_policy_t policy;
	opus_sd_policy_preset(OPUS_SD_MODE_DOD3, &policy);

	if (opus_secure_delete_file(path, &policy) != 0) {
	    fprintf(stderr, "TARGET: secure delete of '%s' failed: %s\n",
		    path, strerror(errno));
	    return;
	}

    /* 5. BLOCK-LEVEL AFTER-CAPTURE from loopback image */
    char blockmap_path[512];
    snprintf(blockmap_path, sizeof(blockmap_path),
             "%s/blockmap.txt", MOUNT_DIR);

    char after_path[512];
    snprintf(after_path, sizeof(after_path),
             "%s/after.bin", MOUNT_DIR);

    uint64_t blk = 0;

    if (forensic_parse_blockmap(blockmap_path, &blk) == 0) {
        printf("[FORENSIC] First block = %llu\n",
               (unsigned long long)blk);

        const size_t block_size = 4096;
        if (st.st_size < 0) {
	    printf("[FORENSIC] invalid image size\n");
	    return;
	}

	size_t img_size = (size_t)st.st_size;
	size_t blocks = (img_size + block_size - 1) / block_size;

        if (forensic_read_blocks(LOOP_IMG,
                                 blk,
                                 blocks,
                                 after_path) == 0) {
            printf("[FORENSIC] Raw after-capture written to after.bin\n");
        } else {
            printf("[FORENSIC] Failed to read raw blocks\n");
            return;
        }
    } else {
        printf("[FORENSIC] Failed to parse blockmap\n");
        return;
    }

    /* 6. Run VERIFY on before.bin/after.bin */
    forensic_verify();
}


static void forensic_target_recurse(const char *root)
{
    if (!root || !*root) {
        fprintf(stderr, "TARGET-RECURSE: missing path\n");
        return;
    }

    forensic_path_list_t list;
    int rc = forensic_enum_paths(root, &list);
    if (rc != 0) {
        fprintf(stderr, "TARGET-RECURSE: enumeration failed: %d\n", rc);
        return;
    }

    printf("[*] TARGET-RECURSE: Found %zu files under %s\n",
           list.count, root);



    for (size_t i = 0; i < list.count; ++i) {
        const char *f = list.paths[i];
        printf("\n[*] Processing: %s\n", f);

        // Reuse your existing single-file forensic pipeline
        // This is the beauty of your architecture.
        forensic_del_verify(f);

        // forensic_target() prints its own PASS/FAIL
        // but we can track success/failure if needed
        // (optional)
    }

    forensic_path_list_free(&list);

    printf("\n[*] TARGET-RECURSE complete.\n");
}

/* ---------------------------------------------------------
 * Dispatcher
 * --------------------------------------------------------- */
void forensicCmd(const char *args)
{
    if (!args || !*args) {
        fprintf(stderr,
                "Usage: FORENSIC <INIT|TEST-DEL|DEL-VERIFY|VERIFY|CLEANUP|SELFTEST|TARGET-RECURSE>\n");
        return;
    }

    char *copy = strdup(args);
    if (!copy) {
        fprintf(stderr, "FORENSIC: strdup failed\n");
        return;
    }

    char *tok = strtok(copy, " \t");

    if (!tok) {
        fprintf(stderr,
                "Usage: FORENSIC <INIT|TEST-DEL|DEL-VERIFY|VERIFY|CLEANUP|SELFTEST|TARGET-RECURSE>\n");
        free(copy);
        return;
    }

    if (strcasecmp(tok, "INIT") == 0) {
        char *size = strtok(NULL, " \t");
        forensic_init(size);
    }
    else if (strcasecmp(tok, "TEST-DEL") == 0) {
        forensic_test_del();
    }
    else if (strcasecmp(tok, "DEL-VERIFY") == 0) {
        char *path = strtok(NULL, " \t");
        forensic_del_verify(path);
    }
    else if (strcasecmp(tok, "VERIFY") == 0) {
        forensic_verify();
    }
    else if (strcasecmp(tok, "CLEANUP") == 0) {
        forensic_cleanup();
    }
    else if (strcasecmp(tok, "SELFTEST") == 0) {
        forensic_selftest();
    }
    else if (strcasecmp(tok, "TARGET-RECURSE") == 0) {
        char *path = strtok(NULL, " \t");
        forensic_target_recurse(path);
    }
    else {
        fprintf(stderr, "Unknown FORENSIC command.\n");
    }

    free(copy);
}

