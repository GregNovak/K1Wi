#include <gmp.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

#include "cli.h"
#include "rsa_factor.h"
#include "md5.h"
#include "rsa_common.h"
#include "rsa_small_e.h"
#include "rsa_wiener.h"
#include "rsa_ecm.h"
#include "rsa_checkpq.h"
#include "rsa_dfrompq.h"
#include "rsa_rho.h"
#include "file_copy.h"
#include "file_ops.h"
#include "secure_delete_cmds.h"

int k1wi_auto_analyze_file(const char *path);


typedef struct opus_context opus_context;

void opus_print_plaintext_from_bigint(const mpz_t m);
int opus_rsa_knownpq(const char *path, const char *p_str, const char *q_str);
int cmd_search(int argc, char **argv);
int opus_cmd_sha256(int argc, char **argv);
int opus_pie_time_cli(int argc, char **argv);
int opus_lyzer_file(const char *path, const char *mode);
int cmd_rsa(int argc, char **argv);
int cmd_about(opus_context *ctx, int argc, char **argv);
int cmd_piecalc(opus_context *ctx, int argc, char **argv);
int cmd_menu(opus_context *ctx, int argc, char **argv);
int cmd_exit(opus_context *ctx, int argc, char **argv);
void detect_magic(const char *filename);
void systemTime(void);
void opus_banner(void);

int opus_read_file(const char *path,
                   bool mode_raw,
                   bool mode_structured,
                   bool mode_safe,
                   size_t limit,
                   size_t offset,
                   size_t page_size,
                   bool ascii,
                   bool hex,
                   const char *force_format,
                   bool verbose,
                   bool summary);
static void opus_flags_init(OpusFlags *f) {
    f->recursive  = false;
    f->json       = false;
    f->min_length = 0;
}
static bool parse_flag(OpusFlags *flags, int *i, int argc, char **argv) {
    const char *arg = argv[*i];

    // Flags without values
    if (strcmp(arg, "--recursive") == 0) {
        flags->recursive = true;
        (*i)++;   // <-- ADVANCE PAST FLAG
        return true;
    }

    if (strcmp(arg, "--json") == 0) {
        flags->json = true;
        (*i)++;   // <-- ADVANCE PAST FLAG
        return true;
    }

    // Flags with values
    if (strcmp(arg, "--min-length") == 0) {
        if (*i + 1 >= argc) {
            fprintf(stderr, "ERROR: --min-length requires a value\n");
            return false;
        }
        flags->min_length = atoi(argv[*i + 1]);
        (*i) += 2;   // <-- ADVANCE PAST FLAG AND VALUE
        return true;
    }

    if (strcmp(arg, "-m") == 0) {
        if (*i + 1 >= argc) {
            fprintf(stderr, "ERROR: -m requires a value\n");
            return false;
        }
        flags->min_length = atoi(argv[*i + 1]);
        (*i) += 2;   // <-- ADVANCE PAST FLAG AND VALUE
        return true;
    }

    return false;
}

static bool opus_cli_parse(OpusCLI *cli, int argc, char **argv) {
    if (argc < 2) {
        return false;
    }

    opus_flags_init(&cli->flags);
    cli->command    = NULL;
    cli->subcommand = NULL;
    cli->arg_start  = argc;

    int i = 1;

    cli->command = argv[i++];
    if (i >= argc) {
        cli->arg_start = i;
        return true;
    }

	// Only commands that actually have subcommands should consume argv[i]
	bool has_sub =
	    strcmp(cli->command, "crypto") == 0 ||
	    strcmp(cli->command, "binary") == 0 ||
	    strcmp(cli->command, "desig")  == 0 ||
	    strcmp(cli->command, "wipefs") == 0;

	if (has_sub && argv[i][0] != '-') {
	    cli->subcommand = argv[i++];
	}


	for (; i < argc; ) {
		if (argv[i][0] == '-') {

	    /*
	     * If it's a known global flag,
	     * consume it.
	     */
	    if (parse_flag(&cli->flags, &i, argc, argv)) {
	        continue;
	    }

    /*
     * Otherwise leave remaining args
     * for command-specific parsing.
     */
    cli->arg_start = i;
    break;
}

	    cli->arg_start = i;
	    break;
	}

    return true;
}

static int opus_cli_dispatch(const OpusCLI *cli, int argc, char **argv) {
    
       char cmd_buf[128];

	snprintf(cmd_buf, sizeof(cmd_buf), "%s", cli->command);

	for (char *p = cmd_buf; *p; ++p) {
	    *p = (char)toupper((unsigned char)*p);
	}

	const char *cmd = cmd_buf;

    if (strcasecmp(cmd, "EXTRACT") == 0) {
        return cmd_extract(cli, argc, argv);

    } else if (strcasecmp(cmd, "STRING") == 0) {
        return cmd_string(argc - cli->arg_start + 1, argv + cli->arg_start - 1);
       
        } else if (strcasecmp(cmd, "MD5") == 0) {
        if (cli->arg_start >= argc) {
            fprintf(stderr, "Usage: k1wi md5 <file>\n");
            fprintf(stderr, "       k1wi md5 -in <file>\n");
            fprintf(stderr, "       k1wi md5 -verify <file> <hash>\n");
            fprintf(stderr, "       k1wi md5 -compare <file1> <file2>\n");
            return 1;
        }

        char digest[33];

        if (strcmp(argv[cli->arg_start], "-in") == 0) {
            if (cli->arg_start + 1 >= argc) {
                fprintf(stderr, "MD5 -in: need <file>\n");
        return 1;
            }

            const char *path = argv[cli->arg_start + 1];

            if (opus_md5_file(path, digest) == true) {
                printf("MD5(%s) = %s\n", path, digest);
                return 0;
            }

            fprintf(stderr, "MD5: failed to read %s\n", path);
            return 1;
        }

        if (strcmp(argv[cli->arg_start], "-verify") == 0) {
            if (cli->arg_start + 2 >= argc) {
                fprintf(stderr, "MD5 -verify: need <file> <hash>\n");
        return 1;
            }

            const char *path = argv[cli->arg_start + 1];
            const char *expected = argv[cli->arg_start + 2];

            if (opus_md5_file(path, digest) != true) {
                fprintf(stderr, "MD5: failed to read %s\n", path);
        return 1;
            }

            if (strcasecmp(digest, expected) == 0) {
                printf("MD5 OK\n");
                return 0;
            }

            printf("MD5 MISMATCH\n");
            return 1;
        }

        if (strcmp(argv[cli->arg_start], "-compare") == 0) {
            if (cli->arg_start + 2 >= argc) {
                fprintf(stderr, "MD5 -compare: need <file1> <file2>\n");
        return 1;
            }

            char h1[33], h2[33];
            const char *file1 = argv[cli->arg_start + 1];
            const char *file2 = argv[cli->arg_start + 2];

            if (opus_md5_file(file1, h1) != true) {
                fprintf(stderr, "MD5: failed to read %s\n", file1);
        return 1;
            }

            if (opus_md5_file(file2, h2) != true) {
                fprintf(stderr, "MD5: failed to read %s\n", file2);
        return 1;
            }

            if (strcasecmp(h1, h2) == 0) {
                printf("MD5 MATCH\n");
                return 0;
            }

            printf("MD5 DIFFER\n");
            printf("  %s: %s\n", file1, h1);
            printf("  %s: %s\n", file2, h2);
            return 1;
        }

        const char *path = argv[cli->arg_start];

        if (opus_md5_file(path, digest) == true) {
            printf("MD5(%s) = %s\n", path, digest);
            return 0;
        }

        fprintf(stderr, "MD5: failed to read %s\n", path);
        return 1;
        
    }
    else if (strcasecmp(cmd, "SHA256") == 0) {
        return opus_cmd_sha256(argc - cli->arg_start + 1,
                               argv + cli->arg_start - 1); 
    }
    else if (strcasecmp(cmd, "ENTROPY") == 0) {
        return cmd_entropy(cli, argc, argv);

    } else if (strcasecmp(cmd, "ELFINFO") == 0) {
        return cmd_binary(cli, argc, argv);

    } else if (strcasecmp(cmd, "DESIG") == 0) {
        return cmd_desig(cli, argc, argv);
} else if (strcasecmp(cmd, "LYZER") == 0) {
    if (cli->arg_start >= argc) {
        fprintf(stderr, "ERROR: lyzer requires a file path\n");
        fprintf(stderr, "Usage: k1wi lyzer <file> [H|R|E|C|S|J|D|ALL|--summary|--quiet|--json|--full|--verbose]\n");
        return 1;
    }

   	const char *path = argv[cli->arg_start];
	const char *mode = "SUMMARY";

	if (cli->arg_start + 1 < argc) {
	    mode = argv[cli->arg_start + 1];

	    if (strcasecmp(mode, "--full") == 0 ||
		strcasecmp(mode, "full") == 0 ||
		strcasecmp(mode, "--verbose") == 0 ||
		strcasecmp(mode, "verbose") == 0) {
		mode = "ALL";
	    } else if (strcasecmp(mode, "--summary") == 0 ||
		       strcasecmp(mode, "summary") == 0) {
		mode = "SUMMARY";
	    } else if (strcasecmp(mode, "--quiet") == 0 ||
               strcasecmp(mode, "quiet") == 0) {
        mode = "QUIET";
    } else if (strcasecmp(mode, "--json") == 0 ||
               strcasecmp(mode, "json") == 0) {
        mode = "JSON";
    }
	 }

	return opus_lyzer_file(path, mode);
    } else if (strcasecmp(cmd, "WIPEFS") == 0) {
        return cmd_wipefs(cli, argc, argv);

    } else if (strcasecmp(cmd, "HELP") == 0) {
        return cmd_help(cli, argc, argv);

   } else if (strcasecmp(cmd, "READ") == 0) {
       if (cli->arg_start >= argc) {
        fprintf(stderr, "Usage: k1wi READ <file>\n");
        return 1;
    }

    const char *path = argv[cli->arg_start];

    return opus_read_file(path,
                          true,      /* raw */
                          false,     /* structured */
                          false,     /* safe */
                          0,         /* limit */
                          0,         /* offset */
                          64,        /* page size */
                          true,      /* ascii */
                          true,      /* hex */
                          NULL,      /* force format */
                          false,     /* verbose */
                          false);    /* summary */

    } else if (strcasecmp(cmd, "VERSION") == 0 ||
               strcasecmp(cmd, "--VERSION") == 0) {
        return cmd_version(cli, argc, argv);

   } else if (strcasecmp(cmd, "SEARCH") == 0) {
    return cmd_search(argc -1, argv + 1);
   
    } else if (strcasecmp(cmd, "PIECALC") == 0) {
        return cmd_piecalc(NULL, argc, argv);

    } else if (strcasecmp(cmd, "PIETIME") == 0) {
	return opus_pie_time_cli(argc - cli->arg_start,
		argv + cli->arg_start);
    }
    else if (strcasecmp(cmd, "MAGIC") == 0) {
        if (cli->arg_start >= argc) {
            fprintf(stderr, "Usage: k1wi magic <file>\n");
            return 1;
        }

        detect_magic(argv[cli->arg_start]);
        return 0;

    
	    
	} else if (strcasecmp(cmd, "RSA-SMALL-E") == 0) {
	    if (cli->arg_start >= argc) {
		fprintf(stderr, "Usage: k1wi RSA-SMALL-E <rsa_file>\n");
		return 1;
	    }

	    const char *path = argv[cli->arg_start];

	    mpz_t N, e, c, m;
	    mpz_inits(N, e, c, m, NULL);

	    if (parse_rsa_file(path, N, e, c) != 0) {
		printf("rsa-small-e: failed to parse RSA file\n");
		mpz_clears(N, e, c, m, NULL);
		return 1;
	    }

	    unsigned long e_ul = mpz_get_ui(e);

	    printf("[*] RSA-SMALL-E: checking for small exponent attack (e = %lu)\n", e_ul);

	    if (e_ul == 0 || e_ul > 64) {
		printf("[-] RSA-SMALL-E: exponent too large or invalid\n");
		mpz_clears(N, e, c, m, NULL);
		return 1;
	    }

	    if (rsa_small_e_attack(m, c, e_ul)) {
		printf("[+] RSA-SMALL-E: recovered plaintext via integer %lu-th root\n", e_ul);
		opus_print_plaintext_from_bigint(m);
		mpz_clears(N, e, c, m, NULL);
		return 0;
	    }

	    printf("[-] RSA-SMALL-E: attack not applicable (no exact root)\n");
	    mpz_clears(N, e, c, m, NULL);
	    return 1;

	} else if (strcasecmp(cmd, "RSA-ROOTS") == 0) {
		if (cli->arg_start >= argc) {
			fprintf(stderr, "Usage: k1wi RSA-ROOTS <rsa_file>\n");
			return 1;
		}

		const char *path = argv[cli->arg_start];

		mpz_t N, e, c, m;
		mpz_inits(N, e, c, m, NULL);

		if (parse_rsa_file(path, N, e, c) != 0) {
			printf("rsa-roots: failed to parse RSA file\n");
			mpz_clears(N, e, c, m, NULL);
			return 1;
		}

		unsigned long e_ul = mpz_get_ui(e);

		printf("[*] RSA-ROOTS: checking exact integer root path\n");
		gmp_printf("[*] N = %Zd\n", N);
		gmp_printf("[*] e = %Zd\n", e);
		gmp_printf("[*] c = %Zd\n", c);

		if (mpz_even_p(e)) {
			printf("[!] RSA-ROOTS: even public exponent detected\n");
			printf("[!] RSA-ROOTS: normal RSA private exponent may not exist if gcd(e, phi(n)) != 1\n");
		}

		if (e_ul == 0 || e_ul > 64 || mpz_cmp_ui(e, e_ul) != 0) {
			printf("[-] RSA-ROOTS: exponent too large or invalid for exact integer root helper\n");
			printf("[*] RSA-ROOTS: modular root support with known p/q is planned for a later expansion\n");
			mpz_clears(N, e, c, m, NULL);
			return 1;
		}

		if (rsa_small_e_attack(m, c, e_ul)) {
			printf("[+] RSA-ROOTS: recovered plaintext via exact integer %lu-th root\n", e_ul);
			opus_print_plaintext_from_bigint(m);
			mpz_clears(N, e, c, m, NULL);
			return 0;
		}

		printf("[-] RSA-ROOTS: no exact integer %lu-th root found\n", e_ul);
		printf("[*] RSA-ROOTS: if p and q are known, modular root recovery may still be possible\n");

		mpz_clears(N, e, c, m, NULL);
		return 1;

	} else if (strcasecmp(cmd, "RSA-WIENER") == 0) {
	    if (cli->arg_start >= argc) {
		fprintf(stderr, "Usage: k1wi RSA-WIENER <rsa_file>\n");
		return 1;
	    }

    const char *path = argv[cli->arg_start];

    printf("[*] Input file: %s\n", path);

    mpz_t N, e, c, d, m;
    mpz_inits(N, e, c, d, m, NULL);

    if (parse_rsa_file(path, N, e, c) != 0) {
        printf("rsa-wiener: failed to parse RSA file\n");
        mpz_clears(N, e, c, d, m, NULL);
        return 1;
    }

    printf("[*] RSA-WIENER: starting Wiener attack\n");

    if (opus_rsa_wiener_attack(N, e, d) != 0) {
        printf("[-] RSA-WIENER: Wiener attack failed (d not small)\n");
        mpz_clears(N, e, c, d, m, NULL);
        return 1;
    }

    printf("[+] RSA-WIENER: recovered d\n");

    mpz_powm(m, c, d, N);
    opus_print_plaintext_from_bigint(m);
    putchar('\n');

    mpz_clears(N, e, c, d, m, NULL);
    return 0;
	} 
        else if (strcasecmp(cmd, "RSA-FACTOR") == 0) {
          if (cli->arg_start >= argc) {
            fprintf(stderr, "Usage: k1wi RSA-FACTOR <rsa_file> [TIME <minutes>|--time <minutes>|--minutes <minutes>|-t <minutes>]\n");
            return 1;
        }

        unsigned long time_limit_minutes = 0;

        if (cli->arg_start + 1 < argc) {
            const char *opt = argv[cli->arg_start + 1];

            if (cli->arg_start + 2 >= argc) {
                fprintf(stderr, "Usage: k1wi RSA-FACTOR <rsa_file> [TIME <minutes>|--time <minutes>|--minutes <minutes>|-t <minutes>]\n");
        return 1;
            }

            if (strcasecmp(opt, "TIME") == 0 ||
                strcasecmp(opt, "--time") == 0 ||
                strcasecmp(opt, "--minutes") == 0 ||
                strcasecmp(opt, "-t") == 0) {
                char *end = NULL;
                time_limit_minutes = strtoul(argv[cli->arg_start + 2], &end, 10);

                if (end == argv[cli->arg_start + 2] || *end != '\0' || time_limit_minutes == 0) {
                    fprintf(stderr, "rsa-factor: time limit must be a positive number of minutes\n");
            return 1;
                }
            } else {
                fprintf(stderr, "rsa-factor: unknown option '%s'\n", opt);
                fprintf(stderr, "Usage: k1wi RSA-FACTOR <rsa_file> [TIME <minutes>|--time <minutes>|--minutes <minutes>|-t <minutes>]\n");
        return 1;
            }
        }

        if (opus_rsa_factor_with_time(argv[cli->arg_start], time_limit_minutes)) {
            return 0;
        }

        return 1;

   } else if (strcasecmp(cmd, "RSA-KNOWNPQ") == 0) {
    if (cli->arg_start + 2 >= argc) {
        fprintf(stderr, "Usage: k1wi RSA-KNOWNPQ <rsa_file> <p> <q>\n");
        return 1;
    }

    const char *path = argv[cli->arg_start];
    const char *p_str = argv[cli->arg_start + 1];
    const char *q_str = argv[cli->arg_start + 2];

    printf("[*] RSA-KNOWNPQ: starting known-pq decryption\n");

    if (opus_rsa_knownpq(path, p_str, q_str)) {
        printf("rsa-knownpq: success\n");
        return 0;
    }

    printf("rsa-knownpq: failed\n");
    return 1;
    
    } else if (strcasecmp(cmd, "RSA-CHECKPQ") == 0) {
    if (cli->arg_start + 1 >= argc) {
        fprintf(stderr, "Usage: k1wi RSA-CHECKPQ <p> <q>\n");
        return 1;
    }

    return opus_rsa_checkpq(argv[cli->arg_start],
                            argv[cli->arg_start + 1]) ? 0 : 1;
    
    
    } else if (strcasecmp(cmd, "RSA-DFROMPQ") == 0) {

    if (cli->arg_start + 2 >= argc) {
        fprintf(stderr,
                "Usage: k1wi RSA-DFROMPQ <p> <q> <e>\n");
        return 1;
    }

    return opus_rsa_dfrompq(argv[cli->arg_start],
                            argv[cli->arg_start + 1],
                            argv[cli->arg_start + 2]) ? 0 : 1;
    
    
    
    } else if (strcasecmp(cmd, "RSA-ECM") == 0) {
    if (cli->arg_start >= argc) {
        fprintf(stderr, "Usage: k1wi RSA-ECM <rsa_file> [--curves N] [--bound N]\n");
        return 1;
    }

    const char *path = argv[cli->arg_start];
    unsigned long curves = 20;
    unsigned long bound = 5000;

    for (int i = cli->arg_start + 1; i < argc; i++) {
        const char *opt = argv[i];

        if (strcasecmp(opt, "--curves") == 0 ||
            strcasecmp(opt, "CURVES") == 0 ||
            strcasecmp(opt, "-c") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "rsa-ecm: --curves requires a positive number\n");
        return 1;
            }

            char *endptr = NULL;
            curves = strtoul(argv[++i], &endptr, 10);

            if (endptr == argv[i] || *endptr != '\0' || curves == 0) {
                fprintf(stderr, "rsa-ecm: --curves requires a positive number\n");
        return 1;
            }
        } else if (strcasecmp(opt, "--bound") == 0 ||
                   strcasecmp(opt, "--b1") == 0 ||
                   strcasecmp(opt, "BOUND") == 0 ||
                   strcasecmp(opt, "B1") == 0 ||
                   strcasecmp(opt, "-b") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "rsa-ecm: --bound requires a positive number\n");
        return 1;
            }

            char *endptr = NULL;
            bound = strtoul(argv[++i], &endptr, 10);

            if (endptr == argv[i] || *endptr != '\0' || bound == 0) {
                fprintf(stderr, "rsa-ecm: --bound requires a positive number\n");
        return 1;
            }
        } else {
            fprintf(stderr, "rsa-ecm: unknown option '%s'\n", opt);
            fprintf(stderr, "Usage: k1wi RSA-ECM <rsa_file> [--curves N] [--bound N]\n");
            return 1;
        }
    }

    const char *path_for_parse = path;

    mpz_t N, e, c, f, q;
    mpz_inits(N, e, c, f, q, NULL);

    if (parse_rsa_file(path_for_parse, N, e, c) != 0) {
        printf("rsa-ecm: failed to parse RSA file\n");
        mpz_clears(N, e, c, f, q, NULL);
        return 1;
    }

    printf("[*] RSA-ECM: starting ECM factorization\n");
    printf("[*] RSA-ECM: curves=%lu, B1=%lu\n", curves, bound);

    if (!opus_rsa_ecm_factor_with_bounds(N, f, curves, bound)) {
        printf("[-] RSA-ECM: no factor found after %lu curve(s) with B1=%lu\n", curves, bound);
        mpz_clears(N, e, c, f, q, NULL);
        return 1;
    }

    if (mpz_cmp_ui(f, 1) <= 0 || mpz_cmp(f, N) >= 0 || !mpz_divisible_p(N, f)) {
        gmp_printf("[-] RSA-ECM: rejected invalid factor candidate f = %Zd\n", f);
        mpz_clears(N, e, c, f, q, NULL);
        return 1;
    }

    mpz_divexact(q, N, f);

    gmp_printf("[+] RSA-ECM: found factor f = %Zd\n", f);
    gmp_printf("[+] RSA-ECM: cofactor q = %Zd\n", q);

	mpz_clears(N, e, c, f, q, NULL);
	return 0;

    } else if (strcasecmp(cmd, "RSA-RHO") == 0) {

    if (cli->arg_start >= argc) {
        fprintf(stderr,
                "Usage: k1wi RSA-RHO <rsa_file>\n");
        return 1;
    }

    return opus_rsa_rho(argv[cli->arg_start]) ? 0 : 1;
    
    } else if (strcasecmp(cmd, "RSA-MINI") == 0) {
    if (cli->arg_start >= argc) {
        fprintf(stderr, "Usage: k1wi RSA-MINI <rsa_file>\n");
        return 1;
    }

    return opus_mini_rsa(argv[cli->arg_start]) ? 0 : 1;
    
    } else if (strcasecmp(cmd, "COPY") == 0) {
    if (cli->arg_start + 1 >= argc) {
        fprintf(stderr, "Usage: k1wi COPY <src> <dst>\n");
        return 1;
    }

    const char *src = argv[cli->arg_start];
    const char *dst = argv[cli->arg_start + 1];

    int rc = opus_file_copy(src, dst);

    if (rc == 0) {
        printf("COPY: success\n");
        return 0;
    }

    printf("COPY: failed\n");
    return 1;
    
    } else if (strcasecmp(cmd, "CREATE") == 0) {
    if (cli->arg_start >= argc) {
        fprintf(stderr, "Usage: k1wi CREATE <filename>\n");
        return 1;
    }

    return fileCreate(argv[cli->arg_start]) == 0 ? 0 : 1;
    
    
    
    } else if (strcasecmp(cmd, "DEL") == 0) {
    if (cli->arg_start >= argc) {
        fprintf(stderr, "Usage: k1wi DEL <file> [-s 1|2] [-y]\n");
        return 1;
    }

    char args_buf[4096] = {0};

    for (int i = cli->arg_start; i < argc; i++) {
        if (i > cli->arg_start) {
            strncat(args_buf, " ", sizeof(args_buf) - strlen(args_buf) - 1);
        }

        strncat(args_buf, argv[i], sizeof(args_buf) - strlen(args_buf) - 1);
    }

    fileDeleteCmd(args_buf);
    return 0;
    
    }
    

    else if (strcasecmp(cmd, "AUTO") == 0) {
        if (cli->arg_start >= argc) {
            fprintf(stderr, "Usage: k1wi AUTO <file>\n");
            return 1;
        }

        return k1wi_auto_analyze_file(argv[cli->arg_start]);
    }

    else if (strcasecmp(cmd, "TIME") == 0) {
        systemTime();
        return 0;
	   } else if (strcasecmp(cmd, "SPLASH") == 0) {
	    opus_banner();
	    return 0;
		   	   
	   } else if (strcasecmp(cmd, "ABOUT") == 0) {
	    return cmd_about(NULL, argc, argv);

	  } else if (strcasecmp(cmd, "MENU") == 0) {
	    return cmd_menu(NULL, argc, argv);

	} else if (strcasecmp(cmd, "EXIT") == 0) {
	    return cmd_exit(NULL, argc, argv);
	}
	
	fprintf(stderr, "ERROR: Unknown command '%s'\n", cmd);
	fprintf(stderr, "Try: k1wi help\n");
	return 1;
}

int opus_cli_main(int argc, char **argv) {
    OpusCLI cli;

    if (!opus_cli_parse(&cli, argc, argv)) {
        if (argc == 1) {
            return opus_repl();
        } else {
            return 1;
        }
    }

    if (!cli.command) {
        return opus_repl();
    }

    return opus_cli_dispatch(&cli, argc, argv);
}

