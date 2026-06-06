#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include "cli.h"
#include "rsa_factor.h"
#include "md5.h"


typedef struct opus_context opus_context;


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

    if (strcmp(cmd, "EXTRACT") == 0) {
        return cmd_extract(cli, argc, argv);

    } else if (strcmp(cmd, "STRING") == 0) {
        return cmd_string(argc - cli->arg_start + 1, argv + cli->arg_start - 1);
       
        } else if (strcmp(cmd, "MD5") == 0) {
        if (cli->arg_start >= argc) {
            fprintf(stderr, "Usage: opus md5 <file>\n");
            fprintf(stderr, "       opus md5 -in <file>\n");
            fprintf(stderr, "       opus md5 -verify <file> <hash>\n");
            fprintf(stderr, "       opus md5 -compare <file1> <file2>\n");
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
    else if (strcmp(cmd, "SHA256") == 0) {
        return opus_cmd_sha256(argc - cli->arg_start + 1,
                               argv + cli->arg_start - 1); 
    }
    else if (strcmp(cmd, "ENTROPY") == 0) {
        return cmd_entropy(cli, argc, argv);

    } else if (strcmp(cmd, "ELFINFO") == 0) {
        return cmd_binary(cli, argc, argv);

    } else if (strcmp(cmd, "DESIG") == 0) {
        return cmd_desig(cli, argc, argv);
} else if (strcmp(cmd, "LYZER") == 0) {
    if (cli->arg_start >= argc) {
        fprintf(stderr, "ERROR: lyzer requires a file path\n");
        fprintf(stderr, "Usage: opus lyzer <file> [H|R|E|C|S|J|D|ALL]\n");
        return 1;
    }

    const char *path = argv[cli->arg_start];
    const char *mode = "ALL";

    if (cli->arg_start + 1 < argc) {
        mode = argv[cli->arg_start + 1];
    }

    return opus_lyzer_file(path, mode);
    } else if (strcmp(cmd, "WIPEFS") == 0) {
        return cmd_wipefs(cli, argc, argv);

    } else if (strcmp(cmd, "HELP") == 0) {
        return cmd_help(cli, argc, argv);

    } else if (strcmp(cmd, "VERSION") == 0 ||
               strcmp(cmd, "--VERSION") == 0) {
        return cmd_version(cli, argc, argv);

    } else if (strcmp(cmd, "PIECALC") == 0) {
        return cmd_piecalc(NULL, argc, argv);

    } else if (strcmp(cmd, "PIETIME") == 0) {
	return opus_pie_time_cli(argc - cli->arg_start,
		argv + cli->arg_start);
    }
    else if (strcmp(cmd, "MAGIC") == 0) {
        if (cli->arg_start >= argc) {
            fprintf(stderr, "Usage: opus magic <file>\n");
            return 1;
        }

        detect_magic(argv[cli->arg_start]);
        return 0;

    } else if (strcmp(cmd, "RSA-FACTOR") == 0) {
        if (cli->arg_start >= argc) {
            fprintf(stderr, "Usage: opus rsa-factor <rsa_file>\n");
            return 1;
        }

        return opus_rsa_factor(argv[cli->arg_start]);

    } else if (strcmp(cmd, "TIME") == 0) {
        systemTime();
        return 0;
	   } else if (strcmp(cmd, "SPLASH") == 0) {
	    opus_banner();
	    return 0;
		   	   
	   } else if (strcmp(cmd, "ABOUT") == 0) {
	    return cmd_about(NULL, argc, argv);

	  } else if (strcmp(cmd, "MENU") == 0) {
	    return cmd_menu(NULL, argc, argv);

	} else if (strcmp(cmd, "EXIT") == 0) {
	    return cmd_exit(NULL, argc, argv);
	}
	
	fprintf(stderr, "ERROR: Unknown command '%s'\n", cmd);
	fprintf(stderr, "Try: opus help\n");
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

