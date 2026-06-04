#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cli.h"

typedef struct opus_context opus_context;

int opus_lyzer_file(const char *path, const char *mode);
int cmd_rsa(int argc, char **argv);
int cmd_about(opus_context *ctx, int argc, char **argv);
int cmd_piecalc(opus_context *ctx, int argc, char **argv);


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
    const char *cmd = cli->command;

    if (strcmp(cmd, "extract") == 0) {
        return cmd_extract(cli, argc, argv);

    } else if (strcmp(cmd, "string") == 0) {
        return cmd_string(argc - cli->arg_start + 1, argv + cli->arg_start - 1);

    } else if (strcmp(cmd, "entropy") == 0) {
        return cmd_entropy(cli, argc, argv);

    } else if (strcmp(cmd, "crypto") == 0) {
        return cmd_crypto(cli, argc, argv);

    } else if (strcmp(cmd, "binary") == 0 ||
           strcmp(cmd, "elf") == 0) {
        return cmd_binary(cli, argc, argv);

    } else if (strcmp(cmd, "desig") == 0) {
        return cmd_desig(cli, argc, argv);
} else if (strcmp(cmd, "lyzer") == 0) {
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
    } else if (strcmp(cmd, "wipefs") == 0) {
        return cmd_wipefs(cli, argc, argv);

    } else if (strcmp(cmd, "help") == 0) {
        return cmd_help(cli, argc, argv);

    } else if (strcmp(cmd, "version") == 0 ||
               strcmp(cmd, "--version") == 0) {
        return cmd_version(cli, argc, argv);

    } else if (strcmp(cmd, "piecalc") == 0 ||
               strcmp(cmd, "PIECALC") == 0) {
        return cmd_piecalc(NULL, argc, argv);
    } else if (strcmp(cmd, "rsa") == 0 ||
               strcmp(cmd, "RSA") == 0) {
        return cmd_rsa(argc - cli->arg_start + 1,
                       argv + cli->arg_start - 1);
        
    
	} else if (strcmp(cmd, "about") == 0 ||
           strcmp(cmd, "ABOUT") == 0) {
	    return cmd_about(NULL, argc, argv);
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

