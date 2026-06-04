#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "solver.h"      // for run_solver()
#include "cipher_io.h"

int run_solver_from_opus(const char *cipher_path, const char *forced_spec)
{
    if (!cipher_path) {
        fprintf(stderr, "[solver] No ciphertext file provided.\n");
        return -1;
    }

    printf("Launching old solver on '%s'...\n", cipher_path);

    // Use the old solver’s quadgram file
    const char *quadfile = "english_quadgrams.txt";

    // Old solver parameters (you can expose these later)
    int restarts   = 25;
    int iterations = 20000;

    int r = run_solver(cipher_path, quadfile, forced_spec, restarts, iterations);

    if (r != 0) {
        printf("[!] Solver reported an error.\n");
    }

    return r;
}




// ------------------------------------------------------------
// opus_run_solver
// ------------------------------------------------------------
// Legacy wrapper used by older parts of Opus.
// Now simply prints an error because the REPL should call
// run_solver_from_opus(cipherfile, forced_spec).
// ------------------------------------------------------------
void opus_run_solver(void)
{
    printf("opus_run_solver() is deprecated.\n");
    printf("Use: solve <cipherfile> [forced_spec]\n");
}

