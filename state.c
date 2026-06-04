#include "state.h"

/*
    Opus state module

    This file is intentionally minimal.

    The solver architecture keeps all logic in:
      - solve.c        (orchestration)
      - mutation.c     (key mutation)
      - score.c        (quadgram scoring)
      - logging.c      (instrumentation)

    state.c exists as a dedicated translation unit so that:
      - state.h has a matching .c file
      - future helper functions can be added cleanly
      - the build system remains modular and consistent
*/

