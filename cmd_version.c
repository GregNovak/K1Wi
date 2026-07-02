#include <stdio.h>
#include "cli.h"
#include "version.h"

int cmd_version(const OpusCLI *cli, int argc, char **argv)
{
    (void)cli;
    (void)argc;
    (void)argv;

    printf("%s v%s\n", OPUS_FRAMEWORK, OPUS_VERSION);
    printf("Release Name: %s\n", OPUS_RELEASE_NAME);
    printf("Build Date: %s\n", OPUS_BUILD_DATE);
    printf("Build Time: %s\n", OPUS_BUILD_TIME);
    printf("Integrated Reverse Engineering and Cryptanalysis Framework\n\n");

    return 0;
}
