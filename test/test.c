#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef struct Options {
    uint64_t nfiles;
} Options;

static Options *parse_options(int argc, char *const argv[]);

int main(int argc, char *const argv[]) {

    Options *options = parse_options(argc, argv);
    long nfiles = options->nfiles;

    char namebuf[64];
    struct timespec ts0, ts1;
    double sec;
    struct stat statbuf;
    timespec_get(&ts0, TIME_UTC);

    for (int i = 0; i < nfiles; ++i) {
        sprintf(namebuf, "mop%d.f", i);
        close(creat(namebuf, O_RDWR));
    }

    timespec_get(&ts1, TIME_UTC);
    sec = ts1.tv_sec - ts0.tv_sec + (ts1.tv_nsec - ts0.tv_nsec) * 1E-9;

    printf("Took approx. %.3f seconds to create %ld files\n", sec, nfiles);

    timespec_get(&ts0, TIME_UTC);

    for (int i = 0; i < nfiles; ++i) {
        sprintf(namebuf, "mop%d.f", i);
        stat(namebuf, &statbuf);
    }

    timespec_get(&ts1, TIME_UTC);
    sec = ts1.tv_sec - ts0.tv_sec + (ts1.tv_nsec - ts0.tv_nsec) * 1E-9;

    printf("Took approx. %.3f seconds to stat %ld files\n", sec, nfiles);

    return 0;
}

static Options *parse_options(int argc, char *const argv[]) {
    Options *options = malloc(sizeof(Options));
    if (options == NULL)
        exit(EXIT_FAILURE);

    int opt;
    while ((opt = getopt(argc, argv, "N:")) != -1)
        switch (opt) {
        case 'N':
            options->nfiles = strtol(optarg, NULL, 0);
            break;
        default:
            fprintf(stderr, "Usage: %s -N nfiles\n", argv[0]);
            exit(EXIT_FAILURE);
        }

    return options;
}
