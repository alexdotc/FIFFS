#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

typedef struct Options{
    uint64_t nfiles;
} Options;

static Options* parse_options(int argc, char *const argv[]);

int main(int argc, char *const argv[]){

    Options* options = parse_options(argc, argv);
    long nfiles = options->nfiles;

    char namebuf[64];
    struct timespec ts0;
    struct timespec ts1;
    time_t sec;
    struct stat statbuf;
    clock_gettime(CLOCK_REALTIME, &ts0);

    for (int i = 0; i < nfiles; ++i){
        sprintf(namebuf, "mop%d.f", i);
        creat(namebuf, O_RDWR);
    }

    clock_gettime(CLOCK_REALTIME, &ts1);
    sec = ts1.tv_sec - ts0.tv_sec;

    printf("Took approx. %ld seconds to create %ld files\n", sec, nfiles); 

    clock_gettime(CLOCK_REALTIME, &ts0);

    for (int i = 0; i < nfiles; ++i){
        sprintf(namebuf, "mop%d.f", i);
        stat(namebuf, &statbuf);
    }

    clock_gettime(CLOCK_REALTIME, &ts1);
    sec = ts1.tv_sec - ts0.tv_sec;

    printf("Took approx. %ld seconds to stat %ld files\n", sec, nfiles); 

    return 0;
}

static Options* parse_options(int argc, char *const argv[]){
    Options *options = malloc(sizeof(Options));
    if (options == NULL) exit(EXIT_FAILURE);

    int opt;
    while((opt = getopt(argc, argv, "N:")) != -1)
    switch(opt){
        case 'N': options->nfiles = strtol(optarg, NULL, 0); break;
        default: fprintf(stderr, "Usage: %s -N nfiles\n", argv[0]); exit(EXIT_FAILURE);
    }

    return options;
}
