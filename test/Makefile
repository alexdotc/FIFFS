binout = testfiffs
compiler = gcc
flags := $(compiler) -Wall -Werror -std=c11 -O2

default: test.o
	$(flags) test.o -o $(binout)

test.o: test.c
	$(flags) -c test.c

