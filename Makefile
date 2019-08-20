CFLAGS=-g -O0 -fPIE -Wall -Wextra
LDFLAGS=-lcap -lseccomp

all: ns ns-debug

ns: ns.o
	$(CC) $^ $(LDFLAGS) -o $@

ns-debug: ns-debug.o
	$(CC) $^ $(LDFLAGS) -o $@

ns-debug.o: ns.c
	$(CC) -c $^ $(CFLAGS) -DDEBUG=1 -o $@
