CFLAGS=-g -O0 -fPIE -Wall -Wextra
LDFLAGS=-lcap -lseccomp

all: ns

ns: ns.o
	$(CC) $^ $(LDFLAGS) -o $@

