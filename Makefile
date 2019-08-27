CFLAGS=-g -O0 -fPIE -Wall -Wextra
LDFLAGS=-lcap -lseccomp

all: ns ns-debug ns-persistent

clean:
	rm -rf *.o
	rm -rf ns ns-debug ns-persistent

ns: ns.o
	$(CC) $^ $(LDFLAGS) -o $@

ns-debug: ns-debug.o
	$(CC) $^ $(LDFLAGS) -o $@

ns-debug.o: ns.c
	$(CC) -c $^ $(CFLAGS) -DDEBUG=1 -o $@

ns-persistent: ns-persistent.o
	$(CC) $^ $(LDFLAGS) -o $@

ns-persistent.o: ns.c
	$(CC) -c $^ $(CFLAGS) -DDEBUG=1 -DROOTFS_PERSISTENT=1 -DUSE_TINI=0 -o $@

install: all
	cp ns /usr/bin/ssh2container
	mkdir -p /var/lib/ssh2container

uninstall:
	rm -f /usr/bin/ssh2container
