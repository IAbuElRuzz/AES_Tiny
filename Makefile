CC = gcc
CFLAGS = -Wall -O3 -fPIC
LIBS = -shared -lssl -lcrypto

OBJS = aes256.o

all: libaes256.so

libaes256.so: $(OBJS)
	$(CC) $(CFLAGS) -o libaes256.so $(OBJS) $(LIBS)

aes256.o: aes256.c aes256.h
	$(CC) $(CFLAGS) -c aes256.c

clean:
	rm -f $(OBJS) libaes256.so

.PHONY: all clean
