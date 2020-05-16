CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c sslfunctions.c
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)

client: client.o sslfunctions.o
	$(CC) $(LDFLAGS) -o client client.o sslfunctions.o 

server: server.o
	$(CC) $(LDFLAGS) -o server server.o sslfunctions.o


client.o: client.c 
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

sslfunctions.o: sslfunctions.c
	$(CC) $(CFLAGS) -c -o sslfunctions.o  sslfunctions.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

