CFLAGS =  -g -Wall -pedantic -pthread
LDFLAGS = -pthread

.phony: all clean

all: safelock-example

safelock-example: safelock-example.o safelock.o

clean:
	rm -f safelock-example *.o
