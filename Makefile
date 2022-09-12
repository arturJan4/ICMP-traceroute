CC = gcc -g

#DEBUGFLAGS = -fsanitize=address -fsanitize=leak -fsanitize=undefined -static-libasan

CFLAGS = -O2 -std=gnu17 -Wall -Wextra -Werror $(DEBUGFLAGS)

OBJS = main.o send.o receive.o

all: traceroute

traceroute: $(OBJS)
	$(CC) $(CFLAGS) -o traceroute $(OBJS)

send.o: send.c send.h
receive.o: receive.c receive.h

SRC_C = $(wildcard *.c)
SRC_H = $(wildcard *.h)

clean:
	rm -f *.o

distclean:
	rm -f *.o traceroute

format:
	clang-format --style=Google -i $(SRC_C) $(SRC_H)