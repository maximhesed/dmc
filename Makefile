CC = gcc -m32
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lncurses -lm -g
OBJS = main.o
BINNAME = prog

.PHONY: all
all: $(OBJS)
	@$(CC) $(LDFLAGS) -o $(BINNAME) $^

%.o: %.c
	@$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean
clean:
	@rm -f $(BINNAME) *.o
