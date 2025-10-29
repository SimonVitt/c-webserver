CC = clang
CFLAGS = -std=c99 -Wall -Werror
SRC = src/main.c src/server.c
OUT = webserver

all:
	$(CC) $(SRC) -o $(OUT) $(CFLAGS)

run: all
	./$(OUT)

clean:
	rm -f $(OUT)

.PHONY: all run clean
