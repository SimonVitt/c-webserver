CC = clang
CFLAGS = -std=c99 -Wall -Werror -Iinclude
SRC = src/main.c src/server.c src/http.c src/utils/string_hashmap.c src/utils/string_builder.c
TESTS = tests/test_http.c src/http.c src/utils/string_hashmap.c src/utils/string_builder.c

OUT = webserver
TEST_OUT = test_webserver

all:
	$(CC) $(SRC) -o $(OUT) $(CFLAGS)

test:
	$(CC) $(TESTS) -o $(TEST_OUT) $(CFLAGS)

run: all
	./$(OUT)

test-run: test
	./$(TEST_OUT)

clean:
	rm -f $(OUT)

.PHONY: all run clean test test-run
