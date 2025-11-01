CC = clang
CFLAGS = -std=c99 -Wall -Werror -Iinclude
SRC = src/main.c src/server.c src/http.c src/utils/string_hashmap.c src/utils/string_builder.c src/static_file.c
TESTS_HTTP = tests/test_http.c src/http.c src/utils/string_hashmap.c src/utils/string_builder.c src/static_file.c
TESTS_STATIC = tests/test_static_file.c src/static_file.c src/http.c src/utils/string_hashmap.c src/utils/string_builder.c

OUT = webserver
TEST_HTTP_OUT = test_http
TEST_STATIC_OUT = test_static_file

all:
	$(CC) $(SRC) -o $(OUT) $(CFLAGS)

test-http:
	$(CC) $(TESTS_HTTP) -o $(TEST_HTTP_OUT) $(CFLAGS)

test-static:
	$(CC) $(TESTS_STATIC) -o $(TEST_STATIC_OUT) $(CFLAGS)

test: test-http test-static

run: all
	./$(OUT)

test-http-run: test-http
	./$(TEST_HTTP_OUT)

test-static-run: test-static
	./$(TEST_STATIC_OUT)

test-run: test-http-run test-static-run

clean:
	rm -f $(OUT) $(TEST_HTTP_OUT) $(TEST_STATIC_OUT)

.PHONY: all run clean test test-http test-static test-run test-http-run test-static-run
