CC = gcc
CFLAGS = -std=gnu99 -Wall -Werror -Iinclude
LDFLAGS_SSL = -lssl -lcrypto
DOCKER_RUN = docker compose -f docker-compose-dev.yml run --rm --service-ports webserver

# Main server sources
SRC = src/main.c \
      src/server.c \
      src/http.c \
      src/static_file.c \
      src/connection.c \
      src/ssl_handler.c \
      src/request_handler.c \
      src/utils/string_hashmap.c \
      src/utils/string_builder.c

# Shared test dependencies
TEST_UTILS = src/utils/string_hashmap.c src/utils/string_builder.c

# Test sources
TESTS_HTTP = tests/test_http.c \
             src/http.c \
             src/static_file.c \
             $(TEST_UTILS)

TESTS_STATIC = tests/test_static_file.c \
               src/static_file.c \
               src/http.c \
               $(TEST_UTILS)

TESTS_REQUEST_HANDLER = tests/test_request_handler.c \
                        src/request_handler.c \
                        src/http.c \
                        src/static_file.c \
                        src/connection.c \
                        src/ssl_handler.c \
                        $(TEST_UTILS)

# Output binaries
OUT = webserver
TEST_HTTP_OUT = test_http
TEST_STATIC_OUT = test_static_file
TEST_REQUEST_HANDLER_OUT = test_request_handler

# Build targets
all:
	$(CC) $(SRC) -o $(OUT) $(CFLAGS) $(LDFLAGS_SSL)

# Individual test compilation (native - for use inside Docker)
test-http:
	$(CC) $(TESTS_HTTP) -o $(TEST_HTTP_OUT) $(CFLAGS)

test-static:
	$(CC) $(TESTS_STATIC) -o $(TEST_STATIC_OUT) $(CFLAGS)

test-request-handler:
	$(CC) $(TESTS_REQUEST_HANDLER) -o $(TEST_REQUEST_HANDLER_OUT) $(CFLAGS) $(LDFLAGS_SSL)

# Compile all tests (native)
test: test-http test-static test-request-handler

# Build Docker image
build:
	docker compose -f docker-compose-dev.yml build

# Run server in Docker
run:
	docker compose -f docker-compose-dev.yml up

# Rebuild and run
run-rebuild:
	docker compose -f docker-compose-dev.yml up --build

# Run tests in Docker (recommended)
test-run:
	$(DOCKER_RUN) sh -c "make clean && make test && ./$(TEST_HTTP_OUT) && ./$(TEST_STATIC_OUT) && ./$(TEST_REQUEST_HANDLER_OUT)"

test-http-run:
	$(DOCKER_RUN) sh -c "make test-http && ./$(TEST_HTTP_OUT)"

test-static-run:
	$(DOCKER_RUN) sh -c "make test-static && ./$(TEST_STATIC_OUT)"

test-request-handler-run:
	$(DOCKER_RUN) sh -c "make test-request-handler && ./$(TEST_REQUEST_HANDLER_OUT)"

# Cleanup
clean:
	rm -f $(OUT) $(TEST_HTTP_OUT) $(TEST_STATIC_OUT) $(TEST_REQUEST_HANDLER_OUT)

.PHONY: all run run-rebuild build clean test test-http test-static test-request-handler \
        test-run test-http-run test-static-run test-request-handler-run
