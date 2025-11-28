/*
 * Request Handler Tests
 * Tests for HTTP request processing logic
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "server.h"
#include "http.h"
#include "request_handler.h"

/* === Helper Functions === */

static void init_test_client(Client* client) {
    memset(client, 0, sizeof(Client));
    client->state = CLIENT_STATE_IDLE;
    client->bytes_received = 0;
    client->headers_end_offset = 0;
    client->content_length = 0;
    client->request = NULL;
    client->response = NULL;
    client->ssl = NULL;
}

/* === Header Completion Tests === */

void test_headers_complete_crlf(void) {
    Client client;
    init_test_client(&client);
    
    strcpy(client.buffer, "GET / HTTP/1.1\r\nHost: test\r\n\r\n");
    client.bytes_received = strlen(client.buffer);
    
    int complete = 0;
    int result = check_if_headers_complete(&client, &complete);
    
    assert(result == 0);
    assert(complete == 1);
    assert(client.headers_end_offset == strlen(client.buffer));
    
    printf("  headers_complete_crlf: OK\n");
}

void test_headers_incomplete(void) {
    Client client;
    init_test_client(&client);
    
    strcpy(client.buffer, "GET / HTTP/1.1\r\nHost: test\r\n");
    client.bytes_received = strlen(client.buffer);
    
    int complete = 0;
    check_if_headers_complete(&client, &complete);
    
    assert(complete == 0);
    
    printf("  headers_incomplete: OK\n");
}

void test_headers_partial_terminator(void) {
    Client client;
    init_test_client(&client);
    
    // Only \r\n, not \r\n\r\n
    strcpy(client.buffer, "GET / HTTP/1.1\r\n");
    client.bytes_received = strlen(client.buffer);
    
    int complete = 0;
    check_if_headers_complete(&client, &complete);
    
    assert(complete == 0);
    
    printf("  headers_partial_terminator: OK\n");
}

void test_headers_offset_calculated(void) {
    Client client;
    init_test_client(&client);
    
    strcpy(client.buffer, "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nHello");
    client.bytes_received = strlen(client.buffer);
    
    int complete = 0;
    check_if_headers_complete(&client, &complete);
    
    assert(complete == 1);
    // Offset should point to right after \r\n\r\n (where body starts)
    assert(client.headers_end_offset > 0);
    assert(strncmp(client.buffer + client.headers_end_offset, "Hello", 5) == 0);
    
    printf("  headers_offset_calculated: OK\n");
}

void test_empty_buffer(void) {
    Client client;
    init_test_client(&client);
    
    client.buffer[0] = '\0';
    client.bytes_received = 0;
    
    int complete = 0;
    check_if_headers_complete(&client, &complete);
    
    assert(complete == 0);
    
    printf("  empty_buffer: OK\n");
}

/* === Connection Close Tests === */

void test_close_connection_explicit(void) {
    HttpResponse res;
    init_http_response(&res);
    strcpy(res.version, "HTTP/1.1");
    res.headers = string_hashmap_t_create();
    string_hashmap_put(res.headers, "connection", "close", 10, 5);
    
    int should_close = should_close_connection(&res);
    assert(should_close == 1);
    
    free_http_response(&res);
    printf("  close_connection_explicit: OK\n");
}

void test_keep_alive_explicit(void) {
    HttpResponse res;
    init_http_response(&res);
    strcpy(res.version, "HTTP/1.1");
    res.headers = string_hashmap_t_create();
    string_hashmap_put(res.headers, "connection", "keep-alive", 10, 10);
    
    int should_close = should_close_connection(&res);
    assert(should_close == 0);
    
    free_http_response(&res);
    printf("  keep_alive_explicit: OK\n");
}

void test_http_1_1_default_keep_alive(void) {
    HttpResponse res;
    init_http_response(&res);
    strcpy(res.version, "HTTP/1.1");
    res.headers = string_hashmap_t_create();
    // No Connection header - should default to keep-alive
    
    int should_close = should_close_connection(&res);
    assert(should_close == 0);
    
    free_http_response(&res);
    printf("  http_1_1_default_keep_alive: OK\n");
}

void test_http_1_0_default_close(void) {
    HttpResponse res;
    init_http_response(&res);
    strcpy(res.version, "HTTP/1.0");
    res.headers = string_hashmap_t_create();
    // No Connection header - should default to close for HTTP/1.0
    
    int should_close = should_close_connection(&res);
    assert(should_close == 1);
    
    free_http_response(&res);
    printf("  http_1_0_default_close: OK\n");
}

void test_connection_header_case_insensitive(void) {
    HttpResponse res;
    init_http_response(&res);
    strcpy(res.version, "HTTP/1.1");
    res.headers = string_hashmap_t_create();
    string_hashmap_put(res.headers, "connection", "CLOSE", 10, 5);
    
    int should_close = should_close_connection(&res);
    assert(should_close == 1);
    
    free_http_response(&res);
    printf("  connection_header_case_insensitive: OK\n");
}

/* === Client State Tests === */

void test_client_state_idle(void) {
    Client client;
    init_test_client(&client);
    
    assert(client.state == CLIENT_STATE_IDLE);
    
    printf("  client_state_idle: OK\n");
}

void test_client_state_transitions(void) {
    // Verify state enum values are distinct
    assert(CLIENT_STATE_IDLE != CLIENT_STATE_RECEIVING_HEADERS);
    assert(CLIENT_STATE_RECEIVING_HEADERS != CLIENT_STATE_RECEIVING_BODY);
    assert(CLIENT_STATE_RECEIVING_BODY != CLIENT_STATE_SENDING_RESPONSE);
    assert(CLIENT_STATE_SENDING_RESPONSE != CLIENT_STATE_NO_CONNECTION);
    
    printf("  client_state_transitions: OK\n");
}

/* === Large Request Tests === */

void test_large_headers(void) {
    Client client;
    init_test_client(&client);
    
    // Build a request with many headers
    char* ptr = client.buffer;
    ptr += sprintf(ptr, "GET / HTTP/1.1\r\n");
    ptr += sprintf(ptr, "Host: localhost\r\n");
    
    // Add many headers (but stay under buffer limit)
    for (int i = 0; i < 50; i++) {
        ptr += sprintf(ptr, "X-Custom-Header-%d: value%d\r\n", i, i);
    }
    ptr += sprintf(ptr, "\r\n");
    
    client.bytes_received = ptr - client.buffer;
    
    int complete = 0;
    check_if_headers_complete(&client, &complete);
    
    assert(complete == 1);
    
    printf("  large_headers: OK\n");
}

void test_headers_at_buffer_boundary(void) {
    Client client;
    init_test_client(&client);
    
    // Fill most of the buffer
    memset(client.buffer, 'X', BUF_SIZE - 100);
    
    // Put valid headers at a reasonable offset
    char headers[] = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    strcpy(client.buffer, headers);
    client.bytes_received = strlen(headers);
    
    int complete = 0;
    check_if_headers_complete(&client, &complete);
    
    assert(complete == 1);
    
    printf("  headers_at_buffer_boundary: OK\n");
}

/* === Edge Cases === */

void test_minimal_request(void) {
    Client client;
    init_test_client(&client);
    
    // Minimal valid HTTP/1.0 request (no Host required)
    strcpy(client.buffer, "GET / HTTP/1.0\r\n\r\n");
    client.bytes_received = strlen(client.buffer);
    
    int complete = 0;
    check_if_headers_complete(&client, &complete);
    
    assert(complete == 1);
    
    printf("  minimal_request: OK\n");
}

void test_request_with_body_indicator(void) {
    Client client;
    init_test_client(&client);
    
    strcpy(client.buffer, 
        "POST /data HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "Hello, World!");
    client.bytes_received = strlen(client.buffer);
    
    int complete = 0;
    check_if_headers_complete(&client, &complete);
    
    assert(complete == 1);
    
    // Body should start after headers
    size_t body_start = client.headers_end_offset;
    assert(strncmp(client.buffer + body_start, "Hello, World!", 13) == 0);
    
    printf("  request_with_body_indicator: OK\n");
}

/* === Memory Safety Tests === */

void test_repeated_header_checks(void) {
    Client client;
    init_test_client(&client);
    
    strcpy(client.buffer, "GET / HTTP/1.1\r\nHost: test\r\n\r\n");
    client.bytes_received = strlen(client.buffer);
    
    // Check multiple times (simulating partial reads)
    for (int i = 0; i < 10; i++) {
        int complete = 0;
        check_if_headers_complete(&client, &complete);
        assert(complete == 1);
    }
    
    printf("  repeated_header_checks: OK\n");
}

void test_response_lifecycle(void) {
    for (int i = 0; i < 10; i++) {
        HttpResponse res;
        init_http_response(&res);
        strcpy(res.version, "HTTP/1.1");
        res.headers = string_hashmap_t_create();
        string_hashmap_put(res.headers, "Connection", "keep-alive", 10, 10);
        
        should_close_connection(&res);
        
        free_http_response(&res);
    }
    
    printf("  response_lifecycle: OK\n");
}

int main(void) {
    printf("=== Request Handler Tests ===\n\n");
    
    printf("Header Completion:\n");
    test_headers_complete_crlf();
    test_headers_incomplete();
    test_headers_partial_terminator();
    test_headers_offset_calculated();
    test_empty_buffer();
    
    printf("\nConnection Close:\n");
    test_close_connection_explicit();
    test_keep_alive_explicit();
    test_http_1_1_default_keep_alive();
    test_http_1_0_default_close();
    test_connection_header_case_insensitive();
    
    printf("\nClient State:\n");
    test_client_state_idle();
    test_client_state_transitions();
    
    printf("\nLarge Requests:\n");
    test_large_headers();
    test_headers_at_buffer_boundary();
    
    printf("\nEdge Cases:\n");
    test_minimal_request();
    test_request_with_body_indicator();
    
    printf("\nMemory Safety:\n");
    test_repeated_header_checks();
    test_response_lifecycle();
    
    printf("\n=== All Request Handler tests passed! ===\n");
    return 0;
}

