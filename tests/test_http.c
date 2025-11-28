/*
 * HTTP Module Tests
 * Tests for HTTP request parsing, response creation, and protocol handling
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "./../include/http.h"

/* === Request Parsing Tests === */

void test_parse_get_request(void) {
    char request[] = "GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    assert(strcmp(req.method, "GET") == 0);
    assert(strcmp(req.path, "/index.html") == 0);
    assert(strcmp(req.version, "HTTP/1.1") == 0);
    
    char* host = NULL;
    string_hashmap_get_case_insensitive(req.headers, "Host", 4, &host);
    assert(host != NULL);
    assert(strcmp(host, "localhost") == 0);
    
    free_http_request(&req);
    printf("  parse_get_request: OK\n");
}

void test_parse_head_request(void) {
    char request[] = "HEAD /test.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    assert(strcmp(req.method, "HEAD") == 0);
    assert(strcmp(req.path, "/test.html") == 0);
    
    free_http_request(&req);
    printf("  parse_head_request: OK\n");
}

void test_parse_post_request(void) {
    char request[] = "POST /api/data HTTP/1.1\r\nHost: api.test\r\nContent-Length: 0\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    assert(strcmp(req.method, "POST") == 0);
    assert(strcmp(req.path, "/api/data") == 0);
    
    char* content_length = NULL;
    string_hashmap_get_case_insensitive(req.headers, "Content-Length", 14, &content_length);
    assert(content_length != NULL);
    assert(strcmp(content_length, "0") == 0);
    
    free_http_request(&req);
    printf("  parse_post_request: OK\n");
}

void test_parse_http_1_0(void) {
    char request[] = "GET / HTTP/1.0\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    assert(strcmp(req.version, "HTTP/1.0") == 0);
    assert(is_http_1_0(&req) == 1);
    assert(is_http_1_1(&req) == 0);
    
    free_http_request(&req);
    printf("  parse_http_1_0: OK\n");
}

void test_parse_multiple_headers(void) {
    char request[] = 
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: TestClient/1.0\r\n"
        "Accept: text/html\r\n"
        "Accept-Language: en-US\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    
    char* user_agent = NULL;
    string_hashmap_get_case_insensitive(req.headers, "User-Agent", 10, &user_agent);
    assert(user_agent != NULL);
    assert(strcmp(user_agent, "TestClient/1.0") == 0);
    
    char* accept = NULL;
    string_hashmap_get_case_insensitive(req.headers, "Accept", 6, &accept);
    assert(accept != NULL);
    assert(strcmp(accept, "text/html") == 0);
    
    free_http_request(&req);
    printf("  parse_multiple_headers: OK\n");
}

void test_case_insensitive_headers(void) {
    char request[] = 
        "GET / HTTP/1.1\r\n"
        "HOST: localhost\r\n"
        "content-type: text/plain\r\n"
        "ACCEPT-ENCODING: gzip\r\n"
        "\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    
    // All header lookups should work regardless of case
    char* host = NULL;
    string_hashmap_get_case_insensitive(req.headers, "host", 4, &host);
    assert(host != NULL);
    assert(strcmp(host, "localhost") == 0);
    
    char* content_type = NULL;
    string_hashmap_get_case_insensitive(req.headers, "Content-Type", 12, &content_type);
    assert(content_type != NULL);
    
    free_http_request(&req);
    printf("  case_insensitive_headers: OK\n");
}

/* === URL Decoding Tests === */

void test_url_decode_spaces(void) {
    char request[] = "GET /hello%20world.html HTTP/1.1\r\nHost: test\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    assert(strcmp(req.path, "/hello world.html") == 0);
    
    free_http_request(&req);
    printf("  url_decode_spaces: OK\n");
}

void test_url_decode_special_chars(void) {
    char request[] = "GET /test%3Fquery%3Dvalue HTTP/1.1\r\nHost: test\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    assert(strcmp(req.path, "/test?query=value") == 0);
    
    free_http_request(&req);
    printf("  url_decode_special_chars: OK\n");
}

void test_url_decode_plus_sign(void) {
    char request[] = "GET /search?q=hello+world HTTP/1.1\r\nHost: test\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    assert(strcmp(req.path, "/search?q=hello world") == 0);
    
    free_http_request(&req);
    printf("  url_decode_plus_sign: OK\n");
}

/* === RFC 9112 Compliance Tests === */

void test_reject_bare_cr(void) {
    // Bare CR (not followed by LF) should be rejected
    char request[] = "GET / HTTP/1.1\rHost: test\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST);
    
    // Clean up (headers might not be allocated on error)
    if (req.headers != NULL) {
        free_http_request(&req);
    }
    printf("  reject_bare_cr: OK\n");
}

void test_valid_crlf(void) {
    // Proper CRLF should work
    char request[] = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_SUCCESS);
    
    free_http_request(&req);
    printf("  valid_crlf: OK\n");
}

/* === HTTP Version Detection Tests === */

void test_is_http_1_1(void) {
    HttpRequest req;
    init_http_request(&req);
    
    strcpy(req.version, "HTTP/1.1");
    assert(is_http_1_1(&req) == 1);
    assert(is_http_1_0(&req) == 0);
    
    strcpy(req.version, "HTTP/1.0");
    assert(is_http_1_1(&req) == 0);
    assert(is_http_1_0(&req) == 1);
    
    printf("  is_http_version: OK\n");
}

void test_version_null_request(void) {
    assert(is_http_1_1(NULL) == 0);
    assert(is_http_1_0(NULL) == 0);
    printf("  version_null_request: OK\n");
}

void test_version_empty(void) {
    HttpRequest req;
    init_http_request(&req);
    
    // Empty version string
    req.version[0] = '\0';
    assert(is_http_1_1(&req) == 0);
    assert(is_http_1_0(&req) == 0);
    
    printf("  version_empty: OK\n");
}

/* === Invalid Request Tests === */

void test_malformed_request_line(void) {
    // Missing HTTP version
    char request[] = "GET /path\r\nHost: test\r\n\r\n";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST);
    
    if (req.headers != NULL) {
        free_http_request(&req);
    }
    printf("  malformed_request_line: OK\n");
}

void test_empty_request(void) {
    char request[] = "";
    
    HttpRequest req;
    init_http_request(&req);
    int result = parse_http_request_headers(request, &req);
    
    assert(result == PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST);
    
    if (req.headers != NULL) {
        free_http_request(&req);
    }
    printf("  empty_request: OK\n");
}

/* === Response Tests === */

void test_init_response(void) {
    HttpResponse res;
    int result = init_http_response(&res);
    
    assert(result == 0);
    assert(res.status_code[0] == '\0');
    assert(res.status_message[0] == '\0');
    assert(res.headers == NULL);
    assert(res.body == NULL);
    assert(res.body_length == 0);
    
    printf("  init_response: OK\n");
}

void test_default_response_http_1_1(void) {
    HttpRequest req;
    init_http_request(&req);
    strcpy(req.version, "HTTP/1.1");
    req.headers = string_hashmap_t_create();
    
    HttpResponse res;
    init_http_response(&res);
    int result = get_default_response(&res, &req);
    
    assert(result == 0);
    assert(strcmp(res.status_code, "200") == 0);
    assert(strcmp(res.status_message, "OK") == 0);
    assert(strcmp(res.version, "HTTP/1.1") == 0);
    
    // HTTP/1.1 defaults to keep-alive
    char* connection = NULL;
    string_hashmap_get_case_insensitive(res.headers, "Connection", 10, &connection);
    assert(connection != NULL);
    assert(strcmp(connection, "keep-alive") == 0);
    
    // Server header should be set
    char* server = NULL;
    string_hashmap_get_case_insensitive(res.headers, "Server", 6, &server);
    assert(server != NULL);
    assert(strcmp(server, "C-WebServer/1.0") == 0);
    
    // Date header should be set
    char* date = NULL;
    string_hashmap_get_case_insensitive(res.headers, "Date", 4, &date);
    assert(date != NULL);
    assert(strlen(date) > 0);
    
    free_http_response(&res);
    free_http_request(&req);
    printf("  default_response_http_1_1: OK\n");
}

void test_default_response_http_1_0(void) {
    HttpRequest req;
    init_http_request(&req);
    strcpy(req.version, "HTTP/1.0");
    req.headers = string_hashmap_t_create();
    
    HttpResponse res;
    init_http_response(&res);
    int result = get_default_response(&res, &req);
    
    assert(result == 0);
    assert(strcmp(res.version, "HTTP/1.0") == 0);
    
    // HTTP/1.0 defaults to close
    char* connection = NULL;
    string_hashmap_get_case_insensitive(res.headers, "Connection", 10, &connection);
    assert(connection != NULL);
    assert(strcmp(connection, "close") == 0);
    
    free_http_response(&res);
    free_http_request(&req);
    printf("  default_response_http_1_0: OK\n");
}

void test_client_connection_header_respected(void) {
    HttpRequest req;
    init_http_request(&req);
    strcpy(req.version, "HTTP/1.1");
    req.headers = string_hashmap_t_create();
    string_hashmap_put(req.headers, "connection", "close", 10, 5);
    
    HttpResponse res;
    init_http_response(&res);
    get_default_response(&res, &req);
    
    char* connection = NULL;
    string_hashmap_get_case_insensitive(res.headers, "Connection", 10, &connection);
    assert(connection != NULL);
    assert(strcmp(connection, "close") == 0);
    
    free_http_response(&res);
    free_http_request(&req);
    printf("  client_connection_header_respected: OK\n");
}

/* === Security Headers Tests === */

void test_security_headers_http(void) {
    HttpRequest req;
    init_http_request(&req);
    strcpy(req.version, "HTTP/1.1");
    req.headers = string_hashmap_t_create();
    
    HttpResponse res;
    init_http_response(&res);
    get_default_response(&res, &req);
    add_security_headers(&res, 0); // Not HTTPS
    
    char* x_content_type = NULL;
    string_hashmap_get_case_insensitive(res.headers, "X-Content-Type-Options", 22, &x_content_type);
    assert(x_content_type != NULL);
    assert(strcmp(x_content_type, "nosniff") == 0);
    
    char* x_frame = NULL;
    string_hashmap_get_case_insensitive(res.headers, "X-Frame-Options", 15, &x_frame);
    assert(x_frame != NULL);
    assert(strcmp(x_frame, "DENY") == 0);
    
    // HSTS should NOT be present for HTTP
    char* hsts = NULL;
    int found = string_hashmap_get_case_insensitive(res.headers, "Strict-Transport-Security", 25, &hsts);
    assert(found != HASHMAP_SUCCESS);
    
    free_http_response(&res);
    free_http_request(&req);
    printf("  security_headers_http: OK\n");
}

void test_security_headers_https(void) {
    HttpRequest req;
    init_http_request(&req);
    strcpy(req.version, "HTTP/1.1");
    req.headers = string_hashmap_t_create();
    
    HttpResponse res;
    init_http_response(&res);
    get_default_response(&res, &req);
    add_security_headers(&res, 1); // HTTPS
    
    // HSTS should be present for HTTPS
    char* hsts = NULL;
    int found = string_hashmap_get_case_insensitive(res.headers, "Strict-Transport-Security", 25, &hsts);
    assert(found == HASHMAP_SUCCESS);
    assert(hsts != NULL);
    assert(strstr(hsts, "max-age=") != NULL);
    
    free_http_response(&res);
    free_http_request(&req);
    printf("  security_headers_https: OK\n");
}

/* === Response Serialization Tests === */

void test_response_to_buffer(void) {
    HttpRequest req;
    init_http_request(&req);
    strcpy(req.version, "HTTP/1.1");
    req.headers = string_hashmap_t_create();
    
    HttpResponse res;
    init_http_response(&res);
    get_default_response(&res, &req);
    
    res.body = strdup("Hello, World!");
    res.body_length = strlen(res.body);
    
    char* buffer = NULL;
    int result = response_to_buffer(&res, &buffer);
    
    assert(result == 0);
    assert(buffer != NULL);
    
    // Check status line
    assert(strstr(buffer, "HTTP/1.1 200 OK\r\n") != NULL);
    
    // Check headers present (lowercase keys due to case-insensitive storage)
    assert(strstr(buffer, "server: C-WebServer/1.0\r\n") != NULL);
    
    // Check header/body separator
    assert(strstr(buffer, "\r\n\r\n") != NULL);
    
    // Check body
    assert(strstr(buffer, "Hello, World!") != NULL);
    
    free(buffer);
    free_http_response(&res);
    free_http_request(&req);
    printf("  response_to_buffer: OK\n");
}

void test_response_empty_body(void) {
    HttpRequest req;
    init_http_request(&req);
    strcpy(req.version, "HTTP/1.1");
    req.headers = string_hashmap_t_create();
    
    HttpResponse res;
    init_http_response(&res);
    get_default_response(&res, &req);
    // No body set
    
    char* buffer = NULL;
    int result = response_to_buffer(&res, &buffer);
    
    assert(result == 0);
    assert(buffer != NULL);
    assert(strstr(buffer, "HTTP/1.1 200 OK\r\n") != NULL);
    
    free(buffer);
    free_http_response(&res);
    free_http_request(&req);
    printf("  response_empty_body: OK\n");
}

/* === Memory Tests === */

void test_request_cleanup(void) {
    // Multiple allocations and frees to check for leaks
    for (int i = 0; i < 10; i++) {
        char request[] = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        
        HttpRequest req;
        init_http_request(&req);
        parse_http_request_headers(request, &req);
        free_http_request(&req);
    }
    printf("  request_cleanup: OK\n");
}

void test_response_cleanup(void) {
    for (int i = 0; i < 10; i++) {
        HttpRequest req;
        init_http_request(&req);
        strcpy(req.version, "HTTP/1.1");
        req.headers = string_hashmap_t_create();
        
        HttpResponse res;
        init_http_response(&res);
        get_default_response(&res, &req);
        add_security_headers(&res, 1);
        res.body = strdup("Test body content");
        res.body_length = strlen(res.body);
        
        char* buffer = NULL;
        response_to_buffer(&res, &buffer);
        
        free(buffer);
        free_http_response(&res);
        free_http_request(&req);
    }
    printf("  response_cleanup: OK\n");
}

int main(void) {
    printf("=== HTTP Tests ===\n\n");
    
    printf("Request Parsing:\n");
    test_parse_get_request();
    test_parse_head_request();
    test_parse_post_request();
    test_parse_http_1_0();
    test_parse_multiple_headers();
    test_case_insensitive_headers();
    
    printf("\nURL Decoding:\n");
    test_url_decode_spaces();
    test_url_decode_special_chars();
    test_url_decode_plus_sign();
    
    printf("\nRFC 9112 Compliance:\n");
    test_reject_bare_cr();
    test_valid_crlf();
    
    printf("\nHTTP Version:\n");
    test_is_http_1_1();
    test_version_null_request();
    test_version_empty();
    
    printf("\nInvalid Requests:\n");
    test_malformed_request_line();
    test_empty_request();
    
    printf("\nResponse Creation:\n");
    test_init_response();
    test_default_response_http_1_1();
    test_default_response_http_1_0();
    test_client_connection_header_respected();
    
    printf("\nSecurity Headers:\n");
    test_security_headers_http();
    test_security_headers_https();
    
    printf("\nResponse Serialization:\n");
    test_response_to_buffer();
    test_response_empty_body();
    
    printf("\nMemory:\n");
    test_request_cleanup();
    test_response_cleanup();
    
    printf("\n=== All HTTP tests passed! ===\n");
    return 0;
}

