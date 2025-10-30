#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "./../include/http.h"

void test_http_request_parsing(void) {
    printf("Testing HTTP request parsing...\n");
    
    char request[] = "GET /index.html HTTP/1.0\r\n \
        Host: localhost\r\n \
        User-Agent: test\r\n \
        \r\n";

    HttpRequest req;
    int result = parse_http_request(request, &req);
    assert(result == 0);
    assert(strcmp(req.method, "GET") == 0);
    assert(strcmp(req.path, "/index.html") == 0);
    char test[] = "Host";
    char* value = NULL;

    if (string_hashmap_get_case_insensitive(req.headers, test, strlen(test), &value) == HASHMAP_SUCCESS) {
        assert(strcmp(value, "localhost") == 0);
    } else {
        assert(0 && "key not found");
    }

    printf("✅ HTTP request parsing test passed\n");
}

void test_http_response_creation(void) {
    printf("Testing HTTP response creation...\n");
    
    HttpResponse res;
    int result = get_default_response(&res);
    assert(result == 0);
    assert(res.headers != NULL);
    
    // Check default headers
    char* server_value = NULL;
    char server_key[] = "Server";
    result = string_hashmap_get(res.headers, server_key, strlen(server_key), &server_value);
    printf("server_value: %s\n", server_value);
    assert(result == HASHMAP_SUCCESS);
    assert(strcmp(server_value, "C-WebServer/1.0") == 0);
    
    char* last_modified_value = NULL;
    char last_modified_key[] = "Last-Modified";
    result = string_hashmap_get(res.headers, last_modified_key, strlen(last_modified_key), &last_modified_value);
    assert(result == HASHMAP_SUCCESS);
    assert(strcmp(last_modified_value, "Thu, 30 Oct 2025 12:00:00 GMT") == 0);
    
    // Check size
    size_t size;
    string_hashmap_size(res.headers, &size);
    assert(size == 2);
    
    free_http_response(&res);
    printf("✅ HTTP response creation test passed\n");
}

void test_http_response_to_buffer(void) {
    printf("Testing HTTP response to buffer conversion...\n");
    
    HttpResponse res;
    get_default_response(&res);
    res.body = "Hello, World!";
    
    char* buffer = NULL;
    int result = response_to_buffer(&res, &buffer);
    assert(result == 0);
    assert(buffer != NULL);
    
    // Check that the response starts with the status line
    assert(strstr(buffer, "HTTP/1.0 200 OK\r\n") != NULL);
    
    // Check that headers are present
    assert(strstr(buffer, "Server: C-WebServer/1.0\r\n") != NULL);
    assert(strstr(buffer, "Last-Modified: Thu, 30 Oct 2025 12:00:00 GMT\r\n") != NULL);
    
    // Check that body is present
    assert(strstr(buffer, "Hello, World!") != NULL);
    
    // Check that header/body separator exists
    assert(strstr(buffer, "\r\n\r\n") != NULL);
    
    free(buffer);
    free_http_response(&res);
    printf("✅ HTTP response to buffer test passed\n");
}

void test_http_response_custom_headers(void) {
    printf("Testing HTTP response with custom headers...\n");
    
    HttpResponse res;
    get_default_response(&res);
    
    // Add custom headers
    char content_type_key[] = "Content-Type";
    char content_type_value[] = "text/html";
    string_hashmap_put(res.headers, content_type_key, content_type_value, 
                      strlen(content_type_key), strlen(content_type_value));
    
    char content_length_key[] = "Content-Length";
    char content_length_value[] = "13";
    string_hashmap_put(res.headers, content_length_key, content_length_value,
                      strlen(content_length_key), strlen(content_length_value));
    
    // Check size
    size_t size;
    string_hashmap_size(res.headers, &size);
    assert(size == 4);
    
    res.body = "Hello, World!";
    char* buffer = NULL;
    response_to_buffer(&res, &buffer);
    
    // Check custom headers are in the response
    assert(strstr(buffer, "Content-Type: text/html\r\n") != NULL);
    assert(strstr(buffer, "Content-Length: 13\r\n") != NULL);
    
    free(buffer);
    free_http_response(&res);
    printf("✅ HTTP response custom headers test passed\n");
}

int main(void) {
    printf("=== Running HTTP Tests ===\n\n");
    
    test_http_request_parsing();
    test_http_response_creation();
    test_http_response_to_buffer();
    test_http_response_custom_headers();
    
    printf("\n=== All HTTP tests passed! ===\n");
    return 0;
}
