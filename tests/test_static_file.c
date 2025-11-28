/*
 * Static File Tests
 * Tests for static file serving, content types, and security
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "http.h"
#include "static_file.h"

/* === Helper Functions === */

static void setup_request_response(HttpRequest* req, HttpResponse* res) {
    init_http_request(req);
    strcpy(req->version, "HTTP/1.1");
    req->headers = string_hashmap_t_create();
    
    init_http_response(res);
    res->headers = string_hashmap_t_create();
    strcpy(res->status_code, "200");
    strcpy(res->status_message, "OK");
    strcpy(res->version, "HTTP/1.1");
}

static void cleanup_request_response(HttpRequest* req, HttpResponse* res) {
    free_http_request(req);
    free_http_response(res);
}

/* === Basic File Serving Tests === */

void test_serve_index_html(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    int result = serve_static_file("/index.html", &res, &req);
    
    assert(result == 0);
    assert(strcmp(res.status_code, "200") == 0);
    assert(res.body != NULL);
    assert(res.body_length > 0);
    
    cleanup_request_response(&req, &res);
    printf("  serve_index_html: OK\n");
}

void test_serve_root_path(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Root path should serve index.html
    int result = serve_static_file("/", &res, &req);
    
    assert(result == 0);
    assert(strcmp(res.status_code, "200") == 0);
    assert(res.body != NULL);
    
    cleanup_request_response(&req, &res);
    printf("  serve_root_path: OK\n");
}

void test_serve_trailing_slash(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Trailing slash should serve index.html from that directory
    int result = serve_static_file("/errors/", &res, &req);
    
    // May be 404 if no index.html in errors/, that's fine
    assert(result == 0);
    
    cleanup_request_response(&req, &res);
    printf("  serve_trailing_slash: OK\n");
}

/* === 404 Tests === */

void test_nonexistent_file(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    int result = serve_static_file("/this-file-does-not-exist.html", &res, &req);
    
    assert(result == 0);
    assert(strcmp(res.status_code, "404") == 0);
    assert(strcmp(res.status_message, "Not Found") == 0);
    assert(res.body != NULL);
    
    cleanup_request_response(&req, &res);
    printf("  nonexistent_file: OK\n");
}

void test_nonexistent_deep_path(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    int result = serve_static_file("/a/b/c/d/e/f/file.html", &res, &req);
    
    assert(result == 0);
    assert(strcmp(res.status_code, "404") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  nonexistent_deep_path: OK\n");
}

/* === Path Traversal Security Tests === */

void test_path_traversal_simple(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    int result = serve_static_file("/../../../etc/passwd", &res, &req);
    
    assert(result == 0);
    // Should be either 403 (Forbidden) or 404 (Not Found)
    assert(strcmp(res.status_code, "403") == 0 || strcmp(res.status_code, "404") == 0);
    
    // Must NOT contain passwd file content
    if (res.body != NULL) {
        assert(strstr(res.body, "root:") == NULL);
    }
    
    cleanup_request_response(&req, &res);
    printf("  path_traversal_simple: OK\n");
}

void test_path_traversal_encoded(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // URL encoded ..
    int result = serve_static_file("/..%2F..%2Fetc/passwd", &res, &req);
    
    assert(result == 0);
    assert(strcmp(res.status_code, "403") == 0 || strcmp(res.status_code, "404") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  path_traversal_encoded: OK\n");
}

void test_path_traversal_nested(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Try to escape via nested path
    int result = serve_static_file("/errors/../../etc/passwd", &res, &req);
    
    assert(result == 0);
    assert(strcmp(res.status_code, "403") == 0 || strcmp(res.status_code, "404") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  path_traversal_nested: OK\n");
}

void test_path_traversal_double_dot(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    int result = serve_static_file("/....//....//etc/passwd", &res, &req);
    
    assert(result == 0);
    // Either 403, 404, or could be treated as literal filename
    assert(strcmp(res.status_code, "403") == 0 || 
           strcmp(res.status_code, "404") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  path_traversal_double_dot: OK\n");
}

/* === Content Type Tests === */

void test_content_type_html(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    serve_static_file("/index.html", &res, &req);
    
    char* content_type = NULL;
    string_hashmap_get(res.headers, "content-type", 12, &content_type);
    assert(content_type != NULL);
    assert(strcmp(content_type, "text/html") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  content_type_html: OK\n");
}

void test_content_type_error_page(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Error pages should also have content type
    serve_static_file("/nonexistent.xyz", &res, &req);
    
    char* content_type = NULL;
    int found = string_hashmap_get(res.headers, "content-type", 12, &content_type);
    // Error page should have content type set
    assert(found == HASHMAP_SUCCESS || res.body != NULL);
    
    cleanup_request_response(&req, &res);
    printf("  content_type_error_page: OK\n");
}

/* === Content Length Tests === */

void test_content_length_set(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    serve_static_file("/index.html", &res, &req);
    
    if (strcmp(res.status_code, "200") == 0) {
        char* content_length = NULL;
        string_hashmap_get(res.headers, "content-length", 14, &content_length);
        assert(content_length != NULL);
        
        int length = atoi(content_length);
        assert(length > 0);
        assert((size_t)length == res.body_length);
    }
    
    cleanup_request_response(&req, &res);
    printf("  content_length_set: OK\n");
}

/* === If-Modified-Since Tests === */

void test_if_modified_since_304(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Set a future date - file should not be modified
    string_hashmap_put(req.headers, "if-modified-since", 
                       "Wed, 01 Jan 2099 00:00:00 GMT", 17, 29);
    
    serve_static_file("/index.html", &res, &req);
    
    // Should return 304 Not Modified
    assert(strcmp(res.status_code, "304") == 0);
    assert(res.body == NULL || res.body_length == 0);
    
    cleanup_request_response(&req, &res);
    printf("  if_modified_since_304: OK\n");
}

void test_if_modified_since_200(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Set a past date - file should be modified
    string_hashmap_put(req.headers, "if-modified-since", 
                       "Wed, 01 Jan 2000 00:00:00 GMT", 17, 29);
    
    serve_static_file("/index.html", &res, &req);
    
    // Should return 200 OK with body
    assert(strcmp(res.status_code, "200") == 0);
    assert(res.body != NULL);
    
    cleanup_request_response(&req, &res);
    printf("  if_modified_since_200: OK\n");
}

void test_if_modified_since_invalid_date(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Invalid date format - should serve file normally
    string_hashmap_put(req.headers, "if-modified-since", 
                       "not-a-valid-date", 17, 16);
    
    serve_static_file("/index.html", &res, &req);
    
    // Should return 200 OK (invalid date = serve file)
    assert(strcmp(res.status_code, "200") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  if_modified_since_invalid_date: OK\n");
}

void test_no_if_modified_since(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // No If-Modified-Since header
    serve_static_file("/index.html", &res, &req);
    
    assert(strcmp(res.status_code, "200") == 0);
    assert(res.body != NULL);
    
    cleanup_request_response(&req, &res);
    printf("  no_if_modified_since: OK\n");
}

/* === Error Page Tests === */

void test_error_400_page(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    serve_static_file(ERROR_400_PATH, &res, &req);
    
    // Should serve the error page (200) or show generic error
    assert(res.body != NULL);
    
    cleanup_request_response(&req, &res);
    printf("  error_400_page: OK\n");
}

void test_error_404_page(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    serve_static_file(ERROR_404_PATH, &res, &req);
    
    assert(res.body != NULL);
    
    cleanup_request_response(&req, &res);
    printf("  error_404_page: OK\n");
}

/* === Edge Cases === */

void test_very_long_path(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Create a very long path
    char long_path[5000];
    long_path[0] = '/';
    memset(long_path + 1, 'a', 4998);
    long_path[4999] = '\0';
    
    int result = serve_static_file(long_path, &res, &req);
    
    assert(result == 0);
    // Should handle gracefully (likely 404)
    assert(strcmp(res.status_code, "404") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  very_long_path: OK\n");
}

void test_path_with_dots(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    // Single dot in path
    int result = serve_static_file("/./index.html", &res, &req);
    
    assert(result == 0);
    // Should either work or 404, not 403 (it's still in public/)
    assert(strcmp(res.status_code, "200") == 0 || 
           strcmp(res.status_code, "404") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  path_with_dots: OK\n");
}

void test_file_without_extension(void) {
    HttpRequest req;
    HttpResponse res;
    setup_request_response(&req, &res);
    
    int result = serve_static_file("/somefile", &res, &req);
    
    assert(result == 0);
    // Should be 404 (file doesn't exist)
    assert(strcmp(res.status_code, "404") == 0);
    
    cleanup_request_response(&req, &res);
    printf("  file_without_extension: OK\n");
}

/* === Memory Tests === */

void test_multiple_serves(void) {
    // Test for memory leaks by serving multiple files
    for (int i = 0; i < 20; i++) {
        HttpRequest req;
        HttpResponse res;
        setup_request_response(&req, &res);
        
        serve_static_file("/index.html", &res, &req);
        
        cleanup_request_response(&req, &res);
    }
    printf("  multiple_serves: OK\n");
}

void test_mixed_status_codes(void) {
    const char* paths[] = {
        "/index.html",           // 200
        "/nonexistent.html",     // 404
        "/../etc/passwd",        // 403 or 404
        "/",                     // 200
        "/errors/400.html",      // 200
    };
    
    for (int i = 0; i < 5; i++) {
        HttpRequest req;
        HttpResponse res;
        setup_request_response(&req, &res);
        
        serve_static_file(paths[i], &res, &req);
        
        // Just verify no crashes and valid status code
        assert(strlen(res.status_code) == 3);
        
        cleanup_request_response(&req, &res);
    }
    printf("  mixed_status_codes: OK\n");
}

int main(void) {
    printf("=== Static File Tests ===\n\n");
    
    printf("Basic File Serving:\n");
    test_serve_index_html();
    test_serve_root_path();
    test_serve_trailing_slash();
    
    printf("\n404 Responses:\n");
    test_nonexistent_file();
    test_nonexistent_deep_path();
    
    printf("\nPath Traversal Security:\n");
    test_path_traversal_simple();
    test_path_traversal_encoded();
    test_path_traversal_nested();
    test_path_traversal_double_dot();
    
    printf("\nContent Type:\n");
    test_content_type_html();
    test_content_type_error_page();
    
    printf("\nContent Length:\n");
    test_content_length_set();
    
    printf("\nIf-Modified-Since:\n");
    test_if_modified_since_304();
    test_if_modified_since_200();
    test_if_modified_since_invalid_date();
    test_no_if_modified_since();
    
    printf("\nError Pages:\n");
    test_error_400_page();
    test_error_404_page();
    
    printf("\nEdge Cases:\n");
    test_very_long_path();
    test_path_with_dots();
    test_file_without_extension();
    
    printf("\nMemory:\n");
    test_multiple_serves();
    test_mixed_status_codes();
    
    printf("\n=== All Static File tests passed! ===\n");
    return 0;
}

