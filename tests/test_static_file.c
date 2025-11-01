#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "./../include/http.h"
#include "./../include/static_file.h"

void test_serve_index_html(void) {
    printf("Testing serving index.html...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    int result = serve_static_file("/", &response);
    assert(result == 0);
    assert(strcmp(response.status_code, "200") == 0);
    assert(strcmp(response.status_message, "OK") == 0);
    assert(response.body != NULL);
    assert(strlen(response.body) > 0);
    
    // Check Content-Type header
    char* content_type = NULL;
    string_hashmap_get(response.headers, "Content-Type", 12, &content_type);
    assert(content_type != NULL);
    assert(strcmp(content_type, "text/html") == 0);
    
    // Check Content-Length header
    char* content_length = NULL;
    string_hashmap_get(response.headers, "Content-Length", 14, &content_length);
    assert(content_length != NULL);
    
    free_http_response(&response);
    printf("✅ Serve index.html test passed\n");
}

void test_serve_index_with_trailing_slash(void) {
    printf("Testing serving directory with trailing slash...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    int result = serve_static_file("/", &response);
    assert(result == 0);
    assert(strcmp(response.status_code, "200") == 0);
    assert(response.body != NULL);
    
    
    free_http_response(&response);
    printf("✅ Serve directory with trailing slash test passed\n");
}

void test_serve_nonexistent_file(void) {
    printf("Testing serving nonexistent file (404)...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    int result = serve_static_file("/nonexistent.html", &response);
    assert(result == 0);
    assert(strcmp(response.status_code, "404") == 0);
    assert(strcmp(response.status_message, "Not Found") == 0);
    assert(response.body != NULL);
    
    
    free_http_response(&response);
    printf("✅ Serve nonexistent file test passed\n");
}

void test_path_traversal_attack_simple(void) {
    printf("Testing path traversal attack (simple ../../../)...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    int result = serve_static_file("/../../../etc/passwd", &response);
    assert(result == 0);
    // Should either be 403 (Forbidden) or 404 (Not Found)
    assert(strcmp(response.status_code, "403") == 0 || strcmp(response.status_code, "404") == 0);
    assert(response.body != NULL);
    
    // Make sure we're NOT serving /etc/passwd content
    if (response.body != NULL) {
        // /etc/passwd would contain "root:" - make sure it's not there
        assert(strstr(response.body, "root:") == NULL);
    }
    
    
    free_http_response(&response);
    printf("✅ Path traversal attack (simple) test passed\n");
}

void test_path_traversal_attack_complex(void) {
    printf("Testing path traversal attack (complex path)...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    int result = serve_static_file("/subdir/../../etc/passwd", &response);
    assert(result == 0);
    assert(strcmp(response.status_code, "403") == 0 || strcmp(response.status_code, "404") == 0);
    assert(response.body != NULL);
    
    
    free_http_response(&response);
    printf("✅ Path traversal attack (complex) test passed\n");
}

void test_serve_error_pages(void) {
    printf("Testing error pages exist...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    // Test 404 error page
    int result = serve_static_file("/this-does-not-exist.html", &response);
    assert(result == 0);
    assert(strcmp(response.status_code, "404") == 0);
    assert(response.body != NULL);
    assert(strlen(response.body) > 0);
    
    
    free_http_response(&response);
    printf("✅ Error pages test passed\n");
}

void test_content_type_html(void) {
    printf("Testing Content-Type for HTML files...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    serve_static_file("/index.html", &response);
    
    char* content_type = NULL;
    string_hashmap_get(response.headers, "Content-Type", 12, &content_type);
    assert(content_type != NULL);
    assert(strcmp(content_type, "text/html") == 0);
    
    
    free_http_response(&response);
    printf("✅ Content-Type HTML test passed\n");
}

void test_content_length_set(void) {
    printf("Testing Content-Length header is set...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    serve_static_file("/index.html", &response);
    
    char* content_length = NULL;
    string_hashmap_get(response.headers, "Content-Length", 14, &content_length);
    assert(content_length != NULL);
    
    // Content-Length should be a number
    int length = atoi(content_length);
    assert(length > 0);
    
    // Should match actual body length
    assert(length == (int)strlen(response.body));
    
    
    free_http_response(&response);
    printf("✅ Content-Length test passed\n");
}

void test_path_normalization(void) {
    printf("Testing path normalization (./index.html)...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    // Path with ./ should still work
    int result = serve_static_file("/./index.html", &response);
    assert(result == 0);
    // Should either succeed or 404, but NOT 403 (it's still in public/)
    assert(strcmp(response.status_code, "200") == 0 || strcmp(response.status_code, "404") == 0);
    
    if (response.body != NULL) {
        
    }
    free_http_response(&response);
    printf("✅ Path normalization test passed\n");
}

void test_no_extension_file(void) {
    printf("Testing file without extension...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    // Even if file doesn't exist, should handle no extension gracefully
    int result = serve_static_file("/filenoext", &response);
    assert(result == 0);
    // Should be 404 since file doesn't exist
    assert(strcmp(response.status_code, "404") == 0);
    
    if (response.body != NULL) {
        
    }
    free_http_response(&response);
    printf("✅ No extension file test passed\n");
}

void test_long_path(void) {
    printf("Testing very long path...\n");
    
    HttpResponse response;
    int init_http_response_result = init_http_response(&response);
    int get_default_response_result = get_default_response(&response);
    assert(init_http_response_result == 0);
    assert(get_default_response_result == 0);
    
    // Create a very long path
    char long_path[5000];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';
    
    int result = serve_static_file(long_path, &response);
    assert(result == 0);
    // Should handle gracefully with 404
    assert(strcmp(response.status_code, "404") == 0);
    
    if (response.body != NULL) {
        
    }
    free_http_response(&response);
    printf("✅ Long path test passed\n");
}

void test_memory_cleanup(void) {
    printf("Testing memory cleanup (no leaks)...\n");
    
    // Serve multiple files to ensure proper cleanup
    for (int i = 0; i < 10; i++) {
        HttpResponse response;
        int init_http_response_result = init_http_response(&response);
        int get_default_response_result = get_default_response(&response);
        assert(init_http_response_result == 0);
        assert(get_default_response_result == 0);
        
        serve_static_file("/index.html", &response);
        
        if (response.body != NULL) {
            
        }
        free_http_response(&response);
    }
    
    printf("✅ Memory cleanup test passed\n");
}

int main(void) {
    printf("=== Running Static File Tests ===\n\n");
    
    test_serve_index_html();
    test_serve_index_with_trailing_slash();
    test_serve_nonexistent_file();
    test_path_traversal_attack_simple();
    test_path_traversal_attack_complex();
    test_serve_error_pages();
    test_content_type_html();
    test_content_length_set();
    test_path_normalization();
    test_no_extension_file();
    test_long_path();
    test_memory_cleanup();
    
    printf("\n=== All Static File tests passed! ===\n");
    return 0;
}

