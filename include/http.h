#ifndef HTTP_H
#define HTTP_H

#include "./../include/utils/string_hashmap.h"

typedef struct {
    char method[8];   // "GET", "POST", etc.
    char path[256];   // "/index.html"
    char version[16]; // "HTTP/1.0"
    struct string_hashmap_t* headers; // your hashmap for headers
    char* body; // the body of the request
} HttpRequest;

typedef struct {
    char status_code[4]; // "200", "404", etc.
    char status_message[256]; // "OK", "Not Found", etc.
    char version[16]; // "HTTP/1.0"
    struct string_hashmap_t* headers; // your hashmap for headers
    char* body; // the body of the response
} HttpResponse;

enum parse_http_request_error {
    PARSE_HTTP_REQUEST_SUCCESS = 0,
    PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST = -1
};

int parse_http_request(const char* buffer, HttpRequest* req);
int init_http_request(HttpRequest* req);
int free_http_request(HttpRequest* req);

// Response functions
int init_http_response(HttpResponse* res);
int get_default_response(HttpResponse* res);
int free_http_response(HttpResponse* res);
int response_to_buffer(HttpResponse* res, char** buffer);

#endif