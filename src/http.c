#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "./../include/http.h"
#include "./../include/utils/string_builder.h"
#include "./../include/utils/string_hashmap.h"

int from_hex(char c) {
    return isdigit(c) ? c - '0' : tolower(c) - 'a' + 10;
}

void url_decode(const char *src, char *dest) {
    while (*src) {
        if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
            *dest = from_hex(src[1]) * 16 + from_hex(src[2]);
            src += 3;
            dest++;
        } else if (*src == '+') {
            *dest = ' ';
            dest++;
            src++;
        } else {
            *dest = *src;
            dest++;
            src++;
        }
    }
    *dest = '\0';
}

enum parse_http_request_error parse_http_request_line(const char* buffer, HttpRequest* req) {

    char* buffer_copy = malloc(sizeof(char) * (strlen(buffer) + 1));
    strcpy(buffer_copy, buffer);
    char *saveptr;

    char *method = strtok_r(buffer_copy, " ", &saveptr); // strtok_r already sets the null terminator
    char *path = strtok_r(NULL, " ", &saveptr);
    char *http_version = strtok_r(NULL, "\r\n", &saveptr);

    if (http_version == NULL || method == NULL || path == NULL) {
        free(buffer_copy);
        return PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST;
    }

    strncpy(req->method, method, sizeof(req->method) - 1); // safe copy
    req->method[sizeof(req->method) - 1] = '\0'; // Just safety if method overflowed and the last byte is not null

    strncpy(req->path, path, sizeof(req->path) - 1);
    req->path[sizeof(req->path) - 1] = '\0'; // Just safety if method overflowed and the last byte is not null
    url_decode(req->path, req->path);

    strncpy(req->version, http_version, sizeof(req->version) - 1);
    req->version[sizeof(req->version) - 1] = '\0'; // Just safety if method overflowed and the last byte is not null

    // Normalize version
    for (char *p = req->method; *p; ++p)
        *p = (char)toupper((unsigned char)*p);


    free(buffer_copy);
    return PARSE_HTTP_REQUEST_SUCCESS;
}

enum parse_http_request_error parse_http_request_headers(const char* buffer, HttpRequest* req) {
    char* buffer_copy = malloc(sizeof(char) * (strlen(buffer) + 1));
    strcpy(buffer_copy, buffer);

    char *saveptr;
    char *line = strtok_r(buffer_copy, "\n", &saveptr);
    line = strtok_r(NULL, "\n", &saveptr); // We skip the first line, since this is the request line

    
    for (; line != NULL; line = strtok_r(NULL, "\n", &saveptr)) {

        char *p = line;
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\r') {
            line[len - 1] = '\0';
        }

        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;  // break if the line is empty, this is the end of the headers

        char *colon = strchr(line, ':'); // find colon
        if (!colon) return PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST;

        *colon = '\0';
        char *key = line;
        char *val = colon + 1;

        while (isspace((unsigned char)*key)) key++; // trim leading spaces on key
        while (isspace((unsigned char)*val)) val++; // trim leading spaces on val

        size_t len_key = strlen(key);
        for (char *end = key + len_key; end > key && isspace((unsigned char)end[-1]); --end) { // trim leading spaces on key
            end[-1] = '\0'; // sets previous isspace cahracter to null
            len_key--;
        }

        size_t len_val = strlen(val);
        for (char *end = val + len_val; end > val && isspace((unsigned char)end[-1]); --end) { // trim trailing spaces on val
            end[-1] = '\0'; // sets previous isspace cahracter to null
            len_val--;
        }

        enum hashmap_error put_result = string_hashmap_put_case_insensitive(req->headers, key, val, len_key, len_val);
        if (put_result != 0){
            free(buffer_copy);
            return PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST;
        }
        
    }
    free(buffer_copy);
    return PARSE_HTTP_REQUEST_SUCCESS;
}

int parse_http_request(const char* buffer, HttpRequest* req) {
    req->headers = string_hashmap_t_create();
    if (req->headers == NULL) {
        return -1;
    }

    enum parse_http_request_error parse_http_request_line_result = parse_http_request_line(buffer, req);
    if (parse_http_request_line_result != PARSE_HTTP_REQUEST_SUCCESS) {
        return parse_http_request_line_result;
    }

    enum parse_http_request_error parse_http_request_headers_result = parse_http_request_headers(buffer, req);
    if (parse_http_request_headers_result != PARSE_HTTP_REQUEST_SUCCESS) {
        return parse_http_request_headers_result;
    }

    return PARSE_HTTP_REQUEST_SUCCESS;
}

int init_http_request(HttpRequest* req) {
    req->method[0] = '\0';
    req->path[0] = '\0';
    req->version[0] = '\0';
    req->headers = NULL;
    req->body = NULL;
    return 0;
}

int free_http_request(HttpRequest* req) {
    string_hashmap_free(req->headers);
    free(req->body);
    return 0;
}

// Response functions
int init_http_response(HttpResponse* res) {
    res->status_code[0] = '\0';
    res->status_message[0] = '\0';
    res->version[0] = '\0';
    res->headers = NULL;
    res->body = NULL;
    return 0;
}

int get_default_response(HttpResponse* res) {
    strcpy(res->status_code, "200");
    strcpy(res->status_message, "OK");
    strcpy(res->version, "HTTP/1.0");
    res->headers = string_hashmap_t_create();
    res->body = NULL;
    if (res->headers == NULL) {
        return -1;
    }
    char server_key[] = "Server";
    char server_value[] = "C-WebServer/1.0";
    string_hashmap_put(res->headers, server_key, server_value, strlen(server_key), strlen(server_value));

    char last_modified_key[] = "Last-Modified";
    char last_modified_value[] = "Thu, 30 Oct 2025 12:00:00 GMT";
    string_hashmap_put(res->headers, last_modified_key, last_modified_value, strlen(last_modified_key), strlen(last_modified_value));

    return 0;
}

int free_http_response(HttpResponse* res) {
    string_hashmap_free(res->headers);
    free(res->body);
    return 0;
}

int response_header_append_callback(const char* key, size_t key_len, const char* value, size_t value_len, void* user_data) {
    string_builder_append_format((struct string_builder_t*)user_data, "%s: %s\r\n", key, value);
    return 0;
}

int response_to_buffer(HttpResponse* res, char** buffer) {
    struct string_builder_t* sb = string_builder_t_create();
    string_builder_append_format(sb, "%s %s %s\r\n", res->version, res->status_code, res->status_message);

    string_hashmap_foreach(res->headers, response_header_append_callback, sb);
    string_builder_append_string(sb, "\r\n");

    string_builder_append_string(sb, res->body);

    string_builder_to_string(sb, buffer);

    string_builder_free(sb);

    return 0;
}