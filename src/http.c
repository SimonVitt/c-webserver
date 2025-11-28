#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include "./../include/http.h"
#include "./../include/utils/string_builder.h"
#include "./../include/utils/string_hashmap.h"

int get_current_time_string(char* time_string_buffer, size_t time_string_buffer_size) {
    time_t now = time(NULL);
    struct tm* gmt = gmtime(&now);
    if (gmt == NULL) {
        return -1;
    }
    size_t written = strftime(time_string_buffer, time_string_buffer_size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
    if (written == 0) {
        return -1;
    }
    return 0;
}

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

int is_http_1_1(const HttpRequest* req) {
    if (req == NULL || req->version[0] == '\0') {
        return 0;
    }
    return strncasecmp(req->version, "HTTP/1.1", 8) == 0; // Case-insensitive comparison
}

// Check if request is HTTP/1.0
int is_http_1_0(const HttpRequest* req) {
    if (req == NULL || req->version[0] == '\0') {
        return 0;
    }
    return strncasecmp(req->version, "HTTP/1.0", 8) == 0; // Case-insensitive comparison
}

// RFC 9112: Check for bare CR characters (CR not followed by LF)
// Returns 1 if bare CR found, 0 otherwise
static int has_bare_cr(const char* buffer, size_t buffer_len) {
    for (size_t i = 0; i < buffer_len; i++) {
        if (buffer[i] == '\r') {
            // Check if next character is \n
            if (i + 1 >= buffer_len || buffer[i + 1] != '\n') {
                return 1; // Bare CR found
            }
        }
    }
    return 0; // No bare CR
}

enum parse_http_request_error parse_http_request_line(const char* buffer, HttpRequest* req) {
    // Find the end of the first line
    char* line_end = strstr(buffer, "\r\n");
    if (line_end == NULL) {
        return PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST;
    }
    
    // Copy only the first line
    size_t line_len = line_end - buffer;
    char* first_line = malloc(line_len + 1);
    if (first_line == NULL) {
        return PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST;
    }
    memcpy(first_line, buffer, line_len);
    first_line[line_len] = '\0';
    
    // Parse: METHOD SP PATH SP VERSION
    char *saveptr;
    char *method = strtok_r(first_line, " ", &saveptr);
    char *path = strtok_r(NULL, " ", &saveptr);
    char *http_version = strtok_r(NULL, " ", &saveptr); // Should be last token
    char *extra = strtok_r(NULL, " ", &saveptr); // Should be NULL
    
    // Validate: must have exactly 3 parts
    if (method == NULL || path == NULL || http_version == NULL || extra != NULL) {
        free(first_line);
        return PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST;
    }
    
    // Validate version format starts with HTTP/
    if (strncmp(http_version, "HTTP/", 5) != 0) {
        free(first_line);
        return PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST;
    }

    strncpy(req->method, method, sizeof(req->method) - 1);
    req->method[sizeof(req->method) - 1] = '\0';

    strncpy(req->path, path, sizeof(req->path) - 1);
    req->path[sizeof(req->path) - 1] = '\0';
    url_decode(req->path, req->path);

    strncpy(req->version, http_version, sizeof(req->version) - 1);
    req->version[sizeof(req->version) - 1] = '\0';

    // Normalize version and method to uppercase
    for (char *p = req->version; *p; ++p)
        *p = (char)toupper((unsigned char)*p);
    for (char *p = req->method; *p; ++p)
        *p = (char)toupper((unsigned char)*p);

    free(first_line);
    return PARSE_HTTP_REQUEST_SUCCESS;
}

enum parse_http_request_error parse_http_request_headers_internal(const char* buffer, HttpRequest* req) {
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

int parse_http_request_headers(const char* buffer, HttpRequest* req) {
    req->headers = string_hashmap_t_create();
    if (req->headers == NULL) {
        return -1;
    }

    // RFC 9112: Reject bare CR characters (MUST requirement)
    size_t buffer_len = strlen(buffer);
    if (has_bare_cr(buffer, buffer_len)) {
        return PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST;
    }

    enum parse_http_request_error parse_http_request_line_result = parse_http_request_line(buffer, req);
    if (parse_http_request_line_result != PARSE_HTTP_REQUEST_SUCCESS) {
        return parse_http_request_line_result;
    }

    enum parse_http_request_error parse_http_request_headers_result = parse_http_request_headers_internal(buffer, req);
    if (parse_http_request_headers_result != PARSE_HTTP_REQUEST_SUCCESS) {
        return parse_http_request_headers_result;
    }

    return PARSE_HTTP_REQUEST_SUCCESS;
}

int parse_http_request_body(const char* buffer, HttpRequest* req) {
    // To be implemented
    return 0;
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
    res->body_length = 0;
    return 0;
}

int get_default_response(HttpResponse* res, HttpRequest* req) {
    strcpy(res->status_code, "200");
    strcpy(res->status_message, "OK");
    strcpy(res->version, req->version);
    res->headers = string_hashmap_t_create();
    res->body = NULL;
    if (res->headers == NULL) {
        return -1;
    }
    
    // Use case-insensitive put for consistent lookups
    string_hashmap_put_case_insensitive(res->headers, "Server", "C-WebServer/1.0", 6, 15);

    char date_value[64];
    get_current_time_string(date_value, sizeof(date_value));
    string_hashmap_put_case_insensitive(res->headers, "Date", date_value, 4, strlen(date_value));

    char* client_connection_value = NULL;
    if (string_hashmap_get_case_insensitive(req->headers, "Connection", 10, &client_connection_value) == HASHMAP_SUCCESS && client_connection_value != NULL && strlen(client_connection_value) > 0) {
        // Client specified Connection header - use their value
        string_hashmap_put_case_insensitive(res->headers, "Connection", client_connection_value, 10, strlen(client_connection_value));
    } else {
        if (is_http_1_1(req)) {
            string_hashmap_put_case_insensitive(res->headers, "Connection", "keep-alive", 10, 10);
        } else {
            string_hashmap_put_case_insensitive(res->headers, "Connection", "close", 10, 5);
        }
    }

    return 0;
}

int add_security_headers(HttpResponse* res, int is_https) {
    // Use case-insensitive put for consistent lookups
    string_hashmap_put_case_insensitive(res->headers, "X-Content-Type-Options", "nosniff", 22, 7);
    string_hashmap_put_case_insensitive(res->headers, "X-Frame-Options", "DENY", 15, 4);
    string_hashmap_put_case_insensitive(res->headers, "X-XSS-Protection", "1; mode=block", 16, 13);

    if (is_https) {
        string_hashmap_put_case_insensitive(res->headers, "Strict-Transport-Security", 
                                            "max-age=31536000; includeSubDomains", 25, 35);
    }

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
    
    string_builder_length(sb, &res->headers_length);

    string_builder_append_string_n(sb, res->body, res->body_length);

    string_builder_to_string(sb, buffer);

    string_builder_free(sb);

    return 0;
}