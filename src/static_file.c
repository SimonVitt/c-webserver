#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

#include "http.h"
#include "utils/string_builder.h"
#include "utils/string_hashmap.h"
#include "static_file.h"

#define PUBLIC_DIR "./public"

static int set_content_type(HttpResponse* response, const char* ext) {
    char content_type[256];
    if (strcmp(ext, ".html") == 0) {
        strcpy(content_type, "text/html");
    } else if (strcmp(ext, ".css") == 0) {
        strcpy(content_type, "text/css");
    } else if (strcmp(ext, ".js") == 0) {
        strcpy(content_type, "application/javascript");
    } else if (strcmp(ext, ".json") == 0) {
        strcpy(content_type, "application/json");
    } else if (strcmp(ext, ".xml") == 0) {
        strcpy(content_type, "application/xml");
    } else if (strcmp(ext, ".txt") == 0) {
        strcpy(content_type, "text/plain");
    } else if (strcmp(ext, ".png") == 0) {
        strcpy(content_type, "image/png");
    } else if (strcmp(ext, ".jpg") == 0) {
        strcpy(content_type, "image/jpeg");
    } else if (strcmp(ext, ".gif") == 0) {
        strcpy(content_type, "image/gif");
    } else if (strcmp(ext, ".svg") == 0) {
        strcpy(content_type, "image/svg+xml");
    } else if (strcmp(ext, ".ico") == 0) {
        strcpy(content_type, "image/x-icon");
    } else if (strcmp(ext, ".webp") == 0) {
        strcpy(content_type, "image/webp");
    } else if (strcmp(ext, ".mp4") == 0) {
        strcpy(content_type, "video/mp4");
    } else if (strcmp(ext, ".webm") == 0) {
        strcpy(content_type, "video/webm");
    } else if (strcmp(ext, ".ogg") == 0) {
    } else {
        strcpy(content_type, "application/octet-stream");
    }
    string_hashmap_put_case_insensitive(response->headers, "Content-Type", content_type, 12, strlen(content_type));
    return 0;
}

static int set_content_length(HttpResponse* response, size_t content_length) {
    char content_length_value[256];
    snprintf(content_length_value, 256, "%zu", content_length);
    string_hashmap_put_case_insensitive(response->headers, "Content-Length", content_length_value, 14, strlen(content_length_value));
    return 0;
}

static int set_last_modified(HttpResponse* response, time_t last_modified) {
    char last_modified_value[64];
    struct tm* gmt = gmtime(&last_modified);
    if (gmt != NULL) {
        strftime(last_modified_value, sizeof(last_modified_value), "%a, %d %b %Y %H:%M:%S GMT", gmt);
        string_hashmap_put_case_insensitive(response->headers, "Last-Modified", last_modified_value, 13, strlen(last_modified_value));
    }
    return 0;
}

static int parse_http_date(const char* date_str, time_t* result) {
    struct tm tm = {0};
    // Try RFC 1123 format: "Wed, 09 Jun 2021 10:18:14 GMT"
    char* parsed = strptime(date_str, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (parsed == NULL || *parsed != '\0') {
        return -1;
    }
    *result = timegm(&tm); // timegm converts to time_t (UTC)
    return 0;
}

static int check_if_modified_since(time_t file_mtime, const char* if_modified_since_str) {
    if (if_modified_since_str == NULL || strlen(if_modified_since_str) == 0) {
        return 1; // No header, send file
    }
    
    time_t client_date;
    if (parse_http_date(if_modified_since_str, &client_date) != 0) {
        return 1; // Invalid date, send file
    }
    
    // File is newer if mtime > client_date
    // If file_mtime <= client_date, file hasn't changed (send 304)
    return (file_mtime > client_date) ? 1 : 0;
}

static int set_data_in_response(HttpResponse* response, const char* file_path, struct stat* st) {

    FILE* file = fopen(file_path, "rb"); // open the file
    if (file == NULL) {
        return -1;
    }
    char *content = malloc(st->st_size + 1); // +1 for null terminator
    if (content == NULL) {
        fclose(file);
        return -1;
    }
    size_t read_result = fread(content, 1, st->st_size, file); // read the file content
    if (read_result != (size_t)st->st_size) { // if the read result is not the same as the file size, return -1
        free(content);
        fclose(file);
        return -1;
    }
    content[st->st_size] = '\0'; // null-terminate for safety
    response->body_length = st->st_size;
    fclose(file);
    response->body = content; // set the body of the response

    const char* ext = strrchr(file_path, '.'); // get the extension of the file
    if (ext == NULL) {
        ext = "";
    }
    set_content_type(response, ext); // set the content type of the response
    set_content_length(response, response->body_length); // set the content length of the response
    set_last_modified(response, st->st_mtime); // set the last modified of the response
    return 0;
}

static int set_error_response(HttpResponse* response, const char* status_code, const char* status_message, const char* file_path) {
    strcpy(response->status_code, status_code);
    strcpy(response->status_message, status_message);

    // Build full path - always prepend PUBLIC_DIR for error files
    char full_path[PATH_MAX];
    snprintf(full_path, PATH_MAX, "%s%s", PUBLIC_DIR, file_path);

    struct stat st;
    if (stat(full_path, &st) != 0) {
        response->body = strdup("<html><body><h1>Error</h1></body></html>"); // Dynamically allocate the body
        response->body_length = strlen(response->body);
        if (response->body == NULL) {
            return -1;
        }
        set_content_type(response, ".html");
        set_content_length(response, strlen(response->body));
        return 0;
    }
    set_data_in_response(response, full_path, &st);
    return 0;
}

int serve_static_file(const char* path, HttpResponse* response, HttpRequest* request) {

    char file_path[PATH_MAX]; // create a buffer to store the file path
    int result;

    if (path[strlen(path) - 1] == '/' || strcmp(path, "/") == 0) {
        // Directory request - serve index.html
        result = snprintf(file_path, PATH_MAX, "%s%sindex.html", PUBLIC_DIR, path);
    } else {
        result = snprintf(file_path, PATH_MAX, "%s%s", PUBLIC_DIR, path);
    }

    if (result < 0 || result >= PATH_MAX) { // if the result is less than 0 or greater than the PATH_MAX, return 404, this means the path is too long
        set_error_response(response, "404", "Not Found", ERROR_404_PATH);
        return 0;
    }

    char resolved[PATH_MAX];
    if (!realpath(file_path, resolved)) { // resolve the path to an absolute path
        set_error_response(response, "404", "Not Found", ERROR_404_PATH);
        return 0;
    }

    char public_real[PATH_MAX];
    if (!realpath(PUBLIC_DIR, public_real)) {
        // Public directory doesn't exist
        set_error_response(response, "500", "Internal Server Error", ERROR_500_PATH);
        return 0;
    }

    if (strncmp(resolved, public_real, strlen(public_real)) != 0) {
        // Path traversal attempt - requested file is outside public/
        set_error_response(response, "403", "Forbidden", ERROR_403_PATH);
        return 0;
    }

    struct stat st;
    if (stat(resolved, &st) != 0 || !S_ISREG(st.st_mode)) { // check if the path is a regular file
        set_error_response(response, "404", "Not Found", ERROR_404_PATH);
        return 0;
    }


    char* if_modified_since = NULL;
    if (string_hashmap_get_case_insensitive(request->headers, "If-Modified-Since", strlen("If-Modified-Since"), &if_modified_since) == HASHMAP_SUCCESS) {
        if (if_modified_since != NULL && strlen(if_modified_since) > 0) {
            if (!check_if_modified_since(st.st_mtime, if_modified_since)) {
                // File not modified - return 304 Not Modified
                strcpy(response->status_code, "304");
                strcpy(response->status_message, "Not Modified");
                
                // Set required headers for 304
                set_last_modified(response, st.st_mtime);
                
                // 304 responses must not include a message body
                response->body = NULL;
                response->body_length = 0;
                
                // Remove Content-Length and Content-Type (not needed for 304)
                // But keep Date, Server, Connection headers from get_default_response
                
                return 0;
            }
        }
    }

    int set_data_in_response_result = set_data_in_response(response, resolved, &st);
    if (set_data_in_response_result != 0) {
        set_error_response(response, "500", "Internal Server Error", ERROR_500_PATH);
        return 0;
    }

    return 0;
}