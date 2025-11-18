#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "./../include/http.h"
#include "./../include/utils/string_builder.h"
#include "./../include/utils/string_hashmap.h"
#include "./../include/static_file.h"

#define PUBLIC_DIR "./public"

int set_content_type(HttpResponse* response, const char* ext) {
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
    char content_type_key[] = "Content-Type";
    string_hashmap_put(response->headers, content_type_key, content_type, strlen(content_type_key), strlen(content_type));
    return 0;
}

int set_content_length(HttpResponse* response, size_t content_length) {
    char content_length_key[] = "Content-Length";
    char content_length_value[256];
    snprintf(content_length_value, 256, "%zu", content_length);
    string_hashmap_put(response->headers, content_length_key, content_length_value, strlen(content_length_key), strlen(content_length_value));
    return 0;
}

int set_data_in_response(HttpResponse* response, const char* file_path, struct stat* st) {

    FILE* file = fopen(file_path, "rb"); // open the file
    if (file == NULL) {
        return -1;
    }
    char *content = malloc(st->st_size); // create a buffer to store the file content
    if (content == NULL) {
        fclose(file);
        return -1;
    }
    size_t read_result = fread(content, 1, st->st_size, file); // read the file content
    if (read_result != st->st_size) { // if the read result is not the same as the file size, return -1
        free(content);
        fclose(file);
        return -1;
    }
    response->body_length = st->st_size;
    fclose(file);
    response->body = content; // set the body of the response

    const char* ext = strrchr(file_path, '.'); // get the extension of the file
    if (ext == NULL) {
        ext = "";
    }
    set_content_type(response, ext); // set the content type of the response
    set_content_length(response, response->body_length); // set the content length of the response
    return 0;
}

int set_error_response(HttpResponse* response, const char* status_code, const char* status_message, const char* file_path) {
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

int serve_static_file(const char* path, HttpResponse* response) {

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

    int set_data_in_response_result = set_data_in_response(response, resolved, &st);
    if (set_data_in_response_result != 0) {
        set_error_response(response, "500", "Internal Server Error", ERROR_500_PATH);
        return 0;
    }

    return 0;
}