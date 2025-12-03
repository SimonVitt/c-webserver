/**
 * @file http.h
 * @brief HTTP/1.x request parsing and response generation
 */

#ifndef HTTP_H
#define HTTP_H

#include "utils/string_hashmap.h"

/** @brief Parsed HTTP request */
typedef struct {
    char method[8];                    /**< GET, POST, HEAD, etc. */
    char path[256];                    /**< URL-decoded request path */
    char version[16];                  /**< HTTP/1.0 or HTTP/1.1 */
    struct string_hashmap_t* headers;  /**< Request headers (owned) */
    char* body;                        /**< Request body or NULL (owned) */
} HttpRequest;

/** @brief HTTP response to send */
typedef struct {
    char status_code[4];               /**< 200, 404, etc. */
    char status_message[256];          /**< OK, Not Found, etc. */
    char version[16];                  /**< HTTP/1.0 or HTTP/1.1 */
    struct string_hashmap_t* headers;  /**< Response headers (owned) */
    size_t headers_length;             /**< Serialized headers length */
    char* body;                        /**< Response body or NULL (owned) */
    size_t body_length;                /**< Body length in bytes */
} HttpResponse;

/** @brief Request parsing result codes */
enum parse_http_request_error {
    PARSE_HTTP_REQUEST_SUCCESS = 0,
    PARSE_HTTP_REQUEST_ERROR_INVALID_REQUEST = -1
};

/**
 * @brief Check if request uses HTTP/1.1
 * @return 1 if HTTP/1.1, 0 otherwise
 */
int is_http_1_1(const HttpRequest* req);

/**
 * @brief Check if request uses HTTP/1.0
 * @return 1 if HTTP/1.0, 0 otherwise
 */
int is_http_1_0(const HttpRequest* req);

/**
 * @brief Parse request line and headers from buffer
 * @param buffer  Null-terminated raw HTTP request
 * @param req     Output structure (call free_http_request after use)
 * @return PARSE_HTTP_REQUEST_SUCCESS or error code
 */
int parse_http_request_headers(const char* buffer, HttpRequest* req);

/**
 * @brief Parse request body (placeholder)
 */
int parse_http_request_body(const char* buffer, HttpRequest* req);

/**
 * @brief Initialize request struct to empty state
 */
int init_http_request(HttpRequest* req);

/**
 * @brief Free request resources (headers, body)
 */
int free_http_request(HttpRequest* req);

/**
 * @brief Initialize response struct to empty state
 */
int init_http_response(HttpResponse* res);

/**
 * @brief Populate response with defaults (200 OK, Date, Server, Connection)
 * @param res  Response to populate
 * @param req  Request (for version and Connection header)
 */
int get_default_response(HttpResponse* res, HttpRequest* req);

/**
 * @brief Add security headers (X-Frame-Options, HSTS, etc.)
 * @param is_https  1 to include HSTS header
 */
int add_security_headers(HttpResponse* res, int is_https);

/**
 * @brief Free response resources (headers, body)
 */
int free_http_response(HttpResponse* res);

/**
 * @brief Serialize response to wire format
 * @param res     Response to serialize
 * @param buffer  Output buffer (caller must free)
 */
int response_to_buffer(HttpResponse* res, char** buffer);

#endif
