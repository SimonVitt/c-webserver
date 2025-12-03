/**
 * @file static_file.h
 * @brief Static file serving with caching and security
 */

#ifndef STATIC_FILE_H
#define STATIC_FILE_H

#include "http.h"

/** @brief Error page paths relative to public/ */
#define ERROR_400_PATH "/errors/400.html"
#define ERROR_403_PATH "/errors/403.html"
#define ERROR_404_PATH "/errors/404.html"
#define ERROR_405_PATH "/errors/405.html"
#define ERROR_500_PATH "/errors/500.html"

/**
 * @brief Serve static file or error page
 * 
 * Handles: path traversal protection, If-Modified-Since,
 * content type detection, directory index (index.html).
 * 
 * @param path      Request path (e.g. "/index.html")
 * @param response  Response to populate (status, headers, body)
 * @param request   Request (for If-Modified-Since header)
 * @return 0 (always succeeds, errors set response status)
 */
int serve_static_file(const char* path, HttpResponse* response, HttpRequest* request);

#endif
