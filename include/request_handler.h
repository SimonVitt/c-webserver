/**
 * @file request_handler.h
 * @brief HTTP request processing state machine
 */

#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include "server.h"

/**
 * @brief Process client request based on current state
 * 
 * Drives the state machine: parse headers, validate, build response.
 * Call repeatedly as data arrives until response is ready.
 * 
 * @return 0 on success/wait, -1 on fatal error
 */
int handle_http_request(Client* client);

/**
 * @brief Send HTTP 100 Continue response
 * @return 1 fully sent, 0 partial (retry), -1 error
 */
int send_100_continue(int fd, Client* client, ServerState* server_state);

/**
 * @brief Check if connection should close after response
 * @return 1 to close, 0 to keep alive
 */
int should_close_connection(const HttpResponse* res);

/**
 * @brief Check if request headers are complete (ends with CRLFCRLF)
 * @param headers_complete  Output: 1 if complete, 0 if not
 */
int check_if_headers_complete(Client* client, int* headers_complete);

/**
 * @brief Build and queue error response
 */
int send_error_response(Client* client, const char* error_path, 
                        const char* status_code, const char* status_message);

#endif
