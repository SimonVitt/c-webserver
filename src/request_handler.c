#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <errno.h>
#include <openssl/err.h>
#include "http.h"
#include "static_file.h"
#include "utils/string_hashmap.h"
#include "request_handler.h"
#include "connection.h"

static int init_client_request(Client* client) {
    if (client->request == NULL) {
        client->request = calloc(1, sizeof(HttpRequest));
        if (client->request == NULL) {
            perror("malloc");
            return -1;
        }
        client->last_activity = time(NULL);
        init_http_request(client->request);
    }
    return 0;
}

static int validate_request_headers(Client* client) {
    int parse_result = parse_http_request_headers(client->buffer, client->request);
    if (parse_result != PARSE_HTTP_REQUEST_SUCCESS) {
        send_error_response(client, ERROR_400_PATH, "400", "Bad Request");
        return -1;
    }

    // HTTP/1.1 requires Host header
    if (is_http_1_1(client->request)) {
        char* host_str = NULL;
        if (string_hashmap_get_case_insensitive(client->request->headers, "Host", strlen("Host"), &host_str) != HASHMAP_SUCCESS || 
            host_str == NULL || strlen(host_str) == 0) {
            send_error_response(client, ERROR_400_PATH, "400", "Bad Request");
            return -1;
        }
    }

    if (strcmp(client->request->method, "GET") != 0 && strcmp(client->request->method, "HEAD") != 0) {
        send_error_response(client, ERROR_405_PATH, "405", "Method Not Allowed");
        return -1;
    }

    return 0;
}

static void process_content_length(Client* client) {
    char* content_length_str = NULL;
    if (string_hashmap_get_case_insensitive(client->request->headers, "Content-Length", strlen("Content-Length"), &content_length_str) != HASHMAP_SUCCESS) {
        client->content_length = 0;
    } else {
        client->content_length = atol(content_length_str);
    }
}

static int check_expect_header(Client* client) {
    if (is_http_1_1(client->request)) {
        char* expect_value = NULL;
        if (string_hashmap_get_case_insensitive(client->request->headers, "Expect", strlen("Expect"), &expect_value) == HASHMAP_SUCCESS) {
            if (expect_value != NULL && strcasecmp(expect_value, "100-continue") == 0) {
                client->state = CLIENT_STATE_SENDING_100_CONTINUE;
                return 1; // Need to send 100 Continue
            }
        }
    }
    return 0; // No 100 Continue needed
}

static int process_request_body(Client* client) {
    if (client->bytes_received - client->headers_end_offset >= client->content_length) {
        int parse_result = parse_http_request_body(client->buffer, client->request);
        if (parse_result != PARSE_HTTP_REQUEST_SUCCESS) {
            send_error_response(client, ERROR_400_PATH, "400", "Bad Request");
            return 0;
        }
        client->state = CLIENT_STATE_SENDING_RESPONSE;
        return 1; // Body complete
    }
    return 0; // Body not complete yet
}

static int build_http_response(Client* client) {
    client->response = calloc(1, sizeof(HttpResponse));
    if (client->response == NULL) {
        perror("malloc");
        connection_free_client(client, 0);
        return -1;
    }
    init_http_response(client->response);
    get_default_response(client->response, client->request);
    add_security_headers(client->response, client->ssl != NULL);
    serve_static_file(client->request->path, client->response, client->request);

    int result = response_to_buffer(client->response, &client->response_buffer);
    return result;
}

int handle_http_request(Client* client) {
    if (init_client_request(client) < 0) {
        return -1;
    }

    if (client->state == CLIENT_STATE_IDLE) {
        client->state = CLIENT_STATE_RECEIVING_HEADERS;
    } 

    if (client->state == CLIENT_STATE_RECEIVING_HEADERS) {
        int headers_complete;
        check_if_headers_complete(client, &headers_complete);
        if (!headers_complete) {
            return 0; // Wait for more data
        }
        if (validate_request_headers(client) < 0) {
            return 0; // Error response sent
        }

        process_content_length(client);

        if (check_expect_header(client)) {
            return 0; // Will send 100 Continue
        }
        client->state = CLIENT_STATE_RECEIVING_BODY;
    }

    if (client->state == CLIENT_STATE_RECEIVING_BODY) {
        int body_complete = process_request_body(client);
        if (!body_complete) {
            return 0; // Wait for more data or error response sent
        }
    }

    if (client->state == CLIENT_STATE_SENDING_RESPONSE) {
        return build_http_response(client);
    }
    return 0;
}

int send_error_response(Client* client, const char* error_path, const char* status_code, const char* status_message) {
    client->response = calloc(1, sizeof(HttpResponse));
    if (client->response == NULL) {
        perror("malloc");
        connection_free_client(client, 0);
        return -1;
    }
    init_http_response(client->response);
    get_default_response(client->response, client->request);
    add_security_headers(client->response, client->ssl != NULL);
    strcpy(client->response->status_code, status_code);
    strcpy(client->response->status_message, status_message);

    serve_static_file(error_path, client->response, client->request);

    client->state = CLIENT_STATE_SENDING_RESPONSE;
    return response_to_buffer(client->response, &client->response_buffer);
}

int send_100_continue(int fd, Client* client, ServerState* server_state) {
    const char* response = "HTTP/1.1 100 Continue\r\n\r\n";
    size_t response_len = strlen(response);
    size_t remaining = response_len - client->continue_bytes_sent;
    
    conn_io_result_t io_result;
    int send_result = connection_write(
        fd,
        client->ssl,
        response + client->continue_bytes_sent,
        remaining,
        &io_result
    );
    
    if (io_result == CONN_IO_WANT_WRITE || io_result == CONN_IO_WANT_READ) {
        client->state = CLIENT_STATE_SENDING_100_CONTINUE;
        if (epoll_modify(server_state->epfd, fd, EPOLLIN | EPOLLOUT) < 0) {
            perror("epoll_ctl: mod EPOLLOUT for 100 Continue");
            return -1;
        }
        return 0; // Wait for socket to be writable
    } else if (io_result == CONN_IO_ERROR) {
        return -1; // Fatal error (already logged by connection_write)
    }
        
    client->continue_bytes_sent += send_result;
    
    if (client->continue_bytes_sent >= response_len) {
        // Fully sent - transition to RECEIVING_BODY
        client->continue_bytes_sent = 0;
        printf("[100 CONTINUE] Fully sent to client fd=%d\n", fd);
        return 1; // Success
    }

    // Partial send, so register EPOLLOUT (only if not already registered)
    client->state = CLIENT_STATE_SENDING_100_CONTINUE;
    if (epoll_modify(server_state->epfd, fd, EPOLLIN | EPOLLOUT) < 0) {
        perror("epoll_ctl: mod EPOLLOUT for 100 Continue");
        return -1;
    }
    return 0; // Partial, will continue
}

int should_close_connection(const HttpResponse* res) {
    char* connection_value = NULL;
    if (string_hashmap_get_case_insensitive(res->headers, "Connection", strlen("Connection"), &connection_value) == HASHMAP_SUCCESS && connection_value != NULL && strlen(connection_value) > 0) {
        if (strcasecmp(connection_value, "close") == 0) {
            return 1; // Should close
        }
    }
    // Check request version for default behavior
    if (strncmp(res->version, "HTTP/1.0", 8) == 0) {
        return 1; // HTTP/1.0 defaults to close
    }
    return 0; // HTTP/1.1 defaults to keep-alive
}

int check_if_headers_complete(Client* client, int* headers_complete) {
    char* headers_end = strstr(client->buffer, "\r\n\r\n");
    if (headers_end == NULL) {
        // Only allow \n\n for HTTP/1.0
        if (client->request != NULL && is_http_1_0(client->request)) {
            char* headers_end_n = strstr(client->buffer, "\n\n");
            if (headers_end_n == NULL) {
                *headers_complete = 0;
                return 0;
            }
            client->headers_end_offset = headers_end_n - client->buffer + 2;
        } else {
            *headers_complete = 0;
            return 0;
        }
    } else {
        client->headers_end_offset = headers_end - client->buffer + 4;
    }
    *headers_complete = 1;
    return 0;
}