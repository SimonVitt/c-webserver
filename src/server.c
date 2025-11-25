#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <fcntl.h>   // For fcntl() and O_NONBLOCK
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "./../include/http.h"
#include "./../include/static_file.h"
#include "./../include/server.h"

#define MAX_EVENTS 128
#define MAX_CLIENTS 20000 // the maximum number of clients that can be connected to the server
#define BACKLOG 512 // how many pending connections queue will hold

typedef struct {
    Client* clients; // We use an array of clients to store the clients that are connected to the server. the client will always be at the index of the file descriptor of the socket. We dont use a hashmap because this would cause of memory overhead (more often mallocing and freeing memory).
    int epfd; // epoll file descriptor
    int http_socket;
    int https_socket;
    int active_connections;
    int* active_fds;
    SSL_CTX* ssl_ctx; //SSL context (NULL if not using HTTPS)
} ServerState;

void log_request(HttpRequest* req, HttpResponse* res, double time_ms) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct tm* gmt = gmtime(&tv.tv_sec);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", gmt);
    
    char timestamp_with_ms[80];
    int ms = (int)(tv.tv_usec / 1000);
    snprintf(timestamp_with_ms, sizeof(timestamp_with_ms), "%s.%03d", timestamp, ms);
    
    printf("[REQUEST] [%s GMT] %s %s %s - %s %s (%.2fms)\n",
           timestamp_with_ms,
           req->method,
           req->path,
           req->version,
           res->status_code,
           res->status_message,
           time_ms);
}

int handle_new_connection(ServerState* server_state, int is_https) {
    int listening_socket = is_https ? server_state->https_socket : server_state->http_socket;

    struct sockaddr_storage client_addr; // ip... address of the client
    socklen_t addr_size = sizeof client_addr; // size of the ip... address of the client
    int new_fd = accept(listening_socket, (struct sockaddr *)&client_addr, &addr_size); // we get the addrinfo of someone who wrote/(wants to write?) to this socket. Now we can read and write from there    
        
    if (new_fd < 0) {
        perror("accept");
        return -1;
    } else if (server_state->active_connections >= MAX_CLIENTS) {
        perror("Max clients reached\n");
        close(new_fd); // we close directly without close_connection because we it wasnt a client yet and not counted in the active_connections
        return -1;
    }

    // Make socket non-blocking
    int flags = fcntl(new_fd, F_GETFL, 0); // get the current flags of the socket
    if (flags < 0) {
        perror("fcntl F_GETFL");
        close(new_fd);
        return -1;
    }
    if (fcntl(new_fd, F_SETFL, flags | O_NONBLOCK) < 0) { // set the flags of the socket to the current flags and O_NONBLOCK
        perror("fcntl F_SETFL");
        close(new_fd);
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = new_fd;
    if (epoll_ctl(server_state->epfd, EPOLL_CTL_ADD, new_fd, &ev) < 0) {
        perror("epoll_ctl: add client");
        close(new_fd); // we close directly without close_connection because we it wasnt a client yet and not counted in the active_connections
        return -1;
    }
    server_state->active_fds[server_state->active_connections] = new_fd;
    server_state->active_connections++;

    // Initialize SSL for this connection if SSL is enabled
    server_state->clients[new_fd].ssl = NULL;
    if (is_https && server_state->ssl_ctx != NULL) {
        // Create a new SSL session object for this client connection.
        // Uses the global SSL_CTX configuration (cert, key, protocols, ciphers).
        SSL* ssl = SSL_new(server_state->ssl_ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            close(new_fd);
            server_state->active_connections--;
            return -1;
        }
        
        // Attach the accepted TCP socket (new_fd) to the SSL object.
        // This tells OpenSSL to read/write encrypted data over this socket.
        if (SSL_set_fd(ssl, new_fd) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(new_fd);
            server_state->active_connections--;
            return -1;
        }
        
        server_state->clients[new_fd].ssl = ssl;
        server_state->clients[new_fd].state = CLIENT_STATE_SSL_HANDSHAKE;  // Start handshake
    } else {
        server_state->clients[new_fd].state = CLIENT_STATE_IDLE;
    }

    server_state->clients[new_fd].bytes_received = 0;
    server_state->clients[new_fd].last_activity = time(NULL);
    server_state->clients[new_fd].request = NULL;
    server_state->clients[new_fd].headers_end_offset = 0;
    server_state->clients[new_fd].content_length = 0;
    server_state->clients[new_fd].body_bytes_received = 0;
    server_state->clients[new_fd].response = NULL;
    server_state->clients[new_fd].response_buffer = NULL;
    server_state->clients[new_fd].bytes_sent = 0;
    server_state->clients[new_fd].continue_bytes_sent = 0;
    const char* protocol = is_https ? "HTTPS" : "HTTP";
    printf("[CONNECTION] New %s connection: fd=%d (total active: %d)\n", protocol, new_fd, server_state->active_connections);

    return 0;
}

int free_client(Client* client, int keep_ssl) {
    if (!keep_ssl && client->ssl != NULL) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    if (client->request != NULL) {
        free_http_request(client->request);
        client->request = NULL;
    }
    if (client->response != NULL) {
        free_http_response(client->response);
        client->response = NULL;
    }
    if (client->response_buffer != NULL) {
        free(client->response_buffer);
    }
    client->state = CLIENT_STATE_NO_CONNECTION;
    client->request = NULL;
    client->response = NULL;
    client->response_buffer = NULL;
    client->bytes_received = 0;
    client->headers_end_offset = 0;
    client->content_length = 0;
    client->body_bytes_received = 0;
    client->last_activity = 0;
    client->bytes_sent = 0;
    client->request_start.tv_sec = 0;
    client->request_start.tv_usec = 0;
    client->continue_bytes_sent = 0;
    return 0;
}

int close_connection(int fd, ServerState* server_state, int do_shutdown) {
    if (epoll_ctl(server_state->epfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        perror("epoll_ctl: delete client");
        return -1;
    }
    if (do_shutdown) {
        int shutdown_result = shutdown(fd, SHUT_RDWR); // close the socket for reading and writing first, so the peer is notified of the closure
        if (shutdown_result < 0) {
            perror("shutdown");
            return -1;
        }
    }
    int close_result = close(fd); // close the socket
    if (close_result < 0) {
        perror("close");
        return -1;
    }
    for (int i = 0; i < server_state->active_connections; i++) {
        if (server_state->active_fds[i] == fd) {
            // Swap with last element
            server_state->active_fds[i] = server_state->active_fds[server_state->active_connections - 1];
            break;
        }
    }
    server_state->active_connections--;
    printf("[CONNECTION] Closing connection: fd=%d (total active: %d)\n", fd, server_state->active_connections);
    return 0;
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

int send_error_response(Client* client, const char* error_path, const char* status_code, const char* status_message) {
    client->response = calloc(1, sizeof(HttpResponse));
    if (client->response == NULL) {
        perror("malloc");
        free_client(client, 0);
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
    
    size_t offset = client->continue_bytes_sent;
    size_t remaining = response_len - offset;
    
    int send_result;
    if (client->ssl != NULL) {
        send_result = SSL_write(client->ssl, response + offset, remaining);
    } else {
        send_result = send(fd, response + offset, remaining, 0);
    }
    
    if (send_result < 0) {
        if (client->ssl != NULL) {
            // SSL error handling
            int ssl_error = SSL_get_error(client->ssl, send_result);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                client->state = CLIENT_STATE_SENDING_100_CONTINUE;
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLOUT;
                ev.data.fd = fd;
                if (epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
                    perror("epoll_ctl: mod EPOLLOUT for 100 Continue");
                    return -1;
                }
                return 0;
            } else {
                ERR_print_errors_fp(stderr);
                return -1;
            }
        } else {
            // Plain socket error handling
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                client->state = CLIENT_STATE_SENDING_100_CONTINUE;
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLOUT;
                ev.data.fd = fd;
                if (epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
                    perror("epoll_ctl: mod EPOLLOUT for 100 Continue");
                    return -1;
                }
                return 0;
            } else {
                perror("send 100 Continue");
                return -1;
            }
        }
    }
    
    client->continue_bytes_sent += send_result;
    
    if (client->continue_bytes_sent >= response_len) {
        // Fully sent - transition to RECEIVING_BODY
        client->continue_bytes_sent = 0;
        printf("[100 CONTINUE] Fully sent to client fd=%d\n", fd);
        return 1; // Success
    } else {
        // Partial send, so register EPOLLOUT (only if not already registered)
        client->state = CLIENT_STATE_SENDING_100_CONTINUE;
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        if (epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
            perror("epoll_ctl: mod EPOLLOUT for 100 Continue");
            return -1;
        }
        return 0; // Partial, will continue
    }
}

int handle_http_request(Client* client) {
    
    if (client->request == NULL) {
        client->request = calloc(1, sizeof(HttpRequest));
        if (client->request == NULL) {
            perror("malloc");
            return -1;
        }
        client->last_activity = time(NULL);
        init_http_request(client->request);
    }
    

    if (client->state == CLIENT_STATE_IDLE) {
        client->state = CLIENT_STATE_RECEIVING_HEADERS;
    } 
    if (client->state == CLIENT_STATE_RECEIVING_HEADERS) {
        int headers_complete;
        int parse_result;
        check_if_headers_complete(client, &headers_complete);
        if (headers_complete) {
            parse_result = parse_http_request_headers(client->buffer, client->request);
            if (parse_result != PARSE_HTTP_REQUEST_SUCCESS) {
                send_error_response(client, ERROR_400_PATH, "400", "Bad Request");
                return 0;
            }
            if (is_http_1_1(client->request)) {
                char* host_str = NULL;
                if (string_hashmap_get_case_insensitive(client->request->headers, "Host", strlen("Host"), &host_str) != HASHMAP_SUCCESS || host_str == NULL || strlen(host_str) == 0) {
                    send_error_response(client, ERROR_400_PATH, "400", "Bad Request");
                    return 0;
                }
            }

            if (strcmp(client->request->method, "GET") != 0 && strcmp(client->request->method, "HEAD") != 0) {
                send_error_response(client, ERROR_405_PATH, "405", "Method Not Allowed");
                return 0;
            }

            char* content_length_str = NULL;
            if (string_hashmap_get_case_insensitive(client->request->headers, "Content-Length", strlen("Content-Length"), &content_length_str) != HASHMAP_SUCCESS) {
                client->content_length = 0;
            } else {
                client->content_length = atol(content_length_str);
            }


            if (is_http_1_1(client->request)) {
                char* expect_value = NULL;
                if (string_hashmap_get_case_insensitive(client->request->headers, "Expect", strlen("Expect"), &expect_value) == HASHMAP_SUCCESS) {
                    if (expect_value != NULL && strcasecmp(expect_value, "100-continue") == 0) {
                        client->state = CLIENT_STATE_SENDING_100_CONTINUE;
                        return 0;
                    }
                }
            }

            client->state = CLIENT_STATE_RECEIVING_BODY;

        } else{
            return 0;
        }
    }

    if (client->state == CLIENT_STATE_RECEIVING_BODY) {
        if (client->bytes_received - client->headers_end_offset >= client->content_length) {
            int parse_result = parse_http_request_body(client->buffer, client->request);
            if (parse_result != PARSE_HTTP_REQUEST_SUCCESS) {
                send_error_response(client, ERROR_400_PATH, "400", "Bad Request");
                return 0;
            }
            client->state = CLIENT_STATE_SENDING_RESPONSE;
        } else{
            return 0;
        }
    }

    if (client->state == CLIENT_STATE_SENDING_RESPONSE) {
        client->response = calloc(1, sizeof(HttpResponse));
        if (client->response == NULL) {
            perror("malloc");
            free_client(client, 0);
            return -1;
        }
        init_http_response(client->response);
        get_default_response(client->response, client->request);
        add_security_headers(client->response, client->ssl != NULL);
        serve_static_file(client->request->path, client->response, client->request);

        int result = response_to_buffer(client->response, &client->response_buffer);
        
        return result;
    }
    
    return 0;
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

int handle_client_receive(int fd, ServerState* server_state) {
    Client* client = &server_state->clients[fd];

    if (client->state == CLIENT_STATE_SSL_HANDSHAKE) {
        int ssl_result = SSL_accept(client->ssl);
        if (ssl_result <= 0) {
            int ssl_error = SSL_get_error(client->ssl, ssl_result);
            if (ssl_error == SSL_ERROR_WANT_READ) {
                // Need more data for handshake, wait for EPOLLIN
                return 0;
            } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
                // Need to write for handshake, register for EPOLLOUT
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLOUT;
                ev.data.fd = fd;
                epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev);
                return 0;
            } else {
                // Handshake failed
                ERR_print_errors_fp(stderr);
                free_client(client, 0);
                close_connection(fd, server_state, 0);
                return -1;
            }
        }
        // Handshake complete, proceed to normal HTTP handling
        client->state = CLIENT_STATE_IDLE;
        printf("[SSL] Handshake complete for fd=%d\n", fd);
    }

    if (client->state == CLIENT_STATE_IDLE) {
        gettimeofday(&client->request_start, NULL);
        client->state = CLIENT_STATE_RECEIVING_HEADERS;
    }
    
    if (client->state == CLIENT_STATE_RECEIVING_HEADERS || client->state == CLIENT_STATE_RECEIVING_BODY) {
        int bytes; 

        // Use SSL_read if SSL is enabled, otherwise use recv
        if (client->ssl != NULL) {
            bytes = SSL_read(client->ssl, 
                client->buffer + client->bytes_received,
                sizeof(client->buffer) - client->bytes_received - 1);
        } else {
            bytes = recv(fd, 
                client->buffer + client->bytes_received, // Start after existing data
                sizeof(client->buffer) - client->bytes_received - 1, // Remaining space
                0);
        }

        if (bytes < 0) {
            if (client->ssl != NULL) {
                // NEW: Handle SSL errors
                int ssl_error = SSL_get_error(client->ssl, bytes);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    // SSL needs more data or can't write yet
                    if (ssl_error == SSL_ERROR_WANT_WRITE) {
                        struct epoll_event ev;
                        ev.events = EPOLLIN | EPOLLOUT;
                        ev.data.fd = fd;
                        epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev);
                    }
                    return 0;
                } else {
                    // Real SSL error
                    ERR_print_errors_fp(stderr);
                    free_client(client, 0);
                    close_connection(fd, server_state, 0);
                    return -1;
                }
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 0;  // No data to receive, so just wait
                } else {
                    perror("recv");
                    free_client(client, 0);
                    close_connection(fd, server_state, 0);
                    return -1;
                }
            }
        } else{
            client->bytes_received += bytes;
            client->last_activity = time(NULL);
            
            if (bytes == 0) {
                // client disconnected
                free_client(client, 0);
                return close_connection(fd, server_state, 0);
            } 

            if (client->bytes_received > BUF_SIZE) {
                perror("Client sent too much data");
                free_client(client, 0);
                return close_connection(fd, server_state, 0);
            } 

            client->buffer[client->bytes_received] = '\0';

            handle_http_request(client);
        }
    }

    if (client->state == CLIENT_STATE_SENDING_100_CONTINUE) {
        int result = send_100_continue(fd, client, server_state);
        if (result < 0) {
            free_client(client, 0);
            close_connection(fd, server_state, 0);
            return -1;
        }
        if (result == 0) {
            return 0; // Still partial
        }
        // Fully sent - transition to RECEIVING_BODY
        client->state = CLIENT_STATE_RECEIVING_BODY;
        
        // Remove EPOLLOUT, back to just reading
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        if (epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
            perror("epoll_ctl: mod EPOLLIN for 100 Continue");
            free_client(client, 0);
            close_connection(fd, server_state, 0);
            return -1;
        }
        handle_http_request(client);
    }

    if (client->state == CLIENT_STATE_SENDING_RESPONSE) {
        size_t bytes_to_send;
        int is_head = (strcmp(client->request->method, "HEAD") == 0);
        if (is_head) {
            bytes_to_send = client->response->headers_length;
        } else {
            bytes_to_send = client->response->headers_length + client->response->body_length;
        }

        size_t remaining_to_send = bytes_to_send - client->bytes_sent;
        
        int send_result;
        if (client->ssl != NULL) {
            send_result = SSL_write(client->ssl, client->response_buffer + client->bytes_sent, remaining_to_send);
        } else {
            send_result = send(fd, client->response_buffer + client->bytes_sent, remaining_to_send, 0);
        }
        
        if (send_result < 0) {
            if (client->ssl != NULL) {
                // SSL error handling
                int ssl_error = SSL_get_error(client->ssl, send_result);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    struct epoll_event ev;
                    ev.events = EPOLLIN | EPOLLOUT;
                    ev.data.fd = fd;
                    if (epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
                        perror("epoll_ctl: mod EPOLLOUT");
                        free_client(client, 0);
                        close_connection(fd, server_state, 0);
                        return -1;
                    }
                    return 0;
                } else {
                    ERR_print_errors_fp(stderr);
                    free_client(client, 0);
                    close_connection(fd, server_state, 0);
                    return -1;
                }
            } else {
                // Plain socket error handling
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct epoll_event ev;
                    ev.events = EPOLLIN | EPOLLOUT;
                    ev.data.fd = fd;
                    if (epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
                        perror("epoll_ctl: mod EPOLLOUT");
                        free_client(client, 0);
                        close_connection(fd, server_state, 0);
                        return -1;
                    }
                    return 0;
                } else {
                    perror("send");
                    free_client(client, 0);
                    close_connection(fd, server_state, 0);
                    return -1;
                }
            }
        }
        client->bytes_sent += send_result;

        if (client->bytes_sent >= bytes_to_send) {
            // We've sent all the data, so we can close the connection or go back to idle
            struct timeval end;
            gettimeofday(&end, NULL);
            double time_ms = (end.tv_sec - client->request_start.tv_sec) * 1000.0 + (end.tv_usec - client->request_start.tv_usec) / 1000.0;
            log_request(client->request, client->response, time_ms);

            // Remove EPOLLOUT if we registered it (only listen for reads now)
            struct epoll_event ev;
            ev.events = EPOLLIN;  // Back to just reading
            ev.data.fd = fd;
            if (epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
                perror("epoll_ctl: mod EPOLLIN");
                free_client(client, 0);
                close_connection(fd, server_state, 0);
                return -1;
            }

            if (should_close_connection(client->response)) {
                free_client(client, 0);
                close_connection(fd, server_state, 1);
                return 0;
            } else {
                free_client(client, 1);
                client->state = CLIENT_STATE_IDLE;
                client->last_activity = time(NULL);
                return 0;
            }
        }

        // Partial send - we'll continue when EPOLLOUT fires
        // But first, make sure we're registered for EPOLLOUT
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        if (epoll_ctl(server_state->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
            perror("epoll_ctl: mod EPOLLOUT");
            free_client(client, 0);
            close_connection(fd, server_state, 0);
            return -1;
        }
    }

    return 0;
}

int handle_timed_out_clients(ServerState* server_state) {
    time_t now = time(NULL);
    for (int i = server_state->active_connections - 1; i >= 0; i--) { // we iterate backwards because we are removing elements from the array in close_connection
        int fd = server_state->active_fds[i];
        if (server_state->clients[fd].last_activity != 0 && (now - server_state->clients[fd].last_activity > 30)) {  // 30 sec timeout
            printf("[CONNECTION] Timeout: closing fd=%d (total active: %d)\n", fd, server_state->active_connections);
            free_client(&server_state->clients[fd], 0);
            close_connection(fd, server_state, 1);
        }
    }
    return 0;
}


SSL_CTX* init_ssl_context(const char* cert_file, const char* key_file) {
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create SSL context
    const SSL_METHOD* method = TLS_server_method();  // Use TLS 1.2/1.3
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Load certificate file
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // Load private key file
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    return ctx;
}

static int create_listening_socket(const char* port) {
    struct addrinfo hints, *res; // hints is where we put our own data and say how we want a connection. Res is a pointer to a linked list with possible addresses
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // use TCP
    hints.ai_flags = AI_PASSIVE; // fill in my IP for me

    int getaddrinfo_result = getaddrinfo(NULL, port, &hints, &res);
    if (getaddrinfo_result != 0) {
        fprintf(stderr, "getaddrinfo for port %s: %s\n", port, gai_strerror(getaddrinfo_result));
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)); // allows the socket to be reused immediately after closing. SO_REUSEADDR is a socket option that allows the socket to be reused immediately after closing. yes sets this option to 1.

    if (bind(sock, res->ai_addr, res->ai_addrlen) < 0) { // bind the socket, which by itself just reads or write things, to a port/address where it should write to or read from
        perror("bind");
        freeaddrinfo(res);
        close(sock);
        return -1;
    }

    freeaddrinfo(res);

    if (listen(sock, BACKLOG) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    return sock;
}

int server_run(const char* http_port, const char* https_port, const char* cert_file, const char* key_file) {
    ServerState server_state;
    server_state.active_connections = 0;
    server_state.active_fds = malloc(MAX_CLIENTS * sizeof(int));
    if (server_state.active_fds == NULL) {
        perror("malloc");
        return -1;
    }
    server_state.clients = calloc(MAX_CLIENTS, sizeof(Client));
    if (server_state.clients == NULL) {
        perror("malloc");
        return -1;
    }


    // Initialize SSL/TLS context
    server_state.ssl_ctx = NULL;  // Default: no HTTPS

    server_state.https_socket = -1;

    // Try to initialize SSL/TLS
    if (https_port != NULL && cert_file != NULL && key_file != NULL) {
        server_state.ssl_ctx = init_ssl_context(cert_file, key_file);
        if (server_state.ssl_ctx == NULL) {
            fprintf(stderr, "Warning: Failed to initialize SSL, HTTPS disabled\n");
        } else {
            printf("[SSL] HTTPS enabled with certificate: %s\n", cert_file);
        }
    }
    

    const char* http_port_str = http_port ? http_port : "8080";
    server_state.http_socket = create_listening_socket(http_port_str);
    if (server_state.http_socket < 0) {
        fprintf(stderr, "Failed to create HTTP listening socket on port %s\n", http_port_str);
        return -1;
    }
    printf("[HTTP] Listening on port %s\n", http_port_str);

    if (server_state.ssl_ctx != NULL && https_port != NULL) {
        server_state.https_socket = create_listening_socket(https_port);
        if (server_state.https_socket < 0) {
            fprintf(stderr, "Warning: Failed to create HTTPS socket on port %s, continuing with HTTP only\n", https_port);
            server_state.https_socket = -1;
        } else {
            printf("[HTTPS] Listening on port %s\n", https_port);
        }
    }
    
    server_state.epfd = epoll_create1(0); // create an epoll instance
    if (server_state.epfd < 0) {
        perror("epoll_create1");
        return -1;
    }

    struct epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.fd = server_state.http_socket;
    epoll_ctl(server_state.epfd, EPOLL_CTL_ADD, server_state.http_socket, &ev);

    if (server_state.https_socket >= 0) {
        ev.data.fd = server_state.https_socket;
        epoll_ctl(server_state.epfd, EPOLL_CTL_ADD, server_state.https_socket, &ev);
    }

    // Add timer to epoll
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);

    struct itimerspec timer_spec;
    timer_spec.it_value.tv_sec = 5;      // First expiration in 5 seconds
    timer_spec.it_value.tv_nsec = 0;
    timer_spec.it_interval.tv_sec = 5;   // Then every 5 seconds
    timer_spec.it_interval.tv_nsec = 0;

    timerfd_settime(timer_fd, 0, &timer_spec, NULL);

    // Add timer to epoll
    struct epoll_event timer_ev;
    timer_ev.events = EPOLLIN;
    timer_ev.data.fd = timer_fd;
    epoll_ctl(server_state.epfd, EPOLL_CTL_ADD, timer_fd, &timer_ev);

    struct epoll_event events[MAX_EVENTS];

    while (1){

        int n = epoll_wait(server_state.epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == server_state.http_socket) {
                handle_new_connection(&server_state, 0);
            } else if (fd == server_state.https_socket) {
                handle_new_connection(&server_state, 1);
            } else if (events[i].data.fd == timer_fd) {
                size_t expirations;
                read(timer_fd, &expirations, sizeof(expirations));
                handle_timed_out_clients(&server_state);
            } else {
                handle_client_receive(events[i].data.fd, &server_state);
            }
        }
    }
    return 0;
}