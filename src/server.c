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
#include "ssl_handler.h"
#include "http.h"
#include "static_file.h"
#include "server.h"
#include "config.h"
#include "connection.h"
#include "request_handler.h"

typedef enum {
    HANDLE_SUCCESS = 0, // Continue processing
    HANDLE_WAIT = 1, // Wait for more data/events
    HANDLE_ERROR = -1 // Fatal error
} handle_result_t;

static void log_request(HttpRequest* req, HttpResponse* res, double time_ms) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct tm* gmt = gmtime(&tv.tv_sec);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", gmt);
    
    char timestamp_with_ms[80];
    int ms = (int)(tv.tv_usec / 1000);
    snprintf(timestamp_with_ms, sizeof(timestamp_with_ms), "%s.%03d", timestamp, ms);
    
    char log_line[1024];
    snprintf(log_line, sizeof(log_line), 
             "[REQUEST] [%s GMT] %s %s %s - %s %s (%.2fms)\n",
             timestamp_with_ms,
             req->method,
             req->path,
             req->version,
             res->status_code,
             res->status_message,
             time_ms);
    
    // Log to stdout
    printf("%s", log_line);
    
    // Log to file (if writable)
    FILE* log_file = fopen(LOG_FILE, "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s", log_line);
        fclose(log_file);
    }
}

static handle_result_t handle_ssl_handshake_state(int fd, Client* client, ServerState* server_state) {
    ssl_handshake_result_t result = handle_ssl_handshake(fd, client, server_state);
    if (result == SSL_HANDSHAKE_ERROR) {
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    } else if (result == SSL_HANDSHAKE_WANT_READ || result == SSL_HANDSHAKE_WANT_WRITE) {
        return HANDLE_WAIT;
    }
    // Handshake complete
    client->state = CLIENT_STATE_IDLE;
    return HANDLE_SUCCESS;
}

static handle_result_t handle_idle_state(Client* client) {
    gettimeofday(&client->request_start, NULL);
    client->state = CLIENT_STATE_RECEIVING_HEADERS;
    return HANDLE_SUCCESS;
}

static handle_result_t handle_receiving_state(int fd, Client* client, ServerState* server_state) {
    conn_io_result_t io_result;
    int bytes = connection_read(
        fd, 
        client->ssl,
        client->buffer + client->bytes_received,
        sizeof(client->buffer) - client->bytes_received - 1,
        &io_result
    );
    
    if (io_result == CONN_IO_WANT_WRITE) {
        if (epoll_modify(server_state->epfd, fd, EPOLLIN | EPOLLOUT) < 0) {
            perror("epoll_modify: EPOLLOUT");
            return HANDLE_ERROR;
        }
        return HANDLE_WAIT;
    } else if (io_result == CONN_IO_WANT_READ) {
        return HANDLE_WAIT;
    } else if (io_result == CONN_IO_ERROR) {
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    } else if (io_result == CONN_IO_CLOSED) {
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    }
    
    // CONN_IO_SUCCESS
    client->bytes_received += bytes;
    client->last_activity = time(NULL);
    
    if (client->bytes_received > BUF_SIZE) {
        perror("Client sent too much data");
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    }
    
    client->buffer[client->bytes_received] = '\0';
    handle_http_request(client);
    return HANDLE_SUCCESS;
}

static handle_result_t handle_100_continue_state(int fd, Client* client, ServerState* server_state) {
    int result = send_100_continue(fd, client, server_state);
    if (result < 0) {
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    }
    if (result == 0) {
        return HANDLE_WAIT; // Still partial
    }
    
    // Fully sent
    client->state = CLIENT_STATE_RECEIVING_BODY;
    
    // Remove EPOLLOUT, back to just reading
    if (epoll_modify(server_state->epfd, fd, EPOLLIN) < 0) {
        perror("epoll_modify: EPOLLIN for 100 Continue");
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    }
    handle_http_request(client);
    return HANDLE_SUCCESS;
}

static handle_result_t send_response_data(int fd, Client* client, ServerState* server_state) {
    size_t bytes_to_send;
    int is_head = (strcmp(client->request->method, "HEAD") == 0);
    if (is_head) {
        bytes_to_send = client->response->headers_length;
    } else {
        bytes_to_send = client->response->headers_length + client->response->body_length;
    }

    size_t remaining_to_send = bytes_to_send - client->bytes_sent;
    
    conn_io_result_t io_result;
    int send_result = connection_write(
        fd,
        client->ssl,
        client->response_buffer + client->bytes_sent,
        remaining_to_send,
        &io_result
    );
    
    if (io_result == CONN_IO_WANT_WRITE || io_result == CONN_IO_WANT_READ) {
        if (epoll_modify(server_state->epfd, fd, EPOLLIN | EPOLLOUT) < 0) {
            perror("epoll_modify: EPOLLOUT");
            connection_free_client(client, 0);
            close_connection(fd, server_state, 0);
            return HANDLE_ERROR;
        }
        return HANDLE_WAIT;
    } else if (io_result == CONN_IO_ERROR) {
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    }

    // CONN_IO_SUCCESS
    client->bytes_sent += send_result;

    if (client->bytes_sent >= bytes_to_send) {
        return HANDLE_SUCCESS; // all data sent
    }

    // Partial send
    if (epoll_modify(server_state->epfd, fd, EPOLLIN | EPOLLOUT) < 0) {
        perror("epoll_modify: EPOLLOUT");
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    }
    return HANDLE_WAIT;
}

static handle_result_t handle_response_complete(int fd, Client* client, ServerState* server_state) {
    struct timeval end;
    gettimeofday(&end, NULL);
    double time_ms = (end.tv_sec - client->request_start.tv_sec) * 1000.0 + 
                    (end.tv_usec - client->request_start.tv_usec) / 1000.0;
    log_request(client->request, client->response, time_ms);

    if (epoll_modify(server_state->epfd, fd, EPOLLIN) < 0) {
        perror("epoll_modify: EPOLLIN");
        connection_free_client(client, 0);
        close_connection(fd, server_state, 0);
        return HANDLE_ERROR;
    }

    if (should_close_connection(client->response)) {
        connection_free_client(client, 0);
        close_connection(fd, server_state, 1);
        return HANDLE_SUCCESS; // Connection closed
    } else {
        connection_free_client(client, 1);
        client->state = CLIENT_STATE_IDLE;
        client->last_activity = time(NULL);
        return HANDLE_SUCCESS; // Back to IDLE
    }
}

static handle_result_t handle_sending_response_state(int fd, Client* client, ServerState* server_state) {
    handle_result_t result = send_response_data(fd, client, server_state);
    
    if (result == HANDLE_ERROR || result == HANDLE_WAIT) {
        return result;
    }
    
    // HANDLE_SUCCESS means all data was sent
    return handle_response_complete(fd, client, server_state);
}

static int handle_client_receive(int fd, ServerState* server_state) {
    Client* client = &server_state->clients[fd];
    handle_result_t result;

    if (client->state == CLIENT_STATE_SSL_HANDSHAKE) {
        result = handle_ssl_handshake_state(fd, client, server_state);
        if (result != HANDLE_SUCCESS) {
            return (result == HANDLE_WAIT) ? 0 : -1;
        }
    }
    
    if (client->state == CLIENT_STATE_IDLE) {
        result = handle_idle_state(client);
        // Continue - state changed to RECEIVING_HEADERS
    }
    
    if (client->state == CLIENT_STATE_RECEIVING_HEADERS || client->state == CLIENT_STATE_RECEIVING_BODY) {
        result = handle_receiving_state(fd, client, server_state);
        if (result != HANDLE_SUCCESS) {
            return (result == HANDLE_WAIT) ? 0 : -1;
        }
    }

    if (client->state == CLIENT_STATE_SENDING_100_CONTINUE) {
        result = handle_100_continue_state(fd, client, server_state);
        if (result != HANDLE_SUCCESS) {
            return (result == HANDLE_WAIT) ? 0 : -1;
        }
    }

    if (client->state == CLIENT_STATE_SENDING_RESPONSE) {
        result = handle_sending_response_state(fd, client, server_state);
        if (result != HANDLE_SUCCESS) {
            return (result == HANDLE_WAIT) ? 0 : -1;
        }
    }

    return 0;
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

static int server_init(ServerState* server_state, const char* cert_file, const char* key_file) {
    server_state->active_connections = 0;
    server_state->active_fds = malloc(MAX_CLIENTS * sizeof(int));
    if (server_state->active_fds == NULL) {
        perror("malloc");
        return -1;
    }
    server_state->clients = calloc(MAX_CLIENTS, sizeof(Client));
    if (server_state->clients == NULL) {
        perror("malloc");
        free(server_state->active_fds);
        return -1;
    }

    // Initialize SSL/TLS context
    server_state->ssl_ctx = NULL;  // Default: no HTTPS
    server_state->https_socket = -1;

    // Try to initialize SSL/TLS
    if (cert_file != NULL && key_file != NULL) {
        server_state->ssl_ctx = init_ssl_context(cert_file, key_file);
        if (server_state->ssl_ctx == NULL) {
            fprintf(stderr, "Warning: Failed to initialize SSL, HTTPS disabled\n");
        } else {
            printf("[SSL] HTTPS enabled with certificate: %s\n", cert_file);
        }
    }

    return 0;
}

static int server_setup_sockets(ServerState* server_state, const char* http_port, const char* https_port, int* timer_fd) {
    const char* http_port_str = http_port ? http_port : "8080";
    server_state->http_socket = create_listening_socket(http_port_str);
    if (server_state->http_socket < 0) {
        fprintf(stderr, "Failed to create HTTP listening socket on port %s\n", http_port_str);
        return -1;
    }
    printf("[HTTP] Listening on port %s\n", http_port_str);

    if (server_state->ssl_ctx != NULL && https_port != NULL) {
        server_state->https_socket = create_listening_socket(https_port);
        if (server_state->https_socket < 0) {
            fprintf(stderr, "Warning: Failed to create HTTPS socket on port %s, continuing with HTTP only\n", https_port);
            server_state->https_socket = -1;
        } else {
            printf("[HTTPS] Listening on port %s\n", https_port);
        }
    }
    
    server_state->epfd = epoll_create1(0);
    if (server_state->epfd < 0) {
        perror("epoll_create1");
        return -1;
    }

    if (epoll_add(server_state->epfd, server_state->http_socket, EPOLLIN) < 0) {
        perror("epoll_ctl: add HTTP socket");
        return -1;
    }

    if (server_state->https_socket >= 0) {
        if (epoll_add(server_state->epfd, server_state->https_socket, EPOLLIN) < 0) {
            perror("epoll_ctl: add HTTPS socket");
            return -1;
        }
    }

    // Setup timer
    *timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (*timer_fd < 0) {
        perror("timerfd_create");
        return -1;
    }

    struct itimerspec timer_spec;
    timer_spec.it_value.tv_sec = TIMER_INTERVAL_SEC;
    timer_spec.it_value.tv_nsec = 0;
    timer_spec.it_interval.tv_sec = TIMER_INTERVAL_SEC;
    timer_spec.it_interval.tv_nsec = 0;

    if (timerfd_settime(*timer_fd, 0, &timer_spec, NULL) < 0) {
        perror("timerfd_settime");
        close(*timer_fd);
        return -1;
    }

    if (epoll_add(server_state->epfd, *timer_fd, EPOLLIN) < 0) {
        perror("epoll_ctl: add timer");
        close(*timer_fd);
        return -1;
    }

    return 0;
}

static void server_event_loop(ServerState* server_state, int timer_fd) {
    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int n = epoll_wait(server_state->epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == server_state->http_socket) {
                connection_accept(server_state, 0);
            } else if (fd == server_state->https_socket) {
                connection_accept(server_state, 1);
            } else if (fd == timer_fd) {
                size_t expirations;
                read(timer_fd, &expirations, sizeof(expirations));
                connection_handle_timeouts(server_state);
            } else {
                handle_client_receive(fd, server_state);
            }
        }
    }
}

int server_run(const char* http_port, const char* https_port, const char* cert_file, const char* key_file) {
    ServerState server_state;
    int timer_fd;

    if (server_init(&server_state, cert_file, key_file) < 0) {
        return -1;
    }

    if (server_setup_sockets(&server_state, http_port, https_port, &timer_fd) < 0) {
        // Cleanup on error
        if (server_state.ssl_ctx != NULL) {
            SSL_CTX_free(server_state.ssl_ctx);
        }
        if (server_state.http_socket >= 0) {
            close(server_state.http_socket);
        }
        if (server_state.https_socket >= 0) {
            close(server_state.https_socket);
        }
        if (server_state.epfd >= 0) {
            close(server_state.epfd);
        }
        free(server_state.clients);
        free(server_state.active_fds);
        return -1;
    }

    server_event_loop(&server_state, timer_fd);
    
    return 0;
}