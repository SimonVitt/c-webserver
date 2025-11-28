#include "connection.h"
#include "config.h"
#include "ssl_handler.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <openssl/err.h>

int connection_read(int fd, SSL* ssl, void* buf, size_t len, conn_io_result_t* result) {
    int bytes;
    
    if (ssl != NULL) {
        bytes = SSL_read(ssl, buf, len);
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(ssl, bytes);
            if (ssl_error == SSL_ERROR_WANT_READ) {
                *result = CONN_IO_WANT_READ;
                return 0;
            } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
                *result = CONN_IO_WANT_WRITE;
                return 0;
            } else {
                ERR_print_errors_fp(stderr);
                *result = CONN_IO_ERROR;
                return -1;
            }
        }
    } else {
        bytes = recv(fd, buf, len, 0);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                *result = CONN_IO_WANT_READ;
                return 0;
            } else {
                perror("recv");
                *result = CONN_IO_ERROR;
                return -1;
            }
        } else if (bytes == 0) {
            *result = CONN_IO_CLOSED;
            return 0;
        }
    }
    
    *result = CONN_IO_SUCCESS;
    return bytes;
}

int connection_write(int fd, SSL* ssl, const void* buf, size_t len, conn_io_result_t* result) {
    int bytes;
    
    if (ssl != NULL) {
        bytes = SSL_write(ssl, buf, len);
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(ssl, bytes);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                *result = (ssl_error == SSL_ERROR_WANT_WRITE) ? CONN_IO_WANT_WRITE : CONN_IO_WANT_READ;
                return 0;
            } else {
                ERR_print_errors_fp(stderr);
                *result = CONN_IO_ERROR;
                return -1;
            }
        }
    } else {
        bytes = send(fd, buf, len, 0);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                *result = CONN_IO_WANT_WRITE;
                return 0;
            } else {
                perror("send");
                *result = CONN_IO_ERROR;
                return -1;
            }
        }
    }
    
    *result = CONN_IO_SUCCESS;
    return bytes;
}

int close_connection(int fd, ServerState* server_state, int do_shutdown) {
    if (epoll_remove(server_state->epfd, fd) < 0) {
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


int connection_accept(ServerState* server_state, int is_https) {
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

    if (epoll_add(server_state->epfd, new_fd, EPOLLIN) < 0) {
        perror("epoll_ctl: add client");
        close(new_fd); // we close directly without close_connection because we it wasnt a client yet and not counted in the active_connections
        return -1;
    }
    server_state->active_fds[server_state->active_connections] = new_fd;

    // Initialize SSL for this connection if SSL is enabled
    server_state->clients[new_fd].ssl = NULL;
    if (is_https && server_state->ssl_ctx != NULL) {
        SSL* ssl = create_ssl_session(server_state->ssl_ctx, new_fd);
        if (ssl == NULL) {
            close(new_fd);
            return -1;
        }
        server_state->clients[new_fd].ssl = ssl;
        server_state->clients[new_fd].state = CLIENT_STATE_SSL_HANDSHAKE;  // Start handshake
    } else {
        server_state->clients[new_fd].state = CLIENT_STATE_IDLE;
    }

    server_state->active_connections++;

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

int connection_free_client(Client* client, int keep_ssl) {
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

int connection_handle_timeouts(ServerState* server_state) {
    time_t now = time(NULL);
    for (int i = server_state->active_connections - 1; i >= 0; i--) { // we iterate backwards because we are removing elements from the array in close_connection
        int fd = server_state->active_fds[i];
        if (server_state->clients[fd].last_activity != 0 && (now - server_state->clients[fd].last_activity > CLIENT_TIMEOUT_SEC)) {  // 30 sec timeout
            printf("[CONNECTION] Timeout: closing fd=%d (total active: %d)\n", fd, server_state->active_connections);
            connection_free_client(&server_state->clients[fd], 0);
            close_connection(fd, server_state, 1);
        }
    }
    return 0;
}

// Epoll helper functions
int epoll_modify(int epfd, int fd, int events) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    return epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
}

int epoll_add(int epfd, int fd, int events) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

int epoll_remove(int epfd, int fd) {
    return epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}