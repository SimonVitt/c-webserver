#ifndef SERVER_H
#define SERVER_H

#include <time.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include "./http.h"

#define BUF_SIZE 8192

typedef enum {
    CLIENT_STATE_IDLE = 0,
    CLIENT_STATE_RECEIVING_HEADERS = 1,
    CLIENT_STATE_SENDING_100_CONTINUE = 2,
    CLIENT_STATE_RECEIVING_BODY = 3,
    CLIENT_STATE_SENDING_RESPONSE = 4,
    CLIENT_STATE_NO_CONNECTION = 5,
    CLIENT_STATE_SSL_HANDSHAKE = 6
} ClientState;

typedef struct {
    char buffer[BUF_SIZE];
    size_t bytes_received;
    
    time_t last_activity;
    ClientState state;
    
    HttpRequest* request;
    
    size_t headers_end_offset;
    size_t content_length;
    size_t body_bytes_received;

    HttpResponse* response;
    char* response_buffer;

    struct timeval request_start;

    size_t bytes_sent;

    size_t continue_bytes_sent; // How much of 100 Continue we've sent

    SSL* ssl;
} Client;

typedef struct {
    Client* clients; // We use an array of clients to store the clients that are connected to the server. the client will always be at the index of the file descriptor of the socket. We dont use a hashmap because this would cause of memory overhead (more often mallocing and freeing memory).
    int epfd; // epoll file descriptor
    int http_socket;
    int https_socket;
    int active_connections;
    int* active_fds;
    SSL_CTX* ssl_ctx; //SSL context (NULL if not using HTTPS)
} ServerState;

int server_run(const char* http_port, const char* https_port, const char* cert_file, const char* key_file);

#endif 