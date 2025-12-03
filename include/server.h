/**
 * @file server.h
 * @brief Core server types and entry point
 */

#ifndef SERVER_H
#define SERVER_H

#include <time.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include "http.h"

#define BUF_SIZE 8192

/** @brief Client connection state machine states */
typedef enum {
    CLIENT_STATE_IDLE = 0,
    CLIENT_STATE_RECEIVING_HEADERS = 1,
    CLIENT_STATE_SENDING_100_CONTINUE = 2,
    CLIENT_STATE_RECEIVING_BODY = 3,
    CLIENT_STATE_SENDING_RESPONSE = 4,
    CLIENT_STATE_NO_CONNECTION = 5,
    CLIENT_STATE_SSL_HANDSHAKE = 6
} ClientState;

/** @brief Per-connection state */
typedef struct {
    char buffer[BUF_SIZE];         /**< Receive buffer */
    size_t bytes_received;         /**< Bytes in buffer */
    time_t last_activity;          /**< For timeout detection */
    ClientState state;             /**< Current state machine state */
    HttpRequest* request;          /**< Parsed request (owned) */
    size_t headers_end_offset;     /**< Offset where body starts */
    size_t content_length;         /**< Expected body length */
    size_t body_bytes_received;    /**< Body bytes received so far */
    HttpResponse* response;        /**< Response to send (owned) */
    char* response_buffer;         /**< Serialized response (owned) */
    struct timeval request_start;  /**< For request timing */
    size_t bytes_sent;             /**< Response bytes sent */
    size_t continue_bytes_sent;    /**< 100 Continue bytes sent */
    SSL* ssl;                      /**< TLS session or NULL */
} Client;

/** @brief Global server state */
typedef struct {
    Client* clients;       /**< Client array indexed by fd */
    int epfd;              /**< epoll instance */
    int http_socket;       /**< HTTP listen socket */
    int https_socket;      /**< HTTPS listen socket or -1 */
    int active_connections;
    int* active_fds;       /**< List of active client fds */
    SSL_CTX* ssl_ctx;      /**< TLS context or NULL */
} ServerState;

/**
 * @brief Start the server event loop
 * @param http_port   HTTP port (e.g. "8080")
 * @param https_port  HTTPS port or NULL to disable
 * @param cert_file   PEM certificate path or NULL
 * @param key_file    PEM private key path or NULL
 * @return 0 on clean exit, -1 on error
 */
int server_run(const char* http_port, const char* https_port, 
               const char* cert_file, const char* key_file);

#endif
