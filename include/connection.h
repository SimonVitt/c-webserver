/**
 * @file connection.h
 * @brief Connection I/O and lifecycle management
 */

#ifndef CONNECTION_H
#define CONNECTION_H

#include <stddef.h>
#include <openssl/ssl.h>
#include "server.h"

/** @brief I/O operation result codes */
typedef enum {
    CONN_IO_SUCCESS = 0,    /**< Operation completed, check return value for bytes */
    CONN_IO_WANT_READ = 1,  /**< Would block, retry when readable */
    CONN_IO_WANT_WRITE = 2, /**< Would block, retry when writable */
    CONN_IO_ERROR = -1,     /**< Fatal error */
    CONN_IO_CLOSED = -2     /**< Peer closed connection */
} conn_io_result_t;

/**
 * @brief Read from connection (handles both plain and TLS)
 * @param result  Output: operation result code
 * @return Bytes read on success, 0 or -1 otherwise (check result)
 */
int connection_read(int fd, SSL* ssl, void* buf, size_t len, conn_io_result_t* result);

/**
 * @brief Write to connection (handles both plain and TLS)
 * @param result  Output: operation result code
 * @return Bytes written on success, 0 or -1 otherwise (check result)
 */
int connection_write(int fd, SSL* ssl, const void* buf, size_t len, conn_io_result_t* result);

/**
 * @brief Close connection and remove from epoll
 * @param do_shutdown  1 to send TCP FIN, 0 to close immediately
 */
int close_connection(int fd, ServerState* server_state, int do_shutdown);

/**
 * @brief Accept new connection and register with epoll
 * @param is_https  1 for HTTPS socket, 0 for HTTP
 */
int connection_accept(ServerState* server_state, int is_https);

/**
 * @brief Reset client state for reuse or cleanup
 * @param keep_ssl  1 to preserve SSL session (keep-alive), 0 to free
 */
int connection_free_client(Client* client, int keep_ssl);

/**
 * @brief Close idle connections exceeding CLIENT_TIMEOUT_SEC
 */
int connection_handle_timeouts(ServerState* server_state);

/** @brief Modify epoll events for fd */
int epoll_modify(int epfd, int fd, int events);

/** @brief Add fd to epoll */
int epoll_add(int epfd, int fd, int events);

/** @brief Remove fd from epoll */
int epoll_remove(int epfd, int fd);

#endif
