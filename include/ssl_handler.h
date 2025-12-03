/**
 * @file ssl_handler.h
 * @brief TLS/SSL initialization and handshake handling
 */

#ifndef SSL_HANDLER_H
#define SSL_HANDLER_H

#include <openssl/ssl.h>
#include "server.h"

/** @brief SSL handshake result codes */
typedef enum {
    SSL_HANDSHAKE_SUCCESS = 0,    /**< Handshake complete */
    SSL_HANDSHAKE_WANT_READ = 1,  /**< Need more data, wait for EPOLLIN */
    SSL_HANDSHAKE_WANT_WRITE = 2, /**< Need to write, wait for EPOLLOUT */
    SSL_HANDSHAKE_ERROR = -1      /**< Fatal error, close connection */
} ssl_handshake_result_t;

/**
 * @brief Create and configure SSL context
 * @param cert_file  Path to PEM certificate
 * @param key_file   Path to PEM private key
 * @return SSL_CTX or NULL on error
 */
SSL_CTX* init_ssl_context(const char* cert_file, const char* key_file);

/**
 * @brief Continue non-blocking SSL handshake
 * @return Result code indicating completion or need to wait
 */
ssl_handshake_result_t handle_ssl_handshake(int fd, Client* client, ServerState* server_state);

/**
 * @brief Create SSL session for accepted connection
 * @return SSL object or NULL on error
 */
SSL* create_ssl_session(SSL_CTX* ctx, int fd);

#endif
