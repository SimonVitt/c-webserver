#ifndef SSL_HANDLER_H
#define SSL_HANDLER_H

#include <openssl/ssl.h>
#include "./../include/server.h"

typedef enum {
    SSL_HANDSHAKE_SUCCESS = 0,      // Handshake complete, continue
    SSL_HANDSHAKE_WANT_READ = 1,    // Need more data, wait for EPOLLIN
    SSL_HANDSHAKE_WANT_WRITE = 2,   // Need to write, wait for EPOLLOUT
    SSL_HANDSHAKE_ERROR = -1        // Fatal error, close connection
} ssl_handshake_result_t;

SSL_CTX* init_ssl_context(const char* cert_file, const char* key_file);
ssl_handshake_result_t handle_ssl_handshake(int fd, Client* client, ServerState* server_state);
SSL* create_ssl_session(SSL_CTX* ctx, int fd);

#endif