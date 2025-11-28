#include "ssl_handler.h"
#include "connection.h"
#include <sys/epoll.h>
#include <openssl/err.h>

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

ssl_handshake_result_t handle_ssl_handshake(int fd, Client* client, ServerState* server_state) {
    int ssl_result = SSL_accept(client->ssl);
    if (ssl_result <= 0) {
        int ssl_error = SSL_get_error(client->ssl, ssl_result);
        if (ssl_error == SSL_ERROR_WANT_READ) {
            // Need more data for handshake, wait for EPOLLIN
            return SSL_HANDSHAKE_WANT_READ;
        } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
            // Need to write for handshake, register for EPOLLOUT
            if (epoll_modify(server_state->epfd, fd, EPOLLIN | EPOLLOUT) < 0) {
                perror("epoll_ctl: mod EPOLLOUT for SSL handshake");
                return SSL_HANDSHAKE_ERROR;
            }
            return SSL_HANDSHAKE_WANT_WRITE;
        } else {
            // Handshake failed
            ERR_print_errors_fp(stderr);
            return SSL_HANDSHAKE_ERROR;
        }
    }
    printf("[SSL] Handshake complete for fd=%d\n", fd);
    return SSL_HANDSHAKE_SUCCESS; // Success
}

SSL* create_ssl_session(SSL_CTX* ctx, int fd) {
    // Create a new SSL session object for this client connection.
    // Uses the global SSL_CTX configuration (cert, key, protocols, ciphers).
    SSL* ssl = SSL_new(ctx);
    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Attach the accepted TCP socket (new_fd) to the SSL object.
    // This tells OpenSSL to read/write encrypted data over this socket.
    if (SSL_set_fd(ssl, fd) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}