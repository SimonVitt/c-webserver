#ifndef CONNECTION_H
#define CONNECTION_H

#include <stddef.h>
#include <openssl/ssl.h>
#include "./server.h"

typedef enum {
    CONN_IO_SUCCESS = 0,      // Success, bytes read/written
    CONN_IO_WANT_READ = 1,    // Need more data (EAGAIN/WANT_READ)
    CONN_IO_WANT_WRITE = 2,   // Need to write (WANT_WRITE)
    CONN_IO_ERROR = -1,       // Fatal error
    CONN_IO_CLOSED = -2       // Connection closed (bytes == 0)
} conn_io_result_t;

int connection_read(int fd, SSL* ssl, void* buf, size_t len, conn_io_result_t* result);
int connection_write(int fd, SSL* ssl, const void* buf, size_t len, conn_io_result_t* result);
int close_connection(int fd, ServerState* server_state, int do_shutdown);
int connection_accept(ServerState* server_state, int is_https);
int connection_free_client(Client* client, int keep_ssl);
int connection_handle_timeouts(ServerState* server_state);

int epoll_modify(int epfd, int fd, int events);
int epoll_add(int epfd, int fd, int events);
int epoll_remove(int epfd, int fd);

#endif