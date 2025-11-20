#ifndef SERVER_H
#define SERVER_H

#include <time.h>
#include <sys/time.h>
#include "./http.h"

#define BUF_SIZE 8192

typedef enum {
    CLIENT_STATE_IDLE = 0,
    CLIENT_STATE_RECEIVING_HEADERS = 1,
    CLIENT_STATE_SENDING_100_CONTINUE = 2,
    CLIENT_STATE_RECEIVING_BODY = 3,
    CLIENT_STATE_SENDING_RESPONSE = 4,
    CLIENT_STATE_NO_CONNECTION = 5
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
} Client;

int server_run(void);

#endif 