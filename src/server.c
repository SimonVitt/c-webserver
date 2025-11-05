#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include "./../include/http.h"
#include "./../include/static_file.h"
#include "./../include/server.h"

#define MAX_CLIENTS 100
#define PORT "8080"  // the port users will be connecting to
#define BACKLOG 10 // how many pending connections queue will hold

typedef struct {
    Client* clients; // We use 
    fd_set master;
    int fdmax;
    int server_socket;
} ServerState;

int handle_new_connection(ServerState* server_state) {
    struct sockaddr_storage client_addr; // ip... address of the client
    socklen_t addr_size = sizeof client_addr; // size of the ip... address of the client
    int new_fd = accept(server_state->server_socket, (struct sockaddr *)&client_addr, &addr_size); // we get the addrinfo of someone who wrote/(wants to write?) to this socket. Now we can read and write from there
    if (new_fd < 0) {
        perror("accept");
        return -1;
    } else if (new_fd >= MAX_CLIENTS) {
        perror("Too many clients");
        return -1;
    }
    FD_SET(new_fd, &server_state->master); // add the new socket to the master set
    if (new_fd > server_state->fdmax) server_state->fdmax = new_fd; // update the highest file descriptor number
    server_state->clients[new_fd].bytes_received = 0;
    server_state->clients[new_fd].last_activity = time(NULL);
    server_state->clients[new_fd].state = CLIENT_STATE_IDLE;
    server_state->clients[new_fd].request = NULL;
    server_state->clients[new_fd].headers_end_offset = 0;
    server_state->clients[new_fd].content_length = 0;
    server_state->clients[new_fd].body_bytes_received = 0;
    server_state->clients[new_fd].response = NULL;
    server_state->clients[new_fd].response_buffer = NULL;
    printf("Connected: %d\n\n", new_fd);
    return 0;
}

int free_client(Client* client) {
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
    return 0;
}

int close_connection(int fd, fd_set* master, int do_shutdown) {
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
    FD_CLR(fd, master); // remove the socket from the master set
    printf("Disconnected: %d\n\n", fd);
    return 0;
}

int check_if_headers_complete(Client* client, int* headers_complete) {
    char* headers_end = strstr(client->buffer, "\r\n\r\n");
    if (headers_end == NULL) {
        char* headers_end = strstr(client->buffer, "\n\n");
        if (headers_end == NULL) {
            *headers_complete = 0;
            return 0;
        }
        client->headers_end_offset = headers_end - client->buffer + 2;
    } else {
        client->headers_end_offset = headers_end - client->buffer + 4;
    }
    *headers_complete = 1;
    return 0;
}

int handle_http_request(Client* client) {
    
    if (client->request == NULL) {
        client->request = calloc(1, sizeof(HttpRequest));
        if (client->request == NULL) {
            perror("malloc");
            return -1;
        }
        client->last_activity = time(NULL);
        init_http_request(client->request);
    }
    

    if (client->state == CLIENT_STATE_IDLE) {
        client->state = CLIENT_STATE_RECEIVING_HEADERS;
    } 
    if (client->state == CLIENT_STATE_RECEIVING_HEADERS) {
        int headers_complete;
        int parse_result;
        check_if_headers_complete(client, &headers_complete);
        if (headers_complete) {
            parse_result = parse_http_request_headers(client->buffer, client->request);
            if (parse_result != PARSE_HTTP_REQUEST_SUCCESS) {
                printf("Bad Request - %s\n", client->buffer);
                serve_static_file(ERROR_400_PATH, client->response);
                return -1;
            }
            char* content_length_str = NULL;
            if (string_hashmap_get_case_insensitive(client->request->headers, "Content-Length", strlen("Content-Length"), &content_length_str) != HASHMAP_SUCCESS) {
                client->content_length = 0;
            } else {
                client->content_length = atol(content_length_str);
            }
            client->state = CLIENT_STATE_RECEIVING_BODY;

        } else{
            return 0;
        }
    }

    if (client->state == CLIENT_STATE_RECEIVING_BODY) {
        if (client->bytes_received - client->headers_end_offset >= client->content_length) {
            int parse_result = parse_http_request_body(client->buffer, client->request);
            if (parse_result != PARSE_HTTP_REQUEST_SUCCESS) {
                printf("Bad Request - %s\n", client->buffer);
                serve_static_file(ERROR_400_PATH, client->response);
                return -1;
            }
            client->state = CLIENT_STATE_SENDING_RESPONSE;
        } else{
            return 0;
        }
    }

    if (client->state == CLIENT_STATE_SENDING_RESPONSE) {
        client->response = calloc(1, sizeof(HttpResponse));
        if (client->response == NULL) {
            perror("malloc");
            free_client(client);
            return -1;
        }
        init_http_response(client->response);
        get_default_response(client->response);
        serve_static_file(client->request->path, client->response);

        int result = response_to_buffer(client->response, &client->response_buffer);
        
        return result;
    }
    
    return 0;
}

int handle_client_receive(int fd, ServerState* server_state) {
    Client* client = &server_state->clients[fd];
    if (client->state == CLIENT_STATE_IDLE) {
        client->state = CLIENT_STATE_RECEIVING_HEADERS;
    }
    
    int bytes = recv(fd, 
        client->buffer + client->bytes_received,  // Start after existing data
        sizeof(client->buffer) - client->bytes_received - 1,  // Remaining space
        0);

    if (bytes < 0) {
        perror("recv");
        free_client(client);
        close_connection(fd, &server_state->master, 0);
        return -1;
    }

    client->bytes_received += bytes;
    client->last_activity = time(NULL);
    
    if (bytes == 0) {
        // client disconnected
        return close_connection(fd, &server_state->master, 0);
    } 

    if (client->bytes_received > BUF_SIZE) {
        perror("Client sent too much data");
        free_client(client);
        return close_connection(fd, &server_state->master, 0);
    } 

    client->buffer[client->bytes_received] = '\0';

    handle_http_request(client);

    if (client->state == CLIENT_STATE_SENDING_RESPONSE) {
        int send_result = send(fd, client->response_buffer, client->response->headers_length + client->response->body_length, 0); // send the data back to the socket
        if (send_result < 0) {
            perror("send");
            free_client(client);
            close_connection(fd, &server_state->master, 0);
            return -1;
        }
        close_connection(fd, &server_state->master, 1);
        printf("Send:\n%s\nTo: %d\n\n", client->response_buffer, fd);
        free_client(client);
    }

    return 0;
}

int handle_timed_out_clients(ServerState* server_state) {
    time_t now = time(NULL);
    for (int i = 3; i <= server_state->fdmax; i++) {
        if (!FD_ISSET(i, &server_state->master)) {
            continue;
        }
        if (server_state->clients[i].last_activity != 0 &&
            now - server_state->clients[i].last_activity > 30) {  // 30 sec timeout
            printf("Timeout: closing fd=%d\n", i);
            free_client(&server_state->clients[i]);
            close_connection(i, &server_state->master, 1);
        }
    }
    return 0;
}

int server_run(void) {
    ServerState server_state;
    server_state.clients = calloc(MAX_CLIENTS, sizeof(Client));
    if (server_state.clients == NULL) {
        perror("malloc");
        return -1;
    }
    server_state.fdmax = 0;

    struct addrinfo hints, *res; // hints is where we put our own data and say how we want a connection. Res is a pointer to a linked list with possible addresses
    int server_socket; // sockets, server_socket for server, new_fd for client

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // use TCP
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    int getaddrinfo_result = getaddrinfo(NULL, PORT, &hints, &res);
    if (getaddrinfo_result != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(getaddrinfo_result));
        return -1;
    }


    server_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol); // ai means address information, res->ai_socktype and res->ai_protocol and say if tcp or udp
    if (server_socket < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }
    server_state.server_socket = server_socket;

    int yes = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)); // allows the socket to be reused immediately after closing. SO_REUSEADDR is a socket option that allows the socket to be reused immediately after closing. yes sets this option to 1.

    int bind_result = bind(server_state.server_socket, res->ai_addr, res->ai_addrlen); // bind the socket, which by itself just reads or write things, to a port/address where it should write to or read from
    if (bind_result < 0) {
        perror("bind");
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);

    int listen_result = listen(server_state.server_socket, BACKLOG); // the socket now starts to listen there
    if (listen_result < 0) {
        perror("listen");
        return -1;
    }

    FD_ZERO(&server_state.master);
    FD_SET(server_state.server_socket, &server_state.master); // start watching the listening socket
    server_state.fdmax = server_state.server_socket;

    fd_set read_fds;

    while (1){
        read_fds = server_state.master; // copy it so select doesn't mess it up

        handle_timed_out_clients(&server_state);

        int select_result = select(server_state.fdmax + 1, &read_fds, NULL, NULL, NULL); // highest file descriptor number + 1, read_fds, write_fds, except_fds, timeout
        if (select_result < 0) {
            perror("select");
            continue;
        }

        for (int i = 0; i <= server_state.fdmax; i++) {
            if (FD_ISSET(i, &read_fds)){ // check if the socket is set in the read_fds set
                if (i == server_socket){ // if the socket is the server socket, accept a new connection
                    handle_new_connection(&server_state);
                }else{
                    handle_client_receive(i, &server_state);
                }
            }
        }        
    }
    return 0;
}