#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include "./../include/http.h"
#include "./../include/static_file.h"

#define BUF_SIZE 8192
#define PORT "8080"  // the port users will be connecting to
#define BACKLOG 10 // how many pending connections queue will hold

int handle_new_connection(int server_socket, fd_set* master, int* fdmax) {
    struct sockaddr_storage client_addr; // ip... address of the client
    socklen_t addr_size = sizeof client_addr; // size of the ip... address of the client
    int new_fd = accept(server_socket, (struct sockaddr *)&client_addr, &addr_size); // we get the addrinfo of someone who wrote/(wants to write?) to this socket. Now we can read and write from there
    if (new_fd < 0) {
        perror("accept");
        return -1;
    }
    FD_SET(new_fd, master); // add the new socket to the master set
    if (new_fd > *fdmax) *fdmax = new_fd; // update the highest file descriptor number
    printf("Connected: %d\n\n", new_fd);
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

int handle_http_request(char* buffer, char** response_buffer) {
    HttpRequest request;
    HttpResponse response;
    init_http_request(&request);
    init_http_response(&response);
    get_default_response(&response);
    
    enum parse_http_request_error parse_http_result = parse_http_request(buffer, &request);
    if (parse_http_result != PARSE_HTTP_REQUEST_SUCCESS) {
        printf("Bad Request - %s\n", buffer);
        serve_static_file(ERROR_400_PATH, &response);
    } else {
        serve_static_file(request.path, &response);
    }

    int result = response_to_buffer(&response, response_buffer);
    free_http_response(&response);
    free_http_request(&request);
    return result;
}

int handle_client_receive(int fd, fd_set* master) {
    char buffer[BUF_SIZE];
    int bytes = recv(fd, buffer, sizeof buffer, 0); // receive data from the socket
    if (bytes < 0) {
        perror("recv");
        close_connection(fd, master, 0);
        return -1;
    }
    
    if (bytes == 0) {
        // client disconnected
        return close_connection(fd, master, 0);
    } else {
        // Handle HTTP request
        if (bytes >= BUF_SIZE) {
            buffer[bytes - 1] = '\0';
        } else {
            buffer[bytes] = '\0';
        }
        
        char* response_buffer = NULL;
        handle_http_request(buffer, &response_buffer);
        int send_result = send(fd, response_buffer, strlen(response_buffer), 0); // send the data back to the socket
        if (send_result < 0) {
            perror("send");
            free(response_buffer);
            close_connection(fd, master, 0);
            return -1;
        }
        close_connection(fd, master, 1);
        printf("Send:\n%s\nTo: %d\n\n", response_buffer, fd);
        free(response_buffer);
    }
    return 0;
}

int server_run(void) {
    
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

    int yes = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)); // allows the socket to be reused immediately after closing. SO_REUSEADDR is a socket option that allows the socket to be reused immediately after closing. yes sets this option to 1.

    int bind_result = bind(server_socket, res->ai_addr, res->ai_addrlen); // bind the socket, which by itself just reads or write things, to a port/address where it should write to or read from
    if (bind_result < 0) {
        perror("bind");
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);

    int listen_result = listen(server_socket, BACKLOG); // the socket now starts to listen there
    if (listen_result < 0) {
        perror("listen");
        return -1;
    }

    fd_set master;   // the set of all sockets we're watching
    fd_set read_fds; // temporary copy used by select()

    FD_ZERO(&master);
    FD_SET(server_socket, &master); // start watching the listening socket
    int fdmax = server_socket;      // the highest file descriptor number

    while (1){
        read_fds = master; // copy it so select doesn't mess it up

        int select_result = select(fdmax + 1, &read_fds, NULL, NULL, NULL); // highest file descriptor number + 1, read_fds, write_fds, except_fds, timeout
        if (select_result < 0) {
            perror("select");
            continue;
        }

        for (int i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)){ // check if the socket is set in the read_fds set
                if (i == server_socket){ // if the socket is the server socket, accept a new connection
                    handle_new_connection(server_socket, &master, &fdmax);
                }else{
                    handle_client_receive(i, &master);
                }
            }
        }        
    }
    return 0;
}