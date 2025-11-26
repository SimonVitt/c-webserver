#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include "./../include/server.h"

int handle_http_request(Client* client);
int send_100_continue(int fd, Client* client, ServerState* server_state);
int should_close_connection(const HttpResponse* res);
int check_if_headers_complete(Client* client, int* headers_complete);
int send_error_response(Client* client, const char* error_path, const char* status_code, const char* status_message);

#endif