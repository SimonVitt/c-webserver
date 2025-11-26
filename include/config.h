#ifndef CONFIG_H
#define CONFIG_H

#define MAX_EVENTS 128
#define MAX_CLIENTS 20000 // the maximum number of clients that can be connected to the server
#define BACKLOG 512 // how many pending connections queue will hold
#define CLIENT_TIMEOUT_SEC 30 // how long a client can be idle before being closed
#define TIMER_INTERVAL_SEC 5 // how often to check for timed out clients

#endif