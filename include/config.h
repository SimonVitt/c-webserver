/**
 * @file config.h
 * @brief Server configuration constants
 */

#ifndef CONFIG_H
#define CONFIG_H

#define MAX_EVENTS 128           /**< Max epoll events per wait */
#define MAX_CLIENTS 20000        /**< Max concurrent connections */
#define BACKLOG 512              /**< TCP listen backlog */
#define CLIENT_TIMEOUT_SEC 30    /**< Idle timeout before close */
#define TIMER_INTERVAL_SEC 5     /**< Timeout check interval */
#define MAX_HEADERS 50           /**< Max headers per request */
#define MAX_REQUEST_LINE 2048    /**< Max request line length */
#define LOG_FILE "/var/log/c-webserver.log"  /**< Log file path */

#endif
