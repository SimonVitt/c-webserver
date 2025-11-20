#ifndef STATIC_FILE_H
#define STATIC_FILE_H

#define ERROR_400_PATH "/errors/400.html"
#define ERROR_404_PATH "/errors/404.html"
#define ERROR_405_PATH "/errors/405.html"
#define ERROR_500_PATH "/errors/500.html"
#define ERROR_403_PATH "/errors/403.html"

int serve_static_file(const char* path, HttpResponse* response, HttpRequest* request);

#endif