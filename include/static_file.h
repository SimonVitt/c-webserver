#ifndef STATIC_FILE_H
#define STATIC_FILE_H

#define ERROR_400_PATH "./public/errors/400.html"
#define ERROR_404_PATH "./public/errors/404.html"
#define ERROR_500_PATH "./public/errors/500.html"
#define ERROR_403_PATH "./public/errors/403.html"

int serve_static_file(const char* path, HttpResponse* response);

#endif