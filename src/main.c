#include <stdlib.h>
#include <string.h>
#include "./../include/server.h"

int main(int argc, char* argv[]) {

    const char* http_port = "8080";
    const char* https_port = NULL;
    const char* cert_file = NULL;
    const char* key_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (i + 1 >= argc) break;
        if (strcmp(argv[i], "--http-port") == 0) {
            http_port = argv[++i];
        } else if (strcmp(argv[i], "--https-port") == 0) {
            https_port = argv[++i];
        } else if (strcmp(argv[i], "--cert") == 0) {
            cert_file = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0) {
            key_file = argv[++i];
        }
    }

    if (https_port != NULL && (cert_file == NULL || key_file == NULL)) {
        fprintf(stderr, "Error: --https-port requires --cert and --key\n");
        return EXIT_FAILURE;
    }

    if (server_run(http_port, https_port, cert_file, key_file) != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
