#include <stdlib.h>
#include "server.h"

int main(void) {

    if (server_run() != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
