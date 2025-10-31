#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int open_user_file(char **argv) {
    char path[256];
    strcpy(path, argv[1]);
    return open(path, O_RDONLY); // Expected: PathTraversalRule
}

int main(int argc, char **argv) {
    if (argc > 1) {
        int fd = open_user_file(argv);
        if (fd >= 0) {
            close(fd);
        }
    }
    return 0;
}
