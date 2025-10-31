#include <stdio.h>
#include <string.h>

void vulnerable_copy(const char *input) {
    char buf[16];
    strcpy(buf, input); // Expected: UnsafeBufferCopyRule
    printf("%s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_copy(argv[1]);
    }
    return 0;
}
