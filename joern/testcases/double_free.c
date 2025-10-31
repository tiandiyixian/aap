#include <stdlib.h>

void cleanup_twice(void) {
    char *ptr = malloc(32);
    free(ptr);
    free(ptr); // Expected: DoubleFreeRule
}

int main(void) {
    cleanup_twice();
    return 0;
}
