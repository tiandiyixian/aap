#include <stdio.h>
#include <stdlib.h>

void print_after_free(void) {
    char *ptr = malloc(8);
    free(ptr);
    printf("%c\n", ptr[0]); // Expected: UseAfterFreeRule
}

int main(void) {
    print_after_free();
    return 0;
}
