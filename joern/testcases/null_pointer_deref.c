#include <stdio.h>
#include <stdlib.h>

void print_first_char(size_t size) {
    char *buffer = malloc(size);
    buffer[0] = 'A'; // Expected: NullPointerDereferenceRule
    printf("%c\n", buffer[0]);
    free(buffer);
}

int main(void) {
    print_first_char(4);
    return 0;
}
