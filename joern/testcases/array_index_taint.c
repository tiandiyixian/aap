#include <stdio.h>
#include <stdlib.h>

int read_value(char **argv) {
    int values[4] = {1, 2, 3, 4};
    int index = atoi(argv[1]); // source from argv
    return values[index];       // Expected: ArrayIndexTaintRule
}

int main(int argc, char **argv) {
    if (argc > 1) {
        printf("%d\n", read_value(argv));
    }
    return 0;
}
