#include <stdio.h>

void log_user_input(int argc, char **argv) {
    if (argc > 1) {
        printf(argv[1]); // Expected: FormatStringRule
    }
}

int main(int argc, char **argv) {
    log_user_input(argc, argv);
    return 0;
}
