#include <stdio.h>
#include <stdlib.h>

void run_command(void) {
    char buffer[128];
    if (fgets(buffer, sizeof(buffer), stdin)) {
        system(buffer); // Expected: CommandInjectionRule
    }
}

int main(void) {
    run_command();
    return 0;
}
