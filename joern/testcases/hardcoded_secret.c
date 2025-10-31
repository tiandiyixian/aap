#include <stdio.h>

void show_secret(void) {
    const char *api_key = "API_SECRET_TOKEN_123"; // Expected: HardcodedSecretRule
    printf("%s\n", api_key);
}

int main(void) {
    show_secret();
    return 0;
}
