#include <stdio.h>

int read_config(const char *path) {
    FILE *fp = fopen(path, "r"); // Expected: ResourceLeakRule
    if (!fp) {
        return -1;
    }
    if (fgetc(fp) == EOF) {
        return -2; // Missing fclose on this path
    }
    fclose(fp);
    return 0;
}
