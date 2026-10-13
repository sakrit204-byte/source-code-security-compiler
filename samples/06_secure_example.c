/* A reasonably careful program: bounded input, checked allocation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

static int read_name(char *out, size_t size) {
    if (fgets(out, (int) size, stdin) == NULL) {
        return -1;
    }
    out[strcspn(out, "\n")] = '\0';
    return 0;
}

int main(void) {
    char name[BUF_SIZE];
    if (read_name(name, sizeof(name)) != 0) {
        return EXIT_FAILURE;
    }

    size_t len = strlen(name);
    char *copy = calloc(len + 1, sizeof(char));
    if (copy == NULL) {
        return EXIT_FAILURE;
    }
    snprintf(copy, len + 1, "%s", name);
    printf("Hello, %s (%zu chars)\n", copy, len);

    free(copy);
    copy = NULL;
    return EXIT_SUCCESS;
}
