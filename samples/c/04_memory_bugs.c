/* Heap misuse: unchecked allocation, overflowable sizes, use-after-free */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct record {
    int id;
    char name[24];
} record_t;

record_t *make_records(size_t count) {
    record_t *list = malloc(count * sizeof(record_t));
    list[0].id = 1;                    /* used without NULL check */
    return list;
}

void process(void) {
    char *buf = (char *) malloc(64);
    if (buf == NULL) return;
    strncpy(buf, "data", 64);
    free(buf);
    printf("%s\n", buf);               /* use after free */
}

void cleanup(char *p) {
    free(p);
    free(p);                           /* double free */
}

void grow(void) {
    char *data = malloc(16);
    if (!data) return;
    data = realloc(data, 4096);        /* leaks on failure */
    char small[8];
    memcpy(small, data, 16);           /* 16 bytes into 8 */
    free(data);
    data = NULL;
}

int main(void) {
    record_t *r = make_records(10);
    process();
    grow();
    free(r);
    return 0;
}
