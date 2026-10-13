/* Classic stack buffer overflows */
#include <stdio.h>
#include <string.h>

#define NAME_LEN 16
#define MAX_ITEMS 8

void greet(void) {
    char name[NAME_LEN];
    printf("Enter your name: ");
    gets(name);                         /* unbounded read */
    printf("Hello, %s\n", name);
}

void copy_banner(void) {
    char banner[10];
    strcpy(banner, "Welcome to the system!");   /* 23 bytes into 10 */
    puts(banner);
}

void fill(void) {
    int items[MAX_ITEMS];
    int i;
    for (i = 0; i <= MAX_ITEMS; i++) {  /* off-by-one */
        items[i] = i * i;
    }
    items[8] = 0;                       /* constant out-of-bounds write */
}

void read_line(void) {
    char line[32];
    fgets(line, 128, stdin);            /* size larger than buffer */
    char word[20];
    scanf("%s", word);                  /* no field width */
    char copy[64];
    strcat(copy, line);
}

int main(void) {
    greet();
    copy_banner();
    fill();
    read_line();
    return 0;
}
