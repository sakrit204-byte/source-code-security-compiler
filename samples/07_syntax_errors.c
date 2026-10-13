/* Syntax errors: the parser reports them and recovers in panic mode */
#include <stdio.h>

int add(int a, int b) {
    return a + b
}

int main(void) {
    int x = 10 @ 2;
    char buf[8];
    if (x > 5 {
        gets(buf);
    }
    int y = add(x, );
    printf("%d\n", y);
    return 0;
}
