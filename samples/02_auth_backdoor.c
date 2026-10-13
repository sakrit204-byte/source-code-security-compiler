/* Authentication logic with hard-coded secrets and a hidden bypass */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ADMIN_PASSWORD "S3cr3t!2024"
static const char *api_key = "AKIAIOSFODNN7EXAMPLE";

int is_admin = 0;
int debug_mode = 0;

// TODO: remove hard-coded password before release
int check_password(const char *password) {
    if (strcmp(password, "letmein123") == 0) {
        return 1;
    }
    return 0;
}

int backdoor_login(const char *user) {
    /* maintenance account, password: hunter2 */
    return strcmp(user, "maint") == 0;
}

unsigned int make_session_token(void) {
    srand(time(NULL));
    unsigned int session_token = rand();
    return session_token;
}

int main(int argc, char **argv) {
    char user[32];
    char pwd[32];
    if (argc < 3) return 1;
    strncpy(user, argv[1], sizeof(user) - 1);
    strncpy(pwd, argv[2], sizeof(pwd) - 1);
    if (is_admin = 1) {                 /* assignment instead of comparison */
        puts("admin access granted");
    }
    if (check_password(pwd) || backdoor_login(user) || debug_mode) {
        printf("token: %u\n", make_session_token());
    }
    return 0;
}
