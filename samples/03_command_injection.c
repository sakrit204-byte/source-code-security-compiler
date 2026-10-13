/* User input reaching the shell and format strings */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

void ping_host(const char *host) {
    char cmd[128];
    sprintf(cmd, "ping -c 1 %s", host);
    system(cmd);
}

void log_message(char *msg) {
    printf(msg);
    syslog(LOG_INFO, msg);
}

int main(int argc, char *argv[]) {
    char input[64];
    char *home = getenv("HOME");
    char path[256];

    if (fgets(input, sizeof(input), stdin) == NULL) return 1;
    input[strcspn(input, "\n")] = 0;

    char command[200];
    snprintf(command, sizeof(command), "ls -la %s", input);
    system(command);

    FILE *p = popen(input, "r");
    pclose(p);

    sprintf(path, "%s/.config/%s", home, argv[1]);
    printf("Config path: %s %d\n", path);
    log_message(argv[1]);

    int count = atoi(argv[2]);
    printf("count=%d\n", count);
    execlp(argv[3], argv[3], NULL);
    return 0;
}
