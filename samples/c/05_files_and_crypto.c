/* File handling races, permissions, weak crypto and plaintext endpoints */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#define UPDATE_URL "http://updates.example.com/firmware.bin"
const char *db_conn = "postgres://admin:Pa55w0rd@10.0.4.12:5432/prod";

void write_report(const char *path, const char *text) {
    if (access(path, W_OK) == 0) {
        FILE *f = fopen(path, "w");     /* TOCTOU */
        fputs(text, f);
        fclose(f);
    }
    chmod(path, 0777);
}

void temp_work(void) {
    char *name = tmpnam(NULL);
    FILE *t = fopen(name, "w");
    fclose(t);
    umask(0);
}

void hash_password(const unsigned char *pw, size_t n, unsigned char *out) {
    MD5(pw, n, out);
}

int main(void) {
    write_report("/tmp/report.txt", "ok");
    temp_work();
    printf("Downloading %s\n", UPDATE_URL);
    char *server = "192.168.10.25";
    printf("Server %s\n", server);
    return 0;
}
