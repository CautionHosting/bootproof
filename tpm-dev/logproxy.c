// logproxy.c - listen on port A, relay to port B on loopback, hex-log all bytes.
// usage: logproxy <listen_port> <target_port> <logfile>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

int main(int argc, char **argv) {
    int listen_port = atoi(argv[1]);
    int target_port = atoi(argv[2]);
    FILE *logf = fopen(argv[3], "w");
    if (!logf) return 1;

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(listen_port);
    if (bind(ls, (struct sockaddr *) &a, sizeof a) < 0 || listen(ls, 4) < 0)
        return 1;

    for (;;) {
        int ca = accept(ls, 0, 0);
        if (ca < 0) continue;
        int cb = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in b = {0};
        b.sin_family = AF_INET;
        b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        b.sin_port = htons(target_port);
        if (connect(cb, (struct sockaddr *) &b, sizeof b) < 0) {
            close(ca);
            close(cb);
            continue;
        }

        char buf[4096];
        int alive = 2;
        while (alive > 0) {
            struct pollfd pf[2] = {{ca, POLLIN, 0}, {cb, POLLIN, 0}};
            int r = poll(pf, 2, -1);
            if (r <= 0) break;
            for (int i = 0; i < 2; i++) {
                if (!(pf[i].revents & (POLLIN | POLLHUP))) continue;
                int n = read(i == 0 ? ca : cb, buf, sizeof buf);
                if (n <= 0) {
                    alive--;
                    continue;
                }
                fprintf(logf, "%s %d:", i == 0 ? "C2S" : "S2C", n);
                for (int j = 0; j < n; j++)
                    fprintf(logf, "%02x", (unsigned char) buf[j]);
                fprintf(logf, "\n");
                fflush(logf);
                int dst = i == 0 ? cb : ca;
                int off = 0;
                while (off < n) {
                    int w = write(dst, buf + off, n - off);
                    if (w <= 0) break;
                    off += w;
                }
            }
        }
        close(ca);
        close(cb);
    }
    return 0;
}
