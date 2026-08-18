/* Host smoke test for slp_client: resolve, open, keepalive, ping, recv. */
#include "slp_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 11451;

    uint32_t ip;
    if (!slpResolveHost(host, &ip)) {
        printf("resolve failed: %s\n", host);
        return 1;
    }
    struct in_addr ia = { .s_addr = ip };
    printf("resolved %s -> %s\n", host, inet_ntoa(ia));

    SlpClient c;
    if (!slpClientOpen(&c, host, (uint16_t)port)) {
        printf("open failed\n");
        return 1;
    }
    printf("socket open, fd=%d\n", c.fd);

    if (!slpClientSendKeepalive(&c)) {
        printf("keepalive send failed\n");
        return 1;
    }
    printf("keepalive sent\n");

    if (!slpClientSendPing(&c, 0x11223344)) {
        printf("ping send failed\n");
        return 1;
    }
    printf("ping sent\n");

    uint8_t buf[2048];
    int type = 0;
    int n = slpClientRecv(&c, buf, sizeof(buf), 1000, &type);
    if (n > 0)
        printf("recv %d bytes, type=0x%02x\n", n, type);
    else
        printf("recv timeout (no pong expected from server)\n");

    slpClientClose(&c);
    printf("closed OK\n");
    return 0;
}
