#include "slp_client.h"
#include "sha1.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* DNS                                                               */
/* ------------------------------------------------------------------ */

/* On the host we read /etc/resolv.conf; on Switch we use nifm's current
 * DNS server. The Switch path is guarded by __SWITCH__ so the host build
 * does not need libnx. */
static uint32_t get_dns_server(void) {
#ifdef __SWITCH__
    {
        extern uint32_t nifmGetCurrentIpConfigInfo(uint32_t *ip, uint32_t *subnet,
                                                   uint32_t *gw, uint32_t *dns1,
                                                   uint32_t *dns2);
        uint32_t ip, subnet, gw, dns1, dns2;
        if (nifmGetCurrentIpConfigInfo(&ip, &subnet, &gw, &dns1, &dns2) == 0) {
            if (dns1 != 0)
                return dns1;
            if (dns2 != 0)
                return dns2;
        }
        return 0x08080808; /* fallback Google DNS */
    }
#else
    {
        const char *path = "/etc/resolv.conf";
        FILE *f = fopen(path, "r");
        char line[256];
        if (f != NULL) {
            while (fgets(line, sizeof(line), f) != NULL) {
                char kw[16], addr[64];
                if (sscanf(line, "%15s %63s", kw, addr) == 2 &&
                    strcmp(kw, "nameserver") == 0) {
                    struct in_addr in;
                    if (inet_pton(AF_INET, addr, &in) == 1) {
                        fclose(f);
                        return in.s_addr;
                    }
                }
            }
            fclose(f);
        }
        return 0x08080808;
    }
#endif
}

static size_t dns_encode_name(const char *host, uint8_t *out, size_t cap) {
    size_t pos = 0;
    const char *label = host;
    while (*label != '\0') {
        const char *dot = strchr(label, '.');
        size_t len = dot != NULL ? (size_t)(dot - label) : strlen(label);
        if (len == 0 || len > 63 || pos + len + 2 > cap)
            return 0;
        out[pos++] = (uint8_t)len;
        memcpy(out + pos, label, len);
        pos += len;
        if (dot == NULL)
            break;
        label = dot + 1;
    }
    if (pos + 2 > cap)
        return 0;
    out[pos++] = 0x00;
    return pos;
}

static int dns_build_query(const char *host, uint16_t id, uint8_t *packet,
                           size_t cap) {
    size_t name_len = dns_encode_name(host, packet + 12, cap > 12 ? cap - 12 : 0);
    if (name_len == 0)
        return -1;

    packet[0] = (uint8_t)(id >> 8);
    packet[1] = (uint8_t)(id & 0xFF);
    packet[2] = 0x01; /* RD */
    packet[3] = 0x00;
    packet[4] = 0x00; /* QDCOUNT */
    packet[5] = 0x01;
    packet[6] = 0x00; /* ANCOUNT */
    packet[7] = 0x00;
    packet[8] = 0x00; /* NSCOUNT */
    packet[9] = 0x00;
    packet[10] = 0x00; /* ARCOUNT */
    packet[11] = 0x00;

    size_t pos = 12 + name_len;
    packet[pos++] = 0x00; /* QTYPE = A */
    packet[pos++] = 0x01;
    packet[pos++] = 0x00; /* QCLASS = IN */
    packet[pos++] = 0x01;
    return (int)pos;
}

static int dns_parse_response(const uint8_t *resp, size_t len, uint32_t *out) {
    if (len < 12)
        return 0;
    uint16_t flags = (uint16_t)((resp[2] << 8) | resp[3]);
    if (!(flags & 0x8000) || (flags & 0x000F) != 0)
        return 0;
    uint16_t ancount = (uint16_t)((resp[6] << 8) | resp[7]);
    if (ancount == 0)
        return 0;

    size_t pos = 12;

    /* skip question section (QDCOUNT names) */
    for (int q = 0; q < 1; q++) {
        while (pos < len && resp[pos] != 0) {
            uint8_t l = resp[pos];
            if ((l & 0xC0) == 0xC0) { /* compression pointer in question */
                pos += 2;
                goto done_question;
            }
            pos += 1 + l;
        }
        pos += 5; /* zero label + QTYPE + QCLASS */
    }
done_question:

    /* iterate answers looking for an A record */
    for (uint16_t a = 0; a < ancount && pos + 12 <= len; a++) {
        /* name (skip: possibly pointer) */
        while (pos < len) {
            uint8_t l = resp[pos];
            if ((l & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            if (l == 0) {
                pos += 1;
                break;
            }
            pos += 1 + l;
        }
        if (pos + 10 > len)
            return 0;
        uint16_t type = (uint16_t)((resp[pos] << 8) | resp[pos + 1]);
        uint16_t rdlen = (uint16_t)((resp[pos + 8] << 8) | resp[pos + 9]);
        if (type == 1 && rdlen == 4 && pos + 12 <= len) {
            /* The A-record's RDATA is already 4 bytes in NETWORK order, and
             * *out feeds sockaddr_in::sin_addr which also wants network order.
             * Copy the bytes straight through.
             *
             * This used to pack them MSB-first into a u32:
             *     resp[10]<<24 | resp[11]<<16 | resp[12]<<8 | resp[13]
             * which yields the NUMERIC form (0xC0F1EE88 for 192.241.238.136).
             * Stored into sin_addr on this little-endian machine that lays down
             * the bytes 88 EE F1 C0 -- i.e. 136.238.241.192, the address
             * REVERSED. Every DNS-resolved relay was therefore contacted at the
             * wrong host: we transmitted happily into the void and never
             * received one packet back. Literal addresses were unaffected
             * (inet_aton already returns network order), which is exactly why
             * 10.172.227.153 always worked and tekn0.net never did. The trace
             * said so plainly for hours:
             *     open ok host=10.172.227.153 ip=10.172.227.153   (correct)
             *     open ok host=tekn0.net      ip=136.238.241.192  (reversed)
             */
            memcpy(out, resp + pos + 10, 4);
            return 1;
        }
        pos += 10 + rdlen;
    }
    return 0;
}

int slpResolveHost(const char *host, uint32_t *out_addr) {
    struct in_addr in;
    if (inet_pton(AF_INET, host, &in) == 1) {
        *out_addr = in.s_addr;
        return 1;
    }

    uint16_t id = (uint16_t)(((uint32_t)host[0] << 8 | (uint32_t)host[1]) ^ 0x5A5A);
    uint8_t query[512];
    int qlen = dns_build_query(host, id, query, sizeof(query));
    if (qlen < 0)
        return 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;

    uint32_t dns = get_dns_server();
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = dns;
    sa.sin_port = htons(53);

    int ok = 0;
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (sendto(fd, query, (size_t)qlen, 0, (struct sockaddr *)&sa, sizeof(sa)) >= 0) {
        uint8_t resp[512];
        ssize_t rlen = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
        if (rlen >= 0)
            ok = dns_parse_response(resp, (size_t)rlen, out_addr);
    }

    close(fd);
    return ok;
}

/* ------------------------------------------------------------------ */
/* socket                                                             */
/* ------------------------------------------------------------------ */

/* Pin one local UDP port for this socket's lifetime.
 *
 * WHY THIS MATTERS: the relay identifies a peer by its source addr:port. An
 * UNBOUND socket is free to pick a different source port per datagram, so a
 * client that never binds shows up at the relay as a NEW peer over and over --
 * one per keepalive. Observed on tekn0.net: the peer count climbed at exactly
 * the 10s keepalive cadence and settled at ~6 (the relay's expiry window
 * divided by our keepalive interval), the same console appeared twice in one
 * lobby, and the count drained slowly after disconnecting. Worse, the relay
 * sends replies to the port it last saw, which is never the one we are
 * listening on -- so we transmit fine and receive NOTHING.
 *
 * switch-lan-play binds its UDP socket once (uv_udp_bind), which is why the
 * reference client registers as exactly one peer on the same network.
 *
 * Binding to 0.0.0.0:0 lets the stack choose the port, but fixes it. */
static int slp_bind_ephemeral(int fd) {
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = 0;
    return bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0;
}

int slpClientOpen(SlpClient *c, const char *host, uint16_t port) {
    uint32_t ip;
    if (!slpResolveHost(host, &ip))
        return 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    if (!slp_bind_ephemeral(fd)) {
        close(fd);
        return 0;
    }

    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->server_ip = ip;
    c->server_port = port;
    strncpy(c->host, host, sizeof(c->host) - 1);
    return 1;
}

void slpClientClose(SlpClient *c) {
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* Re-open the UDP socket to the same server (cached ip/port from the last
 * successful open). No DNS, no dependency on the server list, so it is safe
 * even if the list is later emptied. Returns 1 on success. */
int slpClientReopen(SlpClient *c) {
    if (c->server_ip == 0 || c->server_port == 0)
        return 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    if (!slp_bind_ephemeral(fd)) {
        close(fd);
        return 0;
    }

    if (c->fd >= 0)
        close(c->fd);
    c->fd = fd;
    return 1;
}

int slpClientSendRaw(SlpClient *c, const void *buf, size_t len) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = c->server_ip;
    sa.sin_port = htons(c->server_port);
    ssize_t n = sendto(c->fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    return n == (ssize_t)len ? 1 : 0;
}

int slpClientRecv(SlpClient *c, uint8_t *buf, size_t cap, int timeout_ms,
                  int *out_type) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recv(c->fd, buf, cap, 0);
    if (n <= 0)
        return -1;
    if (n < 1)
        return -1;
    *out_type = slpFrameType(buf, (size_t)n);
    return (int)n;
}

/* ------------------------------------------------------------------ */
/* relay login (frame 0x04 AUTH_ME)                                    */
/* ------------------------------------------------------------------ */

void slpClientSetCredentials(SlpClient *c, const char *username,
                             const char *password) {
    if (c == NULL)
        return;
    if (username == NULL || username[0] == '\0') {
        c->has_credentials = 0;
        c->username[0] = '\0';
        memset(c->password_sha1, 0, sizeof(c->password_sha1));
        return;
    }

    size_t ulen = strlen(username);
    if (ulen >= sizeof(c->username))
        ulen = sizeof(c->username) - 1;
    memcpy(c->username, username, ulen);
    c->username[ulen] = '\0';

    /* Store sha1(password) only; the plaintext never persists. */
    SHA1_CTX ctx;
    SHA1Init(&ctx);
    if (password != NULL && password[0] != '\0')
        SHA1Update(&ctx, (const unsigned char *)password,
                   (uint32_t)strlen(password));
    SHA1Final(c->password_sha1, &ctx);

    c->has_credentials = 1;
}

int slpClientHandleAuthMe(SlpClient *c, const uint8_t *payload, size_t len) {
    if (c == NULL || payload == NULL || len < 1)
        return 0;

    uint8_t auth_type = payload[0];
    if (auth_type != 0)
        return 0;               /* only type 0 is defined */

    if (!c->has_credentials)
        return 0;               /* relay wants a login we do not have */

    const uint8_t *challenge = payload + 1;
    size_t challenge_len = len - 1;

    /* response = sha1( sha1(password) ++ challenge ) */
    uint8_t digest[20];
    SHA1_CTX ctx;
    SHA1Init(&ctx);
    SHA1Update(&ctx, c->password_sha1, (uint32_t)sizeof(c->password_sha1));
    if (challenge_len > 0)
        SHA1Update(&ctx, challenge, (uint32_t)challenge_len);
    SHA1Final(digest, &ctx);

    /* [0x04][digest 20][username] */
    uint8_t out[1 + 20 + sizeof(c->username)];
    size_t ulen = strlen(c->username);
    out[0] = SLP_TYPE_AUTH_ME;
    memcpy(out + 1, digest, sizeof(digest));
    memcpy(out + 1 + sizeof(digest), c->username, ulen);

    return slpClientSendRaw(c, out, 1 + sizeof(digest) + ulen);
}

/* ------------------------------------------------------------------ */
/* frame codecs                                                       */
/* ------------------------------------------------------------------ */

size_t slpFrameKeepalive(uint8_t *out) {
    out[0] = SLP_TYPE_KEEPALIVE;
    return 1;
}

size_t slpFramePing(uint8_t *out, uint32_t ts) {
    out[0] = SLP_TYPE_PING;
    out[1] = (uint8_t)(ts >> 24);
    out[2] = (uint8_t)(ts >> 16);
    out[3] = (uint8_t)(ts >> 8);
    out[4] = (uint8_t)(ts & 0xFF);
    return 5;
}

size_t slpFrameIpv4(uint8_t *out, const uint8_t *ip_pkt, size_t len) {
    if (len == 0)
        return 0;
    out[0] = SLP_TYPE_IPV4;
    memcpy(out + 1, ip_pkt, len);
    return 1 + len;
}

size_t slpFrameIpv4Frag(uint8_t *out, uint32_t src, uint32_t dst, uint16_t id,
                        uint8_t part, uint8_t total_part,
                        const uint8_t *chunk, size_t chunk_len) {
    uint8_t *p = out;
    *p++ = SLP_TYPE_IPV4_FRAG;
    *p++ = (uint8_t)(src >> 24);
    *p++ = (uint8_t)(src >> 16);
    *p++ = (uint8_t)(src >> 8);
    *p++ = (uint8_t)(src & 0xFF);
    *p++ = (uint8_t)(dst >> 24);
    *p++ = (uint8_t)(dst >> 16);
    *p++ = (uint8_t)(dst >> 8);
    *p++ = (uint8_t)(dst & 0xFF);
    *p++ = (uint8_t)(id >> 8);
    *p++ = (uint8_t)(id & 0xFF);
    *p++ = part;
    *p++ = total_part;
    *p++ = (uint8_t)(chunk_len >> 8);
    *p++ = (uint8_t)(chunk_len & 0xFF);
    *p++ = (uint8_t)(SLP_MTU >> 8);
    *p++ = (uint8_t)(SLP_MTU & 0xFF);
    memcpy(p, chunk, chunk_len);
    return (size_t)(p - out) + chunk_len;
}

int slpFrameType(const uint8_t *buf, size_t len) {
    if (len < 1)
        return -1;
    return buf[0] & 0x7F;
}

int slpClientSendKeepalive(SlpClient *c) {
    uint8_t f[1];
    slpFrameKeepalive(f);
    return slpClientSendRaw(c, f, sizeof(f));
}

int slpClientSendPing(SlpClient *c, uint32_t ts) {
    uint8_t f[5];
    slpFramePing(f, ts);
    return slpClientSendRaw(c, f, sizeof(f));
}

int slpClientSendIpv4(SlpClient *c, const uint8_t *ip_pkt, size_t len) {
    static thread_local uint8_t out[SLP_MTU + 1 + 16];
    size_t n;
    if (len <= SLP_MTU) {
        n = slpFrameIpv4(out, ip_pkt, len);
        return n ? slpClientSendRaw(c, out, n) : 0;
    }
    /* fragment: split into SLP_MTU chunks.
     * Frag id = the IPv4 identification field (bytes 4-5). This is what a
     * real IP stack uses and it differs per datagram, so the relay's
     * (src_ip, id) reassembly key never collides across datagrams from the
     * same peer. (Historically this read bytes 0-1, a constant 0x4500 for
     * every crafted packet, which corrupted multi-frag sequences.) */
    size_t offset = 0;
    uint8_t part = 0;
    uint16_t id = (uint16_t)((uint32_t)ip_pkt[4] << 8 | ip_pkt[5]);
    unsigned total_u = (unsigned)((len + SLP_MTU - 1) / SLP_MTU);
    if (total_u > 255)
        return 0;
    uint8_t total = (uint8_t)total_u;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > SLP_MTU)
            chunk = SLP_MTU;
        n = slpFrameIpv4Frag(out, slpIpv4Src(ip_pkt), slpIpv4Dst(ip_pkt), id,
                             part, total, ip_pkt + offset, chunk);
        if (!n || !slpClientSendRaw(c, out, n))
            return 0;
        offset += chunk;
        part++;
    }
    return 1;
}

int slpIpv4Valid(const uint8_t *pkt, size_t len) {
    if (len < 20)
        return 0;
    if ((pkt[0] >> 4) != 4) /* IPv4 only */
        return 0;
    size_t ihl = (pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl)
        return 0;
    return 1;
}

uint32_t slpIpv4Src(const uint8_t *pkt) {
    return (uint32_t)pkt[12] << 24 | (uint32_t)pkt[13] << 16 |
           (uint32_t)pkt[14] << 8 | (uint32_t)pkt[15];
}

uint32_t slpIpv4Dst(const uint8_t *pkt) {
    return (uint32_t)pkt[16] << 24 | (uint32_t)pkt[17] << 16 |
           (uint32_t)pkt[18] << 8 | (uint32_t)pkt[19];
}

size_t slpIpv4TotalLen(const uint8_t *pkt, size_t len) {
    size_t total = (size_t)pkt[2] << 8 | pkt[3];
    return total <= len ? total : len;
}
