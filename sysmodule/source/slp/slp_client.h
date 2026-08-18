/*
 * sys-slp-client — slp relay transport.
 *
 * Minimal client for the slp wire protocol (see notes/wire-format.md):
 * one UDP socket to the relay, framing keepalive / ipv4 / ipv4_frag / ping.
 *
 * Pure C, no libnx/stratosphere deps, so it compiles and is testable on a
 * host with plain gcc as well as inside the sysmodule.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* slp frame types (bit7 of the header byte = "encrypted", unused by clients) */
#define SLP_TYPE_KEEPALIVE   0x00
#define SLP_TYPE_IPV4        0x01
#define SLP_TYPE_PING        0x02
#define SLP_TYPE_IPV4_FRAG   0x03
/* Relay login. A relay that requires auth sends this; a client that ignores it
 * is never authenticated and the relay forwards it NOTHING -- it can still
 * send (UDP), so this fails silently and looks like a dead tunnel. Matches
 * switch-lan-play's LAN_CLIENT_TYPE_AUTH_ME. */
#define SLP_TYPE_AUTH_ME     0x04
#define SLP_TYPE_INFO        0x10

#define SLP_MTU 1400  /* max payload for an ipv4 frame; larger -> Ipv4Frag */

typedef struct SlpClient {
    int fd;
    uint32_t server_ip;   /* network byte order */
    uint16_t server_port;
    char     host[128];   /* hostname/IP as configured (debug) */

    /* Relay credentials. We keep ONLY sha1(password), never the password
     * itself -- same as the reference client. has_credentials is 0 when no
     * login is configured, in which case an AUTH_ME challenge is logged and
     * ignored (the relay will simply forward us nothing). */
    int      has_credentials;
    char     username[64];
    uint8_t  password_sha1[20];
} SlpClient;

/* Resolve host to an IPv4 in network byte order. Accepts literals and
 * (on Switch) resolves names via a raw UDP DNS query to the system DNS.
 * Returns 1 on success, 0 on failure. */
int slpResolveHost(const char *host, uint32_t *out_addr);

/* Open the UDP socket and bind to the relay. Returns 1 on success. */
int slpClientOpen(SlpClient *c, const char *host, uint16_t port);

void slpClientClose(SlpClient *c);

/* Re-open the UDP socket to the same server (cached ip/port from the last
 * successful open). Safe with an empty server list. Returns 1 on success. */
int slpClientReopen(SlpClient *c);

/* --- frame codecs (return total datagram length, or 0 on error) --- */

size_t slpFrameKeepalive(uint8_t *out);                 /* [0x00]            */
size_t slpFramePing(uint8_t *out, uint32_t ts);         /* [0x02] ts(4B)     */
size_t slpFrameIpv4(uint8_t *out, const uint8_t *ip_pkt, size_t len);
size_t slpFrameIpv4Frag(uint8_t *out, uint32_t src, uint32_t dst,
                        uint16_t id, uint8_t part, uint8_t total_part,
                        const uint8_t *chunk, size_t chunk_len);

/* Validate a datagram header, return its type (SLP_TYPE_*), or -1. */
int slpFrameType(const uint8_t *buf, size_t len);

/* --- send helpers --- */

int slpClientSendKeepalive(SlpClient *c);
int slpClientSendPing(SlpClient *c, uint32_t ts);
int slpClientSendIpv4(SlpClient *c, const uint8_t *ip_pkt, size_t len);
int slpClientSendRaw(SlpClient *c, const void *buf, size_t len);

/* Configure relay login. Stores sha1(password) and discards the password.
 * Pass NULL/empty username to clear. */
void slpClientSetCredentials(SlpClient *c, const char *username,
                             const char *password);

/* Answer an AUTH_ME challenge.
 *
 *   server -> [0x04][auth_type:1][challenge: 64 bytes]
 *   client -> [0x04][sha1(sha1(password) ++ challenge) : 20][username...]
 *
 * `payload` is the frame body AFTER the type byte, `len` its length.
 * Returns 1 if a response was sent, 0 otherwise. */
int slpClientHandleAuthMe(SlpClient *c, const uint8_t *payload, size_t len);

/* Blocking receive with timeout (ms). Returns datagram length, or -1 on
 * timeout/error. The type is written to *out_type; payload follows the
 * header byte at buf[1]. */
int slpClientRecv(SlpClient *c, uint8_t *buf, size_t cap, int timeout_ms,
                  int *out_type);

/* --- IPv4 header helpers (packets as carried in ipv4 frames) --- */

int      slpIpv4Valid(const uint8_t *pkt, size_t len);
uint32_t slpIpv4Src(const uint8_t *pkt);   /* network byte order */
uint32_t slpIpv4Dst(const uint8_t *pkt);   /* network byte order */
size_t   slpIpv4TotalLen(const uint8_t *pkt, size_t len);

#ifdef __cplusplus
}
#endif
