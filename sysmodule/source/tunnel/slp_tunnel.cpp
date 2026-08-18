#include "slp_tunnel.hpp"

#include "slp/slp_client.h"
#include "slpcfg/slp_runtime.hpp"
#include "bsd/bsd_types.hpp"
#include "bsd/proxy_socket_manager.hpp"
#include "ldn/ldn_control.hpp"
#include "bsd/bsd_log_shim.hpp"
#include "slpcfg/slp_trace.hpp"

#include <cstring>
#include <vector>
#include <unordered_map>

#include <stratosphere.hpp>

namespace slp::tun {

    namespace {

        constexpr size_t MaxFragEntries = 4;
        constexpr size_t MaxTotalParts  = 4;

        /* Our virtual LAN IP (Ryujinx format), parsed at Init(). */
        uint32_t g_local_ip = 0;

        /* Incrementing IP identification — keeps relay (src,id) reassembly
         * keys unique per datagram (see slp_client.c slpClientSendIpv4). */
        uint16_t g_ip_id = 0;

        struct FragEntry {
            bool     active;
            uint32_t src;              /* Ryujinx format                  */
            uint16_t id;
            uint8_t  total;
            uint8_t  seen;             /* bitmap of parts received        */
            /* MUST be 16-bit: a fragment carries up to SLP_MTU (1400) bytes,
             * so a uint8_t truncated clen mod 256. Only the LAST fragment's
             * length feeds the `rebuilt` size below, so any reassembled packet
             * whose final fragment was >= 256 bytes came out silently short
             * and corrupt (e.g. 2000B = 1400+600 rebuilt as 1400+88 = 1488).
             * The 1569B LAN browse reply only escaped this by luck -- its last
             * fragment is 169 bytes. */
            uint16_t lens[MaxTotalParts];
            uint16_t pmtu;             /* per-part stride, fixed by part 0 */
            uint8_t  total_parts;      /* `total` claimed by the first part */
            s64      last_tick;        /* ams::os tick of last update     */
            uint8_t  data[MaxTotalParts * SLP_MTU];
        };

        alignas(16) FragEntry g_frags[MaxFragEntries];

        /* --- byte helpers (explicit shifts, endian-independent) --- */

        uint32_t Rd32be(const uint8_t *p) {
            return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                   (uint32_t)p[2] << 8 | (uint32_t)p[3];
        }

        void Wr16be(uint8_t *p, uint16_t v) {
            p[0] = (uint8_t)(v >> 8);
            p[1] = (uint8_t)(v & 0xFF);
        }

        void Wr32be(uint8_t *p, uint32_t v) {
            p[0] = (uint8_t)(v >> 24);
            p[1] = (uint8_t)(v >> 16);
            p[2] = (uint8_t)(v >> 8);
            p[3] = (uint8_t)(v & 0xFF);
        }

        /* One's-complement sum over the IPv4 header (RFC 1071). */
        uint16_t IpChecksum(const uint8_t *p, size_t n) {
            uint32_t sum = 0;
            while (n >= 2) {
                sum += (uint16_t)((p[0] << 8) | p[1]);
                p += 2;
                n -= 2;
            }
            if (n > 0)
                sum += (uint16_t)(p[0] << 8);
            while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return (uint16_t)~sum;
        }

        uint32_t ParseIp(const char *s) {
            uint32_t v = 0;
            int oct = 0, cur = 0;
            for (const char *p = s;; p++) {
                if (*p >= '0' && *p <= '9') {
                    cur = cur * 10 + (*p - '0');
                } else if (*p == '.' || *p == '\0') {
                    if (cur > 255 || oct > 3)
                        return 0;
                    v = (v << 8) | (uint8_t)cur;
                    oct++;
                    cur = 0;
                    if (*p == '\0')
                        break;
                } else {
                    return 0;
                }
            }
            return (oct == 4) ? v : 0;
        }

        /* --- inbound: IPv4 packet -> game sockets --- */

        void ProcessIpv4(const uint8_t *pkt, size_t len) {
            if (!slpIpv4Valid(pkt, len))
                return;
            size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
            if (len < ihl + 8)
                return;
            size_t total = slpIpv4TotalLen(pkt, len);
            if (total < ihl + 8)
                return;
            if (pkt[9] != 17)   /* UDP only */
                return;

            size_t uoff = ihl;
            uint16_t sport = (uint16_t)((pkt[uoff] << 8) | pkt[uoff + 1]);
            uint16_t dport = (uint16_t)((pkt[uoff + 2] << 8) | pkt[uoff + 3]);
            uint16_t ulen  = (uint16_t)((pkt[uoff + 4] << 8) | pkt[uoff + 5]);
            if (ulen < 8 || (size_t)uoff + ulen > total)
                return;

            uint32_t src = Rd32be(pkt + 12);   /* Ryujinx format */
            uint32_t dst = Rd32be(pkt + 16);

            /* LDN control plane (Scan/ScanResp/Connect/SyncNetwork) runs on
             * the control port through the same tunnel. Consume it here —
             * games never bind :11452, so it must not reach the bsd proxy. */
            if (dport == ams::slp::ldn::ControlPort) {
                ams::slp::ldn::LdnControl::GetInstance().OnControlFrame(
                    src, pkt + uoff + 8, (size_t)ulen - 8);
                return;
            }

            /* Log every inbound UDP that is not LDN control, with its ports.
             * Without this, a browse request that arrives but fails to match a
             * socket is buffered into the pending ring and vanishes silently --
             * indistinguishable from "nothing ever arrived", which is exactly
             * the ambiguity that made the tekn0 LAN test unreadable. */
            const bool routed =
                ams::mitm::bsd::ProxySocketManager::GetInstance().RouteIncomingData(
                    src, sport, dst, dport,
                    ryu_ldn::bsd::ProtocolType::Udp,
                    pkt + uoff + 8, (size_t)ulen - 8);
            ::slp::dbg::Trace("tun: inbound udp %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u %zuB %s",
                              (src >> 24) & 0xFF, (src >> 16) & 0xFF,
                              (src >> 8) & 0xFF, src & 0xFF, sport,
                              (dst >> 24) & 0xFF, (dst >> 16) & 0xFF,
                              (dst >> 8) & 0xFF, dst & 0xFF, dport,
                              (size_t)ulen - 8,
                              routed ? "-> socket" : "NO SOCKET (buffered)");
            if (dport == 49152 || sport == 49152) {
                LOG_INFO("PIA session layer: src=0x%08X:%u dst=0x%08X:%u len=%zu",
                         src, sport, dst, dport, (size_t)ulen - 8);
            }
        }

        /* --- inbound: Ipv4Frag reassembly --- */

        /* A datagram's fragments arrive within a few ms of each other. Anything
         * older than this is debris from a datagram that never completed. */
        constexpr s64 FragTimeoutTicks = 19200000;   /* ~1s @ 19.2MHz */

        FragEntry *FindFragEntry(uint32_t src, uint16_t id) {
            s64 now = ams::os::GetSystemTick().GetInt64Value();

            /* Expire debris FIRST.
             *
             * Nothing used to retire a half-complete entry, so parts 0-1 of a
             * datagram abandoned when you left LAN mode stayed `active` for
             * ever. The relay's `id` is only 16 bits and restarts, and `src` is
             * the same peer, so after a LAN -> WiFi -> LAN cycle a NEW datagram
             * collided with that stale key: its real parts 0-1 were dropped as
             * "duplicates", parts 2-3 landed, `seen` filled, and we handed
             * ProcessIpv4 a packet stitched out of two different datagrams.
             * That is remote data driving a corrupt packet into the game's recv
             * path -- no peer should ever be able to do that. */
            for (size_t i = 0; i < MaxFragEntries; i++) {
                FragEntry &e = g_frags[i];
                if (e.active && (now - e.last_tick) > FragTimeoutTicks)
                    e.active = false;
            }

            for (size_t i = 0; i < MaxFragEntries; i++) {
                FragEntry &e = g_frags[i];
                if (e.active && e.src == src && e.id == id)
                    return &e;
            }
            /* Reuse: any free slot, else the least-recently-updated entry. */
            size_t reuse = MaxFragEntries;
            s64 oldest = INT64_MAX;
            for (size_t i = 0; i < MaxFragEntries; i++) {
                FragEntry &e = g_frags[i];
                if (!e.active) {
                    reuse = i;
                    break;
                }
                if (e.last_tick < oldest) {
                    oldest = e.last_tick;
                    reuse = i;
                }
            }
            if (reuse == MaxFragEntries)
                return nullptr;
            FragEntry &e = g_frags[reuse];
            std::memset(&e, 0, sizeof(e));
            e.active = true;
            e.src = src;
            e.id = id;
            e.last_tick = now;
            return &e;
        }

        void OnFrag(const uint8_t *payload, size_t len) {
            if (len < 16)
                return;
            uint32_t src  = Rd32be(payload + 0);
            uint16_t id   = (uint16_t)((payload[8] << 8) | payload[9]);
            uint8_t  part = payload[10];
            uint8_t  total = payload[11];
            uint16_t clen = (uint16_t)((payload[12] << 8) | payload[13]);
            uint16_t pmtu = (uint16_t)((payload[14] << 8) | payload[15]);

            if (total == 0 || part >= total || total > MaxTotalParts)
                return;
            if (pmtu == 0 || pmtu > SLP_MTU)
                return;
            if (clen > pmtu || len < (size_t)16 + clen)
                return;

            FragEntry *e = FindFragEntry(src, id);
            if (e == nullptr)
                return;

            /* The first part of a datagram fixes the geometry; every later part
             * must agree. Without this a peer could send part 0 with pmtu=1400
             * and part 1 with pmtu=64, moving where part 1 lands and skewing the
             * `rebuilt` length computed from the final part's stride. */
            if (e->seen == 0) {
                e->pmtu        = pmtu;
                e->total_parts = total;
            } else if (e->pmtu != pmtu || e->total_parts != total) {
                /* Loud, not silent: this is a drop, and a silent drop in a
                 * forwarder is indistinguishable from the game misbehaving. */
                ::slp::dbg::Trace("frag: DROP geometry mismatch src=0x%08x id=%u "
                                  "(pmtu %u!=%u or total %u!=%u)",
                                  src, id, pmtu, e->pmtu, total, e->total_parts);
                return;
            }

            u32 mask = 1u << part;
            if (e->seen & mask)
                return;   /* duplicate part */

            size_t off = (size_t)part * pmtu;
            std::memcpy(e->data + off, payload + 16, clen);
            e->lens[part] = clen;
            e->seen |= (uint8_t)mask;
            e->last_tick = ams::os::GetSystemTick().GetInt64Value();

            u32 want = (1u << total) - 1;
            if (e->seen == (uint8_t)want) {
                /* A non-final part shorter than one stride leaves a hole in the
                 * flat `part * pmtu` layout. That is worth NOTICING, but it is
                 * NOT worth dropping the packet over: this check was added
                 * speculatively and dropping here can silently discard LAN
                 * traffic that previously forwarded fine. Forwarding faithfully
                 * is the job; log the anomaly and hand the packet up. Only the
                 * bounds check below is a real safety requirement. */
                for (uint8_t i = 0; i + 1 < total; i++) {
                    if (e->lens[i] != pmtu) {
                        ::slp::dbg::Trace("frag: short part %u (%u != stride %u) src=0x%08x id=%u",
                                          i, e->lens[i], pmtu, src, id);
                        break;
                    }
                }
                size_t rebuilt = (size_t)(total - 1) * pmtu + e->lens[total - 1];
                e->active = false;
                if (rebuilt <= sizeof(e->data))
                    ProcessIpv4(e->data, rebuilt);
            }
        }

    }

    /* --- public API --- */

    void Init() {
        char ip[16];
        slp::rt::GetRuntime().GetVirtualIp(ip, sizeof(ip));
        g_local_ip = ParseIp(ip);
        if (g_local_ip == 0)
            g_local_ip = 0x0A0D2502;   /* fallback 10.13.37.2 */

        auto &mgr = ams::mitm::bsd::ProxySocketManager::GetInstance();
        mgr.SetLocalIp(g_local_ip);
        mgr.SetSendCallback(&slp::tun::Send);
    }

    void RefreshLocalIp() {
        /* Re-read the virtual address once the network is actually up.
         *
         * Init() runs from boot2, BEFORE DHCP, so GetVirtualIp() cannot reach
         * nifm and returns the hardcoded fallback 10.13.37.2. That value was
         * then frozen into g_local_ip for the whole session while LDN, which
         * initializes later, picked up the properly derived address. The
         * console therefore had TWO identities: peers saw our tunnel traffic
         * as 10.13.37.2 while LDN advertised 10.13.227.168. Observed directly
         * -- the fake host logged sessions "from [10,13,37,2]" even though the
         * derived address was 10.13.227.168.
         *
         * Called from Runtime::Start(), by which point nifm answers. */
        char ip[16];
        slp::rt::GetRuntime().GetVirtualIp(ip, sizeof(ip));
        const uint32_t fresh = ParseIp(ip);
        if (fresh == 0 || fresh == g_local_ip)
            return;

        ::slp::dbg::Trace("tun: local ip refreshed %u.%u.%u.%u -> %s",
                          (g_local_ip >> 24) & 0xFF, (g_local_ip >> 16) & 0xFF,
                          (g_local_ip >> 8) & 0xFF, g_local_ip & 0xFF, ip);
        g_local_ip = fresh;
        ams::mitm::bsd::ProxySocketManager::GetInstance().SetLocalIp(g_local_ip);
    }

bool Send(uint32_t src_ip, uint16_t src_port,
          uint32_t dst_ip, uint16_t dst_port,
          ryu_ldn::bsd::ProtocolType /*protocol*/,
          const void *data, size_t len) {
        if (data == nullptr && len > 0)
            return false;
        if (len > 2000)   /* matches PROXY_SOCKET_MAX_PAYLOAD */
            return false;

        if (slp::rt::GetRuntime().GetState() != SLPCFG_STATE_RUNNING)
            return false;

        SlpClient *c = slp::rt::GetRuntime().GetSlpClient();
        if (c == nullptr || c->fd < 0)
            return false;

        /* Loopback: deliver locally, do NOT drop and do NOT tunnel.
         *
         * Pia >= 5.28 sends session keep-alives to 127.0.0.1 (every 2s, on
         * :49152, whether or not it is in a session). We used to `return true`
         * here -- report success and throw the packet away. Not tunnelling it
         * is right (it must never reach the relay room), but discarding it is
         * NOT what hardware does: on a real console the loopback interface
         * delivers that datagram straight back to the socket bound to the same
         * port, so the game receives its own keep-alive. Swallowing it means a
         * game that watches for it sees a dead network.
         *
         * notes/compat-matrix.md lists "the loopback keepalive" as one of only
         * three things the tunnel has to get right, alongside socket/broadcast
         * semantics and the bsd-session interception policy.
         *
         * Feed it back through the normal inbound path so the game's own socket
         * receives it exactly as the loopback interface would. */
        if ((dst_ip & 0xFF000000) == 0x7F000000) {
            ::slp::dbg::Trace("tun: loopback %u -> %u (%zu B) delivered locally",
                              src_port, dst_port, len);
            ams::mitm::bsd::ProxySocketManager::GetInstance().RouteIncomingData(
                dst_ip, src_port, dst_ip, dst_port,
                ryu_ldn::bsd::ProtocolType::Udp,
                static_cast<const uint8_t *>(data), len);
            return true;
        }

        /* INADDR_ANY-bound sockets report src 0 — present our virtual IP so
         * peers can route replies back and the relay caches a real key. */
        if (src_ip == 0)
            src_ip = g_local_ip;

        uint16_t ip_total = (uint16_t)(20 + 8 + len);
        uint16_t udp_len  = (uint16_t)(8 + len);
        uint16_t ip_id    = g_ip_id++;

        static thread_local uint8_t pkt[2048 + 28];
        uint8_t *ip = pkt;

        ip[0] = 0x45;                 /* IPv4, IHL 5 */
        ip[1] = 0x00;                 /* DSCP/ECN */
        Wr16be(ip + 2, ip_total);
        Wr16be(ip + 4, ip_id);
        ip[6] = 0x40;                 /* DF */
        ip[7] = 0x00;
        ip[8] = 64;                   /* TTL */
        ip[9] = 17;                   /* UDP */
        ip[10] = 0;
        ip[11] = 0;                   /* checksum filled below */
        Wr32be(ip + 12, src_ip);
        Wr32be(ip + 16, dst_ip);

        uint8_t *udp = ip + 20;
        Wr16be(udp + 0, src_port);
        Wr16be(udp + 2, dst_port);
        Wr16be(udp + 4, udp_len);
        udp[6] = 0;
        udp[7] = 0;                   /* UDP checksum 0 (valid for IPv4) */
        if (len > 0)
            std::memcpy(udp + 8, data, len);

        uint16_t sum = IpChecksum(ip, 20);
        ip[10] = (uint8_t)(sum >> 8);
        ip[11] = (uint8_t)(sum & 0xFF);

        return slpClientSendIpv4(c, ip, ip_total);
    }

    void OnFrame(int type, const uint8_t *payload, size_t len) {
        switch (type) {
            case SLP_TYPE_IPV4:
                ProcessIpv4(payload, len);
                break;
            case SLP_TYPE_IPV4_FRAG:
                OnFrag(payload, len);
                break;
            default:
                break;
        }
    }

    void OnStop() {
        for (size_t i = 0; i < MaxFragEntries; i++)
            g_frags[i].active = false;
    }

}
