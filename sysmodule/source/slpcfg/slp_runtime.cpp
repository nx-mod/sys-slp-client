#include "slp_runtime.hpp"

#include "servers.h"
#include "slp_trace.hpp"
#include "../tunnel/slp_tunnel.hpp"

#include <cstring>
#include <cstdio>

extern "C" {
#include <switch/services/nifm.h>
}

namespace slp::rt {

    namespace {

        constexpr u32 KeepaliveIntervalMs = 10000;
        constexpr u32 RecvTimeoutMs       = 1000;

        /* Phase 1: fixed virtual IP. See GetVirtualIp(). */
        constexpr const char *DefaultVirtualIp = "10.13.37.2";

        /* Config read via ams::fs so we never touch stdio in a boot2 context. */
        int ReadConfigText(const char *path, char *buf, size_t cap) {
            ams::fs::FileHandle file;
            ams::Result rc = ams::fs::OpenFile(std::addressof(file),
                                               path,
                                               ams::fs::OpenMode_Read);
            if (R_FAILED(rc))
                return -1;

            s64 size = 0;
            rc = ams::fs::GetFileSize(std::addressof(size), file);
            if (R_SUCCEEDED(rc) && size > 0 && (u64)size < cap - 1) {
                size_t read = 0;
                rc = ams::fs::ReadFile(std::addressof(read), file, 0, buf, (size_t)size);
                if (R_SUCCEEDED(rc))
                    buf[read] = '\0';
            } else {
                rc = ams::fs::ResultInvalidSize();
            }

            ams::fs::CloseFile(file);
            if (R_FAILED(rc))
                return -1;
            return (int)size;
        }

    }

    Runtime::Runtime()
        : m_sel_index(-1), m_state(SLPCFG_STATE_STOPPED),
          m_relay_ip(0),
          m_thread_running(false),
          m_rx_frames(0), m_tx_frames(0)
    {
        m_ip[0] = '\0';
        m_connected_host[0] = '\0';
        m_client.fd = -1;
    }

    Runtime::~Runtime() {
        Stop();
    }

    int Runtime::ReloadServers() {
        std::scoped_lock lk(m_mutex);
        char buf[4096];
        int size = ReadConfigText(SLPCFG_CONFIG_PATH, buf, sizeof(buf));
        if (size < 0)
            return 0;
        int count = slpServersParse(buf, (size_t)size);
        /* Default to the first server when nothing is selected yet or the
         * stored selection went out of range. */
        if (m_sel_index < 0 || m_sel_index >= count)
            m_sel_index = count > 0 ? 0 : -1;
        return count;
    }

    bool Runtime::RelayOnLocalNetwork() const {
        u32 ip = m_relay_ip;
        if (ip == 0)
            return false;   /* not connected yet — stay safe */
        /* m_relay_ip is in network byte order (big endian). Convert to host order. */
        u32 ip_host = __builtin_bswap32(ip);
        u8 first = (ip_host >> 24) & 0xFF;
        u16 first_two = (ip_host >> 16) & 0xFFFF;
        switch (first) {
            case 0x0A:      /* 10.0.0.0/8    */
                return true;
            case 0xAC:      /* 172.16.0.0/12 */
                return (first_two & 0xFFF0) == 0xAC10;
            case 0xC0:      /* 192.168.0.0/16 */
                return first_two == 0xC0A8;
            case 0xA9:      /* 169.254.0.0/16 link-local */
                return first_two == 0xA9FE;
            default:
                return false;   /* public / remote relay — keep the internet link */
        }
    }

    int Runtime::ServerCount() {
        std::scoped_lock lk(m_mutex);
        return slpServersCount();
    }

    const char *Runtime::ServerName(int index) {
        std::scoped_lock lk(m_mutex);
        const SlpServer *s = slpServersGet(index);
        return s != nullptr ? s->name : "";
    }

    const char *Runtime::ServerHost(int index) {
        std::scoped_lock lk(m_mutex);
        const SlpServer *s = slpServersGet(index);
        return s != nullptr ? s->host : "";
    }

    unsigned short Runtime::ServerPort(int index) {
        std::scoped_lock lk(m_mutex);
        const SlpServer *s = slpServersGet(index);
        return s != nullptr ? s->port : 0;
    }

    int Runtime::SelectServer(u32 index) {
        std::scoped_lock lk(m_mutex);
        if ((int)index >= slpServersCount())
            return 0;
        m_sel_index = (int)index;
        return 1;
    }

    int Runtime::GetState() {
        std::scoped_lock lk(m_mutex);
        return m_state;
    }

    int Runtime::GetSelectedIndex() {
        std::scoped_lock lk(m_mutex);
        return m_sel_index;
    }

    const char *Runtime::GetIp() {
        std::scoped_lock lk(m_mutex);
        return m_ip;
    }

    u32 Runtime::GetRxFrames() {
        std::scoped_lock lk(m_mutex);
        return m_rx_frames;
    }

    u32 Runtime::GetTxFrames() {
        std::scoped_lock lk(m_mutex);
        return m_tx_frames;
    }

    void Runtime::GetVirtualIp(char *out, size_t cap) {
        /* Derive a per-console address inside the 10.13.0.0/16 virtual subnet.
         *
         * This used to return a hardcoded "10.13.37.2" for EVERY console. On a
         * private relay that is invisible; on a shared one it is fatal. The
         * relay identifies peers by source IP -- map.insert(src_ip, socket) --
         * so two consoles running this module both claim 10.13.37.2 and
         * whichever transmitted last owns the entry. The other keeps sending
         * happily, is counted online, and receives NOTHING, because every reply
         * addressed to 10.13.37.2 goes to its rival. Two instances of this
         * module knock each other off the network.
         *
         * The reference stack avoids this by having the user assign each
         * console a distinct static 10.13.x.x by hand. We do it automatically:
         * take the low two octets of the console's REAL address (unique on its
         * own LAN, which is the uniqueness we need) and graft them onto 10.13:
         *
         *     real 10.172.227.168  ->  virtual 10.13.227.168
         *
         * Deterministic, so it survives reboots and the relay's peer map stays
         * stable. Avoids .0/.255 (network/broadcast) and .1 (gateway). */
        u32 real_ip = 0, real_mask = 0, gw = 0, d1 = 0, d2 = 0;
        const Result rc = nifmGetCurrentIpConfigInfo(&real_ip, &real_mask, &gw, &d1, &d2);

        if (R_SUCCEEDED(rc) && real_ip != 0) {
            /* nifm returns network byte order; we want the numeric form. */
            const u32 host_order = __builtin_bswap32(real_ip);
            u32 c = (host_order >> 8) & 0xFF;
            u32 d =  host_order       & 0xFF;

            if (d == 0 || d == 255 || d == 1)
                d = 2 + (d % 250);          /* keep it inside .2 - .251 */
            if (c == 255)
                c = 37;

            std::snprintf(out, cap, "10.13.%u.%u",
                          static_cast<unsigned>(c), static_cast<unsigned>(d));
            dbg::Trace("runtime: virtual ip %s (derived from real %u.%u.%u.%u)",
                       out,
                       (host_order >> 24) & 0xFF, (host_order >> 16) & 0xFF,
                       (host_order >> 8) & 0xFF, host_order & 0xFF);
            return;
        }

        /* Network not up yet (boot2 runs before DHCP). Fall back to the legacy
         * fixed address; this is called again when a game opens ldn:u, by which
         * time nifm answers. */
        dbg::Trace("runtime: nifm unavailable (0x%08x) -- fallback virtual ip %s",
                   static_cast<unsigned>(rc), DefaultVirtualIp);
        std::strncpy(out, DefaultVirtualIp, cap - 1);
        out[cap - 1] = '\0';
    }

    void Runtime::RunLoop(void *arg) {
        Runtime *rt = static_cast<Runtime *>(arg);
        SlpClient *c = std::addressof(rt->m_client);
        static thread_local uint8_t buf[2048];
        ams::os::Tick last_keepalive = ams::os::GetSystemTick();
        int keepalive_fails = 0;

        while (rt->m_thread_running.load()) {
            ams::os::Tick now = ams::os::GetSystemTick();
            if (ams::os::ConvertToTimeSpan(now - last_keepalive).GetMilliSeconds()
                    >= KeepaliveIntervalMs) {
                last_keepalive = now;
                if (slpClientSendKeepalive(c)) {
                    rt->m_tx_frames++;
                    keepalive_fails = 0;
                    dbg::Trace("run: keepalive sent");
                } else {
                    keepalive_fails++;
                    dbg::Trace("run: keepalive SEND FAILED");
                    if (keepalive_fails >= 3) {
                        /* Relay went away (restart / network blip): drop the
                         * dead socket and re-open to the same cached server.
                         * Reuses ip/port from the last successful open, so an
                         * emptied server list can never trigger this path. */
                        dbg::Trace("run: reconnecting to relay");
                        keepalive_fails = 0;
                        if (slpClientReopen(c))
                            dbg::Trace("run: reconnect ok");
                        else
                            dbg::Trace("run: reconnect failed, will retry");
                    }
                }
            }

            int type = 0;
            int n = slpClientRecv(c, buf, sizeof(buf), (int)RecvTimeoutMs, &type);

            /* Return-path probe. The relay echoes a Ping (0x02) back to the
             * sender unconditionally (see Runtime::Start()'s send-on-connect),
             * so a reply here proves this console can receive from this relay
             * at all -- without depending on any other peer being online. */
            if (n > 0 && type == SLP_TYPE_PING) {
                dbg::Trace("run: PING ECHO received (%d B) -- return path from this relay WORKS", n);
                continue;
            }

            /* Relay login. A relay that requires auth sends AUTH_ME and
             * forwards an unauthenticated peer NOTHING -- we can still send,
             * so ignoring this looks exactly like a dead tunnel. Answer it
             * here and do not pass it to the tunnel.
             *
             * tekn0.net does NOT require a login (confirmed directly), so it
             * was never the explanation for tekn0's earlier "zero frames ever
             * received" symptom -- that was a byte-reversed DNS resolution
             * (see slp_client.c dns_parse_response), unrelated to this frame
             * type. AUTH_ME support is still correct/needed for any relay
             * that DOES require one; it's just not what tekn0 needed. */
            if (n > 0 && type == SLP_TYPE_AUTH_ME) {
                int sent = slpClientHandleAuthMe(c, buf + 1, (size_t)n - 1);
                dbg::Trace("run: AUTH_ME challenge -> %s",
                           sent ? "responded"
                                : "NO CREDENTIALS CONFIGURED (relay will forward us nothing)");
                continue;
            }

            if (n > 1) {
                rt->m_rx_frames++;
                dbg::Trace("run: recv type=0x%X len=%d", type, n);
                /* Tunnel IPv4/IPv4Frag frames into the bsd:u proxy sockets. */
                slp::tun::OnFrame(type, buf + 1, (size_t)n - 1);
            } else if (n > 0) {
                rt->m_rx_frames++;
            }

            /* Check stop request without blocking. */
            if (rt->m_stop_event.TryWait())
                break;
        }
        dbg::Trace("run: loop exit");
    }

    int Runtime::Start() {
        dbg::Trace("runtime: Start() enter");
        std::scoped_lock lk(m_mutex);

        if (m_state == SLPCFG_STATE_RUNNING)
            return 1;

        if (m_sel_index < 0 || m_sel_index >= slpServersCount())
            return 0;

        const SlpServer *s = slpServersGet(m_sel_index);
        if (s == nullptr)
            return 0;

        /* Apply this server's login BEFORE opening: a relay that requires auth
         * challenges us almost immediately, and an unanswered challenge means
         * it forwards us nothing at all. Only sha1(password) is retained. */
        slpClientSetCredentials(std::addressof(m_client),
                                s->username, s->password);
        dbg::Trace("runtime: credentials %s for '%s'",
                   s->username[0] != '\0' ? "configured" : "NOT set", s->name);

        if (!slpClientOpen(std::addressof(m_client), s->host, s->port)) {
            dbg::Trace("runtime: open FAILED host=%s", s->host);
            return 0;
        }
        /* Probe the RETURN PATH. The relay echoes a Ping (0x02) straight back
         * to the sender unconditionally, so this answers "can this console
         * receive anything from this relay at all?" without depending on any
         * other peer being online. Needed because a relay with no active
         * players sends nothing, which is indistinguishable from a broken
         * return path -- exactly the ambiguity that made tekn0 unreadable. */
        slpClientSendPing(std::addressof(m_client), 0xC0FFEE);
        dbg::Trace("runtime: sent return-path ping");

        const u8 *sip = reinterpret_cast<const u8 *>(&m_client.server_ip);
        dbg::Trace("runtime: open ok host=%s port=%u ip=%u.%u.%u.%u",
                   s->host, s->port, sip[0], sip[1], sip[2], sip[3]);
        m_relay_ip = m_client.server_ip;

        GetVirtualIp(m_ip, sizeof(m_ip));
        /* nifm is up by now, so the derived address is finally available --
         * push it into the tunnel, which was stuck with the boot2 fallback. */
        slp::tun::RefreshLocalIp();
        std::strncpy(m_connected_host, s->host, sizeof(m_connected_host) - 1);
        m_connected_host[sizeof(m_connected_host) - 1] = '\0';

        m_stop_event.Clear();
        m_thread_running.store(true);
        ams::Result rc =         ams::os::CreateThread(std::addressof(m_thread), RunLoop,
                                               this, m_thread_stack,
                                               sizeof(m_thread_stack),
                                               0x0F);
        if (R_FAILED(rc)) {
            dbg::Trace("runtime: CreateThread failed 0x%08X",
                       rc.GetValue());
            slpClientClose(std::addressof(m_client));
            m_thread_running.store(false);
            return 0;
        }
        ams::os::SetThreadNamePointer(std::addressof(m_thread), "slp::Run");
        ams::os::StartThread(std::addressof(m_thread));

        m_state = SLPCFG_STATE_RUNNING;
        dbg::Trace("runtime: Start() ok");
        return 1;
    }

    int Runtime::Stop() {
        dbg::Trace("runtime: Stop() enter");

        /* Hold m_mutex ONLY to claim the transition and signal the thread.
         *
         * This used to hold it across WaitThread() + slpClientClose() +
         * tun::OnStop(). Idle that is harmless, but with a game running the
         * bsd MITM has live sessions whose IPC threads call back into the
         * runtime (GetState() and friends) and need this same mutex. They
         * block, and because slpCfgStop is a SYNCHRONOUS ipc call from the
         * Tesla overlay, the overlay's UI thread blocks with them -- pressing
         * Stop mid-game froze uberhand outright. Publishing the state change
         * and then doing the teardown unlocked keeps the button safe to press
         * at any time.
         *
         * m_state is set to STOPPED up front, inside the lock, so any thread
         * that looks while teardown is in progress sees "stopped" rather than
         * a half-torn-down "running" -- and ShouldMitm immediately stops
         * intercepting new sessions. The state check under the lock also makes
         * a concurrent second Stop() a no-op instead of a double teardown. */
        {
            std::scoped_lock lk(m_mutex);
            if (m_state != SLPCFG_STATE_RUNNING)
                return 1;
            m_state = SLPCFG_STATE_STOPPED;
            m_thread_running.store(false);
            m_stop_event.Signal();
        }

        ams::os::WaitThread(std::addressof(m_thread));
        ams::os::DestroyThread(std::addressof(m_thread));

        slpClientClose(std::addressof(m_client));
        slp::tun::OnStop();
        dbg::Trace("runtime: Stop() ok");
        return 1;
    }

    SlpClient *Runtime::GetSlpClient() {
        return std::addressof(m_client);
    }

    Runtime &GetRuntime() {
        static Runtime runtime;
        return runtime;
    }

}
