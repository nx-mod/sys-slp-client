/*
 * sys-slp-client — slp relay runtime.
 *
 * Holds the shared state between the slp:cfg IPC service and (future) the
 * ldn:u / bsd:u MITM data path:
 *
 *   - server list (parsed from sdmc:/config/slp-helper/servers.conf)
 *   - selected server index
 *   - running state (0 = stopped, 1 = running)
 *   - the UDP transport to the relay and a keepalive/recv thread
 *   - the virtual LDN IPv4 address this console presents to the relay
 */
#pragma once

#include "slp/slp_client.h"
#include <array>
#include <atomic>

#include <stratosphere.hpp>

#define SLPCFG_SERVICE_NAME "slp:cfg"
#define SLPCFG_CONFIG_PATH  "sdmc:/config/slp-helper/servers.conf"

#define SLPCFG_STATE_STOPPED 0
#define SLPCFG_STATE_RUNNING 1

namespace slp::rt {

    class Runtime {
    private:
        ams::os::SdkMutex m_mutex;

        int  m_sel_index;         /* selected server index (valid when running) */
        int  m_state;             /* SLPCFG_STATE_* */
        char m_ip[16];            /* virtual IPv4 string, e.g. "10.13.37.2" */
        char m_connected_host[128];

        u32 m_relay_ip; /* connected relay IP (network byte order), 0 = not connected */

        SlpClient m_client;       /* transport socket (only touched on run thread
                                     or with m_mutex held during start/stop) */

        alignas(ams::os::MemoryPageSize) u8 m_thread_stack[0x4000];
        ams::os::ThreadType m_thread;
        std::atomic<bool> m_thread_running;

        ams::os::Event m_stop_event{ams::os::EventClearMode_ManualClear};

        u32 m_rx_frames;
        u32 m_tx_frames;

        static void RunLoop(void *arg);

    public:
        Runtime();
        ~Runtime();

        /* Read + parse the server list from SD. Returns count (0 on error). */
        int ReloadServers();

        /* Whether the connected relay resolves to a private-range address.
         *
         * Used only as INFORMATION now (logged, and feeds the trace message
         * in LdnControl::EnterLocalNetworkMode) -- it no longer gates
         * whether local network mode is entered. That used to be conditional
         * ("skip for a remote relay, since entering kills the tunnel"), but
         * that theory was measured against a broken DNS resolver and is
         * disproven: entering local network mode does not sever the tunnel,
         * even against a remote relay. Local network mode is now entered
         * unconditionally; see EnterLocalNetworkMode's own comment for the
         * full story. */
        bool RelayOnLocalNetwork() const;
        u32 GetRelayIpForDebug() const { return m_relay_ip; }

        int  ServerCount();
        const char *ServerName(int index);
        const char *ServerHost(int index);
        unsigned short ServerPort(int index);

        /* Control (from slp:cfg IPC) */
        int  SelectServer(u32 index);
        int  Start();
        int  Stop();

        /* Transport access for the tunnel send path. Only valid while the
         * state is SLPCFG_STATE_RUNNING (fd is -1 otherwise). */
        SlpClient *GetSlpClient();

        /* Status (from slp:cfg IPC) */
        int  GetState();
        int  GetSelectedIndex();
        const char *GetIp();
        u32  GetRxFrames();
        u32  GetTxFrames();

        /* Virtual IP this console uses on the relay subnet: 10.13.x.x,
         * derived from the low two octets of the console's REAL address
         * (from nifm), not a fixed value and not MAC-based. This is what
         * lets multiple consoles behind one relay coexist without
         * colliding -- every console used to present the same hardcoded
         * 10.13.37.2, so on a shared relay the peer that transmitted last
         * owned that address and the others were invisible to it. See the
         * implementation for the full derivation and its fallback (nifm not
         * yet up at boot2). */
        static void GetVirtualIp(char *out, size_t cap);
    };

    Runtime &GetRuntime();

}
