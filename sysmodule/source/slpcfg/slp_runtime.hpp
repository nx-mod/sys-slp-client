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

        /* LDN policy: enter nifm local network mode on OpenStation. Entering
         * local network mode disconnects the Switch's WiFi from the internet,
         * which would kill the UDP tunnel to a REMOTE relay (e.g. tekn0.net).
         * But it is safe for a relay on the same LAN (local link stays up).
         * Decide automatically per case: enter local network mode iff the
         * connected relay resolves to a private-range address. */
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

        /* Virtual IP this console uses on the relay subnet. Phase 1: fixed;
         * later derived from the console MAC so multiple consoles coexist. */
        static void GetVirtualIp(char *out, size_t cap);
    };

    Runtime &GetRuntime();

}
