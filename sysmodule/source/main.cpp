/*
 * sys-slp-client — slp relay client sysmodule.
 *
 * Registers services at boot:
 *   - "slp:cfg"  standalone IPC the Tesla overlay uses to pick a server,
 *                start/stop the relay connection and read status.
 *   - "ldn:u"    MITM service. Phase 1 forwards everything to the real LDN
 *                service so games behave as stock; the relay data path
 *                (ICommunicationService + bsd proxy) lands in M2.
 *   - "bsd:u"    MITM service (M2). Intercepts LAN-bound sockets so MK8DX
 *                LAN mode traffic flows through the slp relay instead of
 *                the real network (see source/bsd, source/tunnel).
 *
 * When running, the module keeps a UDP connection to the chosen slp relay
 * and sends keepalives so the relay registers this console as a peer.
 */
#include <stratosphere.hpp>

#include <switch/runtime/devices/socket.h>

extern "C" {
#include <switch/services/bsd.h>
}

#include "slpcfg/slp_runtime.hpp"
#include "slpcfg/slp_cfg_service.hpp"
#include "slpcfg/slp_trace.hpp"
#include "build_id.h"
#include "ldn/ldn_mitm_service.hpp"
#include "ldn/ldn_control.hpp"
#include "bsd/bsd_mitm_service.hpp"
#include "bsd/lan_addr_map.hpp"
#include "bsd/proxy_socket_manager.hpp"
#include "tunnel/slp_tunnel.hpp"

namespace ams {

    namespace {

        /* Main malloc buffer — shared ~10 MB across sysmodules, keep small. */
        constexpr size_t MallocBufferSize = 1_MB;
        alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];

        constexpr const ::SocketInitConfig LibnxSocketInitConfig = {
            .tcp_tx_buf_size     = 0x800,
            .tcp_rx_buf_size     = 0x1000,
            .tcp_tx_buf_max_size = 0x2000,
            .tcp_rx_buf_max_size = 0x2000,
            .udp_tx_buf_size     = 0x2000,
            .udp_rx_buf_size     = 0x2000,
            .sb_efficiency       = 4,
            .num_bsd_sessions    = 4,
            .bsd_service_type    = BsdServiceType_User,
        };

        alignas(os::MemoryPageSize) constinit u8 g_socket_tmem_buffer[
            static_cast<size_t>(LibnxSocketInitConfig.sb_efficiency) *
            util::AlignUp(
                static_cast<size_t>(LibnxSocketInitConfig.tcp_tx_buf_max_size +
                                    LibnxSocketInitConfig.tcp_rx_buf_max_size +
                                    LibnxSocketInitConfig.udp_tx_buf_size +
                                    LibnxSocketInitConfig.udp_rx_buf_size),
                os::MemoryPageSize)];

        constexpr const ::BsdInitConfig LibnxBsdInitConfig = {
            .version             = 1,
            .tmem_buffer         = g_socket_tmem_buffer,
            .tmem_buffer_size    = sizeof(g_socket_tmem_buffer),
            .tcp_tx_buf_size     = LibnxSocketInitConfig.tcp_tx_buf_size,
            .tcp_rx_buf_size     = LibnxSocketInitConfig.tcp_rx_buf_size,
            .tcp_tx_buf_max_size = LibnxSocketInitConfig.tcp_tx_buf_max_size,
            .tcp_rx_buf_max_size = LibnxSocketInitConfig.tcp_rx_buf_max_size,
            .udp_tx_buf_size     = LibnxSocketInitConfig.udp_tx_buf_size,
            .udp_rx_buf_size     = LibnxSocketInitConfig.udp_rx_buf_size,
            .sb_efficiency       = LibnxSocketInitConfig.sb_efficiency,
        };

    }

    /* Heap for dynamic allocations (new/delete override below).
     * Each bsd ProxySocket carries a 32-entry x 2000B rx ring, so a MK8DX
     * session (multiple LAN UDP sockets) needs ~256KB+. */
    namespace heap {

        alignas(0x40) constinit u8 g_heap_memory[512_KB];
        constinit lmem::HeapHandle g_heap_handle;
        constinit bool g_heap_initialized;
        constinit os::SdkMutex g_heap_init_mutex;

        lmem::HeapHandle GetHeapHandle() {
            if (AMS_UNLIKELY(!g_heap_initialized)) {
                std::scoped_lock lk(g_heap_init_mutex);
                if (AMS_LIKELY(!g_heap_initialized)) {
                    g_heap_handle = lmem::CreateExpHeap(
                        g_heap_memory, sizeof(g_heap_memory),
                        lmem::CreateOption_ThreadSafe);
                    g_heap_initialized = true;
                }
            }
            return g_heap_handle;
        }

        void *Allocate(size_t size) {
            return lmem::AllocateFromExpHeap(GetHeapHandle(), size);
        }

        void Deallocate(void *p, size_t size) {
            AMS_UNUSED(size);
            return lmem::FreeToExpHeap(GetHeapHandle(), p);
        }

    }

    namespace cfg {

        const s32 ThreadPriority = 10;
        const size_t ThreadStackSize = 0x4000;
        alignas(os::MemoryPageSize) u8 g_thread_stack[ThreadStackSize];
        os::ThreadType g_thread;

        struct ConfigServerManagerOptions {
            static constexpr size_t PointerBufferSize    = 0x100;
            static constexpr size_t MaxDomains           = 0;
            static constexpr size_t MaxDomainObjects     = 0;
            static constexpr bool   CanDeferInvokeRequest = false;
            static constexpr bool   CanManageMitmServers  = false;
        };

        constexpr size_t MaxSessions = 2;
        using ConfigServerManager =
            sf::hipc::ServerManager<1, ConfigServerManagerOptions, MaxSessions>;
        ConfigServerManager g_server_manager;

        void LoopConfigServerThread(void *) {
            g_server_manager.LoopProcess();
        }

    }

    namespace mitm {

        const s32 ThreadPriority = 6;
        const size_t ThreadStackSize = 0x8000;
        alignas(os::MemoryPageSize) u8 g_thread_stack[ThreadStackSize];
        os::ThreadType g_thread;

        struct LdnMitmManagerOptions {
            static constexpr size_t PointerBufferSize    = 0x1000;
            static constexpr size_t MaxDomains           = 0x10;
            static constexpr size_t MaxDomainObjects     = 0x100;
            static constexpr bool   CanDeferInvokeRequest = false;
            static constexpr bool   CanManageMitmServers  = true;
        };

        constexpr size_t MaxSessions = 16;
        constexpr int PortIndex_LdnMitm = 0;
        constexpr int PortIndex_BsdMitm = 1;

        /* First template argument is MaxServers -- it MUST be >= the number of
         * ports registered below (currently ldn:u and bsd:u). Getting this
         * wrong makes RegisterMitmServer() fail and the R_ABORT_UNLESS around
         * it kills the sysmodule at boot with 0xFFE. It was briefly 3 while
         * nifm:u was registered; nifm has since been removed because it aborted
         * MK8DX's LAN thread. Bump this whenever a port is added. */
        /* Kept at 3 even though only two ports are registered. MaxServers only
         * needs to be >= the port count; a spare slot is free, and this was 3
         * during the period when LAN behaved, so it is not left as a variable. */
        constexpr int NumMitmPorts = 3;

        class ServerManager final
            : public sf::hipc::ServerManager<NumMitmPorts, LdnMitmManagerOptions, MaxSessions> {
        private:
            virtual ams::Result OnNeedsToAccept(int port_index, Server *server) override {
                std::shared_ptr<::Service> fsrv;
                sm::MitmProcessInfo client_info;
                server->AcknowledgeMitmSession(std::addressof(fsrv),
                                               std::addressof(client_info));
                switch (port_index) {
                    case PortIndex_LdnMitm:
                        ::slp::dbg::Trace("mitm: accept ldn client pid=0x%lx",
                                          static_cast<unsigned long>(client_info.process_id.value));
                        return this->AcceptMitmImpl(
                            server,
                            sf::CreateSharedObjectEmplaced<
                                ams::slp::ldn::ILdnMitMService,
                                ams::slp::ldn::LdnMitMService>(decltype(fsrv)(fsrv), client_info),
                            fsrv);
                    case PortIndex_BsdMitm:
                        ::slp::dbg::Trace("mitm: accept bsd client pid=0x%lx",
                                          static_cast<unsigned long>(client_info.process_id.value));
                        return this->AcceptMitmImpl(
                            server,
                            sf::CreateSharedObjectEmplaced<
                                ams::mitm::bsd::IBsdMitmService,
                                ams::mitm::bsd::BsdMitmService>(decltype(fsrv)(fsrv), client_info),
                            fsrv);
                    /* PortIndex_NifmMitm removed -- it aborted MK8DX's LAN
                     * thread. See the registration site for the crash report. */
                    default:
                        AMS_ABORT("Unknown port index");
                }
            }
        };

        ServerManager g_server_manager;

        void LoopServerThread(void *) {
            g_server_manager.LoopProcess();
        }

    }

    namespace init {

        void InitializeSystemModule() {
            AMS_UNUSED(g_socket_tmem_buffer);

            R_ABORT_UNLESS(sm::Initialize());
            fs::InitializeForSystem();
            fs::SetAllocator(heap::Allocate, heap::Deallocate);
            fs::SetEnabledAutoAbort(false);
            R_ABORT_UNLESS(fs::MountSdCard("sdmc"));

            R_ABORT_UNLESS(nifmInitialize(NifmServiceType_Admin));
            R_ABORT_UNLESS(bsdInitialize(&LibnxBsdInitConfig,
                                         LibnxSocketInitConfig.num_bsd_sessions,
                                         LibnxSocketInitConfig.bsd_service_type));
            R_ABORT_UNLESS(socketInitialize(&LibnxSocketInitConfig));
        }

        void FinalizeSystemModule() {
            socketExit();
            bsdExit();
            nifmExit();
            fs::Unmount("sdmc");
        }

        void Startup() {
            init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
        }

    }

    void NORETURN Exit(int rc) {
        AMS_UNUSED(rc);
        AMS_ABORT("Exit called by immortal process");
    }

    void Main() {
        /* Boot heartbeat — proves this module actually ran under boot2. */
        {
            constexpr const char kText[] = "slp-client booted\n";
            constexpr const char *kPath = "sdmc:/slp-heartbeat.txt";
            ams::Result rc = ams::fs::DeleteFile(kPath);
            AMS_UNUSED(rc);
            rc = ams::fs::CreateFile(kPath, sizeof(kText) - 1);
            AMS_UNUSED(rc);

            ams::fs::FileHandle file;
            rc = ams::fs::OpenFile(std::addressof(file), kPath,
                                   ams::fs::OpenMode_Write);
            if (R_SUCCEEDED(rc)) {
                rc = ams::fs::WriteFile(file, 0, kText, sizeof(kText) - 1,
                                        ams::fs::WriteOption::Flush);
                ams::fs::CloseFile(file);
            }
            AMS_UNUSED(rc);
        }

        /* Load the server list (sdmc:/config/slp-helper/servers.conf). */
        ::slp::rt::GetRuntime().ReloadServers();
        ::slp::dbg::TraceInit();
        /* FIRST line in the log, always. Identifies the exact binary that
         * produced everything below it. */
        ::slp::dbg::Trace("===== sys-slp-client v%s build %s =====",
                          SLP_VERSION, SLP_BUILD_ID_STR);
        ::slp::dbg::Trace("main: boot done, cfg reloaded");

/* M2: wire the bsd proxy send path into the relay. */
        ::slp::tun::Init();

        /* M3: register TCP proxy callbacks for LDN connection handling.
         * These are invoked by ProxySocket::Connect()/Accept() when TCP
         * proxy sockets call Connect()/Accept() — they route through the
         * LDN control plane so TCP connections can be established. */
        auto& mgr = ams::mitm::bsd::ProxySocketManager::GetInstance();
        mgr.SetSendCallback(&::slp::tun::Send);

        /* TCP control-plane callbacks — NOT IMPLEMENTED, fail fast and honest.
         *
         * TCP proxying over the virtual network has no wire protocol at all:
         * these callbacks used to unconditionally `return true`, claiming a
         * ProxyConnect/-Reply/Disconnect notification had been sent to the
         * peer when nothing was transmitted. For SetProxyConnectCallback that
         * is a real bug, not dead code — BsdMitmService::Connect() promotes
         * ANY socket type (including TCP) to a proxy socket when the
         * destination is an LDN/virtual address, so ProxySocket::Connect()
         * genuinely reaches this callback. Lying "true" made it wait on
         * m_connect_event for a reply that could never arrive, so every TCP
         * connect over the virtual network silently hung for 4 seconds before
         * failing with ETIMEDOUT — the wrong error, for the wrong reason,
         * after a needless stall. Returning false makes it fail immediately
         * with ENETUNREACH instead.
         *
         * The receive side is equally unimplemented: ProxySocketManager::
         * RouteConnectRequest/RouteConnectResponse exist but are never called
         * from anywhere (no inbound frame type feeds them), and
         * proxy_connect_shim.hpp's claim that none of this is reachable is
         * stale — only the RECEIVE side is actually unreachable.
         *
         * SetProxyConnectReplyCallback/SetProxyDisconnectCallback's return
         * values are discarded by their only callers (proxy_socket.cpp), so
         * `false` here is purely honesty, not a behavior change.
         *
         * None of the three titles tested tonight (MK8DX, Diablo III, Advance
         * Wars) use TCP on the virtual network — LAN browse (:30000), Pia
         * session (:49152), and LDN control (:11452) are all UDP — so this
         * has not bitten anything yet. A real implementation needs a wire
         * frame type for connect/reply/disconnect plus inbound dispatch in
         * slp_tunnel.cpp to call RouteConnectRequest/RouteConnectResponse. */
        mgr.SetProxyConnectCallback
            ([](uint32_t src_ip, uint16_t src_port,
                uint32_t dst_ip, uint16_t dst_port,
                ryu_ldn::bsd::ProtocolType protocol) -> bool {
                (void)src_ip; (void)src_port;
                (void)dst_ip; (void)dst_port;
                (void)protocol;
                return false;
            });

        mgr.SetProxyConnectReplyCallback
            ([](uint32_t src_ip, uint16_t src_port,
                uint32_t dst_ip, uint16_t dst_port,
                ryu_ldn::bsd::ProtocolType protocol) -> bool {
                (void)src_ip; (void)src_port;
                (void)dst_ip; (void)dst_port;
                (void)protocol;
                return false;
            });

        mgr.SetProxyDisconnectCallback
            ([](uint32_t src_ip, uint16_t src_port,
                uint32_t dst_ip, uint16_t dst_port,
                ryu_ldn::bsd::ProtocolType protocol) -> bool {
                (void)src_ip; (void)src_port;
                (void)dst_ip; (void)dst_port;
                (void)protocol;
                return false;
            });

        /* M2: LDN control plane — parse the virtual IP and arm the state
         * machine (must be Initialized before any game opens ldn:u). */
        R_ABORT_UNLESS(ams::slp::ldn::LdnControl::GetInstance().Initialize());

        /* slp:cfg standalone service */
        constexpr sm::ServiceName ConfigServiceName =
            sm::ServiceName::Encode(SLPCFG_SERVICE_NAME);
        auto config_service = sf::CreateSharedObjectEmplaced<
            ::slp::ipc::IConfigService,
            ::slp::ipc::ConfigService>();
        R_ABORT_UNLESS(cfg::g_server_manager.RegisterObjectForServer(
            std::move(config_service), ConfigServiceName, cfg::MaxSessions));

        R_ABORT_UNLESS(os::CreateThread(&cfg::g_thread,
                                        cfg::LoopConfigServerThread, nullptr,
                                        cfg::g_thread_stack,
                                        cfg::ThreadStackSize,
                                        cfg::ThreadPriority));
        os::SetThreadNamePointer(&cfg::g_thread, "slp::CfgThread");
        os::StartThread(&cfg::g_thread);

        /* ldn:u MITM service */
        constexpr sm::ServiceName LdnMitmServiceName =
            sm::ServiceName::Encode("ldn:u");
        R_ABORT_UNLESS((mitm::g_server_manager.RegisterMitmServer<
            ams::slp::ldn::LdnMitMService>(mitm::PortIndex_LdnMitm,
                                      LdnMitmServiceName)));

        /* bsd:u MITM service (M2) — intercept LAN-bound sockets for relay. */
        constexpr sm::ServiceName BsdMitmServiceName =
            sm::ServiceName::Encode("bsd:u");
        R_ABORT_UNLESS((mitm::g_server_manager.RegisterMitmServer<
            ams::mitm::bsd::BsdMitmService>(mitm::PortIndex_BsdMitm,
                                      BsdMitmServiceName)));

        /* nifm:u MITM — REMOVED. It crashed MK8DX's LAN mode, 100% reproducible.
         *
         * Atmosphere crash reports for 0100152000022000 (twelve of them, all
         * identical) show:
         *
         *   Result:      0xCA8 (2168-0006)   <- the on-screen 2618-0006
         *   Type:        User Break (nn::diag::detail::Abort)
         *   Thread:      enl::TaskThread     <- Nintendo's LAN layer
         *   Stack:       CmifDomainClientMessage<...>
         *                ObjectImplFactoryWithStatelessAllocator<
         *                    CmifProxyFactory<nn::nifm::detail::IStaticService>>
         *                nn::nifm::detail::ServiceProviderClient::
         *                    GetUserServiceSharedPointer(SharedPointer<IGeneralService>*)
         *
         * Entering LAN mode makes the game ask nifm for its interface address.
         * That call allocates a CMIF *domain* object for IStaticService, and
         * with our server in the path the domain client message aborts. It did
         * this even as a pure passthrough (we declared only unused cmd 65000 so
         * everything auto-forwarded) -- merely interposing on the session is
         * enough. LDN/WiFi never takes this path, which is exactly why wireless
         * play kept working while only the LAN page died.
         *
         * We got nothing for the cost: every attempt to actually override the
         * reported address failed (the handler was never entered across three
         * signature attempts). The address mismatch this was meant to fix
         * turned out not to need fixing at all: LAN browse's broadcast
         * delivery matches on the destination ending in .255
         * (proxy_socket_manager.cpp), not on subnet membership, so it works
         * regardless of what nifm tells the game about its own address.
         * `bsd/lan_addr_map.hpp`'s translation is also currently disabled and
         * LAN still works -- see its own comment for why.
         *
         * source/nifm/nifm_mitm_service.{hpp,cpp} still contain this attempt,
         * dormant and NOT wired into any registration above -- kept as a
         * documented possible future fix (real two-console LAN join may need
         * a host's self-reported address to be the virtual one, untested; see
         * the STATUS note at the top of nifm_mitm_service.hpp for the full
         * analysis of what would need to change to make it reachable again).
         *
         * Do NOT re-register this without first reproducing a LAN-mode join and
         * confirming no new 0100152000022000 crash report appears.
         */

        R_ABORT_UNLESS(os::CreateThread(&mitm::g_thread,
                                        mitm::LoopServerThread, nullptr,
                                        mitm::g_thread_stack,
                                        mitm::ThreadStackSize,
                                        mitm::ThreadPriority));
        os::SetThreadNamePointer(&mitm::g_thread, "slp::MainThread");
        os::StartThread(&mitm::g_thread);

        os::WaitThread(&mitm::g_thread);
    }

}

/* Route global new/delete to our exp heap. */
void *operator new(size_t size) { return ams::heap::Allocate(size); }
void *operator new(size_t size, const std::nothrow_t &) { return ams::heap::Allocate(size); }
void operator delete(void *p) { return ams::heap::Deallocate(p, 0); }
void operator delete(void *p, size_t size) { return ams::heap::Deallocate(p, size); }
void *operator new[](size_t size) { return ams::heap::Allocate(size); }
void *operator new[](size_t size, const std::nothrow_t &) { return ams::heap::Allocate(size); }
void operator delete[](void *p) { return ams::heap::Deallocate(p, 0); }
void operator delete[](void *p, size_t size) { return ams::heap::Deallocate(p, size); }
