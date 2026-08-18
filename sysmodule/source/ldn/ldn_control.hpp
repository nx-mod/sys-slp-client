/*
 * sys-slp-client — LDN control plane over the slp tunnel.
 *
 * Implements the LAN control protocol (ldn_mitm lan_protocol/lan_discovery)
 * transported through our tunnel instead of real UDP broadcast / per-station
 * TCP. Every control frame is a UDP datagram on the control port (11452,
 * ldn_mitm's DefaultPort) carried as an IPv4/UDP packet through the relay —
 * exactly the transport proven by spike/slp_ldn.py against a stock relay.
 *
 * This is a singleton shared by every game's ICommunicationService (only one
 * game runs LDN at a time, matching ldn_mitm's single global LANDiscovery).
 * Inbound control frames are dispatched from the tunnel run-loop thread via
 * OnControlFrame(); IPC handlers call the query/mutation methods below.
 */
#pragma once

#include <stratosphere.hpp>
#include <mutex>

#include "ldn_interfaces.hpp"

namespace ams::slp::ldn {

    constexpr u16 ControlPort = 11452;   /* ldn_mitm DefaultPort */

    /* LAN control frame types (lan_protocol.hpp). */
    enum LanPacketType : u8 {
        LanPacket_Scan        = 0,
        LanPacket_ScanResp    = 1,
        LanPacket_Connect     = 2,
        LanPacket_SyncNetwork = 3,
    };

    constexpr size_t MaxScanResults = 8;

    class LdnControl {
    public:
        static LdnControl &GetInstance();

        /* ---- transport (run-loop thread) ---- */

        /* Handle an inbound control frame (payload of a UDP datagram whose
         * dport == ControlPort). Called by slp::tun::OnFrame. src_ip is the
         * sender's virtual IP in Ryujinx format (network byte order u32). */
        void OnControlFrame(u32 src_ip, const u8 *payload, size_t len);

        /* Send a control frame to one peer or the subnet broadcast. */
        void SendFrame(u32 dst_ip, LanPacketType type,
                       const u8 *body, size_t body_len);

        /* ---- lifecycle (IPC thread) ---- */

        Result Initialize();
        Result Finalize();

        /* ---- host (Access Point) side ---- */

        Result OpenAccessPoint();
        Result CloseAccessPoint();
        Result CreateNetwork(const CreateNetworkConfig &data);
        Result DestroyNetwork();
        Result SetAdvertiseData(const u8 *data, size_t size);
        Result SetStationAcceptPolicy(u8 policy);
        Result Reject(u32 node_id);

        /* ---- station side ---- */

        Result OpenStation();
        Result CloseStation();
        Result Scan(const ScanFilter &filter, NetworkInfo *out,
                    u16 out_capacity, u32 *out_count);
        Result Connect(const ConnectNetworkData &dat, const NetworkInfo &data);
        Result Disconnect();

        /* ---- queries ---- */

        CommState GetState();
        Result GetNetworkInfo(NetworkInfo *out);
        u32 GetIpv4Address();
        u32 GetSubnetMask();
        u32 GetDisconnectReason();
        Result GetSecurityParameter(SecurityParameter *out);
        Result GetNetworkConfig(NetworkConfig *out);
        Result GetNetworkInfoLatestUpdate(NetworkInfo *out,
                                          NodeLatestUpdate *updates,
                                          size_t update_capacity);

        /* State change event (games AttachStateChangeEvent to this). */
        os::SystemEvent &GetStateChangeEvent();

        /* Enter local network mode for LAN browse (port 30000). MK8DX LAN
         * requires nifm local network mode to init wireless, so this always
         * forces entry regardless of relay locality (see EnterLocalNetworkMode).
         * Takes m_mutex itself: unlike OpenAccessPoint/OpenStation, the bsd
         * MITM caller does not hold it. */
        static Result EnterLocalNetworkModePublic() {
            auto &self = GetInstance();
            std::scoped_lock lk(self.m_mutex);
            return self.EnterLocalNetworkMode(true);
        }

        /* Exit local network mode entered via EnterLocalNetworkModePublic,
         * called when a LAN-only bsd:u session (one that never opens ldn:u,
         * so CloseAccessPoint/CloseStation/Finalize never run) ends. No-op if
         * not currently in local network mode. */
        /* Virtual LDN address of this console, for callers outside ldn.
         * LocalIp() itself is private.
         *
         * Used by tunnel/slp_tunnel.cpp (RefreshLocalIp/Init) to keep the bsd
         * proxy's notion of "our address" consistent with LDN's. NOT
         * currently also reported to games via nifm -- the nifm MITM that
         * would do that (source/nifm/nifm_mitm_service.cpp) is dormant and
         * unregistered; see its header comment for why and whether that
         * still matters. */
        static u32 GetLocalIpPublic() {
            return GetInstance().LocalIp();
        }

        static Result ExitLocalNetworkModePublic() {
            auto &self = GetInstance();
            std::scoped_lock lk(self.m_mutex);
            if (!self.m_local_network_mode) {
                R_SUCCEED();
            }
            return self.ExitLocalNetworkMode();
        }

    private:
        struct Station {
            bool     active;
            bool     connected;
            u32      src_ip;        /* Ryujinx format */
            NodeInfo node;
        };

        LdnControl();
        LdnControl(const LdnControl &) = delete;
        LdnControl &operator=(const LdnControl &) = delete;

        void SetState(CommState state);
        void SignalStateChange();
        u32  LocalIp() const;

        /* WiFi/local network mode (nifm). Enters/leaves local network mode to
         * enable local broadcast + LDN socket creation, mirroring ldn_mitm's
         * lan_discovery::initialize()/finalize(). Assumes m_mutex is already
         * held by the caller (OpenAccessPoint/OpenStation, or the *Public
         * wrappers above which take it themselves for the bsd MITM caller).
         *
         * Both force=true (LAN browse) and force=false (WiFi/LDN, called from
         * OpenAccessPoint/OpenStation) now enter UNCONDITIONALLY, including
         * against a remote relay -- see the implementation's own corrected
         * comment for why (entering does not sever the tunnel; the earlier
         * belief that it did was measured against a broken DNS resolver).
         * `force` no longer changes behavior here -- it only affects a trace
         * log string ("LAN browse" vs not). Kept as a parameter rather than
         * removed since three call sites still pass it and it documents
         * intent even though it's not behaviorally load-bearing anymore. */
        Result EnterLocalNetworkMode(bool force);
        Result ExitLocalNetworkMode();

        /* Frame handlers (run on the run-loop thread). */
        void HandleScan(u32 src_ip);
        void HandleScanResp(u32 src_ip, const u8 *body, size_t len);
        void HandleConnect(u32 src_ip, const u8 *body, size_t len);
        void HandleSyncNetwork(u32 src_ip, const u8 *body, size_t len);

        /* Host helpers. */
        void BuildNetwork(NetworkInfo *out);
        void UpdateNodes();          /* rebuild node list + SyncNetwork to all */

        /* Station/host bookkeeping. */
        void ResetStations();
        int  StationCount() const;
        int  FindFreeNodeId() const;
        int  FindStationByIp(u32 src_ip) const;
        u32  SubnetBroadcast() const;

        /* Node-change diff tracking (GetNetworkInfoLatestUpdate). */
        void InitNodeStateChange();
        void OnNetworkInfoChanged();

        os::SdkMutex    m_mutex;

        CommState       m_state;
        u32             m_disconnect_reason;
        u32             m_ipv4_address;   /* our virtual IP (Ryujinx fmt) */
        u32             m_subnet_mask;

        NetworkInfo     m_network_info;   /* ours (host) or joined (station) */
        NetworkConfig   m_network_config; /* from CreateNetwork/joined net    */
        u8              m_advertise_data[AdvertiseDataSizeMax];
        u16             m_advertise_size;
        u8              m_station_accept_policy;

        u8              m_self_name[UserNameBytesMax + 1];

        /* Host side: stations by assigned node_id 1..7. */
        Station         m_stations[NodeCountMax];

        /* Station side: pending scan filter + results. */
        u64             m_scan_filter_lcid;   /* 0 = no filter */
        NetworkInfo     m_scan_results[MaxScanResults];
        u16             m_scan_result_count;

        /* GetNetworkInfoLatestUpdate diff tracking. */
        bool                    m_prev_node_connected[NodeCountMax];
        NodeLatestUpdate        m_node_changes[NodeCountMax];

        /* NIFM local network mode tracking (WiFi integration). Starts false:
         * true would make Initialize()'s cleanup-on-reinit path try to exit a
         * local network mode that was never entered on the very first boot. */
        bool                    m_local_network_mode = false;
        u32                     m_saved_mtu = 0;
        NifmRequest             m_nifm_request;   /* created on enter, cancelled on exit */

        os::SystemEvent m_state_event{os::EventClearMode_AutoClear, true};
    };

}
