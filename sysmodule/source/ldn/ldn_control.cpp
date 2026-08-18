/*
 * sys-slp-client — LDN control plane over the slp tunnel (implementation).
 *
 * Port of ldn_mitm's LANDiscovery / lan_protocol with the socket transport
 * replaced by our tunnel:
 *   - no real UDP broadcast, no per-station TCP sockets;
 *   - every LAN control frame is a UDP datagram on ControlPort (11452)
 *     carried as an IPv4/UDP packet through the relay (slp::tun::Send);
 *   - inbound control frames arrive from the relay run-loop thread via
 *     OnControlFrame(), dispatched from slp::tun::OnFrame when dport==11452.
 *
 * Wire layout is byte-identical to ldn_mitm's lan_protocol (native packed
 * header, RLE-compressed body), so a room can mix this stack with consoles
 * running ldn_mitm + PC bridge. NOTE: the Python spike (spike/slp_ldn.py)
 * encodes header/body big-endian and therefore does NOT byte-verify against
 * ldn_mitm — it proves the state-machine flow only.
 *
 * Concurrency contract: m_mutex guards all game-facing state. IPC handlers
 * take m_mutex; OnControlFrame takes m_mutex and runs the frame handlers on
 * the run-loop thread. SendFrame() does NOT take m_mutex — it is called from
 * both locked contexts (frame handlers) and unlocked ones (Scan broadcast),
 * and reads m_ipv4_address which is immutable after Initialize().
 */
#include "ldn_control.hpp"

#include "slpcfg/slp_runtime.hpp"
#include "slpcfg/slp_trace.hpp"
#include "tunnel/slp_tunnel.hpp"
#include "bsd/bsd_types.hpp"

#include <cstring>

extern "C" {
#include <switch/services/nifm.h>
}

namespace ams::slp::ldn {

    namespace {

        constexpr u32 LanMagic       = 0x11451400;
        constexpr int ModuleID       = 0xFD;   /* ldn_mitm generic errors     */
        constexpr int LdnModuleId    = 0xCB;   /* ldn_mitm state-machine      */
        constexpr int StationCountMax = NodeCountMax - 1;

        /* ldn_mitm lan_discovery.cpp NodeStateChange */
        constexpr u8 NodeStateChange_None             = 0;
        constexpr u8 NodeStateChange_Connect          = 1;
        constexpr u8 NodeStateChange_Disconnect       = 2;

        /* ldn_mitm lan_discovery.cpp ScanFilterFlag */
        constexpr u32 ScanFilterFlag_LocalCommunicationId = 1u << 0;
        constexpr u32 ScanFilterFlag_SessionId            = 1u << 1;
        constexpr u32 ScanFilterFlag_NetworkType          = 1u << 2;
        constexpr u32 ScanFilterFlag_Ssid                 = 1u << 4;
        constexpr u32 ScanFilterFlag_SceneId              = 1u << 5;

        constexpr char FakeSsid[] = "12345678123456781234567812345678";

        struct __attribute__((packed)) LanPacketHeader {
            u32 magic;              /* LanMagic */
            u8  type;
            u8  compressed;
            u16 length;             /* on-wire body length */
            u16 decompress_length;  /* original body length when compressed */
            u8  _reserved[2];
        };
        static_assert(sizeof(LanPacketHeader) == 12, "LanPacketHeader must be 12 bytes");

        /* ams::Result from raw module/description (this libvapours has no
         * MAKERESULT macro). Values match ldn_mitm's MAKERESULT(module,desc). */
        ams::Result MakeError(int module, int description) {
            return ::ams::result::impl::ResultTraits::MakeValue(module, description);
        }

        /* Every 2203-0032 (bad-state) return, tagged with WHERE it came from.
         *
         * There are a dozen of these guards and they all produced the identical
         * opaque code on screen, so a user reporting "2203-0032" told us
         * nothing about which call was refused. Diablo III's scan-from-
         * Initialized was only found by reading the code; this makes the next
         * one self-identifying. */
        ams::Result BadState(const char *who, int state) {
            ::slp::dbg::Trace("ldn: %s refused -- bad state %d (2203-0032)", who, state);
            return MakeError(LdnModuleId, 32);
        }

        /* "10.13.37.2" -> 0x0A0D2502 (Ryujinx format, dotted quad read BE). */
        u32 ParseIp(const char *s) {
            u32 v = 0;
            int oct = 0, cur = 0;
            for (const char *p = s;; p++) {
                if (*p >= '0' && *p <= '9') {
                    cur = cur * 10 + (*p - '0');
                } else if (*p == '.' || *p == '\0') {
                    if (cur > 255 || oct > 3)
                        return 0;
                    v = (v << 8) | (u8)cur;
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

        /* ldn_mitm getFakeMac: 02:00:<ip bytes as written in memory>. */
        MacAddress FakeMac(u32 ip) {
            MacAddress mac;
            mac.raw[0] = 0x02;
            mac.raw[1] = 0x00;
            std::memcpy(mac.raw + 2, &ip, sizeof(ip));
            return mac;
        }

        /* RLE — exact port of lan_protocol.cpp compress()/decompress().
         * A literal 0x00 is written as (0x00, count) = "zero repeated
         * count+1 times"; every other byte is a literal. */
        int Compress(const u8 *in, size_t in_size, u8 *out, size_t *out_size) {
            const u8 *in_end = in + in_size;
            u8 *out_end = out + *out_size;
            while (out < out_end && in < in_end) {
                u8 c = *in++;
                u8 count = 0;
                if (c == 0) {
                    while (in < in_end && *in == 0 && count < 0xFF) {
                        count += 1;
                        in++;
                    }
                }
                if (c == 0) {
                    *out++ = 0;
                    if (out == out_end)
                        return -1;
                    *out++ = count;
                } else {
                    *out++ = c;
                }
            }
            *out_size = static_cast<size_t>(out - (out_end - *out_size));
            return (in == in_end) ? 0 : -1;
        }

        int Decompress(const u8 *in, size_t in_size, u8 *out, size_t *out_size) {
            const u8 *in_end = in + in_size;
            u8 *out_end = out + *out_size;
            while (in < in_end && out < out_end) {
                u8 c = *in++;
                *out++ = c;
                if (c == 0) {
                    if (in == in_end)
                        return -1;
                    u8 count = *in++;
                    for (int i = 0; i < count; i++) {
                        if (out == out_end)
                            break;
                        *out++ = 0;
                    }
                }
            }
            *out_size = static_cast<size_t>(out - (out_end - *out_size));
            return (in == in_end) ? 0 : -1;
        }

    }

    /* ------------------------------------------------------------------ */

    LdnControl &LdnControl::GetInstance() {
        static LdnControl instance;
        return instance;
    }

    LdnControl::LdnControl()
        : m_state(CommState::None), m_disconnect_reason(0),
          m_ipv4_address(0x0A0D2502), m_subnet_mask(0xFFFF0000),
          m_advertise_size(0), m_station_accept_policy(0),
          m_scan_filter_lcid(0), m_scan_result_count(0)
    {
        std::memset(&m_network_info, 0, sizeof(m_network_info));
        std::memset(&m_network_config, 0, sizeof(m_network_config));
        std::memset(m_self_name, 0, sizeof(m_self_name));
        std::memset(m_advertise_data, 0, sizeof(m_advertise_data));
        std::memset(m_stations, 0, sizeof(m_stations));
        ResetStations();
        InitNodeStateChange();
    }

    Result LdnControl::Initialize() {
        std::scoped_lock lk(m_mutex);

        char ip[16];
        ::slp::rt::Runtime::GetVirtualIp(ip, sizeof(ip));
        m_ipv4_address = ParseIp(ip);
        if (m_ipv4_address == 0)
            m_ipv4_address = 0x0A0D2502;
        m_subnet_mask = 0xFFFF0000;

        m_disconnect_reason = 0;
        m_scan_result_count = 0;
        m_scan_filter_lcid  = 0;
        ResetStations();
        InitNodeStateChange();
        /* If a prior session left local network mode entered without going
         * through CloseAccessPoint/CloseStation (e.g. a game re-initializing
         * ldn:u mid-session), close it out properly instead of just
         * discarding the flag -- otherwise the real nifm state and its
         * NifmRequest handle are abandoned while we now believe we're not in
         * local network mode, and the next Open* call creates an overlapping
         * NifmRequest. ExitLocalNetworkMode() clears m_local_network_mode
         * itself. */
        if (m_local_network_mode) {
            ExitLocalNetworkMode();
        }
        m_state_event.Clear();
        SetState(CommState::Initialized);

        ::slp::dbg::Trace("ldn: Initialize ip=%u.%u.%u.%u",
                          (m_ipv4_address >> 24) & 0xFF, (m_ipv4_address >> 16) & 0xFF,
                          (m_ipv4_address >> 8) & 0xFF, m_ipv4_address & 0xFF);
        R_SUCCEED();
    }

    Result LdnControl::Finalize() {
        std::scoped_lock lk(m_mutex);

        /* Leave local network mode if we entered it (WiFi cleanup). */
        if (m_local_network_mode) {
            ExitLocalNetworkMode();
        }

        m_scan_result_count = 0;
        m_scan_filter_lcid  = 0;
        ResetStations();
        SetState(CommState::None);
        R_SUCCEED();
    }

    Result LdnControl::EnterLocalNetworkMode(bool force) {
        /* Put the Switch WiFi interface into local network mode so broadcast
         * sockets (MK8DX port 30000) and LDN local-wireless work. Mirrors
         * ldn_mitm lan_discovery::initialize(): save MTU, set local network mode,
         * increase MTU to 1500, submit the nifm request, keep MTU elevated for
         * the whole session (restored in ExitLocalNetworkMode).
         *
         * DANGER: actually entering local network mode disconnects the Switch
         * from the internet. Our relay tunnel lives on the real network, so
         * that kills the tunnel (keepalive SEND FAILED) and leaves the system
         * in local mode with no connectivity until reboot — game hang, black
         * screens on other apps, hard hang. This only happens when the relay
         * is REMOTE (e.g. tekn0.net); a relay on the same LAN keeps working
         * because local network mode only cuts internet routing, not the local
         * link. So the decision is automatic per case: enter local network
         * mode iff the connected relay is on a private-range address. */

        /* Re-entrancy guard: OpenAccessPoint()/OpenStation() already check
         * !m_local_network_mode before calling in, but EnterLocalNetworkModePublic()
         * (the bsd MITM LAN-bind path, see ldn_control.hpp) does not, and neither
         * did this function itself. Without this guard, entering while already
         * active re-runs nifmCreateRequest and overwrites m_nifm_request, leaking
         * the first request's 3 handles and creating a genuinely overlapping
         * NifmRequest (see the same concern in Initialize()'s comment) -- this is
         * a plausible cause of the WiFi->LAN mode-switch instability (comm error,
         * then a real crash on next launch, then a black screen needing reboot). */
        if (m_local_network_mode) {
            ::slp::dbg::Trace("ldn: EnterLocalNetworkMode SKIP (already active)");
            R_SUCCEED();
        }

        bool local = ::slp::rt::GetRuntime().RelayOnLocalNetwork();
        u32 relay_ip = ::slp::rt::GetRuntime().GetRelayIpForDebug();
        ::slp::dbg::Trace("EnterLocalNetworkMode: relay_ip=0x%08X (%u.%u.%u.%u) local=%d force=%d",
            relay_ip, (relay_ip>>24)&0xFF, (relay_ip>>16)&0xFF, (relay_ip>>8)&0xFF, relay_ip&0xFF, local, force);
        if (!local) {
            /* Enter it anyway. Games need local-communication mode to see a
             * local network at all -- D3 reports "no network detected" without
             * it, even while successfully HOSTING a room.
             *
             * This block previously skipped entry for remote relays, on the
             * theory that entering it severed the tunnel. That evidence was
             * worthless: at the time, DNS resolution returned the relay address
             * BYTE-REVERSED (tekn0.net -> 136.238.241.192 instead of
             * 192.241.238.136), so we were transmitting to an unrelated host
             * and receiving nothing no matter what mode we were in. With the
             * resolver fixed the tunnel stays up on a remote relay -- ping
             * echoes return in ~100ms and the hosted room appears on tekn0's
             * lobby page.
             *
             * The reference stack enters it unconditionally too. */
            ::slp::dbg::Trace("ldn: entering local network mode (remote relay%s)",
                              force ? ", LAN browse" : "");
        }

        NifmNetworkProfileData profile;
        Result rc = nifmGetCurrentNetworkProfile(&profile);
        if (R_FAILED(rc)) {
            ::slp::dbg::Trace("ldn: nifmGetCurrentNetworkProfile failed: 0x%x", rc.GetValue());
            return rc;
        }

        m_saved_mtu = profile.ip_setting_data.mtu;
        profile.ip_setting_data.mtu = 1500;

        rc = nifmSetNetworkProfile(&profile, &profile.uuid);
        if (R_FAILED(rc)) {
            ::slp::dbg::Trace("ldn: nifmSetNetworkProfile failed: 0x%x", rc.GetValue());
            return rc;
        }

        rc = nifmCreateRequest(&m_nifm_request, true);
        if (R_FAILED(rc)) {
            ::slp::dbg::Trace("ldn: nifmCreateRequest failed: 0x%x", rc.GetValue());
            return rc;
        }

        /* Set local network mode via raw dispatch (nifm: IRequest cmd 11,
         * SetConnectionConfirmationOption). Mirrors nifmSetLocalNetworkMode
         * from ldn_mitm's ipinfo.cpp: option = 2 to enter, 4 to restore. */
        serviceAssumeDomain(&m_nifm_request.s);
        u8 option = 2;
        ::Result nifm_rc = serviceDispatchIn(&m_nifm_request.s, 11, option);
        rc = nifm_rc;
        if (R_FAILED(rc)) {
            ::slp::dbg::Trace("ldn: nifmSetLocalNetworkMode failed: 0x%x", rc.GetValue());
            nifmRequestCancel(&m_nifm_request);
            return rc;
        }

        rc = nifmRequestSubmitAndWait(&m_nifm_request);
        if (R_FAILED(rc)) {
            ::slp::dbg::Trace("ldn: nifmRequestSubmitAndWait failed: 0x%x", rc.GetValue());
            nifmRequestCancel(&m_nifm_request);
            return rc;
        }

        /* Keep MTU at 1500 for the session (like ldn_mitm); restored in
         * ExitLocalNetworkMode. */
        m_local_network_mode = true;
        ::slp::dbg::Trace("ldn: local network mode enabled (MTU saved=%u)", m_saved_mtu);

        /* Direct measurement, not inference: does "local network mode" ACTUALLY
         * tear down the Wi-Fi radio's association with the AP, or just flip a
         * state flag games query?
         *
         * The relay tunnel and sys-ftpd (a separate sysmodule, separate socket)
         * both kept working after this call tonight, which argues against a
         * real radio-level disassociation -- if the AP link genuinely dropped,
         * EVERYTHING on that interface would go dark, not just what queries
         * nifm's local-mode flag. Query the actual connectivity APIs here
         * instead of continuing to infer this from socket side-effects. */
        bool wireless_enabled = false;
        NifmInternetConnectionType conn_type = static_cast<NifmInternetConnectionType>(0);
        u32 wifi_strength = 0;
        NifmInternetConnectionStatus conn_status = static_cast<NifmInternetConnectionStatus>(0);
        const Result wrc = nifmIsWirelessCommunicationEnabled(&wireless_enabled);
        const Result crc = nifmGetInternetConnectionStatus(&conn_type, &wifi_strength, &conn_status);
        ::slp::dbg::Trace("ldn: post-entry connectivity: wireless_enabled=%d (rc=0x%x) "
                          "conn_type=%d strength=%u status=%d (rc=0x%x)",
                          wireless_enabled, wrc.GetValue(),
                          static_cast<int>(conn_type), wifi_strength,
                          static_cast<int>(conn_status), crc.GetValue());

        R_SUCCEED();
    }

    Result LdnControl::ExitLocalNetworkMode() {
        /* Mirror ldn_mitm lan_discovery::finalize(): cancel the request created
         * at enter (which exits local network mode) and restore the original
         * MTU. */
        Result rc = nifmRequestCancel(&m_nifm_request);
        if (R_FAILED(rc)) {
            ::slp::dbg::Trace("ldn: ExitLocalNetworkMode nifmRequestCancel failed: 0x%x", rc.GetValue());
        }

        /* nifmRequestCancel only cancels the pending request -- it does not
         * release the NifmRequest's Horizon handles (session + 2 events).
         * Without this, every EnterLocalNetworkMode() call leaks 3 handles
         * for the life of the process. */
        nifmRequestClose(&m_nifm_request);

        NifmNetworkProfileData profile;
        rc = nifmGetCurrentNetworkProfile(&profile);
        if (R_SUCCEEDED(rc)) {
            profile.ip_setting_data.mtu = m_saved_mtu;
            rc = nifmSetNetworkProfile(&profile, &profile.uuid);
            if (R_FAILED(rc)) {
                ::slp::dbg::Trace("ldn: ExitLocalNetworkMode nifmSetNetworkProfile failed: 0x%x", rc.GetValue());
            }
        } else {
            ::slp::dbg::Trace("ldn: ExitLocalNetworkMode nifmGetCurrentNetworkProfile failed: 0x%x", rc.GetValue());
        }

        m_local_network_mode = false;
        ::slp::dbg::Trace("ldn: local network mode disabled");
        R_SUCCEED();
    }

    void LdnControl::SetState(CommState state) {
        if (m_state != state) {
            m_state = state;
            SignalStateChange();
        }
    }

    void LdnControl::SignalStateChange() {
        m_state_event.Signal();
    }

    u32 LdnControl::LocalIp() const {
        return m_ipv4_address;
    }

    os::SystemEvent &LdnControl::GetStateChangeEvent() {
        return m_state_event;
    }

    /* ---- transport ---- */

    void LdnControl::SendFrame(u32 dst_ip, LanPacketType type,
                               const u8 *body, size_t body_len) {
        if (::slp::rt::GetRuntime().GetState() != SLPCFG_STATE_RUNNING)
            return;

        alignas(LanPacketHeader)
        static thread_local u8 buffer[sizeof(LanPacketHeader) + sizeof(NetworkInfo)];
        LanPacketHeader *hdr = reinterpret_cast<LanPacketHeader *>(buffer);
        std::memset(hdr, 0, sizeof(*hdr));
        hdr->magic = LanMagic;
        hdr->type  = static_cast<u8>(type);

        size_t total = sizeof(LanPacketHeader);
        if (body != nullptr && body_len > 0) {
            static thread_local u8 compressed[sizeof(NetworkInfo)];
            size_t out_size = sizeof(compressed);
            if (Compress(body, body_len, compressed, &out_size) == 0) {
                hdr->compressed        = 1;
                hdr->decompress_length = static_cast<u16>(body_len);
                hdr->length            = static_cast<u16>(out_size);
                std::memcpy(buffer + total, compressed, out_size);
                total += out_size;
            } else {
                hdr->length = static_cast<u16>(body_len);
                std::memcpy(buffer + total, body, body_len);
                total += body_len;
            }
        }

        if (!::slp::tun::Send(m_ipv4_address, ControlPort, dst_ip, ControlPort,
                            ryu_ldn::bsd::ProtocolType::Udp, buffer, total)) {
            ::slp::dbg::Trace("ldn: SendFrame(type=%d) FAILED", (int)type);
        } else {
            ::slp::dbg::Trace("ldn: SendFrame(type=%d dst=0x%08x len=%zu ok)",
                              (int)type, dst_ip, total);
        }
    }

    void LdnControl::OnControlFrame(u32 src_ip, const u8 *payload, size_t len) {
        std::scoped_lock lk(m_mutex);

        if (payload == nullptr || len < sizeof(LanPacketHeader))
            return;

        LanPacketHeader hdr;
        std::memcpy(&hdr, payload, sizeof(hdr));
        if (hdr.magic != LanMagic) {
            ::slp::dbg::Trace("ldn: OnControlFrame BAD_MAGIC src=0x%08x len=%zu",
                              src_ip, len);
            return;
        }
        if (len < sizeof(LanPacketHeader) + hdr.length) {
            ::slp::dbg::Trace("ldn: OnControlFrame SHORT type=%d len=%zu hdr_len=%u",
                              (int)hdr.type, len, (unsigned)hdr.length);
            return;
        }

        const u8 *body     = payload + sizeof(LanPacketHeader);
        size_t    body_len = hdr.length;
        static thread_local u8 decompressed[sizeof(NetworkInfo)];
        if (hdr.compressed) {
            size_t out_size = sizeof(decompressed);
            if (Decompress(body, body_len, decompressed, &out_size) != 0) {
                ::slp::dbg::Trace("ldn: OnControlFrame DECOMPRESS_FAIL type=%d len=%zu",
                                  (int)hdr.type, len);
                return;
            }
            if (out_size != hdr.decompress_length) {
                ::slp::dbg::Trace("ldn: OnControlFrame BAD_DECOMPRESS_LEN type=%d out=%zu want=%u",
                                  (int)hdr.type, out_size, (unsigned)hdr.decompress_length);
                return;
            }
            body     = decompressed;
            body_len = out_size;
        }

        ::slp::dbg::Trace("ldn: OnControlFrame src=0x%08x type=%d len=%zu%s",
                          src_ip, (int)hdr.type, len,
                          hdr.compressed ? " (compressed)" : "");

        switch (static_cast<LanPacketType>(hdr.type)) {
            case LanPacket_Scan:
                HandleScan(src_ip);
                break;
            case LanPacket_ScanResp:
                HandleScanResp(src_ip, body, body_len);
                break;
            case LanPacket_Connect:
                HandleConnect(src_ip, body, body_len);
                break;
            case LanPacket_SyncNetwork:
                HandleSyncNetwork(src_ip, body, body_len);
                break;
            default:
                break;
        }
    }

    /* ---- frame handlers (m_mutex held, run-loop thread) ---- */

    void LdnControl::HandleScan(u32 src_ip) {
        ::slp::dbg::Trace("ldn: HandleScan src=0x%08x state=%d", src_ip, (int)m_state);
        if (m_state != CommState::AccessPointCreated)
            return;

        static thread_local NetworkInfo info;
        BuildNetwork(&info);
        SendFrame(src_ip, LanPacket_ScanResp, reinterpret_cast<const u8 *>(&info),
                  sizeof(info));
    }

    void LdnControl::HandleScanResp(u32 src_ip, const u8 *body, size_t len) {
        if (len != sizeof(NetworkInfo)) {
            ::slp::dbg::Trace("ldn: HandleScanResp src=0x%08x BAD_LEN %zu", src_ip, len);
            return;
        }

        static thread_local NetworkInfo info;
        std::memcpy(&info, body, sizeof(info));

        /* Drop responses that don't match the in-flight scan (mirror of the
         * spike's stale-AP guard; the full ScanFilter runs at collect time). */
        if (m_scan_filter_lcid != 0 &&
            info.networkId.intentId.localCommunicationId != m_scan_filter_lcid) {
            ::slp::dbg::Trace("ldn: HandleScanResp src=0x%08x DROP lcid 0x%llx != filter 0x%llx",
                              src_ip,
                              (unsigned long long)info.networkId.intentId.localCommunicationId,
                              (unsigned long long)m_scan_filter_lcid);
            return;
        }

        for (u16 i = 0; i < m_scan_result_count; i++) {
            if (std::memcmp(m_scan_results[i].common.bssid.raw,
                            info.common.bssid.raw, 6) == 0) {
                m_scan_results[i] = info;
                return;
            }
        }
        if (m_scan_result_count < MaxScanResults) {
            m_scan_results[m_scan_result_count++] = info;
        }
        ::slp::dbg::Trace("ldn: HandleScanResp collected, count=%d", m_scan_result_count);
    }

    void LdnControl::HandleConnect(u32 src_ip, const u8 *body, size_t len) {
        if (m_state != CommState::AccessPointCreated)
            return;
        if (len != sizeof(NodeInfo))
            return;

        NodeInfo node;
        std::memcpy(&node, body, sizeof(node));

        if (StationCount() >= StationCountMax)
            return;
        int nid = FindFreeNodeId();
        if (nid < 0)
            return;

        Station &s = m_stations[nid - 1];
        s.active    = true;
        s.connected = true;
        s.src_ip    = src_ip;
        s.node      = node;
        /* The station's advertised node IP must equal the tunnel src IP we
         * will route SyncNetwork/data frames to (PIA games match
         * GetIpv4Address() against NetworkInfo.ldn.nodes[].ipv4Address). */
        s.node.ipv4Address = src_ip;
        s.node.macAddress  = FakeMac(src_ip);
        s.node.nodeId      = nid;
        s.node.isConnected = 1;

        ::slp::dbg::Trace("ldn: station %d connected ip=%u.%u.%u.%u", nid,
                          (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                          (src_ip >> 8) & 0xFF, src_ip & 0xFF);
        UpdateNodes();
    }

    void LdnControl::HandleSyncNetwork(u32 src_ip, const u8 *body, size_t len) {
        AMS_UNUSED(src_ip);
        if (len != sizeof(NetworkInfo))
            return;
        if (m_state != CommState::Station && m_state != CommState::StationConnected)
            return;

        std::memcpy(&m_network_info, body, sizeof(m_network_info));
        if (m_state == CommState::Station) {
            SetState(CommState::StationConnected);
        }
        OnNetworkInfoChanged();
    }

    /* ---- host side ---- */

    Result LdnControl::OpenAccessPoint() {
        std::scoped_lock lk(m_mutex);
        m_disconnect_reason = 0;
        if (m_state == CommState::None)
            return BadState(__func__, (int)m_state);

        /* Enter local network mode so WiFi broadcast/LDN sockets work, unless
         * the relay is remote (see EnterLocalNetworkMode) -- entering would
         * sever this console's only path to it. */
        if (!m_local_network_mode) {
            Result rc = EnterLocalNetworkMode(false);
            if (R_FAILED(rc)) {
                ::slp::dbg::Trace("ldn: OpenAccessPoint: local network mode failed: 0x%x", rc.GetValue());
            }
        }

        ResetStations();
        SetState(CommState::AccessPoint);
        R_SUCCEED();
    }

    Result LdnControl::CloseAccessPoint() {
        std::scoped_lock lk(m_mutex);
        if (m_state == CommState::None)
            return BadState(__func__, (int)m_state);

        /* Exit local network mode when leaving AP. */
        if (m_local_network_mode) {
            Result rc = ExitLocalNetworkMode();
            if (R_FAILED(rc)) {
                ::slp::dbg::Trace("ldn: CloseAccessPoint: ExitLocalNetworkMode failed: 0x%x", rc.GetValue());
            }
        }

        ResetStations();
        SetState(CommState::Initialized);
        R_SUCCEED();
    }

    Result LdnControl::CreateNetwork(const CreateNetworkConfig &data) {
        std::scoped_lock lk(m_mutex);
        if (m_state != CommState::AccessPoint)
            return BadState(__func__, (int)m_state);

        m_network_config = data.networkConfig;
        /* No accept-policy field in CreateNetworkConfig — default AcceptAll. */
        m_station_accept_policy = 0;

        std::memset(&m_network_info, 0, sizeof(m_network_info));
        m_network_info.common.bssid          = FakeMac(m_ipv4_address);
        m_network_info.common.ssid.length    = sizeof(FakeSsid) - 1;
        std::memcpy(m_network_info.common.ssid.raw, FakeSsid, sizeof(FakeSsid));
        m_network_info.common.channel        = data.networkConfig.channel ? data.networkConfig.channel : 6;
        m_network_info.common.linkLevel      = 3;
        m_network_info.common.networkType    = 2;
        m_network_info.networkId.intentId    = data.networkConfig.intentId;
        m_network_info.ldn.securityMode      = data.securityConfig.securityMode;
        m_network_info.ldn.stationAcceptPolicy = m_station_accept_policy;
        m_network_info.ldn.nodeCountMax      = data.networkConfig.nodeCountMax;
        ams::os::GenerateRandomBytes(&m_network_info.networkId.sessionId,
                                     sizeof(m_network_info.networkId.sessionId));
        ams::os::GenerateRandomBytes(m_network_info.ldn.unkRandom, 16);

        std::strncpy(reinterpret_cast<char *>(m_self_name),
                     data.userConfig.userName, UserNameBytesMax);
        m_self_name[UserNameBytesMax] = '\0';
        m_advertise_size = 0;
        std::memset(m_advertise_data, 0, sizeof(m_advertise_data));

        ResetStations();
        InitNodeStateChange();
        SetState(CommState::AccessPointCreated);
        UpdateNodes();
        R_SUCCEED();
    }

    Result LdnControl::DestroyNetwork() {
        std::scoped_lock lk(m_mutex);
        ResetStations();
        SetState(CommState::AccessPoint);
        R_SUCCEED();
    }

    Result LdnControl::SetAdvertiseData(const u8 *data, size_t size) {
        std::scoped_lock lk(m_mutex);
        if (size > AdvertiseDataSizeMax)
            return MakeError(ModuleID, 10);
        if (size > 0 && data != nullptr) {
            std::memcpy(m_advertise_data, data, size);
        }
        m_advertise_size = static_cast<u16>(size);
        m_network_info.ldn.advertiseDataSize = m_advertise_size;
        UpdateNodes();
        R_SUCCEED();
    }

    Result LdnControl::SetStationAcceptPolicy(u8 policy) {
        std::scoped_lock lk(m_mutex);
        m_station_accept_policy = policy;
        m_network_info.ldn.stationAcceptPolicy = policy;
        R_SUCCEED();
    }

    Result LdnControl::Reject(u32 node_id) {
        std::scoped_lock lk(m_mutex);
        if (node_id < 1 || node_id >= (u32)NodeCountMax)
            R_SUCCEED();
        Station &s = m_stations[node_id - 1];
        s.active    = false;
        s.connected = false;
        UpdateNodes();
        R_SUCCEED();
    }

    void LdnControl::BuildNetwork(NetworkInfo *out) {
        std::memcpy(out, &m_network_info, sizeof(m_network_info));
        std::memset(out->ldn.nodes, 0, sizeof(out->ldn.nodes));

        /* node0 = this console (host). */
        NodeInfo &n0 = out->ldn.nodes[0];
        n0.ipv4Address = m_ipv4_address;
        n0.macAddress  = FakeMac(m_ipv4_address);
        n0.nodeId      = 0;
        n0.isConnected = 1;
        std::strncpy(n0.userName, reinterpret_cast<const char *>(m_self_name),
                     UserNameBytesMax);
        n0.userName[UserNameBytesMax] = '\0';
        n0.localCommunicationVersion  = m_network_config.localCommunicationVersion;

        u8 count = 1;
        for (int nid = 1; nid < NodeCountMax; nid++) {
            const Station &s = m_stations[nid - 1];
            if (s.active && s.connected) {
                NodeInfo &n = out->ldn.nodes[count];
                n            = s.node;
                n.nodeId      = nid;
                n.isConnected = 1;
                count++;
            }
        }
        out->ldn.nodeCount = count;
        out->ldn.advertiseDataSize = m_advertise_size;
        if (m_advertise_size > 0) {
            std::memcpy(out->ldn.advertiseData, m_advertise_data, m_advertise_size);
        } else {
            std::memset(out->ldn.advertiseData, 0, sizeof(out->ldn.advertiseData));
        }
    }

    void LdnControl::UpdateNodes() {
        BuildNetwork(&m_network_info);

        for (int nid = 1; nid < NodeCountMax; nid++) {
            const Station &s = m_stations[nid - 1];
            if (s.active && s.connected) {
                SendFrame(s.src_ip, LanPacket_SyncNetwork,
                          reinterpret_cast<const u8 *>(&m_network_info),
                          sizeof(m_network_info));
            }
        }
        OnNetworkInfoChanged();
    }

    void LdnControl::ResetStations() {
        for (int nid = 1; nid < NodeCountMax; nid++) {
            Station &s = m_stations[nid - 1];
            s.active    = false;
            s.connected = false;
            std::memset(&s.node, 0, sizeof(s.node));
        }
    }

    int LdnControl::StationCount() const {
        int count = 0;
        for (int nid = 1; nid < NodeCountMax; nid++) {
            if (m_stations[nid - 1].active && m_stations[nid - 1].connected)
                count++;
        }
        return count;
    }

    int LdnControl::FindFreeNodeId() const {
        for (int nid = 1; nid < NodeCountMax; nid++) {
            if (!m_stations[nid - 1].active)
                return nid;
        }
        return -1;
    }

    u32 LdnControl::SubnetBroadcast() const {
        return m_ipv4_address | ~m_subnet_mask;
    }

    void LdnControl::InitNodeStateChange() {
        std::memset(m_node_changes, 0, sizeof(m_node_changes));
        std::memset(m_prev_node_connected, 0, sizeof(m_prev_node_connected));
    }

    void LdnControl::OnNetworkInfoChanged() {
        bool changed = false;
        for (int i = 0; i < NodeCountMax; i++) {
            u8 connected = m_network_info.ldn.nodes[i].isConnected ? 1u : 0u;
            if (connected != m_prev_node_connected[i]) {
                if (connected) {
                    m_node_changes[i].stateChange |= NodeStateChange_Connect;
                } else {
                    m_node_changes[i].stateChange |= NodeStateChange_Disconnect;
                }
                m_prev_node_connected[i] = connected;
                changed = true;
            }
        }
        if (changed) {
            SignalStateChange();
        }
    }

    /* ---- station side ---- */

    Result LdnControl::OpenStation() {
        std::scoped_lock lk(m_mutex);
        m_disconnect_reason = 0;
        if (m_state == CommState::None)
            return BadState(__func__, (int)m_state);

        /* Enter local network mode so we can create LDN sockets, unless the
         * relay is remote (see EnterLocalNetworkMode). */
        if (!m_local_network_mode) {
            Result rc = EnterLocalNetworkMode(false);
            if (R_FAILED(rc)) {
                ::slp::dbg::Trace("ldn: OpenStation: local network mode failed: 0x%x", rc.GetValue());
            }
        }

        ResetStations();
        SetState(CommState::Station);
        R_SUCCEED();
    }

    Result LdnControl::CloseStation() {
        std::scoped_lock lk(m_mutex);
        if (m_state == CommState::None)
            return BadState(__func__, (int)m_state);

        /* Exit local network mode when leaving station mode. */
        if (m_local_network_mode) {
            Result rc = ExitLocalNetworkMode();
            if (R_FAILED(rc)) {
                ::slp::dbg::Trace("ldn: CloseStation: ExitLocalNetworkMode failed: 0x%x", rc.GetValue());
            }
        }

        ResetStations();
        SetState(CommState::Initialized);
        R_SUCCEED();
    }

    Result LdnControl::Scan(const ScanFilter &filter, NetworkInfo *out,
                            u16 out_capacity, u32 *out_count) {
        {
            std::scoped_lock lk(m_mutex);
            /* Scanning is legal from Initialized too, not just Station.
             *
             * This guard required Station/StationConnected and returned
             * 2203-0032 otherwise. MK8DX happens to call OpenStation before
             * scanning so it slipped through, but Diablo III scans straight
             * from Initialized -- its trace shows no OpenStation anywhere --
             * so every "search for games" was answered with 2203-0032 and the
             * user saw "no network detected" followed by an error. Rejecting a
             * scan is also the wrong shape of failure: "no networks" is an
             * empty result, not an error.
             *
             * Still rejected from None (not initialized) and from the
             * AccessPoint states, where the console is hosting rather than
             * looking. */
            /* UPDATE: Initialized was still not enough. The trace showed
             *   ldn: Scan rejected, state=3     (AccessPointCreated)
             * because Diablo III creates its game FIRST and then scans for
             * nearby players WHILE HOSTING. A host looking for other games is
             * normal, so allow a scan from any initialized state; only None
             * (never initialized) and Error are genuinely invalid. */
            if (m_state == CommState::None || m_state == CommState::Error) {
                return BadState(__func__, (int)m_state);
            }

            m_scan_result_count = 0;
            m_scan_filter_lcid  = 0;
            if (filter.flag & ScanFilterFlag_LocalCommunicationId) {
                m_scan_filter_lcid = filter.networkId.intentId.localCommunicationId;
            }
        }

        SendFrame(SubnetBroadcast(), LanPacket_Scan, nullptr, 0);
        ::slp::dbg::Trace("ldn: Scan broadcast to 0x%08x filter_lcid=0x%llx",
                          SubnetBroadcast(),
                          (unsigned long long)m_scan_filter_lcid);

        /* ldn_mitm sleeps 1s after broadcasting the Scan and then reads the
         * results the recv thread collected; we do the same (the run-loop
         * thread fills m_scan_results via HandleScanResp in that window). */
        ams::os::SleepThread(ams::TimeSpan::FromSeconds(1));

        std::scoped_lock lk(m_mutex);
        u32 count = 0;
        for (u16 i = 0; i < m_scan_result_count && count < out_capacity; i++) {
            const NetworkInfo &info = m_scan_results[i];

            bool copy = true;
            if (filter.flag & ScanFilterFlag_LocalCommunicationId) {
                copy &= filter.networkId.intentId.localCommunicationId ==
                        info.networkId.intentId.localCommunicationId;
            }
            if (filter.flag & ScanFilterFlag_SessionId) {
                copy &= std::memcmp(&filter.networkId.sessionId,
                                    &info.networkId.sessionId,
                                    sizeof(SessionId)) == 0;
            }
            if (filter.flag & ScanFilterFlag_NetworkType) {
                copy &= filter.networkType == (u32)info.common.networkType;
            }
            if (filter.flag & ScanFilterFlag_Ssid) {
                copy &= filter.ssid.length == info.common.ssid.length &&
                        std::memcmp(filter.ssid.raw, info.common.ssid.raw,
                                    filter.ssid.length) == 0;
            }
            if (filter.flag & ScanFilterFlag_SceneId) {
                copy &= filter.networkId.intentId.sceneId ==
                        info.networkId.intentId.sceneId;
            }

            if (copy) {
                out[count++] = info;
            }
        }
        *out_count = count;
        ::slp::dbg::Trace("ldn: Scan done results=%u returned=%u", m_scan_result_count, count);
        R_SUCCEED();
    }

    Result LdnControl::Connect(const ConnectNetworkData &dat,
                               const NetworkInfo &data) {
        u32 host_ip;
        {
            std::scoped_lock lk(m_mutex);
            if (m_state == CommState::None)
                return BadState(__func__, (int)m_state);
            if (data.ldn.nodeCount == 0)
                return MakeError(ModuleID, 30);

            host_ip = data.ldn.nodes[0].ipv4Address;
            m_scan_result_count = 0;
            m_scan_filter_lcid  = 0;
        }

        NodeInfo my;
        std::memset(&my, 0, sizeof(my));
        my.ipv4Address = m_ipv4_address;
        my.macAddress  = FakeMac(m_ipv4_address);
        my.nodeId      = 0;
        my.isConnected = 1;
        std::strncpy(my.userName, dat.userConfig.userName, UserNameBytesMax);
        my.userName[UserNameBytesMax] = '\0';
        my.localCommunicationVersion  = static_cast<u16>(dat.localCommunicationVersion);

        ::slp::dbg::Trace("ldn: connect host=%u.%u.%u.%u",
                          (host_ip >> 24) & 0xFF, (host_ip >> 16) & 0xFF,
                          (host_ip >> 8) & 0xFF, host_ip & 0xFF);
        SendFrame(host_ip, LanPacket_Connect, reinterpret_cast<const u8 *>(&my),
                  sizeof(my));

        /* ldn_mitm waits 1s for the host's SyncNetwork (which flips state to
         * StationConnected on the run-loop thread) and returns success; games
         * poll GetState(). */
        ams::os::SleepThread(ams::TimeSpan::FromSeconds(1));
        R_SUCCEED();
    }

    Result LdnControl::Disconnect() {
        std::scoped_lock lk(m_mutex);
        ResetStations();
        SetState(CommState::Station);
        R_SUCCEED();
    }

    /* ---- queries ---- */

    CommState LdnControl::GetState() {
        std::scoped_lock lk(m_mutex);
        return m_state;
    }

    Result LdnControl::GetNetworkInfo(NetworkInfo *out) {
        std::scoped_lock lk(m_mutex);
        if (m_state != CommState::AccessPointCreated &&
            m_state != CommState::StationConnected) {
            return BadState(__func__, (int)m_state);
        }
        std::memcpy(out, &m_network_info, sizeof(*out));
        R_SUCCEED();
    }

    Result LdnControl::GetNetworkInfoLatestUpdate(NetworkInfo *out,
                                                  NodeLatestUpdate *updates,
                                                  size_t update_capacity) {
        std::scoped_lock lk(m_mutex);
        if (update_capacity > NodeCountMax)
            return MakeError(ModuleID, 50);
        if (m_state != CommState::AccessPointCreated &&
            m_state != CommState::StationConnected) {
            return BadState(__func__, (int)m_state);
        }
        std::memcpy(out, &m_network_info, sizeof(*out));
        for (size_t i = 0; i < update_capacity; i++) {
            updates[i].stateChange = m_node_changes[i].stateChange;
            m_node_changes[i].stateChange = NodeStateChange_None;
        }
        R_SUCCEED();
    }

    u32 LdnControl::GetIpv4Address() {
        std::scoped_lock lk(m_mutex);
        return m_ipv4_address;
    }

    u32 LdnControl::GetSubnetMask() {
        std::scoped_lock lk(m_mutex);
        return m_subnet_mask;
    }

    u32 LdnControl::GetDisconnectReason() {
        std::scoped_lock lk(m_mutex);
        return m_disconnect_reason;
    }

    Result LdnControl::GetSecurityParameter(SecurityParameter *out) {
        std::scoped_lock lk(m_mutex);
        if (m_state != CommState::AccessPointCreated &&
            m_state != CommState::StationConnected) {
            return BadState(__func__, (int)m_state);
        }
        out->sessionId = m_network_info.networkId.sessionId;
        std::memcpy(out->unkRandom, m_network_info.ldn.unkRandom, 16);
        R_SUCCEED();
    }

    Result LdnControl::GetNetworkConfig(NetworkConfig *out) {
        std::scoped_lock lk(m_mutex);
        if (m_state != CommState::AccessPointCreated &&
            m_state != CommState::StationConnected) {
            return BadState(__func__, (int)m_state);
        }
        out->intentId                  = m_network_info.networkId.intentId;
        out->channel                   = m_network_info.common.channel;
        out->nodeCountMax              = m_network_info.ldn.nodeCountMax;
        out->localCommunicationVersion = m_network_info.ldn.nodes[0].localCommunicationVersion;
        R_SUCCEED();
    }

}
