/*
 * sys-slp-client — ICommunicationInterface implementation backed by the
 * LdnControl singleton (M2 LDN control-plane MITM).
 *
 * Every game that opens ldn:u gets one of these objects (created by
 * LdnMitMService::CreateUserLocalCommunicationService). They share the single
 * global LdnControl, mirroring ldn_mitm's single LANDiscovery — only one game
 * drives LDN at a time. The state change event is LdnControl's, so all games
 * observe the same state transitions.
 */
#pragma once

#include <stratosphere.hpp>
#include "ldn_interfaces.hpp"

namespace ams::slp::ldn {

    class LdnICommunicationService {
    public:
        /* If the game force-closes or crashes instead of calling
         * Finalize()/CloseAccessPoint()/DestroyNetwork() itself, this
         * session object is still destroyed when its IPC session dies --
         * but nothing was forcing LdnControl's singleton state back to
         * None, so a hosted network stayed in AccessPointCreated (still
         * answering Scan, still visible on the relay) forever, well past
         * when the game that created it was gone. Confirmed on hardware:
         * closed the game, but the console kept replying to scans and
         * sending keepalives indefinitely. Mirrors BsdMitmService's
         * destructor-cleanup pattern (bsd_mitm_service.cpp), which LDN
         * never got an equivalent of. */
        ~LdnICommunicationService();

        Result Initialize(const ams::sf::ClientProcessId &client_process_id);
        Result InitializeSystem2(u64 unk, const ams::sf::ClientProcessId &client_process_id);
        Result Finalize();

        Result OpenAccessPoint();
        Result CloseAccessPoint();
        Result CreateNetwork(CreateNetworkConfig data);
        Result DestroyNetwork();
        Result SetAdvertiseData(ams::sf::InAutoSelectBuffer data);

        Result OpenStation();
        Result CloseStation();
        Result Connect(ConnectNetworkData dat, const NetworkInfo &data);
        Result Disconnect();

        Result GetState(ams::sf::Out<u32> state);
        Result GetNetworkInfo(ams::sf::Out<NetworkInfo> buffer);
        Result GetIpv4Address(ams::sf::Out<u32> address, ams::sf::Out<u32> mask);
        Result GetDisconnectReason(ams::sf::Out<u32> reason);
        Result GetSecurityParameter(ams::sf::Out<SecurityParameter> out);
        Result GetNetworkConfig(ams::sf::Out<NetworkConfig> out);
        Result AttachStateChangeEvent(ams::sf::Out<ams::sf::CopyHandle> handle);
        Result GetNetworkInfoLatestUpdate(ams::sf::Out<NetworkInfo> buffer,
                                          ams::sf::OutArray<NodeLatestUpdate> pUpdates);
        Result Scan(ams::sf::Out<u32> count,
                    ams::sf::OutAutoSelectArray<NetworkInfo> buffer,
                    u16 channel, ScanFilter filter);
    };

    static_assert(IsICommunicationInterface<LdnICommunicationService>);

}
