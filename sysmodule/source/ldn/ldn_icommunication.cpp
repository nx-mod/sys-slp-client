#include "ldn_icommunication.hpp"

#include "ldn_control.hpp"
#include "slpcfg/slp_trace.hpp"

#include <cstdint>

extern "C" {
#include <switch/services/nifm.h>
}

namespace ams::slp::ldn {

    LdnICommunicationService::~LdnICommunicationService() {
        /* See the declaration's comment: force the shared LdnControl
         * singleton back to a clean state on session teardown, covering the
         * game-force-closed/crashed case where Finalize()/CloseAccessPoint()/
         * DestroyNetwork() never arrive on their own. Finalize() is
         * unconditionally safe to call regardless of current state (it just
         * exits local network mode if entered, clears stations, and resets
         * to CommState::None) -- so no guard is needed here for the normal
         * case where the game already cleaned up properly; this is a no-op
         * then. */
        AMS_UNUSED(LdnControl::GetInstance().Finalize());
        ::slp::dbg::Trace("ldn: ~LdnICommunicationService (session closed, state force-reset)");
    }

    Result LdnICommunicationService::Initialize(const ams::sf::ClientProcessId &client_process_id) {
        ::slp::dbg::Trace("ldn: Initialize pid=0x%lx",
                          static_cast<unsigned long>(client_process_id.process_id.value));
        return LdnControl::GetInstance().Initialize();
    }

    Result LdnICommunicationService::InitializeSystem2(u64 unk,
        const ams::sf::ClientProcessId &client_process_id) {
        AMS_UNUSED(unk);
        return Initialize(client_process_id);
    }

    Result LdnICommunicationService::Finalize() {
        ::slp::dbg::Trace("ldn: Finalize");
        return LdnControl::GetInstance().Finalize();
    }

    /* ---- host (Access Point) ---- */

    Result LdnICommunicationService::OpenAccessPoint() {
        ::slp::dbg::Trace("ldn: OpenAccessPoint");
        return LdnControl::GetInstance().OpenAccessPoint();
    }

    Result LdnICommunicationService::CloseAccessPoint() {
        ::slp::dbg::Trace("ldn: CloseAccessPoint");
        return LdnControl::GetInstance().CloseAccessPoint();
    }

    Result LdnICommunicationService::CreateNetwork(CreateNetworkConfig data) {
        ::slp::dbg::Trace("ldn: CreateNetwork");
        return LdnControl::GetInstance().CreateNetwork(data);
    }

    Result LdnICommunicationService::DestroyNetwork() {
        ::slp::dbg::Trace("ldn: DestroyNetwork");
        return LdnControl::GetInstance().DestroyNetwork();
    }

    Result LdnICommunicationService::SetAdvertiseData(ams::sf::InAutoSelectBuffer data) {
        return LdnControl::GetInstance().SetAdvertiseData(data.GetPointer(),
                                                          data.GetSize());
    }

    /* ---- station ---- */

    Result LdnICommunicationService::OpenStation() {
        ::slp::dbg::Trace("ldn: OpenStation");
        return LdnControl::GetInstance().OpenStation();
    }

    Result LdnICommunicationService::CloseStation() {
        ::slp::dbg::Trace("ldn: CloseStation");
        return LdnControl::GetInstance().CloseStation();
    }

    Result LdnICommunicationService::Connect(ConnectNetworkData dat,
                                             const NetworkInfo &data) {
        ::slp::dbg::Trace("ldn: Connect");
        return LdnControl::GetInstance().Connect(dat, data);
    }

    Result LdnICommunicationService::Disconnect() {
        ::slp::dbg::Trace("ldn: Disconnect");
        return LdnControl::GetInstance().Disconnect();
    }

    /* ---- queries ---- */

    Result LdnICommunicationService::GetState(ams::sf::Out<u32> state) {
        state.SetValue(static_cast<u32>(LdnControl::GetInstance().GetState()));
        R_SUCCEED();
    }

    Result LdnICommunicationService::GetNetworkInfo(ams::sf::Out<NetworkInfo> buffer) {
        return LdnControl::GetInstance().GetNetworkInfo(buffer.GetPointer());
    }

    Result LdnICommunicationService::GetIpv4Address(ams::sf::Out<u32> address,
                                                    ams::sf::Out<u32> mask) {
        /* Return the VIRTUAL LDN address (10.13.x.x), not the console's real
         * nifm address.
         *
         * Tried returning nifm's real address to match ldn_mitm literally
         * (build 20260817-050000). It made Diablo III WORSE: the "no network
         * connection detected" popup went from appearing after a couple of
         * seconds to appearing instantly, i.e. the game rejected the address
         * outright instead of proceeding.
         *
         * The reason ldn_mitm can return nifm's answer is that in its topology
         * the console's real address IS the 10.13.x.x one (the user assigns it
         * statically). The value it reports is virtual-subnet either way. Our
         * console is on a different real subnet, so "copy ldn_mitm literally"
         * and "report an address consistent with the LDN peers" are NOT the
         * same thing here -- and the game wants the latter, since every peer it
         * will see lives in 10.13.x.x. */
        auto &ldn = LdnControl::GetInstance();
        address.SetValue(ldn.GetIpv4Address());
        mask.SetValue(ldn.GetSubnetMask());
        R_SUCCEED();
    }

    Result LdnICommunicationService::GetDisconnectReason(ams::sf::Out<u32> reason) {
        reason.SetValue(LdnControl::GetInstance().GetDisconnectReason());
        R_SUCCEED();
    }

    Result LdnICommunicationService::GetSecurityParameter(
        ams::sf::Out<SecurityParameter> out) {
        return LdnControl::GetInstance().GetSecurityParameter(out.GetPointer());
    }

    Result LdnICommunicationService::GetNetworkConfig(ams::sf::Out<NetworkConfig> out) {
        return LdnControl::GetInstance().GetNetworkConfig(out.GetPointer());
    }

    Result LdnICommunicationService::AttachStateChangeEvent(
        ams::sf::Out<ams::sf::CopyHandle> handle) {
        handle.SetValue(LdnControl::GetInstance().GetStateChangeEvent().GetReadableHandle(),
                        false);
        R_SUCCEED();
    }

    Result LdnICommunicationService::GetNetworkInfoLatestUpdate(
        ams::sf::Out<NetworkInfo> buffer, ams::sf::OutArray<NodeLatestUpdate> pUpdates) {
        return LdnControl::GetInstance().GetNetworkInfoLatestUpdate(
            buffer.GetPointer(), pUpdates.GetPointer(), pUpdates.GetSize());
    }

    Result LdnICommunicationService::Scan(ams::sf::Out<u32> count,
                                          ams::sf::OutAutoSelectArray<NetworkInfo> buffer,
                                          u16 channel, ScanFilter filter) {
        AMS_UNUSED(channel);
        size_t cap = buffer.GetSize();
        if (cap > UINT16_MAX)
            cap = UINT16_MAX;
        u32 n = 0;
        Result rc = LdnControl::GetInstance().Scan(filter, buffer.GetPointer(),
                                                   (u16)cap, &n);
        count.SetValue(n);
        return rc;
    }

}
