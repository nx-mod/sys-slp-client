#include "nifm_mitm_service.hpp"

#include <stratosphere/sf/sf_mitm_dispatch.h>

#include "ldn/ldn_control.hpp"

namespace ams::mitm::nifm {

    namespace {

        /* Virtual subnet presented to the game. Mask matches switch-lan-play's
         * SUBNET_MASK (255.255.0.0) so the game's computed broadcast is
         * 10.13.255.255 -- the same address the relay's ldn_mitm plugin uses as
         * BROADCAST_ADDR. Gateway mirrors its SERVER_IP 10.13.37.1. */
        constexpr u32 VirtualSubnetMask = 0xFFFF0000;   /* 255.255.0.0 */
        constexpr u32 VirtualGateway    = 0x0A0D2501;   /* 10.13.37.1  */

        /* Sourced from LdnControl so LAN and LDN can never disagree about who
         * we are. Stored MSB-first (0x0A0D2502 == 10.13.37.2). */
        u32 GetVirtualIp() {
            return ams::slp::ldn::LdnControl::GetLocalIpPublic();
        }

        /* NifmIpV4Address holds the dotted quad in order: addr[0] is the first
         * octet. Our u32s are MSB-first, so peel from the top. */
        ::NifmIpV4Address ToIpV4(u32 ip) {
            ::NifmIpV4Address out = {};
            out.addr[0] = static_cast<u8>((ip >> 24) & 0xFF);
            out.addr[1] = static_cast<u8>((ip >> 16) & 0xFF);
            out.addr[2] = static_cast<u8>((ip >>  8) & 0xFF);
            out.addr[3] = static_cast<u8>((ip >>  0) & 0xFF);
            return out;
        }

    }

    bool NifmMitmService::ShouldMitm(const ams::sm::MitmProcessInfo &client_info) {
        if (::slp::rt::GetRuntime().GetState() != SLPCFG_STATE_RUNNING)
            return false;

        /* Never ourselves. */
        constexpr u64 OurProgramId = 0x4200000000000011ULL;
        if (client_info.program_id.value == OurProgramId)
            return false;

        /* Applications only -- the system, home menu and background services
         * must keep seeing the console's real address.
         *
         * Was a hand-rolled bound of 0x0100000000000000, which is the start
         * of FIRMWARE SYSMODULES, not applications (see the range breakdown
         * in bsd_mitm_service.cpp's ShouldMitm) -- one tier too loose, so
         * this would have MITM'd firmware sysmodules and system applets
         * (qlaunch, Album) too, the exact false-positive class the
         * application-floor check exists to prevent. Also had no upper
         * bound. ams::ncm::IsApplicationId is the correct, complete check
         * (same fix already applied to BsdMitmService/LdnMitMService). */
        if (!ams::ncm::IsApplicationId(client_info.program_id))
            return false;

        ::slp::dbg::Trace("nifm: MITM application 0x%016lx",
                          static_cast<unsigned long>(client_info.program_id.value));
        return true;
    }

    Result NifmGeneralService::GetCurrentIpAddress(ams::sf::Out<::NifmIpV4Address> out_addr) {
        const u32 ip = GetVirtualIp();
        out_addr.SetValue(ToIpV4(ip));
        ::slp::dbg::Trace("nifm: GetCurrentIpAddress -> %u.%u.%u.%u (virtual)",
                          (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
        R_SUCCEED();
    }

    Result NifmGeneralService::GetCurrentIpConfigInfo(ams::sf::Out<IpConfigInfo> out_info) {
        /* Start from the REAL config so DNS and any flags we don't model stay
         * intact, then overwrite only address/mask/gateway. */
        IpConfigInfo info = {};
        serviceAssumeDomain(m_forward_service.get());
        const Result rc = serviceMitmDispatchOut(m_forward_service.get(), 15, info);
        if (R_FAILED(rc)) {
            ::slp::dbg::Trace("nifm: GetCurrentIpConfigInfo fwd rc=0x%08x (using defaults)",
                              rc.GetValue());
            info = {};
        }

        const u32 ip = GetVirtualIp();
        info.ip_setting.current_addr = ToIpV4(ip);
        info.ip_setting.subnet_mask  = ToIpV4(VirtualSubnetMask);
        info.ip_setting.gateway      = ToIpV4(VirtualGateway);
        out_info.SetValue(info);

        ::slp::dbg::Trace("nifm: GetCurrentIpConfigInfo -> %u.%u.%u.%u/255.255.0.0 gw 10.13.37.1 (virtual)",
                          (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
        R_SUCCEED();
    }

}
