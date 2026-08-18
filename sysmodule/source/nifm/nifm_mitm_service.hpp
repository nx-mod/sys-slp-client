/*
 * sys-slp-client — nifm:u MITM service.
 *
 * WHY THIS EXISTS
 * ---------------
 * MK8DX "LAN mode" is not LDN. It is plain UDP broadcast, and the game decides
 * where to broadcast by asking nifm for its own interface address and subnet
 * mask -- NOT by asking the socket (confirmed empirically: the only bsd:u
 * commands MK8DX issues are Socket/Bind/Close/RegisterClient/SendTo/RecvFrom/
 * Fcntl; there is no Ioctl/SIOCGIFADDR/GetSockName anywhere in the trace).
 *
 * The reference stack we emulate (ldn_mitm + the switch-lan-play PC client)
 * sidesteps this by requiring a STATIC IP inside the virtual subnet --
 * switch-lan-play's config.h pins SUBNET_NET 10.13.0.0 / SUBNET_MASK
 * 255.255.0.0 / SERVER_IP 10.13.37.1 and its README says "set static IP on your
 * Switch". With the console genuinely at 10.13.x.x its broadcast is
 * 10.13.255.255 and every peer is on-subnet, so no game-specific logic is
 * needed anywhere.
 *
 * We cannot do that: the sysmodule needs the real interface to reach the relay,
 * so the console keeps its DHCP address. The game therefore broadcast to
 * 10.172.227.255 while peers answered from 10.13.37.100 -- off-subnet, so the
 * reply was discarded and LAN failed with 2618-0006.
 *
 * So we reproduce the reference's condition by lying to the GAME ONLY.
 * ShouldMitm() gates on the relay running AND the client being an application,
 * so the system, home menu and our own relay socket (nifm:a, admin) keep seeing
 * the real address.
 *
 * IMPLEMENTATION NOTES -- learned the hard way, do not "simplify" these away:
 *
 * 1. nifm sessions are DOMAIN sessions. libnx calls serviceAssumeDomain()
 *    before every single dispatch (see nx/source/services/nifm.c). Forwarding
 *    without it builds a non-domain request against a domain session; that
 *    failed before our handler was even entered, so the game died with NO
 *    trace output at all -- which looked misleadingly like "our code never ran".
 * 2. GetCurrentIpConfigInfo (15) returns ONE struct
 *    { NifmIpAddressSetting; NifmDnsSetting }, NOT five u32 outs.
 * 3. GetCurrentIpAddress (12) returns a 4-byte NifmIpV4Address.
 * 4. Only these two commands are declared. Atmosphere's MITM dispatch
 *    auto-forwards anything it has no handler for (sf_cmif_service_dispatch:
 *    "If we didn't find a handler, forward the request"). A pure-passthrough
 *    build of this MITM was verified stable on hardware before the overrides
 *    were added back, which proved the MITM itself is safe and that earlier
 *    crashes came from wrong command signatures.
 */
#pragma once

#include <stratosphere.hpp>

extern "C" {
#include <switch/services/nifm.h>
}

#include "slpcfg/slp_runtime.hpp"
#include "slpcfg/slp_trace.hpp"

namespace ams::mitm::nifm {

    /* Exactly the out-struct libnx reads back for cmd 15. */
    struct IpConfigInfo {
        ::NifmIpAddressSetting ip_setting;
        ::NifmDnsSetting       dns_setting;
    };

}

/* nifm IGeneralService: 12 GetCurrentIpAddress, 15 GetCurrentIpConfigInfo. */
#define AMS_SLP_NIFM_IGENERAL_INTERFACE(C, H)                                                    \
    AMS_SF_METHOD_INFO(C, H, 12, Result, GetCurrentIpAddress,                                    \
                       (ams::sf::Out<::NifmIpV4Address> out_addr), (out_addr))                   \
    AMS_SF_METHOD_INFO(C, H, 15, Result, GetCurrentIpConfigInfo,                                 \
                       (ams::sf::Out<ams::mitm::nifm::IpConfigInfo> out_info), (out_info))

AMS_SF_DEFINE_MITM_INTERFACE(ams::mitm::nifm, IGeneralService, AMS_SLP_NIFM_IGENERAL_INTERFACE, 0x5350474E)

/* nifm:u IStaticService: 4 CreateGeneralServiceOld (no args),
 * 5 CreateGeneralService (u64 reserved + PID) -- both per libnx nifm.c. */
/* PASSTHROUGH (proven stable on hardware 2026-08-16).
 *
 * Do NOT declare nifm commands 4/5 here. Three attempts at
 * CreateGeneralService(Old) -- with and without an out-object, with two
 * different IN shapes, with and without serviceAssumeDomain -- all crashed
 * the game, and the handler's ENTRY trace NEVER fired even once. Merely
 * declaring those IDs breaks MK8DX, while declaring an unused ID does not,
 * so the game hits them with a request shape we cannot model: it uses
 * Nintendo's nn::nifm, not libnx, so libnx's signatures are not authoritative
 * and we have no way to observe the raw request.
 *
 * The IP virtualisation this was meant to provide is instead done in the bsd
 * proxy, where we control both ends -- see the address translation in
 * proxy_socket_manager. Keeping this MITM as a pure passthrough (it is
 * harmless and already wired up) in case a future signature is ever found. */
#define AMS_SLP_NIFM_ISTATIC_INTERFACE(C, H)                                   \
    AMS_SF_METHOD_INFO(C, H, 65000, Result, SlpUnusedProbe, (), ())

AMS_SF_DEFINE_MITM_INTERFACE(ams::mitm::nifm, IStaticService, AMS_SLP_NIFM_ISTATIC_INTERFACE, 0x5350474F)

namespace ams::mitm::nifm {

    /* Wraps the real IGeneralService; overrides only the address queries. */
    class NifmGeneralService : public ams::sf::MitmServiceImplBase {
    public:
        using MitmServiceImplBase::MitmServiceImplBase;

        Result GetCurrentIpAddress(ams::sf::Out<::NifmIpV4Address> out_addr);
        Result GetCurrentIpConfigInfo(ams::sf::Out<IpConfigInfo> out_info);
    };
    static_assert(IsIGeneralService<NifmGeneralService>);

    class NifmMitmService : public ams::sf::MitmServiceImplBase {
    public:
        using MitmServiceImplBase::MitmServiceImplBase;

        static bool ShouldMitm(const ams::sm::MitmProcessInfo &client_info);

        Result SlpUnusedProbe() { R_SUCCEED(); }
    };
    static_assert(IsIStaticService<NifmMitmService>);

}
