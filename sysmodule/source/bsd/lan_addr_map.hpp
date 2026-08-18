/*
 * sys-slp-client — LAN-mode address translation. CURRENTLY DISABLED
 * (TranslationEnabled = false in lan_addr_map.cpp) and LAN works without it.
 *
 * THE ORIGINAL THEORY (since REJECTED -- kept for context, do not treat as
 * current fact)
 * -----------------------------------------------------------------------
 * MK8DX "LAN mode" is plain UDP broadcast. The game reads its own address from
 * the interface (nifm), NOT from the socket, so it broadcasts to its REAL
 * subnet broadcast (e.g. 10.172.227.255). Our relay peers live on the virtual
 * subnet (10.13.37.x), so the browse reply arrives stamped 10.13.37.100 --
 * off-subnet from the game's point of view. The theory was that MK8DX
 * discarded it for exactly that reason, causing 2618-0006.
 *
 * WHAT ACTUALLY CAUSED 2618-0006 (found 2026-08-17, after this file was
 * written): `BsdMitmService::Send()`/`SendTo()` reported the bsd:u
 * `{ret, errno}` reply in swapped slots, so every successful LAN send looked
 * like "0 bytes sent" to the game -- it gave up before reply content could
 * ever matter, even with zero peers involved. The off-subnet theory was never
 * actually confirmed; see lan_addr_map.cpp's own "Considered 2026-08-17
 * (rejected)" section for the intermediate reasoning (it correctly suspected
 * the removed nifm MITM crash, one step short of the real answer). With
 * translation OFF and the real bug fixed, the browse reply -- still arriving
 * off-subnet, untranslated -- is accepted fine: the LAN lobby lists and the
 * game proceeds to a real Pia join. Off-subnet was never the blocker.
 *
 * The reference stack (ldn_mitm + switch-lan-play PC client) avoids the
 * off-subnet SHAPE entirely by requiring a STATIC console IP inside
 * 10.13.0.0/16, so game and peers share one subnet -- we cannot do that (the
 * sysmodule needs the real interface to reach the relay), which is why this
 * translation layer was built as a workaround for a problem that, it turns
 * out, didn't need one.
 *
 * THE MECHANISM (present but inert while TranslationEnabled = false)
 * --------------------------------------------------------------------------
 * If ever re-enabled: present virtual peers to the game as addresses inside
 * the console's OWN subnet, and map back on send.
 *
 *     virtual 10.13.37.H   <->  game <real-net>.H
 *     virtual 10.13.255.255 <-> game <real-broadcast>
 *
 * SCOPE -- important: this applies ONLY to LAN-mode ports. LDN/WiFi genuinely
 * uses 10.13.37.x addresses that the game learned from the NetworkInfo we
 * synthesise, and translating those would break WiFi, which currently works.
 *
 * All addresses here are "Ryujinx format": a u32 whose MSB is the first octet
 * (10.13.37.2 == 0x0A0D2502), matching what the tunnel and NodeInfo use.
 */
#pragma once

#include <stratosphere.hpp>

namespace slp::netmap {

    /* Virtual subnet used by the relay + peers (switch-lan-play's SUBNET_NET). */
    constexpr u32 VirtualNet     = 0x0A0D0000;   /* 10.13.0.0    */
    constexpr u32 VirtualMask    = 0xFFFF0000;   /* 255.255.0.0  */
    /* Peers are handed out on 10.13.37.x by the relay/ldn convention. */
    constexpr u32 VirtualPeerNet = 0x0A0D2500;   /* 10.13.37.0   */
    constexpr u32 VirtualBcast   = 0x0A0DFFFF;   /* 10.13.255.255 */

    /* Set once we learn the console's real address (nifm, admin). 0 = unknown,
     * in which case every translation is an identity no-op and behaviour is
     * exactly as before. */
    void SetRealAddress(u32 addr, u32 mask);
    bool HasRealAddress();

    /* Compile-time master switch (see lan_addr_map.cpp). When false, callers
     * must not do ANY work on translation's behalf -- notably they must not
     * query nifm for the console's address, since that result is unused and
     * nifm has already proven fragile in MK8DX's LAN path. */
    bool IsTranslationEnabled();

    /* True for the UDP ports MK8DX uses in LAN mode (browse 30000, session
     * 49152-49155, aux 40000). LDN control (12345) is deliberately excluded. */
    constexpr bool IsLanModePort(u16 port) {
        return port == 30000 || port == 40000 || port == 35000 ||
               (port >= 49152 && port <= 49155);
    }

    /* virtual -> what the game should see (peer appears on the game's subnet) */
    u32 VirtualToGame(u32 virt);

    /* what the game sent -> virtual address to put on the wire */
    u32 GameToVirtual(u32 game);

}
