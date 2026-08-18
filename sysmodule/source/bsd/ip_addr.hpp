/*
 * sys-slp-client — IPv4 address type.
 *
 * THE PROBLEM THIS EXISTS TO KILL
 * -------------------------------
 * An IPv4 address shows up in this codebase in two different u32 encodings,
 * and for a long time both were passed around as bare `uint32_t`:
 *
 *   NUMERIC   the address as an integer.   10.13.37.2 == 0x0A0D2502
 *             (MSB = first octet). This is what the tunnel uses, because it
 *             builds real IPv4 headers with explicit shifts (Wr32be), and what
 *             the relay/NodeInfo protocol uses. It was called "Ryujinx format"
 *             in older comments, which made it sound like a foreign convention
 *             we were tolerating -- it isn't, it's just the integer value.
 *
 *   NETWORK   the address as it must sit inside a sockaddr_in, i.e. the bytes
 *             0A 0D 25 02 in memory. On this little-endian ARM64 that is the
 *             u32 0x02250D0A.
 *
 * They differ on every little-endian machine, so a swap between them is
 * unavoidable -- it is not cruft that can be deleted. What WAS cruft is that
 * both were spelled `uint32_t`, so nothing stopped one being used where the
 * other belonged. That cost us real bugs:
 *
 *   - Bind stored NUMERIC into sockaddr_in::sin_addr, so GetSockName handed the
 *     game its own address as 2.37.13.10.
 *   - GetAddr()/GetPort()/IsLanAddress() all assume NETWORK, so every one of
 *     them was wrong on those structs (IsLanAddress on our own bound socket
 *     could never return true).
 *   - The UDP path stored the remote peer as NETWORK while the TCP accept path
 *     stored it as NUMERIC -- same field, two conventions -- so GetPeerName
 *     reported byte-reversed addresses for TCP sockets.
 *
 * THE RULE
 * --------
 * A sockaddr_in ALWAYS holds NETWORK order -- no exceptions, because that
 * struct crosses the boundary to the game and its layout is not ours to
 * redefine. Convert to NUMERIC at the point of use (tunnel, routing compares).
 * Never assign a bare u32 to sin_addr; go through SockAddrIn::SetAddr().
 */
#pragma once

#include <stratosphere.hpp>

namespace slp::net {

    class IpV4 {
    public:
        constexpr IpV4() = default;

        /* Named constructors -- there is deliberately no implicit conversion
         * from u32, so the encoding must be stated at every entry point. */
        static constexpr IpV4 FromNumeric(u32 v) { return IpV4(v); }
        static constexpr IpV4 FromNetwork(u32 v) { return IpV4(__builtin_bswap32(v)); }
        static constexpr IpV4 FromOctets(u8 a, u8 b, u8 c, u8 d) {
            return IpV4((static_cast<u32>(a) << 24) | (static_cast<u32>(b) << 16) |
                        (static_cast<u32>(c) << 8)  |  static_cast<u32>(d));
        }

        /* 10.13.37.2 -> 0x0A0D2502. For the tunnel and for relay/NodeInfo. */
        constexpr u32 Numeric() const { return m_numeric; }
        /* 10.13.37.2 -> 0x02250D0A. ONLY for sockaddr_in::sin_addr. */
        constexpr u32 Network() const { return __builtin_bswap32(m_numeric); }

        /* Octet(0) is the first octet: 10 for 10.13.37.2. */
        constexpr u8 Octet(int i) const {
            return static_cast<u8>((m_numeric >> (24 - 8 * i)) & 0xFF);
        }

        constexpr bool IsAny() const { return m_numeric == 0; }
        /* Trailing .255 -- a directed broadcast for any /24-or-wider netmask. */
        constexpr bool IsBroadcast() const { return (m_numeric & 0xFF) == 0xFF; }

        constexpr bool InSubnet(IpV4 net, IpV4 mask) const {
            return (m_numeric & mask.m_numeric) == (net.m_numeric & mask.m_numeric);
        }

        constexpr bool operator==(const IpV4 &o) const { return m_numeric == o.m_numeric; }
        constexpr bool operator!=(const IpV4 &o) const { return m_numeric != o.m_numeric; }

    private:
        explicit constexpr IpV4(u32 numeric) : m_numeric(numeric) {}
        u32 m_numeric{0};
    };

    /* switch-lan-play's virtual subnet (config.h: SUBNET_NET / SUBNET_MASK). */
    inline constexpr IpV4 VirtualNet  = IpV4::FromOctets(10, 13, 0, 0);
    inline constexpr IpV4 VirtualMask = IpV4::FromOctets(255, 255, 0, 0);

}
