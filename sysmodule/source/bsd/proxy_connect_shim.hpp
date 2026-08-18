/*
 * sys-slp-client — minimal stub of ryu_ldn_nx's protocol connect types.
 *
 * The ported bsd:u MITM carries TCP ProxyConnect handshake code paths. Two
 * different claims used to be made about them here and in main.cpp, and only
 * one is true:
 *
 *   - SEND side (ProxySocket::Connect() -> ProxySocketManager::
 *     SendProxyConnect() -> the callback registered in main.cpp) IS
 *     reachable: BsdMitmService::Connect() promotes any socket type,
 *     including TCP, to a proxy socket when the destination is an LDN/
 *     virtual address, regardless of what game is asking. See main.cpp's
 *     SetProxyConnectCallback for the fix (fail fast instead of lying).
 *
 *   - RECEIVE side (IncomingConnection / HandleConnectResponse /
 *     RouteConnectRequest / RouteConnectResponse) genuinely IS unreachable:
 *     nothing in slp_tunnel.cpp's inbound frame dispatch ever calls them,
 *     because no wire frame type exists yet for a TCP connect notification.
 *
 * So: MK8DX LAN mode and every title tested so far (MK8DX, Diablo III,
 * Advance Wars) are pure UDP on the virtual network and never exercise any of
 * this, which is why it went unnoticed -- but the send side is live code, not
 * dead code, and a future TCP-using title would hit it.
 *
 * Rather than surgically deleting the (compilable) TCP paths now, we provide
 * the exact structs/enums those paths reference so the port stays close to
 * upstream. The fields mirror ryu_ldn_nx's protocol/types.hpp subset that
 * the bsd subsystem touches. A real fix needs a wire frame type for
 * connect/reply/disconnect plus inbound dispatch to feed RouteConnectRequest/
 * RouteConnectResponse.
 */
#pragma once

#include <cstdint>

namespace ryu_ldn::protocol {

    enum class ProtocolType : uint8_t {
        Unspecified = 0,
        Tcp = 6,
        Udp = 17,
    };

    struct ProxyConnectInfo {
        uint32_t     source_ipv4 = 0;  /* Ryujinx format (host-order uint32) */
        uint16_t     source_port = 0;  /* host byte order                    */
        uint32_t     dest_ipv4   = 0;  /* Ryujinx format (host-order uint32) */
        uint16_t     dest_port   = 0;  /* host byte order                    */
        ProtocolType protocol    = ProtocolType::Unspecified;
    };

    struct ProxyConnectRequest {
        ProxyConnectInfo info;
    };

    struct ProxyConnectResponse {
        ProxyConnectInfo info;
    };

}
