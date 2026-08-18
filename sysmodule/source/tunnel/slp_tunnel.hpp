/*
 * sys-slp-client — slp tunnel: IPv4/UDP bridge between the bsd:u MITM
 * proxy sockets and the slp relay.
 *
 * Outbound (game -> relay):
 *   ProxySocketManager::SendProxyData callback -> craft IPv4+UDP packet
 *   (src = our virtual LAN IP, dst = peer/broadcast) -> slpClientSendIpv4.
 *
 * Inbound (relay -> game):
 *   Runtime run loop -> OnFrame() -> reassemble Ipv4Frag if needed ->
 *   parse UDP -> ProxySocketManager::RouteIncomingData().
 *
 * Byte order contract (matches proxy_socket.cpp / proxy_socket_manager.cpp):
 *   - SendProxyData / RouteIncomingData IPs are "Ryujinx format" — the dotted
 *     quad read big-endian (10.13.37.2 == 0x0A0D2502).
 *   - Wire IP bytes are network order = big-endian encoding of that value.
 *   - Ports are host order in the callbacks, network order on the wire.
 *
 * MK8DX LAN mode is pure UDP over bsd:u (broadcast :30000 browse, :49152-49155
 * Pia sessions). Only UDP is tunnelled; TCP proxy sends fail with NetUnreach.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace ryu_ldn::bsd {
    enum class ProtocolType : int32_t;
}

namespace slp::tun {

    /* Called once at boot: parse our virtual IP, register the send callback. */
    void Init();

    /* Re-read the virtual address after the network is up (Init() runs at
     * boot2 before DHCP and can only get the fallback). */
    void RefreshLocalIp();

    /* SendProxyDataCallback implementation (see proxy_socket_manager.hpp). */
    bool Send(uint32_t src_ip, uint16_t src_port,
              uint32_t dst_ip, uint16_t dst_port,
              ryu_ldn::bsd::ProtocolType protocol,
              const void *data, size_t len);

    /* Called by the runtime run loop for every datagram (payload after the
     * 1-byte type header). Handles SLP_TYPE_IPV4 and SLP_TYPE_IPV4_FRAG. */
    void OnFrame(int type, const uint8_t *payload, size_t len);

    /* Called when the relay session stops — drops partial fragments. */
    void OnStop();

}
