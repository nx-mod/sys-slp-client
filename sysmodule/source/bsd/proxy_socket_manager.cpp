/**
 * @file proxy_socket_manager.cpp
 * @brief Implementation of the Proxy Socket Manager
 *
 * This file implements the central registry for proxy sockets.
 * See proxy_socket_manager.hpp for design documentation.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "proxy_socket_manager.hpp"
#include "lan_addr_map.hpp"
#include "bsd_log_shim.hpp"
#include "ldn/ldn_control.hpp"

namespace ams::mitm::bsd {

// =============================================================================
// Singleton
// =============================================================================

ProxySocketManager& ProxySocketManager::GetInstance() {
    static ProxySocketManager instance;
    return instance;
}

// =============================================================================
// Socket Management
// =============================================================================

ProxySocket* ProxySocketManager::CreateProxySocket(s32 fd, ryu_ldn::bsd::SocketType type,
                                                    ryu_ldn::bsd::ProtocolType protocol) {
    std::scoped_lock lock(m_mutex);

    // Check if fd already has a proxy socket
    if (m_sockets.find(fd) != m_sockets.end()) {
        // Already exists - return existing
        return m_sockets[fd].get();
    }

    // Check limit
    if (m_sockets.size() >= MAX_PROXY_SOCKETS) {
        return nullptr;
    }

    // Create new proxy socket
    auto socket = std::make_unique<ProxySocket>(type, protocol);
    ProxySocket* result = socket.get();

    // Add to registry
    m_sockets[fd] = std::move(socket);

    return result;
}

ProxySocket* ProxySocketManager::GetProxySocket(s32 fd) {
    std::scoped_lock lock(m_mutex);

    auto it = m_sockets.find(fd);
    if (it != m_sockets.end()) {
        return it->second.get();
    }

    return nullptr;
}

bool ProxySocketManager::IsProxySocket(s32 fd) const {
    std::scoped_lock lock(m_mutex);
    return m_sockets.find(fd) != m_sockets.end();
}

bool ProxySocketManager::CloseProxySocket(s32 fd) {
    // Close() (below, outside the lock) can call back into this manager for
    // TCP sockets (SendProxyDisconnect), which re-locks m_mutex -- holding it
    // across the Close() call would self-deadlock, since m_mutex is
    // non-recursive. Move the socket out of the registry under the lock, then
    // close it after releasing.
    std::unique_ptr<ProxySocket> socket_to_close;
    {
        std::scoped_lock lock(m_mutex);

        auto it = m_sockets.find(fd);
        if (it == m_sockets.end()) {
            return false;
        }

        ProxySocket* socket = it->second.get();
        if (socket != nullptr) {
            const auto local_addr = socket->GetLocalAddr();
            if (local_addr.GetPort() != 0) {
                m_port_pool.ReleasePort(local_addr.GetPort(), socket->GetProtocol());
            }
        }

        socket_to_close = std::move(it->second);
        m_sockets.erase(it);
    }

    if (socket_to_close != nullptr) {
        Result close_result = socket_to_close->Close();
        if (R_FAILED(close_result)) {
            // Log but continue cleanup - socket will be destroyed regardless
            AMS_UNUSED(close_result);
        }
    }

    return true;
}

void ProxySocketManager::CloseAllProxySockets() {
    // Same deadlock hazard as CloseProxySocket: Close() can call back into
    // this manager, so sockets must be closed after releasing m_mutex.
    std::vector<std::unique_ptr<ProxySocket>> sockets_to_close;
    {
        std::scoped_lock lock(m_mutex);
        for (auto& [fd, socket] : m_sockets) {
            sockets_to_close.push_back(std::move(socket));
        }
        m_sockets.clear();
    }

    for (auto& socket : sockets_to_close) {
        if (socket != nullptr) {
            Result close_result = socket->Close();
            if (R_FAILED(close_result)) {
                // Log but continue cleanup - socket will be destroyed regardless
                AMS_UNUSED(close_result);
            }
        }
    }

    std::scoped_lock lock(m_mutex);
    m_port_pool.ReleaseAll();
}

void ProxySocketManager::Reset() {
    // Same deadlock hazard as CloseProxySocket: Close() can call back into
    // this manager, so sockets must be closed after releasing m_mutex.
    std::vector<std::unique_ptr<ProxySocket>> sockets_to_close;
    {
        std::scoped_lock lock(m_mutex);
        for (auto& [fd, socket] : m_sockets) {
            sockets_to_close.push_back(std::move(socket));
        }
        m_sockets.clear();
    }

    for (auto& socket : sockets_to_close) {
        if (socket != nullptr) {
            Result close_result = socket->Close();
            AMS_UNUSED(close_result);
        }
    }

    std::scoped_lock lock(m_mutex);

    // Release all ports
    m_port_pool.ReleaseAll();

    // Clear pending packets ring (no dealloc — just reset indices)
    m_pending_head = 0;
    m_pending_tail = 0;
    m_pending_count = 0;

    // Reset local IP
    m_local_ip = 0;

    // Clear callbacks
    m_send_callback = nullptr;
    m_proxy_connect_callback = nullptr;
    m_proxy_connect_reply_callback = nullptr;
    m_proxy_disconnect_callback = nullptr;
}

// =============================================================================
// Port Management
// =============================================================================

uint16_t ProxySocketManager::AllocatePort(ryu_ldn::bsd::ProtocolType protocol) {
    return m_port_pool.AllocatePort(protocol);
}

bool ProxySocketManager::ReservePort(uint16_t port, ryu_ldn::bsd::ProtocolType protocol) {
    return m_port_pool.AllocateSpecificPort(port, protocol);
}

void ProxySocketManager::ReleasePort(uint16_t port, ryu_ldn::bsd::ProtocolType protocol) {
    m_port_pool.ReleasePort(port, protocol);
}

// =============================================================================
// Outgoing Data
// =============================================================================

void ProxySocketManager::SetSendCallback(SendProxyDataCallback callback) {
    std::scoped_lock lock(m_mutex);
    m_send_callback = callback;
}

bool ProxySocketManager::SendProxyData(uint32_t source_ip, uint16_t source_port,
                                        uint32_t dest_ip, uint16_t dest_port,
                                        ryu_ldn::bsd::ProtocolType protocol,
                                        const void* data, size_t data_len) {
    SendProxyDataCallback callback;
    {
        std::scoped_lock lock(m_mutex);
        callback = m_send_callback;
    }

    if (callback == nullptr) {
        LOG_WARN("ProxySocketManager::SendProxyData: m_send_callback=nullptr (src=0x%08X:%u dst=0x%08X:%u)",
                 source_ip, source_port, dest_ip, dest_port);
        return false;
    }

    bool ok = callback(source_ip, source_port, dest_ip, dest_port, protocol, data, data_len);
    if (!ok) {
        LOG_WARN("ProxySocketManager::SendProxyData: callback returned false (src=0x%08X:%u dst=0x%08X:%u len=%zu)",
                 source_ip, source_port, dest_ip, dest_port, data_len);
    }
    return ok;
}

void ProxySocketManager::SetProxyConnectCallback(SendProxyConnectCallback callback) {
    std::scoped_lock lock(m_mutex);
    m_proxy_connect_callback = callback;
}

bool ProxySocketManager::SendProxyConnect(uint32_t source_ip, uint16_t source_port,
                                           uint32_t dest_ip, uint16_t dest_port,
                                           ryu_ldn::bsd::ProtocolType protocol) {
    SendProxyConnectCallback callback;
    {
        std::scoped_lock lock(m_mutex);
        callback = m_proxy_connect_callback;
    }

    if (callback == nullptr) {
        return false;
    }

    return callback(source_ip, source_port, dest_ip, dest_port, protocol);
}

void ProxySocketManager::SetProxyConnectReplyCallback(SendProxyConnectReplyCallback callback) {
    std::scoped_lock lock(m_mutex);
    m_proxy_connect_reply_callback = callback;
}

bool ProxySocketManager::SendProxyConnectReply(uint32_t source_ip, uint16_t source_port,
                                                uint32_t dest_ip, uint16_t dest_port,
                                                ryu_ldn::bsd::ProtocolType protocol) {
    SendProxyConnectReplyCallback callback;
    {
        std::scoped_lock lock(m_mutex);
        callback = m_proxy_connect_reply_callback;
    }

    if (callback == nullptr) {
        return false;
    }

    return callback(source_ip, source_port, dest_ip, dest_port, protocol);
}

void ProxySocketManager::SetProxyDisconnectCallback(SendProxyDisconnectCallback callback) {
    std::scoped_lock lock(m_mutex);
    m_proxy_disconnect_callback = callback;
}

bool ProxySocketManager::SendProxyDisconnect(uint32_t source_ip, uint16_t source_port,
                                              uint32_t dest_ip, uint16_t dest_port,
                                              ryu_ldn::bsd::ProtocolType protocol) {
    SendProxyDisconnectCallback callback;
    {
        std::scoped_lock lock(m_mutex);
        callback = m_proxy_disconnect_callback;
    }

    if (callback == nullptr) {
        return false;
    }

    return callback(source_ip, source_port, dest_ip, dest_port, protocol);
}

bool ProxySocketManager::RouteConnectResponse(const ryu_ldn::protocol::ProxyConnectResponse& response) {
    std::scoped_lock lock(m_mutex);

    // Find socket in Connecting state that matches the destination
    uint32_t dest_ip = response.info.source_ipv4;  // Response comes back to our source
    uint16_t dest_port = response.info.source_port;

    for (auto& [fd, socket] : m_sockets) {
        if (socket == nullptr) {
            continue;
        }

        // Check if socket is connecting
        if (socket->GetState() != ProxySocketState::Connecting) {
            continue;
        }

        // Check local address matches
        const auto& local_addr = socket->GetLocalAddr();
        if (local_addr.GetAddr() != dest_ip || local_addr.GetPort() != dest_port) {
            continue;
        }

        // Found matching socket - deliver response
        socket->HandleConnectResponse(response);
        return true;
    }

    return false;
}

bool ProxySocketManager::RouteConnectRequest(const ryu_ldn::protocol::ProxyConnectRequest& request) {
    // IncomingConnection() (called outside the lock, below) calls back into
    // this manager (SendProxyConnectReply), which re-locks m_mutex -- the
    // same self-deadlock hazard as CloseProxySocket. Find the target under
    // the lock, then act on it after releasing.
    ProxySocket* target = nullptr;
    {
        std::scoped_lock lock(m_mutex);

        // Find listening socket that matches the destination
        uint32_t dest_ip = request.info.dest_ipv4;
        uint16_t dest_port = request.info.dest_port;

        for (auto& [fd, socket] : m_sockets) {
            if (socket == nullptr) {
                continue;
            }

            // Check if socket is listening
            if (socket->GetState() != ProxySocketState::Listening) {
                continue;
            }

            // Check protocol matches (TCP)
            if (socket->GetProtocol() != ryu_ldn::bsd::ProtocolType::Tcp) {
                continue;
            }

            // Check local address matches destination
            const auto local_addr = socket->GetLocalAddr();

            // Port must match
            if (local_addr.GetPort() != dest_port) {
                continue;
            }

            // IP can be exact match or INADDR_ANY
            uint32_t local_ip = local_addr.GetAddr();
            if (local_ip != 0 && local_ip != dest_ip) {
                continue;
            }

            target = socket.get();
            break;
        }
    }

    if (target == nullptr) {
        return false;
    }

    // Found matching listener - queue the connection
    target->IncomingConnection(request);
    return true;
}

// =============================================================================
// Data Routing
// =============================================================================

bool ProxySocketManager::RouteIncomingData(uint32_t source_ip, uint16_t source_port,
                                            uint32_t dest_ip, uint16_t dest_port,
                                            ryu_ldn::bsd::ProtocolType protocol,
                                            const void* data, size_t data_len) {
    /* Foreign-session guard, game-data counterpart to LdnControl's
     * scanner-allowlist gate on the control handshake (ldn_control.cpp
     * HandleConnect). A shared internet relay carries every session's
     * traffic to every client; once we're actually in a session, drop game
     * data whose source IP isn't a member of it rather than silently
     * delivering it to a matched socket. Checked OUTSIDE m_mutex -- this
     * takes LdnControl's own mutex internally, and RouteIncomingData is
     * called from the tunnel thread while LdnControl's run-loop thread can
     * itself call back into bsd paths, so nesting the two locks risks a
     * lock-order inversion; not worth it for a check that doesn't need
     * m_mutex at all.
     *
     * LAN-mode traffic (browse 30000, session 49152-49155, aux 40000/35000)
     * is exempt: dogty's equivalent filter (InjectGameFrame, relay_client.cpp)
     * only ever runs on the LDN game-data injection path -- his LAN-mode
     * browse handling is a structurally separate code path that never
     * touches session-membership state at all, by construction. Ours shares
     * one RouteIncomingData chokepoint for both, so without this exemption
     * LdnControl's session state (Station/StationConnected from an unrelated
     * WiFi/LDN join) incorrectly gated LAN browse replies too -- confirmed on
     * hardware: a LAN-mode host's browse reply got dropped as "foreign"
     * solely because the console was mid-session in a completely different
     * LDN network. LAN mode has no LDN session concept to check membership
     * against in the first place. */
    if (!::slp::netmap::IsLanModePort(dest_port) &&
        !ams::slp::ldn::LdnControl::IsKnownSessionPeerPublic(source_ip)) {
        LOG_WARN("bsd: RouteIncomingData DROP foreign-session src=0x%08x dport=%u len=%zu "
                 "(not a member of our current LDN session)",
                 source_ip, dest_port, data_len);
        return false;
    }

    std::scoped_lock lock(m_mutex);

    // For broadcast/multicast packets, deliver to ALL matching sockets.
    // PIA mesh discovery relies on broadcast UDP reaching every listener
    // on the same port. For unicast, only one socket matches.
    constexpr size_t kMaxSockets = 8;
    ProxySocket* targets[kMaxSockets];
    size_t match_count = FindAllSocketsByDestination(dest_ip, dest_port, protocol,
                                                      targets, kMaxSockets);

    if (match_count == 0) {
        // No matching socket — buffer into fixed-size ring for post-bind delivery.
        if (m_pending_count >= MaxPendingPackets) {
            // Drop oldest
            m_pending_head = (m_pending_head + 1) % MaxPendingPackets;
            m_pending_count--;
        }
        PendingPacket& slot = m_pending_ring[m_pending_tail];
        slot.source_ip = source_ip;
        slot.source_port = source_port;
        slot.dest_ip = dest_ip;
        slot.dest_port = dest_port;
        slot.protocol = protocol;
        size_t copy_len = std::min(data_len, static_cast<size_t>(PendingPayloadMax));
        slot.len = static_cast<uint16_t>(copy_len);
        if (copy_len > 0 && data != nullptr) {
            std::memcpy(slot.data, data, copy_len);
        }
        m_pending_tail = (m_pending_tail + 1) % MaxPendingPackets;
        m_pending_count++;
        return false;
    }

    // Build source address for RecvFrom
    // Note: Nintendo Switch uses BSD-style sockaddr with sin_len field
    // sin_len must be sizeof(SockAddrIn) = 16 for the game to accept the address
    //
    // CRITICAL: Ryujinx stores IPs as uint in "big-endian read" format:
    // For our virtual 10.13.37.2, that format is 0x0A0D2502.
    // BUT in BsdSockAddr, sin_addr must be in NETWORK BYTE ORDER (standard BSD).
    // Ryujinx does Array.Reverse() when converting ProxyInfo.SourceIpV4 to IPEndPoint,
    // then copies bytes directly to sin_addr, resulting in network byte order.
    // So we must bswap32 to convert Ryujinx format -> network byte order.
    // For 10.13.37.2: 0x0A0D2502 -> bswap32 -> 0x02250D0A (network order)
    ryu_ldn::bsd::SockAddrIn from_addr{};
    from_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
    from_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
    from_addr.sin_port = __builtin_bswap16(source_port);
    {
        /* LAN mode only: show the game an on-subnet peer.
         *
         * This was written on the theory that an off-subnet reply is what
         * caused 2618-0006. That theory is REJECTED -- the real cause was
         * BsdMitmService::Send()/SendTo() reporting {ret, errno} in swapped
         * slots (see notes/TODO-uncross-bsd-out-params.md). With translation
         * disabled (lan_addr_map.cpp: TranslationEnabled = false), VirtualToGame
         * is an identity no-op and LAN works fine off-subnet. Kept for the rare
         * case translation is ever re-enabled; do not re-enable to chase a
         * missing lobby. */
        uint32_t vis = source_ip;
        if (::slp::netmap::IsLanModePort(source_port))
            vis = ::slp::netmap::VirtualToGame(vis);
        from_addr.SetAddr(::slp::net::IpV4::FromNumeric(vis));
    }

    // Deliver to all matching sockets (critical for broadcast UDP)
    for (size_t i = 0; i < match_count; i++) {
        targets[i]->IncomingData(data, data_len, from_addr);
    }

    return true;
}

ProxySocket* ProxySocketManager::FindSocketByDestination(uint32_t dest_ip, uint16_t dest_port,
                                                          ryu_ldn::bsd::ProtocolType protocol) {
    // Caller must hold m_mutex

    // Check if dest_ip is a broadcast address (ends in .255 or .255.255)
    // Our virtual subnet is 10.13.x.x with mask 255.255.0.0, so broadcast is 10.13.255.255
    // CRITICAL: dest_ip is in Ryujinx format (Big Endian read as uint32)
    // For 10.13.255.255: first octet (10) in HIGH byte, last octet (255) in LOW byte
    // So 10.13.255.255 = 0x0A0DFFFF where:
    //   - 0x0A = 10  (first octet, bits 24-31)
    //   - 0x0D = 13  (second octet, bits 16-23)
    //   - 0xFF = 255 (third octet, bits 8-15)
    //   - 0xFF = 255 (fourth octet, bits 0-7)
    // To check .255 (last octet): mask 0x000000FF
    // To check .255.255 (last two octets): mask 0x0000FFFF
    bool is_broadcast = ((dest_ip & 0x000000FF) == 0x000000FF) ||   // x.x.x.255 in Ryujinx format
                        ((dest_ip & 0x0000FFFF) == 0x0000FFFF);     // x.x.255.255 in Ryujinx format

    for (auto& [fd, socket] : m_sockets) {
        if (socket == nullptr) {
            continue;
        }

        // Check protocol matches
        if (socket->GetProtocol() != protocol) {
            continue;
        }

        // Check local address matches destination
        const auto& local_addr = socket->GetLocalAddr();

        // Port must match (GetPort does bswap16, but dest_port is in host order)
        if (local_addr.GetPort() != dest_port) {
            continue;
        }

        // IP matching:
        // CRITICAL: sin_addr is now in Ryujinx format (NO bswap was applied in Bind).
        // Use sin_addr directly instead of GetAddr() which does bswap32.
        // 1. INADDR_ANY (bound to 0.0.0.0 - accepts any destination)
        // 2. Exact match (bound to specific IP)
        // 3. Broadcast: any socket on the same port receives broadcast packets
        uint32_t local_ip = local_addr.Addr().Numeric();
        if (local_ip == 0) {
            // Bound to INADDR_ANY - accepts all
            return socket.get();
        }
        if (local_ip == dest_ip) {
            // Exact match
            return socket.get();
        }
        if (is_broadcast) {
            // Broadcast packet — deliver to any proxy socket on this port.
            // Every proxy socket is bound to INADDR_ANY (stored as our local
            // IP) or an address inside 10.13.0.0/16 (was narrower 10.13.37.0/24
            // until bsd_types.hpp's IsLanAddress was widened 2026-08-17 to
            // match the per-console-derived virtual IP scheme), so a broadcast
            // always belongs to this virtual LAN. MK8DX LAN sends the *limited*
            // broadcast 255.255.255.255, which a subnet-equality check would
            // never match.
            return socket.get();
        }
    }

    return nullptr;
}

size_t ProxySocketManager::FindAllSocketsByDestination(uint32_t dest_ip, uint16_t dest_port,
                                                          ryu_ldn::bsd::ProtocolType protocol,
                                                          ProxySocket* out_sockets[], size_t max_sockets) {
    // Caller must hold m_mutex

    bool is_broadcast = ((dest_ip & 0x000000FF) == 0x000000FF) ||
                        ((dest_ip & 0x0000FFFF) == 0x0000FFFF);

    size_t count = 0;

    for (auto& [fd, socket] : m_sockets) {
        if (socket == nullptr) {
            continue;
        }
        if (count >= max_sockets) {
            break;
        }

        if (socket->GetProtocol() != protocol) {
            continue;
        }

        const auto& local_addr = socket->GetLocalAddr();

        if (local_addr.GetPort() != dest_port) {
            continue;
        }

        uint32_t local_ip = local_addr.Addr().Numeric();

        if (local_ip == 0) {
            out_sockets[count++] = socket.get();
            continue;
        }
        if (local_ip == dest_ip) {
            out_sockets[count++] = socket.get();
            continue;
        }
        if (is_broadcast) {
            // See FindSocketByDestination: every proxy socket belongs to the
            // virtual LAN, so a broadcast on this port reaches all of them.
            out_sockets[count++] = socket.get();
            continue;
        }
    }

    return count;
}

// =============================================================================
// LDN Network Configuration
// =============================================================================

void ProxySocketManager::SetLocalIp(uint32_t ip) {
    std::scoped_lock lock(m_mutex);
    m_local_ip = ip;
}

uint32_t ProxySocketManager::GetLocalIp() const {
    std::scoped_lock lock(m_mutex);
    return m_local_ip;
}

// =============================================================================
// Statistics
// =============================================================================

size_t ProxySocketManager::GetActiveSocketCount() const {
    std::scoped_lock lock(m_mutex);
    return m_sockets.size();
}

size_t ProxySocketManager::GetAvailablePortCount(ryu_ldn::bsd::ProtocolType protocol) const {
    return m_port_pool.GetAvailableCount(protocol);
}

// =============================================================================
// Pending Packet Delivery
// =============================================================================

void ProxySocketManager::DeliverPendingPackets(ProxySocket* socket, uint16_t port,
                                                ryu_ldn::bsd::ProtocolType protocol) {
    // Called after bind - deliver any buffered packets matching this socket
    // Caller must NOT hold m_mutex (we take it here)
    std::scoped_lock lock(m_mutex);

    if (socket == nullptr || m_pending_count == 0) {
        return;
    }

    // Walk the ring in arrival order, delivering matches and compacting in place.
    size_t read_idx = m_pending_head;
    size_t write_idx = m_pending_head;
    size_t remaining = m_pending_count;
    size_t kept = 0;

    while (remaining > 0) {
        const PendingPacket& pkt = m_pending_ring[read_idx];

        if (pkt.protocol == protocol && pkt.dest_port == port) {
            ryu_ldn::bsd::SockAddrIn from_addr{};
            from_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
            from_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
            from_addr.sin_port = __builtin_bswap16(pkt.source_port);
            {
                /* LAN mode only: show the game an on-subnet peer, otherwise it
                 * discards the reply as foreign (root cause of 2618-0006). */
                uint32_t vis = pkt.source_ip;
                if (::slp::netmap::IsLanModePort(pkt.source_port))
                    vis = ::slp::netmap::VirtualToGame(vis);
                from_addr.SetAddr(::slp::net::IpV4::FromNumeric(vis));
            }

            socket->IncomingData(pkt.data, pkt.len, from_addr);
            // Drop this slot by not copying it forward
        } else {
            if (write_idx != read_idx) {
                m_pending_ring[write_idx] = pkt;
            }
            write_idx = (write_idx + 1) % MaxPendingPackets;
            kept++;
        }

        read_idx = (read_idx + 1) % MaxPendingPackets;
        remaining--;
    }

    m_pending_tail = write_idx;
    m_pending_count = kept;
}

} // namespace ams::mitm::bsd
