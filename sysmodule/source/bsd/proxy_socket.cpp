/**
 * @file proxy_socket.cpp
 * @brief Implementation of the Proxy Socket for LDN Traffic Routing
 *
 * This file implements the ProxySocket class. Data transfer operations
 * (Send/Recv) interact with the ProxySocketManager to encode/decode
 * ProxyData packets.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#include "proxy_socket.hpp"
#include "lan_addr_map.hpp"
#include "proxy_socket_manager.hpp"
#include "bsd_log_shim.hpp"

namespace ams::mitm::bsd {

// =============================================================================
// BSD Error Codes (from bsd_types.hpp)
// =============================================================================

using Errno = ryu_ldn::bsd::BsdErrno;

// =============================================================================
// Construction / Destruction
// =============================================================================

ProxySocket::ProxySocket(ryu_ldn::bsd::SocketType type, ryu_ldn::bsd::ProtocolType protocol)
    : m_type(type)
    , m_protocol(protocol)
    , m_state(ProxySocketState::Created)
    , m_non_blocking(false)
    , m_shutdown_read(false)
    , m_shutdown_write(false)
{
    // Initialize addresses to zero
    std::memset(&m_local_addr, 0, sizeof(m_local_addr));
    std::memset(&m_remote_addr, 0, sizeof(m_remote_addr));

    // Set address family
    m_local_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
    m_local_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
    m_remote_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
    m_remote_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
}

ProxySocket::~ProxySocket() {
    // Just cleanup, don't send disconnect (should have called Close())
    m_state = ProxySocketState::Closed;
}

// =============================================================================
// Address Management
// =============================================================================

Result ProxySocket::Bind(const ryu_ldn::bsd::SockAddrIn& addr) {
    std::scoped_lock lock(m_state_mutex);

    // Check state
    if (m_state != ProxySocketState::Created) {
        // Already bound or in invalid state
        R_THROW(static_cast<s32>(Errno::Inval));
    }

    // Validate address family
    if (addr.sin_family != static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet)) {
        R_THROW(static_cast<s32>(Errno::AfNoSupport));
    }

    // Store local address
    m_local_addr = addr;
    m_state = ProxySocketState::Bound;

    R_SUCCEED();
}

Result ProxySocket::Connect(const ryu_ldn::bsd::SockAddrIn& addr) {
    // NOTE: intentionally NOT held across the SendProxyConnect() call below
    // (which can invoke a callback that calls back into this socket via the
    // manager) or the blocking TimedWait -- only around the actual field
    // reads/writes, taken and released multiple times through this function.
    {
        std::scoped_lock lock(m_state_mutex);
        // Check state - must be at least created (can connect unbound socket)
        if (m_state == ProxySocketState::Closed) {
            R_THROW(static_cast<s32>(Errno::BadF));
        }

        // Validate address family
        if (addr.sin_family != static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet)) {
            R_THROW(static_cast<s32>(Errno::AfNoSupport));
        }

        // If not bound yet, auto-bind will happen with ephemeral port
        // (caller should have done this before calling Connect)

        // Store remote address
        m_remote_addr = addr;
    }

    // For TCP, perform connect handshake
    if (m_type == ryu_ldn::bsd::SocketType::Stream) {
        {
            std::scoped_lock lock(m_state_mutex);
            m_state = ProxySocketState::Connecting;
        }
        m_connect_response_received = false;
        m_connect_event.Clear();

        // Send ProxyConnect via ProxySocketManager
        auto& manager = ProxySocketManager::GetInstance();
        const auto local_addr = GetLocalAddr();
        bool sent = manager.SendProxyConnect(
            local_addr.GetAddr(), local_addr.GetPort(),
            addr.GetAddr(), addr.GetPort(),
            m_protocol
        );

        if (!sent) {
            std::scoped_lock lock(m_state_mutex);
            m_state = ProxySocketState::Bound;
            R_THROW(static_cast<s32>(Errno::NetUnreach));
        }

        // Wait for ProxyConnectReply (with timeout)
        if (!m_non_blocking) {
            // Blocking connect - wait up to 4 seconds (like Ryujinx)
            bool got_response = m_connect_event.TimedWait(TimeSpan::FromSeconds(4));

            std::scoped_lock lock(m_state_mutex);

            if (!got_response || !m_connect_response_received) {
                m_state = ProxySocketState::Bound;
                R_THROW(static_cast<s32>(Errno::TimedOut));
            }

            // Check if connection was refused (protocol != Unspecified means error)
            if (m_connect_response.info.protocol != ryu_ldn::protocol::ProtocolType::Unspecified) {
                m_state = ProxySocketState::Bound;
                R_THROW(static_cast<s32>(Errno::ConnRefused));
            }

            m_state = ProxySocketState::Connected;
        } else {
            // Non-blocking connect - return EINPROGRESS
            // The connect will complete asynchronously
            R_THROW(static_cast<s32>(Errno::InProgress));
        }
    } else {
        // For UDP, just store the default destination
        std::scoped_lock lock(m_state_mutex);
        m_state = ProxySocketState::Connected;
    }

    R_SUCCEED();
}

Result ProxySocket::GetSockName(ryu_ldn::bsd::SockAddrIn* out_addr) const {
    if (out_addr == nullptr) {
        R_THROW(static_cast<s32>(Errno::Fault));
    }

    if (m_state == ProxySocketState::Created) {
        // Not bound yet, return zeroed address
        std::memset(out_addr, 0, sizeof(*out_addr));
        out_addr->sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
        out_addr->sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
    } else {
        *out_addr = m_local_addr;
    }

    R_SUCCEED();
}

Result ProxySocket::GetPeerName(ryu_ldn::bsd::SockAddrIn* out_addr) const {
    if (out_addr == nullptr) {
        R_THROW(static_cast<s32>(Errno::Fault));
    }

    if (m_state != ProxySocketState::Connected) {
        R_THROW(static_cast<s32>(Errno::NotConn));
    }

    *out_addr = m_remote_addr;
    R_SUCCEED();
}

// =============================================================================
// Data Transfer
// =============================================================================

s32 ProxySocket::Send(const void* data, size_t len, s32 flags) {
    // Must be connected for Send()
    if (m_state != ProxySocketState::Connected) {
        return -static_cast<s32>(Errno::NotConn);
    }

    // Use SendTo with connected remote address
    return SendTo(data, len, flags, m_remote_addr);
}

s32 ProxySocket::SendTo(const void* data, size_t len, s32 flags, const ryu_ldn::bsd::SockAddrIn& dest) {
    AMS_UNUSED(flags);

    // Check write shutdown
    if (m_shutdown_write) {
        return -static_cast<s32>(Errno::Inval);
    }

    // Check socket state
    if (m_state == ProxySocketState::Closed) {
        return -static_cast<s32>(Errno::BadF);
    }

    // Must be at least bound to send
    if (m_state == ProxySocketState::Created) {
        return -static_cast<s32>(Errno::DestAddrReq);
    }

    // Validate data
    if (data == nullptr && len > 0) {
        return -static_cast<s32>(Errno::Fault);
    }

    // Check max payload size
    if (len > PROXY_SOCKET_MAX_PAYLOAD) {
        return -static_cast<s32>(Errno::MsgSize);
    }

    // Send via ProxySocketManager which routes to LDN server.
    // m_local_addr holds NETWORK order; .Addr().Numeric() gives the tunnel form,
    // so read it directly. dest comes from the game in network byte order, so GetAddr()
    // bswaps it into Ryujinx format — which is what the server expects on the wire.
    uint32_t source_ip = m_local_addr.Addr().Numeric();
    uint16_t source_port = m_local_addr.GetPort();
    uint32_t dest_ip = dest.GetAddr();
    uint16_t dest_port = dest.GetPort();

    /* LAN mode only: the game addresses peers on its OWN subnet (it reads the
     * interface, not the socket), so map that back into the virtual subnet the
     * relay and peers actually use. LDN/WiFi is excluded -- there the game uses
     * 10.13.37.x addresses it got from our NetworkInfo, which are already
     * correct and must not be touched. */
    if (::slp::netmap::IsLanModePort(source_port) || ::slp::netmap::IsLanModePort(dest_port)) {
        const uint32_t mapped = ::slp::netmap::GameToVirtual(dest_ip);
        if (mapped != dest_ip) {
            LOG_VERBOSE("netmap: send dest %u.%u.%u.%u -> %u.%u.%u.%u",
                        (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF,
                        (dest_ip >> 8) & 0xFF, dest_ip & 0xFF,
                        (mapped >> 24) & 0xFF, (mapped >> 16) & 0xFF,
                        (mapped >> 8) & 0xFF, mapped & 0xFF);
            dest_ip = mapped;
        }
    }

    auto& manager = ProxySocketManager::GetInstance();
    bool sent = manager.SendProxyData(source_ip, source_port, dest_ip, dest_port,
                                       m_protocol, data, len);

    if (!sent) {
        // No send callback registered or send failed
        // Return ENETUNREACH to indicate network is unreachable
        return -static_cast<s32>(Errno::NetUnreach);
    }

    return static_cast<s32>(len);
}

s32 ProxySocket::Recv(void* buffer, size_t len, s32 flags) {
    // For connected sockets, use RecvFrom and discard the address
    if (m_state == ProxySocketState::Connected) {
        return RecvFrom(buffer, len, flags, nullptr);
    }

    // For unconnected sockets, Recv requires a default peer (connected state)
    return -static_cast<s32>(Errno::NotConn);
}

s32 ProxySocket::RecvFrom(void* buffer, size_t len, s32 flags, ryu_ldn::bsd::SockAddrIn* from) {
    // Check read shutdown
    if (m_shutdown_read) {
        return 0; // EOF
    }

    // Check socket state
    if (m_state == ProxySocketState::Closed) {
        return -static_cast<s32>(Errno::BadF);
    }

    // Validate buffer
    if (buffer == nullptr && len > 0) {
        return -static_cast<s32>(Errno::Fault);
    }

    bool peek = (flags & 0x2) != 0; // MSG_PEEK = 0x2
    bool dontwait = (flags & 0x80) != 0 || m_non_blocking; // MSG_DONTWAIT = 0x80 (Nintendo Switch)

    // Helper: copy front-of-ring into caller's buffer, pop unless peeking.
    // Caller must hold m_queue_mutex.
    auto consume_front = [&](void* out_buf, size_t out_len) -> s32 {
        const ReceivedPacket& slot = m_rx_ring[m_rx_head];
        size_t copy_len = std::min(out_len, static_cast<size_t>(slot.len));
        if (copy_len > 0) {
            std::memcpy(out_buf, slot.data, copy_len);
        }
        if (from != nullptr) {
            *from = slot.from;
        }
        if (!peek) {
            m_rx_head = (m_rx_head + 1) % PROXY_SOCKET_MAX_QUEUE_SIZE;
            m_rx_count--;
        }
        if (m_rx_count == 0) {
            m_receive_event.Clear();
        }
        return static_cast<s32>(copy_len);
    };

    // Try to get data from queue
    {
        std::scoped_lock lock(m_queue_mutex);

        if (m_rx_count == 0) {
            if (dontwait) {
                return -static_cast<s32>(Errno::Again);
            }
        } else {
            return consume_front(buffer, len);
        }
    }

    // Blocking wait for data. Bounded, not indefinite: the entire ldn:u+bsd:u
    // MITM service runs on a single thread (see main.cpp), so an unconditional
    // Wait() here would freeze IPC processing for every other game/process
    // until this socket receives something -- possibly forever. Time out and
    // return EAGAIN like a real blocking recv() with SO_RCVTIMEO would.
    if (!dontwait) {
        constexpr TimeSpan RecvBlockTimeout = TimeSpan::FromSeconds(5);
        if (m_receive_event.TimedWait(RecvBlockTimeout)) {
            std::scoped_lock lock(m_queue_mutex);

            if (m_rx_count > 0) {
                return consume_front(buffer, len);
            }
        }
    }

    return -static_cast<s32>(Errno::Again);
}

void ProxySocket::IncomingData(const void* data, size_t len, const ryu_ldn::bsd::SockAddrIn& from) {
    // Hex-dump first 32 bytes — only format and log at VERBOSE level, since this
    // fires on every incoming packet and the snprintf loop is non-trivial under
    // load (~100+ packets/sec during gameplay). Compiles away unless
    // SLPCFG_DEBUG_TRACE is defined (see bsd_log_shim.hpp).
    if (len > 0 && data != nullptr) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        size_t log_len = std::min(len, size_t(32));
        char hex_buf[128];
        char* p = hex_buf;
        for (size_t i = 0; i < log_len && (p - hex_buf) < 120; i++) {
            p += std::snprintf(p, 4, "%02X ", bytes[i]);
        }
        LOG_VERBOSE("ProxySocket IncomingData: %zu bytes, first %zu: %s", len, log_len, hex_buf);
    }

    // NOTE: Broadcast filtering is intentionally incomplete. When this socket
    // is bound to INADDR_ANY (local_ip == 0), we cannot determine the
    // original destination IP of an incoming packet, so filtering based on
    // SO_BROADCAST is not feasible. Since ProxySocketManager::RouteIncomingData
    // already delivers broadcast UDP to all matching sockets, and PIA mesh
    // discovery requires that broadcast reach every listener, skipping the
    // filter here is correct behaviour. The if-block is kept as a structural
    // anchor for a future destination-aware implementation if the proxy
    // protocol ever carries the destination address.

    // Clamp payload to fixed buffer size. UDP datagrams larger than our MTU
    // would already have been rejected by SendTo's MsgSize check on the
    // sender side; clamping here is a defensive guard.
    size_t copy_len = std::min(len, static_cast<size_t>(PROXY_SOCKET_MAX_PAYLOAD));

    std::scoped_lock lock(m_queue_mutex);

    // Drop oldest if ring is full (UDP behavior)
    if (m_rx_count >= PROXY_SOCKET_MAX_QUEUE_SIZE) {
        m_rx_head = (m_rx_head + 1) % PROXY_SOCKET_MAX_QUEUE_SIZE;
        m_rx_count--;
    }

    // Write into tail slot in-place — no heap allocation per packet.
    ReceivedPacket& slot = m_rx_ring[m_rx_tail];
    slot.from = from;
    slot.len = static_cast<uint16_t>(copy_len);
    if (copy_len > 0 && data != nullptr) {
        std::memcpy(slot.data, data, copy_len);
    }

    m_rx_tail = (m_rx_tail + 1) % PROXY_SOCKET_MAX_QUEUE_SIZE;
    m_rx_count++;

    m_receive_event.Signal();
}

ReceivedPacket ProxySocket::PopFrontPacket(bool peek) {
    // Caller must hold m_queue_mutex
    if (m_rx_count == 0) {
        return {};
    }

    ReceivedPacket packet = m_rx_ring[m_rx_head];
    if (!peek) {
        m_rx_head = (m_rx_head + 1) % PROXY_SOCKET_MAX_QUEUE_SIZE;
        m_rx_count--;
    }
    return packet;
}

// =============================================================================
// Socket Options
// =============================================================================

Result ProxySocket::SetSockOpt(s32 level, s32 optname, const void* optval, size_t optlen) {
    // Handle SOL_SOCKET level options
    if (level == static_cast<s32>(ryu_ldn::bsd::SocketOptionLevel::Socket)) {
        switch (static_cast<ryu_ldn::bsd::SocketOption>(optname)) {
            case ryu_ldn::bsd::SocketOption::Broadcast:
                // SO_BROADCAST - enable/disable broadcast reception
                if (optval != nullptr && optlen >= sizeof(s32)) {
                    s32 value = *reinterpret_cast<const s32*>(optval);
                    m_broadcast = (value != 0);
                    R_SUCCEED();
                }
                R_THROW(static_cast<s32>(Errno::Inval));

            case ryu_ldn::bsd::SocketOption::ReuseAddr:
            case ryu_ldn::bsd::SocketOption::KeepAlive:
            case ryu_ldn::bsd::SocketOption::DontRoute:
            case ryu_ldn::bsd::SocketOption::Linger:
            case ryu_ldn::bsd::SocketOption::OobInline:
            case ryu_ldn::bsd::SocketOption::ReusePort:
            case ryu_ldn::bsd::SocketOption::SndBuf:
            case ryu_ldn::bsd::SocketOption::RcvBuf:
            case ryu_ldn::bsd::SocketOption::SndLoWat:
            case ryu_ldn::bsd::SocketOption::RcvLoWat:
            case ryu_ldn::bsd::SocketOption::SndTimeo:
            case ryu_ldn::bsd::SocketOption::RcvTimeo:
                // Accept but ignore these common options
                R_SUCCEED();

            default:
                break;
        }
    }

    // Accept but ignore unknown options (compatibility)
    AMS_UNUSED(level, optname, optval, optlen);
    R_SUCCEED();
}

Result ProxySocket::GetSockOpt(s32 level, s32 optname, void* optval, size_t* optlen) const {
    if (optval == nullptr || optlen == nullptr) {
        R_THROW(static_cast<s32>(Errno::Fault));
    }

    // Handle specific options
    if (level == static_cast<s32>(ryu_ldn::bsd::SocketOptionLevel::Socket)) {
        switch (static_cast<ryu_ldn::bsd::SocketOption>(optname)) {
            case ryu_ldn::bsd::SocketOption::Type:
                // SO_TYPE - return socket type
                if (*optlen >= sizeof(s32)) {
                    *reinterpret_cast<s32*>(optval) = static_cast<s32>(m_type);
                    *optlen = sizeof(s32);
                    R_SUCCEED();
                }
                break;

            case ryu_ldn::bsd::SocketOption::Error:
                // SO_ERROR - return 0 (no error)
                if (*optlen >= sizeof(s32)) {
                    *reinterpret_cast<s32*>(optval) = 0;
                    *optlen = sizeof(s32);
                    R_SUCCEED();
                }
                break;

            case ryu_ldn::bsd::SocketOption::Broadcast:
                // SO_BROADCAST - return broadcast flag
                if (*optlen >= sizeof(s32)) {
                    *reinterpret_cast<s32*>(optval) = m_broadcast ? 1 : 0;
                    *optlen = sizeof(s32);
                    R_SUCCEED();
                }
                break;

            default:
                break;
        }
    }

    // Unknown option - return not supported
    R_THROW(static_cast<s32>(Errno::NoProtoOpt));
}

// =============================================================================
// TCP-specific Operations
// =============================================================================

Result ProxySocket::Listen(s32 backlog) {
    AMS_UNUSED(backlog);

    // Must be TCP
    if (m_type != ryu_ldn::bsd::SocketType::Stream) {
        R_THROW(static_cast<s32>(Errno::OpNotSupp));
    }

    // Must be bound
    if (m_state == ProxySocketState::Created) {
        R_THROW(static_cast<s32>(Errno::Inval));
    }

    m_state = ProxySocketState::Listening;
    R_SUCCEED();
}

std::unique_ptr<ProxySocket> ProxySocket::Accept(ryu_ldn::bsd::SockAddrIn* out_addr) {
    // Must be listening
    if (m_state != ProxySocketState::Listening) {
        return nullptr;
    }

    // Check if non-blocking and no connections available
    {
        std::scoped_lock lock(m_queue_mutex);
        if (m_accept_queue.empty()) {
            if (m_non_blocking) {
                // EWOULDBLOCK
                return nullptr;
            }
        } else {
            // Connection available - return it
            auto accepted = std::move(m_accept_queue.front());
            m_accept_queue.pop_front();

            if (m_accept_queue.empty()) {
                m_accept_event.Clear();
            }

            if (out_addr != nullptr) {
                *out_addr = accepted->GetRemoteAddr();
            }

            return accepted;
        }
    }

    // Blocking wait for connection. Bounded for the same reason as
    // RecvFrom's blocking wait -- a single thread services all ldn:u+bsd:u
    // IPC, so an unconditional Wait() here would freeze everything until a
    // connection arrives (or forever).
    constexpr TimeSpan AcceptBlockTimeout = TimeSpan::FromSeconds(5);
    m_accept_event.TimedWait(AcceptBlockTimeout);

    // Try again after waking up (or timing out)
    {
        std::scoped_lock lock(m_queue_mutex);
        if (!m_accept_queue.empty()) {
            auto accepted = std::move(m_accept_queue.front());
            m_accept_queue.pop_front();

            if (m_accept_queue.empty()) {
                m_accept_event.Clear();
            }

            if (out_addr != nullptr) {
                *out_addr = accepted->GetRemoteAddr();
            }

            return accepted;
        }
    }

    // No connection (spurious wakeup or shutdown)
    return nullptr;
}

void ProxySocket::IncomingConnection(const ryu_ldn::protocol::ProxyConnectRequest& request) {
    // Only accept on listening sockets
    if (m_state != ProxySocketState::Listening) {
        return;
    }

    std::scoped_lock lock(m_queue_mutex);

    // Create a new socket for the accepted connection
    auto accepted = std::make_unique<ProxySocket>(m_type, m_protocol);

    // Set local address (same as listening socket). Read via GetLocalAddr()
    // (not the raw field): this runs on the tunnel run-loop thread, while
    // the listening socket's m_local_addr could in principle still be
    // written concurrently on the MITM IPC thread.
    accepted->m_local_addr = GetLocalAddr();
    accepted->m_state = ProxySocketState::Bound;

    // Set remote address from request
    // CRITICAL: Do NOT bswap32 the IP - must match Ryujinx/NetworkInfo format
    accepted->m_remote_addr.sin_family = static_cast<uint8_t>(ryu_ldn::bsd::AddressFamily::Inet);
    accepted->m_remote_addr.sin_len = sizeof(ryu_ldn::bsd::SockAddrIn);
    accepted->m_remote_addr.SetAddr(::slp::net::IpV4::FromNumeric(request.info.source_ipv4));
    accepted->m_remote_addr.sin_port = __builtin_bswap16(request.info.source_port);

    // Mark as connected
    accepted->m_state = ProxySocketState::Connected;

    // Add to accept queue
    m_accept_queue.push_back(std::move(accepted));

    // Signal that a connection is available
    m_accept_event.Signal();

    // Send ProxyConnectReply back to the peer via ProxySocketManager
    // This confirms the connection was accepted
    auto& manager = ProxySocketManager::GetInstance();
    // m_local_addr holds NETWORK order; .Addr().Numeric() gives the tunnel form (Bind() stores it
    // without a bswap -- see the comment at the top of SendTo). GetAddr()
    // bswap32's, which assumes network byte order, so using it here produced a
    // byte-reversed local IP in the ProxyConnectReply (10.13.37.2 -> 2.37.13.10)
    // while remote_ip below is taken raw from the wire. Read it raw, matching
    // how SendTo builds source_ip.
    uint32_t local_ip = m_local_addr.Addr().Numeric();
    uint16_t local_port = m_local_addr.GetPort();
    uint32_t remote_ip = request.info.source_ipv4;
    uint16_t remote_port = request.info.source_port;

    manager.SendProxyConnectReply(local_ip, local_port, remote_ip, remote_port,
                                   ryu_ldn::bsd::ProtocolType::Tcp);
}

void ProxySocket::HandleConnectResponse(const ryu_ldn::protocol::ProxyConnectResponse& response) {
    // Store the response
    m_connect_response = response;
    m_connect_response_received = true;

    // Signal that connect response arrived
    m_connect_event.Signal();
}

bool ProxySocket::HasPendingConnections() const {
    std::scoped_lock lock(m_queue_mutex);
    return !m_accept_queue.empty();
}

// =============================================================================
// Shutdown and Close
// =============================================================================

Result ProxySocket::Shutdown(ryu_ldn::bsd::ShutdownHow how) {
    std::scoped_lock lock(m_state_mutex);
    switch (how) {
        case ryu_ldn::bsd::ShutdownHow::Read:
            m_shutdown_read = true;
            break;
        case ryu_ldn::bsd::ShutdownHow::Write:
            m_shutdown_write = true;
            break;
        case ryu_ldn::bsd::ShutdownHow::Both:
            m_shutdown_read = true;
            m_shutdown_write = true;
            break;
        default:
            R_THROW(static_cast<s32>(Errno::Inval));
    }

    // Signal any blocked receivers
    m_receive_event.Signal();

    R_SUCCEED();
}

Result ProxySocket::Close() {
    ryu_ldn::bsd::SockAddrIn local_addr_copy, remote_addr_copy;
    ryu_ldn::bsd::ProtocolType protocol_copy;
    {
        std::scoped_lock lock(m_state_mutex);
        m_state = ProxySocketState::Closed;
        m_shutdown_read = true;
        m_shutdown_write = true;
        local_addr_copy = m_local_addr;
        remote_addr_copy = m_remote_addr;
        protocol_copy = m_protocol;
    }

    // Signal any blocked receivers
    m_receive_event.Signal();

    // Clear ring queue (no deallocation — just reset indices)
    {
        std::scoped_lock lock(m_queue_mutex);
        m_rx_head = 0;
        m_rx_tail = 0;
        m_rx_count = 0;
    }

    // For TCP, send ProxyDisconnect to notify the peer. Not called with
    // m_state_mutex held: SendProxyDisconnect() may run a callback that
    // sends data, and this socket is already fully marked Closed above, so
    // nothing is lost by releasing first.
    if (protocol_copy == ryu_ldn::bsd::ProtocolType::Tcp && remote_addr_copy.GetPort() != 0) {
        auto& manager = ProxySocketManager::GetInstance();
        uint32_t local_ip = local_addr_copy.GetAddr();
        uint16_t local_port = local_addr_copy.GetPort();
        uint32_t remote_ip = remote_addr_copy.GetAddr();
        uint16_t remote_port = remote_addr_copy.GetPort();

        manager.SendProxyDisconnect(local_ip, local_port, remote_ip, remote_port,
                                     ryu_ldn::bsd::ProtocolType::Tcp);
    }

    R_SUCCEED();
}

// =============================================================================
// Event Handling
// =============================================================================

bool ProxySocket::HasPendingData() const {
    std::scoped_lock lock(m_queue_mutex);
    return m_rx_count > 0;
}

size_t ProxySocket::GetPendingDataSize() const {
    std::scoped_lock lock(m_queue_mutex);
    size_t total = 0;
    for (size_t i = 0, idx = m_rx_head; i < m_rx_count; i++) {
        total += m_rx_ring[idx].len;
        idx = (idx + 1) % PROXY_SOCKET_MAX_QUEUE_SIZE;
    }
    return total;
}

bool ProxySocket::WaitForData(u64 timeout_ms) {
    if (HasPendingData()) {
        return true;
    }

    if (timeout_ms == 0) {
        m_receive_event.Wait();
        return true;
    } else {
        return m_receive_event.TimedWait(TimeSpan::FromMilliSeconds(timeout_ms));
    }
}

} // namespace ams::mitm::bsd
