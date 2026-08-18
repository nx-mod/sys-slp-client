# slp wire format (validated against slp-server-rust v3.0.0 + switch-lan-play TS server)

Every UDP datagram to/from an slp relay server:

    [1-byte header][payload]
      header bit7 (0x80) = encrypted flag (unused by clients), bits6-0 = type

## Types
| type | name        | payload                                    |
|------|-------------|--------------------------------------------|
| 0x00 | Keepalive   | (none) — also registers the peer          |
| 0x01 | Ipv4        | full IPv4 packet (src @ 12, dst @ 16)     |
| 0x02 | Ping        | server echoes the whole datagram back     |
| 0x03 | Ipv4Frag    | 16B header + chunk (see below)            |
| 0x04 | AuthMe      | 20B sha1 response + username              |
| 0x10 | Info        | server->client room info (RPC-ish)        |

## Keepalive
`b"\x00"` sent every ~10s. No reply. **Any parseable non-ping datagram
registers the sender as a peer in the server's cache.** A peer that has never
sent a datagram is invisible to broadcasts (this bit us in the spike: client B
received nothing until it had sent at least one keepalive).

## Ping — the two servers are NOT wire-compatible
- **TS server** (`switch-lan-play/server`): datagram is `[0x02]+3B` (4 total),
  echoes `msg.slice(0,4)` = same 4 bytes.
- **Rust server** (`slp-server-rust`): `Ping::MIN_LENGTH=4` applies to the
  payload, so datagram is `[0x02]+4B` (5 total); echoes `[0x02]+payload[0..4]`
  = same 5 bytes. A 4-byte ping fails to parse and is dropped.
- Real lan-play clients never send pings (not present in `lan-client.c`).
  Keepalive is the compatibility-critical path; ping is only a liveness probe.

## Ipv4 frame
`[0x01]` + 20B IPv4 header + transport. Server reads src/dst IPs from offsets
12/16 of the payload (i.e. 13/17 of the datagram). Checksum left 0 is accepted.

## Ipv4Frag frame
`[0x03]` + { src_ip[4], dst_ip[4], id[2], part[1], total_part[1],
len[2], pmtu[2] } + chunk. Sent when a frame exceeds the PMTU (~1400B).

## Server routing
1. Cache: src-IP -> peer sockaddr. Peer cache (by sockaddr) TTLs out after
   ~30s idle (peer task rx timeout) and peers are dropped after 5min idle.
2. If dst-IP is in the IP map -> unicast to that peer.
3. Else -> **broadcast to every other registered peer**.

### Stale-map quirk (real bug, affects reconnects)
The IP->sockaddr `map` is **never pruned**. If a client reconnects (new UDP
sockaddr) while reusing the same virtual IP, `map[that_ip]` still points at
the OLD dead socket, so unicast frames to it are silently black-holed until
the peer sends a frame with that src IP again (which refreshes the entry).
- Consequence for our module: the first frame after (re)connect may be lost.
  Games retransmit discovery/disconnect state, but our transport should also
  send a keepalive + periodic broadcast to force-refresh entries.
- For testing: always run the spike against a FRESH server (see run-spike.sh).

## ldn_mitm scan broadcast (Rust server plugin)
The server's `ldn_mitm` plugin broadcasts a magic scan packet every 5s from
`172.10.13.37` (SERVER_ADDR) to `0.10.13.255` — this is the LDN room-scan
advertisement, not game traffic. Ignore frames whose src == 172.10.13.37.

## Encryption
bit7 of the header marks encryption; nothing in the current clients uses it
(the TS server only refuses unencrypted `forwarder` frames — a legacy RPC
type we never send).
