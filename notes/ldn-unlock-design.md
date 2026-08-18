# Local-Wireless unlock: ldn:u control-plane MITM over the slp tunnel

Status: DESIGN (spike-proven). Research 2026-08-14 (switchbrew LDN_services
wiki, ryu_ldn_nx README + sysmodule, ldn_mitm source at
`/home/nx-mod/switch/ldn_mitm`, ryu_ldn_nx sysmodule at
`/home/nx-mod/switch/ryu_ldn_nx/sysmodule`).
Goal: make the ~198 Local-Wireless-only titles play over the same slp relay,
self-contained (no PC), without touching the server.

**Spike status (2026-08-14): the full control plane is proven end-to-end over a
stock relay — `spike/test_ldn.py` 9/9 passing (3x consecutive, 25x in a debug
loop). See "Spike verification" below.**

**M2 build status (2026-08-14): the control-plane MITM is now implemented and
compiles with devkitA64** (`make` in `sysmodule/`, output `sys-slp-client.nso`
~260 KB):

- `ldn/ldn_control.{hpp,cpp}` — `LdnControl` singleton: full LAN control codec
  (12-byte `LANPacketHeader`, magic `0x11451400`, RLE compress/decompress —
  byte-identical port of ldn_mitm `lan_protocol.cpp`) + the
  AP/Station state machine (port of `lan_discovery.cpp`), transport replaced by
  the tunnel (`::slp::tun::Send`), inbound frames dispatched from the run-loop
  thread via `OnControlFrame(src_ip, payload, len)`.
- `ldn/ldn_icommunication.{hpp,cpp}` — `ICommunicationInterface` IPC backed by
  the singleton (Initialize/InitializeSystem2/Finalize, OpenAccessPoint/
  CreateNetwork/DestroyNetwork/SetAdvertiseData, OpenStation/Scan/Connect/
  Disconnect, GetState/GetNetworkInfo/GetIpv4Address/GetDisconnectReason/
  GetSecurityParameter/GetNetworkConfig/AttachStateChangeEvent/
  GetNetworkInfoLatestUpdate). `AttachStateChangeEvent` hands out the global
  `os::SystemEvent` readable handle.
- `tunnel/slp_tunnel.cpp` — `ProcessIpv4` now consumes datagrams whose
  `dport == ControlPort` (11452) into `LdnControl::OnControlFrame` instead of
  the bsd proxy (games never bind that port).
- `ldn/ldn_mitm_service.{hpp,cpp}` — `ShouldMitm()` returns true only while the
  relay is `SLPCFG_STATE_RUNNING` (stopped → forwarded to the real ldn:u,
  stock local-wireless keeps working); `CreateUserLocalCommunicationService`
  now serves `LdnICommunicationService` instead of forwarding.
- `main.cpp` — `LdnControl::GetInstance().Initialize()` at boot (before any
  game can open ldn:u).

**Port notes learned (encode in tests on console):**

1. **Byte order: spike ≠ ldn_mitm on the wire.** The Python spike
   (`slp_ldn.py`) encodes the LAN header/body big-endian (and its RLE is
   length-prefixed), so it proves the *state-machine flow* only. The C++ port
   uses ldn_mitm's **native packed layout** (`sizeof(LanPacketHeader) == 12`,
   `static_assert sizeof(NetworkInfo)==0x480 / sizeof(ConnectNetworkData)==0x7C
   / sizeof(ScanFilter)==0x60`), which is the byte layout a real ldn_mitm +
   PC-bridge peer emits. Interop with ldn_mitm peers must be validated on the
   wire against a real ldn_mitm room, not the spike.
2. **Scan filter's LocalCommunicationId is `u64`** (`m_scan_filter_lcid`),
   matching the spike and ryu_ldn_nx (`LocalCommunicationId` is a 64-bit title
   id), not ldn_mitm's `u32`.
3. **Station node IP = tunnel src IP.** On `Connect`, the host stamps the
   station's `NodeInfo.ipv4Address` with the tunnel `src_ip` seen on the frame
   (Ryujinx format) and the matching fake MAC — so `GetIpv4Address()` /
   `NetworkInfo.ldn.nodes[]` agree and Pia's `FindLocalNodeId()` works, and the
   bsd data plane sees sockets bound inside 10.13.37.0/24.
4. **No stale-station reaping yet.** Because the UDP tunnel has no per-station
   connection-close signal, a peer that drops without leaving the room stays in
   the host's node list until `CloseAccessPoint`/`DestroyNetwork`/
   `resetStations`. Open question #3 below stays open; a lease/timeout is a
   follow-up.
5. **Scan/Connect block ~1 s on the IPC thread** (mirroring ldn_mitm's
   `svcSleepThread(1s)` window for the run-loop thread to collect responses);
   do not hold `m_mutex` across the sleep (it is released before the
   broadcast / unicast send).


## The key fact (switchbrew LDN_services wiki)

> "This does not use DHCP, each node on the network has to manually setup
> IP-config with the NodeInfo array in NetworkInfo. ... **At this point standard
> sockets can be used over Data frames.**"

`ldnGetIpv4Address` returns an `LdnIpv4Address` described by libnx as
"essentially the same as struct in_addr - hence this can be used with standard
sockets".

**Consequence:** once an LDN network is formed (via `ldn:u`), the game's Pia
mesh/session traffic runs over **normal `bsd:u` UDP/TCP sockets** bound to the
LDN-assigned 10.13.37.x address. That traffic is byte-identical in shape to the
LAN-mode data plane we already MITM and tunnel.

`ryu_ldn_nx` (reference, Ryujinx side) confirms the exact split:

> 1. `ldn:u` MITM — intercepts the LDN user service, synthesizes NetworkInfo /
>    node ids from server responses.
> 2. `bsd:u` MITM — sockets that bind/connect to the LDN subnet are tracked as
>    proxy sockets and their traffic is tunneled. **This is how gameplay
>    traffic reaches other peers without pcap.**

So the Local-Wireless unlock is **control-plane only**: the data plane is
already handled by our existing `bsd:u` MITM + tunnel.

## Architecture

```
bsd:u path  (25 LAN-mode games)   — already done, proven locally
ldn:u path  (198 LW-only games)   — NEW: control-plane MITM, data rides bsd:u

Game (LW-only) ─ ldn:u IPC → our ldn:u MITM (control: scan/create/connect/IP)
                    │
                    │ control frames (LAN protocol: Scan/ScanResp/Connect/SyncNetwork)
                    ▼
                 our tunnel ──(UDP on control port, e.g. 11452)──→ slp server
                    │                                              (room relay)
                    ▼
Game Pia mesh ── bsd:u sockets on 10.13.37.x ── existing bsd:u MITM ── tunnel
                    (broadcast 10.13.37.255, ports 49152+ / 30000)
```

The slp server is unchanged: both control frames and game data are just UDP
frames in the room, exactly like LAN-mode traffic. Consoles on our stack and
consoles on `ldn_mitm` + PC bridge (or PC rawsock clients) all speak the same
slp Ipv4/UDP framing, so they can share a room.

## What we port from ldn_mitm (control plane only)

From `/home/nx-mod/switch/ldn_mitm/ldn_mitm/source/`:
- `ldn_types.hpp`            — LDN structs (NetworkInfo, NodeInfo, UserConfig,
                               SecurityConfig, NetworkConfig, LdnIpv4Address).
- `lan_protocol.{hpp,cpp}`   — LAN control codec (LANPacketHeader, magic
  0x11451400, Scan/ScanResp/Connect/SyncNetwork, compress/decompress).
- `lan_discovery.{hpp,cpp}`  — LDN state machine (AP/Station, scan results,
  node tables, fake SSID/MAC, worker loop).
- `ldn_icommunication.{hpp,cpp}` + `interfaces/icommunication.hpp` —
  `IUserLocalCommunicationService` IPC surface the game calls.
- `ipinfo.{hpp,cpp}`         — IP config helpers (we override to use our
  slp-assigned 10.13.37.x IP instead of nifm).
- `ldnmitm_service.{hpp,cpp}` — AMS mitm server plumbing (adapted to our
  sysmodule's service server).

**Primary port reference: `/home/nx-mod/switch/ryu_ldn_nx/sysmodule/source/ldn/`**
is a complete, maintained sysmodule implementation of this exact split
(`ldn_icomcommunication.cpp`, `ldn_node_mapper.cpp`, `ldn_packet_dispatcher.cpp`,
`ldn_proxy_handler.cpp`, `ldn_session_handler.cpp`, `ldn_state_machine.cpp`,
`ldn_shared_state.cpp`, `ldn_mitm_service.cpp`, `ldn_types.hpp`). Use it for the
IPC surface + state machine; use ldn_mitm only for the LAN codec
(lan_protocol/lan_discovery). Transport stays ours (tunnel, not sockets).

## The transport seam

ldn_mitm's LAN protocol carries control over real sockets to a PC bridge
(`UdpLanSocketBase` broadcast for scan, `TcpLanSocketBase` per-station for
Connect/SyncNetwork). We keep that codec but **replace the sockets with our
tunnel**:

- `sendto`/`recvfrom` for control → our `slp_tunnel::Send`/Recv path, carrying
  the LAN-protocol frames as UDP on a dedicated control port (e.g. 11452).
- Scan broadcast → tunnel broadcast (all room members receive, our
  FindAllSocketsByDestination semantics).
- Connect (TCP in original) → unicast UDP control frames through the tunnel to
  the host's virtual IP. The per-station "connections" become logical nodes in
  our state machine, not real TCP fds.
- The host's `NetworkInfo` (node list, per-node IPs) is propagated by
  SyncNetwork frames through the room, keeping all consoles consistent.

`lan_protocol.hpp` already virtualises the transport
(`virtual ssize_t recvfrom(...)` / `virtual int sendto(...)`), so we subclass a
`TunnelLanSocket` — the codec + state machine need no changes.

## Consistency requirements (from ryu_ldn_nx)

- `GetIpv4Address()` must return **our tunnel's virtual IP** (10.13.37.x from
  the slp server), identical to the src-IP we rewrite on game data — so the
  game's sockets bind to an IP that is genuinely ours on the virtual LAN.
- `NetworkInfo.ldn.nodes[].ipv4Address` entries must be the same 10.13.37.x
  space so broadcast/mesh addressing is consistent.
- Broadcast UDP must be delivered to **all** matching proxy sockets (we already
  do `FindAllSocketsByDestination`).

## Build/install notes

- Add `ldn:u` MITM server to our sysmodule service server (parallel to
  `slp:cfg` and the existing `ldn:u` forwarder — the forwarder is skipped while
  our MITM claims the service).
- Heap: add ldn_mitm's thread stack (0x4000) + worker; keep 512 KB budget in
  mind, bump if needed.
- Keep sysmodule stdio-free in boot2 context (`ams::fs::` only); ldn_mitm's
  `LogFormat` maps to our `slp::dbg::Trace`.

## Local verification plan (no console)

Extend `spike/` to emulate the LDN control plane over the live relay, mirroring
the existing browse→join e2e:

1. Two virtual consoles each run an LDN state machine over the tunnel.
2. Host `CreateNetwork` → broadcasts its NetworkInfo (ScanResp-capable).
3. Client `Scan` → receives host's NetworkInfo over the relay.
4. Client `Connect` → host accepts → SyncNetwork propagates node list; both
   sides now have consistent 10.13.37.x node tables.
5. Post-join: game data flows via the existing Pia packet e2e (already proven).

## Spike verification (2026-08-14)

`spike/slp_ldn.py` (LDN codec + virtual console state machine) +
`spike/test_ldn.py` prove the full flow through an **unmodified**
`slp-server-rust` relay:

- host `OpenAccessPoint`+`CreateNetwork` → client `Scan` (broadcast
  Scan/ScanResp) → `Connect` → `SyncNetwork` → `StationConnected`
- host assigns the station node id 1; `nodeCount == 2` on both sides
- the 1152-byte NetworkInfo round-trips byte-identical; RLE-compressed on the
  wire (matches ldn_mitm's `LANPacketHeader`/`compress` codec)
- host + client node tables consistent; host-side IPs verified at host, client,
  and shared-NetworkInfo layers

### Bugs found and fixed in the spike

1. **Host node-list bug (the last flake, `IndexError` at test_ldn.py:213).**
   `_update_nodes()` bumped `network_info["node_count"]` on a joining station
   but never appended the station's NodeInfo to `network_info["nodes"]` on the
   host side. Fix: rebuild the node list as `[node0] + connected stations in
   node_id order`. This mirrors the real requirement: the game's
   `GetNetworkInfo()` must return a complete, consistent `nodes[]` or
   `FindLocalNodeId()` fails.
2. **Stale-AP cross-talk.** A node from a previous test kept answering the next
   test's scan. Fix: `scan(local_comm_id=...)` filters ScanResp by intentId —
   mirror of ldn_mitm's `ScanFilter` (ScanFilterFlag_LocalCommunicationId).
3. **Thread/socket teardown.** `LdnNode.close()` sets a `_closed` Event that
   stops the recv + auto-step threads and closes the socket, so a node actually
   leaves the room between tests.

### Test hygiene now encoded in the suite

- distinct IP ranges per test (`_ip(0..1)`, `_ip(10..12)`) and a fresh random
  /24 per run — works around the relay's never-pruned IP→peer cache (reused
  inner IPs black-hole the first frames)
- keepalive before state transitions; every node `close()`d on exit

### Verified divergences from ldn_mitm (document for the sysmodule port)

1. **No Disconnect frame over UDP.** ldn_mitm's host uses per-station TCP
   connections whose closure is observable; our UDP-tunneled control plane has
   no such signal, so a host keeps stale station entries until the node drops
   the room. Port must handle stale-station cleanup explicitly (timeout or
   node-leave detection).
2. **Host assigns station node ids.** There is no TCP accept order to derive
   ids from; the host must assign them (incrementing, reusing lowest-free).
3. **Control frames are processed inline on the relay run-loop thread** via the
   existing `slp::tun::OnFrame(type, buf+1, n-1)` hook — no dedicated worker
   thread, no real sockets (the codec's `sendto`/`recvfrom` are replaced by
   tunnel Send + a per-room RX dispatch).

### Data-plane coupling constraint (pinned)

The bsd:u MITM already proxies sockets bound/connected to `10.13.37.0/24`
(`bsd_types.hpp`: `LAN_NETWORK_BASE = 0x0A0D2500`, `IsLanAddress` in host byte
order). **LdnControl must therefore assign node IPs inside 10.13.37.0/24** so
the game's post-join sockets (bound to the LDN-assigned IP) hit the existing
data-plane proxy. Broadcast 10.13.37.255 already routes to all matching proxy
sockets (`FindAllSocketsByDestination`).

### IP byte order (ryu_ldn_nx rule, confirmed)

PIA games call `GetIpv4Address()` and `GetNetworkInfo()` separately and match
the IP from the former against `NetworkInfo.ldn.nodes[].ln`. A mismatch makes
`FindLocalNodeId()` return 0xFF and the game breaks. Their sysmodule
(`ldn_node_mapper.cpp`) does `ipv4_address = node.ln` with `ln` **not**
bswapped. Our tunnel virtual IP must equal the node's `ipv4Address` byte-for-
byte. (The spike asserts this equality on both sides.)

## Open questions (console test needed later)

1. Whether games need `ldn:u` `ScanPrivate`/`CreateNetworkPrivate`
   (`ldnSetProtocol`, action frames) — ldn_mitm stubs these; ryu_ldn_nx notes
   some games (ARMS) use odd LocalCommunicationId handling.
2. `GetIpv4Address()` consistency across titles: the spike proves equality with
   the NetworkInfo node entry; real games also do an accept/routing check that
   may need the src-IP rewrite on data frames to match the node entry (already
   true on our bsd path).
3. Stale-station cleanup: how aggressively hosts must reap dead nodes when a
   peer crashes without leaving the room (relay session semantics).
