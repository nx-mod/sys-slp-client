# tekn0.net online-server test (2026-08-15) — our client vs. a good server

## Why this test matters (context)

Reference stack that works: `ldn_mitm` on Switch -> `switch-lan-play` PC client on
local network -> **tekn0.net:11451** (online slp relay). We cannot run a PC client,
so we are re-implementing both halves inside the sys-slp-client sysmodule (no middle
man). The correct validation of OUR client is to point it at a **real, good server**
that already works with ldn_mitm + PC client — that server is tekn0.net.

Earlier session blamed the fake/demo host for failures. That framing was wrong for
this test: tekn0.net is a production server with real ldn_mitm users, so an empty
lobby there is a finding about **our control plane**, not about the host.

## Key fact: tekn0.net runs the same server as ours

`config/servers.conf` entry: `tekn0  tekn0.net:11451` (3 active / 1 idle users).

Our local relay `slp-server-rust` ships an `ldn_mitm` plugin that is byte-identical
to what tekn0.net serves:
- `src/plugin/ldn_mitm/constants.rs`: `LDN_MITM_PORT=11452`, `SERVER_ADDR=10.13.37.0`,
  `BROADCAST_ADDR=10.13.255.255`, `SCAN_PACKET` = 12-byte LAN header (magic
  `0x11451400`, type 0=Scan, compressed=0).
- Plugin `send_broadcast(slp_scan_packet())` every **5s** (a 41-byte relay frame:
  type 0x01 + 20B IPv4 + 8B UDP + 12B scan). Source 10.13.37.0, dst 10.13.255.255,
  sport/dport 11452.
- Plugin `in_packet`: records `RoomInfo` when a peer sends `LanPacket::ScanResp`
  (type 1) with a parseable `NetworkInfo` to `SERVER_ADDR` — i.e. it is the
  **host advertisement** the server surfaces in its status/RPC.

So "does the server do X" is answerable from our own `slp-server-rust` source;
tekn0.net and our local relay behave the same.

## What the test showed (trace /tmp/slp-trace-20260815-005415.log)

The trace contains multiple boot sessions; `host=` per session is the server that
boot used. tekn0.net sessions are at lines with `runtime: open ok host=tekn0.net
port=11451` (e.g. lines 6430, 47391, 59776, 63969, 63975, 64574).

## Which mode was tested

User ran MK8DX in **WIFI (LDN) mode** against tekn0.net — the game offers both LAN
and WIFI modes, and **LAN mode crashes on tekn0 while WIFI does not**. The tekn0
test result "no crash + empty lobby" is therefore about the LDN/control-plane path.
Treat "LAN mode crashes on tekn0" as a separate, real observation to chase later.

Observed during the WIFI (LDN) test:
- `ldn: Initialize ip=10.13.37.2` at every boot.
- `mitm: accept ldn client` -> `OpenStation` -> `local network mode SKIPPED
  (relay tunnel keeps internet link)` x5, then `CloseStation` x5, then
  `OpenAccessPoint` + `CreateNetwork` (game gave up scanning and tried to host).
- One early session (pid 0x8a) DID take the other branch: `local network mode
  enabled (MTU saved=1400)`.
- The server's periodic scan WAS received on-device: `run: recv type=0x1 len=41`
  at ms[114522] — exactly the 41-byte ldn_mitm plugin broadcast. Tunnel RX to the
  control plane works against the real server.
- MK8DX then did its normal socket dance: fd=0 bind 49152, fd=1 bind 40000,
  fd=2 bind 30000 (all `using local LDN IP 0x0a0d2502` = 10.13.37.2), and a
  873-byte `BSD SendTo fd=2 proxy sent` browse.
- No crashes. Empty lobby list.

## What it means / open items

1. **Tunnel + control-plane RX is proven**: the 41-byte server scan arrived and was
   dispatched. The LDN shim is not broken at the transport level.
2. **BLIND SPOT NOW FIXED (2026-08-15 build)**: added Trace logging to the control
   plane — `Scan()` entry (broadcast dst + filter lcid), `SendFrame()` ok/FAILED
   (type+dst+len), `OnControlFrame` header decode (BAD_MAGIC/SHORT/DECOMPRESS_FAIL/
   BAD_DECOMPRESS_LEN + every valid frame), `HandleScan` (src+state), `HandleScanResp`
   (BAD_LEN / lcid-mismatch DROP reason / collect count), `Scan()` result summary.
   Release build compiles them in (SLPCFG_DEBUG_TRACE is set in Makefile).
3. **Subnet broadcast aligned to /16**: `m_subnet_mask` changed 0xFFFFFF00 ->
   0xFFFF0000 (constructor + Initialize) so `SubnetBroadcast()` = 10.13.255.255,
   matching the server plugin's `BROADCAST_ADDR` and switch-lan-play config.h
   (`SUBNET_MASK 255.255.0.0`, `SUBNET_NET 10.13.0.0`). Real ldn_mitm peers use the
   same /16 space.
4. **Interop is on the wire, not the spike**: `notes/ldn-unlock-design.md` warns
   spike byte-order != ldn_mitm wire order. Our C++ port uses ldn_mitm's native
   packed layout (LANPacketHeader 12B, NetworkInfo 0x480). Validating against
   tekn0.net real rooms is the only true interop test.

## Follow-up: hosted-lobby test on the local relay (trace 012633, server log PID 17090)

User hosted a MK8DX WIFI lobby against the local relay (`10.172.227.113:11451`) on
the instrumented + /16-fixed build, then left the lobby (state returned to 0).
Every control-plane hop is now confirmed ON THE WIRE (client-side trace +
server-side `recv Ipv4` in /tmp/slp-server.log):

- Our **Scan broadcast leaves**: server saw `Ipv4 10.13.37.2 -> 10.13.255.255`,
  sport/dport 11452, payload `00 14 45 11` (LAN magic) type 0, 12B — x3
  (matches the game's 3 OpenStation scans). `Scan broadcast to 0x0a0dffff` =
  /16 fix works.
- Server's **5s scan broadcast is received**: `run: recv type=0x1 len=41` ->
  `OnControlFrame src=0x0a0d2500 type=0 len=12` -> `HandleScan` — every ~5s,
  even in idle state=0.
- **Host advertisement leaves**: while hosting (state=3) our client replied to
  server scans with `SendFrame(type=1 dst=0x0a0d2500 len=256 ok)`; server saw
  `Ipv4 10.13.37.2 -> 10.13.37.0 (SERVER_ADDR)` 264B, magic + type 1 + compressed
  + decompress_len `128 04` (0x480 = sizeof NetworkInfo) — x3. This is exactly
  the `LanPacket::ScanResp` the plugin records into RoomInfo.
- `Scan done results=0` was CORRECT: demo_host is dead, no other MK8DX peer was
  on the relay, so nothing could answer our scan.
- No crash; keepalives + tunnel stayed up the whole session.

Conclusion: the sysmodule control plane is now complete and correct on its own
side. What is NOT yet validated is cross-peer interop (another MK8DX console's
ScanResp reaching us / our ScanResp reaching it via the relay).

## Next validation step (pending user)

1. Two clients on the local relay (second Switch, or Switch + PC lan-play
   client as a known-good peer) — expect `HandleScanResp` in our trace and a
   populated lobby. This is the cleanest test of the peer<->peer path.
2. OR MK8DX WIFI against tekn0.net when real rooms are present: the earlier
   "empty lobby on tekn0" predates the /16 fix — worth re-running now that scan
   broadcasts to 10.13.255.255.

## tekn0 WIFI re-test (trace 24940 lines, second session = tekn0 leg at line 2878)

- Session: `open ok host=tekn0.net port=11451` (ms[401583]) — but see the DNS
  caveat below; `open ok` does NOT prove reachability (UDP has no handshake).
- Game did 4x OpenStation -> `Scan broadcast to 0x0a0dffff` -> `results=0`, then
  `OpenAccessPoint`+`CreateNetwork`, LDN socket fd=0 bind 12345, `DestroyNetwork`.
- **ZERO inbound frames during the ENTIRE tekn0 leg (~192s, ~32 expected 5s
  broadcasts): no `run: recv type=0x1`, no OnControlFrame, no HandleScanResp.**
  Compare the LOCAL relay session in the same trace (line 34): server broadcasts
  arrived every ~5s. So against the local relay RX works, against tekn0 nothing
  arrived — the client was likely never registered as a peer on tekn0's server.
- **USER CORRECTION (important):** the earlier "success" of receiving the 41-byte
  server scan on tekn0 (005415 trace, ms[114522]) may have been a **LAN-mode
  attempt that crashed — NOT a WIFI session**. So the "RX works vs the real
  server" claim is unproven for WIFI. Treat tekn0 WIFI as: not yet confirmed to
  reach the server at all.
- DNS check (host side, same resolver code, /etc/resolv.conf path): tekn0.net ->
  192.241.238.136, SINGLE A record (no round-robin). Resolver logic verified
  correct via host probe of slp_client.c. But the SWITCH resolves via
  `nifmGetCurrentIpConfigInfo` DNS — unknown what it returned.
- **FIX DEPLOYED (build cca9f3c7):** `open ok` now also logs the resolved server
  IP (`ip=w.x.y.z`). Next tekn0 test will show whether the switch resolved
  192.241.238.136 or something wrong. If IP is right but still zero inbound,
  suspect peer registration / outbound UDP to that IP.

## Next steps

1. Reboot Switch to load build cca9f3c7.
2. WIFI mode vs tekn0; pull trace; check `open ok host=tekn0.net ip=` matches
   192.241.238.136.
3. If ip correct but no server broadcasts arrive -> verify outbound UDP:11451
   from the switch to 192.241.238.136 is actually going out / not NAT-blocked.

## Do NOT repeat

- Do not conclude "tunnel dead" from the LOCAL relay log when the test went to
  tekn0.net — tekn0 sessions never touch `10.172.227.113:11451`.
- Do not blame the demo host for failures observed against a production server.

## RESOLVED (2026-08-17): the DNS resolver built addresses byte-reversed

This note's own "DNS check" section above got close — it verified the HOST-side
resolver logic and found nothing wrong — but the actual bug was in
`dns_parse_response()` in `sysmodule/source/slp/slp_client.c`, which packed the
DNS A-record's RDATA (already network-byte-order) MSB-first into a `uint32_t`
(the NUMERIC form), then wrote that into `sockaddr_in::sin_addr`, which needs
network order. On this little-endian target that reversed the bytes: `tekn0.net`
(192.241.238.136) was contacted at **136.238.241.192** — a different, unrelated
host. The console transmitted into the void and never received a single packet
back, for every DNS-named relay, every time, all along.

This explains every symptom this note (and the following night's session)
struggled with: `open ok host=tekn0.net` succeeding (DNS lookup itself worked,
UDP has no handshake to fail), keepalives sending fine, zero inbound frames
ever, and the empty tekn0 lobby. It affected LAN control-plane traffic too, not
just LDN — the bug was at the relay-socket layer, below both.

Literal IP addresses (like `10.172.227.113` above) were never affected —
`inet_aton` already returns network order — which is exactly why the local
relay always worked and every DNS-named relay never did.

Fixed by copying the RDATA bytes straight through instead of packing them:
`memcpy(out, resp + pos + 10, 4)`. After the fix: ping echo from tekn0.net in
~100ms, hundreds of inbound frames, and real rooms (Diablo III, Advance Wars,
MK8DX wireless) registering on tekn0's public room list with no PC bridge. See
`[[lan-mode-proven-state]]` in memory for the full trace.
