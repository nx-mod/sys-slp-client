# M1 protocol spike — results & findings (2026-08-13)

## Method
Two simulated players (A=192.168.1.10, B=192.168.1.20) talking to a local
`slp-server-rust` over UDP, validating the slp wire format end-to-end.

## Final result
**5/5 PASS on a fresh server** (`tools/run-spike.sh 11554`): ping echo,
keepalive, A->B unicast, B->A reply, A broadcast.

The earlier "flaky ping / routing" failures were TEST BUGS, not protocol
issues:
- Ping assertion compared the wrong bytes (tag `0x01020304` packs to
  `02 04 03 02 01`, not `02 01 02 03 04`).
- The `ping()` helper returned only the 4 payload bytes while `ping_ok`
  holds the full 5-byte datagram (incl. the `0x02` type byte).
Both fixed; the server echoes pings verbatim as expected.

Remaining genuine server behaviors to design around:
- stale IP->sockaddr map (below), and
- run spikes against fresh servers, never a long-lived one.

## Findings

### 1. Keepalive registers the peer — nothing else does
The server only knows a peer after it sends a parseable non-ping datagram.
A player that never sends anything is invisible to broadcasts. Fix applied:
both clients keepalive at init. Matches real clients (keepalive every 10s).

### 2. Ping is NOT wire-compatible between TS and Rust servers
- TS: `[0x02]+3B`, echoes 4 bytes.
- Rust: `[0x02]+4B`, echoes 5 bytes (stricter parse: 4B payload min/max).
- Real lan-play clients never ping. Our module: rely on keepalive; ping is
  optional liveness and must target the server flavour (or be disabled).

### 3. Stale IP->sockaddr map black-holes first frames after reconnect (server bug)
The Rust server's `map` (virtual-IP -> UDP sockaddr) is never pruned. A client
reusing an inner IP after reconnect is unicast to its OLD dead socket until it
sends a frame refreshing the entry. Observed: A->B unicast delivered on a
fresh server, silently dropped on a server that had processed a prior run.

### 4. Dynamic whitelist overlay — REMOVED (2026-08-17)
This section originally (2026-08-14) documented a Tesla overlay whitelist
(L/R/X/Y buttons, `options.conf bsd_whitelist=`) for per-game bsd:u gating.
**The whole mechanism has since been removed** — see `notes/whitelist-design.md`
for what replaced it (a program_id-based applet-exclusion floor, no config).
Consequence noted at the time still applies regardless: run spikes against
fresh servers; the transport should force a map refresh (keepalive + periodic
broadcast) and be resilient to first-frame loss (games already retransmit
discovery).

### 5. Plugin side-channels
The server's `ldn_mitm` plugin broadcasts a scan from `172.10.13.37` to
`0.10.13.255` every 5s — LDN room-scan advertisement, not game traffic.
Our client must ignore frames from that source IP.

**Unverified as of 2026-08-17**: the actual on-console trace shows this
broadcast arriving from `10.13.37.0`, not `172.10.13.37` — the address here
may itself be stale/mistyped relative to the current `10.13.0.0/16` scheme.
Investigated 2026-08-17: no evidence the client currently mishandles this
(the broadcast is a scan REQUEST, type 0, which only triggers a reply — it
never populates scan RESULTS, so it can't be mistaken for a joinable network).
See `[[lan-mode-proven-state]]` in memory.

### 6. Debug tooling
`tools/dbg_slp.py <port>` prints every datagram sent/received with hex —
useful when a test fails to tell "not received" from "received but wrong".

## Open items
- Module transport must force a map refresh on (re)connect (keepalive +
  periodic broadcast) to work around the server's stale-map black-holing,
  and filter LDN scan frames (src == 172.10.13.37) in the lwIP ingress path.

## Commands
```
# fresh server + spike
tools/run-spike.sh 11552

# manual debugging
./slp-server-rust/target/release/slp-server-rust -p 11552 &
RUST_LOG=debug ...   # peer/route debug lines
python3 tools/dbg_slp.py 11552
```
