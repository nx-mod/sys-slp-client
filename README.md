# sys-slp-client

Switch sysmodule for LAN/LDN multiplayer over an internet relay
— the console talks to the relay directly, no PC bridge.

**Status**: hosting and lobby visibility work (rooms show up, scans find
them). More real world two-console host/join testing is required.

## How it works

```
cfw + sysmodule ── UDP ──▶ Relay (slp-server) ◀── UDP ── cfw + sysmodule
```

One UDP socket to the relay carries everything. Two MITM intercepts ride on it:
- **`ldn:u`** — local-wireless API (LDN). `LdnControl` speaks
  LAN-protocol control frames (Scan/Connect/SyncNetwork, port 11452) over
  the relay, so games see rooms/peers same as real local wireless.
- **`bsd:u`** — raw LAN socket games. Sockets get transparently swapped
  for tunneled proxy sockets.

Neither intercept touches the game's own protocol content (Pia, ENL, etc.) —
that's intentional; the game's real stack builds/reads those bytes, we just
carry them unmodified.

Config lives on the SD card at `/config/slp-helper/` (relay server list,
virtual-IP persistence); the servers list is also editable from a Tesla
overlay in-game.

- **Virtual IP**: auto-assigned at random within the relay's address range
  (avoiding reserved sub-ranges), then persisted — not derived from the
  console's real IP, so two consoles behind different routers can't collide
  on the same address.
- **LDN vs LAN**: auto-detected per game, not configured — whichever
  service the game itself opens (`ldn:u` or `bsd:u`) is what gets handled;
  no manual mode switch.

## Build & deploy

```bash
cd sysmodule && make
```

## Testing

## Debug

- Trace log: `sdmc:/slp-trace.log` Every boot writes a
  banner line (`===== sys-slp-client vX.X.X build <id> =====`)
— the file appends across boots.

## Special thanks to

- https://github.com/spacemeowx2/ldn_mitm
- https://github.com/spacemeowx2/switch-lan-play
- https://github.com/spacemeowx2/slp-server-rust
- https://github.com/Ryubing/LdnServer
- https://github.com/dogty/ldn_mitm

## Untested fixes (built, not yet verified on hardware)

Landed but not yet retested on a real console — flagging so a regression
here is easy to trace back:

- `HandleSyncNetwork` now rejects a SyncNetwork frame whose network doesn't
  match the one `Connect()` actually targeted, instead of accepting any
  self-IP-confirmed sync regardless of source (foreign/stale session on a
  shared relay could previously corrupt an in-flight or already-established
  join).
- `Connect()` now reports a real failure (nn::ldn's own ConnectFailed code)
  after a genuine 3s timeout with no SyncNetwork from the host, instead of
  always reporting success and leaving the game to hang with no nodes.
- New peer-liveness mechanism: stations heartbeat the host every ~5s over
  the relay, the host reaps a station silent for 30s (and re-syncs the
  survivors), and a station similarly disconnects if the host goes silent
  for 30s. A clean disconnect (either side) now also sends an explicit
  goodbye frame so the other side reacts immediately instead of waiting
  out the timeout. None of this existed before — a dropped peer used to
  stay in the room forever.
- `HandleScanResp` now drops a scan result whose source is our own virtual
  IP (a relay can hand a broadcast back to its own sender), which could
  previously make a game attempt to join its own advertisement.