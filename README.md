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