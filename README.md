# sys-slp-client

Switch sysmodule for LAN/LDN multiplayer over an internet relay — the console
talks to the relay directly, with no PC bridge.

## Current Status (2026-08-17)

**Working, verified on hardware:**
- LDN control plane (port 11452) — three independent games (Diablo III,
  Advance Wars, MK8DX wireless) create and register rooms correctly.
- **Public relay, no PC bridge**: rooms host and register on `tekn0.net`, a
  real production relay with real `ldn_mitm` + PC-client users. Tunnel is
  confirmed alive (ping echo ~100ms, hundreds of inbound frames).
- MK8DX LAN browse (port 30000): browse request → relay → browse reply →
  lobby lists, and the game proceeds to a real Pia join attempt (encrypted
  session traffic on port 49152, forwarded transparently, untouched by us).
- LAN <-> WiFi mode switching, no crashes.

**Not yet working:**
- Full LAN join completion needs a second real console — the repo's Python
  fake host (`spike/demo_host.py`) can answer a browse and start a join, but
  cannot complete real Pia session crypto for the join side.
- MK8DX LAN room registration on tekn0's separate LAN-lobbies page is
  untested against a real browsing peer (LAN rooms are passive — they only
  answer browse requests, they never self-advertise, so this needs someone
  actually browsing while we host).

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Switch    │────▶│   Relay     │◀───│   Switch    │
│  (sysmodule)│     │  (slp-server)│    │  (sysmodule)│
└─────────────┘     └─────────────┘     └─────────────┘
```

One UDP socket to the relay carries everything. Two independent MITM
intercepts ride on it:
- **`ldn:u`** — games using Nintendo's local-wireless API get a full LDN
  control-plane state machine (`LdnControl`, ported from `ldn_mitm`) that
  speaks LAN-protocol control frames over the relay.
- **`bsd:u`** — games doing raw LAN socket programming (MK8DX LAN mode) get
  their sockets transparently swapped for tunneled "proxy sockets."

Neither intercept understands the game's own protocol content (Pia, ENL,
etc.) — that's intentional. See `notes/compat-matrix.md` ("Key architectural
insight") and `notes/pia-session-layer-20260815.md`.

## Protocol Flow

1. **LAN Browse** (port 30000) — WORKING
   - Game sends browse request (873B) with crypto challenge
   - Relay forwards to other consoles
   - Host replies with browse reply matching search criteria
   - Root cause of the earlier 2618-0006 crash: `Send`/`SendTo` reported the
     bsd:u `{ret, errno}` reply in swapped slots, so every successful send
     looked like a failure to the game — nothing to do with PIA content. See
     `notes/TODO-uncross-bsd-out-params.md`.

2. **PIA Session Layer** (port 49152) — CORRECTLY NOT IMPLEMENTED, BY DESIGN
   - The game's own real Pia stack builds and reads every packet here; we
     forward the bytes unmodified. Implementing Pia crypto in the sysmodule
     would duplicate what the game already does. Confirmed 2026-08-17: real
     encrypted session traffic (header v2, genuine AES-GCM ciphertext) crosses
     the tunnel untouched.
   - `spike/slp_pia.py` / `spike/demo_host.py` implement Pia only because the
     test harness has no second real console to stand in for — that's the
     *only* place this logic belongs in the repo.

## Build & Deploy

```bash
cd sysmodule
make

# Deploy (verifies build id + byte count against the console)
cd ..
SWITCH_IP=<console-ip> tools/deploy.sh ftp all
```

## Testing

```bash
# Run demo host (Python) — stands in for a second console
cd spike
python3 demo_host.py 127.0.0.1 11451
```

## Debug

- Trace log: `sdmc:/slp-trace.log` (FTP accessible). Every boot writes a
  banner line (`===== sys-slp-client vX.X.X build <id> =====`) so a trace
  can always be tied to the exact binary that produced it — "deployed" and
  "running" are not the same thing; check the *last* banner in the file
  (it appends across boots).
- Relay log: local `slp-server-rust` process stdout.

## Next Priority

A real second console (or Ryujinx, on hardware capable of running it) to
complete a full LAN join and to test whether MK8DX's LAN room gets indexed
onto a public relay's LAN-lobbies page.
