# All-games compatibility matrix (broadening research)

Researched 2026-08-14 (web: kinnay/NintendoClients wiki LAN-Protocol + Pia
pages, TeamXLink supported-games page, switch-lan-play GBAtemp thread).
Goal: decide what the slp tunnel must do so the 25 native-LAN Switch games
play across the relay, using only real consoles (no Pia reimplementation).

## Key architectural insight

Our tunnel is transparent to the Pia protocol: both consoles run real Pia,
and we just forward the raw UDP bytes of their bsd sockets over the relay.
So **Pia 5.7+ crypto challenges, session-key AES-GCM, ENL record framing —
all handled by the real games, never by the tunnel.** The only things the
tunnel must get right are socket/broadcast semantics, the loopback keepalive,
and the bsd-session interception policy.

## Facts from kinnay LAN-Protocol wiki (authoritative)

- Browse request: UDP **broadcast, port 30000** for Pia ≤ 5.45; **port 35000**
  for Pia 6.16–7.2. Plaintext (not Pia-encapsulated). Max 1364 B.
- Browse reply: **unicast to requester**, plaintext, sent **3×**.
- Pia ≤ 5.6 browse request has NO crypto challenge (MK8DX is ≤ 5.6-style).
- Pia 5.7–5.45 browse request ends with a **crypto challenge** (0x12A) and the
  reply must carry a correct response or newer-Pia games reject the room.
  Challenge version 1 = 5.7–5.10, 2 = 5.11–5.45, 3 = 6.16–6.33, 4 = 6.40–6.41,
  5 = 7.2. AES-GCM; nonce = (local_addr | ~subnet_mask) ++ counter; challenge
  key = AES(game key, challenge key); response = HMAC-SHA256(decrypted
  challenge, game key)[0:16].
- Session traffic: Pia-encapsulated (magic `32 AB 98 64`), ports
  **49152–49155**, AES-GCM with a session key derived from the game key +
  session key param. Keep-alive msg type 7, host request 3, host message 4,
  session request 5, session message 6.
- **Keep alive: every 2 s on port 49152, always sent even when not in a
  session. Pia ≥ 5.28 sends it to 127.0.0.1 (localhost); earlier to
  broadcast. "It is ignored by the receiver."**
- Pia game keys (public): MK8DX `ABCDEFGHIJKLMNOP`, Sw/Sh
  `p1frXqxmeCZWFv0X`, Splatoon 2 `ee182a63e216cdb1f51ad4bed8cf6508`, SMM2
  `667c18475889faab61f93ef1da180971`. Most first-party games derive the key
  via ENL (seed + game table — not derivable without the game binary).

## The 25 native-LAN games (TeamXLink supported-games)

Pia-based (Nintendo): ARMS, Bayonetta 2, Mario & Sonic Tokyo 2020, Mario Golf
Super Rush, Mario Kart 8 Deluxe, Mario Tennis Aces, Nintendo Switch Sports,
Pokémon Sword/Shield, Pokkén Tournament DX, Splatoon 2, Splatoon 3, Super
Mario Maker 2.
Custom / classic-FPS netcode (UDP LAN, no Pia): Air Conflicts: Pacific
Carriers, Air Conflicts: Secret Wars, Don't Starve Together (RakNet),
DOOM + DOOM II, Duke Nukem 3D, Quake II, Rise of the Triad, Saints Row IV,
Saints Row: The Third, Serious Sam Collection, Sid Meier's Civilization VI,
Titan Quest.

All use UDP for gameplay. No confirmed TCP usage in any LAN mode. (kinnay
list of Pia games and switch-lan-play's tested list — MK8DX, Splatoon 2,
Pokkén, ARMS, Titan Quest, Mario Tennis Aces, Bayonetta 2, Saints Row 3 —
are all UDP.)

## Compatibility rules for the tunnel

| Rule | Status in code | Notes |
|------|----------------|-------|
| Proxy every UDP bsd socket regardless of port (30000/35000/49152–49155/ephemeral) | ✅ automatic (proxy-all) | Pia 6.x 35000 browse needs no code |
| Broadcast to all sockets on the port (limited 255.255.255.255 + subnet bcast) | ✅ FindAllSocketsByDestination | MK8DX uses limited broadcast |
| INADDR_ANY binds -> virtual IP | ✅ Bind() rewrite | |
| Reply to src virtual IP | ✅ Send() src-IP rewrite (src 0 -> virtual) | |
| Pia ≥ 5.28 keepalive to 127.0.0.1 | ✅ NEW: Send() drops loopback dst, returns success | faithful: never leaves console, receiver ignores |
| Pia 5.7+ crypto challenge (real consoles) | ✅ N/A (transparent) | only laptop fake-player needs the math |
| First bsd session may be the ONLY session | ✅ NEW: `skip_first_bsd_session` option (default 1 = MK8DX-safe) | toggle per-game via overlay/options.conf |
| **Dynamic whitelist overlay (L/R/X/Y toggles)** | ✅ **NEW**: L/R toggle entries 0/1, X adds current game, Y removes | 16-entry max; memory-only; edit `options.conf` for persistence |
| TCP | ⛔ gated (ENETUNREACH) | no LAN game needs it; revisit only if a title proves TCP |
| Bind to a specific non-LAN IP (e.g. 192.168.x.x) + unicast receive | ⚠️ not proxied | falls through to real stack; expected to be a real-WiFi IP. Pia/classic ports bind INADDR_ANY, so low risk |
| Sends from non-LAN source IPs | ✅ Send() src-IP rewrite covers src==0; bound non-LAN IPs never become proxy sockets | |

## Per-game prediction (to verify on-device later)

- **MK8DX (Pia ≤ 5.6, ENL, :30000)**: baseline — should work as designed.
  skip_first=1 (default).
- **Splatoon 2 (Pia 5.6, ENL, :30000)**: same shape as MK8DX. skip_first=1.
- **Pokémon Sw/Sh (Pia 5.7+ challenge, ENL)**: browse on 30000, challenge
  handled by real consoles. May use Pia ≥ 5.28 -> loopback keepalive (now
  handled). skip_first=1.
- **Super Mario Maker 2 (Pia 5.x, ENL)**: similar; key published.
- **Mario Golf / Nintendo Switch Sports / Splatoon 3 (Pia 6.x, browse :35000)**:
  proxy-all covers 35000. Splatoon 3 keepalive: 6.x >= 5.28 -> loopback
  (handled). skip_first unverified (try 1 then 0).
- **Classic FPS / custom (Quake II, DOOM+II, Duke Nukem, Serious Sam, ROT,
  Saints Row 3/4, DST, Titan Quest, Civ VI, Air Conflicts x2)**:
  single/early bsd sessions -> likely need **skip_first_bsd_session=0**.
  UDP broadcast discovery + direct unicast on INADDR_ANY sockets should pass
  the tunnel as-is.

## LDN control plane (Local-Wireless-only titles, ~198) — spike results

`spike/test_ldn.py` passed **9/9** (3x consecutive + 25x debug-loop runs) on
2026-08-14 against the same stock relay. This proves the control-plane split in
`notes/ldn-unlock-design.md` end-to-end: ldn:u-style control (scan/connect/
sync) rides the tunnel as LAN-protocol frames, and the post-join data plane
uses the existing bsd:u MITM. Details, bugs found (`_update_nodes` node-list
fix, stale-AP scan filtering, node teardown), and divergences from ldn_mitm are
recorded in `notes/ldn-unlock-design.md`.

Matrix impact: the 198 "Only-Local-Wireless" titles are **no longer out of
scope** — they move to the LDN control-plane path (`ldn:u` MITM to be ported
into the sysmodule, data over the existing bsd:u proxy on 10.13.37.0/24).

## Unsupported regardless of tunnel (from TeamXLink)

Only-Local-Wireless titles are handled by the ldn:u control-plane MITM (see
`notes/ldn-unlock-design.md`; spike-proven, sysmodule port pending). Third-party
titles listed as
unsupported on XLink (Castle Crashers, Divinity OS2, EXORDER, Queen Black,
Knights and Bikes, Monster Truck Freestyle, MotoGP 20, Portal 2, SpeedRunners,
Strange Brigade, Trine 3) lack real LAN modes — not fixable by traffic
tunneling.

## Remaining unknowns (no console test this round)

1. Which Pia version each 6.x title uses exactly (browse port 35000 vs 30000
   only matters for the fake player, not the tunnel).
2. Whether `skip_first_bsd_session=0` is safe on titles whose first session
   is a dummy (instability observed only for MK8DX so far).
3. Whether any LAN title binds a *specific* non-LAN IP for unicast receive
   (would bypass the proxy and break; none observed in Pia/classic ports).

## Local test results (spike/, run against the stock relay — no server changes)

`spike/test_lan.py` passed **16/16** on 2026-08-14 against the unmodified
`slp-server-rust -p 11451` (relay used purely as a UDP-forwarding black box;
all codecs live client-side). Unit tests cover:
- Browse request/response codec (5.7+ challenge block parse, ≤5.6 no block).
- Crypto challenge round-trip: request challenge decrypts, host reply HMAC
  response verifies, wrong game key + tampered GCM tag rejected, version and
  counter echo, crypto-off path.
- LanSessionInfo layouts (5.3–5.6 / 5.10+), MK8DX (≤5.6) and Sw/Sh (5.7+)
  reply builds with session-key param echo.
- LAN session-key derivation (`HMAC-SHA256(game_key, skp[0:31]+(skp[31]+1))`).
- Pia v9 packet: encrypt/decrypt round-trip, wrong-key reject, tampered body
  reject (GCM), bundled multi-message decode.

**End-to-end over the live relay**: two virtual consoles create a lobby and
join it — 5.7+ browse request → host challenge reply → client HMAC verify →
session-key agreement → encrypted Session Request → encrypted Session Message
carrying the LanSessionInfo fragment → encrypted keep-alives both ways. This
confirms the session-layer handshake works against the real server transport.

**What this does NOT cover**: the tunnel sysmodule itself (still needs
on-console MK8DX validation), and "start game" — post-join traffic is the
game's own protocol (player sync/race state) that only real consoles produce.

Unknown #4 (fake player for Pia 5.7+ titles) is now **solved in spike/**
(`slp_lan.py` challenge + `slp_pia.py` session layer) for the 4 published keys,
and the browse/join handshake is proven against the live relay.

## Changes shipped in this round

- `slp_tunnel.cpp::Send()`: drop loopback-destined datagrams (return true)
  — Pia ≥ 5.28 keepalives no longer leak into the relay room.
- `slp_runtime.{hpp,cpp}`: `skip_first_bsd_session` option + `options.conf`
  parsing (boot + Reload), setters/getters.
- `bsd_mitm_service.cpp::ShouldMitm()`: first-session skip now honours the
  option (default on).
- `slp_cfg_service`: IPC 65006 GetOptions / 65007 SetSkipFirstSession.
- Overlay: "Skip 1st bsd session" toggle + `slpCfgGetOptions`/
  `slpCfgSetSkipFirstSession` client.
- `config/options.conf` canonical copy; IPC + option docs updated.
