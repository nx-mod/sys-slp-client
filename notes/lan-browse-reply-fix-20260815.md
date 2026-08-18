# MK8DX LAN browse-reply fix (2026-08-15)

Decoded the real MK8DX LAN traffic from the relay log and fixed the demo host so
its browse reply passes the game's search criteria + crypto challenge.

## Wire facts (from the game's own packets, relay log)
- Browse request = 873B = `[u8 type 0][u32 size 0x23A][criteria 570B][0x12A challenge]`
  (5.7+ format). Challenge version 1 (= Pia 5.7-5.10), crypto enabled, counter 1.
- AES-GCM nonce broadcast addr = **10.172.227.255** = the game's REAL WiFi subnet
  broadcast (NOT the virtual 10.13.37.x). Confirmed: decrypt succeeds with that
  nonce, fails with 10.13.37.255 / 10.13.255.255 / 10.255.255.255.
- 72B probe on 49152 to broadcast = Pia keep-alive (type 7, pre-5.28 behavior),
  sent ~every 2 s regardless of session, ignored by receiver -> no reply needed.
- Search criteria: min participants 2, max participants 14, opened-only, game mode
  1, session type 0, 6 empty attribute lists, search flags 0xFFF.

## Reply the game accepts (cross-checked vs KartLANPwn CVE-2024-45200 PoC)
- Type 1 + size 0x4F2=1266 + 5.3-5.6-layout body (app data @ body 0x2A, app-data
  size @ 0x1AA). MK8DX uses the OLD session-info layout despite sending a 5.7+
  challenge request (hybrid Pia). The PoC proves no-challenge reply still gets
  parsed, so the challenge is not required — but we append a VALID one anyway.
- Body values that match the joiner's criteria: game_mode 1, network_id 0x0150C000,
  cur/min/max participants 1/2/14, syscomm 2, appcomm 13, is_opened 1, host
  10.13.37.100:30000.
- Our previous reply (game_mode 0, min 1, max 8) was filtered out by the search
  criteria even if it had arrived.

## Changes
- `slp_lan.py`: mk8dx profile -> `challenge: True`, syscomm 2, appcomm 13;
  `build_session_info` gained current/min/max participant params;
  `build_browse_reply` gained `broadcast_addr` + game_mode/network_id/min/max.
- `demo_host.py`: reply uses criteria-matching fields, challenge nonce broadcast =
  the browse packet's dst IP, reply sent 3x (wiki: browse reply is transmitted 3x).

## Verification
- Challenge reply crypto round-trips against the real game browse (HMAC response
  `8b55bd87...` matches).
- All 16 spike tests pass.
- E2E over the local relay with the REAL 873B game browse: demo host replies
  1569B (1+4+1266+298); reply verifies.

## TODO (needs console)
- Re-enter MK8DX LAN Play with the demo host running; check if a room appears.
- If a room appears and joining fails: expect a session request on 49152 (encrypted
  with a session key derived from the session key param) and a host request/message
  flow; that is the next layer to implement.
