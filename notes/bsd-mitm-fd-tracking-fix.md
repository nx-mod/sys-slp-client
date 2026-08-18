# BSD MITM fd tracking fix (2026-08-14, updated with real root cause)

## Problem
MK8DX LAN mode never reaches the relay: the console's LAN-mode traffic on
port 30000 (browse) is forwarded to the REAL bsd service instead of the LDN
proxy, so the broadcast never reaches the relay / fake host.

## REAL Root Cause (from fresh slp-trace.log, 2026-08-14 08:2x)
The "fcntl F_DUPFD duplication" theory was WRONG. The fresh trace shows
ZERO Fcntl calls. MK8DX creates the port-30000 LAN browse socket directly
via `Socket()`, but the tracking gate rejected it:

```
[BSD#1] Socket result: rc=0x0 fd=0 errno=0  -> tracked (errno==0) ✓
[BSD#1] Socket result: rc=0x0 fd=1 errno=1  -> NOT tracked (errno!=0) ✗
[BSD#1] Socket result: rc=0x0 fd=2 errno=2  -> NOT tracked (errno!=0) ✗  <- port 30000!
```

MK8DX returns errno=1 / errno=2 on the SECOND and THIRD socket calls while
still returning valid, usable fds (the game freely does SetSockOpt/Bind/
RecvFrom/SendTo on fd=1 and fd=2). The tracking condition in `Socket()` and
`SocketExempt()` required `out.errno_val == 0`, so fd=1 and fd=2 were never
registered -> Bind fell through to "not tracked, forwarding to real service".

Socket sequence observed (correct LAN-mode behaviour from the game):
- fd=0: bind 0.0.0.0:49152 -> LDN proxy ✓  (PIA session socket)
- fd=1: bind 0.0.0.0:40000 -> real bsd (non-LDN)
- fd=2: bind 0.0.0.0:30000 -> real bsd  <- LAN browse socket, MUST be proxy

## Fix Applied
**File: `sysmodule/source/bsd/bsd_mitm_service.cpp`**

`Socket()` (~line 558) and `SocketExempt()` (~line 630): removed the
`out.errno_val == 0` requirement from the tracking gate. Now:
```cpp
if (R_SUCCEEDED(rc) && out.fd >= 0) { ... track ... }
```
errno field is not a reliable "socket failed" indicator for MK8DX; a valid
fd is. This is what lets fd=2 reach Bind -> CreateProxySocket -> proxy bound
to virtual IP 10.13.37.2:30000 -> broadcast SendTo goes through
SendProxyData -> tunnel -> relay.

## Expected Log After Fix
```
[BSD:I] BSD Socket tracked fd=2 type=2 proto=17 session=1
[BSD:I] BSD Bind fd=2 detected INADDR_ANY address, port=30000
[BSD:I] BSD Bind fd=2: using local LDN IP 0x0a0d2502
[BSD:I] BSD Bind fd=2 successfully bound to LDN proxy (addr=0x02250d0a, port=30000)
```

## Deployment
- Build: `cd sysmodule && make`  (built ok, NSP 266474 B, sha256 154ae2a0...)
- Deploy: `tools/ftp_upload.py` pattern (ftplib, uploads to
  `atmosphere/contents/4200000000000011/exefs.nsp`, hash-verifies round-trip)
- A reboot is required for the sysmodule to reload (boot2.flag present)

## Verification
After reboot, fetch slp-trace.log and check for "Socket tracked fd=2" +
"Bind fd=2 successfully bound to LDN proxy". Fake LAN host
(`spike/slp_fake_player.py 11451 --relay 10.172.227.113 --name LAN-HOST`)
should then show:
```
  [HH:MM:SS] !! Browse Request from 10.13.37.2:30000 (reply #1)
```

## Notes
- Fake host log from the failing run showed only:
  - our module's own LDN control broadcast 10.13.37.0:11452 (12B, every 5s)
  - game PIA traffic 10.13.37.2:49152 -> 10.172.227.255:49152 (72B)
  - NO port-30000 browse -> confirming fd=2 was never proxied.
- The game's PIA broadcast dst 10.172.227.255 (real WiFi subnet) is forwarded
  as-is by the tunnel. Whether that matters for interop with PC clients later
  is a separate concern (see ldn-unlock-design.md); LAN browse to the relay
  only needs fd=2 proxied.
