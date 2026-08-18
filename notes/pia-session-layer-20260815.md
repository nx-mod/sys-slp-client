# PIA session layer — NOT a bug, and was never the cause of 2618-0006

**This note (2026-08-15) concluded the C++ sysmodule needed to implement Pia
session crypto (AES-GCM, HMAC key derivation, Session Request/Message
handling) to fix 2618-0006. That conclusion was wrong, and the "Required
Implementation" list below was never built and must never be built.**

## What actually caused 2618-0006 (found 2026-08-17)

`BsdMitmService::Send()`/`SendTo()` reported the bsd:u `{ret, errno}` reply in
the wrong slots — on a successful send it told the game "0 bytes sent,
errno=N" instead of "N bytes sent, errno=0". MK8DX's 873-byte LAN browse
broadcast therefore appeared to fail on every attempt, and the game gave up
with 2618-0006 after ~2 seconds — **with no peer involved at all**, which is
why it was so hard to pin on session-layer content. Fixed by writing the
correct value into the correct slot; see
`notes/TODO-uncross-bsd-out-params.md` and `[[lan-mode-proven-state]]` in
memory for the full trace. PIA was never touched.

## Why the sysmodule correctly does NOT implement PIA

`bsd:u` is a transparent socket proxy: the game's own real Pia stack builds
and reads every packet on port 49152, and we forward the bytes unmodified —
identical to how `ldn_mitm` and `switch-lan-play`'s PC client both work
(neither of them understands Pia either; see `notes/compat-matrix.md`,
"Key architectural insight"). Implementing Pia crypto inside the sysmodule
would duplicate what the game already does and add a place for us to get the
crypto wrong. Confirmed working 2026-08-17: after the Send/SendTo fix, MK8DX's
real Pia session traffic (84B, header v2, genuine AES-GCM ciphertext) crosses
the tunnel untouched and the game proceeds to a real join attempt.

## Where Pia crypto DOES belong: the Python fake host only

`spike/slp_pia.py` and `spike/demo_host.py` exist because the test harness has
no second real console — something has to pretend to be one. That is the
*only* place Pia session logic is appropriate in this repo. It is not a
model for what the sysmodule should do.
