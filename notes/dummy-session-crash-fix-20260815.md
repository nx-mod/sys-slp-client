# New-build crash root cause + fix (2026-08-15)

**UPDATE (2026-08-17): the mechanism below (a single per-pid counter incremented
by every `ShouldMitm()` call) was itself buggy and has since been replaced.** A
SKIPPED session never constructs a `BsdMitmService`, so its increment into the
counter was never undone in the destructor — the count leaked +1 permanently,
and on the game's second "burst" (e.g. WiFi -> Finalize -> LAN) nothing got
skipped: the dummy session was intercepted and the game died. That was the
WiFi -> LAN crash (observed 2026-08-16).

Current mechanism in `bsd_mitm_service.cpp` (`ShouldMitm()`): two per-pid maps,
`g_mitm_pid_skipped` (has this burst's dummy already been skipped?) and
`g_mitm_pid_live` (count of currently-live intercepted sessions). The
destructor erases BOTH entries once `g_mitm_pid_live` hits zero, which
re-arms the skip for the pid's next burst. The core insight below — MK8DX's
first bsd:u session per burst is a dummy that crashes if intercepted — is
still exactly right; only the bookkeeping changed.

## Symptom

After deploying the whitelist-removal build (exefs.nsp 265808 B, sha 2b78f23a),
MK8DX crashed identically for WiFi-accident, LAN, and homebrew re-open. Same
severe impact each time → single root cause, not user error.

## Evidence (slp-trace.log, 30406 lines, FTP root)

Crash runs show MK8DX:

- Opened **two bsd:u sessions** (`ShouldMitm #1`/`#2` for pid=138)
- ZERO `Socket()` calls ever
- Session #2 `RegisterClient` OK (tmem forwarded, registered=1)
- Both sessions destroyed ~6 s later (`BSD#1 DESTRUCTOR` registered=0,
  `BSD#2 DESTRUCTOR` commands=1 registered=1)
- No `accept ldn`, no `[LDN#]`, no `Socket|Bind|SESSION MODE` entries at crash

So the game aborted BEFORE any socket work. The Bind/whitelist layers are
exonerated. `notes/compat-matrix.md` already predicted this: *"whether
skip_first_bsd_session=0 is safe on titles whose first session is a dummy
(instability observed only for MK8DX so far)"*.

## Root cause

Removing the whitelist also removed the per-pid "skip first bsd session" gate.
MK8DX opens a **dummy first bsd:u session** that never calls RegisterClient and
**crashes if intercepted**, even though the MITM handles the abandon safely
(prevents the SYSTEM freeze, not the GAME abort). The working trace confirms:
old build logged `ShouldMitm #7: SKIP first session for pid=146` → game then
created fd=0/1/2 and bound fd=2 :30000 (270 commands, no crash).

## Fix (deployed)

Restored the first-session skip as **hardcoded auto-detection** in
`BsdMitmService::ShouldMitm()` (`sysmodule/source/bsd/bsd_mitm_service.cpp`):

- Globals: `g_mitm_pid_count` (per-pid session count) + `g_mitm_pids_mutex`
- Session #1 of any pid → return false (forwarded transparently) with
  `SKIP first session` log
- Session #2+ → intercepted
- Destructor decrements/erases the pid entry so counts stay fresh

This is the old `skip_first_bsd_session=1` behavior, now unconditional in code
(no config option, no IPC command).

## Tradeoff (documented)

Games that open only ONE bsd session (e.g. Quake II) route all their traffic
through that session → it is treated as the dummy → NOT intercepted → real
network used. MK8DX (the target) opens 2+ sessions, so it is unaffected.

## Deploy bug caught

`tools/ftp_upload.py` uploads from the staging dir
`/home/nx-mod/switch/sdcard/atmosphere/contents/.../exefs.nsp`, which still held
the OLD crashy build (265808 B, 2b78f23a) → the first "deploy" was a no-op
(hash verified equal). Fixed by copying the fresh build into staging first.
Actual deployed build: **exefs.nsp 267362 B sha 1ec770bc43** (verified on
Switch), overlay unchanged (1036344 B, 117c493b).

## Verification steps after reboot

- `ShouldMitm #N: SKIP first session` for the dummy session
- `Socket tracked fd=2` + `Bind fd=2 successfully bound to LDN proxy` for :30000
- Relay healthy: UDP echo on 10.172.227.113:11451
