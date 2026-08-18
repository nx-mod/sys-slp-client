# Dynamic Whitelist — REMOVED

**This feature no longer exists.** This note originally (2026-08-14) documented
a title-ID whitelist gating `bsd:u` interception (`m_bsd_whitelist[16]`,
`options.conf bsd_whitelist=`, overlay L/R/X/Y toggles). Verified 2026-08-17:
zero references to `whitelist`, `bsd_whitelist`, `options.conf`, or
`ReloadOptions` remain anywhere in `sysmodule/` or `overlay/` — fully removed,
not just undocumented.

## What replaced it

`BsdMitmService::ShouldMitm()` (`bsd_mitm_service.cpp`) now gates purely on:
1. the relay client being `SLPCFG_STATE_RUNNING`
2. `program_id != OUR_PROGRAM_ID` (don't intercept ourselves)
3. `program_id >= 0x0100000000010000` (real applications only — system
   sysmodules and applets, including the Home menu and Album/hbloader, are
   never intercepted; see the applet-MITM fix, 2026-08-17)
4. per-pid first-session auto-skip (see `dummy-session-crash-fix-20260815.md`)

No title ID list, no config file, no overlay buttons. Any real application
gets intercepted while the relay is running — full stop.

## Why this note is kept

The original design (per-game opt-in) predates the discovery that the actual
crash causes were the dummy-session issue and, later, the applet-MITM and
`Send`/`SendTo` ret/errno bugs — none of which needed a whitelist to fix. If
you're reading old commits or traces that mention `bsd_whitelist`, this is
what they refer to.
