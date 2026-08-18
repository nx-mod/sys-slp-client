# Overlay: Removed "Skip 1st bsd session" toggle (2026-08-14)

**UPDATE (2026-08-17): the underlying option is gone too, not just the UI.**
`skip_first_bsd_session`, `options.conf`, and IPC 65006/65007 (`GetOptions`/
`SetSkipFirstSession`) were all later removed — the dummy-session skip is now
unconditional and auto-detected in-code, no config surface at all. See
`notes/dummy-session-crash-fix-20260815.md` and `notes/slp-cfg-ipc.md`. The
rest of this note is historical (what changed on 2026-08-14, before that
later removal).

## Reason
User requested removing the toggle from overlay menu - the option persists in config/options.conf and sysmodule IPC, just not exposed in UI.

## Changes
**File: `overlay/source/main.cpp`**
- Removed `g_skip_val` global
- Removed "Skip 1st bsd session" ListItem from UI
- Removed skip value fetch/display in `refresh()`
- Kept IPC commands 65006/65007 functional for programmatic access

## Config Still Works
- `options.conf`: `skip_first_bsd_session=1` (default, MK8DX-safe)
- Can be changed via IPC if needed: `slpCfgSetSkipFirstSession(&svc, 0)`

## Build
- `overlay/slp-helper.ovl` built and uploaded to Switch FTP root
- Deploy to `/switch/.overlays/slp-helper.ovl` on SD card