# slp:cfg IPC contract + config layout

Contract between the `slp-helper` Tesla overlay and the `sys-slp-client`
sysmodule. The overlay is a thin client; the sysmodule owns config + state.

## Service
- Named port: **`slp:cfg`**
- Client impl: `overlay/source/slpcfg.c/.h` (modeled on ldn_mitm's `ldn.c`)

## Commands
Verified against `sysmodule/source/slpcfg/slp_cfg_service.hpp` (2026-08-17) — this
is the complete command table, nothing else is registered.

| cmd   | name               | args                                                              |
|-------|--------------------|-------------------------------------------------------------------|
| 65000 | GetVersion         | out buffer `char[32]` (hipc pointer)                              |
| 65001 | GetState           | out buffer `u32 state`, out buffer `u32 sel_index`, out buffer `char[16] ip` (all hipc pointer) |
| 65002 | SelectServer       | in u32 `index` (0..9)                                             |
| 65003 | Start              | —                                                                 |
| 65004 | Stop               | —                                                                 |
| 65005 | Reload             | —                                                                 |

- `state`: 0 = stopped, 1 = running.
- `sel_index`: index into the server list of the currently selected server.
- `ip`: virtual IPv4 (dotted) the module bound when running, else "".

**65006 GetOptions / 65007 SetSkipFirstSession do not exist.** They backed
`skip_first_bsd_session`, which was removed entirely (see "Dropped" below) —
grep confirms zero references to `ReloadOptions`, `options.conf`, or
`bsd_whitelist` anywhere in `sysmodule/` or `overlay/`.

### Buffer transfer mode (important)
- The overlay (`slpcfg.c`) sends **all** out buffers with
  `SfBufferAttr_HipcPointer | SfBufferAttr_Out`.
- The sysmodule therefore declares every out param as
  `ams::sf::OutAutoSelectBuffer` (map-alias **and** pointer accepted).
  Do not use plain `ams::sf::OutBuffer` (map-alias only) or
  `ams::sf::Out<...>` (out-scalar, different descriptor kind) — a pointer-mode
  C-buffer against those declarations is rejected by the CMIF dispatcher.

Semantics: `SelectServer` remembers the pick (persisted); `Start` launches the
slp transport on the selected server; `Stop` tears it down; `Reload` re-reads
`servers.conf` (and refreshes selected index; invalid selection -> 0).

## Config file
- On-device path: **`sdmc:/config/slp-helper/servers.conf`**
- Repo canonical copy: `config/servers.conf` (copy to SD when installing).
- Format (parsed by `overlay/source/servers.c`, shared by the sysmodule):
  - one server per line, `#` comment, blank lines skipped
  - `name host:port` or `name host port`
  - max **10** servers; extra lines ignored
- If missing/unreadable, the module runs with 0 servers and Start fails
  gracefully; the overlay shows "no servers in ...".

## Options file — REMOVED
There is no `options.conf` and no runtime-configurable dummy-session policy
anymore. The first-bsd:u-session skip is now unconditional, auto-detected
in-code (per-pid, no config): see `ShouldMitm()` in `bsd_mitm_service.cpp` and
`notes/dummy-session-crash-fix-20260815.md`. `bsd_whitelist` (a separate,
now-removed game-gating mechanism) is documented as dead in
`notes/whitelist-design.md`.

## Limits
- `SLPCFG_MAX_SERVERS` = 10 (must stay in sync across module + overlay).

## Build (overlay)
```
docker run ... devkitpro ...   # devkitA64
make                            # -> overlay/slp-helper.ovl
```
Place `slp-helper.ovl` in `sdmc:/switch/.overlays/` (Tesla). The sysmodule
registers `slp:cfg`; the overlay connects to it at init.

## Dropped from LANHelper-Tesla (legacy refs)
- XLink Kai support (`xlink.cpp`/`xlink.hpp`)
- IP generation + `nifm:admin` writes (`ipglobal.cpp`/`ipglobal.hpp`,
  `include/lanhelper.h`) — the module owns the virtual IP internally
- "Reset IP Config", "Clean up networks", reboot-on-apply GUIs
- `spsm`/`nifm`/`setcal` service init

## Diagnosis: overlay "slp:cfg not loaded" + "servers loaded: 0" (2026-08-13)

Symptom on-device: header "slp-helper ?", single "State" item, diag showed
`slp:cfg connect 0xF201` and `servers loaded: 0`.

### 0xF201 decode (previously mis-decoded as sf::ResultRequestInvalidData)
libnx result encoding is `MAKERESULT(module, desc) = module | (desc << 9)`:
- `0xF201 = 1 | (121 << 9) = MAKERESULT(Module_Kernel, KernelError_NotFound)`
- So the overlay's raw `svcConnectToNamedPort("slp:cfg")` just returned kernel
  NotFound. It does NOT prove the sysmodule is down — only that the name is not
  a kernel named port reachable by raw named-port connect.

### Tesla overlay environment requirements (from libtesla/tesla.hpp)
- Tesla does NOT auto-init `sm` or auto-mount `sdmc`.
- Service lookup must run inside `tsl::hlp::doWithSmSession` (does
  `smInitialize()`/`smExit()`).
- SD config reads must run inside `tsl::hlp::doWithSDCardHandle` (does
  `fsdevMountSdmc()` / unmount) — otherwise `fopen("sdmc:/...")` fails.
- Reference: ldn_mitm overlay wraps `smGetService("ldn:u")` in
  `doWithSmSession`.

### Fixes applied
- `overlay/source/slpcfg.c`: `slpCfgGetConfig` now uses `smGetService(&out->s,
  "slp:cfg")` (tries named port, falls back through sm:) instead of raw
  `svcConnectToNamedPort`.
- `overlay/source/main.cpp`: `initServices` wraps the connect in
  `doWithSmSession` and the config load in `doWithSDCardHandle`; diagnostics
  (connect result + servers count) now always visible until confirmed.
- `sysmodule/source/main.cpp`: writes `sdmc:/slp-heartbeat.txt` ("slp-client
  booted\n") at the top of `Main()` via `ams::fs` to prove the module actually
  boots under boot2 (no stdio in boot2 context).

Deployed + sha256-verified on device:
- `atmosphere/contents/4200000000000011/exefs.nsp` 348d8b48… (205557 B) — priority fix build
- `switch/.overlays/slp-helper.ovl` 61229271… (1036344 B) — AutoSelect fix build

### Open questions to resolve on next test
- Does `sdmc:/slp-heartbeat.txt` appear after reboot?  (module booted?)
- Overlay diag: `slp:cfg connect 0x0`? `servers loaded: 10`?  (smGetService + sdmc)
