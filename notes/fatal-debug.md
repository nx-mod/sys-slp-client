# Fatal error debug (2026-08-14)

## Symptom
After Start was sent, the console rebooted. `atmosphere/fatal_errors/report_00000006b411166a.bin`
appeared (kept; older `0011…` reports deleted).

## Decode (tools/decode_fatal.py)
- error_desc `0xFFE` = `StdAbortErrorDesc` — `std::abort()` from an Atmosphere
  `AMS_ABORT`/`AMS_ASSERT` (NOT a data abort).
- program_id `0x4200000000000011` = sys-slp-client.
- PC `0x7F97227D38`; module base `0x7F97200000` → offset `0x27D38`.
- Backtrace (symbolized vs `sys-slp-client.elf`, `.text` vaddr 0 so offset = ELF addr):
  `Runtime::Start` (slp_runtime.cpp:187) ← `ConfigService::Start` (slp_cfg_service.cpp:55)
  ← CMIF dispatch chain. **The IPC fix works — the request now reaches the service.**

## Root cause
- `Runtime::Start` creates its thread with user priority `0x30` (48).
- `ConvertToHorizonPriority`: horizon = user + `UserThreadPriorityOffset(28)` = 76.
- Valid range is `[0, LowestTargetThreadPriority=63]` → `AMS_ASSERT` fires in
  `os_thread_manager_impl.os.horizon.cpp:26-30` → `AbortWithValue` → fatal 0xFFE.
- Boot threads used priorities 10/6 (→38/34, valid) so only Start crashes.

## Fix
- `slp_runtime.cpp`: priority `0x30` → `0x0F` (horizon 43, in range).
- Rebuilt; deployed `exefs.nsp` sha `348d8b48…`; `boot2.flag` restored (0011 folder was deleted after the fatal).

## Notes
- The old 0xF601 session-close bug also showed here: any `ProcessMessageImpl` error
  closes the session (`sf_hipc_server_session_manager.cpp:245-251`), so failures cascade.
- Never use priority outside `[0,63]` user range in `CreateThread`.

## Verified end-to-end (2026-08-14)
Rebooted with fixed build (`348d8b48…`) + `boot2.flag` restored. Overlay diag:
- `ver rc 0x0 "0.1.0"`
- `state rc 0x0 st=0 sel=0`
- `cmd select rc 0x0`
- Start → "Running", relay `/tmp/slp-hotspot.log` receives Switch keepalives every ~10s
  from `10.172.227.168:58507` (console IP) — first Switch-originated traffic ever.
- Stop → `rc 0x0`.

Both fixes confirmed: AutoSelect IPC + thread priority. The slp relay link is live.
