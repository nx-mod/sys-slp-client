# WiFi / Atmosphere Integration Issues (2026-08-14)

## Black Screen After Game Exit — FIXED with Game Whitelist (2026-08-14)

### Symptom
After exiting a LAN game (MK8DX), opening any other app shows a black screen
until reboot. Happens because the slp runtime auto-starts at boot and stays
`SLPCFG_STATE_RUNNING` forever.

### Root Cause
`BsdMitmService::ShouldMitm()` intercepted **every application** (no game
whitelist) whenever the runtime was running. The **home menu** and other apps
open bsd:u sessions that were then proxied to the relay → their network calls
hang → black screen. (Also: MK8DX LAN-mode never calls ldn:u `OpenAccessPoint`,
so the nifm local-network-mode code is NOT the black-screen cause.)

### Fix
- `slp_runtime.hpp/.cpp`: added `m_bsd_whitelist[16]` + `IsBsdWhitelisted()`,
  parsed from `options.conf` key `bsd_whitelist=` (comma-separated hex title IDs).
  Default = MK8DX (`0x0100152000022000`).
- `bsd_mitm_service.cpp` `ShouldMitm()`: only intercept whitelisted games.
- Deployed `config/slp-helper/options.conf` with the whitelist.

## Root Cause: Missing NIFM Local Network Mode

The sys-slp-client **calls `nifmInitialize()` but never enters local network mode**,
unlike ldn_mitm which does:

```cpp
// ldn_mitm lan_discovery.cpp:initialize()
nifmCreateRequest(&request, true);
nifmSetLocalNetworkMode(&request, true);  // <-- MISSING in sys-slp-client
nifmRequestSubmitAndWait(&request);
```

This is critical because:
1. **Local Network Mode** tells the Switch's WiFi stack that it's in LAN-only mode,
   which changes how broadcast packets are handled, how sockets bind to interfaces,
   and whether certain WiFi ioctl operations are allowed.
2. Without it, games trying to create LAN sockets may get errors (errno=2 on
   socket creation in the trace).
3. The 2618-0006 error (local wireless init failure) is directly caused by the
   WiFi interface not being properly configured for local networking.

## Secondary Issue: Address Space Comments Mismatch

The code comments throughout `bsd_mitm_service.cpp` and `bsd_types.hpp` reference
`10.114.x.x` (Ryujinx LDN format), but the actual implementation uses
`10.13.37.0/24` (the slp virtual LAN):

- `bsd_types.hpp:50`: `LAN_NETWORK_BASE = 0x0A0D2500` = 10.13.37.0 (correct)
- `bsd_types.hpp:63`: `IsLanAddress()` checks `10.13.37.0/24` (correct implementation)
- Comments say "10.114.x.x" everywhere (misleading but harmless)

The virtual IP `10.13.37.2` is consistent across:
- `slp_runtime.cpp:17`: `DefaultVirtualIp = "10.13.37.2"`
- `bsd_types.hpp:50`: `LAN_NETWORK_BASE = 0x0A0D2500`
- `slp_fake_player.py:231,238`: `--ip 10.13.37.100`

## Files to Modify

1. **Add local network mode handling:**
   - `sysmodule/source/main.cpp` — Add nifm local network mode setup during
     LDN operation (OpenAccessPoint / OpenStation) and teardown
     (CloseAccessPoint / CloseStation / Finalize)
   - `sysmodule/source/ldn/ldn_control.cpp` — Enter/exit local network mode
     when transitioning LDN states
   - Or create a new `ipinfo.cpp/.hpp` port from ldn_mitm

2. **Fix misleading comments:**
   - `bsd_types.hpp` — Update comments from "10.114.x.x" to "10.13.37.0/24"
   - `bsd_mitm_service.cpp` — Update all "10.114.x.x" references to "10.13.37.x"

3. **Add Fd tracking for MK8DX LAN mode:**
   - Already partially done (F_DUPFD tracking exists)
   - Need to verify fd=2 Socket creation with errno=2 — may need to track sockets
     even when errno is non-zero, OR the errno=2 causes games to not proceed
   - Add aggressive Fcntl logging at entry to capture all cmd values (from resume)

## Reference: ldn_mitm's IP Info Handling

From `/home/nx-mod/switch/ldn_mitm/ldn_mitm/source/ipinfo.cpp`:
```cpp
Result nifmSetLocalNetworkMode(NifmRequest *r, bool isLocalNetworkMode)
{
    /* Wrapper for nifmSetLocalNetworkMode which is missing from some libnx */
    return nifmSetNetworkMode(r, isLocalNetworkMode ? 
        NifmNetworkMode_LocalNetwork : NifmNetworkMode_Normal);
}
```

The `lan_discovery.cpp:initialize()` method:
1. Gets current network profile
2. Sets MTU to 1500 (for local network)
3. Creates an nifm request with local network mode
4. Submits the request and waits
5. On finalize: cancels request, restores original MTU

## Verification Plan

After fix:
1. Reboot to clean Atmosphere (no overlays)
2. Start relay server, start sys-slp-client
3. Launch MK8DX → LAN Play (L+R+Left Stick)
4. Trace should show:
   - nifm local network mode set
   - Socket fd=0, fd=1, fd=2 tracked
   - Bind fd=2 port 30000 → "successfully bound to LDN proxy"
5. slp_fake_player.py should see browse requests
