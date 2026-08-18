# sys-slp-client

Switch sysmodule for LAN/LDN multiplayer over internet relay.

## Current Status (2026-08-15)

**Working:**
- LAN browse (port 30000) - MK8DX browse request → relay → browse reply ✅
- Local network mode for LAN browse (port 30000) - FORCING enabled ✅
- LDN control plane (port 11452) ✅
- LDN WiFi/LDN mode ✅
- Browse request/reply with crypto challenge ✅

**Broken:**
- **PIA session layer (port 49152) - NOT IMPLEMENTED**
  - Joining LAN lobby crashes with 2618-0006
  - Python spike has working implementation (`spike/slp_pia.py`, `spike/demo_host.py`)
  - C++ sysmodule missing PIA session layer

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Switch    │────▶│   Relay     │◀───│   Switch    │
│  (sysmodule)│     │  (slp-server)│    │  (sysmodule)│
└─────────────┘     └─────────────┘     └─────────────┘
```

## Protocol Flow

1. **LAN Browse** (port 30000)
   - Game sends browse request (873B) with crypto challenge
   - Relay forwards to other consoles
   - Host replies with browse reply (1271B) matching search criteria
   - ✅ WORKING

2. **PIA Session Layer** (port 49152) - **NOT IMPLEMENTED BECAUSE IT SHOULD NOT BE NECESSARY AS SOURCES WE ARE PORTING DO NOT NEED IT. HELPFUL FOR FAKE PLAYER TESTS ONLY!!**
   - Game sends Session Request (type 5)
   - Host must reply with Session Message (type 6) containing LanSessionInfo
   - Session key derived from session_key_param via HMAC-SHA256
   - PIA v9 AES-GCM encryption (MAC=8)
   - ❌ NOT IMPLEMENTED IN C++

## Build & Deploy

```bash
cd sys-slp-client/sysmodule
make

# Deploy
cp sys-slp-client.nsp /path/to/sdcard/atmosphere/contents/4200000000000011/exefs.nsp
```

## Testing

```bash
# Run demo host (Python)
cd spike
python3 demo_host.py 127.0.0.1 11451

# Run tests
python3 test_lan.py
python3 test_ldn.py
```

## Debug

- Trace log: `/switch/slp-trace.log` (FTP accessible)
- PIA session layer logging enabled for port 49152
- Relay log: `/tmp/slp-server.log`

## Next Priority

Find corrections to C++ tunnel (port 49152 handling) to fix 2618-0006 crash on join?
