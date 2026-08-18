#!/bin/bash
# wifi_diag.py - Diagnose WiFi/nifm issues on the Switch via slp-helper overlay IPC
# 
# This script queries the sys-slp-client overlay via GPIO/I2C or checks the
# trace log for WiFi-related initialization status.
#
# Usage: ./wifi_diag.py [--switch-ip IP] [--check-nifm] [--check-wifi-mode]
#
# Prerequisites:
#   - Switch running sys-slp-client with slp-helper overlay
#   - Switch on same network
#   - overlay must support diag commands

import argparse
import socket
import struct
import sys
import time

DEFAULT_SWITCH_IP = "10.172.227.168"
DEFAULT_SWITCH_PORT = 5000

# SLP frame type constants (matching slp_client.h)
SLP_TYPE_KEEPALIVE = 0x00
SLP_TYPE_PING = 0x02
SLP_TYPE_IPV4 = 0x01
SLP_TYPE_IPV4_FRAG = 0x03

def parse_args():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--switch-ip", default=DEFAULT_SWITCH_IP)
    ap.add_argument("--port", type=int, default=DEFAULT_SWITCH_PORT)
    ap.add_argument("--check-nifm", action="store_true",
                    help="Check if nifm local network mode is set")
    ap.add_argument("--check-wifi-mode", action="store_true",
                    help="Check WiFi mode status (requires overlay diag)")
    return ap.parse_args()

def build_keepalive():
    """Build a keepalive frame matching slpFrameKeepalive()."""
    return bytes([SLP_TYPE_KEEPALIVE])

def send_keepalive(ip, port):
    """Send a keepalive packet to register with relay."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        ka = build_keepalive()
        sock.sendto(ka, (ip, port))
        data, addr = sock.recvfrom(65535)
        print(f"  Got response: {len(data)} bytes from {addr}")
        return True
    except socket.timeout:
        print("  No response (timeout)")
        return False
    except Exception as e:
        print(f"  Error: {e}")
        return False
    finally:
        sock.close()

def check_trace_log():
    """Check slp-trace.log for WiFi/nifm related messages."""
    # This would need to be fetched from the Switch SD card
    import subprocess
    result = subprocess.run(
        ["grep", "-i", "nifm\|local_network\|wifi\|wlan\|local network mode", 
         "/tmp/slp-trace.log"],
        capture_output=True, text=True
    )
    if result.stdout:
        print("Trace log WiFi/nifm entries:")
        for line in result.stdout.strip().split('\n'):
            print(f"  {line}")
        return True
    else:
        print("No WiFi/nifm entries found in trace log")
        return False

def main():
    args = parse_args()
    
    print(f"WiFi/NIFM Diagnostic")
    print(f"  Target: {args.switch_ip}:{args.port}")
    print()
    
    # 1. Check network connectivity
    print("[1] Checking relay connectivity...")
    if send_keepalive(args.switch_ip, args.port):
        print("  OK: Relay reachable and responding")
    else:
        print("  FAIL: Cannot reach relay")
    print()
    
    # 2. Check trace log
    print("[2] Checking trace log for NIFM/WiFi entries...")
    try:
        check_trace_log()
    except Exception as e:
        print(f"  Error reading trace: {e}")
    print()
    
    # 3. NIFM check
    if args.check_nifm:
        print("[3] Checking NIFM local network mode status...")
        print("  (Requires overlay diagnostic command)")
        print("  Look for nifmSetLocalNetworkMode calls in trace log")
        print()
    
    # 4. WiFi mode check
    if args.check_wifi_mode:
        print("[4] Checking WiFi mode...")
        print("  (Requires overlay diagnostic command)")
        print("  Look for nifmRequestSubmit / local network mode in trace")
        print()
    
    print("Summary:")
    print("  - If trace shows NO nifm local network mode calls,")
    print("    the WiFi initialization is incomplete (see wifi-atmosphere-issues.md)")
    print("  - If Socket() shows errno!=0 for fd=2, the WiFi mode is likely blocking")
    print("    local broadcast socket creation")
    print("  - If Bind shows 'not tracked, forwarding to real service' for port 30000,")
    print("    the BSD MITM cannot intercept LAN traffic")

if __name__ == "__main__":
    main()
