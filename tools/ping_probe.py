#!/usr/bin/env python3
"""Reproduce the spike's ping ordering in isolation."""
import socket, struct, sys, time

HDR = 0x7F
PING = 0x02

def mk(tag):
    return bytes([PING]) + struct.pack("!4B", tag & 0xFF, (tag >> 8) & 0xFF,
                                       (tag >> 16) & 0xFF, (tag >> 24) & 0xFF)

port = int(sys.argv[1]) if len(sys.argv) > 1 else 11552
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(1.0)
server = ("127.0.0.1", port)

# order exactly like the spike: A and B both keepalive first, then A pings
s.sendto(b"\x00", server)          # A keepalive
s.sendto(b"\x00", server)          # B keepalive
time.sleep(0.2)

dat = mk(0x01020304)
print("SEND", dat.hex())
s.sendto(dat, server)

for i in range(10):
    try:
        d, a = s.recvfrom(65535)
    except socket.timeout:
        print("  ... timeout (no reply)")
        continue
    print(f"  RECV t={d[0] & HDR} {d.hex()}  match={d == dat}")
