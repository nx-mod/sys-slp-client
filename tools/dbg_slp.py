#!/usr/bin/env python3
import socket, struct, threading, time, sys

HDR = 0x7F
KEEPALIVE, IPV4, PING = 0x00, 0x01, 0x02
A_IP = (192, 168, 1, 10)
B_IP = (192, 168, 1, 20)

def ip(i):
    return struct.pack("!4B", *i)

def ipv4(src, dst, proto=17, payload=b""):
    total = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, ip(src), ip(dst)) + payload

def udp(src, sport, dst, dport, payload=b""):
    return ipv4(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)

class C:
    def __init__(self, name, ip_, server):
        self.name, self.sock = name, socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.3)
        self.ip, self.server = ip_, server
        self.recvlog = []
        threading.Thread(target=self._r, daemon=True).start()
    def _r(self):
        while True:
            try:
                d, a = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            t = d[0] & HDR
            self.recvlog.append((time.monotonic(), d.hex()))
            print(f"[{self.name}] RECV t={t} from {a} {d.hex()}", flush=True)
    def send(self, b):
        print(f"[{self.name}] SEND {b.hex()}", flush=True)
        self.sock.sendto(b, self.server)

port = int(sys.argv[1]) if len(sys.argv) > 1 else 11551
server = ("127.0.0.1", port)
a, b = C("A", A_IP, server), C("B", B_IP, server)
time.sleep(0.2)

print("== B keepalive (register) ==")
b.send(bytes([KEEPALIVE]))
time.sleep(0.5)

print("== A ping rust-style 02 + 4B ==")
a.send(bytes([PING, 1, 2, 3, 4]))
time.sleep(1.0)

print("== A ping ts-style 02 + 3B ==")
a.send(bytes([PING, 9, 9, 9]))
time.sleep(1.0)

print("== A ipv4 unicast -> B ==")
a.send(bytes([IPV4]) + udp(A_IP, 11454, B_IP, 11454, b"hello"))
time.sleep(1.0)

print("== A broadcast ==")
a.send(bytes([IPV4]) + udp(A_IP, 11454, (255, 255, 255, 255), 11454, b"disc"))
time.sleep(1.0)
