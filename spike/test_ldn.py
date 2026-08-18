#!/usr/bin/env python3
"""
sys-slp-client — local test suite for the LDN control plane over slp.

Verifies the ldn:u control-plane MITM design WITHOUT a console:

  Codec (unit):         RLE round-trips (incl. long zero runs), LAN packet
                        header parse/build, struct sizes/offsets, fake MAC /
                        ssid / node-info fields.
  State machine (unit): host CreateNetwork invariants; scan filter.
  End-to-end (relay):   two virtual consoles over slp-server-rust:
                        host OpenAccessPoint+CreateNetwork ->
                        client OpenStation -> scan (broadcast Scan /
                        ScanResp) -> connect (Connect / SyncNetwork) ->
                        both nodes agree on NetworkInfo; disconnect.

The control frames are UDP datagrams on port 11452 (ldn_mitm's DefaultPort)
carried as IPv4/UDP packets through the relay — exactly the transport
sys-slp-client's LdnControl uses on console.

Usage:  python3 spike/test_ldn.py [relay_host] [relay_port]
"""

import random
import socket
import struct
import sys
import time

import slp_ldn as ldn

RES = []
RELAY_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RELAY_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 11451
RELAY = (RELAY_HOST, RELAY_PORT)

# The relay's IP->peer cache never prunes, so reusing an inner IP across runs
# black-holes first frames (known quirk). Give every run a fresh /24 subnet.
_IPBASE = random.randint(16, 200)


def _ip(i):
    return [10, 13, 37, _IPBASE + i]


def test(name, fn):
    try:
        fn()
        RES.append((name, True, ""))
    except Exception as e:  # noqa: BLE001
        RES.append((name, False, str(e)))


def ok(cond, msg=""):
    if not cond:
        raise AssertionError(msg or "assertion failed")


# ================================================================= codec =

def t_rle_roundtrip():
    samples = [
        b"A" * 100,
        b"\x00" * 10,
        b"\x00" * 256,
        bytes(range(256)) * 2,
        b"",
        b"\x00AB\x00\x00\x00CD",
    ]
    for s in samples:
        c = ldn.compress(s)
        if c is not None:
            ok(ldn.decompress(c) == s, f"roundtrip failed for {s!r}")
        else:
            # Incompressible: sender transmits the raw body with compressed=0,
            # so the receiver must NOT decompress it. Verify that path through
            # the packet codec instead of decompress() (which would misread any
            # literal 0x00 byte in the raw body).
            t, out = ldn.unpack_packet(
                ldn.pack_header(ldn.LAN_SCAN_RESP, s, use_compression=False))
            ok(t == ldn.LAN_SCAN_RESP and out == s, f"raw path failed for {s!r}")


def t_rle_zero_run():
    ok(ldn.compress(b"\x00" * 10) == b"\x00\x09", "zero-run encoding")
    ok(ldn.decompress(b"\x00\x09") == b"\x00" * 10, "zero-run decoding")
    ok(ldn.decompress(b"\x00\x00") == b"\x00", "single zero is 00 00")
    ok(ldn.decompress(b"\x41\x42") == b"AB", "literals pass through")


def t_packet_codec():
    body = bytes(range(256)) * 2
    raw = ldn.pack_header(ldn.LAN_SCAN_RESP, body)
    t, out = ldn.unpack_packet(raw)
    ok(t == ldn.LAN_SCAN_RESP and out == body, "compressed packet roundtrip")
    raw2 = ldn.pack_header(ldn.LAN_SYNC_NETWORK, body[:20], use_compression=False)
    t2, out2 = ldn.unpack_packet(raw2)
    ok(t2 == ldn.LAN_SYNC_NETWORK and out2 == body[:20], "uncompressed roundtrip")
    ok(ldn.unpack_packet(b"\x00" * 11) is None, "short/garbage rejected")
    bad = bytearray(raw)
    bad[0] ^= 0xFF
    ok(ldn.unpack_packet(bytes(bad)) is None, "wrong magic rejected")


def t_struct_sizes():
    ok(ldn.HDR.size == 12, f"header {ldn.HDR.size} != 12")
    ok(ldn.NODE.size == 64, f"NodeInfo {ldn.NODE.size} != 0x40")
    ok(ldn.COMMON.size == 48, f"CommonNetworkInfo {ldn.COMMON.size} != 0x30")
    ok(ldn.LDN.size == 0x430, f"LdnNetworkInfo {ldn.LDN.size} != 0x430")
    ok(ldn.NETWORK.size == 0x480, f"NetworkInfo {ldn.NETWORK.size} != 0x480")


def t_node_info_fields():
    ni = ldn.build_node_info(bytes([10, 13, 37, 101]), 3, 1, "Alice", lcv=6)
    p = ldn.parse_node_info(ni)
    ok(p["ip"] == bytes([10, 13, 37, 101]), "ip roundtrip")
    ok(p["node_id"] == 3 and p["is_connected"] == 1 and p["lcv"] == 6, "fields")
    ok(p["name"] == "Alice", "name roundtrip")
    ok(p["mac"] == bytes([0x02, 0x00, 10, 13, 37, 101]), "fake mac")


def t_network_info_fields():
    ip = bytes([10, 13, 37, 100])
    intent = struct.pack("<QHH4x", 0x1122334455667788, 0, 7)
    node0 = ldn.build_node_info(ip, 0, 1, "HOST", 6)
    ldnblob = ldn.build_ldn_network_info([node0], node_count_max=7)
    common = ldn.build_common_network_info(ldn.fake_mac(ip))
    ni = ldn.parse_network_info(
        ldn.build_network_info(intent, b"\x00" * 16, common, ldnblob))
    ok(ni["ssid"] == ldn.FAKE_SSID, "fake ssid")
    ok(ni["channel"] == 6 and ni["link_level"] == 3 and ni["network_type"] == 2,
       "channel/link/networkType defaults")
    ok(ni["node_count"] == 1 and ni["node_count_max"] == 7, "node counts")
    ok(ni["nodes"][0]["node_id"] == 0 and ni["nodes"][0]["ip"] == ip, "node0")
    ok(ldn.network_id_of(ni) == 0x1122334455667788, "localCommunicationId")
    ok(ldn.scene_id_of(ni) == 7, "sceneId")


# ====================================================== state machine unit =

def t_host_create_invariants():
    n = ldn.LdnNode(_ip(0), "HOST", RELAY)
    n.state = ldn.STATE_INITIALIZED
    n.open_access_point()
    ok(n.state == ldn.STATE_ACCESS_POINT, "AP state")
    n.create_network()
    ok(n.state == ldn.STATE_ACCESS_POINT_CREATED, "AP created")
    ok(n.network_info["node_count"] == 1, "nodeCount starts at 1")
    ok(n.network_info["nodes"][0]["is_connected"] == 1, "host node connected")
    ok(network_host_ip(n) == n.ip, "nodes[0] is us")
    n.destroy_network()
    ok(n.state == ldn.STATE_ACCESS_POINT, "destroy -> AP")


def network_host_ip(node):
    return node.network_info["nodes"][0]["ip"]


# ============================================================== end-to-end =

def relay_available():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    try:
        s.sendto(bytes([0x00]), RELAY)
        s.close()
        return True
    except OSError:
        return False


def t_e2e_ldn_room():
    host = ldn.LdnNode(_ip(0), "HOST-1", RELAY)
    client = ldn.LdnNode(_ip(1), "CLIENT-1", RELAY)
    host.keepalive()
    client.keepalive()
    time.sleep(0.2)
    host.state = ldn.STATE_INITIALIZED
    client.state = ldn.STATE_INITIALIZED

    # host opens a room
    host.open_access_point()
    lcid = 0x0A0B0C0D
    session_id = bytes((0x40 + i) & 0xFF for i in range(16))
    host.create_network(local_comm_id=lcid, session_id=session_id,
                        node_count_max=3, security_mode=0)

    # client scans (filtered by intentId like ldn_mitm's ScanFilter)
    client.open_station()
    results = client.scan(local_comm_id=lcid)
    ok(len(results) == 1, f"scan found {len(results)} network(s)")
    info = results[0]
    ok(info["bssid"] == host.network_info["bssid"], "host bssid found")
    ok(ldn.network_id_of(info) == lcid, "localCommunicationId matches")
    ok(info["session"] == session_id, "session id matches")
    ok(info["nodes"][0]["ip"] == host.ip, "host ip in scan result")
    ok(len(client.recv_srcs) > 0, "client saw control datagrams")

    # client connects: Connect -> SyncNetwork -> StationConnected
    ok(client.connect(info), "client joined")
    ok(client.state == ldn.STATE_STATION_CONNECTED, "station connected")

    # host side sees the station and nodeCount grew
    ok(len(host.stations) == 1, "host registered the station")
    sid, s = next(iter(host.stations.items()))
    ok(s["ip"] == client.ip, "station recorded with client tunnel IP")
    ok(s["node"]["name"] == "CLIENT-1", "station node name")

    # both sides agree on NetworkInfo (nodeCount 2, same nodes)
    hn = host.network_info
    cn = client.network_info
    ok(hn["node_count"] == 2 and cn["node_count"] == 2, "nodeCount == 2 both sides")
    ok(hn["nodes"][1]["ip"] == client.ip, "host node list has client")
    ok(cn["nodes"][1]["ip"] == client.ip, "client sees itself in node list")
    ok(cn["nodes"][0]["ip"] == host.ip, "client sees host as node0")
    ok(cn["bssid"] == hn["bssid"], "client syncs host bssid")
    ok(cn["session"] == hn["session"], "client syncs session id")

    # disconnect
    client.disconnect()
    ok(client.state == ldn.STATE_STATION, "disconnect -> Station")
    host.close()
    client.close()


def t_e2e_two_clients():
    host = ldn.LdnNode(_ip(10), "HOST-2", RELAY)
    c1 = ldn.LdnNode(_ip(11), "C-1", RELAY)
    c2 = ldn.LdnNode(_ip(12), "C-2", RELAY)
    for n in (host, c1, c2):
        n.keepalive()
    time.sleep(0.2)
    for n in (host, c1, c2):
        n.state = ldn.STATE_INITIALIZED

    host.open_access_point()
    lcid2 = 0x77778888
    host.create_network(local_comm_id=lcid2, node_count_max=3)

    c1.open_station()
    c2.open_station()
    r1 = c1.scan(local_comm_id=lcid2)
    r2 = c2.scan(local_comm_id=lcid2)
    ok(len(r1) == 1 and len(r2) == 1, "both clients scan one network")

    ok(c1.connect(r1[0]) and c2.connect(r2[0]), "both clients join")
    ok(len(host.stations) == 2, "host sees two stations")
    ok(host.network_info["node_count"] == 3, "nodeCount == 3")

    # Client-side leave is instant for the leaving player. The host keeps the
    # station entry: ldn_mitm's LAN codec has no Disconnect frame and hosts only
    # learn of departures via TCP close, which we do not emulate over UDP.
    # (Pia's own keepalives in the data plane are what games actually use to
    # detect peer loss.) So nodeCount stays 3 on the host.
    c1.disconnect()
    time.sleep(0.3)
    ok(c1.state == ldn.STATE_STATION, "c1 left (client side)")
    ok(c2.state == ldn.STATE_STATION_CONNECTED, "c2 stays connected")
    ok(host.network_info["node_count"] == 3,
       "host keeps stale station (no Disconnect frame in ldn_mitm codec)")
    host.close()
    c1.close()
    c2.close()


def main():
    print(f"relay: {RELAY_HOST}:{RELAY_PORT}  control port: 11452 (ldn_mitm DefaultPort)")
    print()

    tests = [
        ("codec: RLE round-trip incl. zero runs", t_rle_roundtrip),
        ("codec: zero-run encoding matches ldn_mitm", t_rle_zero_run),
        ("codec: LAN packet header parse/build", t_packet_codec),
        ("codec: struct sizes (0x480/0x430/0x40/0x30/12)", t_struct_sizes),
        ("codec: NodeInfo fields + fake MAC", t_node_info_fields),
        ("codec: NetworkInfo fields (ssid/channel/link)", t_network_info_fields),
        ("sm: host CreateNetwork invariants", t_host_create_invariants),
    ]

    e2e = [
        ("e2e: host room -> client scan/connect/sync (relay)", t_e2e_ldn_room),
        ("e2e: two clients join, re-sync on leave (relay)", t_e2e_two_clients),
    ]

    for name, fn in tests:
        test(name, fn)
    if relay_available():
        for name, fn in e2e:
            test(name, fn)
    else:
        print(f"  (relay {RELAY_HOST}:{RELAY_PORT} not reachable — skipping e2e tests)")

    print()
    fails = 0
    for name, ok_, err in RES:
        print(f"  [{'PASS' if ok_ else 'FAIL'}] {name}" + (f"  ({err})" if err else ""))
        fails += 0 if ok_ else 1
    print(f"\n{len(RES) - fails}/{len(RES)} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
