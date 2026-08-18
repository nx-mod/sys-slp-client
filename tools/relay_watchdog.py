#!/usr/bin/env python3
"""relay_watchdog.py - keep the slp relay + fake host alive during testing.

WHY THIS EXISTS
---------------
On Windows the relay's UDP recv task dies from a WSAECONNRESET raised by an
ICMP port-unreachable (a peer went away). When that happens the process does
NOT exit and its HTTP endpoint keeps answering normally -- it just stops
forwarding every packet. From the console it is indistinguishable from "our
sysmodule broke": both the LAN and the WiFi lobby vanish at once.

That has already burned several on-hardware test runs, where a reboot was
spent testing against a relay that could not hear anything. We cannot fix the
cause -- slp-server-rust is a fixed target and must never be modified -- so we
detect it from outside and restart.

DETECTION
---------
The fake host holds two peer slots (LDN + LAN) for as long as it is running.
So if the host process is up but the relay reports fewer than 2 peers, the
relay's recv path is dead even though HTTP is fine. A grace period avoids
tripping during the couple of seconds after a restart.

Usage:  python3 relay_watchdog.py [--interval 10] [--port 11451]
Stop:   Ctrl-C, or kill the process.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAN_PLAY = os.path.dirname(ROOT)
RELAY = os.path.join(LAN_PLAY, "slp-server-rust", "target", "release", "slp-server-rust.exe")
HOST_SCRIPT = os.path.join(ROOT, "spike", "demo_host.py")
MIN_PEERS = 2          # the fake host alone accounts for this many
GRACE_SECONDS = 20     # let a fresh relay+host settle before judging it


def server_info(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/info", timeout=5) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def kill(name):
    subprocess.run(["taskkill", "/F", "/IM", name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def kill_fake_host():
    """Kill ONLY the demo_host python process.

    A blanket `taskkill /IM python.exe` would kill this watchdog too -- it is
    also python.exe -- so match on the command line and skip our own PID."""
    me = os.getpid()
    try:
        out = subprocess.run(
            ["wmic", "process", "where", "name='python.exe'",
             "get", "ProcessId,CommandLine", "/format:csv"],
            capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return
    for line in out.splitlines():
        if "demo_host.py" not in line:
            continue
        pid = line.strip().rsplit(",", 1)[-1]
        if not pid.isdigit() or int(pid) == me:
            continue
        subprocess.run(["taskkill", "/F", "/PID", pid],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def restart(port):
    kill("slp-server-rust.exe")
    kill_fake_host()
    time.sleep(1)
    subprocess.Popen([RELAY, "-p", str(port)],
                     cwd=os.path.dirname(RELAY),
                     stdout=open("/tmp/slp-server.log", "ab"),
                     stderr=subprocess.STDOUT)
    time.sleep(2)
    subprocess.Popen([sys.executable, "-u", HOST_SCRIPT, "127.0.0.1", str(port)],
                     cwd=os.path.dirname(HOST_SCRIPT),
                     stdout=open("/tmp/slp-demo-host.log", "ab"),
                     stderr=subprocess.STDOUT)
    time.sleep(3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=10)
    ap.add_argument("--port", type=int, default=11451)
    args = ap.parse_args()

    print(f"watchdog: polling :{args.port} every {args.interval}s "
          f"(restart if peers < {MIN_PEERS})", flush=True)
    last_action = time.time()

    while True:
        time.sleep(args.interval)
        info = server_info(args.port)
        now = time.strftime("%H:%M:%S")

        if info is None:
            if time.time() - last_action < GRACE_SECONDS:
                continue
            print(f"[{now}] relay HTTP unreachable -> restarting", flush=True)
            restart(args.port)
            last_action = time.time()
            continue

        online = info.get("online", 0)
        if online < MIN_PEERS:
            if time.time() - last_action < GRACE_SECONDS:
                continue
            # HTTP answered but peers are gone => recv task died silently.
            print(f"[{now}] relay deaf (online={online}, HTTP alive) -> restarting",
                  flush=True)
            restart(args.port)
            last_action = time.time()
        else:
            print(f"[{now}] ok online={online} idle={info.get('idle')}", flush=True)


if __name__ == "__main__":
    main()
