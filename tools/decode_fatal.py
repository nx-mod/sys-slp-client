#!/usr/bin/env python3
"""
decode_fatal.py — decode Atmosphere fatal error reports (atmosphere/fatal_reports/dumps/*.bin).

Fetches the newest report over FTP (unless a local path is given), parses the
"AFE2" FatalErrorContext, and symbolizes the backtrace against the sys-slp-client ELF.

NOTE (2026-08-16): this only decodes AFE2-format sysmodule fatal aborts
(std::abort/AMS_ABORT/R_ABORT_UNLESS in our own code), written to
atmosphere/fatal_reports/dumps/. A GAME crashing (e.g. MK8DX) produces a
DIFFERENT format in atmosphere/crash_reports/dumps/ -- Atmosphere's creport,
magic "DTI2", a per-thread dump (registers + full thread-name table), not an
AFE2 FatalErrorContext. This script does NOT parse that format; there is no
tooling for it yet.

Usage:
    python3 tools/decode_fatal.py [report.bin] [elf]

Examples:
    python3 tools/decode_fatal.py                       # fetch newest from console + symbolize
    python3 tools/decode_fatal.py /tmp/fatal.bin        # decode a local dump
    python3 tools/decode_fatal.py /tmp/fatal.bin out.elf
"""

import ftplib
import struct
import subprocess
import sys
import os

FTP_HOST, FTP_PORT = "10.172.227.168", 5000
FATAL_DIR = "atmosphere/fatal_reports/dumps"
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ELF = os.path.join(_SCRIPT_DIR, "..", "sysmodule", "sys-slp-client.elf")
ADDR2LINE = os.environ.get(
    "DEVKITPRO", "C:/devkitpro").rstrip("/\\") + "/devkitA64/bin/aarch64-none-elf-addr2line.exe"

ERROR_DESC = {
    0xFFE: "StdAbortErrorDesc (std::abort / AMS_ABORT / R_ABORT_UNLESS / AMS_ASSERT)",
    0xFFD: "StackOverflowErrorDesc (stack overflow)",
    0xF00: "KernelPanicDesc",
    0x101: "DataAbortErrorDesc (data abort)",
}


def fmt_ver(major, minor, micro):
    return f"{major}.{minor}.{micro}"


def parse_report(data):
    """Parse ams::impl::FatalErrorContext (AFE2, 0x450 bytes)."""
    magic, error_desc = struct.unpack_from("<II", data, 0x00)
    program_id = struct.unpack_from("<Q", data, 0x08)[0]
    gprs = list(struct.unpack_from("<32Q", data, 0x10))
    pc = struct.unpack_from("<Q", data, 0x110)[0]
    module_base = struct.unpack_from("<Q", data, 0x118)[0]
    pstate, afsr0, afsr1, esr = struct.unpack_from("<IIII", data, 0x120)
    far = struct.unpack_from("<Q", data, 0x130)[0]
    report_id = struct.unpack_from("<Q", data, 0x138)[0]
    stack_trace_size = struct.unpack_from("<Q", data, 0x140)[0]
    stack_dump_size = struct.unpack_from("<Q", data, 0x148)[0]
    stack_trace = list(struct.unpack_from("<32Q", data, 0x150))

    return {
        "magic": magic,
        "error_desc": error_desc,
        "program_id": program_id,
        "gprs": gprs,
        "pc": pc,
        "module_base": module_base,
        "pstate": pstate,
        "afsr0": afsr0,
        "afsr1": afsr1,
        "esr": esr,
        "far": far,
        "report_id": report_id,
        "stack_trace_size": stack_trace_size,
        "stack_dump_size": stack_dump_size,
        "stack_trace": stack_trace,
    }


def fetch_newest_report():
    ftp = ftplib.FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=30)
    ftp.login()
    names = [n for n, _ in ftp.mlsd(FATAL_DIR) if n.startswith("report_") and n.endswith(".bin")]
    if not names:
        ftp.quit()
        raise SystemExit("no fatal reports on console")
    names.sort()
    remote = f"{FATAL_DIR}/{names[-1]}"
    print(f"fetching {remote}")
    data = bytearray()
    ftp.retrbinary(f"RETR {remote}", data.extend)
    ftp.quit()
    return bytes(data), remote


def symbolize(addr, elf):
    try:
        out = subprocess.run(
            [ADDR2LINE, "-f", "-C", "-e", elf, hex(addr)],
            capture_output=True, text=True, timeout=30)
        func, loc = out.stdout.splitlines()[:2]
        return f"{func}  ({loc})"
    except Exception as e:
        return f"<symbolize failed: {e}>"


def main():
    if len(sys.argv) >= 2:
        data = open(sys.argv[1], "rb").read()
        remote = sys.argv[1]
    else:
        data, remote = fetch_newest_report()

    elf = sys.argv[2] if len(sys.argv) >= 3 else DEFAULT_ELF

    if data[:4] != b"AFE2":
        print(f"error: not an AFE2 fatal report (magic {data[:4]!r})")
        return 1

    r = parse_report(data)
    title = f"0x{r['program_id']:016X}"

    print(f"== {remote} ({len(data)} bytes)")
    print(f"error_desc : 0x{r['error_desc']:X}  {ERROR_DESC.get(r['error_desc'], 'unknown')}")
    print(f"program_id : {title}")
    print(f"pc         : 0x{r['pc']:X}  (module base 0x{r['module_base']:X}, offset 0x{r['pc'] - r['module_base']:X})")
    print(f"pstate     : 0x{r['pstate']:X}  afsr0=0x{r['afsr0']:X}  afsr1=0x{r['afsr1']:X}  esr=0x{r['esr']:X}  far=0x{r['far']:X}")
    print(f"report id  : 0x{r['report_id']:X}")
    print()
    print(f"== stack trace ({r['stack_trace_size']} frames)")
    for i, a in enumerate(r["stack_trace"][: r["stack_trace_size"]]):
        if a == 0:
            continue
        off = a - r["module_base"]
        print(f"  [{i}] 0x{a:X}  {symbolize(off, elf)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
