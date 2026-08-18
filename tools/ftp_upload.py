import ftplib, hashlib, os, sys

HOST, PORT = "10.172.227.168", 5000

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.join(_SCRIPT_DIR, "..")
_SDCARD = os.path.join(_PROJECT_ROOT, "..", "sdcard")

# sys-slp-client is deployed ONLY as exefs.nsp -- no loose romfs/*.nso (see
# deploy.sh's note; having both caused a fatal boot error, 2026-08-16).
files = [
    (os.path.join(_SDCARD, "atmosphere/contents/4200000000000011/exefs.nsp"), "atmosphere/contents/4200000000000011/exefs.nsp"),
    (os.path.join(_SDCARD, "switch/.overlays/slp-helper.ovl"), "switch/.overlays/slp-helper.ovl"),
]

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()

ftp = ftplib.FTP()
ftp.connect(HOST, PORT, timeout=30)
ftp.login()
for local, remote in files:
    # ensure parent dirs exist
    parts = remote.split("/")
    cur = ""
    for part in parts[:-1]:
        cur += part
        try:
            ftp.mkd(cur)
        except Exception:
            pass
        cur += "/"
    with open(local, "rb") as f:
        ftp.storbinary("STOR " + remote, f)
    # download back and verify
    data = bytearray()
    def collect(b):
        data.extend(b)
    ftp.retrbinary("RETR " + remote, collect)
    got = hashlib.sha256(bytes(data)).hexdigest()
    want = sha(local)
    print(f"{remote}: {'OK' if got == want else 'MISMATCH'} local={want[:16]}... ftp={got[:16]}... size={len(data)}")
ftp.quit()
