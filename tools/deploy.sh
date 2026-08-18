#!/bin/bash
# deploy.sh - Deploy sys-slp-client build artifacts to the local sdcard/ mirror
#             (default) or to a real Switch via FTP.
# Usage: ./deploy.sh [sdcard|ftp] [nsp|ovl|config|all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SYSMODULE_DIR="${PROJECT_ROOT}/sysmodule"
OVERLAY_DIR="${PROJECT_ROOT}/overlay"
CONFIG_DIR="${PROJECT_ROOT}/config"
SDCARD_DIR="$(cd "${PROJECT_ROOT}/../sdcard" && pwd)"

TITLE_ID="4200000000000011"
CONTENT_DIR="${SDCARD_DIR}/atmosphere/contents/${TITLE_ID}"

SWITCH_IP="10.172.227.168"
SWITCH_PORT="5000"
FTP_BASE="ftp://${SWITCH_IP}:${SWITCH_PORT}"

# --- sdcard/ (local mirror) ---------------------------------------------

# NOTE: sys-slp-client is deployed ONLY as exefs.nsp. An older convention
# also placed a loose sys-slp-client.nso + app.json under a "romfs/"
# subdirectory of the content dir; that was never a real bootable layout,
# and having both present at once caused a fatal error at boot (2026-08-16,
# most likely because Atmosphere tried to mount "romfs/" as this title's
# RomFs data and choked on two arbitrary files that aren't a real RomFs
# image). Removed. If you see a "romfs/" folder under
# atmosphere/contents/4200000000000011/ on a console or the sdcard/ mirror,
# delete it.

sdcard_nsp() {
    mkdir -p "${CONTENT_DIR}"
    cp "${SYSMODULE_DIR}/sys-slp-client.nsp" "${CONTENT_DIR}/exefs.nsp"
    cp "${SYSMODULE_DIR}/res/toolbox.json" "${CONTENT_DIR}/toolbox.json"
    rm -rf "${CONTENT_DIR}/romfs"
    # See ftp_nsp(): a deploy always re-enables the module.
    mkdir -p "${CONTENT_DIR}/flags"
    : > "${CONTENT_DIR}/flags/boot2.flag"
    echo "sdcard: exefs.nsp + toolbox.json + flags/boot2.flag updated (stale romfs/ removed if present)"
}

sdcard_ovl() {
    mkdir -p "${SDCARD_DIR}/switch/.overlays"
    cp "${OVERLAY_DIR}/slp-helper.ovl" "${SDCARD_DIR}/switch/.overlays/slp-helper.ovl"
    echo "sdcard: switch/.overlays/slp-helper.ovl updated"
}

sdcard_config() {
    mkdir -p "${SDCARD_DIR}/config/slp-helper"
    cp "${CONFIG_DIR}/servers.conf" "${SDCARD_DIR}/config/slp-helper/servers.conf"
    echo "sdcard: config/slp-helper/servers.conf updated"
    # options.conf is not deployed: it's device-side/live tuning with no
    # source-of-truth file in the project, and the sysmodule no longer reads
    # it at all (ReloadOptions()/skip_first_bsd_session/bsd_whitelist were
    # removed 2026-08-16 -- see slp_runtime.cpp).
}

sdcard_all() {
    sdcard_nsp
    sdcard_ovl
    sdcard_config
}

# --- FTP (real console) ---------------------------------------------------

# Direct-to-final-path uploads (curl --ftp-create-dirs). This only works
# while sys-slp-client is NOT currently running -- its content dir is held
# open/locked for as long as the boot2 process is alive. If a write fails
# with "550"/"450", the module is probably still resident; there is no remote
# way to force it to release the lock short of rebooting the console. In that
# case the on-console file is simply left as-is (unchanged), which is safe.

# Delete a remote file before re-uploading, so we never leave a stale/partial
# file behind. MUST use an ABSOLUTE remote path: curl runs -Q commands on the
# initial (root) connection before any CWD, and a relative "DELE
# switch/.overlays/x.ovl" silently fails there, while "DELE /switch/..." works.
# Missing files are fine -- the DELE just errors and we carry on.
ftp_rm() {
    curl -s --connect-timeout 10 "${FTP_BASE}/" -Q "DELE $1" -o /dev/null 2>/dev/null || true
}

ftp_nsp() {
    ftp_rm "/atmosphere/contents/${TITLE_ID}/exefs.nsp"
    ftp_rm "/atmosphere/contents/${TITLE_ID}/toolbox.json"
    echo "Uploading exefs.nsp + toolbox.json via FTP (direct to final path)..."
    curl --ftp-create-dirs -T "${SYSMODULE_DIR}/sys-slp-client.nsp" \
        "${FTP_BASE}/atmosphere/contents/${TITLE_ID}/exefs.nsp"
    curl --ftp-create-dirs -T "${SYSMODULE_DIR}/res/toolbox.json" \
        "${FTP_BASE}/atmosphere/contents/${TITLE_ID}/toolbox.json"

    # ALWAYS restore boot2.flag. Without it the sysmodule is simply not started
    # at boot, so a deploy "succeeds" and then nothing runs -- which looks
    # exactly like the new build being broken. Disabling the module is a
    # deliberate, temporary act (done to recover from a fatal); deploying a new
    # build is the point at which it must come back on.
    : > "${TMP_EMPTY_FLAG:=/tmp/slp-boot2.flag}"
    curl --ftp-create-dirs -T "${TMP_EMPTY_FLAG}" \
        "${FTP_BASE}/atmosphere/contents/${TITLE_ID}/flags/boot2.flag"
    rm -f "${TMP_EMPTY_FLAG}"
    echo "exefs.nsp + toolbox.json + flags/boot2.flag placed in atmosphere/contents/${TITLE_ID}/."

    # Report the build id compiled into this binary, and verify the upload is
    # byte-complete. A partial/blocked FTP write (exefs.nsp can be held open by
    # the running sysmodule) otherwise looks identical to a successful deploy.
    local bid local_size remote_size
    bid="$(strings "${SYSMODULE_DIR}/sys-slp-client.nso" 2>/dev/null            | grep -oE '^20[0-9]{6}-[0-9]{6}$' | head -1)"
    local_size="$(stat -c%s "${SYSMODULE_DIR}/sys-slp-client.nsp" 2>/dev/null)"
    remote_size="$(curl -s --max-time 10 "${FTP_BASE}/atmosphere/contents/${TITLE_ID}/"                    | awk '/exefs.nsp/{print $5}')"
    echo "  build id : ${bid:-<unknown>}"
    if [ -n "${local_size}" ] && [ "${local_size}" = "${remote_size}" ]; then
        echo "  verified : ${remote_size} bytes on console == local build"
    else
        echo "  MISMATCH : local=${local_size:-?} console=${remote_size:-?} -- DEPLOY DID NOT LAND"
        echo "             reboot with the module disabled and deploy again."
    fi
    # slp-trace.log APPENDS across boots, so the banner is not line 1 of the
    # file -- it marks the start of each boot section. Grep for it.
    echo "  after boot, slp-trace.log must contain: build ${bid:-?}"
    echo "             (check with: grep '=====' slp-trace.log | tail -1)"
}

ftp_ovl() {
    ftp_rm "/switch/.overlays/slp-helper.ovl"
    echo "Uploading slp-helper.ovl via FTP (direct to final path)..."
    curl --ftp-create-dirs -T "${OVERLAY_DIR}/slp-helper.ovl" \
        "${FTP_BASE}/switch/.overlays/slp-helper.ovl"
    echo "slp-helper.ovl placed directly in switch/.overlays/."
    return 0
}

ftp_config() {
    echo "FTP deploy has no config step (sdcard-only); skipping."
}

ftp_all() {
    ftp_nsp
    ftp_ovl
}

# --- dispatch ---------------------------------------------------------------

TARGET="${1:-sdcard}"
ARTIFACT="${2:-all}"

case "${TARGET}" in
    sdcard) PREFIX="sdcard" ;;
    ftp)    PREFIX="ftp" ;;
    *) echo "Usage: $0 [sdcard|ftp] [nsp|ovl|config|all]"; exit 1 ;;
esac

case "${ARTIFACT}" in
    nsp|ovl|config|all) "${PREFIX}_${ARTIFACT}" ;;
    *) echo "Usage: $0 [sdcard|ftp] [nsp|ovl|config|all]"; exit 1 ;;
esac
