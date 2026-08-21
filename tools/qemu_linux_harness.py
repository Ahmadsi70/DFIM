#!/usr/bin/env python3
"""
One-click QEMU validation harness for DFIM x86_64-unknown-linux-musl builds.

Builds the static provisioner, assembles an Alpine netboot kernel + custom initramfs
(pure-Python cpio newc packer — no bash/cpio dependency), boots QEMU in -nographic mode,
and collects JSONL compliance logs back to the host via the serial console.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEBUG_LOG = ROOT / "debug-e6be4e.log"
DEBUG_SESSION = "e6be4e"
ALPINE_VERSION = "3.20"
NETBOOT_BASE = (
    f"https://dl-cdn.alpinelinux.org/alpine/v{ALPINE_VERSION}/releases/x86_64/netboot"
)
ARTIFACTS = {
    "vmlinuz-virt": f"{NETBOOT_BASE}/vmlinuz-virt",
    "initramfs-virt": f"{NETBOOT_BASE}/initramfs-virt",
}
BUSYBOX_URL = (
    "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
)
CPIO_NEWC_MAGIC = b"070701"
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000
S_IFCHR = 0o020000
S_IFBLK = 0o060000

# Static virtio-blk node for QEMU `-drive if=virtio` (major 254, minor 0).
VDA_MAJOR = 254
VDA_MINOR = 0


def log(msg: str) -> None:
    print(f"[qemu-harness] {msg}", flush=True)


# #region agent log
def _agent_log(hypothesis_id: str, location: str, message: str, data: dict) -> None:
    """Append NDJSON debug line for harness diagnostics (session e6be4e)."""
    payload = {
        "sessionId": DEBUG_SESSION,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
        "runId": os.environ.get("DFIM_DEBUG_RUN_ID", "pre-fix"),
    }
    with DEBUG_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


# #endregion


def enforce_unix_lf(text: str) -> str:
    """Normalizes any CRLF/CR source text to strict Unix LF line endings."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def render_guest_init(*, cycles: int, inject_sector: int = 1) -> str:
    """Returns the guest PID-1 `/init` script with static VFS bootstrap injected."""
    return enforce_unix_lf(
        f"""#!/bin/busybox sh
# DFIM QEMU guest init — static device nodes, no dynamic udev/mdev dependency.
set -eu
BB=/bin/busybox
DEV="${{DFIM_BLOCK_DEV:-/dev/vda}}"
BIN="${{DFIM_PROVISIONER:-/dfim/dfim-provisioner}}"
GOLDEN="${{DFIM_GOLDEN:-/dfim/golden.bin}}"
JSONL="${{DFIM_JSONL_OUT:-/host_share/dfim_qemu_compliance.jsonl}}"
CYCLES="${{DFIM_CYCLES:-{cycles}}}"
INJECT_SECTOR="${{DFIM_INJECT_SECTOR:-{inject_sector}}}"

log() {{ printf '[guest] %s\\n' "$*"; }}

# Static VFS layout — avoids Alpine mini-kernel wiping dynamic /dev nodes.
"$BB" mkdir -p /proc /sys /dev /host_share /custom_dev /dfim
"$BB" mount -t proc proc /proc
"$BB" mount -t sysfs sys /sys
"$BB" mknod /custom_dev/zero c 1 5 2>/dev/null || true
"$BB" mknod /custom_dev/null c 1 3 2>/dev/null || true
"$BB" mknod /dev/null c 1 3 2>/dev/null || true

if [ -x /sbin/modprobe ]; then
  log "loading virtio_blk (Alpine virt initramfs has no sd_mod)"
  if /sbin/modprobe virtio_blk; then
    log "virtio_blk loaded"
  else
    log "WARN: virtio_blk modprobe exit=$?"
  fi
  /sbin/modprobe sd_mod 2>/dev/null || true
fi
"$BB" mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

_DEVNAME=""
_WAIT=0
while [ "$_WAIT" -lt 30 ]; do
  _BLK=$("$BB" awk 'NR>2 && $4 !~ /^(loop|ram|fd)/ {{print $4; exit}}' /proc/partitions)
  if [ -n "$_BLK" ]; then
    _DEVNAME="$_BLK"
    break
  fi
  for _candidate in vda sda hda xvda; do
    if [ -b "/dev/${{_candidate}}" ] || [ -r "/sys/block/${{_candidate}}/dev" ]; then
      _DEVNAME="${{_candidate}}"
      break
    fi
  done
  if [ -n "$_DEVNAME" ]; then
    break
  fi
  _WAIT=$((_WAIT + 1))
  "$BB" sleep 1
done

if [ -n "$_DEVNAME" ]; then
  DEV="/dev/${{_DEVNAME}}"
  if [ -r "/sys/block/${{_DEVNAME}}/dev" ]; then
    _VDEV=$("$BB" cat "/sys/block/${{_DEVNAME}}/dev")
    _VMAJ=${{_VDEV%%:*}}
    _VMIN=${{_VDEV##*:}}
    log "block ${{_DEVNAME}} dev=${{_VDEV}} — mknod $DEV"
    "$BB" mknod "$DEV" b "${{_VMAJ}}" "${{_VMIN}}" 2>/dev/null || true
  else
    log "block device $DEV present via devtmpfs"
  fi
else
  log "WARN: no block device after 30s — /proc/partitions:"
  "$BB" cat /proc/partitions 2>/dev/null || true
  exit 3
fi

log "paths DEV=$DEV GOLDEN=$GOLDEN JSONL=$JSONL CYCLES=$CYCLES"

if [ ! -x "$BIN" ]; then
  log "FATAL: provisioner missing at $BIN"
  exit 2
fi

if [ ! -s "$GOLDEN" ]; then
  log "FATAL: golden image missing at $GOLDEN"
  exit 2
fi

if [ ! -b "$DEV" ]; then
  log "FATAL: block device $DEV not present after static mknod"
  "$BB" ls -l /dev/ 2>/dev/null || true
  exit 3
fi

log "running raw-stress on $DEV ($CYCLES cycles, inject sector $INJECT_SECTOR)"
set +e
"$BIN" raw-stress \\
  --device "$DEV" \\
  --golden "$GOLDEN" \\
  --cycles "$CYCLES" \\
  --inject-sector "$INJECT_SECTOR" \\
  --jsonl-out "$JSONL"
_RS=$?
set -e
log "raw-stress exit code=${{_RS}}"

log "exporting compliance JSONL via serial console"
printf '===DFIM_JSONL_BEGIN===\\n'
if [ -s "$JSONL" ]; then
  "$BB" cat "$JSONL"
else
  log "WARN: JSONL empty at $JSONL"
fi
printf '===DFIM_JSONL_END===\\n'
"$BB" sync
"$BB" poweroff -f 2>/dev/null || "$BB" halt -f 2>/dev/null || "$BB" reboot -f
"""
    )


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    log("exec: " + " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size > 0:
        log(f"reuse {dest.name} ({dest.stat().st_size} bytes)")
        return
    log(f"download {url}")
    with urllib.request.urlopen(url, timeout=120) as response, dest.open("wb") as out:
        shutil.copyfileobj(response, out)
    sidecar = dest.with_suffix(dest.suffix + ".sha256")
    sidecar.write_text(sha256_file(dest) + "\n", encoding="utf-8")


def ensure_crypto_key(env: dict[str, str]) -> None:
    if env.get("DFIM_CRYPTO_KEY"):
        return
    import secrets

    env["DFIM_CRYPTO_KEY"] = secrets.token_hex(32)
    log("generated ephemeral DFIM_CRYPTO_KEY for this harness run")


def find_tool(name: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    if sys.platform == "win32":
        for root in (
            Path(r"C:\Program Files\qemu"),
            Path(r"C:\Program Files\QEMU"),
            Path(r"C:\qemu"),
        ):
            candidate = root / f"{name}.exe"
            if candidate.is_file():
                return str(candidate)
    raise RuntimeError(f"required tool not found on PATH: {name}")


@dataclass(frozen=True)
class CpioEntry:
    """Single newc cpio archive member."""

    path: str
    mode: int
    content: bytes = b""
    rdev_major: int = 0
    rdev_minor: int = 0
    nlink: int = 1
    ino: int = 0


def _cpio_field(value: int) -> bytes:
    return f"{value:08x}".encode("ascii")


def _cpio_header(entry: CpioEntry) -> bytes:
    namesize = len(entry.path.encode("utf-8")) + 1
    return b"".join(
        [
            CPIO_NEWC_MAGIC,
            _cpio_field(entry.ino),
            _cpio_field(entry.mode),
            _cpio_field(0),  # uid
            _cpio_field(0),  # gid
            _cpio_field(entry.nlink),
            _cpio_field(int(time.time())),
            _cpio_field(len(entry.content)),
            _cpio_field(0),  # devmajor
            _cpio_field(0),  # devminor
            _cpio_field(entry.rdev_major),
            _cpio_field(entry.rdev_minor),
            _cpio_field(namesize),
            _cpio_field(0),  # check
        ]
    )


class _CpioWriter:
    """Tracks stream offset so padding matches the Linux initramfs cpio parser."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._offset = 0

    def _align4(self) -> None:
        while self._offset % 4 != 0:
            self._buf.append(0)
            self._offset += 1

    def _write(self, data: bytes) -> None:
        self._buf.extend(data)
        self._offset += len(data)

    def add(self, entry: CpioEntry) -> None:
        name = entry.path.encode("utf-8") + b"\x00"
        self._write(_cpio_header(entry))
        self._write(name)
        self._align4()
        if entry.content:
            self._write(entry.content)
            self._align4()

    def finish(self) -> bytes:
        trailer = CpioEntry(path="TRAILER!!!", mode=0, ino=999999)
        self.add(trailer)
        return bytes(self._buf)


def pack_cpio_newc(entries: list[CpioEntry]) -> bytes:
    """Packs `entries` into a POSIX cpio newc (`070701`) archive."""
    writer = _CpioWriter()
    for idx, entry in enumerate(entries, start=1):
        ino = entry.ino if entry.ino else idx
        writer.add(
            CpioEntry(
                path=entry.path,
                mode=entry.mode,
                content=entry.content,
                rdev_major=entry.rdev_major,
                rdev_minor=entry.rdev_minor,
                nlink=entry.nlink,
                ino=ino,
            )
        )
    return writer.finish()


def strip_cpio_trailer(cpio: bytes) -> bytes:
    """Removes the trailing TRAILER!!! entry so another cpio may be concatenated."""
    trailer_name = b"TRAILER!!!\x00"
    idx = cpio.rfind(trailer_name)
    if idx == -1:
        return cpio
    header_start = cpio.rfind(CPIO_NEWC_MAGIC, 0, idx)
    if header_start == -1:
        return cpio
    return cpio[:header_start]


def merge_initramfs_cpio(base_cpio: bytes, overlay_cpio: bytes) -> bytes:
    """Concatenates cpio archives; later entries override same paths (Linux initramfs)."""
    return strip_cpio_trailer(base_cpio) + overlay_cpio


def static_vfs_cpio_entries() -> list[CpioEntry]:
    """Pre-populates persistent char/block nodes that survive dynamic /dev wipes."""
    return [
        CpioEntry("proc", S_IFDIR | 0o755, nlink=2),
        CpioEntry("sys", S_IFDIR | 0o755, nlink=2),
        CpioEntry("dev", S_IFDIR | 0o755, nlink=2),
        CpioEntry("dev/console", S_IFCHR | 0o622, rdev_major=5, rdev_minor=1),
        CpioEntry("dev/null", S_IFCHR | 0o666, rdev_major=1, rdev_minor=3),
        CpioEntry("custom_dev", S_IFDIR | 0o755, nlink=2),
        CpioEntry("custom_dev/zero", S_IFCHR | 0o666, rdev_major=1, rdev_minor=5),
        CpioEntry("custom_dev/null", S_IFCHR | 0o666, rdev_major=1, rdev_minor=3),
        CpioEntry("host_share", S_IFDIR | 0o755, nlink=2),
    ]


def build_initramfs(
    work: Path,
    provisioner: Path,
    busybox: Path,
    alpine_initramfs: Path,
    cycles: int,
    inject_sector: int = 1,
) -> Path:
    """Builds gzip initramfs: Alpine base (modules) + DFIM overlay cpio."""
    out = work / "dfim-initramfs.gz"
    guest_init = render_guest_init(cycles=cycles, inject_sector=inject_sector)

    init_snapshot = work / "generated_init.sh"
    init_snapshot.write_bytes(guest_init.encode("utf-8"))
    guest_src = ROOT / "tools" / "qemu" / "guest_dfim_runner.sh"
    guest_src.write_bytes(guest_init.encode("utf-8"))
    log(f"guest init snapshot -> {init_snapshot} ({len(guest_init)} bytes, strict LF)")

    provisioner_bytes = provisioner.read_bytes()
    busybox_bytes = busybox.read_bytes()
    golden_bytes = bytes([0x4D] * (32 * 4096))

    init_bytes = guest_init.encode("utf-8")
    if b"\r" in init_bytes:
        raise RuntimeError("guest init script contains CR bytes — LF enforcement failed")

    init_sha = hashlib.sha256(init_bytes).hexdigest()
    # #region agent log
    _agent_log(
        "H2",
        "build_initramfs",
        "init script fingerprint",
        {
            "init_sha256": init_sha,
            "init_bytes": len(init_bytes),
            "golden_path_in_init": "/dfim/golden.bin" in guest_init,
            "cycles": cycles,
            "provisioner_bytes": len(provisioner_bytes),
            "alpine_initramfs_bytes": alpine_initramfs.stat().st_size,
        },
    )
    # #endregion

    overlay_entries: list[CpioEntry] = [
        CpioEntry("init", S_IFREG | 0o100755, init_bytes),
        CpioEntry("bin", S_IFDIR | 0o755, nlink=2),
        CpioEntry("bin/busybox", S_IFREG | 0o100755, busybox_bytes),
        CpioEntry("dfim", S_IFDIR | 0o755, nlink=2),
        CpioEntry("dfim/dfim-provisioner", S_IFREG | 0o100755, provisioner_bytes),
        CpioEntry("dfim/golden.bin", S_IFREG | 0o644, golden_bytes),
        *static_vfs_cpio_entries(),
    ]
    overlay_cpio = pack_cpio_newc(overlay_entries)

    with gzip.open(alpine_initramfs, "rb") as alpine_gz:
        base_cpio = alpine_gz.read()
    merged_cpio = merge_initramfs_cpio(base_cpio, overlay_cpio)
    log(
        f"merged cpio: alpine={len(base_cpio)} + overlay={len(overlay_cpio)} "
        f"= {len(merged_cpio)} bytes"
    )

    if out.is_file():
        out.unlink()
    with out.open("wb") as raw_out:
        with gzip.GzipFile(fileobj=raw_out, mode="wb", compresslevel=9) as handle:
            handle.write(merged_cpio)
    log(f"initramfs -> {out} ({out.stat().st_size} bytes gzip)")
    return out


def build_musl_provisioner(env: dict[str, str], work: Path) -> Path:
    run(["rustup", "target", "add", "x86_64-unknown-linux-musl"], env=env)
    run(
        [
            "cargo",
            "build",
            "--release",
            "--target",
            "x86_64-unknown-linux-musl",
            "-p",
            "dfim_cli_provisioner",
        ],
        cwd=ROOT,
        env=env,
    )
    binary = (
        ROOT
        / "target"
        / "x86_64-unknown-linux-musl"
        / "release"
        / "dfim-provisioner"
    )
    if not binary.is_file():
        raise RuntimeError(f"musl binary missing: {binary}")
    staged = work / "dfim-provisioner"
    shutil.copy2(binary, staged)
    staged.chmod(staged.stat().st_mode | stat.S_IEXEC)
    log(f"musl provisioner: {staged} ({staged.stat().st_size} bytes)")
    return staged


def create_disk_image(work: Path, size_mb: int) -> Path:
    disk = work / "qemu_disk.img"
    run([find_tool("qemu-img"), "create", "-f", "raw", str(disk), f"{size_mb}M"])
    return disk


def extract_jsonl_from_console(output: str, dest: Path) -> list[str]:
    """Pulls JSONL lines emitted between serial console markers."""
    begin = "===DFIM_JSONL_BEGIN==="
    end = "===DFIM_JSONL_END==="
    if begin not in output or end not in output:
        raise RuntimeError("JSONL serial markers not found in QEMU console output")
    block = output.split(begin, 1)[1].split(end, 1)[0]
    lines = [ln.strip() for ln in block.splitlines() if ln.strip().startswith("{")]
    # #region agent log
    _agent_log(
        "H5",
        "extract_jsonl_from_console",
        "serial block parsed",
        {
            "json_line_count": len(lines),
            "block_preview": block[:500],
            "has_begin": begin in output,
            "has_end": end in output,
        },
    )
    # #endregion
    if not lines:
        raise RuntimeError("no JSONL records between serial markers")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return lines


def launch_qemu(
    work: Path,
    kernel: Path,
    initrd: Path,
    disk: Path,
    host_share: Path,
    timeout_s: int,
) -> Path:
    share = host_share.resolve()
    share.mkdir(parents=True, exist_ok=True)
    jsonl = share / "dfim_qemu_compliance.jsonl"
    if jsonl.is_file():
        jsonl.unlink()

    cmd = [
        find_tool("qemu-system-x86_64"),
        "-m",
        "512",
        "-smp",
        "1",
        "-nographic",
        "-no-reboot",
        "-kernel",
        str(kernel),
        "-initrd",
        str(initrd),
        "-append",
        "console=ttyS0 rdinit=/init",
        "-drive",
        f"file={disk},format=raw,if=none,id=hd0,media=disk",
        "-device",
        "virtio-blk-pci,drive=hd0",
    ]
    log(f"QEMU timeout {timeout_s}s; JSONL -> {jsonl}")
    console_log = work / "qemu_console.log"
    combined = ""
    try:
        result = subprocess.run(
            cmd,
            cwd=work,
            timeout=timeout_s,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        combined = (result.stdout or "") + (result.stderr or "")
        console_log.write_text(combined, encoding="utf-8", newline="\n")
        log(f"QEMU exit code: {result.returncode}; console log -> {console_log}")
    except subprocess.TimeoutExpired as exc:
        combined = (exc.stdout or "") + (exc.stderr or "")
        console_log.write_text(combined, encoding="utf-8", newline="\n")
        log(f"QEMU timed out; console log -> {console_log}")

    # #region agent log
    guest_lines = [ln.strip() for ln in combined.splitlines() if "[guest]" in ln]
    _agent_log(
        "H3",
        "launch_qemu",
        "guest console summary",
        {
            "has_virtio_vda": "virtio_blk" in combined or "[vda]" in combined,
            "has_sda": "[sda]" in combined,
            "guest_line_count": len(guest_lines),
            "guest_tail": guest_lines[-8:],
            "has_jsonl_begin": "===DFIM_JSONL_BEGIN===" in combined,
        },
    )
    # #endregion

    if not jsonl.is_file():
        lines = extract_jsonl_from_console(combined, jsonl)
    else:
        lines = [ln for ln in jsonl.read_text(encoding="utf-8").splitlines() if ln.strip()]

    log(f"collected {len(lines)} JSONL events")
    for line in lines:
        event = json.loads(line)
        log(f"  {event.get('phase')} -> {event.get('status')}")
        if event.get("status") != "PASS":
            raise RuntimeError(f"non-PASS event: {line}")

    summary = work / "harness_summary.json"
    summary.write_text(
        json.dumps({"events": [json.loads(ln) for ln in lines], "jsonl": str(jsonl)}, indent=2),
        encoding="utf-8",
        newline="\n",
    )
    log(f"summary -> {summary}")
    return jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description="DFIM QEMU Linux musl validation harness")
    parser.add_argument("--work-dir", type=Path, default=None, help="persistent work directory")
    parser.add_argument("--disk-mb", type=int, default=512)
    parser.add_argument("--skip-build", action="store_true", help="reuse existing musl binary")
    parser.add_argument("--cycles", type=int, default=1000, help="raw-stress validation cycles in guest")
    parser.add_argument(
        "--inject-sector",
        type=int,
        default=1,
        help="DFIM block index for fault injection (golden image is 32 blocks)",
    )
    parser.add_argument("--timeout", type=int, default=1800, help="QEMU guest timeout seconds")
    args = parser.parse_args()

    env = os.environ.copy()
    ensure_crypto_key(env)

    work = args.work_dir or Path(tempfile.mkdtemp(prefix="dfim_qemu_", dir=str(ROOT / "target")))
    work.mkdir(parents=True, exist_ok=True)
    # #region agent log
    _agent_log(
        "H1",
        "main",
        "harness start",
        {"work_dir": str(work), "cycles": args.cycles, "skip_build": args.skip_build},
    )
    # #endregion
    cache = work / "cache"
    cache.mkdir(exist_ok=True)

    try:
        for name, url in ARTIFACTS.items():
            download(url, cache / name)
        download(BUSYBOX_URL, cache / "busybox")

        if args.skip_build:
            binary = (
                ROOT
                / "target"
                / "x86_64-unknown-linux-musl"
                / "release"
                / "dfim-provisioner"
            )
            if not binary.is_file():
                raise RuntimeError(f"--skip-build but binary missing: {binary}")
            provisioner = work / "dfim-provisioner"
            shutil.copy2(binary, provisioner)
            provisioner.chmod(provisioner.stat().st_mode | stat.S_IEXEC)
        else:
            provisioner = build_musl_provisioner(env, work)

        initrd = build_initramfs(
            work,
            provisioner,
            cache / "busybox",
            cache / "initramfs-virt",
            args.cycles,
            inject_sector=args.inject_sector,
        )
        disk = create_disk_image(work, args.disk_mb)
        host_share = work / "host_share"
        jsonl = launch_qemu(
            work,
            cache / "vmlinuz-virt",
            initrd,
            disk,
            host_share,
            args.timeout,
        )
        log(f"compliance JSONL:\n{jsonl.read_text(encoding='utf-8')}")
    except subprocess.CalledProcessError as err:
        log(f"command failed: {err}")
        return 1
    except RuntimeError as err:
        log(f"ERROR: {err}")
        return 1

    log("PASS: QEMU Linux validation complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
