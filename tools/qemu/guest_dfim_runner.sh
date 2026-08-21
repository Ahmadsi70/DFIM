#!/bin/busybox sh
# DFIM QEMU guest init — static device nodes, no dynamic udev/mdev dependency.
set -eu
BB=/bin/busybox
DEV="${DFIM_BLOCK_DEV:-/dev/vda}"
BIN="${DFIM_PROVISIONER:-/dfim/dfim-provisioner}"
GOLDEN="${DFIM_GOLDEN:-/dfim/golden.bin}"
JSONL="${DFIM_JSONL_OUT:-/host_share/dfim_qemu_compliance.jsonl}"
CYCLES="${DFIM_CYCLES:-10}"
INJECT_SECTOR="${DFIM_INJECT_SECTOR:-1}"

log() { printf '[guest] %s\n' "$*"; }

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
  _BLK=$("$BB" awk 'NR>2 && $4 !~ /^(loop|ram|fd)/ {print $4; exit}' /proc/partitions)
  if [ -n "$_BLK" ]; then
    _DEVNAME="$_BLK"
    break
  fi
  for _candidate in vda sda hda xvda; do
    if [ -b "/dev/${_candidate}" ] || [ -r "/sys/block/${_candidate}/dev" ]; then
      _DEVNAME="${_candidate}"
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
  DEV="/dev/${_DEVNAME}"
  if [ -r "/sys/block/${_DEVNAME}/dev" ]; then
    _VDEV=$("$BB" cat "/sys/block/${_DEVNAME}/dev")
    _VMAJ=${_VDEV%%:*}
    _VMIN=${_VDEV##*:}
    log "block ${_DEVNAME} dev=${_VDEV} — mknod $DEV"
    "$BB" mknod "$DEV" b "${_VMAJ}" "${_VMIN}" 2>/dev/null || true
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
"$BIN" raw-stress \
  --device "$DEV" \
  --golden "$GOLDEN" \
  --cycles "$CYCLES" \
  --inject-sector "$INJECT_SECTOR" \
  --jsonl-out "$JSONL"
_RS=$?
set -e
log "raw-stress exit code=${_RS}"

log "exporting compliance JSONL via serial console"
printf '===DFIM_JSONL_BEGIN===\n'
if [ -s "$JSONL" ]; then
  "$BB" cat "$JSONL"
else
  log "WARN: JSONL empty at $JSONL"
fi
printf '===DFIM_JSONL_END===\n'
"$BB" sync
"$BB" poweroff -f 2>/dev/null || "$BB" halt -f 2>/dev/null || "$BB" reboot -f
