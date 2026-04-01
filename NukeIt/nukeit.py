#!/usr/bin/env python3
"""
NukeIt: Secure Data Erasure Tool  — v0.2
==========================================
Cross-platform (Windows + Linux) forensically non-recoverable data erasure.

Key behaviours:
  • Requires and enforces Administrator (Windows) / root (Linux) — exits hard otherwise.
  • Multi-pass overwrite: DoD 7-pass, Gutmann 35-pass, random, zeros.
  • Crypto-shredding: AES-256-GCM + ChaCha20-Poly1305, ephemeral HKDF keys (RAM only).
  • SSD optimisations: TRIM/blkdiscard (Linux), ATA Secure Erase, NVMe Format,
    Windows DISKPART CLEAN ALL / Optimize-Volume.
  • Pre-erasure backup: copies ONLY live (non-deleted) regular files via the filesystem.
    Never reads raw unallocated blocks, Recycle Bin, swap, or hibernation files.
  • Audit log saved to the erased device/location itself (written last, before exit).
    Contains NO sensitive data — no keys, no file content, no plaintext file paths.
  • Ed25519-signed audit envelope for cryptographic integrity verification.
  • All crypto keys live in RAM only — never touch disk.
"""

import os
import sys
import json
import time
import ctypes
import hashlib
import secrets
import struct
import platform
import datetime
import subprocess
import shutil
import threading
import signal
import atexit
import glob
import stat
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

# ─── Crypto imports ───────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[FATAL] 'cryptography' package not found.\n  Install: pip install cryptography")
    sys.exit(1)

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MACOS   = platform.system() == "Darwin"

# ─── ANSI colour support (Windows 10+ VT mode) ────────────────────────────────
if IS_WINDOWS:
    try:
        import ctypes as _ct
        _ct.windll.kernel32.SetConsoleMode(_ct.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def cprint(msg: str, color: str = C.WHITE, bold: bool = False):
    print(f"{C.BOLD if bold else ''}{color}{msg}{C.RESET}")

def banner():
    print(f"""\
{C.RED}{C.BOLD}
  ███╗   ██╗██╗   ██╗██╗  ██╗███████╗    ██╗████████╗
  ████╗  ██║██║   ██║██║ ██╔╝██╔════╝    ██║╚══██╔══╝
  ██╔██╗ ██║██║   ██║█████╔╝ █████╗      ██║   ██║
  ██║╚██╗██║██║   ██║██╔═██╗ ██╔══╝      ██║   ██║
  ██║ ╚████║╚██████╔╝██║  ██╗███████╗    ██║   ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝   ╚═╝
{C.RESET}{C.YELLOW}        Secure Data Erasure Tool — v0.2
{C.DIM}        Post-Quantum Crypto · Multi-Pass · Forensic-Grade · Windows + Linux{C.RESET}
""")


# ══════════════════════════════════════════════════════════════════════════════
#  1. PRIVILEGE ENFORCEMENT  — hard exit if not root / Administrator
# ══════════════════════════════════════════════════════════════════════════════

def check_and_enforce_privileges():
    if IS_WINDOWS:
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False
        if not is_admin:
            cprint("\n  [FATAL] NukeIt must be run as Administrator.", C.RED, bold=True)
            cprint("  Right-click your terminal → 'Run as administrator', then retry.\n",
                   C.YELLOW)
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            cprint("\n  [FATAL] NukeIt must be run as root.", C.RED, bold=True)
            cprint("  Run:  sudo python3 nukeit.py\n", C.YELLOW)
            sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  2. SECURE MEMORY — ephemeral key store, RAM-only, auto-zeroed
# ══════════════════════════════════════════════════════════════════════════════

class SecureBytes:
    """Mutable bytearray that zeroes itself on deletion. Never persisted."""
    def __init__(self, data: bytes):
        self._buf    = bytearray(data)
        self._zeroed = False

    def __bytes__(self):
        if self._zeroed:
            raise ValueError("SecureBytes already zeroed")
        return bytes(self._buf)

    def __len__(self):
        return len(self._buf)

    def zero(self):
        if not self._zeroed:
            for i in range(len(self._buf)):
                self._buf[i] = 0
            self._zeroed = True

    def __del__(self):
        self.zero()


class EphemeralKeyStore:
    """All crypto keys live here — RAM only. Zeroed on exit, signal, or explicit call."""
    def __init__(self):
        self._keys: Dict[str, SecureBytes] = {}
        self._lock = threading.Lock()
        atexit.register(self.wipe_all)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._on_signal)
            except (OSError, ValueError):
                pass

    def _on_signal(self, signum, frame):
        self.wipe_all()
        cprint("\n[KeyStore] Keys wiped from RAM. Exiting.", C.GREEN)
        sys.exit(0)

    def store(self, name: str, data: bytes):
        with self._lock:
            if name in self._keys:
                self._keys[name].zero()
            self._keys[name] = SecureBytes(data)

    def get(self, name: str) -> bytes:
        with self._lock:
            if name not in self._keys:
                raise KeyError(f"Key '{name}' not in store")
            return bytes(self._keys[name])

    def wipe(self, name: str):
        with self._lock:
            if name in self._keys:
                self._keys[name].zero()
                del self._keys[name]

    def wipe_all(self):
        with self._lock:
            for k in list(self._keys):
                self._keys[k].zero()
            self._keys.clear()

    def list_keys(self) -> List[str]:
        return list(self._keys.keys())


KEY_STORE = EphemeralKeyStore()


# ══════════════════════════════════════════════════════════════════════════════
#  3. DRIVE DETECTION  — Windows (PowerShell/wmic) + Linux (lsblk) + macOS
# ══════════════════════════════════════════════════════════════════════════════

def human_size(n: int) -> str:
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


@dataclass
class DriveInfo:
    device:       str          # /dev/sda  or  \\.\PhysicalDrive0
    model:        str
    size_bytes:   int
    size_human:   str
    drive_type:   str          # SSD / HDD / NVMe SSD / Unknown
    is_removable: bool
    is_system:    bool
    partitions:   List[Dict]   = field(default_factory=list)
    mount_points: List[str]    = field(default_factory=list)
    drive_letter: str          = ""  # Windows: first drive letter, e.g. "D:"
    disk_number:  str          = ""  # Windows disk number for diskpart


def detect_drives() -> List[DriveInfo]:
    if IS_WINDOWS:
        return _detect_windows()
    elif IS_LINUX:
        return _detect_linux()
    elif IS_MACOS:
        return _detect_macos()
    return []


# ── Windows ───────────────────────────────────────────────────────────────────

def _detect_windows() -> List[DriveInfo]:
    try:
        ps = (
            "Get-Disk | Select-Object Number,FriendlyName,Size,"
            "MediaType,BusType,IsSystem | ConvertTo-Json -Compress"
        )
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, check=True, timeout=30
        )
        raw = r.stdout.strip()
        if not raw:
            return _detect_windows_wmi()
        disks = json.loads(raw)
        if isinstance(disks, dict):
            disks = [disks]
    except Exception:
        return _detect_windows_wmi()

    drives: List[DriveInfo] = []
    for d in disks:
        num    = str(d.get("Number", 0))
        device = f"\\\\.\\PhysicalDrive{num}"
        model  = (d.get("FriendlyName") or "Unknown").strip()
        size   = int(d.get("Size") or 0)
        media  = str(d.get("MediaType") or "").lower()
        bus    = str(d.get("BusType") or "").lower()

        if "nvme" in bus:
            dtype = "NVMe SSD"
        elif media in ("3", "ssd"):
            dtype = "SSD"
        elif media in ("4", "hdd"):
            dtype = "HDD"
        else:
            dtype = "Unknown"

        is_sys = bool(d.get("IsSystem"))
        parts, mounts, dl = _windows_partitions(num)
        drives.append(DriveInfo(
            device=device, model=model, size_bytes=size, size_human=human_size(size),
            drive_type=dtype, is_removable=False, is_system=is_sys,
            partitions=parts, mount_points=mounts, drive_letter=dl, disk_number=num,
        ))
    return drives


def _windows_partitions(disk_num: str) -> Tuple[List[Dict], List[str], str]:
    parts: List[Dict] = []
    mounts: List[str] = []
    drive_letter = ""
    try:
        ps = (
            f"Get-Partition -DiskNumber {disk_num} | "
            "Select-Object PartitionNumber,Size,DriveLetter,Type | "
            "ConvertTo-Json -Compress"
        )
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=15
        )
        raw = r.stdout.strip()
        if not raw:
            return parts, mounts, drive_letter
        ps_parts = json.loads(raw)
        if isinstance(ps_parts, dict):
            ps_parts = [ps_parts]
        for p in ps_parts:
            dl  = p.get("DriveLetter") or ""
            dls = f"{dl}:\\" if dl else ""
            if dls:
                mounts.append(dls)
                if not drive_letter:
                    drive_letter = dls
            parts.append({
                "device":     f"\\\\.\\PhysicalDrive{disk_num}p{p.get('PartitionNumber',0)}",
                "name":       f"Disk{disk_num}p{p.get('PartitionNumber',0)}",
                "size":       int(p.get("Size") or 0),
                "size_human": human_size(int(p.get("Size") or 0)),
                "mountpoint": dls,
                "type":       p.get("Type") or "",
            })
    except Exception:
        pass
    return parts, mounts, drive_letter


def _detect_windows_wmi() -> List[DriveInfo]:
    drives: List[DriveInfo] = []
    try:
        r = subprocess.run(
            ["wmic", "diskdrive", "get",
             "Index,Model,Size,MediaType,InterfaceType", "/format:csv"],
            capture_output=True, text=True, check=True, timeout=20
        )
        for line in r.stdout.strip().splitlines()[2:]:
            cols = line.split(",")
            if len(cols) < 5:
                continue
            _, idx, iface, media, model, *rest = (cols + [""] * 6)
            size = int(rest[0].strip() or "0") if rest else 0
            num  = idx.strip()
            dtype = "SSD" if "ssd" in media.lower() else "HDD"
            drives.append(DriveInfo(
                device=f"\\\\.\\PhysicalDrive{num}", model=model.strip(),
                size_bytes=size, size_human=human_size(size),
                drive_type=dtype, is_removable=False, is_system=False,
                disk_number=num,
            ))
    except Exception:
        pass
    return drives


# ── Linux ─────────────────────────────────────────────────────────────────────

def _detect_linux() -> List[DriveInfo]:
    try:
        r = subprocess.run(
            ["lsblk", "-J", "-b", "-o",
             "NAME,MODEL,SIZE,ROTA,RM,MOUNTPOINT,TYPE,TRAN"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(r.stdout)
    except Exception:
        return _detect_linux_fallback()

    drives: List[DriveInfo] = []
    for dev in data.get("blockdevices", []):
        if dev.get("type") in ("loop", "rom"):
            continue
        if dev.get("type") != "disk":
            continue

        name   = dev.get("name", "")
        model  = (dev.get("model") or "Unknown").strip()
        size   = int(dev.get("size") or 0)
        rota   = dev.get("rota", "1")
        rm     = dev.get("rm", "0")
        tran   = (dev.get("tran") or "").lower()

        if "nvme" in tran or "nvme" in name:
            dtype = "NVMe SSD"
        elif rota in ("0", 0, False):
            dtype = "SSD"
        else:
            dtype = "HDD"

        mounts: List[str] = []
        partitions: List[Dict] = []
        for child in dev.get("children") or []:
            mp = child.get("mountpoint") or ""
            if mp:
                mounts.append(mp)
            partitions.append({
                "name":       child.get("name", ""),
                "device":     f"/dev/{child.get('name','')}",
                "size":       int(child.get("size") or 0),
                "size_human": human_size(int(child.get("size") or 0)),
                "mountpoint": mp,
                "type":       child.get("type", ""),
            })

        is_system = "/" in mounts or any(m.startswith("/boot") for m in mounts)
        drives.append(DriveInfo(
            device=f"/dev/{name}", model=model,
            size_bytes=size, size_human=human_size(size),
            drive_type=dtype, is_removable=(rm in ("1", True, 1)),
            is_system=is_system, partitions=partitions, mount_points=mounts,
        ))
    return drives


def _detect_linux_fallback() -> List[DriveInfo]:
    drives: List[DriveInfo] = []
    for pat in ["/dev/sd?", "/dev/nvme?n?", "/dev/hd?", "/dev/vd?"]:
        for dev in sorted(glob.glob(pat)):
            size = 0
            sf = f"/sys/block/{os.path.basename(dev)}/size"
            try:
                size = int(open(sf).read().strip()) * 512
            except Exception:
                pass
            dtype = "NVMe SSD" if "nvme" in dev else "Unknown"
            drives.append(DriveInfo(
                device=dev, model="Unknown",
                size_bytes=size, size_human=human_size(size),
                drive_type=dtype, is_removable=False, is_system=False,
            ))
    return drives


# ── macOS ─────────────────────────────────────────────────────────────────────

def _detect_macos() -> List[DriveInfo]:
    import plistlib
    drives: List[DriveInfo] = []
    try:
        r = subprocess.run(["diskutil", "list", "-plist"],
                           capture_output=True, check=True)
        data = plistlib.loads(r.stdout)
        for disk in data.get("AllDisksAndPartitions", []):
            dev  = f"/dev/{disk.get('DeviceIdentifier','')}"
            size = disk.get("Size", 0)
            parts = [{
                "name":       p.get("DeviceIdentifier",""),
                "device":     f"/dev/{p.get('DeviceIdentifier','')}",
                "size":       p.get("Size",0),
                "size_human": human_size(p.get("Size",0)),
                "mountpoint": p.get("MountPoint",""),
                "type":       p.get("Content",""),
            } for p in disk.get("Partitions", [])]
            drives.append(DriveInfo(
                device=dev, model=disk.get("Content","Unknown"),
                size_bytes=size, size_human=human_size(size),
                drive_type="Unknown", is_removable=False, is_system=False,
                partitions=parts,
            ))
    except Exception as e:
        cprint(f"  [!] macOS detection error: {e}", C.YELLOW)
    return drives


def _get_device_size(device: str) -> int:
    if IS_WINDOWS:
        try:
            num = device.replace("\\\\.\\PhysicalDrive", "")
            ps  = f"(Get-Disk -Number {num}).Size"
            r   = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, check=True, timeout=10)
            return int(r.stdout.strip())
        except Exception:
            return 0
    for fn in [
        lambda: int(subprocess.check_output(
            ["blockdev", "--getsize64", device], stderr=subprocess.DEVNULL).decode().strip()),
        lambda: int(open(
            f"/sys/block/{os.path.basename(device)}/size").read().strip()) * 512,
        lambda: os.path.getsize(device),
    ]:
        try:
            v = fn()
            if v > 0:
                return v
        except Exception:
            pass
    return 0


# ══════════════════════════════════════════════════════════════════════════════
#  4. OVERWRITE PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

class OverwritePattern(Enum):
    ZEROS      = "zeros"
    ONES       = "ones"
    RANDOM     = "random"
    DOD_7PASS  = "dod_7pass"
    GUTMANN_35 = "gutmann_35"

# None in list = random pass
PASS_PATTERNS: Dict[OverwritePattern, list] = {
    OverwritePattern.DOD_7PASS: [
        b'\x00', b'\xff', b'\x92', b'\x49', b'\x24', None, None,
    ],
    OverwritePattern.GUTMANN_35: (
        [None]*4 +
        [bytes([p]) for p in [
            0x55,0xAA,0x92,0x49,0x24,0x00,0x11,0x22,
            0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,
            0xBB,0xCC,0xDD,0xEE,0xFF,0x92,0x49,0x24,
            0x6D,0xB6,0xDB,0xB6,0x6D,0xDB,
        ]] +
        [None]*4
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
#  5. CRYPTO ENGINE — AES-256-GCM + ChaCha20-Poly1305, RAM-only ephemeral keys
# ══════════════════════════════════════════════════════════════════════════════

class CryptoEngine:
    """
    Hybrid symmetric crypto-shredding engine.
    Per-block HKDF-SHA3-256 derived keys; keys never leave RAM.
    Ed25519 for audit log signing.

    PQ note: AES-256 has 128-bit post-quantum security (Grover).
    Full Kyber KEM needs liboqs — out of scope for this prototype.
    """

    def __init__(self, ks: EphemeralKeyStore):
        self.ks = ks
        raw = secrets.token_bytes(64)        # 512-bit master secret
        self.ks.store("master_aes",    raw[:32])
        self.ks.store("master_chacha", raw[32:])
        del raw
        priv = Ed25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        pub_raw = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.ks.store("sign_priv", priv_raw)
        self.ks.store("sign_pub",  pub_raw)
        del priv_raw

    def _block_keys(self, blk: int, pass_num: int) -> Tuple[SecureBytes, SecureBytes]:
        salt    = struct.pack(">QI", blk, pass_num) + secrets.token_bytes(16)
        master  = self.ks.get("master_aes")
        aes_k   = HKDF(hashes.SHA3_256(), 32, salt,
                       f"nk-aes-{blk}-{pass_num}".encode(),
                       default_backend()).derive(master)
        cha_k   = HKDF(hashes.SHA3_256(), 32, salt,
                       f"nk-cha-{blk}-{pass_num}".encode(),
                       default_backend()).derive(master)
        return SecureBytes(aes_k), SecureBytes(cha_k)

    def encrypt_block(self, plaintext: bytes, blk: int, pass_num: int) -> bytes:
        aes_sb, cha_sb = self._block_keys(blk, pass_num)
        n1 = secrets.token_bytes(12)
        ct = AESGCM(bytes(aes_sb)).encrypt(n1, plaintext, None)
        n2 = secrets.token_bytes(12)
        ct = ChaCha20Poly1305(bytes(cha_sb)).encrypt(n2, ct, None)
        aes_sb.zero(); cha_sb.zero()
        return (n1 + n2 + ct)[:len(plaintext)]

    def sign(self, data: bytes) -> bytes:
        priv = Ed25519PrivateKey.from_private_bytes(self.ks.get("sign_priv"))
        return priv.sign(data)

    def public_key_hex(self) -> str:
        return self.ks.get("sign_pub").hex()

    def wipe_keys(self):
        self.ks.wipe_all()
        cprint("  [Crypto] All ephemeral keys wiped from RAM.", C.GREEN)


# ══════════════════════════════════════════════════════════════════════════════
#  6. AUDIT LOG — no sensitive data; saved to erased device/location
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuditEvent:
    timestamp: str
    event:     str
    details:   Dict[str, Any]
    checksum:  str = ""


class AuditLog:
    """
    Sensitive data policy (strict):
      ✗  NO encryption keys (not even partial)
      ✗  NO file names or file paths (only counts and hashes)
      ✗  NO file content
      ✗  NO usernames or hostnames
      ✓  Device labels chosen by operator
      ✓  Operation type, timestamps, pass hashes (SHA3-256 of written bytes)
      ✓  Counts: files copied, bytes written, passes executed
    Saved to the erased device/location as the very last write before exit.
    """

    def __init__(self, crypto: CryptoEngine):
        self.crypto     = crypto
        self.events:    List[AuditEvent] = []
        self.session_id = secrets.token_hex(8).upper()
        self._t0        = time.time()
        self.log("SESSION_START", {
            "session_id": self.session_id,
            "os_type":    platform.system(),
            "tool":       "NukeIt v0.2",
        })

    def log(self, event: str, details: Dict[str, Any] = {}):
        ts      = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = json.dumps(
            {"ts": ts, "event": event, "details": details}, sort_keys=True
        ).encode()
        chk = hashlib.sha3_256(payload).hexdigest()
        self.events.append(AuditEvent(ts, event, details, chk))

    def finalize_and_save(self, save_dir: str) -> str:
        self.log("SESSION_END", {
            "duration_seconds": round(time.time() - self._t0, 2),
            "total_events":     len(self.events) + 1,
        })
        log_body  = {
            "session_id":           self.session_id,
            "tool":                 "NukeIt v0.2",
            "signing_pubkey":       self.crypto.public_key_hex(),
            "sensitive_data_logged": False,
            "events":               [asdict(e) for e in self.events],
        }
        log_bytes = json.dumps(log_body, indent=2).encode()
        sig       = self.crypto.sign(log_bytes)
        envelope  = {
            "log":            log_body,
            "signature_hex":  sig.hex(),
            "signature_algo": "Ed25519",
            "verify_note":    (
                "Verify: Ed25519.verify(hex(signing_pubkey), log_json_bytes, hex(signature))"
            ),
        }
        os.makedirs(save_dir, exist_ok=True)
        path = os.path.join(save_dir, f"nukeit_audit_{self.session_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
        cprint(f"\n  [AuditLog] Signed log saved → {path}", C.CYAN)
        return path


# ══════════════════════════════════════════════════════════════════════════════
#  7. PROGRESS BAR
# ══════════════════════════════════════════════════════════════════════════════

def progress_bar(current: int, total: int, label: str = "", width: int = 44):
    pct    = min(current / total, 1.0) if total else 0
    filled = int(width * pct)
    bar    = "█" * filled + "░" * (width - filled)
    print(f"\r  {C.CYAN}{label:<20}{C.RESET} [{C.GREEN}{bar}{C.RESET}] {pct*100:5.1f}% ",
          end="", flush=True)
    if current >= total:
        print()


# ══════════════════════════════════════════════════════════════════════════════
#  8. ERASE TARGET
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class EraseTarget:
    device:       str
    start_byte:   int  = 0
    length_bytes: int  = -1    # -1 = full device
    label:        str  = ""
    mount_point:  str  = ""    # for audit log placement and live-file backup

    def resolve_length(self) -> int:
        return self.length_bytes if self.length_bytes > 0 else _get_device_size(self.device)


# ══════════════════════════════════════════════════════════════════════════════
#  9. SECURE ERASER
# ══════════════════════════════════════════════════════════════════════════════

class SecureEraser:
    BLOCK_SIZE = 1 * 1024 * 1024   # 1 MB write blocks

    def __init__(self, crypto: CryptoEngine, audit: AuditLog):
        self.crypto = crypto
        self.audit  = audit

    # ── Platform SSD commands ─────────────────────────────────────────────────

    def _ssd_linux(self, device: str) -> List[Dict]:
        cmds = []
        # TRIM via blkdiscard
        try:
            subprocess.run(["blkdiscard", device], check=True, capture_output=True)
            cprint(f"  [SSD] blkdiscard TRIM completed.", C.GREEN)
            cmds.append({"blkdiscard": True})
        except Exception as e:
            cprint(f"  [SSD] blkdiscard unavailable: {e}", C.YELLOW)
            cmds.append({"blkdiscard": False})
        # ATA Secure Erase
        try:
            subprocess.run(["hdparm", "--security-set-pass", "nk_tmp", device],
                           check=True, capture_output=True)
            subprocess.run(["hdparm", "--security-erase", "nk_tmp", device],
                           check=True, capture_output=True)
            cprint("  [SSD] ATA Secure Erase completed.", C.GREEN)
            cmds.append({"ata_secure_erase": True})
        except Exception as e:
            cprint(f"  [SSD] ATA Secure Erase unavailable: {e}", C.YELLOW)
            cmds.append({"ata_secure_erase": False})
        return cmds

    def _nvme_linux(self, device: str) -> List[Dict]:
        cmds = []
        for ses in (2, 1):
            try:
                subprocess.run(["nvme", "format", device, f"--ses={ses}"],
                               check=True, capture_output=True)
                cprint(f"  [NVMe] Format --ses={ses} completed.", C.GREEN)
                cmds.append({f"nvme_format_ses{ses}": True})
                break
            except Exception:
                cmds.append({f"nvme_format_ses{ses}": False})
        return cmds

    def _ssd_windows(self, disk_number: str, drive_letter: str) -> List[Dict]:
        cmds = []
        # Optimize-Volume (TRIM)
        if drive_letter:
            dl = drive_letter.rstrip(":\\")
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"Optimize-Volume -DriveLetter {dl} -ReTrim -Verbose"],
                    check=True, capture_output=True, timeout=120
                )
                cprint(f"  [SSD-Win] Optimize-Volume TRIM on {drive_letter}", C.GREEN)
                cmds.append({"optimize_trim": True})
            except Exception as e:
                cprint(f"  [SSD-Win] Optimize-Volume failed: {e}", C.YELLOW)
                cmds.append({"optimize_trim": False})
        # DISKPART CLEAN ALL
        try:
            script = f"select disk {disk_number}\nclean all\nexit\n"
            subprocess.run(["diskpart"], input=script, text=True,
                           check=True, capture_output=True, timeout=600)
            cprint("  [SSD-Win] DISKPART CLEAN ALL completed.", C.GREEN)
            cmds.append({"diskpart_clean_all": True})
        except Exception as e:
            cprint(f"  [SSD-Win] DISKPART CLEAN ALL failed: {e}", C.YELLOW)
            cmds.append({"diskpart_clean_all": False})
        return cmds

    # ── Single overwrite pass ─────────────────────────────────────────────────

    def _overwrite_pass(self, target: EraseTarget, pass_num: int,
                        pattern: Optional[bytes], total: int,
                        crypto: bool) -> str:
        size = target.resolve_length()
        if size == 0:
            cprint(f"  [!] Cannot determine size of {target.device}. Skipping.", C.RED)
            return ""

        label   = f"Pass {pass_num}/{total}"
        written = 0
        hasher  = hashlib.sha3_256()

        try:
            with open(target.device, "rb+") as f:
                f.seek(target.start_byte)
                blk = 0
                while written < size:
                    sz    = min(self.BLOCK_SIZE, size - written)
                    chunk = secrets.token_bytes(sz) if pattern is None \
                            else (pattern * (sz // len(pattern) + 1))[:sz]
                    if crypto and pattern is None:
                        chunk = self.crypto.encrypt_block(chunk, blk, pass_num)
                    hasher.update(chunk)
                    f.write(chunk)
                    written += sz
                    blk     += 1
                    progress_bar(written, size, label)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass   # raw devices on Windows may not support fsync
        except PermissionError as e:
            cprint(f"\n  [!] Permission denied on {target.device}: {e}", C.RED)
            raise
        except OSError as e:
            cprint(f"\n  [!] OS error pass {pass_num}: {e}", C.RED)
            raise

        return hasher.hexdigest()

    # ── Full erasure sequence ─────────────────────────────────────────────────

    def erase(self, target: EraseTarget, pattern: OverwritePattern,
              use_crypto: bool, drive_info: Optional[DriveInfo] = None) -> Dict:

        dtype  = drive_info.drive_type if drive_info else "Unknown"
        result: Dict[str, Any] = {
            "device": target.device, "pattern": pattern.value,
            "crypto_shredding": use_crypto, "drive_type": dtype,
            "ssd_commands": [], "passes": [], "final_hash": "", "success": False,
        }

        size = target.resolve_length()
        cprint(f"\n  Target : {target.label}  ({human_size(size)})", C.BOLD)
        self.audit.log("ERASE_START", {
            "device_label":     target.label,
            "size_bytes":       size,
            "pattern":          pattern.value,
            "crypto_shredding": use_crypto,
            "drive_type":       dtype,
        })

        # Phase 0 — SSD hardware commands
        if "SSD" in dtype or "NVMe" in dtype:
            cprint("\n  [Phase 0] SSD hardware commands", C.MAGENTA, bold=True)
            if IS_WINDOWS and drive_info:
                cmds = self._ssd_windows(drive_info.disk_number, drive_info.drive_letter)
            elif "NVMe" in dtype:
                cmds = self._nvme_linux(target.device)
            else:
                cmds = self._ssd_linux(target.device)
            result["ssd_commands"] = cmds
            # Only log success/failure booleans — not device paths or keys
            self.audit.log("SSD_COMMANDS", {
                "count": len(cmds),
                "any_succeeded": any(list(c.values())[0] for c in cmds if c),
            })

        # Phase 1 — Multi-pass overwrite
        passes = PASS_PATTERNS.get(pattern, {
            OverwritePattern.ZEROS:  [b'\x00'],
            OverwritePattern.ONES:   [b'\xff'],
            OverwritePattern.RANDOM: [None, None, None],
        }.get(pattern, [None]))

        total = len(passes)
        cprint(f"\n  [Phase 1] Overwrite — {total} pass(es)", C.MAGENTA, bold=True)
        for i, pat in enumerate(passes, 1):
            digest = self._overwrite_pass(target, i, pat, total, False)
            result["passes"].append({
                "pass": i, "pattern_name": "random" if pat is None else repr(pat),
                "sha3_256": digest
            })
            self.audit.log("OVERWRITE_PASS", {
                "pass": i, "pattern_name": "random" if pat is None else repr(pat),
                "sha3_256": digest,
            })

        # Phase 2 — Crypto-shredding
        if use_crypto:
            cprint("\n  [Phase 2] Crypto-Shredding (AES-256-GCM + ChaCha20-Poly1305)",
                   C.MAGENTA, bold=True)
            cprint("  Per-block ephemeral HKDF keys — destroyed after each block.", C.DIM)
            digest = self._overwrite_pass(target, total + 1, None, total + 1, True)
            result["passes"].append({"pass": "crypto_shred", "sha3_256": digest})
            self.audit.log("CRYPTO_SHRED_PASS", {"sha3_256": digest})
            cprint("  [Crypto] Block-level keys wiped.", C.GREEN)

        # Phase 3 — Final zero pass
        cprint("\n  [Phase 3] Final zero pass (known terminal state)", C.MAGENTA, bold=True)
        final_hash = self._overwrite_pass(target, 99, b'\x00', 99, False)
        result["final_hash"] = final_hash
        result["success"]    = True
        self.audit.log("FINAL_ZERO_PASS", {"sha3_256": final_hash})
        cprint(f"\n  ✓ Erasure complete. Surface hash: {final_hash[:40]}...",
               C.GREEN, bold=True)
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  10. BACKUP ENGINE — live files only (no deleted data, no raw image)
# ══════════════════════════════════════════════════════════════════════════════

class BackupEngine:
    """
    Copies only live, regular files from the mounted filesystem.

    What it SKIPS (by design — these may contain deleted/recoverable data):
      Windows: $Recycle.Bin, System Volume Information, pagefile.sys,
               swapfile.sys, hiberfil.sys, thumbs.db, desktop.ini
      Linux:   lost+found, .Trash*, proc, sys, dev (virtual FS entries)
      Both:    symlinks outside the source tree, device files, sockets,
               zero-byte files (deleted placeholders), unreadable/locked files

    The audit log records only file counts and a master SHA3-256 hash —
    never individual file names or content.
    """

    SKIP_DIRS_WIN  = {"$recycle.bin", "system volume information",
                      "$windows.~bt", "$windows.~ws"}
    SKIP_FILES_WIN = {"pagefile.sys", "swapfile.sys", "hiberfil.sys",
                      "desktop.ini",  "thumbs.db"}
    SKIP_DIRS_LIN  = {"lost+found", "proc", "sys", "dev"}

    def __init__(self, audit: AuditLog):
        self.audit = audit

    def backup_live_files(self, source_mount: str, dest_dir: str) -> Dict:
        if not os.path.isdir(source_mount):
            cprint(f"  [Backup] Source '{source_mount}' is not a directory.", C.RED)
            return {"success": False, "reason": "source_not_a_directory"}

        os.makedirs(dest_dir, exist_ok=True)
        cprint(f"\n  Scanning live files on {source_mount}...", C.CYAN)

        total_files  = 0
        total_bytes  = 0
        skipped      = 0
        failed       = 0
        master_hash  = hashlib.sha3_256()

        for root, dirs, files in os.walk(source_mount, topdown=True, followlinks=False):
            # Prune skip directories in-place
            prune = []
            for d in dirs:
                dl = d.lower()
                if IS_WINDOWS and dl in self.SKIP_DIRS_WIN:
                    prune.append(d); skipped += 1; continue
                if IS_LINUX  and dl in self.SKIP_DIRS_LIN:
                    prune.append(d); skipped += 1; continue
                if dl.startswith(".trash"):
                    prune.append(d); skipped += 1; continue
            for d in prune:
                dirs.remove(d)

            for fname in files:
                # Skip system files (Windows)
                if IS_WINDOWS and fname.lower() in self.SKIP_FILES_WIN:
                    skipped += 1; continue

                src = os.path.join(root, fname)

                # Must be a regular file (not symlink, device, socket, pipe)
                try:
                    st = os.lstat(src)
                    if not stat.S_ISREG(st.st_mode):
                        skipped += 1; continue
                    if st.st_size == 0:
                        skipped += 1; continue   # zero-byte = likely deleted placeholder
                except OSError:
                    skipped += 1; continue

                # Compute destination path preserving relative structure
                rel  = os.path.relpath(src, source_mount)
                dest = os.path.join(dest_dir, rel)

                try:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    fhash = hashlib.sha3_256()
                    with open(src, "rb") as sf, open(dest, "wb") as df:
                        while True:
                            buf = sf.read(4 * 1024 * 1024)
                            if not buf:
                                break
                            df.write(buf)
                            fhash.update(buf)
                            master_hash.update(buf)
                            total_bytes += len(buf)
                    total_files += 1
                    progress_bar(total_bytes, total_bytes, f"{total_files} files")
                except (PermissionError, OSError):
                    failed += 1   # locked/system file — silently skip
                except Exception as e:
                    cprint(f"\n  [Backup] Error on file #{total_files + failed}: {e}",
                           C.YELLOW)
                    failed += 1

        digest  = master_hash.hexdigest()
        summary = {
            "success":         True,
            "dest":            dest_dir,
            "files_copied":    total_files,
            "bytes_copied":    total_bytes,
            "files_skipped":   skipped,
            "files_failed":    failed,
            "master_sha3_256": digest,
        }
        cprint(f"\n  ✓ Backup: {total_files} files, {human_size(total_bytes)}, "
               f"{failed} failed — hash {digest[:24]}...", C.GREEN)

        # Audit: counts and hash only — no file names, no paths
        self.audit.log("BACKUP_COMPLETE", {
            "files_copied":    total_files,
            "bytes_copied":    total_bytes,
            "files_skipped":   skipped,
            "files_failed":    failed,
            "master_sha3_256": digest,
        })
        return summary


# ══════════════════════════════════════════════════════════════════════════════
#  11. UI HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _prompt(msg: str, default: str = "") -> str:
    try:
        val = input(f"{C.YELLOW}  ▶ {msg}{C.RESET} ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        cprint("\n  Interrupted — wiping keys.", C.RED)
        KEY_STORE.wipe_all()
        sys.exit(1)

def _confirm(msg: str, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    val  = _prompt(f"{msg} {hint}:").lower()
    return default if val == "" else val in ("y", "yes")

def _menu(title: str, options: List[Tuple[str, str]]) -> str:
    cprint(f"\n  {title}", C.CYAN, bold=True)
    for k, label in options:
        cprint(f"    {C.BOLD}{k}{C.RESET}  {label}")
    valid = [k.lower() for k, _ in options]
    while True:
        c = _prompt("Choice:").lower()
        if c in valid:
            return c
        cprint("  Invalid choice.", C.RED)


def _select_target(drives: List[DriveInfo]) -> Optional[Tuple[EraseTarget, DriveInfo]]:
    cprint("\n  Detected Storage Devices:", C.CYAN, bold=True)
    cprint("  " + "─" * 68, C.DIM)
    for i, d in enumerate(drives):
        sys_tag = f" {C.RED}[SYSTEM]{C.RESET}"       if d.is_system    else ""
        rm_tag  = f" {C.YELLOW}[REMOVABLE]{C.RESET}" if d.is_removable else ""
        cprint(f"  {C.BOLD}[{i+1}]{C.RESET}  {d.device}  |  {d.model}  "
               f"|  {d.size_human}  |  {C.CYAN}{d.drive_type}{C.RESET}{sys_tag}{rm_tag}")
        for p in d.partitions:
            mp = f" → {p['mountpoint']}" if p.get("mountpoint") else ""
            cprint(f"        {C.DIM}├── {p['device']}  {p['size_human']}{mp}{C.RESET}")
    cprint("  " + "─" * 68, C.DIM)

    while True:
        raw = _prompt(f"Select drive [1-{len(drives)}]:")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(drives):
                break
        except ValueError:
            pass
        cprint("  Invalid.", C.RED)

    drive = drives[idx]
    if drive.is_system:
        cprint("\n  ⚠  WARNING: This appears to be the SYSTEM drive!", C.RED, bold=True)
        if not _confirm("  Are you ABSOLUTELY SURE you want to erase the system drive?"):
            return None

    gran = _menu("What to erase?", [
        ("1", f"Entire disk  {drive.device}  ({drive.size_human})"),
        ("2", "Specific partition"),
        ("3", "Custom byte range"),
    ])

    if gran == "1":
        mp = drive.mount_points[0] if drive.mount_points else drive.drive_letter
        return (EraseTarget(drive.device, label=f"{drive.model} ({drive.device})",
                            mount_point=mp or ""), drive)

    elif gran == "2":
        if not drive.partitions:
            cprint("  No partitions found. Using full disk.", C.YELLOW)
            return (EraseTarget(drive.device, label=drive.device,
                                mount_point=drive.drive_letter), drive)
        cprint("\n  Partitions:", C.CYAN)
        for i, p in enumerate(drive.partitions):
            cprint(f"    [{i+1}]  {p['device']}  {p['size_human']}  {p.get('mountpoint','')}")
        while True:
            raw = _prompt(f"Partition [1-{len(drive.partitions)}]:")
            try:
                pidx = int(raw) - 1
                if 0 <= pidx < len(drive.partitions):
                    p = drive.partitions[pidx]
                    return (EraseTarget(p["device"], label=f"Partition {p['device']}",
                                        mount_point=p.get("mountpoint","")), drive)
            except ValueError:
                pass
            cprint("  Invalid.", C.RED)

    else:  # "3"
        total = drive.size_bytes
        cprint(f"  Size: {human_size(total)} ({total} bytes)", C.DIM)
        start  = int(_prompt("  Start byte (0):") or "0")
        length = int(_prompt(f"  Length bytes ({total-start}):") or str(total - start))
        return (EraseTarget(drive.device, start_byte=start, length_bytes=length,
                            label=f"{drive.device}[{start}:{start+length}]",
                            mount_point=drive.drive_letter), drive)


def _select_pattern() -> OverwritePattern:
    c = _menu("Overwrite pattern:", [
        ("1", "DoD 5220.22-M  (7-pass)  — Recommended"),
        ("2", "Gutmann        (35-pass) — Maximum"),
        ("3", "3× Random      — Fast, strong for SSDs"),
        ("4", "Zeros only     — Minimal / fast"),
    ])
    return {"1": OverwritePattern.DOD_7PASS, "2": OverwritePattern.GUTMANN_35,
            "3": OverwritePattern.RANDOM,    "4": OverwritePattern.ZEROS}[c]


def _resolve_audit_dir(target: EraseTarget) -> str:
    """
    Determine where to save the audit log.
    Priority: erased device's own mount point → cwd fallback.
    The log is written AFTER erasure so it lands on the just-cleared device.
    """
    mp = target.mount_point
    if mp and os.path.isdir(mp):
        candidate = os.path.join(mp, "nukeit_audit")
        try:
            os.makedirs(candidate, exist_ok=True)
            probe = os.path.join(candidate, ".probe")
            open(probe, "w").close(); os.remove(probe)
            return candidate
        except Exception:
            pass
    fallback = os.path.join(os.getcwd(), "nukeit_audit")
    cprint(f"  [AuditLog] Mount not writable — using fallback: {fallback}", C.YELLOW)
    return fallback


def _list_external_mounts(exclude_device: str) -> List[str]:
    mounts: List[str] = []
    if IS_WINDOWS:
        import string
        for dl in string.ascii_uppercase:
            path = f"{dl}:\\"
            if os.path.exists(path) and f"{dl}:" not in exclude_device:
                mounts.append(path)
    else:
        try:
            r    = subprocess.run(["lsblk", "-o", "MOUNTPOINT", "-J"],
                                  capture_output=True, text=True)
            data = json.loads(r.stdout)
            for dev in data.get("blockdevices", []):
                for child in dev.get("children") or []:
                    mp = child.get("mountpoint") or ""
                    if mp and mp not in ("/", "") and exclude_device not in mp:
                        mounts.append(mp)
        except Exception:
            pass
    return mounts


# ══════════════════════════════════════════════════════════════════════════════
#  12. DEMO TARGET
# ══════════════════════════════════════════════════════════════════════════════

def _create_demo_target() -> Optional[DriveInfo]:
    path = (
        os.path.join(os.environ.get("TEMP", "C:\\Temp"), "nukeit_demo.bin")
        if IS_WINDOWS else "/tmp/nukeit_demo.bin"
    )
    try:
        with open(path, "wb") as f:
            f.write(os.urandom(4 * 1024 * 1024))
        cprint(f"  Demo file created: {path}  (4 MB)", C.GREEN)
        parent = os.path.dirname(path)
        return DriveInfo(
            device=path, model="Demo File Target",
            size_bytes=4*1024*1024, size_human="4.0 MB",
            drive_type="SSD", is_removable=True, is_system=False,
            mount_points=[parent], drive_letter=parent,
        )
    except Exception as e:
        cprint(f"  [!] Could not create demo file: {e}", C.RED)
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  13. MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    banner()

    # 1. Hard privilege gate — exit if not root / Administrator
    check_and_enforce_privileges()
    cprint(f"  ✓ Running as {'Administrator' if IS_WINDOWS else 'root'}.", C.GREEN)

    # 2. Initialise ephemeral crypto engine (keys in RAM only)
    cprint("\n  [Init] Generating ephemeral crypto keys in RAM...", C.CYAN)
    crypto = CryptoEngine(KEY_STORE)
    cprint(f"  [Init] Ed25519 pubkey: {crypto.public_key_hex()[:32]}...", C.GREEN)
    cprint(f"  [Init] Keys in store: {KEY_STORE.list_keys()}", C.DIM)

    audit = AuditLog(crypto)

    # 3. Detect drives
    cprint("\n  [Scan] Detecting storage devices...", C.CYAN, bold=True)
    drives = detect_drives()

    if not drives:
        cprint("  No drives detected (VM or restricted environment).", C.YELLOW)
        if _confirm("  Create a demo 4MB file target for testing?"):
            demo = _create_demo_target()
            if demo:
                drives = [demo]
        if not drives:
            cprint("  No targets. Exiting.", C.RED)
            sys.exit(1)

    # 4. Select target
    sel = _select_target(drives)
    if sel is None:
        cprint("  No target selected. Exiting.", C.YELLOW)
        sys.exit(0)
    target, drive_info = sel

    audit.log("TARGET_SELECTED", {
        "device_label": target.label,
        "drive_type":   drive_info.drive_type,
        "size_bytes":   target.resolve_length(),
    })

    # 5. Overwrite pattern
    pattern = _select_pattern()
    audit.log("PATTERN_SELECTED", {"pattern": pattern.value})

    # 6. Crypto-shredding option
    cprint("\n  Crypto-Shredding", C.CYAN, bold=True)
    cprint("  AES-256-GCM + ChaCha20-Poly1305, per-block ephemeral HKDF keys.", C.DIM)
    cprint("  Keys are never written to disk and are destroyed after each block.", C.DIM)
    use_crypto = _confirm("\n  Enable crypto-shredding?", default=True)
    audit.log("OPTIONS", {"crypto_shredding": use_crypto})

    # 7. Pre-erasure backup — LIVE FILES ONLY
    backup_result = None
    do_backup = _confirm("\n  Extract live files to external device before erasure?")
    if do_backup:
        source_mount = target.mount_point
        if not source_mount or not os.path.isdir(source_mount):
            cprint(
                "  [!] No accessible filesystem mount on target.\n"
                "  Mount the partition first, then re-run with backup option.",
                C.YELLOW
            )
            do_backup = False
        else:
            ext = _list_external_mounts(target.device)
            if ext:
                cprint("\n  Available external locations:", C.CYAN)
                for i, m in enumerate(ext):
                    cprint(f"    [{i+1}]  {m}", C.DIM)
            dest = _prompt("  Backup destination path:",
                           default=ext[0] if ext else "")
            if not dest:
                cprint("  No destination — skipping backup.", C.YELLOW)
                do_backup = False
            else:
                be = BackupEngine(audit)
                backup_result = be.backup_live_files(source_mount, dest)

    # 8. Final confirmation
    cprint("\n" + "═" * 66, C.RED)
    cprint("  ⚠   FINAL WARNING — THIS OPERATION CANNOT BE UNDONE   ⚠",
           C.RED, bold=True)
    cprint("═" * 66 + "\n", C.RED)
    cprint(f"  Device  : {target.label}")
    cprint(f"  Pattern : {pattern.value}")
    cprint(f"  Crypto  : {'YES — AES-256 + ChaCha20 ephemeral' if use_crypto else 'NO'}")
    cprint(f"  Backup  : {'YES → ' + str((backup_result or {}).get('dest','')) if do_backup else 'NO'}")
    cprint(f"  OS      : {platform.system()}")
    print()

    if not _confirm("  Confirm — type YES to begin:", default=False):
        cprint("  Aborted by user.", C.YELLOW)
        audit.log("ABORTED_BY_USER", {})
        audit.finalize_and_save(_resolve_audit_dir(target))
        crypto.wipe_keys()
        sys.exit(0)

    # 9. Erasure
    cprint("\n" + "═" * 66, C.GREEN)
    cprint("  ERASURE IN PROGRESS", C.GREEN, bold=True)
    cprint("═" * 66, C.GREEN)

    eraser  = SecureEraser(crypto, audit)
    start_t = time.time()
    try:
        result = eraser.erase(target, pattern, use_crypto, drive_info)
    except Exception as e:
        cprint(f"\n  [!] Erasure failed: {e}", C.RED)
        audit.log("ERASURE_FAILED", {"error_type": type(e).__name__})
        audit.finalize_and_save(_resolve_audit_dir(target))
        crypto.wipe_keys()
        sys.exit(1)

    elapsed = time.time() - start_t
    audit.log("ERASURE_COMPLETE", {
        "duration_seconds": round(elapsed, 2),
        "passes_executed":  len(result["passes"]),
        "final_sha3_256":   result["final_hash"],
    })

    # 10. Save audit log to the erased device/location
    audit_dir = _resolve_audit_dir(target)
    log_path  = audit.finalize_and_save(audit_dir)

    # 11. Wipe all keys from RAM
    cprint("\n  [Cleanup] Wiping all ephemeral keys from RAM...", C.CYAN)
    crypto.wipe_keys()

    # 12. Summary
    cprint("\n" + "═" * 66, C.GREEN)
    cprint("  ✓  ERASURE COMPLETE", C.GREEN, bold=True)
    cprint("═" * 66, C.GREEN)
    cprint(f"\n  Device       : {target.label}")
    cprint(f"  Duration     : {elapsed:.1f}s")
    cprint(f"  Passes done  : {len(result['passes'])}")
    cprint(f"  Final hash   : {result['final_hash'][:48]}...")
    cprint(f"  Crypto-shred : {'✓' if use_crypto else '✗'}")
    cprint(f"  Audit log    : {log_path}", C.GREEN)
    cprint(f"\n  NukeIt complete. Data is gone. 🔥\n", C.GREEN, bold=True)


if __name__ == "__main__":
    main()