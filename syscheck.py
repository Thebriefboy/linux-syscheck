#!/usr/bin/env python3
"""
syscheck - a complete, read-only system health checkup.

Checks system, CPU, memory, processes, storage, network, services, security,
logs/kernel, cleanliness and power. Every problem found comes with a concrete
suggestion, and the run ends with a health score and a prioritised to-do list.

Pure standard library (Python 3.8+). Linux gets the full checkup; other Unix
systems get a reduced one. It NEVER modifies anything on your machine.

Usage:
    python3 syscheck.py                 # full checkup
    sudo python3 syscheck.py            # more complete (SMART, shadow, logs)
    python3 syscheck.py --fast          # quicker, skips the slowest checks
    python3 syscheck.py --offline       # skip network tests
    python3 syscheck.py --json          # machine-readable output
    python3 syscheck.py --report r.txt  # also save a plain-text report

Exit codes: 0 = healthy, 1 = warnings found, 2 = critical problems found.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

VERSION = "1.0.0"

OK, WARN, CRIT, INFO = "OK", "WARN", "CRIT", "INFO"
LINUX = sys.platform.startswith("linux")
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
HOME = os.path.expanduser("~")

G = {"unicode": True}          # global render settings
SAMPLE: Dict[str, object] = {}  # data shared between checks
SAMPLE_SECS = 1.0
OPTS = {"fast": False, "offline": False}

KiB, MiB, GiB = 1024, 1024 ** 2, 1024 ** 3


# --------------------------------------------------------------------------- #
#  Styling
# --------------------------------------------------------------------------- #
class Style:
    enabled = False
    codes = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
             "blue": "34", "magenta": "35", "cyan": "36", "gray": "90"}

    @classmethod
    def c(cls, text, *names) -> str:
        text = str(text)
        if not cls.enabled or not names:
            return text
        seq = ";".join(cls.codes[n] for n in names)
        return f"\033[{seq}m{text}\033[0m"


COLORS = {OK: "green", WARN: "yellow", CRIT: "red", INFO: "cyan"}
ICONS_U = {OK: "✔", WARN: "▲", CRIT: "✖", INFO: "•"}
ICONS_A = {OK: "+", WARN: "!", CRIT: "x", INFO: "-"}
ORDER = {CRIT: 0, WARN: 1, INFO: 2, OK: 3}


def asciify(text: str) -> str:
    """Make text safe for terminals that cannot show Unicode."""
    for src, dst in (("·", "|"), ("…", "..."), ("°", " "), ("━", "="), ("─", "-"),
                     ("█", "#"), ("░", "-"), ("✔", "+"), ("✖", "x"), ("▲", "!"), ("•", "-")):
        text = text.replace(src, dst)
    return text.encode("ascii", "replace").decode("ascii")


def bar(pct: float, status: str, width: int = 12) -> str:
    pct = max(0.0, min(100.0, pct))
    filled = int(round(pct / 100 * width))
    full = "█" if G["unicode"] else "#"
    empty = "░" if G["unicode"] else "-"
    return Style.c(full * filled, COLORS[status]) + Style.c(empty * (width - filled), "gray")


# --------------------------------------------------------------------------- #
#  Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    section: str
    name: str
    status: str
    detail: str
    suggestion: str = ""
    meter: Optional[float] = None


class Report:
    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self.section = "General"

    def add(self, name: str, status: str, detail: str, suggestion: str = "",
            meter: Optional[float] = None) -> None:
        self.findings.append(Finding(self.section, name, status, detail, suggestion, meter))

    def by_section(self) -> List[Tuple[str, List[Finding]]]:
        out: Dict[str, List[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.section, []).append(f)
        return list(out.items())

    def count(self, status: str) -> int:
        return sum(1 for f in self.findings if f.status == status)

    @property
    def score(self) -> int:
        return max(0, 100 - 15 * self.count(CRIT) - 5 * self.count(WARN))


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
def read(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def run(cmd: List[str], timeout: float = 10) -> Tuple[int, str, str]:
    """Run a command safely. Returns (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, env={**os.environ, "LC_ALL": "C", "LANG": "C"})
        return p.returncode, p.stdout, p.stderr
    except (FileNotFoundError, PermissionError):
        return 127, "", ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # pragma: no cover
        return 1, "", str(exc)


def with_timeout(fn: Callable, timeout: float):
    box: Dict[str, object] = {}

    def runner() -> None:
        try:
            box["v"] = fn()
        except Exception as exc:
            box["e"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None, TimeoutError("timed out")
    return box.get("v"), box.get("e")


def hs(n: float) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def fmt_dur(sec: float) -> str:
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def unescape_mount(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def dir_size(path: str, budget: float) -> Tuple[int, bool, bool]:
    """Disk usage of a directory tree. Returns (bytes, complete, had_permission_errors)."""
    deadline = time.monotonic() + budget
    total, complete, denied = 0, True, False
    stack = [path]
    while stack:
        if time.monotonic() > deadline:
            complete = False
            break
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            st = e.stat(follow_symlinks=False)
                            total += getattr(st, "st_blocks", 0) * 512 or st.st_size
                    except OSError:
                        continue
        except PermissionError:
            denied = True
        except OSError:
            continue
    return total, complete, denied


# --------------------------------------------------------------------------- #
#  /proc readers
# --------------------------------------------------------------------------- #
def cpu_times() -> Optional[Dict[str, int]]:
    for line in read("/proc/stat").splitlines():
        if line.startswith("cpu "):
            try:
                v = [int(x) for x in line.split()[1:]]
            except ValueError:
                return None
            v += [0] * (8 - len(v))
            return {"total": sum(v[:8]), "idle": v[3] + v[4], "iowait": v[4], "steal": v[7]}
    return None


def proc_snapshot() -> Dict[int, Tuple[str, str, int, int]]:
    snap: Dict[int, Tuple[str, str, int, int]] = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return snap
    for pid in pids:
        s = read(f"/proc/{pid}/stat")
        l, r = s.find("("), s.rfind(")")
        if l < 0 or r < 0:
            continue
        rest = s[r + 2:].split()
        try:
            snap[int(pid)] = (s[l + 1:r], rest[0], int(rest[11]) + int(rest[12]), int(rest[21]))
        except (IndexError, ValueError):
            continue
    return snap


def meminfo() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for line in read("/proc/meminfo").splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m:
            out[m.group(1)] = int(m.group(2)) * 1024
    return out


def read_temps() -> List[Tuple[str, float]]:
    temps: List[Tuple[str, float]] = []
    for hw in glob.glob("/sys/class/hwmon/hwmon*"):
        name = read(os.path.join(hw, "name")).strip() or os.path.basename(hw)
        for f in glob.glob(os.path.join(hw, "temp*_input")):
            try:
                val = int(read(f).strip()) / 1000.0
            except ValueError:
                continue
            label = read(f.replace("_input", "_label")).strip() or name
            if 0 < val < 150:
                temps.append((f"{name}/{label}", val))
    if not temps:
        for z in glob.glob("/sys/class/thermal/thermal_zone*"):
            try:
                val = int(read(os.path.join(z, "temp")).strip()) / 1000.0
            except ValueError:
                continue
            if 0 < val < 150:
                temps.append((read(os.path.join(z, "type")).strip() or "zone", val))
    return temps


# --------------------------------------------------------------------------- #
#  Checks
# --------------------------------------------------------------------------- #
def check_system(r: Report) -> None:
    osname = platform.platform()
    if LINUX:
        for line in read("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                osname = line.split("=", 1)[1].strip().strip('"')
    r.add("Operating system", INFO, f"{osname} · kernel {platform.release()} · {platform.machine()}")
    r.add("Hostname", INFO, socket.gethostname())

    if LINUX:
        product = read("/sys/class/dmi/id/product_name").strip()
        rc, virt, _ = run(["systemd-detect-virt"], 3)
        virt = virt.strip() if rc == 0 else ""
        if product or virt:
            r.add("Hardware", INFO, " · ".join(x for x in (product, f"virtualized ({virt})" if virt else "") if x))

    uptime = None
    if LINUX:
        try:
            uptime = float(read("/proc/uptime").split()[0])
        except (IndexError, ValueError):
            uptime = None
    if uptime is not None:
        days = uptime / 86400
        if days > 90:
            r.add("Uptime", WARN, f"{fmt_dur(uptime)} without a reboot",
                  "Reboot soon so kernel and library updates actually take effect.")
        else:
            r.add("Uptime", OK, fmt_dur(uptime))

    if LINUX and "microsoft" not in platform.release().lower():
        rel = platform.release()
        needs = os.path.exists("/var/run/reboot-required")
        mod_roots = [p for p in ("/usr/lib/modules", "/lib/modules") if os.path.isdir(p)]
        if mod_roots and not any(os.path.isdir(os.path.join(p, rel)) for p in mod_roots):
            needs = True
        if needs:
            r.add("Reboot needed", WARN, "A kernel/system update is waiting for a reboot",
                  "Save your work and run: sudo reboot")
        else:
            r.add("Reboot needed", OK, "no")

    if shutil.which("timedatectl"):
        rc, out, _ = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], 5)
        val = out.strip().lower()
        if rc == 0 and val in ("yes", "no"):
            if val == "yes":
                r.add("Clock sync", OK, "synchronised with NTP")
            else:
                r.add("Clock sync", WARN, "system clock is not NTP-synchronised",
                      "Enable time sync: sudo timedatectl set-ntp true")


def check_cpu(r: Report) -> None:
    cores = os.cpu_count() or 1
    model = ""
    if LINUX:
        found: Dict[str, str] = {}
        for line in read("/proc/cpuinfo").splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key, val = key.strip().lower(), val.strip()
            if val and key not in found:
                found[key] = val
        for key in ("model name", "hardware", "cpu model", "model"):
            val = found.get(key, "")
            if val and not val.isdigit():  # x86 "model" is just a numeric id
                model = val
                break
    model = model or platform.processor() or platform.machine()
    r.add("Processor", INFO, f"{model} ({cores} logical cores)")

    if LINUX:
        a, p0, t0 = cpu_times(), proc_snapshot(), time.monotonic()
        time.sleep(SAMPLE_SECS)
        b, p1, dt = cpu_times(), proc_snapshot(), time.monotonic() - t0
        SAMPLE.update(p0=p0, p1=p1, dt=dt)
        if a and b and b["total"] > a["total"]:
            dtot = b["total"] - a["total"]
            busy = 100.0 * (1 - (b["idle"] - a["idle"]) / dtot)
            iow = 100.0 * (b["iowait"] - a["iowait"]) / dtot
            steal = 100.0 * (b["steal"] - a["steal"]) / dtot
            busy = max(0.0, min(100.0, busy))
            if busy > 90:
                r.add("CPU usage", WARN, f"{busy:.0f}% busy over {dt:.1f}s",
                      "Find the culprit with `top` or `htop` (sort by CPU) and stop or fix it.", busy)
            else:
                r.add("CPU usage", OK, f"{busy:.0f}% busy over {dt:.1f}s", meter=busy)
            if iow > 20:
                r.add("I/O wait", WARN, f"{iow:.0f}% of CPU time waiting on disk",
                      "The disk is a bottleneck. Check `iotop`, free disk space, and drive health (SMART).")
            if steal > 10:
                r.add("CPU steal", WARN, f"{steal:.0f}% stolen by the hypervisor",
                      "The host is overcommitted. Move to a less busy host or a larger VM plan.")

    try:
        l1, l5, l15 = os.getloadavg()
        per = l15 / cores
        detail = f"{l1:.2f} / {l5:.2f} / {l15:.2f}  (1/5/15 min, {cores} cores)"
        if per > 2.0:
            r.add("Load average", CRIT, detail,
                  "System is heavily overloaded for a sustained period. Find and stop heavy jobs (`top`).")
        elif per > 1.0:
            r.add("Load average", WARN, detail,
                  "Load exceeds core count over 15 min. Check long-running processes with `top`.")
        else:
            r.add("Load average", OK, detail)
    except OSError:
        pass

    if LINUX:
        temps = read_temps()
        if temps:
            label, val = max(temps, key=lambda t: t[1])
            detail = f"{val:.0f}°C hottest sensor ({label})"
            if val >= 95:
                r.add("Temperature", CRIT, detail,
                      "Dangerously hot. Shut down if it persists; clean dust, check fans and thermal paste.")
            elif val >= 85:
                r.add("Temperature", WARN, detail,
                      "Running hot. Clean vents/fans, improve airflow, reduce load.")
            else:
                r.add("Temperature", OK, detail)


def check_memory(r: Report) -> None:
    if not LINUX:
        return
    m = meminfo()
    total = m.get("MemTotal", 0)
    if not total:
        return
    avail = m.get("MemAvailable", m.get("MemFree", 0))
    used_pct = 100.0 * (total - avail) / total
    avail_pct = 100.0 - used_pct
    detail = f"{hs(total - avail)} used of {hs(total)} ({hs(avail)} available)"
    if avail_pct < 10:
        r.add("Memory", CRIT, detail,
              "Almost out of RAM. Close heavy apps, check `ps aux --sort=-%mem | head`, or add RAM/swap.", used_pct)
    elif avail_pct < 20:
        r.add("Memory", WARN, detail,
              "RAM is getting tight. Close unused apps/browser tabs or add more RAM.", used_pct)
    else:
        r.add("Memory", OK, detail, meter=used_pct)

    st = m.get("SwapTotal", 0)
    if st:
        su = st - m.get("SwapFree", 0)
        sp = 100.0 * su / st
        detail = f"{hs(su)} used of {hs(st)}"
        if sp > 80 and avail_pct < 10:
            r.add("Swap", CRIT, detail, "System is thrashing on swap. Free memory or add RAM.", sp)
        elif sp > 50 and avail_pct < 25:
            r.add("Swap", WARN, detail,
                  "Heavy swap use together with low free RAM slows everything down. Reduce memory use.", sp)
        else:
            r.add("Swap", OK, detail, meter=sp)
    elif total < 4 * GiB:
        r.add("Swap", INFO, "no swap configured on a low-memory system",
              "Enable zram or a swap file to avoid out-of-memory kills (e.g. install `zram-tools`/`systemd-zram-generator`).")
    else:
        r.add("Swap", INFO, "none configured")


def check_processes(r: Report) -> None:
    if not LINUX:
        return
    p0 = SAMPLE.get("p0") or {}
    p1 = SAMPLE.get("p1") or proc_snapshot()
    dt = float(SAMPLE.get("dt") or 0)  # type: ignore[arg-type]
    page = os.sysconf("SC_PAGE_SIZE")
    clk = os.sysconf("SC_CLK_TCK")

    r.add("Process count", INFO, f"{len(p1)} processes")  # type: ignore[arg-type]
    zombies = [v[0] for v in p1.values() if v[1] == "Z"]  # type: ignore[union-attr]
    dstate = [v[0] for v in p1.values() if v[1] == "D"]  # type: ignore[union-attr]
    if len(zombies) > 10:
        r.add("Zombies", WARN, f"{len(zombies)} zombie processes ({', '.join(sorted(set(zombies))[:4])})",
              "Zombies are finished children never reaped. Restart or fix their parent process.")
    elif zombies:
        r.add("Zombies", INFO, f"{len(zombies)} zombie process(es)")
    else:
        r.add("Zombies", OK, "none")
    if len(dstate) >= 5:
        r.add("Blocked (D state)", WARN, f"{len(dstate)} processes stuck in uninterruptible I/O wait",
              "Usually a failing disk, hung NFS mount or driver. Check `dmesg` and storage health.")

    cpu_by: Counter = Counter()
    rss_by: Counter = Counter()
    for pid, (name, _state, ticks, rss) in p1.items():  # type: ignore[union-attr]
        rss_by[name] += rss * page
        if dt > 0 and pid in p0 and p0[pid][0] == name:  # type: ignore[index]
            cpu_by[name] += max(0, ticks - p0[pid][2]) / clk / dt * 100  # type: ignore[index]
    if cpu_by:
        top = [(n, c) for n, c in cpu_by.most_common(5) if c > 0.0]
        r.add("Top CPU", INFO, ", ".join(f"{n} {c:.0f}%" for n, c in top) if top else "system is idle")
    top_mem = rss_by.most_common(5)
    if top_mem and top_mem[0][1] > 0:
        r.add("Top memory", INFO, ", ".join(f"{n} {hs(v)}" for n, v in top_mem))

    # Pressure stall information (kernel 4.20+)
    for res, thr_w, thr_c in (("cpu", 25, 50), ("memory", 10, 30), ("io", 25, 50)):
        txt = read(f"/proc/pressure/{res}")
        m = re.search(r"some avg10=([\d.]+)", txt)
        if not m:
            continue
        val = float(m.group(1))
        detail = f"{val:.1f}% of the last 10s spent stalled"
        if val >= thr_c:
            r.add(f"{res.upper() if res == 'io' else res.capitalize()} pressure", CRIT, detail,
                  f"Processes are heavily stalled on {res}. Identify the heavy workload and reduce it.")
        elif val >= thr_w:
            r.add(f"{res.upper() if res == 'io' else res.capitalize()} pressure", WARN, detail,
                  f"Noticeable {res} contention. Check what is running with `top`/`iotop`.")

    fn = read("/proc/sys/fs/file-nr").split()
    if len(fn) >= 3 and int(fn[2]) > 0:
        pct = 100.0 * int(fn[0]) / int(fn[2])
        if pct > 70:
            r.add("File handles", WARN, f"{fn[0]} of {fn[2]} in use ({pct:.0f}%)",
                  "A process may be leaking file descriptors. Check `lsof | wc -l`, raise fs.file-max if legitimate.")


REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3",
           "fuseblk", "zfs", "jfs", "reiserfs"}


def mounted_filesystems() -> List[Tuple[str, str, str, List[str]]]:
    out, seen = [], set()
    for line in read("/proc/self/mounts").splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        dev, mp, fs, opts = p[0], unescape_mount(p[1]), p[2], p[3].split(",")
        if fs not in REAL_FS or dev.startswith("/dev/loop"):
            continue
        if mp.startswith(("/snap/", "/var/snap/", "/var/lib/docker", "/var/lib/containers")):
            continue
        try:
            key = os.stat(mp).st_dev
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append((dev, mp, fs, opts))
    return out


def check_storage(r: Report) -> None:
    mounts = mounted_filesystems() if LINUX else []
    if not mounts:
        mounts = [("(root)", "/", "?", [])]
    for dev, mp, fs, opts in mounts:
        try:
            st = os.statvfs(mp)
        except OSError:
            continue
        frs = st.f_frsize or st.f_bsize
        total = st.f_blocks * frs
        if total == 0:
            continue
        used = (st.f_blocks - st.f_bfree) * frs
        avail = st.f_bavail * frs
        pct = 100.0 * used / (used + avail) if (used + avail) else 0.0
        detail = f"{mp}: {hs(used)} of {hs(total)} used, {hs(avail)} free  [{fs}]"
        hint = (f"Find big items: sudo du -xh {mp} --max-depth=2 2>/dev/null | sort -rh | head -20  "
                "(or use `ncdu`). Then clean caches/logs, see the Cleanliness section.")
        read_only = "ro" in opts
        if read_only and pct >= 80:
            # A full read-only image (installer, runtime bundle) is normal, not a problem.
            r.add("Disk space", INFO, detail + " (read-only, nothing can fill it)", meter=pct)
        elif pct >= 90:
            r.add("Disk space", CRIT, detail, hint, pct)
        elif pct >= 80:
            r.add("Disk space", WARN, detail, hint, pct)
        else:
            r.add("Disk space", OK, detail, meter=pct)

        if st.f_files > 0:
            ipct = 100.0 * (st.f_files - st.f_ffree) / st.f_files
            if ipct >= 90:
                r.add("Inodes", CRIT, f"{mp}: {ipct:.0f}% of inodes used",
                      "Too many small files. Find them: sudo find %s -xdev -type f | cut -d/ -f1-4 | sort | uniq -c | sort -rn | head" % mp)
            elif ipct >= 80:
                r.add("Inodes", WARN, f"{mp}: {ipct:.0f}% of inodes used",
                      "Lots of small files (caches, mail, sessions). Clean them before inodes run out.")
        if read_only:
            if mp in ("/", "/home", "/var", "/usr", "/boot"):
                r.add("Read-only mount", WARN, f"{mp} is mounted read-only",
                      "A system filesystem is read-only; it may have hit errors. Check `dmesg | grep -i error` and run fsck from rescue mode.")
            else:
                r.add("Read-only mount", INFO, f"{mp} is mounted read-only (usually intentional)")

    if LINUX:
        _check_smart(r)


def _check_smart(r: Report) -> None:
    disks = [d for d in sorted(os.listdir("/sys/block"))
             if not d.startswith(("loop", "ram", "zram", "dm-", "sr", "md", "nbd"))] \
        if os.path.isdir("/sys/block") else []
    if not disks:
        return
    if not shutil.which("smartctl"):
        r.add("Drive health", INFO, "smartmontools not installed - can't read SMART data",
              "Install it (e.g. sudo apt install smartmontools) to detect failing drives early.")
        return
    if not IS_ROOT:
        r.add("Drive health", INFO, "SMART check needs root", "Re-run with sudo to check drive health.")
        return
    for d in disks:
        rc, out, _ = run(["smartctl", "-H", f"/dev/{d}"], 15)
        txt = out.upper()
        if "FAILED" in txt:
            r.add(f"SMART {d}", CRIT, "drive reports FAILING health",
                  "BACK UP YOUR DATA NOW and replace the drive.")
        elif "PASSED" in txt or "OVERALL-HEALTH SELF-ASSESSMENT TEST RESULT: OK" in txt or ": OK" in txt:
            r.add(f"SMART {d}", OK, "health test passed")
        else:
            r.add(f"SMART {d}", INFO, "SMART not available on this device (virtual disk or USB bridge)")


def tcp_latency(host: str, port: int, timeout: float = 3.0) -> Optional[float]:
    t = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return (time.monotonic() - t) * 1000
    except OSError:
        return None


def _is_loopback(ip: str, v6: bool) -> bool:
    if not v6:
        return len(ip) == 8 and ip.endswith("7F")
    return ip == "0" * 24 + "01000000" or (ip.startswith("0" * 16 + "FFFF0000") and ip.endswith("7F"))


def listening_ports() -> List[int]:
    ports = set()
    for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        for line in read(path).splitlines()[1:]:
            p = line.split()
            if len(p) < 4 or p[3] != "0A":
                continue
            ip, _, port = p[1].partition(":")
            if _is_loopback(ip, v6):
                continue
            try:
                ports.add(int(port, 16))
            except ValueError:
                continue
    return sorted(ports)


def check_network(r: Report) -> None:
    if LINUX:
        names = []
        for line in read("/proc/net/dev").splitlines()[2:]:
            if ":" not in line:
                continue
            iface, data = line.split(":", 1)
            iface = iface.strip()
            if iface == "lo":
                continue
            f = data.split()
            try:
                rx_p, rx_e, rx_d, tx_p, tx_e, tx_d = (int(f[i]) for i in (1, 2, 3, 9, 10, 11))
            except (IndexError, ValueError):
                continue
            state = read(f"/sys/class/net/{iface}/operstate").strip() or "?"
            names.append(f"{iface} ({state})")
            pk = rx_p + tx_p
            bad = rx_e + rx_d + tx_e + tx_d
            if pk > 10000 and bad / pk > 0.01:
                r.add(f"Errors {iface}", WARN, f"{bad} errors/drops out of {pk} packets ({100 * bad / pk:.1f}%)",
                      "Check the cable, Wi-Fi signal, driver and router. Try `ethtool -S %s`." % iface)
        if names:
            r.add("Interfaces", INFO, ", ".join(names))
        has_route = any(l.split()[1] == "00000000" for l in read("/proc/net/route").splitlines()[1:] if len(l.split()) > 1)
        if not has_route and not OPTS["offline"]:
            r.add("Default route", WARN, "no default gateway configured",
                  "Check your network connection/DHCP: `ip route`, `nmcli device status`.")

    ports = listening_ports() if LINUX else []
    if LINUX:
        if len(ports) > 15:
            r.add("Open ports", WARN, f"{len(ports)} ports listening on non-loopback addresses: "
                  + ", ".join(map(str, ports[:15])) + " ...",
                  "Review with `sudo ss -tulpn` and stop services you don't need.")
        elif ports:
            r.add("Open ports", INFO, f"{len(ports)} listening on non-loopback: " + ", ".join(map(str, ports)),
                  "Make sure each is intended: `sudo ss -tulpn`.")
        else:
            r.add("Open ports", OK, "nothing listens on external interfaces")

    if OPTS["offline"]:
        r.add("Internet", INFO, "network tests skipped (--offline)")
        return

    lat = []
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)):
        samples = [tcp_latency(host, port) for _ in range(3)]
        ok = [s for s in samples if s is not None]
        if ok:
            lat = ok
            lat_host, lost = host, 3 - len(ok)
            break
    dns_ok, dns_ms = False, 0.0
    for name in ("example.com", "cloudflare.com"):
        t = time.monotonic()
        _, err = with_timeout(lambda n=name: socket.getaddrinfo(n, 443, proto=socket.IPPROTO_TCP), 5)
        if err is None:
            dns_ok, dns_ms = True, (time.monotonic() - t) * 1000
            break

    if lat:
        avg = sum(lat) / len(lat)
        detail = f"reachable via {lat_host}: {avg:.0f} ms avg, {max(lat):.0f} ms max"
        if lost:
            r.add("Internet", WARN, detail + f", {lost}/3 attempts failed",
                  "Unstable connection. Check Wi-Fi signal, router, and ISP.")
        elif avg > 200:
            r.add("Internet", WARN, detail, "High latency. Check Wi-Fi quality, VPN, or ISP/route problems.")
        else:
            r.add("Internet", OK, detail)
        if dns_ok:
            if dns_ms > 1000:
                r.add("DNS", WARN, f"resolves, but slowly ({dns_ms:.0f} ms)",
                      "Switch to a faster resolver (e.g. 1.1.1.1 or 9.9.9.9) in your network settings.")
            else:
                r.add("DNS", OK, f"resolving normally ({dns_ms:.0f} ms)")
        else:
            r.add("DNS", CRIT, "internet reachable but names do not resolve",
                  "Check /etc/resolv.conf and systemd-resolved (`resolvectl status`), or set a public DNS like 1.1.1.1.")
    else:
        if dns_ok:
            r.add("Internet", WARN, "DNS works but test servers were unreachable (firewall/blocked?)",
                  "Check firewall or ISP filtering of ports 443/53.")
        else:
            r.add("Internet", WARN, "no internet connectivity detected",
                  "Check cable/Wi-Fi, router and `ip route`. Ignore if this machine is intentionally offline.")


def check_services(r: Report) -> None:
    if not (LINUX and shutil.which("systemctl") and os.path.isdir("/run/systemd/system")):
        return
    rc, out, _ = run(["systemctl", "is-system-running"], 5)
    state = out.strip()
    rc, out, _ = run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"], 8)
    failed = [l.split()[0].lstrip("●* ") for l in out.splitlines() if l.strip()]
    if failed:
        r.add("Failed services", CRIT if len(failed) > 3 else WARN,
              f"{len(failed)} failed: {', '.join(failed[:6])}",
              f"Inspect each: systemctl status {failed[0]}  and  journalctl -u {failed[0]} -b")
    else:
        r.add("Failed services", OK, "none (system state: %s)" % (state or "unknown"))

    if not OPTS["fast"] and shutil.which("systemd-analyze"):
        rc, out, _ = run(["systemd-analyze", "time"], 8)
        line = next((l for l in out.splitlines() if "Startup finished" in l), "")
        m = re.search(r"=\s*(?:(\d+)min\s*)?([\d.]+)s", line)
        if m:
            secs = int(m.group(1) or 0) * 60 + float(m.group(2))
            detail = f"last boot took {secs:.0f}s"
            if secs > 60:
                r.add("Boot time", WARN, detail,
                      "Slow boot. See offenders: systemd-analyze blame | head -15  and disable unneeded services.")
            else:
                r.add("Boot time", OK, detail)


def _sshd_settings() -> Optional[Dict[str, str]]:
    base = "/etc/ssh/sshd_config"
    if not os.path.exists(base):
        return None
    vals: Dict[str, str] = {}

    def parse(path: str, depth: int = 0) -> None:
        in_match = False
        for raw in read(path).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            if key == "match":
                in_match = True
                continue
            if in_match:
                continue
            if key == "include" and len(parts) > 1 and depth < 3:
                for pat in parts[1].split():
                    pat = pat if os.path.isabs(pat) else os.path.join("/etc/ssh", pat)
                    for f in sorted(glob.glob(pat)):
                        parse(f, depth + 1)
                continue
            if len(parts) == 2 and key not in vals:
                vals[key] = parts[1].strip().lower()

    parse(base)
    return vals


def pending_updates() -> Optional[Tuple[str, int, int, str]]:
    if shutil.which("apt"):
        rc, out, _ = run(["apt", "list", "--upgradable"], 25)
        lines = [l for l in out.splitlines() if "upgradable" in l.lower()]
        return "apt", len(lines), sum(1 for l in lines if "-security" in l), "sudo apt update && sudo apt upgrade"
    if shutil.which("checkupdates"):
        rc, out, _ = run(["checkupdates"], 40)
        return "pacman", len([l for l in out.splitlines() if l.strip()]), 0, "sudo pacman -Syu"
    if shutil.which("dnf") and not OPTS["fast"]:
        rc, out, _ = run(["dnf", "-q", "check-update"], 40)
        n = 0
        for l in out.splitlines():
            if l.startswith("Obsoleting"):
                break
            if re.match(r"^\S+\.\S+\s+\S+\s+\S+", l):
                n += 1
        return "dnf", n, 0, "sudo dnf upgrade"
    return None


def check_security(r: Report) -> None:
    if not LINUX:
        return
    up = pending_updates()
    if up:
        mgr, n, sec, cmd = up
        if n == 0:
            r.add("Updates", OK, f"all packages up to date ({mgr})")
        else:
            detail = f"{n} update(s) available" + (f", {sec} security" if sec else "") + f" ({mgr})"
            if sec or n >= 30:
                r.add("Updates", WARN, detail, f"Install them: {cmd}")
            else:
                r.add("Updates", INFO, detail, f"Install them: {cmd}")

    # Firewall
    ports = listening_ports()
    active = []
    if shutil.which("systemctl"):
        for svc in ("ufw", "firewalld", "nftables", "netfilter-persistent"):
            if run(["systemctl", "is-active", "--quiet", svc], 4)[0] == 0:
                active.append(svc)
    if active:
        r.add("Firewall", OK, "active: " + ", ".join(active))
    elif ports:
        r.add("Firewall", WARN, "no active firewall service detected while ports are exposed",
              "Enable one: sudo apt install ufw && sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable")
    else:
        r.add("Firewall", INFO, "no firewall service detected (nothing is exposed right now)")

    ssh = _sshd_settings()
    if ssh is not None:
        if ssh.get("permitemptypasswords") == "yes":
            r.add("SSH empty passwords", CRIT, "PermitEmptyPasswords is enabled",
                  "Set `PermitEmptyPasswords no` in /etc/ssh/sshd_config and restart sshd.")
        if ssh.get("permitrootlogin") == "yes":
            r.add("SSH root login", WARN, "root can log in over SSH with a password",
                  "Set `PermitRootLogin prohibit-password` (or `no`) in /etc/ssh/sshd_config, then restart sshd.")
        else:
            r.add("SSH root login", OK, "not permitted with a password")
        if ssh.get("passwordauthentication", "yes") == "yes":
            r.add("SSH passwords", INFO, "password logins are enabled",
                  "Prefer key-only auth: set `PasswordAuthentication no` once your SSH key works.")

    if IS_ROOT:
        empty = []
        for line in read("/etc/shadow").splitlines():
            p = line.split(":")
            if len(p) > 1 and p[1] == "":
                empty.append(p[0])
        if empty:
            r.add("Empty passwords", CRIT, "accounts with no password: " + ", ".join(empty),
                  "Lock or set a password: sudo passwd -l <user>  or  sudo passwd <user>")
        else:
            r.add("Empty passwords", OK, "no accounts without a password")

    vdir = "/sys/devices/system/cpu/vulnerabilities"
    if os.path.isdir(vdir):
        bad = [n for n in sorted(os.listdir(vdir)) if read(os.path.join(vdir, n)).startswith("Vulnerable")]
        if bad:
            r.add("CPU vulnerabilities", INFO, "unmitigated: " + ", ".join(bad),
                  "Update the kernel and CPU microcode (intel-microcode / amd64-microcode) and reboot.")


def check_logs(r: Report) -> None:
    if not LINUX:
        return
    has_journal = shutil.which("journalctl") is not None
    if has_journal:
        rc, out, err = run(["journalctl", "-p", "err", "--since", "24 hours ago", "--no-pager", "-q"], 15)
        if "insufficient permissions" in err.lower() or ("No journal files" in err):
            r.add("Error log (24h)", INFO, "journal not readable by this user",
                  "Add yourself to the `systemd-journal` group or run with sudo for log analysis.")
        elif rc == 124:
            r.add("Error log (24h)", INFO, "journal scan timed out (very large journal)")
        else:
            lines = [l for l in out.splitlines() if l.strip() and not l.startswith("-- ")]
            units = Counter()
            for l in lines:
                parts = l.split()
                if len(parts) > 4:
                    units[re.sub(r"\[\d+\]$", "", parts[4].rstrip(":"))] += 1
            top = ", ".join(f"{u} ({c})" for u, c in units.most_common(3))
            detail = f"{len(lines)} error entries" + (f"; noisiest: {top}" if top else "")
            if len(lines) > 1000:
                r.add("Error log (24h)", CRIT, detail,
                      "Excessive errors. Inspect: journalctl -p err --since '24 hours ago' | less")
            elif len(lines) > 200:
                r.add("Error log (24h)", WARN, detail,
                      "Many errors. Inspect: journalctl -p err --since '24 hours ago' | less")
            else:
                r.add("Error log (24h)", OK, detail)

        rc, out, _ = run(["journalctl", "--disk-usage"], 8)
        m = re.search(r"([\d.]+)\s*([KMGT])", out)
        if m:
            size = float(m.group(1)) * {"K": KiB, "M": MiB, "G": GiB, "T": GiB * 1024}[m.group(2)]
            if size > 2 * GiB:
                r.add("Journal size", WARN, f"logs use {hs(size)}",
                      "Trim: sudo journalctl --vacuum-size=500M  (and set SystemMaxUse=500M in /etc/systemd/journald.conf)")

    # Kernel log: OOM kills and hardware / filesystem errors
    klog = ""
    if has_journal:
        rc, klog, _ = run(["journalctl", "-k", "-b", "-q", "--no-pager"], 15)
    if not klog.strip():
        rc, klog, _ = run(["dmesg"], 8)
    if klog.strip():
        klog = klog[-5_000_000:]
        oom = len(re.findall(r"Out of memory: Kill(?:ed)? process", klog))
        if oom:
            r.add("OOM kills", CRIT if oom > 2 else WARN, f"kernel killed processes {oom} time(s) since boot",
                  "You are running out of RAM. Add RAM/swap, limit memory-hungry apps, or find leaks.")
        else:
            r.add("OOM kills", OK, "none since boot")
        hw = re.findall(
            r"(?im)^.*(Buffer I/O error|EXT4-fs error|XFS .*(?:corrupt|error)|BTRFS (?:error|critical)|"
            r"blk_update_request: I/O error|nvme\d+.*(?:timeout|reset)|ata\d+(?:\.\d+)?: .*(?:failed command|exception)|"
            r"Hardware Error|Machine check).*$", klog)
        if hw:
            r.add("Disk/hardware errors", CRIT if len(hw) >= 3 else WARN,
                  f"{len(hw)} I/O or hardware error line(s) in the kernel log",
                  "Back up important data, check `sudo smartctl -a /dev/<disk>`, reseat cables, and inspect `dmesg -T | grep -i error`.")
        else:
            r.add("Disk/hardware errors", OK, "none in kernel log")
    else:
        r.add("Kernel log", INFO, "not readable by this user", "Run with sudo to analyse the kernel log.")


CLEAN_TARGETS: List[Tuple[str, str, int, str]] = [
    ("User cache", os.path.join(HOME, ".cache"), 5 * GiB,
     "Inspect: du -sh ~/.cache/* | sort -h | tail. Most app caches are safe to delete (apps rebuild them)."),
    ("Trash", os.path.join(HOME, ".local/share/Trash"), 1 * GiB,
     "Empty it: gio trash --empty   (or rm -rf ~/.local/share/Trash/*)"),
    ("npm cache", os.path.join(HOME, ".npm"), 2 * GiB, "npm cache clean --force"),
    ("APT cache", "/var/cache/apt/archives", 1 * GiB, "sudo apt clean && sudo apt autoremove --purge"),
    ("DNF cache", "/var/cache/dnf", 1 * GiB, "sudo dnf clean all"),
    ("Pacman cache", "/var/cache/pacman/pkg", 3 * GiB, "sudo paccache -r  (from pacman-contrib)"),
    ("System logs", "/var/log", 1 * GiB,
     "sudo journalctl --vacuum-time=14d ; sudo logrotate -f /etc/logrotate.conf ; remove old *.gz logs"),
    ("Core dumps", "/var/lib/systemd/coredump", 500 * MiB, "sudo rm -f /var/lib/systemd/coredump/*"),
    ("Temp (/tmp)", "/tmp", 2 * GiB, "Reboot clears /tmp, or delete files you no longer need."),
    ("Temp (/var/tmp)", "/var/tmp", 2 * GiB, "Delete files you no longer need in /var/tmp."),
]


def check_cleanliness(r: Report) -> None:
    if sys.platform == "win32":
        return
    budget = 1.0 if OPTS["fast"] else 4.0
    seen = set()
    for label, path, limit, hint in CLEAN_TARGETS:
        if not os.path.isdir(path) or path in seen:
            continue
        seen.add(path)
        size, complete, denied = dir_size(path, budget)
        note = ""
        if not complete:
            note = " (at least; scan time limit reached)"
        elif denied and not IS_ROOT:
            note = " (partial; run with sudo for exact size)"
        detail = f"{hs(size)}{note}  - {path}"
        if size > limit:
            r.add(label, WARN, detail, hint)
        else:
            r.add(label, OK, detail)

    if shutil.which("docker"):
        rc, out, _ = run(["docker", "system", "df", "--format", "{{.Type}}: {{.Reclaimable}}"], 8)
        if rc == 0 and out.strip():
            r.add("Docker", INFO, "reclaimable: " + "; ".join(out.strip().splitlines()),
                  "Free space with: docker system prune   (add -a for unused images; review first)")


def check_power(r: Report) -> None:
    if not LINUX:
        return
    for bat in sorted(glob.glob("/sys/class/power_supply/BAT*")):
        name = os.path.basename(bat)

        def num(fname: str) -> Optional[float]:
            try:
                return float(read(os.path.join(bat, fname)).strip())
            except ValueError:
                return None

        cap, status = num("capacity"), read(os.path.join(bat, "status")).strip()
        full = num("energy_full") or num("charge_full")
        design = num("energy_full_design") or num("charge_full_design")
        parts = []
        if cap is not None:
            parts.append(f"{cap:.0f}% ({status or 'unknown'})")
        if full and design:
            health = 100.0 * full / design
            parts.append(f"health {health:.0f}% of original capacity")
            if health < 60:
                r.add(f"Battery {name}", WARN, ", ".join(parts),
                      "Battery has lost much of its capacity. Consider replacing it.")
                continue
        cyc = read(os.path.join(bat, "cycle_count")).strip()
        if cyc.isdigit() and int(cyc) > 0:
            parts.append(f"{cyc} cycles")
        if parts:
            r.add(f"Battery {name}", OK, ", ".join(parts))


SECTIONS: List[Tuple[str, Callable[[Report], None]]] = [
    ("System", check_system),
    ("CPU", check_cpu),
    ("Memory", check_memory),
    ("Processes & Pressure", check_processes),
    ("Storage", check_storage),
    ("Network", check_network),
    ("Services", check_services),
    ("Security", check_security),
    ("Logs & Kernel", check_logs),
    ("Cleanliness", check_cleanliness),
    ("Power", check_power),
]


# --------------------------------------------------------------------------- #
#  Rendering
# --------------------------------------------------------------------------- #
def render(rep: Report, width: int, color: bool, meta: Dict[str, object]) -> str:
    Style.enabled = color
    U = G["unicode"]
    out: List[str] = []
    heavy, light = ("━", "─") if U else ("=", "-")

    out.append(Style.c(heavy * width, "cyan"))
    out.append(Style.c("  SYSCHECK", "bold", "cyan") + Style.c(f"  v{VERSION} · complete system health checkup", "gray"))
    out.append(Style.c(f"  {meta['host']} · {meta['when']} · scanned in {meta['secs']:.1f}s"
                       f"{'' if IS_ROOT else ' · not root (some checks limited)'}", "gray"))
    out.append(Style.c(heavy * width, "cyan"))

    for section, items in rep.by_section():
        out.append("")
        title = f" {section} "
        out.append(Style.c(light * 2, "gray") + Style.c(title, "bold") + Style.c(light * max(2, width - len(title) - 2), "gray"))
        for f in items:
            icon = Style.c((ICONS_U if U else ICONS_A)[f.status], COLORS[f.status], "bold")
            name = Style.c(f"{f.name:<19.19}", "bold")
            prefix = 2 + 1 + 1 + 19 + 1
            meter = ""
            if f.meter is not None:
                meter = bar(f.meter, f.status) + " "
                prefix += 13
            lines = textwrap.wrap(f.detail, max(24, width - prefix), break_long_words=False,
                                  break_on_hyphens=False) or [""]
            tint = COLORS[f.status] if f.status in (WARN, CRIT) else None
            first = Style.c(lines[0], tint) if tint else lines[0]
            out.append(f"  {icon} {name} {meter}{first}")
            for ln in lines[1:]:
                out.append(" " * prefix + (Style.c(ln, tint) if tint else ln))

    # Summary
    score = rep.score
    grade, gcol = (("EXCELLENT", "green") if score >= 90 else ("GOOD", "green") if score >= 75
                   else ("NEEDS ATTENTION", "yellow") if score >= 55 else ("POOR", "red"))
    gstatus = {"green": OK, "yellow": WARN, "red": CRIT}[gcol]
    out.append("")
    out.append(Style.c(heavy * width, "cyan"))
    out.append("  " + Style.c("HEALTH SCORE ", "bold") + Style.c(f"{score}/100", "bold", gcol) + "  "
               + bar(score, gstatus, 30) + "  " + Style.c(grade, "bold", gcol))
    out.append("  " + "   ".join([
        Style.c(f"{rep.count(OK)} ok", "green"), Style.c(f"{rep.count(WARN)} warnings", "yellow"),
        Style.c(f"{rep.count(CRIT)} critical", "red"), Style.c(f"{rep.count(INFO)} info", "cyan")]))
    out.append(Style.c(heavy * width, "cyan"))

    todo = sorted([f for f in rep.findings if f.status in (CRIT, WARN) and f.suggestion],
                  key=lambda f: ORDER[f.status])
    tips = [f for f in rep.findings if f.status == INFO and f.suggestion]

    def listing(items: List[Finding], title: str) -> None:
        out.append("")
        out.append(Style.c(f"  {title}", "bold"))
        for i, f in enumerate(items, 1):
            tag = Style.c(f"[{f.status}]", COLORS[f.status], "bold")
            head = f"  {i:>2}. "
            body = f"{f.name}: {f.suggestion}"
            wrapped = textwrap.wrap(body, max(30, width - len(head) - 7), break_long_words=False,
                                    break_on_hyphens=False)
            out.append(f"{head}{tag} {wrapped[0]}")
            for ln in wrapped[1:]:
                out.append(" " * (len(head) + 7) + ln)

    if todo:
        listing(todo, "WHAT TO FIX (most urgent first)")
    elif rep.count(CRIT) == 0 and rep.count(WARN) == 0:
        out.append("")
        out.append("  " + Style.c("Nothing to fix. Your system is clean, fast and healthy.", "bold", "green"))
    if tips:
        listing(tips, "OPTIONAL IMPROVEMENTS")
    out.append("")
    Style.enabled = False
    text = "\n".join(out)
    return text if U else asciify(text)


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    global SAMPLE_SECS
    ap = argparse.ArgumentParser(description="Complete, read-only system health checkup with suggestions.")
    ap.add_argument("--fast", action="store_true", help="shorter sampling, skip the slowest checks")
    ap.add_argument("--offline", action="store_true", help="skip network connectivity tests")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON")
    ap.add_argument("--no-color", action="store_true", help="disable colours")
    ap.add_argument("--report", metavar="FILE", help="also save a plain-text report to FILE")
    ap.add_argument("--version", action="version", version=f"syscheck {VERSION}")
    args = ap.parse_args(argv)

    if sys.platform == "win32":
        print("syscheck supports Linux (full) and macOS/BSD (reduced). Windows is not supported.", file=sys.stderr)
        return 3
    if sys.version_info < (3, 8):
        print("Python 3.8 or newer is required.", file=sys.stderr)
        return 3

    OPTS["fast"], OPTS["offline"] = args.fast, args.offline
    SAMPLE_SECS = 0.5 if args.fast else 1.0
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # never crash on an odd terminal encoding
        except (AttributeError, ValueError):
            pass
    G["unicode"] = (sys.stdout.encoding or "").lower().startswith("utf")
    color = (sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
             and os.environ.get("TERM") != "dumb" and not args.json)
    show_progress = sys.stderr.isatty() and not args.json

    rep = Report()
    start = time.monotonic()
    for title, fn in SECTIONS:
        rep.section = title
        if show_progress:
            sys.stderr.write(f"\r\033[K  Checking {title}...")
            sys.stderr.flush()
        try:
            fn(rep)
        except Exception as exc:  # one broken check must never kill the whole run
            rep.add("Check error", INFO, f"{title} check could not complete: {type(exc).__name__}: {exc}")
    if show_progress:
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()

    meta = {"host": socket.gethostname(), "when": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "secs": time.monotonic() - start}
    width = max(72, min(110, shutil.get_terminal_size((100, 24)).columns))

    if args.json:
        print(json.dumps({"version": VERSION, "host": meta["host"], "timestamp": meta["when"],
                          "score": rep.score,
                          "counts": {s: rep.count(s) for s in (OK, WARN, CRIT, INFO)},
                          "findings": [asdict(f) for f in rep.findings]}, indent=2))
    else:
        print(render(rep, width, color, meta))

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                G_prev = G["unicode"]
                G["unicode"] = True
                fh.write(render(rep, width, False, meta))
                G["unicode"] = G_prev
            if not args.json:
                print(f"  Report saved to {args.report}")
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)

    return 2 if rep.count(CRIT) else (1 if rep.count(WARN) else 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
