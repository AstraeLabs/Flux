#!/usr/bin/env python3

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time

DATA = "/data"
VERIFY_STRIDE = 10


def sh(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


# ---------------------------------------------------------------------------------------------- host info
def versions():
    def first(argv, n=1):
        try:
            r = sh(argv)
            txt = (r.stdout + r.stderr).strip().splitlines()
            return " / ".join(l.strip() for l in txt[:n])
        except OSError as e:
            return "unavailable (%s)" % e
    return {"flux": first(["flux", "--version"]), "shaka": first(["packager", "--version"]),
            "bento4": first(["mp4decrypt"], 2), "ffmpeg": first(["ffmpeg", "-version"])}


def host_info():
    cpu = mem = "?"
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal"):
                mem = "%.1f GiB" % (int(line.split()[1]) / 1048576)
                break
    except OSError:
        pass
    visible = len(os.sched_getaffinity(0))  # type: ignore[attr-defined]
    return {"cpu": cpu, "cpus_visible": visible, "mem": mem, "kernel": platform.release()}


# ----------------------------------------------------------------------------------------------- cache
def cached_mb():
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("Cached:"):
                return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return -1.0


COLD = {"mode": "cold", "method": "none", "cached_before_mb": None, "cached_after_mb": None}


def drop_caches(paths):
    os.sync()  # type: ignore[attr-defined]
    before = cached_mb()
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3\n")
        COLD["method"] = "drop_caches"
    except OSError:
        for p in paths:
            if os.path.isfile(p):
                fd = os.open(p, os.O_RDONLY)
                try:
                    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)  # type: ignore[attr-defined]
                finally:
                    os.close(fd)
        COLD["method"] = "fadvise(DONTNEED) on the input file only - run the container with --privileged for a full drop"
    COLD["cached_before_mb"], COLD["cached_after_mb"] = round(before), round(cached_mb())


# ------------------------------------------------------------------------------------------- measuring
def run_proc(argv, errfile, stdout_path=None):
    t0 = time.perf_counter()
    with open(errfile, "ab") as ef:
        out = open(stdout_path, "wb") if stdout_path else None
        try:
            p = subprocess.Popen(argv, stdout=out if out else subprocess.DEVNULL, stderr=ef)
            _, status, ru = os.wait4(p.pid, 0)  # type: ignore[attr-defined]
        finally:
            if out:
                out.close()
    p.returncode = os.waitstatus_to_exitcode(status)
    return {"rc": p.returncode, "wall": time.perf_counter() - t0, "cpu": ru.ru_utime + ru.ru_stime,
            "rss_mb": ru.ru_maxrss / 1024.0}


def combine(parts, wall):
    """Metrics of a pass made of several processes: wall measured by the caller, CPU summed, RSS = max."""
    return {"rc": next((m["rc"] for m in parts if m["rc"] != 0), 0), "wall": wall,
            "cpu": sum(m["cpu"] for m in parts), "rss_mb": max(m["rss_mb"] for m in parts)}


def last_err(errfile):
    try:
        return open(errfile, "rb").read()[-300:].decode("utf-8", "replace").strip()
    except OSError:
        return ""


def rm(path):
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    elif os.path.exists(path):
        os.remove(path)


def dir_size(d):
    return sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d))


# ----------------------------------------------------------------------------------------- verification
def packet_md5(path):
    """(md5, clean): clean is False when ffmpeg printed any error while demuxing."""
    r = sh(["ffmpeg", "-v", "error", "-i", path, "-map", "0:v:0", "-c", "copy", "-f", "md5", "-"])
    return (r.stdout.strip() or "ERR:" + r.stderr.strip()[:200]), r.returncode == 0 and not r.stderr.strip()


def decode_tail_ok(path):
    r = sh(["ffmpeg", "-v", "error", "-sseof", "-4", "-i", path, "-map", "0:v:0", "-f", "null", "-"])
    return r.returncode == 0 and not r.stderr.strip()


def media_seconds(path):
    r = sh(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "packet=pts_time,duration_time",
            "-of", "csv=p=0", path])
    first, end = None, 0.0
    for line in r.stdout.splitlines():
        parts = line.split(",")
        try:
            pts = float(parts[0])
            dur = float(parts[1]) if len(parts) > 1 and parts[1] not in ("", "N/A") else 0.0
        except ValueError:
            continue
        first = pts if first is None else min(first, pts)
        end = max(end, pts + dur)
    return round(end - first, 1) if first is not None else None


def _children(f, start, end):
    pos = start
    while pos + 8 <= end:
        f.seek(pos)
        h = f.read(16)
        sz = int.from_bytes(h[:4], "big")
        if sz == 1:
            sz = int.from_bytes(h[8:16], "big")
        if sz < 8:
            break
        yield h[4:8], pos, sz
        pos += sz


def scrub_encryption_boxes(path):
    """Rename leftover senc/saiz/saio boxes in every moof/traf to `free`, in place (what Flux does itself).
    Some decryptors keep them; ffmpeg then rejects the file because the init no longer describes them."""
    boxes, _ = read_boxes(path)
    with open(path, "r+b") as f:
        for typ, pos, sz in boxes:
            if typ != b"moof":
                continue
            for ct, cp, cs in list(_children(f, pos + 8, pos + sz)):
                if ct != b"traf":
                    continue
                for tt, tp, _ in list(_children(f, cp + 8, cp + cs)):
                    if tt in (b"senc", b"saiz", b"saio"):
                        f.seek(tp + 4)
                        f.write(b"free")


def file_signature(path):
    """(packet md5, plays as-is, scrubbed). `plays as-is` = ffmpeg decodes the last seconds of the raw output.
    If ffmpeg cannot even demux it, the leftover encryption boxes are scrubbed first so the packets can still be
    compared; the report keeps the two facts apart."""
    plays = decode_tail_ok(path)
    md5, clean = packet_md5(path)
    scrubbed = False
    if not clean:
        scrub_encryption_boxes(path)
        md5, clean = packet_md5(path)
        scrubbed = True
    return (md5 if clean else "ERR:" + md5), plays, scrubbed


def concat_files(paths, dst):
    with open(dst, "wb") as o:
        for p in paths:
            with open(p, "rb") as i:
                shutil.copyfileobj(i, o, 8 << 20)


# -------------------------------------------------------------------------------------- input staging
def read_boxes(path):
    size = os.path.getsize(path)
    boxes, pos = [], 0
    with open(path, "rb") as f:
        while pos < size:
            f.seek(pos)
            h = f.read(16)
            sz = int.from_bytes(h[:4], "big")
            if sz == 1:
                sz = int.from_bytes(h[8:16], "big")
            elif sz == 0:
                sz = size - pos
            if sz < 8:
                raise ValueError("bad box at %d in %s" % (pos, path))
            boxes.append((h[4:8], pos, sz))
            pos += sz
    return boxes, size


def split_chunks(src, dstdir):
    """seg_00000.mp4 = everything before the first moof (the init); then one file per moof..mdat.
    Concatenated they are byte-identical to src (what `flux --chunks` expects); seg_00000 alone is the init."""
    boxes, size = read_boxes(src)
    ranges, cur, seen = [], 0, False
    for typ, pos, sz in boxes:
        if typ == b"moof" and not seen:
            ranges.append((0, pos))
            cur, seen = pos, True
        elif typ == b"mdat" and seen:
            ranges.append((cur, pos + sz))
            cur = pos + sz
    if not seen or len(ranges) < 2:
        raise ValueError("%s is not a fragmented MP4" % src)
    ranges[-1] = (ranges[-1][0], size)  # trailing boxes (mfra...) stay with the last fragment
    os.makedirs(dstdir, exist_ok=True)
    with open(src, "rb") as f:
        for i, (a, b) in enumerate(ranges):
            f.seek(a)
            left = b - a
            with open(os.path.join(dstdir, "seg_%05d.mp4" % i), "wb") as o:
                while left:
                    buf = f.read(min(left, 8 << 20))
                    o.write(buf)
                    left -= len(buf)
    return len(ranges) - 1


# ----------------------------------------------------------------------------------------------- scenarios
class Ctx:
    def __init__(self, job, inp, chunks, nseg):
        self.job, self.inp, self.chunks, self.nseg = job, inp, chunks, nseg
        self.keys = job["keys"]
        # Files whose tenc carries an all-zero KID (PlayReady-style): Flux resolves the real KID itself, Shaka and
        # Bento4 need the key mapped to the KID the file actually carries (e.g. 000...0:KEY).
        self.extra_keys = job.get("extra_keys", [])
        self.init = os.path.join(chunks, "seg_00000.mp4")
        self.err = os.path.join(DATA, "stderr.txt")
        self.out = os.path.join(DATA, "out.mp4")
        self.work = os.path.join(DATA, "work.mp4")          # copy of the input for --in-place
        self.workdir = os.path.join(DATA, "work-chunks")    # copy of the chunk set for --chunks --in-place
        self.segout = os.path.join(DATA, "out-segs")
        self.verify = os.path.join(DATA, "verify.mp4")

    def keyargs(self, flag="--key", extra=False):
        a = []
        for k in self.keys + (self.extra_keys if extra else []):
            a += [flag, k]
        return a

    def seg(self, i):
        return os.path.join(self.chunks, "seg_%05d.mp4" % i)


class FileScenario:
    """One process, one input file, one output (file, or stdout redirected to a file, or the input itself)."""
    group = "whole file"

    def __init__(self, label, build, stdout=False, inplace=False):
        self.label, self.build, self.stdout, self.inplace = label, build, stdout, inplace

    def prepare(self, c):
        rm(c.out)
        if self.inplace:
            shutil.copyfile(c.inp, c.work)

    def run(self, c):
        target = c.work if self.inplace else c.out
        return run_proc(self.build(c, target), c.err, stdout_path=c.out if self.stdout else None)

    def result_path(self, c):
        return c.work if self.inplace else c.out

    def out_bytes(self, c):
        return os.path.getsize(self.result_path(c))

    def signature(self, c):
        return file_signature(self.result_path(c))

    def cleanup(self, c):
        rm(c.out)
        rm(c.work)


class ChunksScenario(FileScenario):
    """`flux --chunks DIR`: no merge step, the input is the seg_<n>.mp4 set."""
    group = "streaming (Flux)"

    def __init__(self, label, mode, extra=()):
        self.label, self.mode, self.extra = label, mode, list(extra)
        self.stdout = mode == "stdout"
        self.inplace = mode == "inplace"

    def prepare(self, c):
        rm(c.out)
        if self.inplace:
            rm(c.workdir)
            shutil.copytree(c.chunks, c.workdir)

    def run(self, c):
        d = c.workdir if self.inplace else c.chunks
        argv = ["flux", "--chunks", d] + c.keyargs() + self.extra
        argv += ["--in-place"] if self.inplace else ["-o", "-" if self.stdout else c.out]
        return run_proc(argv, c.err, stdout_path=c.out if self.stdout else None)

    def result_path(self, c):
        if self.inplace:
            concat_files([os.path.join(c.workdir, f) for f in sorted(os.listdir(c.workdir))], c.verify)
            return c.verify
        return c.out

    def out_bytes(self, c):
        return dir_size(c.workdir) if self.inplace else os.path.getsize(c.out)

    def cleanup(self, c):
        rm(c.out)
        rm(c.workdir)
        rm(c.verify)


class DaemonFileScenario(FileScenario):
    """`flux --daemon` fed one JSON job for the whole merged file (progressive MP4 out, no key sanity check)."""

    def run(self, c):
        t0 = time.perf_counter()
        p = subprocess.Popen(["flux", "--daemon"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        assert p.stdin and p.stdout
        p.stdin.write(json.dumps({"input": c.inp, "output": c.out, "keys": c.keys}) + "\n")
        p.stdin.flush()
        line = p.stdout.readline()
        ok = bool(line) and bool(json.loads(line).get("ok"))
        if not ok:
            with open(c.err, "a") as ef:
                ef.write("daemon job: %s\n" % line.strip())
        p.stdin.write("--quit\n")
        p.stdin.close()
        _, status, ru = os.wait4(p.pid, 0)  # type: ignore[attr-defined]
        p.returncode = os.waitstatus_to_exitcode(status)
        return {"rc": 0 if ok and p.returncode == 0 else 1, "wall": time.perf_counter() - t0,
                "cpu": ru.ru_utime + ru.ru_stime, "rss_mb": ru.ru_maxrss / 1024.0}


class SegmentsScenario:
    """Live-style: every fragment is a separate job, decrypted with the init segment (--fragments-info)."""
    group = "live, one fragment per job"

    def __init__(self, label, kind):
        self.label, self.kind = label, kind

    def _out(self, c, i):
        return os.path.join(c.segout, "o_%05d.mp4" % i)

    def prepare(self, c):
        rm(c.segout)
        os.makedirs(c.segout)

    def run(self, c):
        if self.kind == "daemon":
            return self._daemon(c)
        parts, t0 = [], time.perf_counter()
        for i in range(1, c.nseg + 1):
            if self.kind == "flux":
                argv = ["flux", c.seg(i), "-o", self._out(c, i), "--fragments-info", c.init] + c.keyargs()
            else:
                argv = ["mp4decrypt"] + c.keyargs(extra=True) + ["--fragments-info", c.init, c.seg(i), self._out(c, i)]
            m = run_proc(argv, c.err)
            parts.append(m)
            if m["rc"] != 0:
                break
        return combine(parts, time.perf_counter() - t0)

    def _daemon(self, c):
        t0 = time.perf_counter()
        p = subprocess.Popen(["flux", "--daemon"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        assert p.stdin and p.stdout
        rc = 0
        for i in range(1, c.nseg + 1):
            job = {"input": c.seg(i), "output": self._out(c, i), "keys": c.keys, "fragments_info": c.init}
            p.stdin.write(json.dumps(job) + "\n")
            p.stdin.flush()
            line = p.stdout.readline()
            if not line or not json.loads(line).get("ok"):
                rc = 1
                with open(c.err, "a") as ef:
                    ef.write("daemon job %d: %s\n" % (i, line.strip()))
                break
        p.stdin.write("--quit\n")
        p.stdin.close()
        _, status, ru = os.wait4(p.pid, 0)  # type: ignore[attr-defined]
        p.returncode = os.waitstatus_to_exitcode(status)
        return {"rc": rc or p.returncode, "wall": time.perf_counter() - t0, "cpu": ru.ru_utime + ru.ru_stime,
                "rss_mb": ru.ru_maxrss / 1024.0}

    def out_bytes(self, c):
        return dir_size(c.segout)

    def signature(self, c):
        """packet md5 of every VERIFY_STRIDE-th output. Both tools write a bare moof+mdat, so the init is prepended."""
        idx = sorted(set(range(1, c.nseg + 1, VERIFY_STRIDE)) | {c.nseg})
        sums, scrubbed, plays = [], False, True
        for i in idx:
            concat_files([c.init, self._out(c, i)], c.verify)
            md5, clean = packet_md5(c.verify)
            if not clean:
                scrub_encryption_boxes(c.verify)
                md5, clean = packet_md5(c.verify)
                scrubbed = True
            sums.append(md5 if clean else "ERR:" + md5)
        return "|".join(sums), plays, scrubbed

    def cleanup(self, c):
        rm(c.segout)
        rm(c.verify)


def _shaka(c, out):
    spec = ",".join("label=k%d:key_id=%s:key=%s" % ((n,) + tuple(k.split(":", 1)))
                    for n, k in enumerate(c.keys + c.extra_keys))
    return ["packager", "in=%s,stream=video,output=%s" % (c.inp, out), "--enable_raw_key_decryption", "--keys", spec]


def _bento4(c, out):
    return ["mp4decrypt"] + c.keyargs(extra=True) + [c.inp, out]


def _flux(extra, inplace=False):
    # NOTE: `flux IN -o -` (stdout for a single input) is documented in the README but not routed by the CLI
    # (it asks for -f); streaming to stdout is only benchmarked through --chunks.
    def build(c, target):
        if inplace:
            return ["flux", target, "--in-place"] + c.keyargs() + extra
        return ["flux", c.inp, "-o", target] + c.keyargs() + extra
    return build


SCENARIOS = {
    # whole file, every tool with its own default command line
    "shaka": FileScenario("Shaka Packager", _shaka),
    "bento4": FileScenario("Bento4 mp4decrypt", _bento4),
    "flux": FileScenario("Flux (default, progressive MP4)", _flux([])),
    "flux-nosanity": FileScenario("Flux --skip-key-sanity-check", _flux(["--skip-key-sanity-check"])),
    # Flux streaming / in-place modes on the same merged file
    "flux-daemon-file": DaemonFileScenario("Flux --daemon (1 job: whole file)", _flux([])),
    "flux-inplace": FileScenario("Flux --in-place", _flux([], inplace=True), inplace=True),
    # Flux on the unmerged chunk set (no merge step)
    "flux-chunks": ChunksScenario("Flux --chunks -o file", "file"),
    "flux-chunks-stdout": ChunksScenario("Flux --chunks -o - --tfdt-rebase", "stdout", ["--tfdt-rebase"]),
    "flux-chunks-inplace": ChunksScenario("Flux --chunks --in-place", "inplace"),
    # live: one fragment per job
    "flux-segments": SegmentsScenario("Flux --fragments-info (1 process/fragment)", "flux"),
    "flux-daemon": SegmentsScenario("Flux --daemon (1 process, JSON jobs)", "daemon"),
    "bento4-segments": SegmentsScenario("Bento4 --fragments-info (1 process/fragment)", "bento4"),
}


# -------------------------------------------------------------------------------------------------- bench
def stage(src, dst):
    if os.path.exists(dst) and os.path.getsize(dst) == os.path.getsize(src):
        return
    print("  staging %s -> %s (%.2f GB)" % (src, dst, os.path.getsize(src) / 1e9), flush=True)
    shutil.copyfile(src, dst)


def bench_title(job, names, runs):
    inp = os.path.join(DATA, "in-%s.mp4" % job["id"])
    chunks = os.path.join(DATA, "chunks-%s" % job["id"])
    stage(job["path"], inp)
    rm(chunks)
    nseg = split_chunks(inp, chunks)
    duration = None  # measured on the first readable decrypted output (the encrypted input demuxes unreliably)
    print("  split into init + %d fragments" % nseg, flush=True)
    c = Ctx(job, inp, chunks, nseg)
    rows = {n: {"samples": [], "sig": None, "plays": None, "scrubbed": False, "out_bytes": None, "fail": None}
            for n in names}
    rm(c.err)

    for rnd in range(runs + 1):  # round 0 = warm-up, not in the stats, and where correctness is checked
        for n in names:
            sc, row = SCENARIOS[n], rows[n]
            sc.cleanup(c)
            sc.prepare(c)
            if COLD["mode"] == "cold":
                drop_caches([inp])
            m = sc.run(c)
            if m["rc"] != 0:
                row["fail"] = "exit %s: %s" % (m["rc"], last_err(c.err))
                print("  [%s] FAILED round %d: %s" % (n, rnd, row["fail"]), flush=True)
                sc.cleanup(c)
                continue
            if rnd == 0:
                row["out_bytes"] = sc.out_bytes(c)
                row["sig"], row["plays"], row["scrubbed"] = sc.signature(c)
                if duration is None and n in ("flux", "flux-nosanity", "bento4", "shaka") and row["plays"]:
                    duration = media_seconds(sc.result_path(c))
                    print("  video duration: %s s" % duration, flush=True)
            else:
                row["samples"].append(m)
            print("  [%s] round %d: wall %.2fs cpu %.2fs rss %.0f MB" % (n, rnd, m["wall"], m["cpu"], m["rss_mb"]),
                  flush=True)
            sc.cleanup(c)

    def majority(sigs):
        sigs = [x for x in sigs if x and not x.startswith("ERR") and "|ERR" not in x]
        return max(set(sigs), key=sigs.count) if sigs else None

    whole_ref = majority([rows[n]["sig"] for n in names if SCENARIOS[n].group == "whole file"])
    live_ref = majority([rows[n]["sig"] for n in names if SCENARIOS[n].group == "live, one fragment per job"])
    for n in names:
        g = SCENARIOS[n].group
        ref = live_ref if g == "live, one fragment per job" else whole_ref  # chunks outputs: same clear packets
        rows[n]["match"] = bool(ref) and rows[n]["sig"] == ref
    rm(chunks)

    dl = {}
    try:
        dl = json.load(open(os.path.join(os.path.dirname(job["path"]), "download.json")))
    except (OSError, ValueError):
        pass
    return {"id": job["id"], "label": job.get("label", job["id"]), "in_bytes": os.path.getsize(inp),
            "fragments": nseg, "media_seconds": duration, "download": dl, "rows": rows}


def summarize(results, label, vers, host):
    L = ["### %s\n" % label,
         "Host: %s, %d CPUs visible, %s RAM, kernel %s" % (host["cpu"], host["cpus_visible"], host["mem"], host["kernel"]),
         "Tools: " + "; ".join("%s = %s" % (k, v) for k, v in vers.items())]
    if COLD["mode"] == "cold":
        L.append("Cache: cold - page cache dropped before every run via %s (cached %s MB -> %s MB at the last drop)\n"
                 % (COLD["method"], COLD["cached_before_mb"], COLD["cached_after_mb"]))
    else:
        L.append("Cache: WARM (not dropped between runs)\n")
    for res in results:
        dl, dur = res.get("download") or {}, res.get("media_seconds")
        line = "**%s**: %.2f GB, %d fragments" % (res["label"], res["in_bytes"] / 1e9, res["fragments"])
        if dur:
            line += ", %.0f s of video (%.1f s/fragment)" % (dur, dur / res["fragments"])
        if dl.get("download_seconds"):
            line += "; download (N_m3u8DL-RE, %s connections, includes its own merge): %.1f s = %.0f Mbit/s" % (
                dl.get("downloader_threads", "?"), dl["download_seconds"], dl.get("download_mbps", 0))
        L.append(line + "\n")
    L.append("| Title | Mode | Tool / command | Wall median (s) | min-max | ms/fragment | x real time | % of download time "
             "| CPU time user+sys (s) | Avg cores busy | Peak RSS (MB) | MB/s | Output (GB) | Packets match | Plays as-is |")
    L.append("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|")
    for res in results:
        dl, dur = res.get("download") or {}, res.get("media_seconds")
        for n, r in res["rows"].items():
            sc, s = SCENARIOS[n], r["samples"]
            head = "| %s | %s | %s |" % (res["label"], sc.group, sc.label)
            if not s:
                L.append(head + " FAILED: %s ||||||||||||" % " ".join((r["fail"] or "no samples").split())[:110])
                continue
            walls = [x["wall"] for x in s]
            med = statistics.median(walls)
            rt = "%.1f" % (dur / med) if dur else ""
            dpct = "%.1f%%" % (100 * med / dl["download_seconds"]) if dl.get("download_seconds") else ""
            plays = "-" if r["plays"] is None else ("yes" if r["plays"] else "NO")
            if r["scrubbed"]:
                plays += " (leftover senc/saiz/saio)" if not r["plays"] else ""
            cpu = statistics.median(x["cpu"] for x in s)
            L.append(head + " %.2f | %.2f-%.2f | %.0f | %s | %s | %.2f | %.2f | %.0f | %.0f | %.2f | %s | %s |" % (
                med, min(walls), max(walls), 1000 * med / res["fragments"], rt, dpct,
                cpu, cpu / med, max(x["rss_mb"] for x in s),
                res["in_bytes"] / 1e6 / med, (r["out_bytes"] or 0) / 1e9,
                "yes" if r.get("match") else "NO", plays))
    L.append("")
    L.append("_x real time_ = seconds of video decrypted per second of wall time. _% of download time_ = decrypt wall "
             "time divided by the measured download time of the same fragments (below 100% means decrypting is faster "
             "than downloading, so a live pipeline is download-bound). _Avg cores busy_ = CPU time / wall time (1.0 = one "
             "core fully used; Flux decrypts in parallel threads, Shaka and Bento4 mostly do not). _Peak RSS_ = largest "
             "resident set of any process of the run (child processes included). _Packets match_ = md5 of the clear "
             "video packets equals the majority of the tools in the same mode (fragment jobs: every "
             + str(VERIFY_STRIDE) + "th fragment).\n")
    return "\n".join(L) + "\n"


def load_jobs(a):
    if a.file:
        return [{"id": os.path.splitext(os.path.basename(a.file))[0], "path": a.file, "keys": a.key}]
    wanted = set(a.ids.split(",")) if a.ids else None
    jobs = []
    for t in json.load(open(a.titles)):
        if wanted and t["id"] not in wanted:
            continue
        p = os.path.join(a.in_dir, t["id"], "video.mp4")
        if not os.path.exists(p):
            sys.exit("missing input %s (run bench/fetch.sh first)" % p)
        jobs.append({"id": t["id"], "label": t.get("label", t["id"]), "path": p, "keys": t["keys"],
                     "extra_keys": t.get("extra_keys", [])})
    return jobs


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("versions")
    r = sub.add_parser("run")
    r.add_argument("--titles", default="/in/titles.local.json")
    r.add_argument("--in-dir", default="/in")
    r.add_argument("--ids")
    r.add_argument("--file")
    r.add_argument("--key", action="append", default=[])
    r.add_argument("--out", default="/out")
    r.add_argument("--label", default="run")
    r.add_argument("--runs", type=int, default=5)
    r.add_argument("--tools", default=",".join(SCENARIOS), help="comma-separated scenario names")
    r.add_argument("--warm", action="store_true", help="keep the page cache between runs (default: cold)")
    a = ap.parse_args()

    if a.cmd in (None, "versions"):
        print(json.dumps(versions(), indent=2))
        return
    COLD["mode"] = "warm" if a.warm else "cold"
    names = a.tools.split(",")
    for n in names:
        if n not in SCENARIOS:
            sys.exit("unknown scenario %s (have: %s)" % (n, ",".join(SCENARIOS)))
    if a.file and not a.key:
        sys.exit("--file needs at least one --key")
    os.makedirs(DATA, exist_ok=True)
    vers, host = versions(), host_info()
    results = []
    for job in load_jobs(a):
        print("== %s (%s) ==" % (job["id"], a.label), flush=True)
        results.append(bench_title(job, names, a.runs))
    md = summarize(results, a.label, vers, host)
    print(md)
    if os.path.isdir(a.out):
        stamp = time.strftime("%Y%m%d-%H%M%S")
        with open(os.path.join(a.out, "%s-%s.md" % (stamp, a.label)), "w") as f:
            f.write(md)
        with open(os.path.join(a.out, "%s-%s.json" % (stamp, a.label)), "w") as f:
            json.dump({"label": a.label, "cache": COLD, "versions": vers, "host": host, "results": results}, f, indent=1)
    bad = [(x["id"], n) for x in results for n, row in x["rows"].items() if row["fail"] or not row.get("match")]
    if bad:
        print("PROBLEMS: %s" % bad, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
