#!/usr/bin/env python3
"""Collect configuration and outcome metadata from Cuckoo 2.0.x JSON reports.

For each archive folder it prints a summary, and with --csv it also writes one
row per report so the numbers can be joined to the manifest.

Fields collected (missing ones show as <missing>; sanitized reports drop some):
  info.version, info.monitor     Cuckoo build and monitor hash in use
  info.route                     network route
  info.package                   analysis package Cuckoo chose (exe, dll, doc, pdf, ...)
  info.machine.name / .label     which guest ran the sample (-> which host)
  info.started / info.ended      analysis dates and throughput
  info.duration                  total analysis time in seconds
  target.file.type               libmagic file type of the sample
  behavior.processes             number of monitored processes (0 = no captured process)
  signatures                     count of anti-VM / anti-sandbox / anti-debug signatures fired
  debug.errors                   Cuckoo's own error messages (raw reports only)

Usage:
  python3 report_metadata.py ROOT                     # sample 500 per archive
  python3 report_metadata.py ROOT --per 2000
  python3 report_metadata.py ROOT --all --csv out.csv
"""
import argparse
import collections
import csv
import datetime
import gzip
import json
import os
import random
import re
import sys

EVASION_SIG = re.compile(r"^(antivm|antisandbox|antidbg|antiemu|antianalysis)", re.I)


def iter_reports(folder):
    for dirpath, _, files in os.walk(folder):
        for name in files:
            if name.endswith(".json") or name.endswith(".json.gz"):
                yield os.path.join(dirpath, name)


def to_date(v):
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)) or str(v).isdigit():
        return datetime.datetime.fromtimestamp(int(v), datetime.timezone.utc)
    s = str(v)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s[: len(fmt) + 2].split(".")[0], fmt).replace(
                tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
    return None


def extract(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        r = json.load(f)
    info = r.get("info") or {}
    machine = info.get("machine") or {}
    if not isinstance(machine, dict):
        machine = {"name": str(machine)}
    target_file = ((r.get("target") or {}).get("file") or {})
    behavior = r.get("behavior") or {}
    procs = behavior.get("processes") or []
    sigs = r.get("signatures") or []
    sig_names = [s.get("name", "") for s in sigs if isinstance(s, dict)]
    debug = r.get("debug") or {}
    errors = debug.get("errors") or []
    return {
        "file": os.path.basename(path),
        "version": info.get("version", "<missing>"),
        "monitor": info.get("monitor", "<missing>"),
        "route": info.get("route", "<missing>"),
        "package": info.get("package") or "<auto/missing>",
        "machine": machine.get("name") or machine.get("label") or "<missing>",
        "started": to_date(info.get("started")),
        "ended": to_date(info.get("ended")),
        "duration": info.get("duration"),
        "file_type": (target_file.get("type") or "<missing>")[:60],
        "n_processes": len(procs) if isinstance(procs, list) else 0,
        "n_signatures": len(sig_names),
        "evasion_sigs": ";".join(n for n in sig_names if EVASION_SIG.match(n)),
        "errors": " | ".join(str(e)[:120] for e in errors)[:400],
    }


def pct(c, n):
    return ", ".join(f"{k}={v} ({v / max(n, 1):.1%})" for k, v in c.most_common(8))


def summarize(name, rows, bad):
    n = len(rows)
    print(f"\n=== {name}: {n} reports read ({bad} unreadable) ===")
    for field in ("version", "monitor", "route"):
        print(f"  {field}:", pct(collections.Counter(str(r[field]) for r in rows), n))
    machines = collections.Counter(r["machine"] for r in rows)
    print(f"  guests seen: {len(machines)} distinct ->", pct(machines, n))

    dates = sorted(r["started"] for r in rows if r["started"])
    if dates:
        print(f"  analyzed between {dates[0]:%Y-%m-%d} and {dates[-1]:%Y-%m-%d}")

    durs = sorted(int(r["duration"]) for r in rows if isinstance(r["duration"], (int, float)))
    if durs:
        q = lambda p: durs[min(len(durs) - 1, int(p * len(durs)))]
        print(f"  duration s: min={durs[0]} p25={q(.25)} median={q(.5)} p75={q(.75)} max={durs[-1]}")

    noproc = [r for r in rows if r["n_processes"] == 0]
    print(f"  no captured process: {len(noproc)} ({len(noproc) / max(n, 1):.1%})")

    # Outcome by package and by file type: the core of the failure-tail table.
    for field, label in (("package", "package"), ("file_type", "file type")):
        tot = collections.Counter(r[field] for r in rows)
        bad_ = collections.Counter(r[field] for r in noproc)
        print(f"  no-process rate by {label}:")
        for k, v in tot.most_common(8):
            print(f"      {k:<45} {bad_[k]:>5}/{v:<5} ({bad_[k] / v:.0%})")

    ev = [r for r in rows if r["evasion_sigs"]]
    print(f"  reports firing anti-VM/sandbox/debug signatures: {len(ev)} ({len(ev) / max(n, 1):.1%})")
    if ev:
        names = collections.Counter(s for r in ev for s in r["evasion_sigs"].split(";"))
        print("      most common:", pct(names, len(ev)))

    errs = collections.Counter(re.sub(r"\d+", "N", r["errors"])[:100] for r in rows if r["errors"])
    if errs:
        print("  Cuckoo error messages (most common):")
        for k, v in errs.most_common(6):
            print(f"      {v:>5}  {k}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--per", type=int, default=500)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--csv", help="write one row per report to this CSV file")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    a.root = os.path.normpath(a.root.strip().strip('"').strip("'"))
    if not os.path.isdir(a.root):
        sys.exit(f"Not a folder: {a.root!r}")

    random.seed(a.seed)
    subdirs = sorted(d for d in os.listdir(a.root) if os.path.isdir(os.path.join(a.root, d)))
    groups = [(d, os.path.join(a.root, d)) for d in subdirs] or [(os.path.basename(a.root), a.root)]

    writer = None
    if a.csv:
        fh = open(a.csv, "w", newline="", encoding="utf-8")
        writer = csv.writer(fh)
        writer.writerow(["archive", "file", "version", "monitor", "route", "package", "machine",
                         "started", "ended", "duration", "file_type", "n_processes",
                         "n_signatures", "evasion_sigs", "errors"])

    for name, folder in groups:
        paths = list(iter_reports(folder))
        if not paths:
            continue
        if not a.all and len(paths) > a.per:
            paths = random.sample(paths, a.per)
        rows, bad = [], 0
        for p in paths:
            try:
                rows.append(extract(p))
            except Exception:
                bad += 1
        summarize(name, rows, bad)
        if writer:
            for r in rows:
                writer.writerow([name] + [r[k].isoformat() if isinstance(r[k], datetime.datetime) else r[k]
                                          for k in ("file", "version", "monitor", "route", "package",
                                                    "machine", "started", "ended", "duration",
                                                    "file_type", "n_processes", "n_signatures",
                                                    "evasion_sigs", "errors")])
    if writer:
        fh.close()
        print(f"\nWrote {a.csv}")


if __name__ == "__main__":
    sys.exit(main())
