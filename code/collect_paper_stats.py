#!/usr/bin/env python3
"""Collect every corpus statistic the DTRAP paper still needs.

Reads the sanitized (or raw) Cuckoo JSON reports once, caches one CSV row per
report, then prints a summary keyed to the paper's TODO markers.

Covers these TODOs:
  [T1] Table 3 / Sec 5: per-archive totals, successes, failure modes, dates,
       median duration                                   (full counts, not samples)
  [T2] Share of successful reports by archive
  [T3] Mean and median API calls per successful report
  [T4] Environment-probing signature rates over ALL successful reports
  [T5] Successful AND labeled count; count in classes with >= 500 samples
       (compare to the baseline's 185,732)                (needs --labels)
  [T6] Sample-age proxy: PE compile timestamps, if present in the reports
  [T7] Archive list and duplicate-archive check (identical hash sets)

USAGE
  # Quick trial on 2,000 reports per archive:
  python collect_paper_stats.py D:\\reports --per 2000

  # Full run (resumable: finished archives are cached in --out):
  python collect_paper_stats.py D:\\reports --workers 12 --out stats_out

  # Add labels (any CSV or JSONL with an md5 or sha256 column and a label column):
  python collect_paper_stats.py D:\\reports --out stats_out --labels manifest.csv --label-col maldict_label

  # Re-print the summary from the cache without re-reading reports:
  python collect_paper_stats.py D:\\reports --out stats_out --summary-only --labels manifest.csv

ROOT should contain one folder per archive (e.g. reports_VirusShare_00000).
Reports may be .json or .json.gz. Success criterion defaults match the paper:
parses, >=1 process, >=1 API call, >=4 distinct API functions. Check that the
reported success total matches 714,252; if not, adjust --min-calls/--min-unique.
"""
import argparse
import collections
import csv
import datetime as dt
import gzip
import json
import os
import re
import statistics
import sys
from concurrent.futures import ProcessPoolExecutor

HEX32 = re.compile(r"[0-9a-fA-F]{32}")
PROBE = re.compile(r"^(antivm|antisandbox|antidbg|antiemu|antianalysis)", re.I)
FIELDS = ["archive", "file", "md5", "sha256", "outcome", "n_processes", "n_calls",
          "n_unique", "started", "duration", "machine", "file_type", "pe_timestamp",
          "probe_sigs", "bytes"]


# --------------------------------------------------------------------------- scanning
def iter_reports(folder):
    for dirpath, _, files in os.walk(folder):
        for name in files:
            if name.endswith(".json") or name.endswith(".json.gz"):
                yield os.path.join(dirpath, name)


def to_iso(v):
    if v in (None, ""):
        return ""
    try:
        if isinstance(v, (int, float)) or str(v).isdigit():
            return dt.datetime.fromtimestamp(int(v), dt.timezone.utc).strftime("%Y-%m-%d")
        return str(v)[:10]
    except (ValueError, OSError, OverflowError):
        return ""


def count_calls(behavior):
    """Return (n_calls, n_unique) from apistats if present, else from call lists."""
    apistats = behavior.get("apistats") or {}
    totals = collections.Counter()
    if isinstance(apistats, dict) and apistats:
        for per_proc in apistats.values():
            if isinstance(per_proc, dict):
                for api, n in per_proc.items():
                    try:
                        totals[api] += int(n)
                    except (TypeError, ValueError):
                        pass
    else:
        for proc in behavior.get("processes") or []:
            for call in (proc.get("calls") or []) if isinstance(proc, dict) else []:
                api = call.get("api") if isinstance(call, dict) else None
                if api:
                    totals[api] += 1
    return sum(totals.values()), len(totals)


def scan_one(args):
    path, archive, min_calls, min_unique, max_bytes = args
    name = os.path.basename(path)
    m = HEX32.search(name)
    row = dict.fromkeys(FIELDS, "")
    row.update(archive=archive, file=name, md5=(m.group(0).lower() if m else ""))
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    row["bytes"] = size
    if size == 0:
        row["outcome"] = "parse_fail_empty"
        return row
    if max_bytes and size > max_bytes:
        row["outcome"] = "skipped_oversize"
        return row
    try:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            r = json.load(f)
        if not isinstance(r, dict):
            raise ValueError("not an object")
    except Exception:
        row["outcome"] = "parse_fail_invalid"
        return row

    info = r.get("info") or {}
    target = (r.get("target") or {}).get("file") or {}
    behavior = r.get("behavior") or {}
    procs = behavior.get("processes") or []
    machine = info.get("machine") or {}
    static = r.get("static") or {}
    n_calls, n_unique = count_calls(behavior)
    sigs = [s.get("name", "") for s in (r.get("signatures") or []) if isinstance(s, dict)]

    row.update(
        md5=(target.get("md5") or row["md5"] or "").lower(),
        sha256=(target.get("sha256") or "").lower(),
        n_processes=len(procs) if isinstance(procs, list) else 0,
        n_calls=n_calls,
        n_unique=n_unique,
        started=to_iso(info.get("started")),
        duration=info.get("duration", ""),
        machine=(machine.get("name") if isinstance(machine, dict) else machine) or "",
        file_type=(target.get("type") or "")[:80],
        pe_timestamp=to_iso(static.get("pe_timestamp")) if static.get("pe_timestamp") else "",
        probe_sigs=";".join(s for s in sigs if PROBE.match(s)),
    )
    if row["n_processes"] == 0:
        row["outcome"] = "no_process"
    elif n_calls < min_calls:
        row["outcome"] = "too_few_calls"
    elif n_unique < min_unique:
        row["outcome"] = "too_few_unique"
    else:
        row["outcome"] = "success"
    return row


def scan_archive(name, folder, out_csv, a):
    paths = list(iter_reports(folder))
    if a.per and len(paths) > a.per:
        import random
        random.seed(0)
        paths = random.sample(paths, a.per)
    jobs = [(p, name, a.min_calls, a.min_unique, a.max_bytes) for p in paths]
    tmp = out_csv + ".partial"
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        done = 0
        with ProcessPoolExecutor(max_workers=a.workers) as ex:
            for row in ex.map(scan_one, jobs, chunksize=64):
                w.writerow(row)
                done += 1
                if done % 20000 == 0:
                    print(f"    {name}: {done:,}/{len(jobs):,}", flush=True)
    os.replace(tmp, out_csv)
    print(f"  {name}: {len(jobs):,} reports scanned", flush=True)


# --------------------------------------------------------------------------- summary
def load_rows(out_dir):
    rows = []
    for fn in sorted(os.listdir(out_dir)):
        if fn.endswith(".csv") and fn.startswith("scan_"):
            with open(os.path.join(out_dir, fn), newline="", encoding="utf-8") as fh:
                rows.extend(csv.DictReader(fh))
    return rows


def load_labels(path, hash_col, label_col):
    labels = {}
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.lstrip().startswith("{"):
            records = (json.loads(line) for line in fh if line.strip())
        else:
            records = csv.DictReader(fh)
        for rec in records:
            keys = {k.lower(): k for k in rec}
            hc = hash_col or next((keys[k] for k in ("md5", "sha256") if k in keys), None)
            lc = label_col or next((keys[k] for k in ("label", "maldict_label", "behavior", "tags", "type")
                                    if k in keys), None)
            if not hc or not lc:
                sys.exit(f"Could not find hash/label columns in {path}; columns are {list(rec)}. "
                         "Use --hash-col and --label-col.")
            h, lab = str(rec.get(hc) or "").lower(), rec.get(lc)
            if isinstance(lab, list):
                lab = lab[0] if lab else ""
            if h and lab not in (None, "", "nan"):
                labels[h] = str(lab)
    return labels


def pct(a, b):
    return f"{a / b:.1%}" if b else "n/a"


def summarize(rows, a):
    out = []
    p = out.append
    if not rows:
        sys.exit("No scanned rows found.")
    archives = sorted({r["archive"] for r in rows})
    succ = [r for r in rows if r["outcome"] == "success"]
    sample_note = f" (SAMPLED: up to {a.per} per archive)" if a.per else ""

    p(f"=== CORPUS TOTALS{sample_note} ===")
    oc = collections.Counter(r["outcome"] for r in rows)
    parsed = len(rows) - oc["parse_fail_empty"] - oc["parse_fail_invalid"] - oc["skipped_oversize"]
    p(f"  reports            {len(rows):,}")
    p(f"  parsed             {parsed:,}")
    p(f"  parse failures     {oc['parse_fail_empty'] + oc['parse_fail_invalid']:,} "
      f"(empty {oc['parse_fail_empty']:,}, invalid {oc['parse_fail_invalid']:,})")
    if oc["skipped_oversize"]:
        p(f"  SKIPPED oversize   {oc['skipped_oversize']:,}  <- rerun without --max-bytes for exact totals")
    p(f"  success            {oc['success']:,} ({pct(oc['success'], parsed)} of parsed)   paper: 714,252")
    p(f"  no process         {oc['no_process']:,} ({pct(oc['no_process'], parsed)})")
    p(f"  too few calls      {oc['too_few_calls']:,}")
    p(f"  too few unique     {oc['too_few_unique']:,}")

    p("\n=== [T1][T2] PER ARCHIVE (Table 3) ===")
    p(f"  {'archive':<26}{'reports':>9}{'success':>9}{'no proc':>9}{'%noproc':>8}"
      f"{'med dur':>8}{'%succ share':>12}  analyzed")
    for arc in archives:
        rs = [r for r in rows if r["archive"] == arc]
        o = collections.Counter(r["outcome"] for r in rs)
        par = len(rs) - o["parse_fail_empty"] - o["parse_fail_invalid"] - o["skipped_oversize"]
        durs = [float(r["duration"]) for r in rs if r["duration"] not in ("", None)]
        dates = sorted(r["started"] for r in rs if r["started"])
        span = f"{dates[0]} to {dates[-1]}" if dates else "n/a"
        p(f"  {arc:<26}{len(rs):>9,}{o['success']:>9,}{o['no_process']:>9,}"
          f"{pct(o['no_process'], par):>8}{(statistics.median(durs) if durs else 0):>8.0f}"
          f"{pct(o['success'], len(succ)):>12}  {span}")

    p("\n=== [T3] API CALLS PER SUCCESSFUL REPORT ===")
    calls = sorted(int(r["n_calls"]) for r in succ if r["n_calls"] not in ("", None))
    if calls:
        p(f"  mean {statistics.mean(calls):,.0f}   median {statistics.median(calls):,.0f}   "
          f"p10 {calls[len(calls) // 10]:,}   p90 {calls[9 * len(calls) // 10]:,}   max {calls[-1]:,}")
        uniq = {int(r["n_unique"]) for r in succ if r["n_unique"]}
        p(f"  max distinct APIs in one report: {max(uniq) if uniq else 'n/a'}")
    durs = [float(r["duration"]) for r in succ if r["duration"] not in ("", None)]
    if durs:
        p(f"  median analysis duration (successful): {statistics.median(durs):.0f} s")

    p("\n=== [T4] ENVIRONMENT PROBING OVER ALL SUCCESSFUL REPORTS ===")
    n = len(succ)
    anyp = sum(1 for r in succ if r["probe_sigs"])
    fam = collections.Counter()
    names = collections.Counter()
    for r in succ:
        sigs = [s for s in r["probe_sigs"].split(";") if s]
        for f_ in {s.split("_")[0].lower() for s in sigs}:
            fam[f_] += 1
        names.update(set(sigs))
    p(f"  any probing signature: {anyp:,} / {n:,} ({pct(anyp, n)})")
    for f_ in ("antivm", "antisandbox", "antidbg"):
        p(f"  {f_:<12} {fam[f_]:>9,} ({pct(fam[f_], n)})")
    p("  most common:")
    for k, v in names.most_common(10):
        p(f"    {k:<36} {v:>9,} ({pct(v, n)})")
    if n and anyp == 0:
        p("  NOTE: no probing signatures found. If the sanitizer dropped 'signatures', "
          "these numbers must come from the raw reports.")

    if a.labels:
        p("\n=== [T5] LABELS ===")
        labels = load_labels(a.labels, a.hash_col, a.label_col)
        def lab(r):
            return labels.get(r["md5"]) or labels.get(r["sha256"])
        all_lab = [r for r in rows if lab(r)]
        succ_lab = [r for r in succ if lab(r)]
        p(f"  label file entries          {len(labels):,}")
        p(f"  reports with a label        {len(all_lab):,}   paper: 246,776")
        p(f"  successful AND labeled      {len(succ_lab):,}   <- fills the '\\todo{{n}}' cells")
        dedup = {}
        for r in succ_lab:
            dedup.setdefault(r["sha256"] or r["md5"], lab(r))
        cls = collections.Counter(dedup.values())
        big = {c for c, k in cls.items() if k >= 500}
        n_big = sum(k for c, k in cls.items() if c in big)
        p(f"  successful+labeled, unique hashes: {len(dedup):,}; classes: {len(cls)}")
        p(f"  in classes with >=500 samples: {n_big:,} across {len(big)} classes "
          f"(baseline used 185,732 across 41)")
        if not a.per and n_big < 185732 * 0.95:
            p("  -> The baseline count is larger: it likely included non-successful reports. "
              "Re-run the baseline on successful reports only.")
        p("  successful+labeled by archive:")
        by_arc = collections.Counter(r["archive"] for r in succ_lab)
        for arc in archives:
            p(f"    {arc:<26}{by_arc[arc]:>9,}")

    p("\n=== [T6] SAMPLE AGE PROXY (PE compile timestamps; can be forged) ===")
    years = collections.Counter(r["pe_timestamp"][:4] for r in rows if r["pe_timestamp"][:4].isdigit())
    plaus = sorted(y for y in years.elements() if "1995" <= y <= "2026")
    if plaus:
        p(f"  reports with a timestamp: {sum(years.values()):,}; plausible (1995-2026): {len(plaus):,}")
        p(f"  5th pct {plaus[len(plaus) // 20]}, median {plaus[len(plaus) // 2]}, "
          f"95th pct {plaus[19 * len(plaus) // 20]}")
        for arc in archives:
            ys = sorted(r["pe_timestamp"][:4] for r in rows if r["archive"] == arc
                        and "1995" <= r["pe_timestamp"][:4] <= "2026")
            if ys:
                p(f"    {arc:<26} median {ys[len(ys) // 2]}  (n={len(ys):,})")
    else:
        p("  No PE timestamps in these reports (the sanitizer may drop static.pe_timestamp).")
        p("  Use MalDICT or VirusTotal first-seen dates instead, or run this on raw reports.")

    p("\n=== [T7] ARCHIVES AND DUPLICATES ===")
    sets = {arc: {r["md5"] for r in rows if r["archive"] == arc and r["md5"]} for arc in archives}
    for arc in archives:
        p(f"  {arc:<26} {len(sets[arc]):,} distinct MD5s")
    for i, x in enumerate(archives):
        for y in archives[i + 1:]:
            if sets[x] and sets[y]:
                ov = len(sets[x] & sets[y]) / min(len(sets[x]), len(sets[y]))
                if ov > 0.5:
                    p(f"  OVERLAP: {x} and {y} share {ov:.1%} of hashes")
    if a.per:
        p("  (Duplicate detection is unreliable on a sample; run the full scan.)")
    return "\n".join(out)


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--out", default="stats_out", help="cache and output folder")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--per", type=int, default=0, help="sample N reports per archive (0 = all)")
    ap.add_argument("--min-calls", type=int, default=1)
    ap.add_argument("--min-unique", type=int, default=4)
    ap.add_argument("--max-bytes", type=int, default=0, help="skip reports larger than this (0 = no limit)")
    ap.add_argument("--labels", help="CSV or JSONL with hash and label columns")
    ap.add_argument("--hash-col")
    ap.add_argument("--label-col")
    ap.add_argument("--summary-only", action="store_true")
    a = ap.parse_args()
    a.root = os.path.normpath(a.root.strip().strip('"').strip("'"))
    os.makedirs(a.out, exist_ok=True)

    if not a.summary_only:
        if not os.path.isdir(a.root):
            sys.exit(f"Not a folder: {a.root!r}")
        subdirs = sorted(d for d in os.listdir(a.root) if os.path.isdir(os.path.join(a.root, d)))
        groups = [(d, os.path.join(a.root, d)) for d in subdirs] or [(os.path.basename(a.root), a.root)]
        tag = f"_per{a.per}" if a.per else ""
        print(f"Scanning {len(groups)} archive folder(s) with {a.workers} workers")
        for name, folder in groups:
            out_csv = os.path.join(a.out, f"scan_{name}{tag}.csv")
            if os.path.exists(out_csv):
                print(f"  {name}: cached, skipping")
                continue
            scan_archive(name, folder, out_csv, a)

    rows = load_rows(a.out)  # use separate --out folders for sampled and full scans
    text = summarize(rows, a)
    print("\n" + text)
    with open(os.path.join(a.out, "summary.txt"), "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    print(f"\nSaved {os.path.join(a.out, 'summary.txt')}")


if __name__ == "__main__":
    main()
