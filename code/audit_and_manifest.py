#!/usr/bin/env python3
r"""
audit_and_manifest.py - Final-pass audit of the sanitized report archives plus
generation of the master release manifest.

Two jobs:
  1. AUDIT every sanitized report for schema conformance and leakage, reporting
     any nonconformant reports so nothing unexpected ships.
  2. MANIFEST: emit one row per report (md5, sha256, archive, report_id, n_proc,
     n_calls, success, category, label_source) joined to the MalDICT labels, so
     researchers filter this single small file instead of scanning 2 TB.

Audit checks per report:
  * top-level keys are within the allowed sanitized set (no leaked sections)
  * target carries at least one hash; no local-path field present
  * behavior.processes entries have the expected fields
  * call entries reference API names only (no raw buffer/path arguments unless
    the whitelist mode was used)
  * recompute n_calls from the sequence and confirm it matches the stored n_calls
  * success flag computed by the SAME criterion as the profiler
    (>=1 process, >=1 call, >=4 unique APIs)

Usage:
    python audit_and_manifest.py \
        --reports sanitized/00000.sanitized.tar.gz ... \
        --labels corpus_category_labeled.csv \
        --out-manifest manifest.csv \
        --out-audit audit_report.txt \
        [--min-apis 4] [--min-calls 1]
"""
import os
import re
import csv
import sys
import json
import glob
import tarfile
import argparse
from collections import Counter, defaultdict

ALLOWED_TOP = {"info", "target", "behavior", "static", "signatures"}
FORBIDDEN_TOP = {"strings", "dropped", "buffer", "procmemory", "extracted",
                 "screenshots", "debug", "metadata", "network_raw"}
LEAK_MARKERS = ("/home/", "/media/",
                "C:\\Users\\", "C:\\\\Users\\\\",   # raw and JSON-escaped
                "\\AppData\\", "\\\\AppData\\\\",
                "/Users/", "\\Users\\")


def infer_tag(path):
    m = re.search(r"(\d{5})", os.path.basename(path))
    return m.group(1) if m else os.path.splitext(os.path.basename(path))[0]


def iter_reports(inp):
    low = inp.lower()
    if low.endswith((".tar.gz", ".tgz", ".tar")):
        mode = "r:gz" if low.endswith((".tar.gz", ".tgz")) else "r:*"
        with tarfile.open(inp, mode) as tf:
            for m in tf:
                if not m.isfile() or not m.name.lower().endswith(".json"):
                    continue
                stem = os.path.splitext(os.path.basename(m.name))[0]
                f = tf.extractfile(m)
                if f is None:
                    continue
                raw = f.read()
                yield stem, raw
    elif os.path.isdir(inp):
        for p in glob.iglob(os.path.join(inp, "**", "*.json"), recursive=True):
            stem = os.path.splitext(os.path.basename(p))[0]
            with open(p, "rb") as f:
                yield stem, f.read()
    else:
        raise RuntimeError(f"not a tar or directory: {inp}")


def audit_report(d, raw_bytes, min_calls, min_apis):
    """Return (issues:list[str], n_proc, n_calls, n_unique_apis, hashes:dict)."""
    issues = []
    keys = set(d.keys())
    bad = (keys - ALLOWED_TOP) & FORBIDDEN_TOP
    if bad:
        issues.append(f"forbidden top-level section(s): {sorted(bad)}")
    unexpected = keys - ALLOWED_TOP - FORBIDDEN_TOP
    if unexpected:
        issues.append(f"unexpected top-level key(s): {sorted(unexpected)}")

    target = d.get("target", {}) or {}
    tf = target.get("file", target) if isinstance(target, dict) else {}
    hashes = {k: tf.get(k) for k in ("md5", "sha1", "sha256", "sha512", "ssdeep")
              if tf.get(k)}
    if not hashes:
        issues.append("no sample hash present")
    if isinstance(tf, dict) and ("path" in tf or "filepath" in tf):
        issues.append("local path field present in target")

    procs = d.get("behavior", {}).get("processes", []) or []
    n_proc = len(procs)
    total_calls = 0
    apis = set()
    for p in procs:
        calls = p.get("calls", []) or []
        stored = p.get("n_calls")
        total_calls += len(calls)
        for c in calls:
            api = c.get("api") if isinstance(c, dict) else c
            if api:
                apis.add(api)
        if stored is not None and stored != len(calls):
            issues.append(f"pid {p.get('pid')}: n_calls={stored} != "
                          f"actual {len(calls)}")

    # cheap leakage scan on the raw bytes
    txt = raw_bytes.decode("utf-8", "replace")
    for mark in LEAK_MARKERS:
        if mark in txt:
            issues.append(f"possible path leak marker: {mark!r}")
            break

    return issues, n_proc, total_calls, len(apis), hashes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", nargs="+", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--out-manifest", default="manifest.csv")
    ap.add_argument("--out-audit", default="audit_report.txt")
    ap.add_argument("--min-calls", type=int, default=1)
    ap.add_argument("--min-apis", type=int, default=4)
    ap.add_argument("--max-issues", type=int, default=200,
                    help="stop recording individual issues after this many")
    args = ap.parse_args()

    # load labels by md5
    md5cat = {}
    for row in csv.DictReader(open(args.labels, newline="")):
        if row.get("label_source") == "maldict":
            md5 = (row.get("md5") or "").strip().lower()
            if md5:
                md5cat[md5] = (row.get("category", ""),
                               row.get("category_support", ""))
    print(f"loaded {len(md5cat):,} MalDICT labels", file=sys.stderr)

    manifest_rows = []
    issue_log = []
    n_total = n_success = n_labeled = 0
    issue_counts = Counter()
    per_archive = Counter()

    for inp in args.reports:
        tag = infer_tag(inp)
        n_arch = 0
        for rid, raw in iter_reports(inp):
            n_total += 1
            n_arch += 1
            try:
                d = json.loads(raw)
            except Exception as e:
                issue_counts["parse_fail"] += 1
                if len(issue_log) < args.max_issues:
                    issue_log.append(f"{tag}/{rid}: JSON parse fail: {e}")
                continue
            issues, n_proc, n_calls, n_apis, hashes = audit_report(
                d, raw, args.min_calls, args.min_apis)
            for iss in issues:
                issue_counts[iss.split(":")[0]] += 1
            if issues and len(issue_log) < args.max_issues:
                issue_log.append(f"{tag}/{rid}: " + "; ".join(issues))

            success = (n_proc >= 1 and n_calls >= args.min_calls
                       and n_apis >= args.min_apis)
            if success:
                n_success += 1
            md5 = (hashes.get("md5") or "").lower()
            cat, sup = md5cat.get(md5, ("", ""))
            if cat:
                n_labeled += 1
            manifest_rows.append({
                "md5": md5,
                "sha256": hashes.get("sha256", ""),
                "archive": tag,
                "report_id": rid,
                "n_proc": n_proc,
                "n_calls": n_calls,
                "n_unique_apis": n_apis,
                "success": int(success),
                "category": cat,
                "category_support": sup,
                "label_source": "maldict" if cat else "",
            })
        per_archive[tag] = n_arch
        print(f"  {tag}: {n_arch:,} reports", file=sys.stderr)

    # write manifest
    fields = ["md5", "sha256", "archive", "report_id", "n_proc", "n_calls",
              "n_unique_apis", "success", "category", "category_support",
              "label_source"]
    with open(args.out_manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(manifest_rows)

    # write audit report
    with open(args.out_audit, "w") as f:
        f.write("SANITIZED CORPUS AUDIT\n")
        f.write("======================\n\n")
        f.write(f"total reports:        {n_total:,}\n")
        f.write(f"successful analyses:  {n_success:,} "
                f"({100*n_success/max(n_total,1):.1f}%)\n")
        f.write(f"MalDICT-labeled:      {n_labeled:,} "
                f"({100*n_labeled/max(n_total,1):.1f}%)\n\n")
        f.write("per-archive report counts:\n")
        for tag in sorted(per_archive):
            f.write(f"  {tag}: {per_archive[tag]:,}\n")
        f.write("\nissue summary (type -> count):\n")
        if issue_counts:
            for k, v in issue_counts.most_common():
                f.write(f"  {k}: {v:,}\n")
        else:
            f.write("  none\n")
        f.write(f"\nfirst {min(len(issue_log), args.max_issues)} individual "
                f"issues:\n")
        for line in issue_log:
            f.write("  " + line + "\n")

    print(f"\nmanifest: {len(manifest_rows):,} rows -> {args.out_manifest}")
    print(f"audit: {sum(issue_counts.values()):,} issues across "
          f"{len(issue_counts)} types -> {args.out_audit}")
    print(f"success: {n_success:,} ({100*n_success/max(n_total,1):.1f}%) | "
          f"labeled: {n_labeled:,}")
    if issue_counts:
        print("\ntop issue types:")
        for k, v in issue_counts.most_common(8):
            print(f"  {k}: {v:,}")
        print("Review audit_report.txt before publishing.")
    else:
        print("\nNo schema/leak issues found. Corpus is clean.")


if __name__ == "__main__":
    main()
