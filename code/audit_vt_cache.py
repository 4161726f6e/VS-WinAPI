#!/usr/bin/env python3
r"""
audit_vt_cache.py - Inspect a VirusTotal cache directory and report how many
cached files are REAL reports vs error stubs (404 / quota / auth errors), and
optionally delete the error stubs so they can be re-queried.

Why: the free VT tier allows ~500 lookups/day. A large run will hit the cap and
cache the remaining responses as small error stubs. Those stubs must be cleared
(not treated as done) so a later run re-fetches them. This tool distinguishes
real reports (have last_analysis_results) from stubs without re-querying.

Usage:
    python audit_vt_cache.py vt_cache                 # report only
    python audit_vt_cache.py vt_cache --delete-stubs  # remove error stubs
    python audit_vt_cache.py vt_cache --list-errors    # show error-code tally
"""
import os
import sys
import json
import glob
import argparse
from collections import Counter


def classify(path):
    """Return ('real'|'stub'|'unreadable', detail)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return "unreadable", str(e)[:40]
    if not isinstance(data, dict):
        return "stub", "non-dict"
    if "_http_error" in data:
        return "stub", f"http_{data['_http_error']}"
    if "_error" in data:
        return "stub", "neterr"
    attrs = (data.get("data", {}) or {}).get("attributes", {})
    if attrs.get("last_analysis_results"):
        return "real", ""
    # has data but no analysis results - treat as stub (e.g. 'error' object)
    if "error" in data:
        err = data.get("error", {})
        return "stub", str(err.get("code", "error"))[:30]
    return "stub", "no_analysis"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cache")
    ap.add_argument("--delete-stubs", action="store_true")
    ap.add_argument("--list-errors", action="store_true")
    args = ap.parse_args()

    files = glob.glob(os.path.join(args.cache, "*.json"))
    real = stubs = unreadable = 0
    detail_counts = Counter()
    stub_paths = []

    for p in files:
        kind, detail = classify(p)
        if kind == "real":
            real += 1
        elif kind == "unreadable":
            unreadable += 1
            detail_counts[f"unreadable:{detail}"] += 1
            stub_paths.append(p)
        else:
            stubs += 1
            detail_counts[detail] += 1
            stub_paths.append(p)

    print(f"cache: {args.cache}")
    print(f"  total files:  {len(files)}")
    print(f"  real reports: {real}")
    print(f"  error stubs:  {stubs}")
    if unreadable:
        print(f"  unreadable:   {unreadable}")

    if args.list_errors and detail_counts:
        print("\n  stub breakdown:")
        for d, c in detail_counts.most_common():
            print(f"    {d}: {c}")

    if args.delete_stubs and stub_paths:
        for p in stub_paths:
            try:
                os.remove(p)
            except OSError:
                pass
        print(f"\n  deleted {len(stub_paths)} stub/unreadable files; "
              f"re-run label_corpus.py to re-fetch them.")
    elif stubs and not args.delete_stubs:
        print(f"\n  re-run with --delete-stubs to clear {stubs} stubs for retry.")


if __name__ == "__main__":
    main()
