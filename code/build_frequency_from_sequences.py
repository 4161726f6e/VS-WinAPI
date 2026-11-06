#!/usr/bin/env python3
r"""
build_frequency_from_sequences.py - Regenerate per-archive API-frequency matrices
directly from the sanitized reports' ordered call sequences.

Why: the original freq_*.csv files were produced by a separate, earlier process
that (for some archives built under a different sandbox build) emitted truncated
and duplicated column headers. The sanitized reports themselves store clean,
canonical API names in each process's `calls` sequence. Deriving the frequency
table from those sequences yields a matrix that is (a) canonical and
single-column-per-API, and (b) provably consistent with the released sequences,
since it is a direct count over them.

For each report, the per-API frequency is the number of times each API name
appears across all of the report's processes (summed), matching the semantics of
the original apistats table. Output is one CSV per archive:
    report_id, <api_1>, <api_2>, ...
with a column per API in the union vocabulary (missing -> 0).

Input: the sanitized tar.gz archives (each containing <report_id>.json), or a
directory of such JSON files.

Usage:
    python build_frequency_from_sequences.py \
        --in sanitized/00000.sanitized.tar.gz ... \
        --outdir freq_clean [--min-report-id-from-name]

Two passes: pass 1 collects the API vocabulary (union of all names seen); pass 2
writes each archive's matrix with the shared column order. This keeps a single
consistent schema across archives while remaining memory-light (one report at a
time).
"""
import os
import re
import csv
import sys
import json
import glob
import tarfile
import argparse
from collections import Counter


def infer_tag(path):
    m = re.search(r"(\d{5})", os.path.basename(path))
    return m.group(1) if m else os.path.splitext(os.path.basename(path))[0]


def iter_reports(inp):
    """Yield (report_id, parsed_json) for each .json report in a tar.gz or dir.
    report_id is the filename stem."""
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
                try:
                    yield stem, json.load(f)
                except Exception:
                    continue
    elif os.path.isdir(inp):
        for p in glob.iglob(os.path.join(inp, "**", "*.json"), recursive=True):
            stem = os.path.splitext(os.path.basename(p))[0]
            try:
                with open(p, encoding="utf-8") as f:
                    yield stem, json.load(f)
            except Exception:
                continue
    else:
        raise RuntimeError(f"not a tar archive or directory: {inp}")


def report_api_counts(d):
    """Return Counter of API name -> total invocations across all processes,
    computed from the ordered call sequences."""
    c = Counter()
    for p in d.get("behavior", {}).get("processes", []):
        for call in p.get("calls", []):
            if isinstance(call, dict):
                api = call.get("api")
            else:
                api = call
            if api:
                c[api] += 1
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inputs", nargs="+", required=True)
    ap.add_argument("--outdir", default="freq_clean")
    ap.add_argument("--vocab-out", default="api_vocabulary.txt")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    # Pass 1: build the union API vocabulary
    print("pass 1: collecting API vocabulary...", file=sys.stderr)
    vocab = set()
    per_archive_reports = {}
    for inp in args.inputs:
        tag = infer_tag(inp)
        n = 0
        for rid, d in iter_reports(inp):
            counts = report_api_counts(d)
            if counts:
                vocab.update(counts.keys())
            n += 1
        per_archive_reports[tag] = inp
        print(f"  {tag}: scanned {n:,} reports", file=sys.stderr)
    vocab = sorted(vocab)
    with open(args.vocab_out, "w") as f:
        f.write("\n".join(vocab) + "\n")
    print(f"vocabulary: {len(vocab)} distinct API functions -> {args.vocab_out}",
          file=sys.stderr)

    # Pass 2: write each archive's matrix with shared column order
    col_index = {a: i for i, a in enumerate(vocab)}
    print("pass 2: writing frequency matrices...", file=sys.stderr)
    for tag, inp in per_archive_reports.items():
        outp = os.path.join(args.outdir, f"freq_{tag}.csv")
        n = 0
        with open(outp, "w", newline="") as of:
            w = csv.writer(of)
            w.writerow(["report_id"] + vocab)
            for rid, d in iter_reports(inp):
                counts = report_api_counts(d)
                row = [0] * len(vocab)
                for api, k in counts.items():
                    idx = col_index.get(api)
                    if idx is not None:
                        row[idx] = k
                w.writerow([rid] + row)
                n += 1
        print(f"  wrote {outp} ({n:,} rows, {len(vocab)} cols)", file=sys.stderr)

    print("\nDone. All archives share one canonical column schema derived from "
          "the released call sequences; frequencies are provably consistent with "
          "the sequences.")


if __name__ == "__main__":
    main()
