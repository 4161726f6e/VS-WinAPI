#!/usr/bin/env python3
r"""
join_claravy_labels.py - Attach malware family/type labels to the corpus by MD5,
using the precomputed ClarAVy label files for VirusShare archives (redistributed
via VX Underground), with NO VirusTotal queries.

Background
----------
ClarAVy publishes per-archive label files covering VirusShare 00000-00465. Each
line corresponds to one sample and contains its MD5 followed by space-separated
tags. Tags are typed and carry an AV-engine support count after a '|', e.g.:

    <md5> FILE:vbs|10 BEH:adware|6,BEH:downloader|6,PACK:nsis|1 SINGLETON:<md5>
    <md5> 53
    <md5> FAM:zbot|34 CLASS:grayware|12

The exact tag vocabulary varies by ClarAVy version. This tool is deliberately
tolerant: it parses any `PREFIX:value|count` or `PREFIX:value` token, and also
bare-integer lines, and extracts:
  * family       - the highest-support FAM:/FAMILY: tag (or AVClass-style token)
  * is_singleton - whether the sample is a ClarAVy SINGLETON (generic-only)
  * top_tags     - the full tag string (kept verbatim for transparency)

It then joins these to your corpus mapping(s) by MD5 and writes one labeled CSV.

Usage
-----
    python join_claravy_labels.py \
        --labels VirusShare_00000_labels.txt VirusShare_00001_labels.txt ... \
        --mapping mapping_00000.csv mapping_00001.csv ... \
        --out corpus_labeled.csv

You may pass --labels-dir DIR to glob all *_labels.txt in a directory instead.
Mappings may be the per-archive files or a single merged mapping; join is by md5.

Output columns:
    md5,archive,report_id,family,is_singleton,label_source,raw_tags
Samples present in the corpus but absent from the label files get an empty
family and label_source=unlabeled (recorded, not dropped).
"""
import os
import re
import csv
import sys
import glob
import argparse

FAM_RE = re.compile(r"^(?:FAM|FAMILY|AVCLASS)$", re.IGNORECASE)
TOKEN_RE = re.compile(r"^([A-Za-z_]+):(.+)$")


def parse_label_line(line):
    """Return (md5, family, is_singleton, raw_tags) or None."""
    line = line.strip()
    if not line:
        return None
    parts = line.split()
    md5 = parts[0].lower()
    if not re.fullmatch(r"[0-9a-f]{32}", md5):
        return None
    raw_tags = " ".join(parts[1:])
    family = ""
    best_support = -1
    is_singleton = 0

    # tags may be space- or comma-separated; flatten both
    flat = []
    for chunk in parts[1:]:
        flat.extend(chunk.split(","))

    for tok in flat:
        tok = tok.strip()
        if not tok:
            continue
        if tok.upper().startswith("SINGLETON"):
            is_singleton = 1
            continue
        m = TOKEN_RE.match(tok)
        if not m:
            continue
        prefix, value = m.group(1), m.group(2)
        # split optional |count support
        support = 0
        if "|" in value:
            value, _, cnt = value.partition("|")
            try:
                support = int(cnt)
            except ValueError:
                support = 0
        if FAM_RE.match(prefix):
            if support >= best_support:
                best_support = support
                family = value.lower()

    return md5, family, is_singleton, raw_tags


def load_labels(label_paths):
    table = {}
    n_lines = 0
    for p in label_paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                rec = parse_label_line(line)
                if rec:
                    md5, family, singleton, raw = rec
                    table[md5] = (family, singleton, raw)
                    n_lines += 1
    return table, n_lines


def iter_mapping_rows(mapping_paths):
    for p in mapping_paths:
        with open(p, newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                yield row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", nargs="*", default=[],
                    help="ClarAVy *_labels.txt files")
    ap.add_argument("--labels-dir", default=None,
                    help="directory to glob *_labels.txt from")
    ap.add_argument("--mapping", nargs="+", required=True,
                    help="corpus mapping CSV(s) with an md5 column")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    label_paths = list(args.labels)
    if args.labels_dir:
        label_paths += glob.glob(os.path.join(args.labels_dir, "*_labels.txt"))
    if not label_paths:
        sys.exit("ERROR: provide --labels and/or --labels-dir")

    print(f"loading {len(label_paths)} label file(s)...", file=sys.stderr)
    table, n_lines = load_labels(label_paths)
    print(f"  parsed {len(table)} unique md5 labels from {n_lines} lines",
          file=sys.stderr)

    n = n_labeled = n_singleton = n_unlabeled = n_nohash = 0
    fam_counts = {}

    with open(args.out, "w", newline="") as out:
        w = csv.writer(out)
        w.writerow(["md5", "archive", "report_id", "family", "is_singleton",
                    "label_source", "raw_tags"])
        for row in iter_mapping_rows(args.mapping):
            n += 1
            md5 = (row.get("md5") or "").strip().lower()
            archive = row.get("archive", "")
            rid = row.get("report_id", "")
            if not md5:
                n_nohash += 1
                w.writerow(["", archive, rid, "", "", "no_hash", ""])
                continue
            hit = table.get(md5)
            if hit is None:
                n_unlabeled += 1
                w.writerow([md5, archive, rid, "", "", "unlabeled", ""])
                continue
            family, singleton, raw = hit
            if singleton:
                n_singleton += 1
            if family:
                n_labeled += 1
                fam_counts[family] = fam_counts.get(family, 0) + 1
            w.writerow([md5, archive, rid, family, singleton,
                        "claravy", raw])

    print(f"\nrows processed: {n}")
    print(f"  with family label: {n_labeled}")
    print(f"  singleton (generic-only): {n_singleton}")
    print(f"  unlabeled (not in label set): {n_unlabeled}")
    print(f"  no hash in mapping: {n_nohash}")
    if fam_counts:
        top = sorted(fam_counts.items(), key=lambda kv: -kv[1])[:15]
        print("\ntop families:")
        for fam, c in top:
            print(f"  {fam}: {c}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
