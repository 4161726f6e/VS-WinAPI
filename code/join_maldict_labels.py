#!/usr/bin/env python3
r"""
join_maldict_labels.py - Attach MalDICT type/behavior (or packer/platform/
vulnerability) labels to the corpus by MD5, fully offline (no VirusTotal).

MalDICT_Tags/*.jsonl files have one JSON object per line:
    {"md5": "<md5>", "ranking": [["worm", 13], ["blocker", 5]]}
where `ranking` is a list of [tag, av_support_count] pairs ordered by support.
The primary label is the highest-support tag (the first entry).

These files key on MD5, so they join against the WHOLE corpus, including the
MD5-only archives recovered from Cuckoo 2.0.7 reports.

Pass BOTH the train and test split for a label type so no labels are missed
(the split is MalDICT's own ML partition, irrelevant to labeling your corpus):

    python join_maldict_labels.py \
        --labels MalDICT_Tags/maldict_category_train.jsonl \
                 MalDICT_Tags/maldict_category_test.jsonl \
        --mapping mappings/mapping_00000.csv ... \
        --label-name category \
        --out corpus_category_labeled.csv

Output columns:
    md5,archive,report_id,<label-name>,<label-name>_support,secondary,label_source,full_ranking
Samples present in the corpus but absent from the label file are recorded with
an empty label and label_source=unlabeled (not dropped), so coverage is explicit.
"""
import os
import csv
import sys
import json
import glob
import argparse


def load_maldict(label_paths):
    """md5 -> (primary, primary_support, secondary, full_ranking_json)."""
    table = {}
    n_lines = 0
    for p in label_paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                md5 = (obj.get("md5") or "").strip().lower()
                ranking = obj.get("ranking") or []
                if not md5 or not ranking:
                    continue
                # ranking is ordered by support; take the top, keep a secondary
                primary, p_sup = ranking[0][0], ranking[0][1]
                secondary = ranking[1][0] if len(ranking) > 1 else ""
                table[md5] = (primary, p_sup, secondary,
                              json.dumps(ranking, separators=(",", ":")))
                n_lines += 1
    return table, n_lines


def iter_mapping_rows(mapping_paths):
    for p in mapping_paths:
        with open(p, newline="") as f:
            for row in csv.DictReader(f):
                yield row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", nargs="*", default=[],
                    help="MalDICT *.jsonl tag files (pass train AND test)")
    ap.add_argument("--labels-dir", default=None,
                    help="glob *.jsonl from this directory instead/in addition")
    ap.add_argument("--mapping", nargs="+", required=True,
                    help="corpus mapping CSV(s) with an md5 column")
    ap.add_argument("--label-name", default="label",
                    help="name for the label column (e.g. category, packer, "
                         "platform, vulnerability)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    label_paths = list(args.labels)
    if args.labels_dir:
        label_paths += glob.glob(os.path.join(args.labels_dir, "*.jsonl"))
    if not label_paths:
        sys.exit("ERROR: provide --labels and/or --labels-dir")

    print(f"loading {len(label_paths)} MalDICT file(s)...", file=sys.stderr)
    table, n_lines = load_maldict(label_paths)
    print(f"  {len(table)} unique md5 labels from {n_lines} lines",
          file=sys.stderr)

    ln = args.label_name
    n = n_labeled = n_unlabeled = n_nohash = 0
    label_counts = {}

    with open(args.out, "w", newline="") as out:
        w = csv.writer(out)
        w.writerow(["md5", "archive", "report_id", ln, f"{ln}_support",
                    "secondary", "label_source", "full_ranking"])
        for row in iter_mapping_rows(args.mapping):
            n += 1
            md5 = (row.get("md5") or "").strip().lower()
            archive = row.get("archive", "")
            rid = row.get("report_id", "")
            if not md5:
                n_nohash += 1
                w.writerow(["", archive, rid, "", "", "", "no_hash", ""])
                continue
            hit = table.get(md5)
            if hit is None:
                n_unlabeled += 1
                w.writerow([md5, archive, rid, "", "", "", "unlabeled", ""])
                continue
            primary, sup, secondary, ranking_json = hit
            n_labeled += 1
            label_counts[primary] = label_counts.get(primary, 0) + 1
            w.writerow([md5, archive, rid, primary, sup, secondary,
                        "maldict", ranking_json])

    cov = 100 * n_labeled / n if n else 0
    print(f"\nrows processed: {n}")
    print(f"  labeled ({ln}): {n_labeled}  ({cov:.1f}% coverage)")
    print(f"  unlabeled (not in MalDICT): {n_unlabeled}")
    print(f"  no hash in mapping: {n_nohash}")
    if label_counts:
        top = sorted(label_counts.items(), key=lambda kv: -kv[1])[:15]
        print(f"\ntop {ln} labels:")
        for lab, c in top:
            print(f"  {lab}: {c}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
