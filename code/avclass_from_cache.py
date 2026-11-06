#!/usr/bin/env python3
r"""
avclass_from_cache.py - Run AVClass over the VirusTotal reports already cached by
label_corpus.py, and merge the resulting family names into the spot-check CSV.
No new VirusTotal queries are made.

Why this exists
---------------
label_corpus.py caches each VT v3 file report as <cache>/<hash>.json. AVClass's
CLI is stable across versions and reads a JSONL file of VT reports:
    avclass -f reports.jsonl -t -hash md5 -o out.txt
This script (1) collects the cached reports into a JSONL, (2) runs avclass,
(3) parses its family output, and (4) writes the spot-check rows with an added
avclass_family column so you can compare AVClass vs MalDICT category directly.

Usage
-----
    python avclass_from_cache.py \
        --spotcheck vt_spotcheck.csv \
        --cache vt_cache \
        --out vt_spotcheck_avclass.csv \
        [--hash md5] [--avclass-bin avclass]

Requires the `avclass` command on PATH (pip install avclass-malicialab).
"""
import os
import csv
import sys
import json
import subprocess
import argparse


def collect_reports(spotcheck, cache_dir, jsonl_path):
    """Write a JSONL of cached VT reports for the hashes in the spotcheck.
    Returns the set of hashes that had a usable cached report."""
    seen = set()
    with open(jsonl_path, "w", encoding="utf-8") as out:
        with open(spotcheck, newline="") as f:
            for row in csv.DictReader(f):
                h = (row.get("query_hash") or row.get("sha256")
                     or row.get("md5") or "").strip().lower()
                if not h or h in seen:
                    continue
                cp = os.path.join(cache_dir, f"{h}.json")
                if not os.path.exists(cp):
                    continue
                try:
                    with open(cp, encoding="utf-8") as cf:
                        data = json.load(cf)
                except Exception:
                    continue
                # only include reports that actually have VT analysis data
                attrs = (data.get("data", {}) or {}).get("attributes", {})
                if not attrs.get("last_analysis_results"):
                    continue
                out.write(json.dumps(data) + "\n")
                seen.add(h)
    return seen


def run_avclass(jsonl_path, out_path, hash_type, avclass_bin):
    # -t emits ALL tags (FILE/CLASS/BEH/FAM) with per-tag support, so we can
    # recover the malware CLASS (type) even when no FAMILY consensus exists -
    # important for old/generic corpora where family often resolves to SINGLETON.
    cmd = [avclass_bin, "-f", jsonl_path, "-hash", hash_type, "-t", "-o", out_path]
    print("running:", " ".join(cmd), file=sys.stderr)
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("avclass stderr:\n" + res.stderr, file=sys.stderr)
        raise RuntimeError(f"avclass exited {res.returncode}")
    return out_path


def parse_avclass_output(path):
    """Parse `avclass -t` output lines of the form:
        <hash>\t<vt_count>\tTAG:val|support,TAG:val|support,...
    Return md5 -> dict(family, family_support, av_class, class_support,
    behaviors, all_tags). FAMILY tags appear as 'FAM:<name>'; malware type as
    'CLASS:<name>'; behaviors as 'BEH:<name>'. When no FAM tag is present the
    family is '' (AVClass would mark it SINGLETON)."""
    out = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            h = parts[0].strip().lower()
            tag_field = parts[2] if len(parts) >= 3 else ""
            family = ""
            fam_sup = 0
            av_class = ""
            class_sup = 0
            behaviors = []
            for tok in tag_field.split(","):
                tok = tok.strip()
                if not tok or ":" not in tok:
                    continue
                key, _, sup = tok.partition("|")
                try:
                    sup = int(sup)
                except ValueError:
                    sup = 0
                if key.startswith("FAM:"):
                    if sup >= fam_sup:
                        family, fam_sup = key[4:], sup
                elif key.startswith("CLASS:"):
                    if sup >= class_sup:
                        av_class, class_sup = key[6:], sup
                elif key.startswith("BEH:"):
                    behaviors.append(key[4:])
            out[h] = {"family": family, "family_support": fam_sup,
                      "av_class": av_class, "class_support": class_sup,
                      "behaviors": ";".join(behaviors), "all_tags": tag_field}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spotcheck", required=True)
    ap.add_argument("--cache", default="vt_cache")
    ap.add_argument("--out", required=True)
    ap.add_argument("--hash", default="md5", choices=["md5", "sha1", "sha256"])
    ap.add_argument("--avclass-bin", default="avclass")
    ap.add_argument("--jsonl", default="vt_reports_for_avclass.jsonl")
    ap.add_argument("--avclass-out", default="avclass_families.txt")
    args = ap.parse_args()

    seen = collect_reports(args.spotcheck, args.cache, args.jsonl)
    print(f"collected {len(seen)} cached VT reports -> {args.jsonl}",
          file=sys.stderr)
    if not seen:
        sys.exit("No cached VT reports found; check --cache path.")

    run_avclass(args.jsonl, args.avclass_out, args.hash, args.avclass_bin)
    tags = parse_avclass_output(args.avclass_out)
    n_fam = sum(1 for v in tags.values() if v["family"])
    n_class = sum(1 for v in tags.values() if v["av_class"])
    print(f"avclass: {n_fam} of {len(tags)} got a FAMILY, "
          f"{n_class} got a CLASS (type) tag", file=sys.stderr)

    # merge back into the spotcheck
    n = n_have = 0
    class_vs_maldict_comparable = class_agree = 0
    with open(args.spotcheck, newline="") as f:
        rows = list(csv.DictReader(f))
        fields = list(rows[0].keys()) if rows else []
    add_cols = ["avclass_family", "avclass_class", "avclass_behaviors"]
    out_fields = fields + add_cols
    with open(args.out, "w", newline="") as out:
        w = csv.DictWriter(out, fieldnames=out_fields)
        w.writeheader()
        for row in rows:
            n += 1
            h = (row.get("query_hash") or row.get("sha256")
                 or row.get("md5") or "").strip().lower()
            t = tags.get(h, {})
            row["avclass_family"] = t.get("family", "")
            row["avclass_class"] = t.get("av_class", "")
            row["avclass_behaviors"] = t.get("behaviors", "")
            if t.get("family") or t.get("av_class"):
                n_have += 1
            # if the spotcheck carries a MalDICT category column, compare it to
            # the AVClass CLASS tag as a coarse cross-check (both are type-level)
            mal = (row.get("category") or "").strip().lower()
            avc = t.get("av_class", "").strip().lower()
            if mal and avc:
                class_vs_maldict_comparable += 1
                # loose match: same token or one contains the other
                if mal == avc or mal in avc or avc in mal:
                    class_agree += 1
            w.writerow(row)

    print(f"\nwrote {args.out}")
    print(f"  rows: {n}, with any avclass tag: {n_have}")
    if class_vs_maldict_comparable:
        rate = 100 * class_agree / class_vs_maldict_comparable
        print(f"  AVClass-CLASS vs MalDICT-category: {class_agree}/"
              f"{class_vs_maldict_comparable} loosely agree ({rate:.0f}%)")
    print("Note: for old/generic corpora AVClass often returns no FAMILY "
          "consensus (SINGLETON); the CLASS tag (virus/worm/trojan...) is the "
          "reliable layer and is what aligns with MalDICT's category labels.")


if __name__ == "__main__":
    main()
