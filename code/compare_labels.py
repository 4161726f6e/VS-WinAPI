#!/usr/bin/env python3
r"""
compare_labels.py - Join the AVClass spot-check against the MalDICT-labeled
corpus by MD5 and measure how often the two independent label sources agree.

AVClass CLASS tags and MalDICT category tags are both malware TYPE labels, drawn
from overlapping but not identical taxonomies (e.g. AVClass "grayware" vs MalDICT
"adware"/"pua"). So we report three views:
  * exact agreement  - identical token
  * loose agreement  - one token contains the other, or a small alias map matches
  * confusion pairs   - the most common (maldict, avclass) disagreements, so the
                        taxonomy gaps are visible rather than hidden.

Usage:
    python compare_labels.py \
        --spotcheck vt_spotcheck_avclass.csv \
        --maldict corpus_category_labeled.csv \
        --out spotcheck_vs_maldict.csv
"""
import csv
import sys
import argparse
from collections import Counter

# Minimal alias bridge between the two taxonomies (extend as needed). Maps tokens
# that mean the same malware type across AVClass and MalDICT vocabularies.
ALIASES = {
    "grayware": {"adware", "pua", "pup", "grayware", "unwanted"},
    "rogueware": {"fakeav", "rogue", "fakeantivirus", "scareware"},
    "downloader": {"downloader", "dropper", "download"},
    "backdoor": {"backdoor", "rat"},
    "infostealer": {"infostealer", "passwordstealer", "spyware", "stealer"},
    "virus": {"virus", "fileinfector"},
    "worm": {"worm"},
    "ransomware": {"ransomware", "ransom"},
    "trojan": {"trojan"},
}


def alias_set(token):
    token = (token or "").strip().lower()
    if not token:
        return set()
    # strip avclass sub-tags like "grayware:adware" -> consider both parts
    parts = set(token.replace(":", " ").split())
    out = set(parts)
    for canon, members in ALIASES.items():
        if parts & members or canon in parts:
            out |= members | {canon}
    return out


def loose_match(a, b):
    a = (a or "").strip().lower()
    b = (b or "").strip().lower()
    if not a or not b:
        return False
    if a == b or a in b or b in a:
        return True
    return bool(alias_set(a) & alias_set(b))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spotcheck", required=True)
    ap.add_argument("--maldict", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    # load MalDICT category by md5 (stream; file is large)
    mal = {}
    with open(args.maldict, newline="") as f:
        for row in csv.DictReader(f):
            md5 = (row.get("md5") or "").strip().lower()
            if md5:
                mal[md5] = (row.get("category") or "").strip().lower()
    print(f"loaded {len(mal):,} MalDICT category rows", file=sys.stderr)

    rows_out = []
    n = both = exact = loose = 0
    confusion = Counter()
    only_avclass = only_maldict = neither = 0

    with open(args.spotcheck, newline="") as f:
        for row in csv.DictReader(f):
            n += 1
            md5 = (row.get("md5") or row.get("query_hash") or "").strip().lower()
            avc = (row.get("avclass_class") or "").strip().lower()
            mcat = mal.get(md5, "")
            row_out = {
                "md5": md5,
                "maldict_category": mcat,
                "avclass_class": avc,
                "avclass_family": (row.get("avclass_family") or "").strip(),
                "exact": "", "loose": "",
            }
            if avc and mcat:
                both += 1
                e = (avc == mcat)
                l = loose_match(avc, mcat)
                row_out["exact"] = "1" if e else "0"
                row_out["loose"] = "1" if l else "0"
                if e:
                    exact += 1
                if l:
                    loose += 1
                if not l:
                    confusion[(mcat, avc)] += 1
            elif avc and not mcat:
                only_avclass += 1
            elif mcat and not avc:
                only_maldict += 1
            else:
                neither += 1
            rows_out.append(row_out)

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["md5", "maldict_category",
                                          "avclass_class", "avclass_family",
                                          "exact", "loose"])
        w.writeheader()
        w.writerows(rows_out)

    print(f"\nsampled rows: {n}")
    print(f"  labeled by BOTH sources:  {both}")
    print(f"  only AVClass (no MalDICT): {only_avclass}")
    print(f"  only MalDICT (no AVClass): {only_maldict}")
    print(f"  neither:                  {neither}")
    if both:
        print(f"\nAgreement where both label the sample (n={both}):")
        print(f"  exact token match: {exact} ({100*exact/both:.0f}%)")
        print(f"  loose/alias match: {loose} ({100*loose/both:.0f}%)")
    if confusion:
        print("\nTop disagreements (maldict -> avclass):")
        for (m, a), c in confusion.most_common(12):
            print(f"  {m or '<none>'} vs {a or '<none>'}: {c}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
