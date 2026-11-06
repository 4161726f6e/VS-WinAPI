#!/usr/bin/env python3
"""Build manifest_v3.csv: the release manifest with the gaps in manifest.csv fixed.

Fixes and additions relative to manifest.csv:
  * md5/sha256 filled from mappings/mapping_XXXXX.csv (joined on archive + report_id).
    The sanitized reports in archives 00002, 00003, and part of 00001/00007 carry no
    hash, so manifest.csv left them blank.
  * labels joined on archive + report_id from corpus_category_labeled.csv
    (manifest.csv joined on md5 and so missed the reports above: 188,034 -> 246,776).
  * outcome, guest, host, analysis date, duration, and an any-probing-signature flag
    from collect_paper_stats.py scan files (joined on archive + report_id).
  * collection_fault = 1 for archives 00008-00012 (see paper Sec. "A collection fault").
  * archive 00003, a second copy of the 00002 analyses, merged into 00002: one row
    per task, using the more complete copy; source_archive says which copy
    (and therefore which release file and frequency matrix holds the report).

Usage
  python build_manifest_v2.py --manifest manifest.csv --mappings mappings \
      --labels corpus_category_labeled.csv --scans stats_full --out manifest_v3.csv
"""
import argparse
import glob
import os
import sys

import pandas as pd

FAULT = {"00008", "00009", "00010", "00011", "00012"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--mappings", required=True, help="folder of mapping_XXXXX.csv")
    ap.add_argument("--labels", required=True)
    ap.add_argument("--scans", help="folder of scan_reports_VirusShare_XXXXX.csv (optional)")
    ap.add_argument("--out", default="manifest_v3.csv")
    ap.add_argument("--keep-00003", action="store_true",
                    help="do not merge the duplicate 00003 copy into 00002")
    a = ap.parse_args()

    m = pd.read_csv(a.manifest, dtype=str, low_memory=False)
    m = m.drop(columns=["category", "category_support", "label_source"], errors="ignore")

    maps = []
    for p in sorted(glob.glob(os.path.join(a.mappings, "mapping_*.csv"))):
        mp = pd.read_csv(p, dtype=str, usecols=["report_id", "md5", "sha256", "archive"])
        maps.append(mp[mp.archive != "00013"])
    if maps:
        mp = pd.concat(maps).rename(columns={"md5": "md5_map", "sha256": "sha256_map"})
        mp = mp.drop_duplicates(["archive", "report_id"])
        m = m.merge(mp, on=["archive", "report_id"], how="left")
        m["md5"] = m.md5.fillna(m.md5_map)
        m["sha256"] = m.sha256.fillna(m.sha256_map)
        m = m.drop(columns=["md5_map", "sha256_map"])

    lab = pd.read_csv(a.labels, dtype=str,
                      usecols=["md5", "archive", "report_id", "category", "category_support", "label_source"])
    lab = lab[(lab.archive != "00013") & (lab.label_source == "maldict")]
    cols = ["category", "category_support", "label_source"]
    # 1) by sample hash (now that hashes are filled), 2) fall back to archive + report_id
    by_md5 = lab.dropna(subset=["md5"]).drop_duplicates("md5")[["md5"] + cols]
    m = m.merge(by_md5, on="md5", how="left")
    by_rid = lab.drop_duplicates(["archive", "report_id"])[["archive", "report_id"] + cols]
    by_rid = by_rid.rename(columns={c: c + "_rid" for c in cols})
    m = m.merge(by_rid, on=["archive", "report_id"], how="left")
    for c in cols:
        m[c] = m[c].fillna(m[c + "_rid"])
        m = m.drop(columns=[c + "_rid"])

    if a.scans:
        parts = []
        scan_files = sorted(glob.glob(os.path.join(a.scans, "**", "scan_*.csv"), recursive=True) + glob.glob(os.path.join(a.scans, "**", "scan_*.csv.gz"), recursive=True))
        if not scan_files:
            sys.exit(f"No scan_*.csv files found in or below {a.scans!r}. Point --scans at the folder "
                     "collect_paper_stats.py wrote, or leave --scans out.")
        print(f"found {len(scan_files)} scan files")
        for p in scan_files:
            s = pd.read_csv(p, dtype=str, usecols=["archive", "file", "outcome", "started", "duration",
                                                    "machine", "probe_sigs"])
            s["archive"] = s.archive.str[-5:]
            if (s.archive == "00013").any():
                continue
            s["report_id"] = s.file.str.replace(r"\.json(\.gz)?$", "", regex=True)
            parts.append(s.drop(columns=["file"]))
        if not parts:
            sys.exit("Scan files were found but none matched archives 00000-00012.")
        s = pd.concat(parts).drop_duplicates(["archive", "report_id"])
        s["host"] = s.machine.fillna("").str.startswith("cuck").map({True: "2", False: "1"})
        s.loc[s.machine.isna(), "host"] = ""
        s["any_probe_sig"] = s.probe_sigs.notna().astype(int)
        s = s.rename(columns={"started": "analyzed", "machine": "guest"}).drop(columns=["probe_sigs"])
        m = m.merge(s, on=["archive", "report_id"], how="left")

    m["collection_fault"] = m.archive.isin(FAULT).astype(int)

    # The reports stored as archive 00003 are a second copy of the 00002 analyses
    # (same task ids, hashes, guests, timestamps). Keep, for each 00002 task, the
    # copy with the more complete behavior, and record where it came from.
    m["source_archive"] = m["archive"]
    if not a.keep_00003 and (m.archive == "00003").any():
        rank = {"success": 0, "too_few_unique": 1, "too_few_calls": 2, "no_process": 3}
        pair = m[m.archive.isin(["00002", "00003"])].copy()
        if "outcome" in pair:
            pair["_r"] = pair.outcome.map(rank).fillna(4)
        else:
            pair["_r"] = (pair.success != "1").astype(int)
        pair["_c"] = -pd.to_numeric(pair.get("n_calls"), errors="coerce").fillna(0)
        pair["_p"] = (pair.source_archive != "00002").astype(int)
        pair = pair.sort_values(["report_id", "_r", "_c", "_p"]).drop_duplicates("report_id")
        pair = pair.drop(columns=["_r", "_c", "_p"])
        pair["archive"] = "00002"
        pair["collection_fault"] = 0
        m = pd.concat([m[~m.archive.isin(["00002", "00003"])], pair], ignore_index=True)
        print(f"merged 00003 into 00002: {int((pair.source_archive == '00003').sum()):,} tasks use the 00003 copy")
    m.to_csv(a.out, index=False)

    print(f"rows {len(m):,}")
    print(f"with a hash {m.md5.notna().sum():,} ({m.md5.notna().mean():.1%})")
    print(f"labeled {m.category.notna().sum():,}; successful and labeled "
          f"{((m.success == '1') & m.category.notna()).sum():,}")
    if "outcome" in m:
        print(f"scan rows joined {m.outcome.notna().sum():,}")
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
