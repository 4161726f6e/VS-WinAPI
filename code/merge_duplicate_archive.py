#!/usr/bin/env python3
"""Fold the duplicate "00003" copy into archive 00002 in the release folder.

The reports labeled 00003 are a second copy of the 00002 analyses (same task IDs,
sample hashes, guests, timestamps), saved at a different stage: about 18,000 of
them contain behavior that the 00002 copy lacks. manifest_v3.csv records, for each
00002 report, which copy is better (column source_archive).

This script:
  1. writes release/reports_00002.merged.tar.gz: every 00002 report, taking the
     00003 copy where the manifest says so (renamed to 00002/<id>.json and its
     dataset.archive set to "00002")
  2. writes freq_merged/freq_00002.csv (next to --freq-dir) the same way from freq_00002/00003.csv
  3. leaves the originals in place; after checking, replace reports_00002.tar.gz
     with the merged file, delete reports_00003.tar.gz and freq_00003.csv, and
     rerun SHA256SUMS (this script prints the commands)

Usage
  python merge_duplicate_archive.py --release release --freq-dir freq_clean ^
      --manifest manifest_v3.csv
"""
import argparse
import gzip
import hashlib
import io
import os
import shutil
import tarfile

import pandas as pd


def tarinfo(name, size):
    ti = tarfile.TarInfo(name)
    ti.size, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.mode = size, 0, 0, 0, "", "", 0o644
    return ti


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", required=True)
    ap.add_argument("--freq-dir", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--tmp", default=None, help="temp folder for extracted 00003 copies (default: release/_tmp3)")
    a = ap.parse_args()

    m = pd.read_csv(a.manifest, dtype=str, usecols=["archive", "report_id", "source_archive"])
    m = m[m.archive == "00002"]
    use3 = set(m.loc[m.source_archive == "00003", "report_id"])
    all_ids = set(m.report_id)
    print(f"00002 reports in manifest: {len(all_ids):,}; taking the 00003 copy for {len(use3):,}")

    tmp = a.tmp or os.path.join(a.release, "_tmp3")
    os.makedirs(tmp, exist_ok=True)

    # Pass 1: extract only the chosen 00003 copies to disk (bounded memory).
    got3 = set()
    with tarfile.open(os.path.join(a.release, "reports_00003.tar.gz"), "r|gz") as t3:
        for ti in t3:
            rid = os.path.basename(ti.name)[:-5]
            if ti.isfile() and rid in use3:
                src = t3.extractfile(ti)
                with open(os.path.join(tmp, rid + ".json"), "wb") as out:
                    head = src.read(4096)
                    # parsed reports carry "dataset":{"archive":"00003",...}; fix it
                    head = head.replace(b'"dataset":{"archive":"00003"', b'"dataset":{"archive":"00002"')
                    out.write(head)
                    shutil.copyfileobj(src, out, 1 << 20)
                got3.add(rid)
    print(f"extracted {len(got3):,} copies from reports_00003.tar.gz")
    missing = use3 - got3
    if missing:
        print(f"WARNING: {len(missing)} chosen 00003 copies not found; the 00002 copy will be kept for them")

    # Pass 2: stream 00002, substituting the chosen copies; add 00002 ids that exist only in 00003.
    out_path = os.path.join(a.release, "reports_00002.merged.tar.gz")
    seen = set()
    raw = open(out_path + ".partial", "wb")
    gz = gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0)
    n_sub = n_keep = 0
    with tarfile.open(os.path.join(a.release, "reports_00002.tar.gz"), "r|gz") as t2, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tout:
        for ti in t2:
            if not ti.isfile():
                continue
            rid = os.path.basename(ti.name)[:-5]
            seen.add(rid)
            name = f"00002/{rid}.json"
            if rid in got3:
                p = os.path.join(tmp, rid + ".json")
                with open(p, "rb") as fh:
                    tout.addfile(tarinfo(name, os.path.getsize(p)), fh)
                n_sub += 1
            else:
                tout.addfile(tarinfo(name, ti.size), t2.extractfile(ti))
                n_keep += 1
        extra = sorted(got3 - seen, key=lambda x: (len(x), x))
        for rid in extra:
            p = os.path.join(tmp, rid + ".json")
            with open(p, "rb") as fh:
                tout.addfile(tarinfo(f"00002/{rid}.json", os.path.getsize(p)), fh)
    gz.close()
    raw.close()
    os.replace(out_path + ".partial", out_path)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"wrote {out_path}: kept {n_keep:,}, substituted {n_sub:,}, added {len(extra):,} "
          f"(total {n_keep + n_sub + len(extra):,}; manifest has {len(all_ids):,})")

    # Frequency matrix.
    f2 = pd.read_csv(os.path.join(a.freq_dir, "freq_00002.csv"), dtype={"report_id": str})
    f3 = pd.read_csv(os.path.join(a.freq_dir, "freq_00003.csv"), dtype={"report_id": str})
    cols = list(f2.columns)
    f3 = f3.reindex(columns=cols, fill_value=0)
    f2 = f2[~f2.report_id.isin(got3)]
    merged = pd.concat([f2, f3[f3.report_id.isin(got3)]])
    merged = merged[merged.report_id.isin(all_ids)]
    merged = merged.sort_values("report_id", key=lambda s: s.str.zfill(10))
    fdir = os.path.join(os.path.dirname(os.path.abspath(a.freq_dir)), "freq_merged")
    os.makedirs(fdir, exist_ok=True)
    merged.to_csv(os.path.join(fdir, "freq_00002.csv"), index=False)
    print(f"wrote {os.path.join(fdir, 'freq_00002.csv')}: {len(merged):,} rows")

    print("\nAfter checking the counts above:")
    print(f'  move "{out_path}" over "{os.path.join(a.release, "reports_00002.tar.gz")}"')
    print(f'  delete "{os.path.join(a.release, "reports_00003.tar.gz")}" and freq_00003.csv from the release')
    print(f"  replace freq_00002.csv in the release with {os.path.join(fdir, 'freq_00002.csv')}")
    print("  regenerate SHA256SUMS:  python prepare_release.py ... (all archives are skipped as built; it rewrites SHA256SUMS)")


if __name__ == "__main__":
    main()
