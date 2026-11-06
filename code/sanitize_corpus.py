#!/usr/bin/env python3
r"""
sanitize_corpus.py - Run the report sanitizer across MANY archives (all 13) in
one pass and report the AGGREGATE size reduction, so the paper can state a real
full-corpus figure instead of a pilot-slice estimate.

It reuses the exact sanitization logic from sanitize_report.py (imported, not
reimplemented), so the batch output is identical to the single-file tool.

Each input may be a .tar.gz / .tgz / .tar archive (streamed, no extraction) or a
directory of <id>.json files. For each archive it writes one sanitized output
archive (<tag>.sanitized.tar.gz) plus a per-archive manifest, and at the end it
prints the aggregate input->output ratio across everything processed.

Resumable: an archive whose sanitized output already exists (with a .done
sidecar) is skipped, so a crash/restart costs only the archive in flight.

Usage:
    python sanitize_corpus.py \
        00000.tar.gz 00001.tar.gz ... 00012.tar.gz \
        --outdir sanitized [--keep-args] [--workers 4]

Output per archive:
    sanitized/<tag>.sanitized.tar.gz   (gzip tar of sanitized <id>.json files)
    sanitized/<tag>.manifest.csv
    sanitized/<tag>.sanitized.tar.gz.done   (completion sidecar)

Aggregate report: total raw bytes, total sanitized bytes, overall percentage,
and a per-archive breakdown.
"""
import os
import re
import sys
import csv
import json
import glob
import gzip
import time
import tarfile
import argparse
import io
from concurrent.futures import ProcessPoolExecutor, as_completed

# reuse the real sanitization logic
import sanitize_report as S

ID_RE = re.compile(r"(\d+)\.json$", re.IGNORECASE)
ARCHIVE_RE = re.compile(r"(\d{5})")


def infer_tag(path):
    base = os.path.basename(path.rstrip("/\\"))
    m = ARCHIVE_RE.search(base)
    return m.group(1) if m else os.path.splitext(base)[0]


def iter_members(inp):
    """Yield (name, raw_bytes, stored_size) for each .json report."""
    low = inp.lower()
    if low.endswith((".tar.gz", ".tgz", ".tar")):
        mode = "r:gz" if low.endswith((".tar.gz", ".tgz")) else "r:*"
        with tarfile.open(inp, mode) as tf:
            for m in tf:
                if not m.isfile() or not m.name.lower().endswith(".json"):
                    continue
                f = tf.extractfile(m)
                if f is None:
                    continue
                yield os.path.basename(m.name), f.read(), m.size
    elif os.path.isdir(inp):
        for p in glob.iglob(os.path.join(inp, "**", "*.json"), recursive=True):
            try:
                with open(p, "rb") as fh:
                    raw = fh.read()
                yield os.path.basename(p), raw, len(raw)
            except Exception:
                continue
    else:
        raise RuntimeError(f"not a tar archive or directory: {inp}")


def process_archive(inp, out_tar, manifest_path, keep_args):
    """Sanitize one archive; write a gzip tar of sanitized reports + manifest.
    Returns (n_ok, n_fail, in_bytes, out_bytes)."""
    partial = out_tar + ".partial"
    n_ok = n_fail = 0
    in_bytes = out_bytes = 0
    rows = []

    # write sanitized reports into a new gzip tar as we go (streaming out)
    with tarfile.open(partial, "w:gz") as tout:
        for name, raw, stored in iter_members(inp):
            in_bytes += stored
            try:
                d = json.loads(raw)
            except Exception as e:
                n_fail += 1
                rows.append({"file": name, "status": "PARSE_FAIL",
                             "error": str(e)[:80], "sha256": "", "md5": "",
                             "n_proc": "", "n_calls": "", "label": ""})
                continue
            clean = S.sanitize(d, keep_args)
            txt = json.dumps(clean, separators=(",", ":")).encode("utf-8")
            out_bytes += len(txt)
            ti = tarfile.TarInfo(name=name)
            ti.size = len(txt)
            tout.addfile(ti, io.BytesIO(txt))
            n_ok += 1

            tf = clean.get("target", {}).get("file", {})
            n_calls = sum(p.get("n_calls", 0)
                          for p in clean.get("behavior", {}).get("processes", []))
            rows.append({"file": name, "status": "OK", "error": "",
                         "sha256": tf.get("sha256", ""), "md5": tf.get("md5", ""),
                         "n_proc": len(clean.get("behavior", {}).get("processes", [])),
                         "n_calls": n_calls, "label": ""})

    with open(manifest_path, "w", newline="") as mf:
        w = csv.DictWriter(mf, fieldnames=["file", "status", "error", "sha256",
                                           "md5", "n_proc", "n_calls", "label"])
        w.writeheader()
        w.writerows(rows)

    os.replace(partial, out_tar)
    with open(out_tar + ".done", "w") as d:
        d.write(f"{n_ok},{n_fail},{in_bytes},{out_bytes}\n")
    return n_ok, n_fail, in_bytes, out_bytes


def is_done(out_tar):
    return os.path.exists(out_tar + ".done")


def read_done(out_tar):
    try:
        with open(out_tar + ".done") as f:
            a, b, c, d = f.read().strip().split(",")
            return int(a), int(b), int(c), int(d)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--outdir", default="sanitized")
    ap.add_argument("--keep-args", action="store_true")
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # resolve tasks, skipping completed archives
    tasks = []
    pre = {}  # tag -> counts already done
    for inp in args.inputs:
        tag = infer_tag(inp)
        out_tar = os.path.join(args.outdir, f"{tag}.sanitized.tar.gz")
        man = os.path.join(args.outdir, f"{tag}.manifest.csv")
        if not args.force and is_done(out_tar):
            r = read_done(out_tar)
            if r:
                pre[tag] = r
            continue
        tasks.append((inp, out_tar, man, tag))

    for tag, r in pre.items():
        print(f"SKIP {tag} (done: {r[0]} reports, "
              f"{100*r[3]/max(r[2],1):.1f}% of input)")

    results = dict(pre)  # tag -> (n_ok,n_fail,in,out)

    if tasks:
        workers = args.workers or min(len(tasks), os.cpu_count() or 1)
        workers = max(1, min(workers, len(tasks)))
        print(f"Sanitizing {len(tasks)} archive(s) with {workers} worker(s)...\n")
        if workers == 1:
            for inp, out_tar, man, tag in tasks:
                t0 = time.time()
                r = process_archive(inp, out_tar, man, args.keep_args)
                results[tag] = r
                print(f"DONE {tag}: {r[0]} reports, {r[1]} fail, "
                      f"{100*r[3]/max(r[2],1):.1f}% of input "
                      f"({time.time()-t0:.0f}s)", flush=True)
        else:
            with ProcessPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(process_archive, inp, out_tar, man,
                                  args.keep_args): tag
                        for inp, out_tar, man, tag in tasks}
                for fut in as_completed(futs):
                    tag = futs[fut]
                    try:
                        r = fut.result()
                        results[tag] = r
                        print(f"DONE {tag}: {r[0]} reports, {r[1]} fail, "
                              f"{100*r[3]/max(r[2],1):.1f}% of input", flush=True)
                    except Exception as e:
                        print(f"ERROR {tag}: {e}", file=sys.stderr)

    # aggregate
    tot_ok = sum(r[0] for r in results.values())
    tot_fail = sum(r[1] for r in results.values())
    tot_in = sum(r[2] for r in results.values())
    tot_out = sum(r[3] for r in results.values())

    print("\n=== AGGREGATE (all archives) ===")
    print(f"{'archive':>8} {'reports':>10} {'raw GB':>10} {'clean GB':>10} {'%':>7}")
    for tag in sorted(results):
        r = results[tag]
        print(f"{tag:>8} {r[0]:>10} {r[2]/1e9:>10.2f} {r[3]/1e9:>10.2f} "
              f"{100*r[3]/max(r[2],1):>6.1f}%")
    print(f"{'TOTAL':>8} {tot_ok:>10} {tot_in/1e9:>10.2f} {tot_out/1e9:>10.2f} "
          f"{100*tot_out/max(tot_in,1):>6.1f}%")
    print(f"\nParse failures across corpus: {tot_fail}")
    print(f"Overall sanitized size: {100*tot_out/max(tot_in,1):.1f}% of raw "
          f"(reduction to ~{100*tot_out/max(tot_in,1):.0f}%).")


if __name__ == "__main__":
    main()
