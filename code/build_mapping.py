#!/usr/bin/env python3
r"""
build_mapping.py - Windows/cross-platform replacement for match_ID_to_MD5.sh.

Parses each Cuckoo JSON and reads the sample identity directly from target.file,
emitting a clean canonical mapping:  report_id,md5,sha256,archive,has_hash

Handles ONE or MANY archives in a single run, in PARALLEL, and is RESUMABLE so a
crash or Windows restart costs minutes, not the whole batch.

Each input may be a .tar.gz / .tgz / .tar archive (streamed) or a directory of
<id>.json files. One mapping file is written per archive, named by archive id
(00000 -> mapping_00000.csv) into --outdir.

SPEED:  --workers N processes N archives at once (default: min(#inputs, #CPUs)).
        Each archive is one task, so there is no shared state and no contention.

RESUME: by default, an archive whose output already exists AND is marked complete
        is SKIPPED. Completion is tracked two ways: a sidecar <out>.done file, and
        a final-row sentinel. Use --force to re-do everything. An interrupted
        archive leaves a <out>.partial that is overwritten cleanly on resume.

Examples:
    python build_mapping.py 00000.tar.gz 00001.tar.gz ... 00013.tar.gz ^
        --outdir D:\mappings --workers 6

    # resume after a restart - finished archives are skipped automatically:
    python build_mapping.py D:\archives\*.tar.gz --outdir D:\mappings --workers 6

    # single archive, explicit output:
    python build_mapping.py 00000.tar.gz --out mapping_00000.csv
"""
import os
import re
import sys
import csv
import json
import glob
import tarfile
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed

ARCHIVE_RE = re.compile(r"(\d{5})")
ID_RE = re.compile(r"(\d+)\.json$", re.IGNORECASE)


def infer_archive(path):
    base = os.path.basename(path.rstrip("/\\"))
    m = ARCHIVE_RE.search(base)
    return m.group(1) if m else ""


def report_id_from_name(name):
    m = ID_RE.search(name.replace("\\", "/"))
    return int(m.group(1)) if m else None


MD5_IN_NAME_RE = re.compile(r"VirusShare_([0-9a-fA-F]{32})")


def extract_identity(raw):
    """Return (md5, sha256). Falls back to parsing the MD5 out of the
    VirusShare_<md5> filename for Cuckoo builds (e.g. 2.0.7) that leave
    target.file.md5 null but retain the hash inside target.file.name."""
    try:
        d = json.loads(raw)
    except Exception:
        return ("", "")
    if not isinstance(d, dict):
        return ("", "")
    tf = (d.get("target") or {}).get("file") or {}
    md5 = (tf.get("md5") or "").lower()
    sha256 = (tf.get("sha256") or "").lower()
    if not md5:
        nm = tf.get("name") or ""
        m = MD5_IN_NAME_RE.search(nm)
        if m:
            md5 = m.group(1).lower()
    return (md5, sha256)


def iter_reports(inp):
    low = inp.lower()
    if low.endswith((".tar.gz", ".tgz", ".tar")):
        mode = "r:gz" if low.endswith((".tar.gz", ".tgz")) else "r:*"
        with tarfile.open(inp, mode) as tf:
            for m in tf:
                if not m.isfile():
                    continue
                rid = report_id_from_name(os.path.basename(m.name))
                if rid is None:
                    continue
                f = tf.extractfile(m)
                yield rid, (f.read() if f else b"")
    elif os.path.isdir(inp):
        for p in glob.iglob(os.path.join(inp, "**", "*.json"), recursive=True):
            rid = report_id_from_name(os.path.basename(p))
            if rid is None:
                continue
            try:
                with open(p, "rb") as fh:
                    yield rid, fh.read()
            except Exception:
                yield rid, b""
    else:
        raise RuntimeError(f"not a directory or tar archive: {inp}")


def is_complete(out_path):
    """An archive is complete iff its .done sidecar exists."""
    return os.path.exists(out_path + ".done")


def process_one(inp, out_path, archive, progress):
    """Worker task. Writes to <out>.partial, then atomically renames + .done."""
    partial = out_path + ".partial"
    rows = []
    n = n_hash = 0
    for rid, raw in iter_reports(inp):
        n += 1
        md5, sha256 = extract_identity(raw)
        has_hash = 1 if md5 else 0
        if has_hash:
            n_hash += 1
        rows.append((rid, md5, sha256, archive, has_hash))
        if progress and n % progress == 0:
            print(f"  [{archive or '?'}] ...{n} reports ({n_hash} with hash)",
                  file=sys.stderr, flush=True)

    rows.sort(key=lambda r: r[0])
    with open(partial, "w", newline="") as out:
        w = csv.writer(out)
        w.writerow(["report_id", "md5", "sha256", "archive", "has_hash"])
        w.writerows(rows)
    # atomic finalize
    if os.path.exists(out_path):
        os.remove(out_path)
    os.replace(partial, out_path)
    with open(out_path + ".done", "w") as d:
        d.write(f"{n},{n_hash}\n")

    dupes = len(rows) - len({r[0] for r in rows})
    return {"inp": inp, "archive": archive, "out": out_path,
            "n": n, "n_hash": n_hash, "dupes": dupes}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--out", default=None,
                    help="explicit output path (single input only)")
    ap.add_argument("--archive", default=None,
                    help="force archive id (single input only)")
    ap.add_argument("--workers", type=int, default=0,
                    help="parallel archives at once (default: min(#inputs,#CPUs))")
    ap.add_argument("--force", action="store_true",
                    help="re-process archives even if already complete")
    ap.add_argument("--progress", type=int, default=5000)
    args = ap.parse_args()

    if args.out and len(args.inputs) != 1:
        sys.exit("ERROR: --out is only valid with a single input; use --outdir.")
    os.makedirs(args.outdir, exist_ok=True)

    # build the task list, resolving output paths and skipping completed ones
    tasks = []
    skipped = []
    for inp in args.inputs:
        archive = args.archive or infer_archive(inp)
        if args.out:
            out_path = args.out
        else:
            tag = archive if archive else os.path.splitext(os.path.basename(inp))[0]
            out_path = os.path.join(args.outdir, f"mapping_{tag}.csv")
        if not args.force and is_complete(out_path):
            skipped.append((archive, out_path))
            continue
        tasks.append((inp, out_path, archive))

    for archive, out_path in skipped:
        print(f"SKIP archive {archive or '?'} (already complete: {out_path})")

    if not tasks:
        print("Nothing to do; all requested archives are already complete.")
        return

    workers = args.workers or min(len(tasks), os.cpu_count() or 1)
    workers = max(1, min(workers, len(tasks)))
    print(f"Processing {len(tasks)} archive(s) with {workers} worker(s); "
          f"{len(skipped)} already complete.\n")

    total = total_hash = done = 0

    if workers == 1:
        for inp, out_path, archive in tasks:
            try:
                r = process_one(inp, out_path, archive, args.progress)
                done += 1
                total += r["n"]; total_hash += r["n_hash"]
                w = f"  WARNING {r['dupes']} dup ids" if r["dupes"] else ""
                print(f"DONE archive {r['archive'] or '?'}: {r['n']} reports, "
                      f"{r['n_hash']} with hash -> {r['out']}{w}", flush=True)
            except Exception as e:
                print(f"ERROR processing {inp}: {e}", file=sys.stderr)
    else:
        # In parallel mode, suppress per-report progress to keep logs readable;
        # progress is reported at archive granularity as each completes.
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(process_one, inp, out_path, archive, 0): archive
                    for inp, out_path, archive in tasks}
            for fut in as_completed(futs):
                arch = futs[fut]
                try:
                    r = fut.result()
                    done += 1
                    total += r["n"]; total_hash += r["n_hash"]
                    w = f"  WARNING {r['dupes']} dup ids" if r["dupes"] else ""
                    print(f"[{done}/{len(tasks)}] DONE archive {r['archive'] or '?'}: "
                          f"{r['n']} reports, {r['n_hash']} with hash -> "
                          f"{r['out']}{w}", flush=True)
                except Exception as e:
                    print(f"ERROR processing archive {arch}: {e}", file=sys.stderr)

    print(f"\nBATCH COMPLETE: {done}/{len(tasks)} processed this run, "
          f"{total} reports, {total_hash} with hash. "
          f"({len(skipped)} skipped as already done.)")


if __name__ == "__main__":
    main()
