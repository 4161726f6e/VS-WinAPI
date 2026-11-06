#!/usr/bin/env python3
"""Build the release copy of the bulk tier from the sanitized archives.

For each sanitized/XXXXX.sanitized.tar.gz (00013 and stray files are skipped):
  * drops zero-byte and unparseable reports (they stay listed in the manifest)
  * fills target.file.md5 / sha256 from mappings/mapping_XXXXX.csv where the
    sanitized report lacks them (archives 00002, 00003, parts of 00001/00007)
  * adds a small "dataset" block: {"archive", "report_id"} so every report
    identifies itself without relying on its file name
  * redacts the user-name segment of Windows profile paths (C:\\Users\\<name>\\ ->
    C:\\Users\\<USER>\\) anywhere in the report; these come from the samples, e.g.
    shortcut or quarantine files that recorded the victim machine's paths
  * checks each report: only allowed top-level sections; no Unix home paths, no
    unredacted profile paths, and no --extra-markers words (e.g. your user name)
  * writes release/reports_XXXXX.tar.gz deterministically (input order, mtime 0,
    owner 0), one report at a time so memory stays bounded; reports larger than
    --max-parse-mb are streamed through text-level redaction instead of parsed and records its SHA-256 in release/SHA256SUMS
  * writes release/release_report.txt with counts to reconcile against
    manifest_v2.csv, and release/leak_hits.csv listing any report that matched

Reports with a leak hit are still written unless --exclude-hits is given, so
you can inspect the list first and rerun.

Usage
  python prepare_release.py --sanitized sanitized --mappings mappings --out release ^
      --extra-markers aaron,msi
  python prepare_release.py ... --only 00012          # one archive, for a trial
"""
import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import time

ALLOWED_TOP = {"info", "target", "behavior", "static", "signatures", "dataset"}
# Unix home paths are never expected in a report.
MARKERS = ["/home/", "/media/", "/Users/"]
# Windows user-profile paths: the user-name segment is redacted to <USER> (these
# come from the samples themselves, e.g. a shortcut or quarantine file recording
# the victim's path); any profile path left with a real name is reported.
PROFILE = re.compile(r"(?i)([A-Za-z]:\\+(?:Users|Documents and Settings)\\+)([^\\/\"\r\n]+)")
LEFT_OVER = re.compile(r"(?i)[A-Za-z]:\\+(?:Users|Documents and Settings)\\+(?![\\\"]|<USER>|Public|Default|All Users)")


def redact(obj):
    """Replace user-name segments of Windows profile paths in every string."""
    n = 0
    if isinstance(obj, dict):
        for k, v in obj.items():
            obj[k], c = redact(v)
            n += c
        return obj, n
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i], c = redact(v)
            n += c
        return obj, n
    if isinstance(obj, str) and ("sers" in obj or "ettings" in obj):
        new, c = PROFILE.subn(lambda m: m.group(1) + (m.group(2) if m.group(2).lower() in
                              ("public", "default", "all users", "<user>") else "<USER>"), obj)
        return new, c
    return obj, 0


def load_mapping(path):
    m = {}
    if not os.path.exists(path):
        return m
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            m[row["report_id"]] = (row.get("md5") or "", row.get("sha256") or "")
    return m


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# JSON-escaped form of a Windows profile path, for text-level redaction of reports
# too large to parse: C:\\Users\\name\\  (backslashes doubled inside JSON strings)
PROFILE_JSON = re.compile(r'(?i)([A-Za-z]:(?:\\\\)+(?:Users|Documents and Settings)(?:\\\\)+)([^\\"]+)')
KEEP_NAMES = ("public", "default", "all users", "<user>")


def _redact_json_text(text):
    return PROFILE_JSON.subn(
        lambda m: m.group(1) + (m.group(2) if m.group(2).lower() in KEEP_NAMES else "<USER>"), text)


def write_member(tout, name, path_or_bytes, size):
    ti = tarfile.TarInfo(name)
    ti.size, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.mode = size, 0, 0, 0, "", "", 0o644
    if isinstance(path_or_bytes, bytes):
        tout.addfile(ti, io.BytesIO(path_or_bytes))
    else:
        with open(path_or_bytes, "rb") as fh:
            tout.addfile(ti, fh)


def stream_large(fin, tmp_path, markers, words):
    """Copy a report too large to parse, redacting profile paths and scanning for
    markers in overlapping text chunks. Returns (n_redactions, hits, empty)."""
    import codecs
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    carry, n_red, hits, total = "", 0, [], 0
    keep = 600  # overlap so a path split across chunks is still matched
    with open(tmp_path, "wb") as out:
        while True:
            block = fin.read(16 << 20)
            final = not block
            text = carry + dec.decode(block, final=final)
            total += len(block)
            if final:
                head, carry = text, ""
            else:
                cut = max(0, len(text) - keep)
                # do not cut inside a match: back up to the last quote before the cut
                q = text.rfind('"', 0, cut)
                cut = q if q > 0 else cut
                head, carry = text[:cut], text[cut:]
            head, c = _redact_json_text(head)
            n_red += c
            for mk in markers:
                if mk in head:
                    hits.append(mk)
            if LEFT_OVER.search(head):
                hits.append("unredacted profile path")
            for w in words:
                if w.search(head):
                    hits.append(w.pattern)
            out.write(head.encode("utf-8"))
            if final:
                break
    return n_red, sorted(set(hits)), total == 0


def process_archive(arc, src, mapping, out_path, markers, words, exclude_hits, hits_writer,
                    max_parse_bytes, tmp_dir):
    stats = dict(members=0, empty=0, invalid=0, written=0, hash_filled=0, hash_missing=0,
                 bad_sections=0, profile_redactions=0, reports_redacted=0, leak_hits=0, excluded=0,
                 with_apistats=0, with_calls=0, large_streamed=0)
    tmp_path = os.path.join(tmp_dir, f"_large_{arc}.json")
    raw = open(out_path + ".partial", "wb")
    gz = gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0)
    # Members are processed one at a time in the order they appear in the input
    # archive, so memory use is bounded by the largest report parsed.
    with tarfile.open(src, "r|gz") as tin, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tout:
        for ti in tin:
            if not (ti.isfile() and ti.name.endswith(".json")):
                continue
            stats["members"] += 1
            rid = os.path.basename(ti.name)[:-5]
            name = f"{arc}/{rid}.json"
            if ti.size == 0:
                stats["empty"] += 1
                continue

            if ti.size > max_parse_bytes:
                # Too large to parse safely: stream it through text-level redaction.
                # Hashes are not filled and no dataset block is added; the manifest
                # carries both for these reports.
                n_red, found, _ = stream_large(tin.extractfile(ti), tmp_path, markers, words)
                stats["large_streamed"] += 1
                hits_writer.writerow([arc, rid, "note", f"streamed without parsing ({ti.size:,} bytes)"])
                if n_red:
                    stats["profile_redactions"] += n_red
                    stats["reports_redacted"] += 1
                if found:
                    stats["leak_hits"] += 1
                    for mk in found:
                        hits_writer.writerow([arc, rid, mk, "(large report; inspect manually)"])
                    if exclude_hits:
                        stats["excluded"] += 1
                        continue
                write_member(tout, name, tmp_path, os.path.getsize(tmp_path))
                stats["written"] += 1
                continue

            data = tin.extractfile(ti).read()
            try:
                r = json.loads(data)
                if not isinstance(r, dict):
                    raise ValueError
            except Exception:
                stats["invalid"] += 1
                continue
            del data

            extra = set(r) - ALLOWED_TOP
            if extra:
                stats["bad_sections"] += 1
                hits_writer.writerow([arc, rid, "unexpected sections", ";".join(sorted(extra))])

            tf = r.setdefault("target", {}).setdefault("file", {})
            if not tf.get("md5") or not tf.get("sha256"):
                md5, sha = mapping.get(rid, ("", ""))
                if md5 or sha:
                    tf["md5"] = tf.get("md5") or md5
                    tf["sha256"] = tf.get("sha256") or sha
                    stats["hash_filled"] += 1
            if not tf.get("md5"):
                stats["hash_missing"] += 1
            r["dataset"] = {"archive": arc, "report_id": rid}
            r, n_red = redact(r)
            if n_red:
                stats["profile_redactions"] += n_red
                stats["reports_redacted"] += 1

            beh = r.get("behavior") or {}
            if beh.get("apistats"):
                stats["with_apistats"] += 1
            if any(p.get("calls") for p in beh.get("processes") or [] if isinstance(p, dict)):
                stats["with_calls"] += 1

            out = json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            del r
            text = out.decode("utf-8")
            found = [(mk, text.find(mk)) for mk in markers if mk in text]
            lo = LEFT_OVER.search(text)
            if lo:
                found.append(("unredacted profile path", lo.start()))
            found += [(w.pattern, m.start()) for w in words for m in [w.search(text)] if m]
            if found:
                stats["leak_hits"] += 1
                for mk, i in found:
                    hits_writer.writerow([arc, rid, mk, text[max(0, i - 80): i + len(mk) + 80]])
                if exclude_hits:
                    stats["excluded"] += 1
                    continue
            del text
            write_member(tout, name, out, len(out))
            stats["written"] += 1
            if stats["members"] % 20000 == 0:
                print(f"  {arc}: {stats['members']:,} reports", flush=True)
    gz.close()
    raw.close()
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    os.replace(out_path + ".partial", out_path)
    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sanitized", required=True, help="folder with XXXXX.sanitized.tar.gz")
    ap.add_argument("--mappings", required=True, help="folder with mapping_XXXXX.csv")
    ap.add_argument("--out", default="release")
    ap.add_argument("--extra-markers", default="",
                    help="comma list of words that must not appear, matched as whole words, case-insensitive "
                         "(e.g. your Windows user name, the hosts' and guests' names)")
    ap.add_argument("--exclude-hits", action="store_true", help="leave out reports that match a marker")
    ap.add_argument("--max-parse-mb", type=float, default=256,
                    help="reports larger than this are streamed with text-level redaction instead of parsed")
    ap.add_argument("--only", default="", help="comma list of archives to process")
    a = ap.parse_args()

    markers = MARKERS
    # extra markers match whole words, case-insensitively ("aaron" but not "baaron")
    words = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(m.strip()) + r"(?![A-Za-z0-9])", re.I)
             for m in a.extra_markers.split(",") if m.strip()]
    os.makedirs(a.out, exist_ok=True)
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    srcs = []
    for fn in sorted(os.listdir(a.sanitized)):
        m = re.fullmatch(r"(\d{5})\.sanitized\.tar\.gz", fn)
        if not m or m.group(1) == "00013" or (only and m.group(1) not in only):
            continue
        srcs.append((m.group(1), os.path.join(a.sanitized, fn)))
    if not srcs:
        sys.exit("No XXXXX.sanitized.tar.gz files found.")

    hits_fh = open(os.path.join(a.out, "leak_hits.csv"), "a", newline="", encoding="utf-8")
    hits = csv.writer(hits_fh)
    report_lines = []
    for arc, src in srcs:
        out_path = os.path.join(a.out, f"reports_{arc}.tar.gz")
        if os.path.exists(out_path):
            print(f"{arc}: already built, skipping (delete it to rebuild)")
            continue
        t = time.time()
        print(f"{arc}: processing {src}", flush=True)
        st = process_archive(arc, src, load_mapping(os.path.join(a.mappings, f"mapping_{arc}.csv")),
                             out_path, markers, words, a.exclude_hits, hits,
                             int(a.max_parse_mb * 1024 * 1024), a.out)
        hits_fh.flush()
        line = f"{arc}: " + ", ".join(f"{k}={v:,}" for k, v in st.items()) + f"  ({time.time() - t:.0f}s)"
        print(line, flush=True)
        report_lines.append(line)
    hits_fh.close()

    with open(os.path.join(a.out, "release_report.txt"), "a", encoding="utf-8") as fh:
        fh.write("\n".join(report_lines) + ("\n" if report_lines else ""))
    with open(os.path.join(a.out, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        for fn in sorted(os.listdir(a.out)):
            if fn.startswith("reports_") and fn.endswith(".tar.gz"):
                fh.write(f"{sha256_file(os.path.join(a.out, fn))}  {fn}\n")
    print(f"\nWrote {a.out}/SHA256SUMS, release_report.txt, leak_hits.csv")


if __name__ == "__main__":
    main()
