#!/usr/bin/env python3
"""List every sanitized report containing a path-leak marker, with context.

audit_and_manifest.py counted 8 such reports but printed only the first 200
issues (all "no sample hash"), so the 8 were never shown. This prints each one
with the surrounding text so you can decide whether it is a real leak (the
analysis host's or guest's own path) or a harmless string the sample used
(e.g. a generic "C:\\Users\\" inside a registry value).

Works on a folder of .json/.json.gz reports or on .tar.gz archives of them.

  python find_leaks.py "D:\\API research data\\!new\\sanitized"
"""
import gzip
import os
import sys
import tarfile

MARKERS = ("/home/", "/media/", "C:\\Users\\", "C:\\\\Users\\\\", "\\AppData\\",
           "\\\\AppData\\\\", "/Users/", "\\Users\\")
CONTEXT = 120


def check(name, text):
    hits = 0
    for mark in MARKERS:
        start = 0
        while True:
            i = text.find(mark, start)
            if i < 0:
                break
            snippet = text[max(0, i - CONTEXT): i + len(mark) + CONTEXT].replace("\n", " ")
            print(f"\n[{name}] marker {mark!r} at {i}:\n  ...{snippet}...")
            hits += 1
            start = i + 1
            if hits >= 5:
                print("  (more hits in this report omitted)")
                return hits
    return hits


def main(root):
    n_files = n_hit = 0
    for dirpath, _, files in os.walk(root):
        for fn in sorted(files):
            path = os.path.join(dirpath, fn)
            if fn.endswith((".tar.gz", ".tgz", ".tar")):
                with tarfile.open(path) as tf:
                    for member in tf:
                        if not member.isfile() or not member.name.endswith((".json", ".json.gz")):
                            continue
                        data = tf.extractfile(member).read()
                        if member.name.endswith(".gz"):
                            data = gzip.decompress(data)
                        n_files += 1
                        if check(f"{fn}:{member.name}", data.decode("utf-8", "replace")):
                            n_hit += 1
            elif fn.endswith((".json", ".json.gz")):
                opener = gzip.open if fn.endswith(".gz") else open
                with opener(path, "rb") as f:
                    data = f.read()
                n_files += 1
                if check(path, data.decode("utf-8", "replace")):
                    n_hit += 1
            if n_files and n_files % 100000 == 0:
                print(f"  scanned {n_files:,} reports", file=sys.stderr, flush=True)
    print(f"\nScanned {n_files:,} reports; {n_hit} contain a marker.")


if __name__ == "__main__":
    main(sys.argv[1].strip().strip('"'))
