#!/usr/bin/env python3
"""
profile_corpus.py (v2) - Descriptive statistics over Cuckoo JSON reports.

Reads reports from ANY of:
  * a .tar.gz / .tgz / .tar archive (streamed, no extraction needed)
  * a directory of *.json files (recursively)
  * one or more explicit file paths

and accepts MULTIPLE inputs at once (e.g. all 14 archives in one run).

Usage:
    python3 profile_corpus.py <input> [<input> ...] [--out stats.json]
    python3 profile_corpus.py "D:\\API research data\\VirusShare_00010\\09252024_0841.tar.gz" --out corpus_stats_1.json
    python3 profile_corpus.py archive1.tar.gz archive2.tar.gz --out merged.json
    python3 profile_corpus.py ./reports_dir --out stats.json

Success criterion (reported alongside the raw counts):
  A report counts as a SUCCESSFUL analysis when it
    (1) parses as valid JSON,
    (2) has a non-empty behavior.processes list, and
    (3) records at least --min-calls API calls across >= --min-apis unique APIs.
  Defaults: --min-calls 1, --min-apis 4  (tune to taste; see paper methodology).

Output: a JSON summary (same shape as before, plus success/failure fields) and a
printed human-readable report.
"""
import json, os, sys, argparse, statistics, tarfile, glob as globmod
from collections import Counter


# ----------------------------- input iteration ----------------------------- #
def iter_inputs(inputs):
    """Yield (name, size_bytes, raw_bytes_or_None, error_or_None) for each report.

    raw_bytes is the undecoded JSON content; size_bytes is the stored/extracted
    size. For unreadable members we yield an error string.
    """
    for inp in inputs:
        low = inp.lower()
        if low.endswith((".tar.gz", ".tgz", ".tar")):
            yield from _iter_tar(inp)
        elif os.path.isdir(inp):
            yield from _iter_dir(inp)
        elif os.path.isfile(inp) and low.endswith(".json"):
            try:
                with open(inp, "rb") as fh:
                    data = fh.read()
                yield (os.path.basename(inp), len(data), data, None)
            except Exception as e:
                yield (os.path.basename(inp), 0, None, str(e)[:120])
        else:
            print(f"WARNING: input not recognized (not tar/dir/.json): {inp}",
                  file=sys.stderr)


def _iter_tar(path):
    mode = "r:gz" if path.lower().endswith((".tar.gz", ".tgz")) else "r:*"
    try:
        tf = tarfile.open(path, mode)
    except Exception as e:
        print(f"ERROR: cannot open archive {path}: {e}", file=sys.stderr)
        return
    with tf:
        for member in tf:
            if not member.isfile():
                continue
            name = os.path.basename(member.name)
            if not name.lower().endswith(".json"):
                # some archives store reports without .json extension; include
                # all regular files but flag non-json by trying to parse later.
                pass
            try:
                f = tf.extractfile(member)
                if f is None:
                    yield (name, member.size, None, "not extractable")
                    continue
                data = f.read()
                yield (name, member.size, data, None)
            except Exception as e:
                yield (name, member.size, None, str(e)[:120])


def _iter_dir(d):
    for p in globmod.iglob(os.path.join(d, "**", "*.json"), recursive=True):
        try:
            with open(p, "rb") as fh:
                data = fh.read()
            yield (os.path.basename(p), len(data), data, None)
        except Exception as e:
            yield (os.path.basename(p), 0, None, str(e)[:120])


# ----------------------------- analysis helpers ---------------------------- #
def report_api_counts(d):
    """(unique_api_set, total_calls) from apistats if present, else processes."""
    uniq, total = set(), 0
    b = d.get("behavior", {}) if isinstance(d, dict) else {}
    api = b.get("apistats") if isinstance(b, dict) else None
    if isinstance(api, dict) and api:
        for _pid, calls in api.items():
            if isinstance(calls, dict):
                uniq.update(calls.keys())
                total += sum(v for v in calls.values() if isinstance(v, int))
        if uniq:
            return uniq, total
    if isinstance(b, dict):
        for p in b.get("processes", []) or []:
            for c in (p.get("calls", []) or []):
                a = c.get("api")
                if a:
                    uniq.add(a)
                    total += 1
    return uniq, total


def dist(vals):
    if not vals:
        return {}
    vals = sorted(vals)
    return {"min": vals[0], "max": vals[-1],
            "mean": round(statistics.mean(vals), 1),
            "median": statistics.median(vals),
            "p90": vals[int(0.9 * (len(vals) - 1))]}


# ----------------------------------- main ---------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+",
                    help="tar.gz archive(s), directory(ies), or .json file(s)")
    ap.add_argument("--out", default="corpus_stats.json")
    ap.add_argument("--min-calls", type=int, default=1,
                    help="min API calls for a SUCCESSFUL analysis")
    ap.add_argument("--min-apis", type=int, default=4,
                    help="min unique APIs for a SUCCESSFUL analysis")
    ap.add_argument("--progress", type=int, default=5000,
                    help="print progress every N reports (0 to disable)")
    args = ap.parse_args()

    SENSITIVE = ["strings", "dropped", "buffer", "procmemory", "extracted",
                 "screenshots", "static", "network", "debug", "virustotal"]

    n = parsed = 0
    parse_errors = []
    sizes = []
    calls_list, uniq_list, proc_list = [], [], []
    toplevel_presence = Counter()
    behavior_presence = Counter()
    sensitive_presence = Counter()
    corpus_api_freq = Counter()
    corpus_api_docfreq = Counter()
    n_success = 0
    n_empty = 0
    failure_reasons = Counter()

    for name, size, raw, err in iter_inputs(args.inputs):
        n += 1
        sizes.append(size)
        if args.progress and n % args.progress == 0:
            print(f"  ...{n} reports scanned ({parsed} parsed OK)",
                  file=sys.stderr)

        if err is not None:
            parse_errors.append({"file": name, "size": size, "error": err})
            failure_reasons["unreadable"] += 1
            continue
        try:
            d = json.loads(raw)
        except Exception as e:
            parse_errors.append({"file": name, "size": size,
                                 "error": str(e)[:120]})
            failure_reasons["parse_fail"] += 1
            continue

        parsed += 1
        if isinstance(d, dict):
            for k in d.keys():
                toplevel_presence[k] += 1
            b = d.get("behavior", {})
            if isinstance(b, dict):
                for k in b.keys():
                    behavior_presence[k] += 1
            for s in SENSITIVE:
                if s in d:
                    sensitive_presence[s] += 1

        uniq, total = report_api_counts(d)
        n_proc = len(d.get("behavior", {}).get("processes", []) or []) \
            if isinstance(d, dict) and isinstance(d.get("behavior"), dict) else 0
        calls_list.append(total)
        uniq_list.append(len(uniq))
        proc_list.append(n_proc)
        for a in uniq:
            corpus_api_docfreq[a] += 1
        b = d.get("behavior", {}) if isinstance(d, dict) else {}
        api = b.get("apistats") if isinstance(b, dict) else None
        if isinstance(api, dict):
            for _pid, calls in api.items():
                if isinstance(calls, dict):
                    for a, c in calls.items():
                        if isinstance(c, int):
                            corpus_api_freq[a] += c

        # success / failure classification
        if n_proc >= 1 and total >= args.min_calls and len(uniq) >= args.min_apis:
            n_success += 1
        else:
            if total == 0 or len(uniq) <= 3:
                n_empty += 1
            if n_proc < 1:
                failure_reasons["no_processes"] += 1
            elif total < args.min_calls:
                failure_reasons["too_few_calls"] += 1
            elif len(uniq) < args.min_apis:
                failure_reasons["too_few_unique_apis"] += 1

    summary = {
        "inputs": args.inputs,
        "success_criterion": {"min_calls": args.min_calls,
                              "min_apis": args.min_apis,
                              "rule": "valid JSON AND >=1 process AND "
                                      ">=min_calls calls AND >=min_apis unique APIs"},
        "n_files": n,
        "n_parsed_ok": parsed,
        "n_parse_errors": len(parse_errors),
        "n_successful_analyses": n_success,
        "success_rate_of_parsed": round(100 * n_success / parsed, 2) if parsed else 0,
        "n_empty_or_near_empty": n_empty,
        "failure_reasons": dict(failure_reasons),
        "parse_errors_sample": parse_errors[:50],
        "n_parse_errors_total": len(parse_errors),
        "size_bytes": dist(sizes),
        "total_size_bytes": sum(sizes),
        "calls_per_report": dist(calls_list),
        "unique_apis_per_report": dist(uniq_list),
        "processes_per_report": dist(proc_list),
        "corpus_unique_api_count": len(corpus_api_docfreq),
        "toplevel_section_presence": dict(toplevel_presence),
        "behavior_section_presence": dict(behavior_presence),
        "sensitive_section_presence": dict(sensitive_presence),
        "top_30_apis_by_total_calls": corpus_api_freq.most_common(30),
        "top_30_apis_by_doc_frequency": corpus_api_docfreq.most_common(30),
    }
    with open(args.out, "w") as fh:
        json.dump(summary, fh, indent=2)

    print(f"REPORTS: {n} files, {parsed} parsed OK, {len(parse_errors)} parse/read errors")
    print(f"TOTAL SIZE: {sum(sizes)/1e9:.2f} GB")
    print(f"SUCCESSFUL ANALYSES: {n_success} "
          f"({summary['success_rate_of_parsed']}% of parsed) "
          f"[criterion: >=1 proc, >={args.min_calls} calls, >={args.min_apis} APIs]")
    print(f"EMPTY/NEAR-EMPTY: {n_empty}")
    print(f"FAILURE REASONS: {dict(failure_reasons)}")
    print(f"CORPUS-WIDE UNIQUE APIs: {summary['corpus_unique_api_count']}")
    print(f"SIZE/report bytes: {summary['size_bytes']}")
    print(f"CALLS/report: {summary['calls_per_report']}")
    print(f"UNIQUE APIs/report: {summary['unique_apis_per_report']}")
    if parse_errors:
        print(f"\nFirst few parse/read errors:")
        for e in parse_errors[:5]:
            print(f"  {e['file']} ({e['size']:,} B): {e['error']}")
    print(f"\nTOP 15 APIs BY TOTAL CALLS:")
    for a, c in corpus_api_freq.most_common(15):
        print(f"  {a}: {c:,}")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
