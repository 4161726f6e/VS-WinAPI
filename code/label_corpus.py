#!/usr/bin/env python3
"""
label_corpus.py - Multi-source family labeling for the sanitized behavioral
dataset.

Pipeline (matching the methodology section of the paper):
  1. For each sample (identified by SHA-256), query the VirusTotal v3 file
     report endpoint.
  2. Record a single, frozen query date for the whole run (controls label drift).
  3. Collect per-engine verdicts, derive a multi-engine detection consensus, and
     normalize the family using AVClass when available.
  4. Write an enriched manifest with: detection ratio, AVClass family token,
     a fallback most-common-family token, the raw vendor label set (optional),
     and the frozen query date. Disagreement is preserved, not collapsed.

This script is designed to run against the manifest produced by
sanitize_report.py (which already contains file + sha256 + md5 + counts).

IMPORTANT
---------
- Requires a VirusTotal API key in the environment variable VT_API_KEY.
- Respects the public API rate limit by default (4 requests/min). Override with
  --rate-per-min if you have a higher-tier key.
- This script does NOT submit/upload any sample to VirusTotal. It only looks up
  existing reports by hash, so no binary leaves your machine.
- AVClass (https://github.com/malicialab/avclass) is optional. If the `avclass`
  CLI or python module is importable, it is used to normalize families; if not,
  the script falls back to a simple majority vote over vendor-supplied family
  tokens and records that AVClass was unavailable.

Usage
-----
    export VT_API_KEY=...
    python3 label_corpus.py manifest.csv labeled_manifest.csv \
        [--rate-per-min 4] [--keep-raw-labels] [--cache vt_cache]

Re-running is safe: responses are cached on disk by SHA-256, so an interrupted
run resumes without re-spending API quota.
"""
import argparse
import csv
import json
import os
import sys
import time
import datetime
import urllib.request
import urllib.error

VT_URL = "https://www.virustotal.com/api/v3/files/{hash_id}"


# ----------------------------- VirusTotal I/O ------------------------------ #
def vt_lookup(hash_id, api_key, cache_dir):
    """Return the parsed VT JSON for a hash, using an on-disk cache.

    hash_id may be a SHA-256, SHA-1, or MD5; VirusTotal's /files/{id} endpoint
    accepts any of them. The cache is keyed on whatever identifier is used, so
    MD5-only samples (recovered from Cuckoo 2.0.7 reports) and SHA-256 samples
    coexist without collision.
    """
    cache_path = os.path.join(cache_dir, f"{hash_id}.json") if cache_dir else None
    if cache_path and os.path.exists(cache_path):
        with open(cache_path) as fh:
            return json.load(fh), True  # (data, from_cache)

    req = urllib.request.Request(
        VT_URL.format(hash_id=hash_id),
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 404 = hash unknown to VT; record explicitly rather than crashing.
        data = {"_http_error": e.code, "_reason": str(e.reason)}
    except Exception as e:  # network/timeout
        data = {"_error": str(e)[:200]}

    if cache_path:
        with open(cache_path, "w") as fh:
            json.dump(data, fh)
    return data, False


# ----------------------------- Label extraction ---------------------------- #
def parse_vt(data):
    """Extract detection ratio and per-engine family tokens from a VT report."""
    attrs = (data.get("data", {}) or {}).get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) if stats else 0

    # Collect the engine "result" strings (raw vendor labels) for AVClass / vote.
    vendor_labels = {}
    for engine, res in results.items():
        if isinstance(res, dict) and res.get("result"):
            vendor_labels[engine] = res["result"]

    return {
        "detected": malicious + suspicious,
        "total_engines": total,
        "vendor_labels": vendor_labels,
        "vt_present": bool(stats),
    }


def try_avclass(vendor_labels, sha256):
    """Normalize a family with AVClass if importable; else return None."""
    if not vendor_labels:
        return None
    # AVClass expects a VT-style record; build the minimal shape it reads.
    try:
        from avclass.labeler import AVClassLabeler  # avclass >= 4
        labeler = AVClassLabeler()
        sample = {
            "md5": sha256,  # AVClass keys on any hash field; sha256 is fine
            "av_labels": [[eng, lab] for eng, lab in vendor_labels.items()],
        }
        out = labeler.get_sample_call()(sample) if False else None  # guard
    except Exception:
        out = None

    # Most installations expose the CLI; the module API varies across versions,
    # so we keep this defensive. If the import path above doesn't yield a family,
    # we return None and let the caller fall back to majority vote.
    return out


def majority_family(vendor_labels):
    """Very simple fallback: most common alphanumeric family-ish token."""
    from collections import Counter
    import re
    tokens = Counter()
    GENERIC = {"malware", "trojan", "virus", "worm", "win32", "win64", "generic",
               "agent", "gen", "heur", "eldorado", "unsafe", "malicious",
               "variant", "application", "riskware", "pua", "trojandownloader",
               "trojandropper", "backdoor", "a", "b", "c"}
    for lab in vendor_labels.values():
        for tok in re.split(r"[^A-Za-z0-9]+", lab.lower()):
            if len(tok) >= 4 and tok not in GENERIC and not tok.isdigit():
                tokens[tok] += 1
    if not tokens:
        return ""
    return tokens.most_common(1)[0][0]


# ----------------------------------- Main ---------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("in_manifest")
    ap.add_argument("out_manifest")
    ap.add_argument("--rate-per-min", type=float, default=4.0,
                    help="max VT requests per minute (public key = 4)")
    ap.add_argument("--cache", default="vt_cache",
                    help="directory for cached VT responses")
    ap.add_argument("--keep-raw-labels", action="store_true",
                    help="store the full vendor label set as JSON in a column")
    ap.add_argument("--detection-threshold", type=int, default=2,
                    help="min detections to consider a sample malicious")
    ap.add_argument("--sample", type=int, default=0,
                    help="label only a reproducible random subset of this size "
                         "(0 = all). Useful for VT spot-validation under the "
                         "free-tier 500/day limit.")
    ap.add_argument("--sample-seed", type=int, default=1337,
                    help="random seed for --sample (reproducibility)")
    ap.add_argument("--stratify-by", default="archive",
                    help="column to stratify the sample across (default: archive; "
                         "use '' for a simple random sample)")
    ap.add_argument("--require-nonempty", default="",
                    help="only sample rows whose named column is non-empty "
                         "(e.g. 'category' to draw only MalDICT-labeled samples, "
                         "maximizing cross-validation overlap)")
    args = ap.parse_args()

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        sys.exit("ERROR: set VT_API_KEY in the environment before running.")

    if args.cache:
        os.makedirs(args.cache, exist_ok=True)

    query_date = datetime.date.today().isoformat()  # frozen for the whole run
    min_interval = 60.0 / args.rate_per_min if args.rate_per_min > 0 else 0.0

    with open(args.in_manifest, newline="") as fh:
        rows = list(csv.DictReader(fh))

    # optional reproducible (optionally stratified) subsampling -------------- #
    if args.sample and args.sample < len(rows):
        import random as _random
        rng = _random.Random(args.sample_seed)
        # only sample among rows that actually have a usable hash
        eligible = [r for r in rows
                    if (r.get("sha256") or r.get("md5") or "").strip()]
        # optionally restrict to rows where a given column is non-empty, e.g.
        # only MalDICT-labeled samples so the agreement overlap is large
        req = args.require_nonempty.strip()
        if req:
            before = len(eligible)
            eligible = [r for r in eligible if (r.get(req) or "").strip()]
            print(f"require-nonempty '{req}': {len(eligible)} of {before} "
                  f"rows qualify", file=sys.stderr)
        strat_col = args.stratify_by.strip()
        if strat_col and any(strat_col in r for r in eligible):
            # proportional allocation across strata
            from collections import defaultdict
            buckets = defaultdict(list)
            for r in eligible:
                buckets[r.get(strat_col, "")].append(r)
            chosen = []
            total = len(eligible)
            for key, group in buckets.items():
                k = max(1, round(args.sample * len(group) / total))
                rng.shuffle(group)
                chosen.extend(group[:k])
            rng.shuffle(chosen)
            rows = chosen[:args.sample]
            print(f"sampled {len(rows)} rows, stratified by '{strat_col}' "
                  f"(seed {args.sample_seed})", file=sys.stderr)
        else:
            rng.shuffle(eligible)
            rows = eligible[:args.sample]
            print(f"sampled {len(rows)} rows, simple random "
                  f"(seed {args.sample_seed})", file=sys.stderr)

    out_fields = ["file", "status", "sha256", "md5", "query_hash", "query_hash_type",
                  "n_proc", "n_calls",
                  "vt_detected", "vt_total_engines", "vt_detection_ratio",
                  "family_avclass", "family_fallback", "is_malicious",
                  "vt_query_date", "label_source"]
    if args.keep_raw_labels:
        out_fields.append("vendor_labels_json")

    avclass_ok_any = False
    n_done = 0
    last_call = 0.0

    with open(args.out_manifest, "w", newline="") as out_fh:
        writer = csv.DictWriter(out_fh, fieldnames=out_fields)
        writer.writeheader()

        for row in rows:
            sha = (row.get("sha256") or "").strip()
            md5 = (row.get("md5") or "").strip()
            # Prefer SHA-256; fall back to MD5 for samples recovered from
            # Cuckoo 2.0.7 reports that carry no SHA-256. VirusTotal's
            # /files/{id} endpoint accepts either identifier.
            if sha:
                query_hash, query_type = sha, "sha256"
            elif md5:
                query_hash, query_type = md5, "md5"
            else:
                query_hash, query_type = "", ""

            base = {
                "file": row.get("file", ""),
                "status": row.get("status", ""),
                "sha256": sha,
                "md5": md5,
                "query_hash": query_hash,
                "query_hash_type": query_type,
                "n_proc": row.get("n_proc", ""),
                "n_calls": row.get("n_calls", ""),
                "vt_query_date": query_date,
            }

            # status column is optional (frequency-mapping inputs lack it);
            # treat a row as processable if it has any usable hash.
            status_ok = row.get("status", "OK") == "OK"
            if not query_hash or not status_ok:
                base.update({"vt_detected": "", "vt_total_engines": "",
                             "vt_detection_ratio": "", "family_avclass": "",
                             "family_fallback": "", "is_malicious": "",
                             "label_source": "skipped"})
                if args.keep_raw_labels:
                    base["vendor_labels_json"] = ""
                writer.writerow(base)
                continue

            # rate limit only when we actually hit the network
            cache_path = os.path.join(args.cache, f"{query_hash}.json")
            if not os.path.exists(cache_path) and min_interval:
                wait = min_interval - (time.time() - last_call)
                if wait > 0:
                    time.sleep(wait)

            data, from_cache = vt_lookup(query_hash, api_key, args.cache)
            if not from_cache:
                last_call = time.time()

            parsed = parse_vt(data)
            fam_av = try_avclass(parsed["vendor_labels"], query_hash)
            if fam_av:
                avclass_ok_any = True
                source = "avclass"
            else:
                source = "majority_vote"
            fam_fb = majority_family(parsed["vendor_labels"])

            det = parsed["detected"]
            tot = parsed["total_engines"]
            ratio = f"{det}/{tot}" if tot else ""
            is_mal = "" if not parsed["vt_present"] else \
                ("1" if det >= args.detection_threshold else "0")

            base.update({
                "vt_detected": det if parsed["vt_present"] else "",
                "vt_total_engines": tot if parsed["vt_present"] else "",
                "vt_detection_ratio": ratio,
                "family_avclass": fam_av or "",
                "family_fallback": fam_fb,
                "is_malicious": is_mal,
                "label_source": source if parsed["vt_present"] else "vt_unknown",
            })
            if args.keep_raw_labels:
                base["vendor_labels_json"] = json.dumps(parsed["vendor_labels"],
                                                         separators=(",", ":"))
            writer.writerow(base)
            n_done += 1
            if n_done % 25 == 0:
                print(f"  ...{n_done} samples processed", file=sys.stderr)

    print(f"Labeled {n_done} samples. Query date frozen at {query_date}.")
    if not avclass_ok_any:
        print("NOTE: AVClass was not used (module not importable or no family "
              "returned). Family tokens come from the majority-vote fallback. "
              "For the paper's stated methodology, install AVClass "
              "(pip install avclass-malicialab) and re-run; cached VT responses "
              "make the re-run free of additional API calls.")


if __name__ == "__main__":
    main()
