#!/usr/bin/env python3
"""
sanitize_report.py - Convert a raw Cuckoo 2.x JSON report into a clean,
release-ready behavioral record suitable for public distribution.

Design goals
------------
1. Keep the research signal: ordered API call sequences + per-process API
   frequency, the behavioral features used across the author's prior work.
2. Remove sample-reconstruction risk: drop raw strings, dropped-file blobs,
   process-memory dumps, extracted secondary payloads, buffers, screenshots.
3. Remove environment leakage: strip absolute host paths, machine/owner IDs,
   analyst-identifying fields, and rewrite any local analysis paths.
4. Preserve provenance: keep sample hashes (so vetted researchers can
   re-source the original binary from VirusShare) and sandbox config metadata
   needed for reproducibility.

Usage
-----
    python3 sanitize_report.py <in_dir> <out_dir> [--keep-args] [--manifest manifest.csv]

By default, API-call `arguments` are DROPPED (smallest, safest output). Use
--keep-args to retain a whitelisted, path-scrubbed subset of arguments.

Output: one <name>.json per input report containing only release-safe fields,
plus a manifest CSV row per sample (hashes, label placeholder, counts, flags).
"""
import json, os, glob, sys, argparse, csv, re

# ---- sections removed entirely (sample-reconstruction or env-leak risk) ----
DROP_TOPLEVEL = {
    "strings",       # raw extracted strings -> can embed payload/URLs/creds
    "dropped",       # dropped-file metadata/content -> secondary payloads
    "buffer",        # captured buffers -> payload fragments
    "procmemory",    # process memory dumps + extracted PEs
    "extracted",     # extracted scripts/PEs (host paths + payloads)
    "screenshots",   # VM screenshots
    "debug",         # dbgview/log/errors -> host paths + env detail
    "metadata",      # cuckoo output file paths
}

# Argument keys safe to keep when --keep-args is set. Everything not listed is
# dropped. We deliberately exclude filepath/buffer/handle/address-style fields.
ARG_WHITELIST = {
    "regkey", "regkey_r", "key_name",
    "protection", "allocation_type",
    "region_size", "size", "length",
    "access", "desired_access", "share_access",
    "creation_flags", "flags", "process_name",
    "socket_type", "protocol", "port",  # network *type* info, not endpoints
    "status_info", "control_code",
}

# Patterns that indicate an absolute host (Linux) path we should not publish.
HOST_PATH_RE = re.compile(r"(/media/|/home/|/mnt/)")

# User-specific Windows path segments inside registry keys / args. We normalise
# rather than drop, because registry *structure* is research-relevant but the
# embedded VM username / SID is environment-identifying noise.
USER_PROFILE_RE = re.compile(r"(\\Users\\|/Users/)[^\\/]+", re.IGNORECASE)
SID_RE = re.compile(r"S-1-5-21-[\d-]+")
DOCS_SETTINGS_RE = re.compile(r"(Documents and Settings\\)[^\\]+", re.IGNORECASE)


def scrub_value(v):
    """Normalise host paths and user-specific segments inside string values."""
    if not isinstance(v, str):
        return v
    if HOST_PATH_RE.search(v):
        return "<path-redacted>"
    v = USER_PROFILE_RE.sub(r"\1<user>", v)
    v = DOCS_SETTINGS_RE.sub(r"\1<user>", v)
    v = SID_RE.sub("S-1-5-21-<sid>", v)
    return v


def clean_info(info):
    """Keep only reproducibility-relevant, non-identifying config fields."""
    if not isinstance(info, dict):
        return {}
    keep = {}
    for k in ("duration", "score", "category", "package", "route",
              "platform", "version", "monitor"):
        if k in info:
            keep[k] = info[k]
    # machine: keep only platform/manager label, drop name/label/ip
    m = info.get("machine")
    if isinstance(m, dict):
        keep["machine"] = {k: m[k] for k in ("platform", "manager") if k in m}
    # explicitly NOT kept: owner, id, added/started/ended timestamps, git, custom
    return keep


def clean_target(target):
    """Keep hashes + size + type; drop local path and name-embedded host info."""
    if not isinstance(target, dict):
        return {}
    f = target.get("file", {}) if isinstance(target, dict) else {}
    out = {"category": target.get("category")}
    keep_file = {}
    for k in ("md5", "sha1", "sha256", "sha512", "ssdeep", "crc32", "size", "type"):
        if k in f:
            keep_file[k] = f[k]
    # keep the VirusShare_<md5> name (provenance) but not the local path
    nm = f.get("name")
    if isinstance(nm, str) and nm.startswith("VirusShare_"):
        keep_file["name"] = nm
    out["file"] = keep_file
    return out


def clean_static(static):
    """Optional static features: keep structural PE info, drop resource blobs."""
    if not isinstance(static, dict):
        return None
    keep = {}
    for k in ("pe_imphash", "imported_dll_count", "pe_timestamp",
              "peid_signatures"):
        if k in static:
            keep[k] = static[k]
    # imports: keep DLL + imported function NAMES only (structure, not data)
    imports = static.get("pe_imports")
    if isinstance(imports, list):
        slim = []
        for imp in imports:
            if isinstance(imp, dict):
                dll = imp.get("dll")
                names = [i.get("name") for i in imp.get("imports", [])
                         if isinstance(i, dict) and i.get("name")]
                slim.append({"dll": dll, "imports": names})
        keep["pe_imports"] = slim
    # sections: keep name/size/entropy, drop raw data
    secs = static.get("pe_sections")
    if isinstance(secs, list):
        keep["pe_sections"] = [
            {k: s.get(k) for k in ("name", "size_of_data", "entropy",
                                   "virtual_size") if k in s}
            for s in secs if isinstance(s, dict)
        ]
    return keep or None


def clean_call(call, keep_args):
    """Slim a single API call entry to behavior-relevant fields."""
    out = {
        "api": call.get("api"),
        "category": call.get("category"),
        "status": call.get("status"),
        "return_value": call.get("return_value"),
        "time": call.get("time"),
        "tid": call.get("tid"),
    }
    if keep_args:
        args = call.get("arguments", {})
        if isinstance(args, dict):
            kept = {}
            for k, v in args.items():
                if k in ARG_WHITELIST:
                    kept[k] = scrub_value(v)
            if kept:
                out["arguments"] = kept
    return out


def clean_behavior(behavior, keep_args):
    """Keep apistats (frequency) + slimmed ordered call sequences + processtree."""
    if not isinstance(behavior, dict):
        return {}
    out = {}
    if isinstance(behavior.get("apistats"), dict):
        out["apistats"] = behavior["apistats"]          # per-PID api->count
    if isinstance(behavior.get("processtree"), list):
        # keep structure but scrub command lines / paths
        def slim_tree(node):
            if not isinstance(node, dict):
                return None
            n = {k: node.get(k) for k in ("pid", "ppid", "process_name", "track")
                 if k in node}
            ch = node.get("children")
            if isinstance(ch, list):
                n["children"] = [slim_tree(c) for c in ch]
            return n
        out["processtree"] = [slim_tree(x) for x in behavior["processtree"]]
    procs_out = []
    for p in behavior.get("processes", []) or []:
        if not isinstance(p, dict):
            continue
        po = {k: p.get(k) for k in ("pid", "ppid", "process_name", "track",
                                    "first_seen") if k in p}
        calls = p.get("calls", []) or []
        po["calls"] = [clean_call(c, keep_args) for c in calls]
        po["n_calls"] = len(calls)
        procs_out.append(po)
    out["processes"] = procs_out
    return out


def sanitize(d, keep_args):
    out = {}
    out["info"] = clean_info(d.get("info", {}))
    out["target"] = clean_target(d.get("target", {}))
    st = clean_static(d.get("static"))
    if st:
        out["static"] = st
    out["behavior"] = clean_behavior(d.get("behavior", {}), keep_args)
    # signatures: keep name/description/severity, drop matched data marks
    sigs = d.get("signatures")
    if isinstance(sigs, list):
        out["signatures"] = [
            {k: s.get(k) for k in ("name", "description", "severity")
             if k in s}
            for s in sigs if isinstance(s, dict)
        ]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("in_dir")
    ap.add_argument("out_dir")
    ap.add_argument("--keep-args", action="store_true",
                    help="retain whitelisted, path-scrubbed call arguments")
    ap.add_argument("--manifest", default="manifest.csv")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    files = glob.glob(os.path.join(args.in_dir, "*.json"))

    rows = []
    n_ok = n_fail = 0
    in_bytes = out_bytes = 0
    for f in files:
        name = os.path.basename(f)
        in_bytes += os.path.getsize(f)
        try:
            d = json.load(open(f))
        except Exception as e:
            n_fail += 1
            rows.append({"file": name, "status": "PARSE_FAIL",
                         "error": str(e)[:80], "sha256": "", "md5": "",
                         "n_proc": "", "n_calls": "", "label": ""})
            continue
        clean = sanitize(d, args.keep_args)
        outpath = os.path.join(args.out_dir, name)
        txt = json.dumps(clean, separators=(",", ":"))
        open(outpath, "w").write(txt)
        out_bytes += len(txt)
        n_ok += 1

        tf = clean.get("target", {}).get("file", {})
        n_calls = sum(p.get("n_calls", 0) for p in clean["behavior"].get("processes", []))
        rows.append({
            "file": name, "status": "OK", "error": "",
            "sha256": tf.get("sha256", ""), "md5": tf.get("md5", ""),
            "n_proc": len(clean["behavior"].get("processes", [])),
            "n_calls": n_calls,
            "label": "",   # to be filled by labeling pipeline (VT/AVClass)
        })

    with open(args.manifest, "w", newline="") as mf:
        w = csv.DictWriter(mf, fieldnames=["file", "status", "error", "sha256",
                                           "md5", "n_proc", "n_calls", "label"])
        w.writeheader()
        w.writerows(rows)

    print(f"Sanitized {n_ok} reports, {n_fail} parse failures.")
    print(f"Input:  {in_bytes/1e9:.3f} GB")
    print(f"Output: {out_bytes/1e9:.3f} GB  ({100*out_bytes/max(in_bytes,1):.1f}% of input)")
    print(f"Manifest: {args.manifest}")


if __name__ == "__main__":
    main()
