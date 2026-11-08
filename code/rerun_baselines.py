#!/usr/bin/env python3
"""Re-run the reference experiments on SUCCESSFUL, labeled reports only.

The original baseline_classifier.py joined every frequency row to a label without
checking the success flag, so about half of its 185,732 samples were reports with
no captured behavior (all-zero vectors). This script restricts to manifest
success == 1 and runs:

  A. baseline   : majority class, logistic regression, random forest (same settings
                  as baseline_classifier.py), stratified 80/20 split
  B. scale      : random forest trained on 1/5/10/25/50/100% of the same training
                  split, evaluated on the same test split
  C. archive    : train on archives 00000-00004 (00003 is a copy of 00002), test on
                  00005-00007, vs a random
                  split of the same sizes

Inputs
  --freq-dir   folder of freq_XXXXX.csv (first column report_id, then one column per API)
  --manifest   manifest_v3.csv (archive, report_id, md5, success, category,
               source_archive); with an older manifest, also pass --labels
  --labels     corpus_category_labeled.csv (archive, report_id, category, label_source)

Example
  python rerun_baselines.py --freq-dir freq_clean --manifest manifest_v3.csv --out rerun_results.json
"""
import argparse
import glob
import json
import os
import gc
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split


def load(a):
    man = pd.read_csv(a.manifest, dtype=str, low_memory=False)
    if "source_archive" not in man:
        man["source_archive"] = man["archive"]
    if "category" in man and not a.labels:
        df = man[man.category.notna()].copy()
    else:
        lab = pd.read_csv(a.labels, dtype=str, usecols=["archive", "report_id", "category", "label_source"])
        lab = lab[(lab.label_source == "maldict") & lab.category.notna() & (lab.archive != "00013")]
        df = man.drop(columns=["category"], errors="ignore").merge(
            lab[["archive", "report_id", "category"]], on=["archive", "report_id"])
    df = df[(df.success == "1") & (df.archive != "00013")]
    # de-duplicate by sample hash (keep first), so no sample is in both train and test
    key = df.md5.fillna(df.archive + ":" + df.report_id)
    df = df.loc[~key.duplicated()].copy()
    counts = df.category.value_counts()
    keep = counts[counts >= a.min_support].index
    dropped = sorted(set(counts.index) - set(keep))
    df = df[df.category.isin(keep)]
    # frequency rows are looked up in the archive whose copy of the report is used
    # Frequency rows are looked up in the archive whose copy of the report is used.
    # In the published release, freq_00002.csv is already merged (it holds the rows
    # taken from the 00003 copy) and there is no freq_00003.csv, so fall back to
    # the report's own archive when its source archive has no frequency file.
    have = {os.path.basename(p)[5:10] for p in glob.glob(os.path.join(a.freq_dir, "freq_*.csv"))}
    want = {((r.source_archive if r.source_archive in have else r.archive), r.report_id): r.archive
            for r in df.itertuples()}

    X_parts, keys, apis = [], [], None
    for path in sorted(glob.glob(os.path.join(a.freq_dir, "freq_*.csv"))):
        arc = os.path.basename(path)[5:10]
        if arc == "00013":
            continue
        for chunk in pd.read_csv(path, dtype={"report_id": str}, chunksize=50000):
            if apis is None:
                apis = list(chunk.columns[1:])
            chunk = chunk.reindex(columns=["report_id"] + apis, fill_value=0)
            m = chunk.report_id.map(lambda r: (arc, r) in want)
            sub = chunk[m]
            if len(sub):
                X_parts.append(sub[apis].to_numpy(np.float32))
                keys.extend((want[(arc, r)], r) for r in sub.report_id)
    X = np.vstack(X_parts)
    kdf = pd.DataFrame(keys, columns=["archive", "report_id"])
    kdf = kdf.merge(df[["archive", "report_id", "category"]], on=["archive", "report_id"], how="left")
    y = kdf.category.to_numpy()
    arc = kdf.archive.to_numpy()
    s = X.sum(1, keepdims=True)
    X = np.divide(X, s, out=np.zeros_like(X), where=s > 0)
    return X, y, arc, len(apis), dropped, int((s.ravel() == 0).sum())


def scores(yt, yp):
    return {"accuracy": round(accuracy_score(yt, yp), 4),
            "macro_f1": round(f1_score(yt, yp, average="macro"), 4),
            "weighted_f1": round(f1_score(yt, yp, average="weighted"), 4)}


def rf(seed):
    return RandomForestClassifier(n_estimators=200, n_jobs=-1, class_weight="balanced_subsample",
                                  random_state=seed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--freq-dir", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--labels", help="label file; not needed if the manifest has a category column")
    ap.add_argument("--out", default="rerun_results.json")
    ap.add_argument("--min-support", type=int, default=500)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip", default="", help="comma list of experiments to skip: baseline,scale,archive")
    ap.add_argument("--fractions", default="0.01,0.05,0.10,0.25,0.50,1.0")
    a = ap.parse_args()
    skip = set(filter(None, a.skip.split(",")))
    res = {}

    t = time.time()
    X, y, arc, n_feat, dropped, n_zero = load(a)
    res["data"] = {"n_samples": int(len(y)), "n_classes": int(len(set(y))), "n_features": n_feat,
                   "all_zero_vectors": n_zero, "dropped_tail_classes": dropped,
                   "per_archive": {k: int(v) for k, v in zip(*np.unique(arc, return_counts=True))}}
    print(json.dumps(res["data"], indent=1), f"\nloaded in {time.time() - t:.0f}s", flush=True)

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=a.seed, stratify=y)
    maj = pd.Series(ytr).value_counts().index[0]
    res["majority_class_accuracy"] = round(float((yte == maj).mean()), 4)

    if "baseline" not in skip:
        res["baseline"] = {}
        for name, model in (("logreg", LogisticRegression(max_iter=200, class_weight="balanced")),
                            ("random_forest", rf(a.seed))):
            t = time.time()
            model.fit(Xtr, ytr)
            res["baseline"][name] = scores(yte, model.predict(Xte))
            print(name, res["baseline"][name], f"{time.time() - t:.0f}s", flush=True)
            del model
            gc.collect()
        json.dump(res, open(a.out, "w"), indent=1)

    if "scale" not in skip:
        res["scale"] = []
        rng = np.random.default_rng(a.seed)
        order = rng.permutation(len(ytr))
        for frac in [float(f) for f in a.fractions.split(",")]:
            idx = order[: max(1, int(frac * len(ytr)))]
            t = time.time()
            m = rf(a.seed).fit(Xtr[idx], ytr[idx])
            r = {"fraction": frac, "n_train": int(len(idx)), **scores(yte, m.predict(Xte))}
            res["scale"].append(r)
            print("scale", r, f"{time.time() - t:.0f}s", flush=True)
            del m
            gc.collect()
            json.dump(res, open(a.out, "w"), indent=1)

    if "archive" not in skip:
        tr = np.isin(arc, ["00000", "00001", "00002", "00004"])
        te = np.isin(arc, ["00005", "00006", "00007"])
        classes = set(y[tr]) & set(y[te])
        tr &= np.isin(y, list(classes))
        te &= np.isin(y, list(classes))
        t = time.time()
        m = rf(a.seed).fit(X[tr], y[tr])
        by_archive = scores(y[te], m.predict(X[te]))
        del m
        gc.collect()
        pool = np.where(tr | te)[0]
        rng = np.random.default_rng(a.seed)
        perm = rng.permutation(pool)
        rtr, rte = perm[: tr.sum()], perm[tr.sum(): tr.sum() + te.sum()]
        m2 = rf(a.seed).fit(X[rtr], y[rtr])
        random_split = scores(y[rte], m2.predict(X[rte]))
        res["archive"] = {"n_train": int(tr.sum()), "n_test": int(te.sum()), "n_classes": len(classes),
                          "archive_split": by_archive, "random_split_same_sizes": random_split}
        print("archive", res["archive"], f"{time.time() - t:.0f}s", flush=True)

    json.dump(res, open(a.out, "w"), indent=1)
    print("saved", a.out)


if __name__ == "__main__":
    main()
