# VS-WinAPI pipeline code

Scripts in the order they were run. Python 3.10+; `pandas`, `numpy`, and
`scikit-learn` for the analysis steps. AVClass is needed only for labeling.

## 1. From raw Cuckoo reports to sanitized reports

| Script | What it does |
|---|---|
| `build_mapping.py` | Maps each raw report (task ID) to its sample hashes, before sanitization. |
| `profile_corpus_v2.py` | Counts processes, calls, and distinct APIs per report; applies the success criterion. |
| `sanitize_report.py` | Sanitizes one report: drops sensitive sections, slims calls, redacts paths. |
| `sanitize_corpus.py` | Runs `sanitize_report.py` over an archive. |
| `audit_and_manifest.py` | Audits sanitized archives (allowed sections, path markers) and writes the first manifest. |
| `find_leaks.py` | Lists every report that matches a path-leak marker, with context. |

## 2. Features and labels

| Script | What it does |
|---|---|
| `build_frequency_from_sequences.py` | Builds the per-report API frequency matrices from the sanitized call sequences. |
| `join_maldict_labels.py`, `join_claravy_labels.py` | Join MalDICT / ClarAVy labels to reports by hash. |
| `label_corpus.py` | VirusTotal lookups for a sample (needs `VT_API_KEY` in the environment). |
| `avclass_from_cache.py` | Runs AVClass over cached VirusTotal reports. |
| `audit_vt_cache.py` | Checks the VirusTotal cache. |
| `compare_labels.py` | MalDICT vs. AVClass agreement, exact and alias-aware. |

## 3. Corpus statistics and diagnosis

| Script | What it does |
|---|---|
| `collect_paper_stats.py` | One pass over all reports: outcomes, durations, calls, probing signatures, compile dates. |
| `report_metadata.py` | Per-report configuration and outcome metadata; used to diagnose the collection fault. |

## 4. Release build

| Script | What it does |
|---|---|
| `build_manifest.py` | Builds the release `manifest.csv`: fills hashes, joins labels and outcomes, flags the collection fault, merges the duplicate 00003 copy into 00002. |
| `prepare_release.py` | Builds `reports_XXXXX.tar.gz`: fills hashes, redacts user names in profile paths, rescans, writes checksums. |
| `merge_duplicate_archive.py` | Folds the duplicate 00003 copy into archive 00002 in the release files. |

## 5. Experiments

| Script | What it does |
|---|---|
| `rerun_baselines.py` | Every result in the paper's experiments section: baseline, scale curve, archive split. |

```
python rerun_baselines.py --freq-dir frequency --manifest manifest.csv
```

`baseline_classifier.py` from earlier versions is not included: it did not
filter to successful analyses and is superseded by `rerun_baselines.py`.
