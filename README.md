# VS-WinAPI: Sanitized Windows API Behavioral Traces from VirusShare Malware

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24060359.svg)](https://doi.org/10.5281/zenodo.24060359)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

VS-WinAPI is a public dataset of sanitized dynamic-analysis reports for Windows
malware. Samples from twelve VirusShare archives were executed in Cuckoo Sandbox
on Windows 10 guests, and each report gives the sample's **ordered Windows API
call sequence** for every process, plus a **per-API call-frequency table**, over
a vocabulary of 321 functions. No malware binaries or reconstructable sample
content are included.

This repository holds the code and documentation. **The data is on Zenodo:
[doi.org/10.5281/zenodo.24060359](https://doi.org/10.5281/zenodo.24060359).**

| | |
|---|---|
| Reports | 1,437,789 (1,401,594 parse as JSON) |
| Successful analyses | **643,781** (behavior captured; see [Success criterion](#success-criterion)) |
| Behavior-category labels (MalDICT) | 227,714 reports; 112,738 of them successful |
| API vocabulary | 321 functions |
| Archives | VirusShare_00000–00012, excluding 00003 (see [Provenance](#provenance)) |
| Samples' PE compile dates | mostly 2002–2012, median 2010 |
| Sandbox | Cuckoo 2.0.7, VirtualBox, Windows 10 21H2, 300 s timeout, no network |
| Size | about 19 GB compressed (1.95 TB uncompressed) |

## Getting the data

Download from [Zenodo](https://doi.org/10.5281/zenodo.24060359). Most work needs
only the first four files (about 330 MB):

| File | Contents |
|---|---|
| `manifest.csv` | **One row per parsed report. Start here.** Hashes, outcome, label, guest, analysis date, flags. |
| `splits.csv` | The fixed train/test splits used in the paper (108,932 reports). |
| `frequency.zip` | `freq_XXXXX.csv`: one row per report, one column per API (call counts); `api_vocabulary.txt`. Extract into a folder named `frequency`. |
| `labels.zip` | MalDICT behavior labels, AVClass tags for a sampled subset, and the label-agreement table. |
| `reports_XXXXX.tar.gz` (12 files) | The sanitized reports, `XXXXX/<report_id>.json`. Needed only for call sequences. |
| `SHA256SUMS` | Checksums of the report archives. |
| `code.zip`, `README.md`, `DATASHEET.md`, `LICENSE` | Snapshot of this repository at release. |

Verify a downloaded archive with `sha256sum -c SHA256SUMS --ignore-missing`
(Linux/macOS) or `Get-FileHash reports_00012.tar.gz -Algorithm SHA256`
(PowerShell).

## Repository contents

| Path | Contents |
|---|---|
| `code/` | The full pipeline: hash mapping, sanitization, profiling, labeling, statistics, release build, and experiments. `code/README.md` lists the scripts in the order they were run. |
| `DATASHEET.md` | Datasheet following *Datasheets for Datasets*: motivation, composition, collection, preprocessing, uses, distribution, maintenance. |
| `LICENSE` | CC BY 4.0. |

The code here is the maintained version; `code.zip` on Zenodo is the snapshot
taken at release.

## Quick start

**Classify behavior categories from API frequencies.** With `splits.csv` and the
extracted `frequency/` folder in the working directory:

```python
import pandas as pd

splits = pd.read_csv("splits.csv", dtype=str)
with open("frequency/api_vocabulary.txt") as fh:
    vocab = fh.read().split()
parts = []
for archive, rows in splits.groupby("archive"):
    f = pd.read_csv(f"frequency/freq_{archive}.csv", dtype={"report_id": str})
    f = f[f.report_id.isin(rows.report_id)]
    f = f.reindex(columns=["report_id"] + vocab, fill_value=0).copy()
    f["archive"] = archive
    parts.append(f)
data = splits.merge(pd.concat(parts), on=["archive", "report_id"])

X = data[vocab].to_numpy("float32", copy=True)
X /= X.sum(1, keepdims=True)              # call proportions, as in the paper
y = data.category.to_numpy()
train = (data.split == "train").to_numpy()
```

A random forest (200 trees, balanced class weights) trained on `X[train]` reaches
about 0.60 macro-F1 on `X[~train]` across 36 behavior categories.

**Reproduce the paper's experiments** (baseline, training-set-size curve, and
archive split):

```
pip install pandas numpy scikit-learn
python code/rerun_baselines.py --freq-dir frequency --manifest manifest.csv --out results.json
```

This takes a few minutes and about 8 GB of RAM.

**Get call sequences for a subset**

1. Filter `manifest.csv`, for example `success == "1"` and `category == "backdoor"`.
2. Each matching report is `<archive>/<report_id>.json` inside
   `reports_<archive>.tar.gz`.

```python
import json, tarfile
with tarfile.open("reports_00006.tar.gz") as tar:
    report = json.load(tar.extractfile("00006/12345.json"))
for proc in report["behavior"]["processes"]:
    apis = [call["api"] for call in proc.get("calls", [])]
```

## Reference results

From the paper, on successful, labeled, hash-deduplicated reports in the 36
categories with at least 500 samples (108,932 reports):

| Model (API-frequency features) | Accuracy | Macro-F1 |
|---|---|---|
| Majority class | 0.075 | — |
| Logistic regression | 0.352 | 0.273 |
| Random forest | 0.694 | 0.604 |

- **Training-set size:** random-forest macro-F1 rises from 0.35 with 871 training
  reports to 0.60 with 87,145, with no sign of leveling off.
- **Archive split:** training on archives 00000–00004 and testing on 00005–00007
  gives 0.497 macro-F1, against 0.609 for a random split of the same size.

## manifest.csv columns

| Column | Meaning |
|---|---|
| `archive`, `report_id` | Identify the report; together they are unique. |
| `md5`, `sha256` | Sample hashes (all but 7 rows have an MD5). |
| `success` | 1 if the analysis meets the success criterion. |
| `outcome` | `success`, `no_process`, `too_few_calls`, or `too_few_unique`. |
| `n_proc`, `n_calls`, `n_unique_apis` | Processes, API calls, distinct API functions. |
| `category`, `category_support`, `label_source` | MalDICT behavior category (blank if unlabeled). |
| `analyzed`, `duration` | Analysis date and duration in seconds (timeout 300 s). |
| `guest`, `host` | Guest VM name and host (1 or 2) that ran the sample. |
| `any_probe_sig` | 1 if Cuckoo flagged an anti-VM, anti-sandbox, or anti-debug check. |
| `collection_fault` | 1 for archives 00008–00012 (see below). |
| `source_archive` | Which stored copy of an 00002 report was used (see [Provenance](#provenance)). |

### Success criterion

A report is successful when it parses as JSON, contains at least one process,
and records calls to at least four distinct API functions.

## Things to know before using the data

- **Archives 00008–00012 are mostly empty.** A collection fault left about 98% of
  their analyses with no captured process. It depended on the submission batch,
  not the samples, so their no-process reports describe the pipeline, not
  malware behavior. Filter with `collection_fault == "0"` or `success == "1"`.
- **Random splits overstate generalization.** Report results on the archive
  split (`archive_split` in `splits.csv`) as well as the random one. The paper
  restricts the archive split to the 35 categories present on both sides.
- **De-duplicate by hash.** The same sample can appear in more than one archive.
  `splits.csv` is already de-duplicated by MD5.
- **No benign samples.** The dataset cannot support malicious-vs-benign detection
  on its own.
- **No network behavior.** Guests had no network access, so behavior that depends
  on a server's response is absent.
- **The samples are old,** mostly compiled between 2002 and 2012. Validate any
  conclusion on newer malware.
- **Labels are automated,** from antivirus consensus (MalDICT), not manual
  analysis.
- **Environment probing is common:** Cuckoo's anti-VM, anti-sandbox, or anti-debug
  signatures fire in 45.5% of successful analyses.

## Provenance

The fourteen VirusShare archive files obtained (00000–00013) contained two
duplicates. Archive 00013 was identical to 00012 and is excluded. The reports
stored as 00003 were a second copy of the 00002 analyses, saved at a different
stage of processing; they were merged into 00002, keeping the more complete copy
of each analysis (`source_archive` records which). VirusShare_00003 was analyzed,
but its reports were lost, so it is not represented.

Hashes are included so researchers with their own VirusShare access can retrieve
the original samples under VirusShare's terms. The dataset does not contain or
link to any binary.

## Report format

Each `XXXXX/<report_id>.json` has these sections:

- `info`: sandbox version, analysis duration, routing (`none`), platform.
- `target.file`: hashes (md5, sha1, sha256, sha512, ssdeep), size, libmagic type.
- `behavior.processes[]`: per process, `pid`, `ppid`, `process_name`,
  `first_seen`, `n_calls`, and `calls[]` in order. Each call has `api`,
  `category`, `status`, `return_value`, `tid` (thread ID), and `time`. Call
  arguments are not included, so file paths, buffers, and handles never appear.
- `behavior.apistats`: per-process API call counts.
- `behavior.processtree`: the process hierarchy.
- `static` (optional): import hash, imported functions, section names, sizes,
  and entropy.
- `signatures` (optional): Cuckoo signature name, description, and severity.
- `dataset`: `{"archive", "report_id"}`.

94 very large reports (270 MB to 1.3 GB each) were copied through the release
build without being parsed, so they have no `dataset` section and may lack
filled-in hashes. `manifest.csv` covers them like every other report.

## Sanitization

Raw Cuckoo reports contain dropped files, memory dumps, extracted payloads, and
string tables that can reconstruct parts of a sample. These sections were
removed, each API call was reduced to its name, category, status, return value,
thread, and timestamp (no arguments), and host paths
were redacted, reducing 13.8 TB of raw reports to 1.95 TB. Every report was
then scanned for path markers. Windows profile paths recorded by the samples
themselves (for example, an antivirus quarantine file noting where it was found
on the victim's machine) have their user-name segment replaced with `<USER>`.
The scripts that do this are in `code/`, so the transformation is auditable.

## License

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): you may share and
adapt the data and code for any purpose, with attribution. Obtaining the
original samples is subject to VirusShare's own terms.

## Citation

```bibtex
@dataset{walker_vs_winapi_2026,
  author    = {Walker, Aaron},
  title     = {{VS-WinAPI}: Sanitized Windows API Behavioral Traces from {VirusShare} Malware},
  year      = {2026},
  publisher = {Zenodo},
  version   = {1.0.1},
  doi       = {10.5281/zenodo.24060359},
  url       = {https://doi.org/10.5281/zenodo.24060359}
}
```

Please also credit [VirusShare](https://virusshare.com) as the source of the
samples, and MalDICT (Joyce et al., CAMLIS 2023) for the behavior labels.

## Questions and problems

Open an [issue](https://github.com/4161726f6e/VS-WinAPI/issues) to report an
error in the data or code, or to ask a question.
