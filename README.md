# VS-WinAPI: Sanitized Windows API Behavioral Traces from VirusShare Malware

VS-WinAPI is a set of sanitized Cuckoo Sandbox reports for samples from twelve
VirusShare archives,
executed on Windows 10 guests. Each report gives the sample's **ordered Windows
API call sequence** per process and a **per-API call-frequency table**, over a
vocabulary of 321 functions. No malware binaries or reconstructable sample
content are included.

| | |
|---|---|
| Reports | 1,437,789 (1,401,594 parse as JSON) |
| Successful analyses | **643,781** (behavior captured; see *Success criterion*) |
| Behavior-category labels (MalDICT) | 227,714 reports; 112,738 of them successful |
| API vocabulary | 321 functions |
| Archives | VirusShare_00000–00012, excluding 00003 (see *Provenance*) |
| Samples' PE compile dates | mostly 2002–2012, median 2010 |
| Size | about 19 GB compressed (1.95 TB uncompressed) |

Paper: A. Walker, *VS-WinAPI: A Public Dataset of 644,000 Windows API Behavioral
Traces from VirusShare Malware* (TODO: venue / arXiv link).
DOI: [10.5281/zenodo.24022846](https://doi.org/10.5281/zenodo.24022846)

## Files

| File | Contents |
|---|---|
| `manifest.csv` | **One row per parsed report. Start here.** Hashes, outcome, label, guest, analysis date, flags. |
| `splits.csv` | The fixed train/test split used in the paper (108,932 reports). |
| `frequency.zip` | `freq_XXXXX.csv`: one row per report, one column per API (call counts); `api_vocabulary.txt`. |
| `labels.zip` | MalDICT labels, AVClass tokens for a sampled subset, the alias map, and the agreement table. |
| `reports_XXXXX.tar.gz` (12 files) | The sanitized reports, `XXXXX/<report_id>.json`. |
| `SHA256SUMS` | Checksums of the report archives. |
| `code.zip` | The full pipeline: mapping, sanitization, profiling, labeling, release build, experiments. |
| `DATASHEET.md` | Datasheet (motivation, composition, collection, uses, limitations). |
| `LICENSE` | Creative Commons Attribution 4.0 International (CC BY 4.0). |

Most work needs only `manifest.csv`, `splits.csv`, and `frequency.zip` (well
under 2 GB). Download the report archives only if you need call sequences.

## Quick start

**Classify behavior categories from API frequencies**

```python
import pandas as pd
man = pd.read_csv("manifest.csv", dtype=str)
splits = pd.read_csv("splits.csv", dtype=str)
freq = pd.concat(pd.read_csv(f"frequency/freq_{a}.csv", dtype={"report_id": str}).assign(archive=a)
                 for a in sorted(man.archive.unique()))
data = splits.merge(freq, on=["archive", "report_id"])
X = data.drop(columns=["archive", "report_id", "category", "split", "archive_split"]).to_numpy(float)
X = X / X.sum(1, keepdims=True)          # call proportions, as in the paper
y, train = data.category, data.split == "train"
```

Or run `code/rerun_baselines.py --freq-dir frequency --manifest manifest.csv`
to reproduce every number in the paper's experiments section.

**Get call sequences for a subset**

1. Filter `manifest.csv`, e.g. `success == "1"` and `category == "backdoor"`.
2. For each row, the report is `<archive>/<report_id>.json` inside
   `reports_<archive>.tar.gz`.

## manifest.csv columns

| Column | Meaning |
|---|---|
| `archive`, `report_id` | Identify the report; together they are unique. |
| `md5`, `sha256` | Sample hashes (99.9995% of rows have an MD5). |
| `success` | 1 if the analysis meets the success criterion. |
| `outcome` | `success`, `no_process`, `too_few_calls`, or `too_few_unique`. |
| `n_proc`, `n_calls`, `n_unique_apis` | Processes, API calls, distinct API functions. |
| `category`, `category_support`, `label_source` | MalDICT behavior category (blank if unlabeled). |
| `analyzed`, `duration` | Analysis date and duration in seconds (timeout 300 s). |
| `guest`, `host` | Guest VM name and host (1 or 2) that ran the sample. |
| `any_probe_sig` | 1 if Cuckoo flagged an anti-VM, anti-sandbox, or anti-debug check. |
| `collection_fault` | 1 for archives 00008–00012 (see below). |
| `source_archive` | Which stored copy the report came from (see *Provenance*). |

**Success criterion:** the report parses, has at least one process, and records
calls to at least four distinct API functions.

## Things to know before using the data

- **Archives 00008–00012 are mostly empty.** A collection fault left about 98% of
  their analyses with no captured process; it depended on the submission batch,
  not the samples. Their no-process reports describe the pipeline, not malware
  behavior. Filter with `collection_fault == "0"` or `success == "1"`.
- **Random splits overstate generalization.** In the paper, training on archives
  00000–00004 and testing on 00005–00007 gives 0.497 macro-F1, against 0.609 for
  a random split of the same size. `splits.csv` provides both (`split` and
  `archive_split`; the paper restricts the archive split to the 35 categories
  present on both sides).
- **De-duplicate by hash.** The same sample can appear in more than one archive.
  `splits.csv` is already de-duplicated by MD5.
- **No benign samples.** The corpus cannot support malicious-vs-benign detection
  on its own.
- **No network behavior.** Guests had no network access, so behavior that
  depends on a server's response is absent.
- **Labels are automated**, from antivirus consensus, not manual analysis.

## Provenance

The fourteen VirusShare archive files obtained (00000–00013) contained two
duplicates. Archive 00013 was identical to 00012 and is excluded. The reports
stored as 00003 were a second copy of the 00002 analyses, saved at a different
stage of processing; they were merged into 00002, keeping the more complete copy
of each analysis (`source_archive` records which). VirusShare_00003 itself is
therefore not represented.

Hashes are included so researchers with their own VirusShare access can retrieve
the original samples under VirusShare's terms. This release does not contain or
link to any binary.

## Report format

Each `XXXXX/<report_id>.json` has these sections:

- `info`: sandbox version, analysis duration, routing (`none`), platform.
- `target.file`: hashes (md5, sha1, sha256, sha512, ssdeep), size, libmagic type.
- `behavior.processes[]`: per process, `pid`, `ppid`, `process_name`, and
  `calls[]` in order; each call has the API name, category, return status, and a
  small allowlist of non-identifying arguments. File paths, buffers, handles,
  and addresses are never kept.
- `behavior.apistats`: per-process API call counts.
- `behavior.processtree`: the process hierarchy.
- `static` (optional): import hash, imported functions, section names, sizes,
  and entropy.
- `signatures` (optional): Cuckoo signature name, description, and severity.
- `dataset`: `{"archive", "report_id"}`.

Windows profile paths that originate from the samples (for example, an antivirus
quarantine file recording where it was found) have their user-name segment
replaced with `<USER>`.

94 very large reports (270 MB to 1.3 GB each) were copied through the release
build without being parsed: they have no `dataset` section and may lack the
filled-in hashes. `manifest.csv` covers them like every other report.

## License

CC BY 4.0: you may share and adapt the data for any purpose, with attribution.
See `LICENSE`. Obtaining the original samples is subject to VirusShare's own
terms.

## Citation

```bibtex
@dataset{walker_vs_winapi_2026,
  author    = {Walker, Aaron},
  title     = {{VS-WinAPI}: Sanitized Windows API Behavioral Traces from {VirusShare} Malware},
  year      = {2026},
  publisher = {Zenodo},
  version   = {1.0},
  doi       = {10.5281/zenodo.24022846},
  url       = {https://doi.org/10.5281/zenodo.24022846}
}
```

TODO: add the paper's BibTeX once it has a venue or arXiv ID.

Please also credit VirusShare (https://virusshare.com) as the source of the
samples, and MalDICT (Joyce et al., CAMLIS 2023) for the behavior labels.

## Contact

Aaron Walker — https://github.com/4161726f6e
