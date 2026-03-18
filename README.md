# CVE Scanner — Multi-Distro Vulnerability Report Tool

A command-line tool that queries **MITRE**, **NVD**, **Ubuntu Security**, and the **Debian Security Tracker** for a given CVE ID and produces a structured terminal report, a machine-readable JSON file, and a dark-themed HTML report — all saved into a dedicated output directory named after the CVE.

---

## Table of Contents

- [Overview](#overview)
- [Data Sources](#data-sources)
  - [MITRE CVE](#mitre-cve)
  - [NVD — National Vulnerability Database](#nvd--national-vulnerability-database)
  - [Ubuntu Security API](#ubuntu-security-api)
  - [Debian Security Tracker](#debian-security-tracker)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Arguments](#arguments)
  - [Scan a specific Ubuntu release only](#scan-a-specific-ubuntu-release-only)
  - [Scan a specific Debian release only](#scan-a-specific-debian-release-only)
- [Ubuntu Releases Covered](#ubuntu-releases-covered)
- [Debian Releases Covered](#debian-releases-covered)
- [Examples](#examples)
  - [Example 1 — Scan all distros (default)](#example-1--scan-all-distros-default)
  - [Example 2 — Target a single Ubuntu release](#example-2--target-a-single-ubuntu-release)
  - [Example 3 — Target a single Debian release](#example-3--target-a-single-debian-release)
  - [Example 4 — CVE not affecting Ubuntu or Debian](#example-4--cve-not-affecting-ubuntu-or-debian)
- [Terminal Output](#terminal-output)
- [File & Directory Structure](#file--directory-structure)
- [Output File Structure](#output-file-structure)
  - [JSON Report](#json-report)
  - [HTML Report](#html-report)
- [Status Values & Highlighting](#status-values--highlighting)
- [Debian Cache](#debian-cache)
- [Troubleshooting](#troubleshooting)

---

## Overview

```
python3 Script.py --cve CVE-2023-44487
```

The tool fetches data from four independent sources, merges them into a single normalised report, and writes two output files — a JSON data file and an HTML visual report — into a directory named `CVE-YYYY-XXXXX/`.

```
CVE-2023-44487/
├── CVE-2023-44487.json
└── CVE-2023-44487_report.html
```

---

## Data Sources

### MITRE CVE

**API:** `https://cveawg.mitre.org/api/cve/{CVE-ID}`

MITRE is the official CVE Numbering Authority (CNA) coordinator. The tool fetches:

- CVE ID and publication state (`PUBLISHED`, `RESERVED`, `REJECTED`)
- Assigner organisation (the CNA that published the CVE)
- Publication date
- Official English description
- Reference URLs with tags

MITRE data is combined with NVD data into a single merged overview. If both sources return the same description, it is deduplicated automatically. If MITRE returns data but NVD does not (or vice versa), the available data is still used and the missing source is recorded in `fetch_errors`.

---

### NVD — National Vulnerability Database

**API:** `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE-ID}`

NVD is maintained by NIST and enriches the raw MITRE CVE record with scoring and analysis. The tool fetches:

- CVSS severity rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- CVSS base score (numeric, e.g. `7.5`)
- CVSS vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- CVSS version — supports v3.1, v3.0, and v2 in priority order
- CWE weakness identifiers (e.g. `CWE-400`, `CWE-772`)
- Last modified date
- Additional reference URLs

> **NVD Rate Limiting:** The NVD API allows 5 requests per 30 seconds without an API key. If you are scanning many CVEs in sequence and see `[WARN] NVD: no vulnerabilities found`, wait 30 seconds and retry. A free NVD API key is available at https://nvd.nist.gov/developers/request-an-api-key and removes rate limiting.

---

### Ubuntu Security API

**API:** `https://ubuntu.com/security/cves/{CVE-ID}.json`

The Ubuntu Security team maintains a JSON endpoint for each tracked CVE. The tool reads:

- Ubuntu priority (`critical`, `high`, `medium`, `low`, `negligible`)
- Per-release package status using the `release_codename` field (current API) with fallback to the legacy `release` field
- Package component (`main`, `universe`, `restricted`, `multiverse`)
- Fixed version string or notes
- End-of-life status for unsupported releases

If the CVE is not tracked by Ubuntu (404 response or empty package list), the report shows a **Not Affected — Ubuntu** banner in both the HTML and JSON outputs.

---

### Debian Security Tracker

**API:** `https://security-tracker.debian.org/tracker/data/json`

The Debian Security Tracker provides a single bulk JSON file (~20 MB) covering all packages and CVEs across all Debian releases. The tool:

- Downloads the full tracker JSON on first run and **caches it at `/tmp/debian_security_tracker.json`** for 6 hours to avoid repeated large downloads
- Filters the cached data for the requested CVE
- Expands each base release entry to also include its **security pocket** row (e.g. `bookworm-security` lives inside the `bookworm` release entry under `repositories`, not as a separate key)
- Shows `(unfixed)`, `(not affected)`, or the exact fixed version per release

If the CVE is not found in the tracker, the report shows a **Not Affected — Debian** banner.

---

## Requirements

- **Python** 3.8 or newer
- **pip** package: `requests`

```
requests>=2.28.0
```

All other imports (`argparse`, `json`, `os`, `time`, `datetime`) are Python standard library.

---

## Installation

```bash
# 1. Clone or download the script
git clone <your-repo-url>
cd <your-repo>

# 2. Install the dependency
pip install -r requirements.txt

# 3. Run
python3 Script.py --cve CVE-2023-44487
```

---

## Usage

### Basic Usage

```bash
python3 Script.py --cve <CVE-ID>
```

Scans **all** Ubuntu releases and **all** Debian releases by default.

### Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--cve` | Yes | — | CVE identifier, e.g. `CVE-2023-44487` |
| `--ubuntu-release` | No | all releases | Limit Ubuntu scan to one release codename |
| `--debian-release` | No | all releases | Limit Debian scan to one release codename |

### Scan a specific Ubuntu release only

```bash
python3 Script.py --cve CVE-2023-44487 --ubuntu-release focal
```

### Scan a specific Debian release only

```bash
python3 Script.py --cve CVE-2023-44487 --debian-release bookworm
```

---

## Ubuntu Releases Covered

When no `--ubuntu-release` is specified, the tool checks all of the following releases:

| Codename | Version | Notes |
|---|---|---|
| `questing` | 25.10 Questing | Current development |
| `noble` | 24.04 LTS Noble | Current LTS |
| `jammy` | 22.04 LTS Jammy | LTS — standard support |
| `focal` | 20.04 LTS Focal | LTS — standard support |
| `bionic` | 18.04 LTS Bionic | ESM only (Ubuntu Pro) |
| `xenial` | 16.04 LTS Xenial | ESM only (Ubuntu Pro) |
| `trusty` | 14.04 LTS Trusty | Legacy ESM |

Releases with **end-of-life** (`end-of-life`, `eol`, `dne`) status are highlighted in **amber** in both the terminal and the HTML report.

---

## Debian Releases Covered

When no `--debian-release` is specified, the tool checks all of the following releases. Security pockets are automatically expanded for supported releases:

| Codename | Notes |
|---|---|
| `sid` | Unstable / rolling |
| `forky` | Testing / future stable |
| `trixie` | Debian 13 |
| `bookworm` | Debian 12 — current stable |
| `bookworm (security)` | Debian 12 security pocket — auto-expanded |
| `bullseye` | Debian 11 — oldstable |
| `bullseye (security)` | Debian 11 security pocket — auto-expanded |
| `buster` | Debian 10 — archived |

> **Security pockets:** The Debian tracker stores security pocket versions inside the base release entry under `repositories`. The tool automatically detects and expands these into separate rows so `bookworm (security)` and `bullseye (security)` appear distinctly in the output with a purple colour.

---

## Examples

### Example 1 — Scan all distros (default)

```bash
python3 Script.py --cve CVE-2023-44487
```

Terminal output:

```
[INFO] CVE             : CVE-2023-44487
[INFO] Output dir      : CVE-2023-44487/
[INFO] Ubuntu releases : questing, noble, jammy, focal, bionic, xenial, trusty
[INFO] Debian releases : sid, forky, trixie, bookworm, bullseye, buster

[INFO] Fetching MITRE data ...
[INFO] Fetching NVD data ...
[INFO] Fetching Ubuntu data ...
[INFO] Fetching Debian data ...
[DEBIAN] Fetching Debian Security Tracker (~20MB) ...

==========================
=== MITRE DATA / NVD DATA ===
==========================
CVE:           CVE-2023-44487
State:         PUBLISHED
Severity:      HIGH  (CVSS 7.5)
CVSS Vector:   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
Assigner:      cisa-cg
Published:     2023-10-10T00:00:00
Last Modified: 2025-11-07T19:00:41.810
CWEs:          CWE-400, CWE-772
Description:   The HTTP/2 protocol allows a denial of service (server resource
               consumption) because request cancellation can reset many streams
               quickly, as exploited in the wild in August through October 2023.

========= UBUNTU ANALYSIS =========
[UBUNTU] Priority: high

  Release                      Package                                Status                       Component
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────
  25.10 Questing               nghttp2                                released                     main
  24.04 LTS Noble              nghttp2                                released                     main
  22.04 LTS Jammy              nghttp2                                released                     main
  22.04 LTS Jammy              trafficserver                          needs-triage                 universe
  20.04 LTS Focal              nghttp2                                released                     main
  18.04 LTS Bionic             nghttp2                                end-of-life [EOL]            main
  16.04 LTS Xenial             nghttp2                                end-of-life [EOL]            main
  14.04 LTS Trusty             Not in release

========= DEBIAN ANALYSIS =========
  Package                        Release                      Fixed Version                  Status
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  nghttp2                        (unstable)                   1.61.0-1                       resolved
  nghttp2                        trixie                       1.61.0-1                       resolved
  nghttp2                        bookworm                     1.52.0-1+deb12u1               resolved
  nghttp2                        bookworm (security)          1.52.0-1+deb12u1               resolved
  nghttp2                        bullseye                     1.43.0-1+deb11u1               resolved
  nghttp2                        bullseye (security)          1.43.0-1+deb11u1               resolved
  nghttp2                        buster                       1.36.0-2+deb10u2               resolved
  trafficserver                  bookworm                     9.2.3+ds-1+deb12u1             resolved
  trafficserver                  bookworm (security)          9.2.3+ds-1+deb12u1             resolved
  trafficserver                  (unstable)                   (unfixed)                      open

[INFO] JSON report  -> CVE-2023-44487/CVE-2023-44487.json
[INFO] HTML report  -> CVE-2023-44487/CVE-2023-44487_report.html
[INFO] Done.
```

---

### Example 2 — Target a single Ubuntu release

```bash
python3 Script.py --cve CVE-2023-44487 --ubuntu-release noble
```

Only the `noble` (24.04 LTS) row is shown in the Ubuntu section. All other releases are skipped. The Debian section still checks all releases unless `--debian-release` is also specified.

---

### Example 3 — Target a single Debian release

```bash
python3 Script.py --cve CVE-2023-44487 --debian-release bookworm
```

Only `bookworm` and its `bookworm (security)` pocket are shown in the Debian section.

---

### Example 4 — CVE not affecting Ubuntu or Debian

```bash
python3 Script.py --cve CVE-2024-99999
```

If a CVE has no Ubuntu packages and is not in the Debian tracker, both sections display a **Not Affected** banner in the HTML report and `"not_affected": true` in the JSON.

---

## Terminal Output

The terminal prints three sections in sequence:

**Section 1 — CVE Overview (MITRE / NVD)**
Merged data from MITRE and NVD. If both return the same description it is printed once under a combined heading `=== MITRE DATA / NVD DATA ===`. If only one source succeeds, the heading reflects that. Fetch warnings (`[WARN]`) are printed above the section if any API call failed.

**Section 2 — Ubuntu Analysis**
A table of all Ubuntu releases with package name, status, and component. Releases with no data show `Not in release`. EOL statuses are flagged with `[EOL]`.

**Section 3 — Debian Analysis**
A table of all Debian releases with package name, fixed version, and status. Security pockets appear as separate rows labelled `bookworm (security)` etc. Unfixed entries show `(unfixed)` and not-affected entries show `(not affected)`.

---

## File & Directory Structure

```
project/
├── Script.py        ← Main scanner script
├── requirements.txt        ← Python dependencies (requests only)
├── README.md               ← This file
│
└── CVE-2023-44487/         ← Auto-created output directory (named after CVE)
    ├── CVE-2023-44487.json
    └── CVE-2023-44487_report.html
```

Each CVE scan creates its own directory. Running the same CVE again overwrites the files inside that directory.

The Debian tracker cache is stored separately at `/tmp/debian_security_tracker.json` and shared across all CVE scans during a session.

---

## Output File Structure

### JSON Report

`CVE-YYYY-XXXXX/CVE-YYYY-XXXXX.json`

```jsonc
{
  "generated_at": "2026-03-18T10:45:00Z",   // UTC timestamp
  "cve_id": "CVE-2023-44487",

  "overview": {
    "cve_id":        "CVE-2023-44487",
    "state":         "PUBLISHED",             // MITRE state
    "severity":      "HIGH",                  // NVD CVSS severity
    "cvss_score":    7.5,                     // NVD base score
    "cvss_vector":   "CVSS:3.1/AV:N/...",    // Full CVSS vector string
    "assigner":      "cisa-cg",               // CNA short name
    "published":     "2023-10-10T00:00:00Z",
    "last_modified": "2025-11-07T19:00:41Z",
    "description":   "The HTTP/2 protocol...",
    "cwes":          ["CWE-400", "CWE-772"],  // Weakness identifiers
    "references":    [                        // Up to 10 references
      {
        "url":  "https://example.com/advisory",
        "tags": ["vendor-advisory"]
      }
    ],
    "sources":       ["MITRE", "NVD"],        // Which sources succeeded
    "fetch_errors":  []                       // Any API fetch failures
  },

  "ubuntu": {
    "releases_checked": ["questing", "noble", "jammy", ...],
    "priority":         "high",               // Ubuntu priority level
    "not_affected":     false,                // true = no packages affected
    "by_release": {
      "noble": [
        {
          "name":        "nghttp2",
          "release":     "noble",
          "status":      "released",
          "description": "1.59.0-1ubuntu0.1", // Fixed version from Ubuntu API
          "component":   "main",
          "pocket":      "security"
        }
      ],
      "trusty": []                            // Empty = Not in release
    },
    "all_packages": [ /* flat list of all entries */ ]
  },

  "debian": {
    "releases_checked": ["sid", "forky", "trixie", "bookworm", "bullseye", "buster"],
    "not_affected":     false,                // true = CVE not in Debian tracker
    "packages": [
      {
        "package":       "nghttp2",
        "release":       "bookworm",          // Base release key
        "release_label": "bookworm",          // Display label (same for base)
        "fixed_version": "1.52.0-1+deb12u1",
        "status":        "resolved"
      },
      {
        "package":       "nghttp2",
        "release":       "bookworm",          // Same base release
        "release_label": "bookworm-security", // Security pocket row
        "fixed_version": "1.52.0-1+deb12u1",
        "status":        "resolved"
      }
    ]
  }
}
```

### HTML Report

`CVE-YYYY-XXXXX/CVE-YYYY-XXXXX_report.html`

A self-contained dark-themed HTML file. Open it in any browser — no server required. It contains three sections:

**CVE Details** — metadata grid (severity badge, CVSS score, state, assigner, published/modified dates), CVSS vector string, full description, CWE weakness pills, and up to 10 clickable references. A red error banner appears at the top of this section if any API call failed.

**Ubuntu Analysis** — a table with columns `Release | Package | Component | Status | Fixed Version / Info`. End-of-life rows have an amber background tint, amber release label, and an `⚠` warning badge. Releases with no data show `Not in release` in muted italic text. If the CVE does not affect Ubuntu at all, a green "Not Affected — Ubuntu" banner replaces the table.

**Debian Analysis** — a table with columns `Package | Release | Fixed Version | Status`. Security pocket rows (`bookworm (security)`, `bullseye (security)`) are shown in purple to distinguish them from base release rows. Unfixed versions are amber, not-affected versions are green. If the CVE is not in the Debian tracker, a blue "Not Affected — Debian" banner replaces the table.

---

## Status Values & Highlighting

### Ubuntu Status Values

| Status | Colour | Meaning |
|---|---|---|
| `released` | Green | Fix is available and published |
| `needs-triage` | Blue | Not yet assessed by Ubuntu security team |
| `not-affected` | Green | Package exists but is not vulnerable |
| `end-of-life` | **Amber ⚠** | Release is EOL — no fix will be provided |
| `ignored` | Grey | Deliberately not fixed (low impact) |
| `deferred` | Grey | Fix deferred to a later date |

### Debian Status Values

| Status | Colour | Meaning |
|---|---|---|
| `resolved` | Green | Fix released in this version |
| `open` → `(unfixed)` | Amber | Vulnerability present, not yet fixed |
| `undetermined` | Grey | Status not yet determined |
| `not affected` | Green | Package is not affected |

---

## Debian Cache

The Debian Security Tracker bulk JSON (~20 MB) is downloaded once and cached at:

```
/tmp/debian_security_tracker.json
```

The cache is reused for **6 hours**. After that, the next scan automatically re-downloads a fresh copy. To force a refresh immediately, delete the cache file:

```bash
rm /tmp/debian_security_tracker.json
```

---

## Troubleshooting

**`[WARN] NVD: no vulnerabilities found`**
The NVD API rate-limits unauthenticated requests to 5 per 30 seconds. Wait 30 seconds and retry. For bulk scanning, get a free API key at https://nvd.nist.gov/developers/request-an-api-key.

**`[WARN] MITRE: CVE not found (404)`**
The CVE ID may be `RESERVED` and not yet published by MITRE. Check https://www.cve.org/CVERecord?id=CVE-YYYY-XXXXX for the current state.

**`[WARN] MITRE: connection error`** or **`[WARN] NVD: request timed out`**
Network connectivity issue or the API is temporarily unavailable. The tool will still produce a report using whichever sources it could reach, with the missing sources recorded in `fetch_errors` inside the JSON.

**Debian section shows no data for a recent CVE**
The Debian tracker may not have triaged the CVE yet, or the cached file may be stale. Delete `/tmp/debian_security_tracker.json` to force a fresh download.

**Ubuntu section shows `Not in release` for every release**
The CVE may genuinely not affect any Ubuntu packages, or the Ubuntu Security API may have changed its response format. Verify at https://ubuntu.com/security/CVE-YYYY-XXXXX.
