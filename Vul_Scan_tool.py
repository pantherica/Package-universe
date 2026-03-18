#!/usr/bin/env python3

import requests
import argparse
import json
import os
import time
from datetime import datetime

NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UBUNTU_API = "https://ubuntu.com/security/cves"
DEBIAN_API = "https://security-tracker.debian.org/tracker/data/json"

DEBIAN_CACHE_FILE = "/tmp/debian_security_tracker.json"
CACHE_TTL_HOURS   = 6

UBUNTU_RELEASES = [
    ("questing", "25.10 Questing"),
    ("noble",    "24.04 LTS Noble"),
    ("jammy",    "22.04 LTS Jammy"),
    ("focal",    "20.04 LTS Focal"),
    ("bionic",   "18.04 LTS Bionic"),
    ("xenial",   "16.04 LTS Xenial"),
    ("trusty",   "14.04 LTS Trusty"),
]
UBUNTU_CODENAMES = [r[0] for r in UBUNTU_RELEASES]

DEBIAN_RELEASES = [
    ("sid",      "(unstable)"),
    ("forky",    "forky"),
    ("trixie",   "trixie"),
    ("bookworm", "bookworm"),
    ("bullseye", "bullseye"),
    ("buster",   "buster"),
]
DEBIAN_CODENAMES = [r[0] for r in DEBIAN_RELEASES]

# Security-pocket display labels — these are sub-repositories inside a base release,
# NOT separate top-level release keys in the Debian tracker JSON.
# We expand each base release to also show its -security repository row.
DEBIAN_SECURITY_RELEASES = {"bookworm", "bullseye", "buster"}

# ── Ubuntu EOL / warning status values ──
# Ubuntu API can return any of these for end-of-life or unsupported states
EOL_STATUSES = {"end-of-life", "eol", "dne", "ignored", "deferred"}


def _is_eol(status):
    """Return True if the Ubuntu status indicates EOL / unsupported / DNE."""
    if not status:
        return False
    return status.lower() in EOL_STATUSES or "end-of-life" in status.lower()


# ─────────────────────────────────────────
# MITRE
# ─────────────────────────────────────────

def get_mitre_cve(cve, debug=False):
    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    try:
        r = requests.get(url, timeout=15)
        if debug:
            print(f"[DEBUG] MITRE HTTP {r.status_code}")
        if r.status_code == 404:
            print(f"[WARN]  MITRE: CVE {cve} not found (404)")
            return None
        if r.status_code != 200:
            print(f"[WARN]  MITRE returned HTTP {r.status_code}")
            return None
        data = r.json()
        if debug:
            print(f"[DEBUG] MITRE keys: {list(data.keys())}")
        return data
    except requests.exceptions.Timeout:
        print(f"[WARN]  MITRE: request timed out")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[WARN]  MITRE: connection error — {e}")
        return None
    except Exception as e:
        print(f"[WARN]  MITRE: {e}")
        return None


# ─────────────────────────────────────────
# NVD
# ─────────────────────────────────────────

def get_nvd_cve(cve, debug=False):
    url = f"{NVD_API}?cveId={cve}"
    try:
        r = requests.get(url, timeout=15)
        if debug:
            print(f"[DEBUG] NVD HTTP {r.status_code}")
        if r.status_code == 404:
            print(f"[WARN]  NVD: CVE {cve} not found (404)")
            return None
        if r.status_code != 200:
            print(f"[WARN]  NVD returned HTTP {r.status_code}")
            return None
        data = r.json()
        vuln_count = len(data.get("vulnerabilities", []))
        if debug:
            print(f"[DEBUG] NVD vulnerabilities in response: {vuln_count}")
        if vuln_count == 0:
            print(f"[WARN]  NVD: no vulnerabilities found for {cve}")
        return data
    except requests.exceptions.Timeout:
        print(f"[WARN]  NVD: request timed out")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[WARN]  NVD: connection error — {e}")
        return None
    except Exception as e:
        print(f"[WARN]  NVD: {e}")
        return None


# ─────────────────────────────────────────
# MERGED MITRE + NVD
# ─────────────────────────────────────────

def merge_mitre_nvd(mitre_data, nvd_data):
    result = {
        "cve_id":        None,
        "state":         None,
        "assigner":      None,
        "published":     None,
        "severity":      None,
        "cvss_score":    None,
        "cvss_vector":   None,
        "last_modified": None,
        "description":   None,
        "cwes":          [],
        "references":    [],
        "sources":       [],
        "fetch_errors":  [],
    }

    # ── MITRE ──
    if mitre_data is None:
        result["fetch_errors"].append("MITRE data unavailable — API unreachable or CVE not found")
    elif "cveMetadata" not in mitre_data:
        result["fetch_errors"].append(f"MITRE returned unexpected format")
    else:
        result["sources"].append("MITRE")
        meta      = mitre_data.get("cveMetadata", {})
        container = mitre_data.get("containers", {}).get("cna", {})
        result["cve_id"]    = meta.get("cveId")
        result["state"]     = meta.get("state")
        result["assigner"]  = meta.get("assignerShortName")
        result["published"] = meta.get("datePublished")
        descs = container.get("descriptions", [])
        if descs:
            result["description"] = descs[0].get("value")
        for ref in container.get("references", []):
            url = ref.get("url", "")
            if url and url not in [r["url"] for r in result["references"]]:
                result["references"].append({"url": url, "tags": ref.get("tags", [])})

    # ── NVD ──
    if nvd_data is None:
        result["fetch_errors"].append("NVD data unavailable — API unreachable or rate-limited")
    elif "vulnerabilities" not in nvd_data:
        result["fetch_errors"].append(f"NVD returned unexpected format")
    elif len(nvd_data["vulnerabilities"]) == 0:
        result["fetch_errors"].append(f"NVD: CVE not found in database (0 results)")
    else:
        result["sources"].append("NVD")
        for item in nvd_data["vulnerabilities"]:
            c = item.get("cve", {})
            if not result["cve_id"]:
                result["cve_id"] = c.get("id")
            if not result["description"] and c.get("descriptions"):
                result["description"] = c["descriptions"][0]["value"]
            if not result["published"]:
                result["published"] = c.get("published")
            result["last_modified"] = c.get("lastModified")
            metrics = c.get("metrics", {})
            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]
                result["severity"]    = m["cvssData"]["baseSeverity"]
                result["cvss_score"]  = m["cvssData"]["baseScore"]
                result["cvss_vector"] = m["cvssData"].get("vectorString")
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]
                result["severity"]    = m["cvssData"]["baseSeverity"]
                result["cvss_score"]  = m["cvssData"]["baseScore"]
                result["cvss_vector"] = m["cvssData"].get("vectorString")
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]
                result["severity"]    = m["baseSeverity"]
                result["cvss_score"]  = m["cvssData"]["baseScore"]
                result["cvss_vector"] = m["cvssData"].get("vectorString")
            for w in c.get("weaknesses", []):
                for d in w.get("description", []):
                    val = d.get("value", "")
                    if val and val not in result["cwes"]:
                        result["cwes"].append(val)
            for ref in c.get("references", []):
                url = ref.get("url", "")
                if url and url not in [r["url"] for r in result["references"]]:
                    result["references"].append({"url": url, "tags": ref.get("tags", [])})

    return result


def print_merged(merged):
    errors = merged.get("fetch_errors", [])
    if errors:
        print("\n[WARN] Fetch issues:")
        for e in errors:
            print(f"       - {e}")
    label = " / ".join(f"{s} DATA" for s in merged["sources"]) if merged["sources"] else "CVE DATA"
    bar   = "=" * (len(label) + 6)
    print(f"\n{bar}")
    print(f"=== {label} ===")
    print(bar)
    if merged["cve_id"]:        print(f"CVE:           {merged['cve_id']}")
    if merged["state"]:         print(f"State:         {merged['state']}")
    if merged["severity"]:
        score = f"  (CVSS {merged['cvss_score']})" if merged["cvss_score"] else ""
        print(f"Severity:      {merged['severity']}{score}")
    if merged["cvss_vector"]:   print(f"CVSS Vector:   {merged['cvss_vector']}")
    if merged["assigner"]:      print(f"Assigner:      {merged['assigner']}")
    if merged["published"]:     print(f"Published:     {merged['published']}")
    if merged["last_modified"]: print(f"Last Modified: {merged['last_modified']}")
    if merged["cwes"]:          print(f"CWEs:          {', '.join(merged['cwes'])}")
    if merged["description"]:   print(f"Description:   {merged['description'][:300]}")
    if not merged["sources"]:
        print("  [No data retrieved from MITRE or NVD]")


# ─────────────────────────────────────────
# UBUNTU
# ─────────────────────────────────────────

def get_ubuntu_cve(cve):
    try:
        r = requests.get(f"{UBUNTU_API}/{cve}.json", timeout=15)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def _get_release_key(status_item):
    return (
        status_item.get("release_codename") or
        status_item.get("release") or
        ""
    )


def parse_ubuntu_all(data, target_releases=None):
    out = {
        "priority":     None,
        "not_affected": False,
        "by_release":   {},
        "all_packages": [],
    }
    if not data:
        out["not_affected"] = True
        return out

    out["priority"] = data.get("priority", "unknown")
    releases_to_check = target_releases or UBUNTU_CODENAMES
    packages = data.get("packages", [])

    for r in releases_to_check:
        out["by_release"][r] = []

    if not packages:
        out["not_affected"] = True
        return out

    if isinstance(packages, list):
        for pkg in packages:
            pkg_name = pkg.get("name", "")
            for s in pkg.get("statuses", []):
                rel = _get_release_key(s)
                if rel not in releases_to_check:
                    continue
                entry = {
                    "name":        pkg_name,
                    "release":     rel,
                    "status":      s.get("status", "unknown"),
                    "description": s.get("description", ""),
                    "component":   s.get("component", ""),
                    "pocket":      s.get("pocket", ""),
                }
                out["by_release"][rel].append(entry)
                out["all_packages"].append(entry)

    elif isinstance(packages, dict):
        for pkg_name, releases in packages.items():
            for rel in releases_to_check:
                if rel not in releases:
                    continue
                rel_data = releases[rel]
                entry = {
                    "name":        pkg_name,
                    "release":     rel,
                    "status":      rel_data.get("status", "unknown"),
                    "description": rel_data.get("description", ""),
                    "component":   rel_data.get("component", ""),
                    "pocket":      rel_data.get("pocket", ""),
                }
                out["by_release"][rel].append(entry)
                out["all_packages"].append(entry)

    if not out["all_packages"]:
        out["not_affected"] = True

    return out


def print_ubuntu_all(parsed, target_releases=None):
    releases = target_releases or UBUNTU_CODENAMES
    rl       = dict(UBUNTU_RELEASES)
    print("\n========= UBUNTU ANALYSIS =========")
    if parsed["not_affected"]:
        print(f"[UBUNTU] Priority : {parsed.get('priority') or 'N/A'}")
        print(f"[UBUNTU] NOT AFFECTED — no affected packages found")
        return
    print(f"[UBUNTU] Priority: {parsed['priority']}\n")
    print(f"  {'Release':<28} {'Package':<38} {'Status':<28} {'Component'}")
    print("  " + "─" * 100)
    for release in releases:
        label = rl.get(release, release)
        pkgs  = parsed["by_release"].get(release, [])
        if pkgs:
            for p in pkgs:
                eol_flag = " [EOL]" if _is_eol(p["status"]) else ""
                print(f"  {label:<28} {p['name']:<38} {p['status'] + eol_flag:<28} {p.get('component','')}")
        else:
            print(f"  {label:<28} {'Not in release':<38}")


# ─────────────────────────────────────────
# DEBIAN
# ─────────────────────────────────────────

def get_debian_data_cached():
    if os.path.exists(DEBIAN_CACHE_FILE):
        age_hours = (time.time() - os.path.getmtime(DEBIAN_CACHE_FILE)) / 3600
        if age_hours < CACHE_TTL_HOURS:
            print("[DEBIAN] Using cached tracker data ...")
            with open(DEBIAN_CACHE_FILE) as f:
                return json.load(f)
    print("[DEBIAN] Fetching Debian Security Tracker (~20MB) ...")
    r = requests.get(DEBIAN_API, timeout=90)
    data = r.json()
    with open(DEBIAN_CACHE_FILE, "w") as f:
        json.dump(data, f)
    return data


def get_debian_cve(cve):
    try:
        full    = get_debian_data_cached()
        results = {}
        for pkg_name, cve_map in full.items():
            if cve in cve_map:
                results[pkg_name] = cve_map[cve]
        return results if results else None
    except Exception as e:
        print(f"[DEBIAN] Error: {e}")
        return None


def parse_debian_all(data, target_releases=None):
    """
    The Debian Security Tracker JSON structure is:
      { package: { CVE: { releases: { "bookworm": {
            status, urgency, fixed_version,
            repositories: { "bookworm": "ver", "bookworm-security": "ver" }
          }}}}}

    Security pocket data lives INSIDE the base release entry under repositories,
    not as a separate top-level release key. So we expand each base release into
    up to two rows: one for the base repo and one for the -security repo.
    """
    rows = []
    if not data:
        return rows

    releases_to_check = target_releases or DEBIAN_CODENAMES
    release_order     = {r: i for i, r in enumerate(DEBIAN_CODENAMES)}

    for pkg_name, entry in data.items():
        pkg_releases = entry.get("releases", {})

        for release in releases_to_check:
            if release not in pkg_releases:
                continue

            rd            = pkg_releases[release]
            status        = rd.get("status", "unknown")
            fixed_version = rd.get("fixed_version", "")
            repositories  = rd.get("repositories", {})

            def _display_fixed(ver, st):
                if st == "resolved" and ver:
                    return ver
                if st == "open":
                    return "(unfixed)"
                if st == "undetermined":
                    return "(undetermined)"
                if "not affected" in st.lower():
                    return "(not affected)"
                return ver or f"({st})"

            # ── base release row ──
            base_ver = repositories.get(release, fixed_version)
            rows.append({
                "package":       pkg_name,
                "release":       release,
                "release_label": release,           # resolved in print/html
                "fixed_version": _display_fixed(base_ver or fixed_version, status),
                "status":        status,
            })

            # ── security pocket row (if present) ──
            sec_key = f"{release}-security"
            if sec_key in repositories and release in DEBIAN_SECURITY_RELEASES:
                sec_ver = repositories[sec_key]
                rows.append({
                    "package":       pkg_name,
                    "release":       release,
                    "release_label": sec_key,       # shows as "bookworm (security)"
                    "fixed_version": _display_fixed(sec_ver, status),
                    "status":        status,
                })

    # Sort by package name then by release order, security pocket right after base
    def sort_key(x):
        base   = x["release"]
        is_sec = x["release_label"].endswith("-security")
        return (x["package"], release_order.get(base, 99), int(is_sec))

    rows.sort(key=sort_key)
    return rows


def print_debian_all(rows):
    rl = dict(DEBIAN_RELEASES)
    # also map security pocket labels
    sec_labels = {f"{r}-security": f"{r} (security)" for r in DEBIAN_SECURITY_RELEASES}

    print("\n========= DEBIAN ANALYSIS =========")
    if not rows:
        print("[DEBIAN] NOT AFFECTED — CVE not found in Debian Security Tracker")
        return
    print(f"  {'Package':<30} {'Release':<28} {'Fixed Version':<30} {'Status'}")
    print("  " + "─" * 98)
    for r in rows:
        lbl = r.get("release_label", r["release"])
        display = sec_labels.get(lbl) or rl.get(lbl, lbl)
        print(f"  {r['package']:<30} {display:<28} {r['fixed_version']:<30} {r['status']}")


# ─────────────────────────────────────────
# JSON REPORT
# ─────────────────────────────────────────

def build_json_report(cve_id, merged, ubuntu_parsed, ubuntu_releases_used,
                      debian_rows, debian_releases_used):
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "cve_id":       cve_id,
        "overview": {
            "cve_id":        cve_id,
            "state":         merged["state"],
            "severity":      merged["severity"],
            "cvss_score":    merged["cvss_score"],
            "cvss_vector":   merged["cvss_vector"],
            "assigner":      merged["assigner"],
            "published":     merged["published"],
            "last_modified": merged["last_modified"],
            "description":   merged["description"],
            "cwes":          merged["cwes"],
            "references":    merged["references"][:10],
            "sources":       merged["sources"],
            "fetch_errors":  merged.get("fetch_errors", []),
        },
        "ubuntu": {
            "releases_checked": ubuntu_releases_used,
            "priority":         ubuntu_parsed["priority"],
            "not_affected":     ubuntu_parsed["not_affected"],
            "by_release":       ubuntu_parsed["by_release"],
            "all_packages":     ubuntu_parsed["all_packages"],
        },
        "debian": {
            "releases_checked": debian_releases_used,
            "not_affected":     len(debian_rows) == 0,
            "packages":         debian_rows,
        },
    }


# ─────────────────────────────────────────
# HTML BADGE HELPERS
# ─────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": ("#7f1d1d", "#fca5a5"),
    "HIGH":     ("#7c2d12", "#fdba74"),
    "MEDIUM":   ("#713f12", "#fcd34d"),
    "LOW":      ("#14532d", "#86efac"),
    "UNKNOWN":  ("#1e3a5f", "#93c5fd"),
}


def sev_badge(sev):
    if not sev:
        sev = "UNKNOWN"
    s = sev.upper()
    bg, fg = SEV_COLOR.get(s, SEV_COLOR["UNKNOWN"])
    return f'<span class="badge" style="background:{fg};color:{bg}">{s}</span>'


def status_badge(st):
    if not st:
        st = "unknown"
    sl = st.lower()
    if "resolved" in sl or "released" in sl:
        return f'<span class="badge" style="background:#bbf7d0;color:#14532d">{st}</span>'
    if "not-affected" in sl or "not affected" in sl:
        return f'<span class="badge" style="background:#d1fae5;color:#065f46">{st}</span>'
    if "open" in sl or "unfixed" in sl:
        return f'<span class="badge" style="background:#fde68a;color:#7c2d12">{st}</span>'
    if "triage" in sl:
        return f'<span class="badge" style="background:#bae6fd;color:#0c4a6e">{st}</span>'
    # EOL / DNE / ignored / deferred — amber warning
    if _is_eol(st):
        return (
            f'<span class="badge" style="background:#431407;color:#fb923c;'
            f'border:1px solid #9a3412">&#9888; {st}</span>'
        )
    return f'<span class="badge" style="background:#374151;color:#9ca3af">{st}</span>'


def _not_affected_banner(distro, color_border, color_bg, color_text, color_icon):
    return (
        f'<div style="display:flex;align-items:center;gap:1rem;padding:1.25rem 1.5rem;'
        f'background:{color_bg};border:1px solid {color_border};border-radius:8px;'
        f'border-left:4px solid {color_icon};">'
        f'<svg width="20" height="20" viewBox="0 0 20 20" fill="none" style="flex-shrink:0">'
        f'<circle cx="10" cy="10" r="9" stroke="{color_icon}" stroke-width="1.5"/>'
        f'<path d="M6 10l3 3 5-5" stroke="{color_icon}" stroke-width="1.5"'
        f' stroke-linecap="round" stroke-linejoin="round"/>'
        f'</svg>'
        f'<div>'
        f'<div style="font-weight:600;color:{color_text};font-size:14px;margin-bottom:2px">'
        f'Not Affected \u2014 {distro}</div>'
        f'<div style="font-size:13px;color:{color_text};opacity:.8">'
        f'This CVE does not affect any {distro} packages across all checked releases.</div>'
        f'</div></div>'
    )


# ─────────────────────────────────────────
# CVE SUMMARY SECTION
# ─────────────────────────────────────────

def cve_summary_html(ov):
    """
    ov  =  report["overview"]  which now always contains all fields including cve_id.
    """
    cve    = ov.get("cve_id") or "—"
    sev    = (ov.get("severity") or "UNKNOWN").upper()
    score  = ov.get("cvss_score") or "—"
    vector = ov.get("cvss_vector") or ""
    state  = ov.get("state")  or "—"
    asgn   = ov.get("assigner") or "—"
    pub    = (ov.get("published")     or "—")[:10]
    mod    = (ov.get("last_modified") or "—")[:10]
    desc   = ov.get("description") or "No description available."
    cwes   = ov.get("cwes", []) or []
    refs   = (ov.get("references") or [])[:10]
    src    = " / ".join(ov.get("sources", []) or [])
    errors = ov.get("fetch_errors", []) or []

    # ── fetch error banner ──
    error_html = ""
    if errors:
        error_items = "".join(
            f'<li style="padding:.2rem 0;font-size:12px;color:#fca5a5">'
            f'⚠ {e}</li>'
            for e in errors
        )
        error_html = (
            f'<div style="background:#1a0a0a;border:1px solid #7f1d1d;border-left:4px solid #ef4444;'
            f'border-radius:8px;padding:1rem 1.25rem;margin-bottom:1.25rem">'
            f'<div style="font-size:12px;font-weight:600;color:#fca5a5;'
            f'font-family:var(--font-mono);margin-bottom:.4rem">Data Fetch Issues</div>'
            f'<ul style="list-style:none">{error_items}</ul>'
            f'<div style="font-size:11px;color:#9ca3af;margin-top:.5rem">'
            f'Run with <code>--debug</code> for more detail. '
            f'NVD may rate-limit unauthenticated requests — '
            f'add <code>--nvd-api-key YOUR_KEY</code> if you have one.</div>'
            f'</div>'
        )

    cwe_html = ""
    if cwes:
        pills = " ".join(
            f'<span class="badge" style="background:#1f2937;color:#93c5fd;'
            f'border:1px solid #30363d">{c}</span>'
            for c in cwes
        )
        cwe_html = f'<div style="margin-top:.75rem">{pills}</div>'

    ref_items = ""
    for ref in refs:
        url  = ref.get("url", "")
        tags = ref.get("tags", [])
        tag_str = " ".join(
            f'<span style="font-size:10px;background:#1f2937;color:#8b949e;'
            f'padding:1px 6px;border-radius:3px">{t}</span>'
            for t in tags
        )
        ref_items += (
            f'<li style="padding:.35rem 0;border-bottom:1px solid #30363d;'
            f'display:flex;align-items:flex-start;gap:.5rem;flex-wrap:wrap">'
            f'<a href="{url}" target="_blank" style="color:#58a6ff;font-size:12px;'
            f'font-family:var(--font-mono);word-break:break-all;flex:1">{url}</a>'
            f'{tag_str}</li>'
        )
    ref_html = ""
    if ref_items:
        ref_html = (
            f'<div style="margin-top:1.5rem">'
            f'<div style="font-size:11px;font-family:var(--font-mono);color:#8b949e;'
            f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.5rem">'
            f'References ({len(refs)})</div>'
            f'<ul style="list-style:none;border-top:1px solid #30363d">{ref_items}</ul>'
            f'</div>'
        )

    vector_html = ""
    if vector:
        vector_html = (
            f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
            f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.35rem">CVSS Vector</div>'
            f'<div style="font-family:var(--font-mono);font-size:12px;color:#79c0ff;'
            f'margin-bottom:1rem">{vector}</div>'
        )

    cwe_section = ""
    if cwes:
        cwe_section = (
            f'<div style="margin-top:1rem">'
            f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
            f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.4rem">Weakness (CWE)</div>'
            f'{cwe_html}</div>'
        )

    return (
        f'<div style="background:var(--surface);border:1px solid var(--border);'
        f'border-radius:8px;padding:1.5rem">'

        f'{error_html}'

        # ── metadata grid ──
        f'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));'
        f'gap:1px;background:var(--border);border:1px solid var(--border);'
        f'border-radius:6px;overflow:hidden;margin-bottom:1.25rem">'

        f'<div style="background:var(--surface2);padding:.8rem 1rem">'
        f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
        f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.25rem">Severity</div>'
        f'<div>{sev_badge(sev)}</div></div>'

        f'<div style="background:var(--surface2);padding:.8rem 1rem">'
        f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
        f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.25rem">CVSS Score</div>'
        f'<div style="font-weight:600;font-size:14px">{score}</div></div>'

        f'<div style="background:var(--surface2);padding:.8rem 1rem">'
        f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
        f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.25rem">State</div>'
        f'<div style="font-weight:600;font-size:13px;color:#e6edf3">{state}</div></div>'

        f'<div style="background:var(--surface2);padding:.8rem 1rem">'
        f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
        f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.25rem">Assigner</div>'
        f'<div style="font-size:13px;color:#e6edf3">{asgn}</div></div>'

        f'<div style="background:var(--surface2);padding:.8rem 1rem">'
        f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
        f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.25rem">Published</div>'
        f'<div style="font-family:var(--font-mono);font-size:12px">{pub}</div></div>'

        f'<div style="background:var(--surface2);padding:.8rem 1rem">'
        f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
        f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.25rem">Last Modified</div>'
        f'<div style="font-family:var(--font-mono);font-size:12px">{mod}</div></div>'

        f'</div>'  # end grid

        f'{vector_html}'

        # ── description ──
        f'<div style="font-size:10px;font-family:var(--font-mono);color:#8b949e;'
        f'text-transform:uppercase;letter-spacing:.08em;margin-bottom:.4rem">Description</div>'
        f'<div style="font-size:14px;color:#cdd9e5;line-height:1.8;'
        f'border-left:3px solid #58a6ff;padding-left:1rem">{desc}</div>'

        f'{cwe_section}'
        f'{ref_html}'

        f'<div style="margin-top:1rem;font-size:11px;color:#4b5563;'
        f'font-family:var(--font-mono)">Source: {src}</div>'
        f'</div>'
    )


# ─────────────────────────────────────────
# UBUNTU SECTION
# ─────────────────────────────────────────

def ubuntu_section_html(ubuntu_parsed):
    if ubuntu_parsed.get("not_affected"):
        return _not_affected_banner(
            "Ubuntu", "#166534", "#0d1f0d", "#86efac", "#16a34a"
        )

    rows_html = ""
    for codename, label in UBUNTU_RELEASES:
        pkgs = ubuntu_parsed["by_release"].get(codename, [])
        if pkgs:
            for i, p in enumerate(pkgs):
                eol = _is_eol(p["status"])

                # Full row amber tint for EOL/DNE
                row_style = ' style="background:rgba(251,146,60,.07)"' if eol else ""

                # Release label cell — only on first package of this release
                if i == 0:
                    rel_color  = "#fb923c" if eol else "#93c5fd"
                    rel_prefix = "&#9888; " if eol else ""
                    rel_cell   = (
                        f'<td rowspan="{len(pkgs)}" style="font-family:var(--font-mono);'
                        f'font-size:12px;vertical-align:middle;white-space:nowrap;'
                        f'color:{rel_color}">{rel_prefix}{label}</td>'
                    )
                else:
                    rel_cell = ""

                info       = p.get("description", "") or "—"
                comp       = p.get("component",   "") or "—"
                info_color = "#b45309" if eol else "#8b949e"

                rows_html += (
                    f'<tr{row_style}>'
                    f'{rel_cell}'
                    f'<td><code>{p["name"]}</code></td>'
                    f'<td style="font-size:12px;color:#8b949e">{comp}</td>'
                    f'<td>{status_badge(p["status"])}</td>'
                    f'<td style="font-size:12px;color:{info_color};'
                    f'font-family:var(--font-mono)">{info}</td>'
                    f'</tr>'
                )
        else:
            rows_html += (
                f'<tr>'
                f'<td style="font-family:var(--font-mono);font-size:12px;color:#4b5563">{label}</td>'
                f'<td colspan="4" style="color:#4b5563;font-style:italic;font-size:12px">'
                f'Not in release</td>'
                f'</tr>'
            )

    return (
        f'<div class="tbl-wrap"><table>'
        f'<thead><tr>'
        f'<th>Release</th><th>Package</th><th>Component</th>'
        f'<th>Status</th><th>Fixed Version / Info</th>'
        f'</tr></thead>'
        f'<tbody>{rows_html}</tbody>'
        f'</table></div>'
    )


# ─────────────────────────────────────────
# DEBIAN SECTION
# ─────────────────────────────────────────

def debian_section_html(debian_rows):
    if not debian_rows:
        return _not_affected_banner(
            "Debian", "#1e3a5f", "#0d1a2d", "#93c5fd", "#3b82f6"
        )

    rl        = dict(DEBIAN_RELEASES)
    sec_labels = {f"{r}-security": f"{r} (security)" for r in DEBIAN_SECURITY_RELEASES}
    rows_html = ""

    for r in debian_rows:
        # Resolve display label — security pocket gets "(security)" suffix
        lbl     = r.get("release_label", r["release"])
        rel_display = sec_labels.get(lbl) or rl.get(lbl, lbl)
        is_sec  = lbl.endswith("-security")
        rel_color = "#c4b5fd" if is_sec else "#93c5fd"  # purple tint for security rows

        fixed = r["fixed_version"] or "—"
        if "(unfixed)" in fixed:
            fv = (f'<td style="color:#fdba74;font-family:var(--font-mono);'
                  f'font-size:12px">{fixed}</td>')
        elif "(not affected)" in fixed:
            fv = (f'<td style="color:#86efac;font-family:var(--font-mono);'
                  f'font-size:12px">{fixed}</td>')
        elif fixed and fixed not in ("—", "(undetermined)"):
            fv = f'<td><code>{fixed}</code></td>'
        else:
            fv = f'<td style="color:#4b5563;font-size:12px">{fixed}</td>'

        rows_html += (
            f'<tr>'
            f'<td><code>{r["package"]}</code></td>'
            f'<td style="font-family:var(--font-mono);font-size:12px;'
            f'white-space:nowrap;color:{rel_color}">{rel_display}</td>'
            f'{fv}'
            f'<td>{status_badge(r["status"])}</td>'
            f'</tr>'
        )

    return (
        f'<div class="tbl-wrap"><table>'
        f'<thead><tr>'
        f'<th>Package</th><th>Release</th>'
        f'<th>Fixed Version</th><th>Status</th>'
        f'</tr></thead>'
        f'<tbody>{rows_html}</tbody>'
        f'</table></div>'
    )


# ─────────────────────────────────────────
# HTML REPORT BUILDER
# ─────────────────────────────────────────

def build_html_report(report):
    # ── overview dict now always has cve_id stored inside it ──
    ov    = report["overview"]
    cve   = report["cve_id"]
    sev   = (ov.get("severity") or "UNKNOWN").upper()
    bg, _ = SEV_COLOR.get(sev, SEV_COLOR["UNKNOWN"])
    ts    = report["generated_at"]
    src   = " / ".join(ov.get("sources", []) or []) or "N/A"

    u_data  = report["ubuntu"]
    u_na    = u_data.get("not_affected", False)
    u_pri   = u_data.get("priority") or "unknown"
    u_count = len(u_data.get("releases_checked", UBUNTU_CODENAMES))

    d_data  = report["debian"]
    d_na    = d_data.get("not_affected", False)
    d_count = len(d_data.get("releases_checked", DEBIAN_CODENAMES))

    # ── pass ov directly — it already contains all fields including cve_id ──
    summary_html = cve_summary_html(ov)
    ubuntu_html  = ubuntu_section_html({
        "priority":     u_pri,
        "not_affected": u_na,
        "by_release":   u_data.get("by_release", {}),
    })
    debian_html = debian_section_html(d_data.get("packages", []))

    u_badge = (
        '<span class="badge" style="background:#d1fae5;color:#065f46">NOT AFFECTED</span>'
        if u_na else status_badge(u_pri)
    )
    d_badge = (
        '<span class="badge" style="background:#dbeafe;color:#1e40af">NOT AFFECTED</span>'
        if d_na else
        '<span class="badge" style="background:#374151;color:#9ca3af">AFFECTED</span>'
    )

    css = (
        ":root{"
        "--bg:#0d1117;--surface:#161b22;--surface2:#1f2937;"
        "--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;"
        "--font-sans:'IBM Plex Sans',sans-serif;--font-mono:'IBM Plex Mono',monospace"
        "}"
        "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}"
        "body{background:var(--bg);color:var(--text);font-family:var(--font-sans);font-size:15px;line-height:1.7}"
        ".header{background:var(--surface);border-bottom:1px solid var(--border);padding:2rem 3rem;display:flex;align-items:flex-start;gap:2rem}"
        ".sev-bar{width:6px;min-height:80px;border-radius:3px;flex-shrink:0}"
        ".header-meta{font-family:var(--font-mono);font-size:11px;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-bottom:.4rem}"
        ".header h1{font-size:2rem;font-weight:600;font-family:var(--font-mono);letter-spacing:-.02em;color:var(--text);margin-bottom:.6rem}"
        ".header-badges{display:flex;gap:.5rem;flex-wrap:wrap}"
        ".badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;font-family:var(--font-mono);letter-spacing:.05em;text-transform:uppercase}"
        ".main{max-width:1200px;margin:0 auto;padding:2.5rem 3rem}"
        ".section{margin-bottom:2.5rem}"
        ".section-title{font-family:var(--font-mono);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);border-bottom:1px solid var(--border);padding-bottom:.6rem;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}"
        ".section-title::before{content:'';display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--accent);flex-shrink:0}"
        "table{width:100%;border-collapse:collapse;font-size:13px}"
        "th{text-align:left;padding:.6rem 1rem;font-family:var(--font-mono);font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);background:var(--surface2);border-bottom:1px solid var(--border)}"
        "td{padding:.65rem 1rem;border-bottom:1px solid var(--border);vertical-align:middle}"
        "tr:last-child td{border-bottom:none}"
        "tr:hover td{background:rgba(88,166,255,.04)}"
        ".tbl-wrap{border:1px solid var(--border);border-radius:8px;overflow:hidden;overflow-x:auto}"
        "code{font-family:var(--font-mono);font-size:12px;background:var(--surface2);padding:1px 6px;border-radius:4px;color:#79c0ff}"
        ".footer{border-top:1px solid var(--border);padding:1.5rem 3rem;font-size:12px;color:var(--muted);font-family:var(--font-mono);display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem}"
    )

    cvss_badge = (
        f'<span class="badge" style="background:#21262d;color:#58a6ff">'
        f'CVSS {ov.get("cvss_score")}</span>'
        if ov.get("cvss_score") else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CVE Report \u2014 {cve}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet"/>
<style>{css}</style>
</head>
<body>

<div class="header">
  <div class="sev-bar" style="background:{bg}"></div>
  <div style="flex:1">
    <div class="header-meta">Security Vulnerability Report &nbsp;&middot;&nbsp; {ts}</div>
    <h1>{cve}</h1>
    <div class="header-badges">
      {sev_badge(sev)}
      <span class="badge" style="background:#21262d;color:#8b949e">{ov.get('state') or 'UNKNOWN'}</span>
      <span class="badge" style="background:#21262d;color:#8b949e">Source: {src}</span>
      {cvss_badge}
      <span class="badge" style="background:#21262d;color:#f0883e">Ubuntu: {u_pri}</span>
    </div>
  </div>
</div>

<div class="main">

  <div class="section">
    <div class="section-title">CVE Details &nbsp;&middot;&nbsp; {cve}</div>
    {summary_html}
  </div>

  <div class="section">
    <div class="section-title">
      Ubuntu Analysis &nbsp;&middot;&nbsp; {u_badge} &nbsp;&middot;&nbsp; {u_count} releases checked
    </div>
    {ubuntu_html}
  </div>

  <div class="section">
    <div class="section-title">
      Debian Analysis &nbsp;&middot;&nbsp; {d_badge} &nbsp;&middot;&nbsp; {d_count} releases checked
    </div>
    {debian_html}
  </div>

</div>

<div class="footer">
  <span>CVE Scanner &nbsp;&middot;&nbsp; MITRE / NVD / Ubuntu / Debian</span>
  <span>{cve} &nbsp;&middot;&nbsp; {ts}</span>
</div>

</body></html>"""


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Multi-distro CVE Scanner: MITRE + NVD + Ubuntu + Debian"
    )
    parser.add_argument("--cve", required=True,
                        help="CVE ID  e.g. CVE-2023-44487")
    parser.add_argument("--ubuntu-release", default=None,
                        help=f"Single Ubuntu release (omit = all). Options: {', '.join(UBUNTU_CODENAMES)}")
    parser.add_argument("--debian-release", default=None,
                        help=f"Single Debian release (omit = all). Options: {', '.join(DEBIAN_CODENAMES)}")
    args = parser.parse_args()

    cve_id = args.cve.upper().strip()

    ubuntu_releases = [args.ubuntu_release] if args.ubuntu_release else UBUNTU_CODENAMES
    debian_releases = [args.debian_release] if args.debian_release else DEBIAN_CODENAMES

    out_dir = cve_id
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n[INFO] CVE             : {cve_id}")
    print(f"[INFO] Output dir      : {out_dir}/")
    print(f"[INFO] Ubuntu releases : {', '.join(ubuntu_releases)}")
    print(f"[INFO] Debian releases : {', '.join(debian_releases)}")

    print(f"\n[INFO] Fetching MITRE data ...")
    mitre_raw = get_mitre_cve(cve_id)

    print(f"[INFO] Fetching NVD data ...")
    nvd_raw   = get_nvd_cve(cve_id)

    print(f"[INFO] Fetching Ubuntu data ...")
    ubuntu_raw    = get_ubuntu_cve(cve_id)
    ubuntu_parsed = parse_ubuntu_all(ubuntu_raw, ubuntu_releases)

    print(f"[INFO] Fetching Debian data ...")
    debian_raw  = get_debian_cve(cve_id)
    debian_rows = parse_debian_all(debian_raw, debian_releases)

    merged = merge_mitre_nvd(mitre_raw, nvd_raw)
    print_merged(merged)
    print_ubuntu_all(ubuntu_parsed, ubuntu_releases)
    print_debian_all(debian_rows)

    report = build_json_report(cve_id, merged, ubuntu_parsed, ubuntu_releases,
                               debian_rows, debian_releases)

    json_path = os.path.join(out_dir, f"{cve_id}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[INFO] JSON report  -> {json_path}")

    html_path = os.path.join(out_dir, f"{cve_id}_report.html")
    with open(html_path, "w") as f:
        f.write(build_html_report(report))
    print(f"[INFO] HTML report  -> {html_path}")
    print(f"[INFO] Done.\n")


if __name__ == "__main__":
    main()