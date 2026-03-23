#!/usr/bin/env python3
"""
Package Universe — Flask Backend
Run: python3 server.py
Then open: http://localhost:5000
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests as req
import json, os, time
from pathlib import Path
from datetime import datetime, timezone

app = Flask(__name__, static_folder=".")
CORS(app)

TIMEOUT = 20
SESSION = req.Session()
SESSION.headers.update({"User-Agent": "Package-Universe/2.0"})

# ── sources.json ────────────────────────────────────────────
SOURCES_FILE = Path(__file__).parent / "sources.json"

def load_sources():
    with open(SOURCES_FILE) as f:
        return json.load(f)

# ── HTTP ────────────────────────────────────────────────────
def get_json(url):
    try:
        r = SESSION.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None

# ── MITRE + NVD ─────────────────────────────────────────────
def fetch_mitre(cve, cfg):
    url = cfg["meta_sources"]["mitre"]["cve_url"].replace("{CVE}", cve)
    return get_json(url)

def fetch_nvd(cve, cfg):
    url = cfg["meta_sources"]["nvd"]["cve_url"].replace("{CVE}", cve)
    return get_json(url)

def merge_mitre_nvd(mitre, nvd):
    r = dict(cve_id=None, state=None, assigner=None, published=None,
             severity=None, cvss_score=None, cvss_vector=None,
             last_modified=None, description=None,
             cwes=[], references=[], sources=[], errors=[])

    if not mitre or "cveMetadata" not in mitre:
        r["errors"].append("MITRE: unavailable or CVE not found")
    else:
        r["sources"].append("MITRE")
        meta = mitre.get("cveMetadata", {})
        cna  = mitre.get("containers", {}).get("cna", {})
        r["cve_id"]    = meta.get("cveId")
        r["state"]     = meta.get("state")
        r["assigner"]  = meta.get("assignerShortName")
        r["published"] = meta.get("datePublished")
        descs = cna.get("descriptions", [])
        if descs:
            r["description"] = descs[0].get("value")
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            if url and url not in [x["url"] for x in r["references"]]:
                r["references"].append({"url": url, "tags": ref.get("tags", [])})

    if not nvd:
        r["errors"].append("NVD: unavailable or rate-limited")
    else:
        vulns = nvd.get("vulnerabilities", [])
        if not vulns:
            r["errors"].append("NVD: CVE not found")
        else:
            r["sources"].append("NVD")
            c = vulns[0].get("cve", {})
            if not r["cve_id"]:    r["cve_id"]     = c.get("id")
            if not r["description"] and c.get("descriptions"):
                r["description"] = c["descriptions"][0]["value"]
            if not r["published"]: r["published"]  = c.get("published")
            r["last_modified"] = c.get("lastModified")
            m = c.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in m and not r["severity"]:
                    d  = m[key][0]
                    cd = d.get("cvssData", d)
                    r["severity"]    = cd.get("baseSeverity") or d.get("baseSeverity")
                    r["cvss_score"]  = cd.get("baseScore")
                    r["cvss_vector"] = cd.get("vectorString")
            for w in c.get("weaknesses", []):
                for d in w.get("description", []):
                    v = d.get("value", "")
                    if v and v not in r["cwes"]:
                        r["cwes"].append(v)
            for ref in c.get("references", []):
                url = ref.get("url", "")
                if url and url not in [x["url"] for x in r["references"]]:
                    r["references"].append({"url": url, "tags": ref.get("tags", [])})
    return r

# ── UBUNTU ──────────────────────────────────────────────────
def fetch_ubuntu_cve(cve, dcfg):
    return get_json(dcfg["cve_url"].replace("{CVE}", cve))

def fetch_ubuntu_package(pkg, dcfg):
    return get_json(dcfg["package_url"].replace("{PKG}", pkg))

def parse_ubuntu_cve(data, dcfg):
    releases = [r[0] for r in dcfg.get("releases", [])]
    out = {"priority": None, "not_affected": False, "by_release": {r: [] for r in releases}}
    if not data:
        out["not_affected"] = True
        return out
    out["priority"] = data.get("priority", "unknown")
    pkgs = data.get("packages", [])
    if not pkgs:
        out["not_affected"] = True
        return out

    def add(name, rel, s):
        if rel in out["by_release"]:
            out["by_release"][rel].append({
                "name": name, "release": rel,
                "status": s.get("status", "unknown"),
                "description": s.get("description", ""),
                "component": s.get("component", ""),
            })

    if isinstance(pkgs, list):
        for p in pkgs:
            for s in p.get("statuses", []):
                rel = s.get("release_codename") or s.get("release", "")
                add(p.get("name", ""), rel, s)
    elif isinstance(pkgs, dict):
        for name, rels in pkgs.items():
            for rel in releases:
                if rel in rels:
                    add(name, rel, rels[rel])

    if not sum(len(v) for v in out["by_release"].values()):
        out["not_affected"] = True
    return out

def parse_ubuntu_package(data):
    if not data:
        return []
    cves = data.get("cves", data) if isinstance(data, dict) else data
    if not isinstance(cves, list):
        return []
    return [{"id": c.get("id") or c.get("cve_id", ""),
             "priority": c.get("ubuntu_priority") or c.get("priority", "unknown")}
            for c in cves if c.get("id") or c.get("cve_id")]

# ── DEBIAN ──────────────────────────────────────────────────
def fetch_debian_cve(cve, dcfg):
    return get_json(dcfg["cve_url"].replace("{CVE}", cve))

def fetch_debian_package(pkg, dcfg):
    return get_json(dcfg["package_url"].replace("{PKG}", pkg))

def parse_debian_cve(data, dcfg):
    rows = []
    if not data:
        return rows
    releases  = [r[0] for r in dcfg.get("releases", [])]
    sec_rels  = set(dcfg.get("security_pocket_releases", []))
    rel_order = {r: i for i, r in enumerate(releases)}

    def disp(ver, st):
        if st == "resolved" and ver: return ver
        if st == "open":             return "(unfixed)"
        if st == "undetermined":     return "(undetermined)"
        if st and "not affected" in st: return "(not affected)"
        return ver or f"({st})"

    for pkg, info in data.items():
        pr = info.get("releases", info) or {}
        for rel in releases:
            if rel not in pr: continue
            rd     = pr[rel]
            status = rd.get("status", "unknown")
            fixed  = rd.get("fixed_version", "")
            repos  = rd.get("repositories", {})
            rows.append({"package": pkg, "release": rel, "release_label": rel,
                         "fixed_version": disp(repos.get(rel, fixed), status), "status": status})
            sec_key = f"{rel}-security"
            if sec_key in repos and rel in sec_rels:
                rows.append({"package": pkg, "release": rel, "release_label": sec_key,
                             "fixed_version": disp(repos[sec_key], status), "status": status})

    rows.sort(key=lambda x: (x["package"], rel_order.get(x["release"], 99),
                              x["release_label"].endswith("-security")))
    return rows

def parse_debian_package(data):
    if not data:
        return []
    return [{"id": cve, "description": info.get("description", ""), "scope": info.get("scope", "")}
            for cve, info in data.items()]

# ── RED HAT ─────────────────────────────────────────────────
def fetch_rhel_cve(cve, dcfg):
    return get_json(dcfg["cve_url"].replace("{CVE}", cve))

def fetch_rhel_package(pkg, dcfg):
    return get_json(dcfg["package_url"].replace("{PKG}", pkg))

def parse_rhel_cve(data, dcfg):
    products = dcfg.get("products", {})
    if not data:
        return {"not_affected": True, "rows": [], "threat_severity": None}
    rows, seen = [], set()
    for rel in data.get("affected_release", []):
        prod  = rel.get("product_name", "")
        short = next((v for k, v in products.items() if k in prod), prod[:40])
        key   = f"{short}|{rel.get('package','')}|Fixed"
        if key in seen: continue
        seen.add(key)
        rows.append({"product": short, "package": rel.get("package", "—"),
                     "advisory": rel.get("advisory", ""), "status": "Fixed",
                     "fixed_version": rel.get("package", "—")})
    for ps in data.get("package_state", []):
        prod  = ps.get("product_name", "")
        short = next((v for k, v in products.items() if k in prod), prod[:40])
        st    = ps.get("fix_state", "Affected")
        key   = f"{short}|{ps.get('package_name','')}|{st}"
        if key in seen: continue
        seen.add(key)
        rows.append({"product": short, "package": ps.get("package_name", "—"),
                     "advisory": "", "status": st, "fixed_version": ""})
    rows.sort(key=lambda x: x["product"])
    return {"not_affected": len(rows) == 0, "rows": rows,
            "threat_severity": data.get("threat_severity")}

def parse_rhel_package(data):
    if not data:
        return []
    items = data if isinstance(data, list) else data.get("data", data.get("cves", []))
    if not isinstance(items, list):
        return []
    return [{"id": i.get("CVE") or i.get("cve_id", ""),
             "severity": i.get("severity", "unknown"),
             "description": i.get("bugzilla_description", "")}
            for i in items if i.get("CVE") or i.get("cve_id")]

# ── ARCH ────────────────────────────────────────────────────
def fetch_arch_cve(cve, dcfg):
    return get_json(dcfg["cve_url"].replace("{CVE}", cve))

def fetch_arch_package(pkg, dcfg):
    return get_json(dcfg["package_url"].replace("{PKG}", pkg))

def parse_arch_cve(data):
    if not data:
        return {"not_affected": True, "rows": []}
    items = data if isinstance(data, list) else [data]
    rows  = []
    for item in items:
        status   = item.get("status", "Unknown")
        severity = item.get("severity", "Unknown")
        adv      = ", ".join(a.get("name", str(a)) if isinstance(a, dict) else str(a)
                             for a in item.get("advisories", []))
        groups   = ", ".join(item.get("groups", []))
        for pkg in item.get("packages", []):
            rows.append({"package": pkg, "status": status,
                         "severity": severity, "advisory": adv, "groups": groups})
    return {"not_affected": len(rows) == 0, "rows": rows}

def parse_arch_package(data):
    if not data:
        return []
    items = data if isinstance(data, list) else [data]
    return [{"id": i.get("id", i.get("cve", "")),
             "status": i.get("status", ""),
             "severity": i.get("severity", "")} for i in items]

# ── ALPINE ──────────────────────────────────────────────────
def fetch_alpine_cve(cve, dcfg):
    return get_json(dcfg["cve_url"].replace("{CVE}", cve))

def fetch_alpine_package(pkg, dcfg):
    return get_json(dcfg["package_url"].replace("{PKG}", pkg))

def parse_alpine_cve(data):
    if not data:
        return {"not_affected": True, "rows": []}
    pkgs = data.get("packages") or data.get("affected") or []
    rows = []
    if isinstance(pkgs, list):
        for p in pkgs:
            pkg    = p.get("pkg", p)
            name   = pkg.get("name") or p.get("name", "?")
            branch = pkg.get("branch") or pkg.get("reponame") or p.get("branch", "unknown")
            sf     = pkg.get("secfixes") or p.get("secfixes") or {}
            fixed  = next((v for v, cves in sf.items() if isinstance(cves, list) and cves), None)
            rows.append({"package": name, "branch": branch,
                         "fixed_version": fixed or "(unfixed)",
                         "status": "fixed" if fixed else "open"})
    return {"not_affected": len(rows) == 0, "rows": rows}

def parse_alpine_package(data):
    if not data:
        return []
    items = data if isinstance(data, list) else data.get("packages", data.get("results", []))
    if not isinstance(items, list):
        return []
    return [{"id": i.get("id") or i.get("cve", ""),
             "package": i.get("package", ""),
             "branch": i.get("branch", "")} for i in items]

# ── ROUTES ──────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/api/scan")
def scan():
    mode    = request.args.get("mode", "cve").lower()      # cve | package
    query   = request.args.get("q", "").strip()
    distros = request.args.get("distros", "")              # comma-sep, empty = all

    if not query:
        return jsonify({"error": "Missing query parameter ?q="}), 400

    cfg        = load_sources()
    all_distros = [k for k, v in cfg["distros"].items() if v.get("enabled")]
    use_distros = [d.strip() for d in distros.split(",") if d.strip()] if distros else all_distros
    use_distros = [d for d in use_distros if d in all_distros]

    sources_config = {k: {"label": v["label"], "color": v["color"]}
                      for k, v in cfg["distros"].items() if v.get("enabled")}

    result = {
        "mode":           mode,
        "query":          query,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "distros_used":   use_distros,
        "sources_config": sources_config,
        "distros":        {},
    }

    # ── CVE mode ──
    if mode == "cve":
        cve_id = query.upper()
        mitre  = fetch_mitre(cve_id, cfg) if cfg["meta_sources"]["mitre"]["enabled"] else None
        nvd    = fetch_nvd(cve_id, cfg)   if cfg["meta_sources"]["nvd"]["enabled"]   else None
        result["overview"] = merge_mitre_nvd(mitre, nvd)
        if not result["overview"]["cve_id"]:
            result["overview"]["cve_id"] = cve_id

        for d in use_distros:
            dcfg = cfg["distros"][d]
            if d == "ubuntu":
                raw = fetch_ubuntu_cve(cve_id, dcfg)
                result["distros"][d] = parse_ubuntu_cve(raw, dcfg)
            elif d == "debian":
                raw  = fetch_debian_cve(cve_id, dcfg)
                rows = parse_debian_cve(raw, dcfg)
                result["distros"][d] = {"rows": rows, "not_affected": len(rows) == 0}
            elif d == "rhel":
                raw = fetch_rhel_cve(cve_id, dcfg)
                result["distros"][d] = parse_rhel_cve(raw, dcfg)
            elif d == "arch":
                raw = fetch_arch_cve(cve_id, dcfg)
                result["distros"][d] = parse_arch_cve(raw)
            elif d == "alpine":
                raw = fetch_alpine_cve(cve_id, dcfg)
                result["distros"][d] = parse_alpine_cve(raw)

    # ── Package mode ──
    else:
        for d in use_distros:
            dcfg = cfg["distros"][d]
            if d == "ubuntu":
                raw = fetch_ubuntu_package(query, dcfg)
                result["distros"][d] = {"cves": parse_ubuntu_package(raw)}
            elif d == "debian":
                raw = fetch_debian_package(query, dcfg)
                result["distros"][d] = {"cves": parse_debian_package(raw)}
            elif d == "rhel":
                raw = fetch_rhel_package(query, dcfg)
                result["distros"][d] = {"cves": parse_rhel_package(raw)}
            elif d == "arch":
                raw = fetch_arch_package(query, dcfg)
                result["distros"][d] = {"cves": parse_arch_package(raw)}
            elif d == "alpine":
                raw = fetch_alpine_package(query, dcfg)
                result["distros"][d] = {"cves": parse_alpine_package(raw)}

    return jsonify(result)

@app.route("/api/sources")
def sources():
    cfg = load_sources()
    return jsonify({
        k: {"label": v["label"], "color": v["color"], "enabled": v.get("enabled", True)}
        for k, v in cfg["distros"].items()
    })

if __name__ == "__main__":
    print("\n  Package Universe — Backend")
    print("  Running at http://localhost:5000\n")
    app.run(debug=True, port=5000)