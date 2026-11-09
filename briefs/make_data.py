#!/usr/bin/env python3
"""Turn pixel_scan results.json into per-organisation evidence JSON (+ screenshot files) for the brief decks.

Only things the scan actually observed go in. Internal triage ratings/scores are deliberately NOT exported.
Usage: python briefs/make_data.py run_shortlist/results.json briefs_out
"""
import base64
import collections
import json
import re
import os
import sys
import urllib.parse as up

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pixel_scan as ps  # noqa: E402

AD = ("advertising", "session_replay")
OPAQUE = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_-]{16,}$")  # e.g. Google Ads conversion labels - not meaningful to a reader


def clean_events(events):
    return {e for e in events if e and not OPAQUE.match(e)}
CATEGORY_LABEL = {"advertising": "Advertising", "session_replay": "Session replay", "analytics": "Analytics"}
VERDICT_LABEL = {
    "reject_ignored": "Ad-tech still fired after Reject was clicked",
    "fires_before_choice": "Ad-tech fired before any choice was made",
    "blocked_until_consent": "Ad-tech loaded only after Accept",
    "no_adtech_observed": "No ad-tech observed in any mode",
    "no_consent_control_found": "No Accept/Reject control could be found or clicked",
}


def path_of(url: str) -> str:
    return up.urlsplit(url).path or "/"


def short_list(items, n=3):
    items = sorted(items)
    return ", ".join(items[:n]) + (f" (+{len(items) - n} more)" if len(items) > n else "")


def slug(domain: str) -> str:
    return domain.replace(".", "_")


def build(r: "ps.SiteResult", outdir: str) -> dict:
    r.hits = ps.reclassify_hits(r.hits)
    beacons = [h for h in r.hits if h.kind == "beacon"]
    ad_beacons = [h for h in beacons if h.category in AD]
    visited = [p for p in r.pages if not p.error]
    health_pages = [p for p in visited if p.role == "sensitive" and ps.is_sensitive_url(p.url)]
    other_pages = [p for p in visited if p not in health_pages]

    # per-vendor table
    by_v: dict[str, dict] = collections.defaultdict(lambda: {"pages": set(), "ids": set(), "events": set(), "sent": set(), "cat": ""})
    for h in beacons:
        v = by_v[h.vendor]
        v["cat"] = h.category
        v["pages"].add(path_of(h.page))
        if h.pixel_id:
            v["ids"].add(h.pixel_id)
        v["events"] |= clean_events(h.event.split(","))
        if h.page_url_sent:
            v["sent"].add(path_of(h.page))
    vendors = []
    for name, v in sorted(by_v.items(), key=lambda kv: (kv[1]["cat"] not in AD, kv[0])):
        vendors.append({
            "vendor": name, "category": CATEGORY_LABEL.get(v["cat"], v["cat"]),
            "ids": short_list(v["ids"], 2) or "-", "events": short_list(v["events"], 4) or "-",
            "pages": f"{len(v['pages'])} page(s), e.g. " + short_list(v["pages"], 2), "page_count": len(v["pages"]),
            "url_in_request": f"Yes ({len(v['sent'])} page(s))" if v["sent"] else "Not observed",
        })

    # health-related pages and what fired there
    hp = []
    for p in health_pages:
        pth = path_of(p.url)
        fired = sorted({h.vendor for h in ad_beacons if _same(h.page, p.url)})
        got_url = sorted({h.vendor for h in ad_beacons if _same(h.page, p.url) and h.page_url_sent})
        hp.append({"path": pth, "forms": p.forms, "adtech": fired, "url_sent_to": got_url})

    # Meta dl note: what the document-location parameter contained
    meta_dl = {"origin_only": 0, "with_path": 0}
    for h in beacons:
        if h.key == "meta" and path_of(h.page).strip("/"):
            dl = (up.parse_qs(up.urlsplit(h.url).query).get("dl") or [""])[0]
            if dl:
                meta_dl["with_path" if up.urlsplit(dl).path.strip("/") else "origin_only"] += 1

    adv_all = sorted({f for h in beacons for f in h.adv_matching})
    adv_contact = ps.am_contact_fields(adv_all)

    # undisclosed (keyword check of the privacy page we landed on)
    fired_keys = {h.key for h in beacons}
    undisclosed = []
    for k in sorted(fired_keys):
        pk = "ga4" if k == "ga_audiences" else k
        if pk in ps.PRIVACY_VENDOR_TERMS and pk not in r.privacy_mentions and k != "gtm":
            undisclosed.append(ps.TRACKER_BY_KEY[k].vendor)

    # screenshots
    imgdir = os.path.join(outdir, "img")
    os.makedirs(imgdir, exist_ok=True)
    shots = []
    for i, p in enumerate(visited):
        if p.screenshot and len(shots) < 3 and (p.role == "home" or any(p.url == hpg.url for hpg in health_pages)):
            fn = os.path.join(imgdir, f"{slug(r.domain)}_{i}.jpg")
            with open(fn, "wb") as f:
                f.write(base64.b64decode(p.screenshot))
            shots.append({"file": os.path.abspath(fn), "role": p.role, "path": path_of(p.url)})

    ct = r.consent_test or {}
    modes = []
    for key, label in (("none", "No interaction"), ("reject", "Reject clicked"), ("accept", "Accept clicked")):
        m = (ct.get("modes") or {}).get(key)
        if m:
            clicked = "n/a" if m["clicked"] is None else ("Yes" if m["clicked"] else "No control found")
            adtech = ", ".join(m["adtech"]) or "None observed"
            if key != "none" and not m["clicked"]:
                adtech = "Not tested (no control to click)"
            modes.append({"mode": label, "clicked": clicked, "adtech": adtech})

    # evidence log
    grp: dict = {}
    for h in sorted(beacons, key=lambda h: (h.category not in AD, h.vendor, path_of(h.page))):
        g = grp.setdefault((h.vendor, path_of(h.page)), {"events": set(), "ids": set(), "sent": False, "n": 0})
        g["events"] |= clean_events(h.event.split(","))
        if h.pixel_id:
            g["ids"].add(h.pixel_id)
        g["sent"] = g["sent"] or h.page_url_sent
        g["n"] += h.count
    log = [[v, pth[:46], (", ".join(sorted(g["events"])) or "-")[:36], (", ".join(sorted(g["ids"])) or "-")[:26],
            "Yes" if g["sent"] else "No", str(g["n"])] for (v, pth), g in grp.items()]

    return {
        "domain": r.domain, "url": r.url, "sector": r.sector, "scanned_at": r.scanned_at, "tool": f"pixel_scan {ps.__version__}",
        "n_pages": len(visited), "n_health_pages": len(health_pages),
        "n_health_pages_with_adtech": sum(1 for x in hp if x["adtech"]),
        "adtech_vendors": ps.assess(r)["vendors"] and sorted({h.vendor for h in ad_beacons}),
        "vendors": vendors, "health_pages": hp, "other_pages": [path_of(p.url) for p in other_pages],
        "meta_dl": meta_dl, "adv_contact": adv_contact, "adv_all": adv_all,
        "cmps": r.cmps, "privacy_url": r.privacy_url, "undisclosed": undisclosed,
        "consent_verdict": ct.get("verdict", ""), "consent_verdict_label": VERDICT_LABEL.get(ct.get("verdict", ""), "Not tested"),
        "consent_notes": ct.get("notes", []), "consent_modes": modes,
        "shots": shots, "log": log[:36], "log_total": len(log),
    }


def _same(a: str, b: str) -> bool:
    return ps._norm_page(a) == ps._norm_page(b)


def main() -> int:
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(os.path.join(outdir, "data"), exist_ok=True)
    n = 0
    for r in ps.load_json(src):
        if r.status != "ok":
            print(f"skip {r.domain}: {r.status} {r.error}")
            continue
        d = build(r, outdir)
        with open(os.path.join(outdir, "data", slug(r.domain) + ".json"), "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1, ensure_ascii=False)
        n += 1
        print(f"{r.domain}: {len(d['vendors'])} vendors, {d['n_health_pages_with_adtech']}/{d['n_health_pages']} health pages with ad-tech, consent={d['consent_verdict']}")
    print(f"wrote {n} data files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
