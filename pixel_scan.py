#!/usr/bin/env python3
"""pixel_scan - find Australian organisations in sensitive sectors whose websites
fire ad-tech / analytics tracking pixels *before* cookie consent.

Subcommands
-----------
  discover   query the Brave Search API (BRAVE_API_KEY) and write targets.csv
  scan       load each target in a fresh Playwright Chromium context (no consent
             given), record tracker requests, score each site, write results.json,
             results.csv and report.html
  report     rebuild report.html from results.json

IMPORTANT: output is a triage signal - a *potential issue*, NOT a legal finding.
Whether any APP breach occurred depends on facts this tool cannot see (what the
organisation's privacy policy says, what the pixel is configured to send, whether
the data is "sensitive information", consent mechanics, etc.).

The scanner never clicks consent banners, never fills or submits forms, and
honours robots.txt unless --ignore-robots is passed.

Only third-party dependency: playwright (imported lazily, so everything except
`scan` works without it).
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import datetime as dt
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

__version__ = "0.1.0"
BOT_TOKEN = "pixel_scan"
DISCLAIMER = (
    "Potential issue, not a legal finding. This report records network requests "
    "observed on public web pages before any cookie consent was given. It does not "
    "establish that any organisation has breached the Privacy Act 1988 (Cth) or the "
    "Australian Privacy Principles; that requires analysis of facts this tool cannot "
    "see."
)

# --------------------------------------------------------------------------- #
# Discovery configuration
# --------------------------------------------------------------------------- #
CITIES = [
    "Sydney", "Melbourne", "Brisbane", "Perth", "Adelaide", "Canberra",
    "Gold Coast", "Newcastle", "Hobart", "Darwin",
]

SECTORS: dict[str, list[str]] = {
    "IVF / fertility": [
        "IVF clinic {city}",
        "fertility specialist {city}",
        "egg freezing {city}",
    ],
    "Telehealth": [
        "telehealth doctor online consultation {city}",
        "online doctor prescription {city}",
    ],
    "Mental health": [
        "psychologist {city}",
        "counselling service {city}",
        "psychiatrist {city}",
    ],
    "Sexual & reproductive health": [
        "sexual health clinic {city}",
        "abortion clinic {city}",
        "women's health clinic {city}",
    ],
    "Alcohol & drug treatment": [
        "drug and alcohol rehab {city}",
    ],
    "Menopause / hormone": [
        "menopause clinic {city}",
        "gender affirming care clinic {city}",
    ],
}

# Domains that are directories / aggregators / social / media, not the organisation itself.
EXCLUDED_DOMAINS = {
    "healthengine.com.au", "hotdoc.com.au", "healthdirect.gov.au", "whitepages.com.au",
    "yellowpages.com.au", "truelocal.com.au", "localsearch.com.au", "yelp.com",
    "yelp.com.au", "google.com", "google.com.au", "facebook.com", "instagram.com",
    "linkedin.com", "twitter.com", "x.com", "youtube.com", "tiktok.com", "pinterest.com",
    "reddit.com", "wikipedia.org", "tripadvisor.com", "tripadvisor.com.au",
    "ratemds.com", "ratemyspecialist.com.au", "findapsychologist.org", "psychologytoday.com",
    "au.indeed.com", "indeed.com", "seek.com.au", "glassdoor.com.au", "glassdoor.com",
    "abc.net.au", "smh.com.au", "theage.com.au", "news.com.au", "9news.com.au",
    "theguardian.com", "medium.com", "quora.com", "amazon.com.au", "amazon.com",
    "bing.com", "apple.com", "maps.apple.com", "doctoralia.com.au", "cosmetic-clinic.com.au",
    "bestdoctors.com.au", "ivf.net.au", "fertilitysociety.com.au", "racgp.org.au",
    "ahpra.gov.au", "mhfa.com.au", "beyondblue.org.au", "lifeline.org.au",
}

# --------------------------------------------------------------------------- #
# Tracker / CMP signatures
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Tracker:
    key: str
    vendor: str
    category: str  # advertising | analytics | session_replay | tag_manager
    beacon: Optional[re.Pattern]  # request that actually transmits data
    script: Optional[re.Pattern]  # request that loads the tracker library


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.I)


TRACKERS: list[Tracker] = [
    Tracker("ga4", "Google Analytics (GA4)", "analytics",
            _r(r"^https?://([\w-]+\.)*(google-analytics\.com|analytics\.google\.com)/(g/|j/)?collect"
               r"|^https?://stats\.g\.doubleclick\.net/(g|j)/collect"),
            _r(r"^https?://www\.googletagmanager\.com/gtag/js\b|^https?://www\.google-analytics\.com/analytics\.js")),
    Tracker("google_ads", "Google Ads / DoubleClick", "advertising",
            _r(r"^https?://(www\.)?googleadservices\.com/pagead/(conversion|viewthroughconversion)"
               r"|^https?://[\w.-]*doubleclick\.net/(pagead|activity|ddm|td)/"
               r"|^https?://www\.google\.com(\.au)?/(pagead|ads)/(1p-)?(user-list|conversion|ga-audiences)"),
            _r(r"^https?://www\.googleadservices\.com/pagead/conversion(_async)?\.js"
               r"|^https?://pagead2\.googlesyndication\.com/")),
    Tracker("meta", "Meta Pixel", "advertising",
            _r(r"^https?://www\.facebook\.com/tr/?(\?|$)|^https?://www\.facebook\.com/tr\b"),
            _r(r"^https?://connect\.facebook\.net/[^/]+/(fbevents|sdk)\.js")),
    Tracker("tiktok", "TikTok Pixel", "advertising",
            _r(r"^https?://analytics\.tiktok\.com/api/v\d+/(pixel|track)|^https?://business-api\.tiktok\.com/"),
            _r(r"^https?://analytics\.tiktok\.com/i18n/pixel/")),
    Tracker("pinterest", "Pinterest Tag", "advertising",
            _r(r"^https?://ct\.pinterest\.com/(v3|user)/?"),
            _r(r"^https?://s\.pinimg\.com/ct/core\.js")),
    Tracker("linkedin", "LinkedIn Insight Tag", "advertising",
            _r(r"^https?://(px\.ads\.linkedin\.com|www\.linkedin\.com/px)/"),
            _r(r"^https?://snap\.licdn\.com/li\.lms-analytics/insight")),
    Tracker("bing", "Microsoft Advertising (UET)", "advertising",
            _r(r"^https?://bat\.bing\.com/action/"),
            _r(r"^https?://bat\.bing\.com/bat\.js")),
    Tracker("hotjar", "Hotjar", "session_replay",
            _r(r"^https?://(in|vc|events)\.hotjar\.(com|io)/|^wss?://[\w.-]*hotjar\.(com|io)/"
               r"|^https?://script\.hotjar\.com/modules"),
            _r(r"^https?://static\.hotjar\.com/c/hotjar-")),
    Tracker("clarity", "Microsoft Clarity", "session_replay",
            _r(r"^https?://[a-z]\.clarity\.ms/collect"),
            _r(r"^https?://(www\.)?clarity\.ms/tag/")),
    Tracker("gtm", "Google Tag Manager", "tag_manager",
            None,
            _r(r"^https?://www\.googletagmanager\.com/gtm\.js\b")),
]
TRACKER_BY_KEY = {t.key: t for t in TRACKERS}

CMPS: list[tuple[str, re.Pattern]] = [
    ("OneTrust", _r(r"cdn\.cookielaw\.org|onetrust\.com|cookiepro\.com")),
    ("Cookiebot", _r(r"consent\.cookiebot\.com|consentcdn\.cookiebot\.com|cookiebot\.com/")),
    ("Usercentrics", _r(r"usercentrics\.eu|app\.usercentrics\.")),
    ("CookieYes", _r(r"cdn-cookieyes\.com|cookieyes\.com")),
    ("Termly", _r(r"app\.termly\.io")),
    ("Osano", _r(r"osano\.com")),
    ("Didomi", _r(r"didomi\.io")),
    ("iubenda", _r(r"iubenda\.com")),
    ("Quantcast Choice", _r(r"quantcast\.mgr\.consensu\.org|quantcast\.com/choice")),
    ("TrustArc", _r(r"trustarc\.com|truste\.com")),
    ("CookieScript", _r(r"cookie-script\.com")),
    ("Civic", _r(r"civiccomputing\.com")),
]
# Self-hosted banners leave no third-party request; look for their DOM instead.
CMP_DOM: dict[str, str] = {
    "OneTrust": "#onetrust-banner-sdk",
    "Cookiebot": "#CybotCookiebotDialog",
    "Usercentrics": "#usercentrics-root",
    "CookieYes": ".cky-consent-container",
    "Complianz": "#cmplz-cookiebanner-container, .cmplz-cookiebanner",
    "Cookie Law Info": "#cookie-law-info-bar",
    "CookieConsent (osano oss)": ".cc-window",
    "Generic cookie banner": "[id*='cookie-banner' i], [class*='cookie-banner' i], [id*='cookie-consent' i]",
}

# Words that make a link / page "likely sensitive" (path + link text), with weights.
SENSITIVE_TERMS: dict[str, int] = {
    "ivf": 5, "fertility": 5, "egg-freezing": 5, "iui": 4, "pregnan": 4, "miscarriage": 5,
    "abortion": 5, "termination": 4, "contracepti": 4, "sexual": 4, "sti": 3, "hiv": 5,
    "mental": 4, "psycholog": 4, "psychiatr": 4, "counsel": 3, "depress": 4, "anxiety": 4,
    "trauma": 4, "ptsd": 4, "eating-disorder": 5, "addiction": 5, "drug": 3, "alcohol": 3,
    "rehab": 4, "gender": 4, "menopause": 4, "hormone": 3, "oncolog": 3, "cancer": 3,
    "treatment": 3, "telehealth": 3, "consult": 3, "appointment": 3, "book": 3,
    "enquir": 3, "inquir": 3, "contact": 2, "referral": 3, "patient": 2, "service": 1,
    "clinic": 1, "symptom": 3, "diagnos": 3, "prescription": 3, "medication": 3,
    "assessment": 3, "genetic": 4, "nurse": 3, "donor-egg": 4, "egg-donor": 4, "sperm": 4, "donor-conception": 4, "surrogacy": 4, "pathology": 2, "intake": 3,
}
# Generic words that help find pages worth visiting but do NOT, on their own, make a page "health-related".
WEAK_TERMS = {"contact", "service", "clinic", "patient", "pathology", "assessment"}

# [2026] AICmr 40 concerned a health service provider: the "sensitive information" finding rests on health-service
# engagement [83]-[85]. Ratings (High/Medium/Low) are therefore only given to organisations in health-related sectors;
# others are labelled "Observed". An empty sector (ad-hoc target list) is treated as in scope.
HEALTH_SECTOR_RX = re.compile(
    r"ivf|fertil|telehealth|health|hospital|pathology|diagnos|pharmac|dental|medical|aged care|disab|"
    r"reproductive|drug|alcohol|menopause|hormone|mental", re.I)


def is_health_sector(sector: str) -> bool:
    return not sector or bool(HEALTH_SECTOR_RX.search(sector))


SKIP_LINK_RE = re.compile(r"\.(pdf|jpe?g|png|gif|svg|webp|zip|docx?|xlsx?|mp4|css|js)(\?|$)|^(mailto|tel|javascript|sms):", re.I)
PRIVACY_RE = re.compile(r"privacy|collection[-_ ]notice", re.I)
EVENT_CONVERSION = {
    "lead", "schedule", "contact", "submitapplication", "completeregistration", "purchase",
    "subscribe", "findlocation", "starttrial", "generate_lead", "form_submit", "conversion",
    "pagevisit_lead", "lead_submit", "appointment", "book", "booking",
}

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class TrackerHit:
    key: str
    vendor: str
    category: str
    kind: str                 # "beacon" (data sent) | "script" (library loaded)
    page: str                 # page URL the hit was observed on
    pixel_id: str = ""
    event: str = ""
    gcs: str = ""             # Google Consent Mode state (GA4), e.g. G100 = both denied
    page_url_sent: bool = False
    method: str = "GET"
    url: str = ""             # truncated request URL (evidence)
    count: int = 1
    adv_matching: list[str] = field(default_factory=list)  # Meta advanced-matching field NAMES only (never values)


@dataclass
class PageInfo:
    url: str
    role: str = "home"        # home | sensitive | privacy
    status: int = 0
    title: str = ""
    forms: int = 0
    inputs: int = 0
    error: str = ""
    score: int = 0
    screenshot: str = ""      # base64 JPEG (only with --screenshots)


@dataclass
class SiteResult:
    domain: str
    url: str
    sector: str = ""
    city: str = ""
    status: str = "ok"        # ok | error | skipped_robots
    error: str = ""
    scanned_at: str = ""
    pages: list[PageInfo] = field(default_factory=list)
    hits: list[TrackerHit] = field(default_factory=list)
    cmps: list[str] = field(default_factory=list)
    privacy_url: str = ""
    privacy_mentions: list[str] = field(default_factory=list)
    assessment: dict[str, Any] = field(default_factory=dict)
    consent_test: Optional[dict] = None   # only with --consent-test


# --------------------------------------------------------------------------- #
# Pure logic: matching and parsing
# --------------------------------------------------------------------------- #
def _flatten_body(post_data: Optional[str]) -> dict[str, list[str]]:
    """Best-effort parse of a request body into {param: [values]}."""
    out: dict[str, list[str]] = {}
    if not post_data:
        return out
    text = post_data.strip()
    if text.startswith("{") or text.startswith("["):
        try:
            obj = json.loads(text)

            def walk(prefix: str, v: Any) -> None:
                if isinstance(v, dict):
                    for k, x in v.items():
                        walk(f"{prefix}.{k}" if prefix else str(k), x)
                elif isinstance(v, list):
                    for x in v:
                        walk(prefix, x)
                else:
                    out.setdefault(prefix, []).append(str(v))

            walk("", obj)
            return out
        except ValueError:
            pass
    for line in text.splitlines():
        for k, vs in urllib.parse.parse_qs(line, keep_blank_values=True).items():
            out.setdefault(k, []).extend(vs)
    return out


def parse_params(url: str, post_data: Optional[str] = None) -> dict[str, list[str]]:
    q = urllib.parse.urlsplit(url).query
    params = {k: list(v) for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}
    for k, vs in _flatten_body(post_data).items():
        params.setdefault(k, []).extend(vs)
    return params


def _first(params: dict[str, list[str]], *names: str) -> str:
    for n in names:
        if params.get(n):
            return params[n][0]
    return ""


def _norm_page(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    return f"{u.netloc.lower()}{u.path.rstrip('/')}"


def page_url_in_request(page_url: str, url: str, post_data: Optional[str]) -> bool:
    """True if the page URL (or host+path) appears in the request, i.e. the
    tracker was told which page the visitor was on."""
    if not page_url or page_url.startswith("about:"):
        return False
    blob = urllib.parse.unquote(urllib.parse.unquote(url + " " + (post_data or "")))
    full = page_url.split("#")[0]
    if full in blob or full.rstrip("/") + "/" in blob:
        return True
    u = urllib.parse.urlsplit(page_url)
    hostpath = (u.netloc + u.path).rstrip("/")
    if u.path.strip("/"):
        return hostpath in blob
    # homepage: only count the bare origin when it stands alone (not as a prefix of another page)
    return bool(u.netloc) and bool(re.search(
        r"(?:[?&=\"'\s]|^)(?:https?:)?//" + re.escape(u.netloc) + r"/?(?=$|[&?#\"'\s])", blob))


def extract_details(key: str, kind: str, url: str, post_data: Optional[str]) -> dict[str, str]:
    """Pull pixel id / event / consent state out of a matched request."""
    p = parse_params(url, post_data)
    d = {"pixel_id": "", "event": "", "gcs": ""}
    path = urllib.parse.urlsplit(url).path
    if key == "meta":
        d["pixel_id"] = _first(p, "id")
        if not d["pixel_id"]:
            m = re.search(r"/tr/?\?.*\bid=(\d+)", url)
            d["pixel_id"] = m.group(1) if m else ""
        d["event"] = _first(p, "ev")
    elif key == "ga4":
        d["pixel_id"] = _first(p, "tid", "id")
        d["event"] = ",".join(dict.fromkeys(p.get("en", [])))
        d["gcs"] = _first(p, "gcs")
    elif key == "google_ads":
        m = re.search(r"/(?:conversion|viewthroughconversion)/(\d+)", path)
        d["pixel_id"] = m.group(1) if m else _first(p, "tid", "id")
        d["event"] = _first(p, "label", "en")
        d["gcs"] = _first(p, "gcs")
    elif key == "tiktok":
        d["pixel_id"] = _first(p, "sdkid", "pixel_code", "context.pixel.code", "pixelCode")
        d["event"] = _first(p, "event", "event_name")
        if not d["pixel_id"] and post_data:
            m = re.search(r'"(?:code|pixel_code|pixelCode)"\s*:\s*"([A-Z0-9]+)"', post_data)
            d["pixel_id"] = m.group(1) if m else ""
    elif key == "pinterest":
        d["pixel_id"] = _first(p, "tid")
        d["event"] = _first(p, "event", "ev")
    elif key == "linkedin":
        d["pixel_id"] = _first(p, "pid")
        d["event"] = _first(p, "conversionId", "fmt")
    elif key == "bing":
        d["pixel_id"] = _first(p, "ti")
        d["event"] = _first(p, "evt", "ea")
    elif key == "hotjar":
        m = re.search(r"hotjar-(\d+)\.js", url) or re.search(r"/sites/(\d+)", path) \
            or re.search(r"[?&]site(?:Id|_id)?=(\d+)", url)
        d["pixel_id"] = m.group(1) if m else ""
    elif key == "clarity":
        m = re.search(r"/tag/([a-z0-9]+)", path)
        d["pixel_id"] = m.group(1) if m else ""
    elif key == "gtm":
        d["pixel_id"] = _first(p, "id")
    return d


_AM_RX = re.compile(r"^(ud|udff)\[(\w+)\]$")
_REDACT_RX = re.compile(r"((?:ud|udff)(?:\[|%5B)[^=&]*=)[^&]*", re.I)


def advanced_matching_fields(params: dict[str, list[str]]) -> list[str]:
    """Names of Meta advanced-matching fields present (ud[em], ud[ph], ...; udff[..] = scraped from
    form fields, shown as 'form:em'). Values are hashed identifiers - we record names only."""
    out = []
    for k, vs in params.items():
        m = _AM_RX.match(k)
        if m and any(vs):
            out.append(("form:" if m.group(1) == "udff" else "") + m.group(2))
    return sorted(dict.fromkeys(out))


def redact_url(url: str) -> str:
    """Never keep hashed identifiers in stored evidence."""
    return _REDACT_RX.sub(r"\1[redacted]", url)


def match_request(url: str, method: str = "GET", post_data: Optional[str] = None,
                  page_url: str = "") -> list[TrackerHit]:
    """Match one network request against TRACKERS. Returns 0 or 1 hit."""
    for t in TRACKERS:
        kind = ""
        if t.beacon and t.beacon.search(url):
            kind = "beacon"
        elif t.script and t.script.search(url):
            kind = "script"
        if not kind:
            continue
        det = extract_details(t.key, kind, url, post_data)
        sent = kind == "beacon" and page_url_in_request(page_url, url, post_data)
        adv = advanced_matching_fields(parse_params(url, post_data)) if t.key == "meta" and kind == "beacon" else []
        return [TrackerHit(
            key=t.key, vendor=t.vendor, category=t.category, kind=kind, page=page_url,
            pixel_id=det["pixel_id"], event=det["event"], gcs=det["gcs"],
            page_url_sent=sent, method=method, url=redact_url(url)[:400], adv_matching=adv,
        )]
    return []


def match_cmp(url: str) -> Optional[str]:
    for name, rx in CMPS:
        if rx.search(url):
            return name
    return None


def merge_hit(hits: list[TrackerHit], new: TrackerHit) -> None:
    """Deduplicate: identical (tracker, kind, id, event, gcs, page) collapse into a count."""
    for h in hits:
        if (h.key, h.kind, h.pixel_id, h.event, h.gcs, h.page, h.page_url_sent) == \
                (new.key, new.kind, new.pixel_id, new.event, new.gcs, new.page, new.page_url_sent):
            h.count += 1
            return
    hits.append(new)


def gcs_state(gcs: str) -> str:
    """Decode Google Consent Mode v2 'gcs' param: G1<ad><analytics>."""
    if not gcs:
        return "unknown"
    m = re.fullmatch(r"G1([01])([01])", gcs)
    if not m:
        return "unknown"
    ad, an = m.group(1) == "1", m.group(2) == "1"
    if not ad and not an:
        return "denied"
    if ad and an:
        return "granted"
    return "partial"


# --------------------------------------------------------------------------- #
# Pure logic: link scoring
# --------------------------------------------------------------------------- #
def text_sensitivity(text: str, terms: Optional[dict[str, int]] = None) -> int:
    """Sum of weights of sensitive terms. Short terms (<=4 chars, e.g. 'sti', 'hiv', 'ivf') must match a whole
    word so 'sti' doesn't fire inside 'investing'; longer stems match as substrings ('psycholog')."""
    t = text.lower()
    tokens = set(re.split(r"[^a-z0-9]+", t))
    total = 0
    for term, w in (terms or SENSITIVE_TERMS).items():
        if (term in t) if len(term) > 4 else (term in tokens):
            total += w
    return total


CORE_TERMS = {k: v for k, v in SENSITIVE_TERMS.items() if k not in WEAK_TERMS}


def is_sensitive_url(url: str) -> bool:
    """A page that *looks* health-related by URL keywords (condition, treatment, booking/enquiry on a health site...).
    A keyword match only - it cannot tell whether the page really reveals health information. Generic words
    ('contact', 'service', 'patient', 'clinic') do not count on their own."""
    return text_sensitivity(urllib.parse.urlsplit(url).path, CORE_TERMS) >= 3


def score_links(links: list[tuple[str, str]], base_url: str, max_pages: int = 3) -> list[str]:
    """Pick up to max_pages same-site links most likely to be sensitive
    (treatment, booking, enquiry, ...). links = [(href, link text)]."""
    base = urllib.parse.urlsplit(base_url)
    base_host = base.netloc.lower().removeprefix("www.")
    scored: dict[str, int] = {}
    for href, text in links:
        if not href or SKIP_LINK_RE.search(href):
            continue
        u = urllib.parse.urlsplit(urllib.parse.urljoin(base_url, href))
        if u.scheme not in ("http", "https"):
            continue
        if u.netloc.lower().removeprefix("www.") != base_host:
            continue
        norm = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path or "/", u.query if len(u.query) < 40 else "", ""))
        if _norm_page(norm) == _norm_page(base_url) or PRIVACY_RE.search(u.path):
            continue
        # path counts fully; link text counts at half weight
        s = text_sensitivity(u.path) + text_sensitivity(text) // 2
        depth = len([x for x in u.path.split("/") if x])
        if depth > 4:
            s -= 1
        if s > 0:
            scored[norm] = max(scored.get(norm, 0), s)
    ranked = sorted(scored.items(), key=lambda kv: (-kv[1], len(kv[0])))
    return [u for u, _ in ranked[:max_pages]]


def find_privacy_link(links: list[tuple[str, str]], base_url: str) -> str:
    base_host = urllib.parse.urlsplit(base_url).netloc.lower().removeprefix("www.")
    best, best_s = "", 0
    for href, text in links:
        if not href or SKIP_LINK_RE.search(href):
            continue
        u = urllib.parse.urlsplit(urllib.parse.urljoin(base_url, href))
        if u.scheme not in ("http", "https"):
            continue
        s = 0
        if PRIVACY_RE.search(u.path):
            s += 2
        if PRIVACY_RE.search(text or ""):
            s += 1
        if re.search(r"privacy[-_ ]?(policy|statement|notice)", u.path + " " + (text or ""), re.I):
            s += 2
        if u.netloc.lower().removeprefix("www.") != base_host:
            s -= 1  # allow off-site policies but prefer on-site
        if s > best_s:
            best, best_s = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, u.query, "")), s
    return best


PRIVACY_VENDOR_TERMS = {
    "meta": r"facebook|meta pixel|\bmeta\b|instagram",
    "ga4": r"google analytics|analytics\.google",
    "google_ads": r"google ads|doubleclick|adwords|remarketing",
    "hotjar": r"hotjar",
    "pinterest": r"pinterest",
    "tiktok": r"tiktok",
    "linkedin": r"linkedin",
    "clarity": r"clarity",
    "bing": r"microsoft advertising|bing",
}


def privacy_mentions(text: str) -> list[str]:
    return [k for k, rx in PRIVACY_VENDOR_TERMS.items() if re.search(rx, text or "", re.I)]


# --------------------------------------------------------------------------- #
# Pure logic: assessment
# --------------------------------------------------------------------------- #
WEIGHT = {"meta": 30, "tiktok": 20, "pinterest": 20, "linkedin": 20, "bing": 20,
          "google_ads": 20, "hotjar": 10, "clarity": 10}


def rating_for(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    if score >= 1:
        return "Low"
    return "None"


def assess(res: SiteResult) -> dict[str, Any]:
    """Score a site 0-100 and give High/Medium/Low/None with reasons.
    Triage heuristic only - see DISCLAIMER."""
    if res.status != "ok":
        return {"score": 0, "rating": "Not scanned", "reasons": [res.error or res.status],
                "vendors": [], "pixel_ids": {}, "events": []}
    score, reasons = 0, []
    beacons = [h for h in res.hits if h.kind == "beacon"]
    scripts = [h for h in res.hits if h.kind == "script"]
    fired = {h.key for h in beacons}

    # 1. Which vendors transmitted data before consent
    # ad-tech: strongest vendor counts in full, each extra vendor adds a little (capped) so a long tail of
    # marketing pixels doesn't alone saturate the score; session replay counted separately.
    adtech_w, replay_w = [], []
    for key in sorted(fired):
        t = TRACKER_BY_KEY[key]
        hs = [h for h in beacons if h.key == key]
        if key == "ga4":
            states = {gcs_state(h.gcs) for h in hs}
            if states == {"denied"}:
                score += 3
                reasons.append("GA4 beacon sent with Consent Mode denied (cookieless ping; page URL/event still transmitted)")
            else:
                score += 10
                why = "granted/partial" if states & {"granted", "partial"} else "no consent signal (gcs missing)"
                reasons.append(f"GA4 beacon sent before consent: {why}")
        elif key in WEIGHT:
            (replay_w if t.category == "session_replay" else adtech_w).append(WEIGHT[key])
            ids = ", ".join(sorted({h.pixel_id for h in hs if h.pixel_id})) or "id not parsed"
            label = "session-replay" if t.category == "session_replay" else "ad-tech"
            reasons.append(f"{t.vendor} ({label}) beacon sent before consent [{ids}]")
    if adtech_w:
        score += min(40, max(adtech_w) + 5 * (len(adtech_w) - 1))
    if replay_w:
        score += min(15, 10 + 5 * (len(replay_w) - 1))
    # script loaded but no beacon observed: weaker signal
    for key in sorted({h.key for h in scripts} - fired):
        if key in WEIGHT:
            score += WEIGHT[key] // 3
            reasons.append(f"{TRACKER_BY_KEY[key].vendor} library loaded before consent (no beacon observed)")
        elif key == "ga4":
            score += 2
            reasons.append("GA4 library loaded before consent (no beacon observed)")

    # 2. Conversion events on sensitive pages
    conv = [h for h in beacons if h.category in ("advertising", "session_replay") or h.key == "ga4"
            if any(e.strip().lower() in EVENT_CONVERSION for e in re.split(r"[,]", h.event) if e)
            and is_sensitive_url(h.page)]
    if conv:
        score += 15
        ev = ", ".join(sorted({f"{h.vendor}:{h.event}" for h in conv}))
        reasons.append(f"Conversion-type event(s) on health-related page(s) (URL keyword match): {ev}")

    # 3. Page URL disclosed to ad/replay vendors on sensitive pages
    leak = [h for h in beacons if h.page_url_sent and h.category in ("advertising", "session_replay")
            and is_sensitive_url(h.page)]
    if leak:
        score += 15
        pages = ", ".join(sorted({urllib.parse.urlsplit(h.page).path or "/" for h in leak}))
        reasons.append(f"URL of health-related page(s) (keyword match) sent to ad/replay vendor(s): {pages}")

    # 3b. Meta advanced matching (hashed customer identifiers in the pixel payload)
    adv = sorted({f for h in beacons for f in h.adv_matching})
    if adv:
        score += 10
        reasons.append("Meta advanced matching: hashed identifier field(s) sent in pixel payload (" + ", ".join(adv)
                       + ") - hashed identifiers can still be personal information")

    # 4. Forms on pages that also carried ad/replay beacons
    adpages = {_norm_page(h.page) for h in beacons if h.category in ("advertising", "session_replay")}
    form_pages = [p for p in res.pages if p.forms and _norm_page(p.url) in adpages]
    if form_pages:
        score += 5
        reasons.append("Form present on page(s) with ad/replay tracking: "
                       + ", ".join(sorted({urllib.parse.urlsplit(p.url).path or "/" for p in form_pages})))

    # 5. CMP context
    adtech_fired = any(h.category in ("advertising", "session_replay") for h in beacons)
    if res.cmps and adtech_fired:
        score += 5
        reasons.append("Consent platform/banner detected (" + ", ".join(res.cmps) + ") but ad-tech fired before any consent given")
    elif res.cmps and not beacons:
        reasons.append("Consent platform/banner detected (" + ", ".join(res.cmps) + "); no tracker beacons observed pre-consent")
    elif not res.cmps and beacons:
        reasons.append("No consent platform detected")

    # 6. Disclosure context (informational)
    if res.privacy_url and fired:
        undisclosed = [TRACKER_BY_KEY[k].vendor for k in sorted(fired)
                       if k in PRIVACY_VENDOR_TERMS and k not in res.privacy_mentions and k != "gtm"]
        if undisclosed:
            reasons.append("Privacy policy does not appear to name: " + ", ".join(undisclosed))
    elif fired and not res.privacy_url:
        reasons.append("No privacy policy link found")

    # 7. Consent-platform behaviour (--consent-test)
    ct = res.consent_test
    if ct:
        if ct["verdict"] == "reject_ignored":
            score += 15
        reasons.extend("Consent test: " + n for n in ct["notes"])

    # High needs evidence tied to sensitive context, not just marketing pixels on a generic page.
    ct_bad = bool(ct and ct["verdict"] == "reject_ignored")
    sensitive_evidence = bool(conv or leak or adv or ct_bad)
    if score >= 60 and not sensitive_evidence:
        score = 59
        reasons.append("Rated no higher than Medium: no ad-tech/replay was observed on pages that look health-related by URL, "
                       "no advanced matching and no ignored Reject (the scan only samples a few pages)")
    score = max(0, min(100, score))
    rating = rating_for(score)
    if not is_health_sector(res.sector) and score >= 1:
        rating = "Observed"
        reasons.insert(0, f"Outside the ruling's health context (sector: {res.sector}): tracking was observed, but whether "
                          "sensitive information is involved is not established, so no risk rating is given")
    if not reasons:
        reasons.append("No tracker requests observed before consent on pages visited")
    ids: dict[str, list[str]] = {}
    for h in beacons + scripts:
        if h.pixel_id:
            ids.setdefault(h.vendor, [])
            if h.pixel_id not in ids[h.vendor]:
                ids[h.vendor].append(h.pixel_id)
    events = sorted({f"{h.vendor}: {e}" for h in beacons for e in h.event.split(",") if e})
    return {
        "score": score, "rating": rating, "reasons": reasons,
        "vendors": sorted({TRACKER_BY_KEY[k].vendor for k in fired}),
        "pixel_ids": ids, "events": events,
    }


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #
def result_from_dict(d: dict) -> SiteResult:
    return SiteResult(
        domain=d["domain"], url=d["url"], sector=d.get("sector", ""), city=d.get("city", ""),
        status=d.get("status", "ok"), error=d.get("error", ""), scanned_at=d.get("scanned_at", ""),
        pages=[PageInfo(**p) for p in d.get("pages", [])],
        hits=[TrackerHit(**h) for h in d.get("hits", [])],
        cmps=d.get("cmps", []), privacy_url=d.get("privacy_url", ""),
        privacy_mentions=d.get("privacy_mentions", []), assessment=d.get("assessment", {}),
        consent_test=d.get("consent_test"),
    )


def save_json(results: list[SiteResult], path: str) -> None:
    payload = {"tool": f"pixel_scan {__version__}", "generated": _now(), "disclaimer": DISCLAIMER,
               "results": [asdict(r) for r in results]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def load_json(path: str) -> list[SiteResult]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    items = data["results"] if isinstance(data, dict) else data
    return [result_from_dict(d) for d in items]


CSV_FIELDS = ["domain", "url", "sector", "city", "status", "rating", "score", "vendors", "pixel_ids",
              "events", "meta_advanced_matching", "consent_platforms", "consent_test", "pages_scanned", "reasons", "error"]


def save_csv(results: list[SiteResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in results:
            a = r.assessment or assess(r)
            w.writerow({
                "domain": r.domain, "url": r.url, "sector": r.sector, "city": r.city, "status": r.status,
                "rating": a["rating"], "score": a["score"], "vendors": "; ".join(a["vendors"]),
                "pixel_ids": "; ".join(f"{v}={'/'.join(i)}" for v, i in a["pixel_ids"].items()),
                "events": "; ".join(a["events"]),
                "meta_advanced_matching": "; ".join(sorted({f for h in r.hits for f in h.adv_matching})),
                "consent_test": (r.consent_test or {}).get("verdict", ""), "consent_platforms": "; ".join(r.cmps),
                "pages_scanned": len(r.pages), "reasons": " | ".join(a["reasons"]), "error": r.error,
            })


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------------------- #
# Report (self-contained HTML: inline CSS + JS, no external resources)
# --------------------------------------------------------------------------- #
_CSS = """
:root{--bg:#fff;--fg:#1d2330;--mut:#5b6475;--line:#d9dde5;--card:#f6f7fa;
--high:#b42318;--med:#b54708;--low:#175cd3;--none:#067647;--na:#667085}
@media(prefers-color-scheme:dark){:root{--bg:#14171f;--fg:#e6e9f0;--mut:#9aa3b5;--line:#2a2f3b;--card:#1b1f29;
--high:#f97066;--med:#fdb022;--low:#84adff;--none:#47cd89;--na:#98a2b3}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{margin:0 0 4px;font-size:22px}h2{font-size:16px;margin:28px 0 8px}
.sub{color:var(--mut);margin:0 0 16px}
.banner{border:1px solid var(--med);border-left-width:4px;background:var(--card);padding:10px 14px;border-radius:6px;margin:12px 0 20px}
.tiles{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:110px}
.tile b{display:block;font-size:22px}
.controls{display:flex;gap:8px;margin:8px 0;flex-wrap:wrap}
input,select{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{cursor:pointer;user-select:none;white-space:nowrap}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.High{color:var(--high)}.Medium{color:var(--med)}.Low{color:var(--low)}.None{color:var(--none)}.NotScanned{color:var(--na)}.Observed{color:var(--low)}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--card)}
summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.body{padding:0 14px 12px}
code{font:12px ui-monospace,Menlo,monospace;word-break:break-all}
ul{margin:4px 0 8px;padding-left:20px}.mut{color:var(--mut)}
img.shot{max-width:100%;border:1px solid var(--line);border-radius:6px;margin:4px 0}
figure{margin:8px 0}figcaption{font-size:12px;color:var(--mut)}
footer{margin-top:32px;color:var(--mut);font-size:12px}
"""
_JS = """
(function(){
var q=document.getElementById('q'),r=document.getElementById('r'),rows=[].slice.call(document.querySelectorAll('#t tbody tr'));
function f(){var s=q.value.toLowerCase(),v=r.value;rows.forEach(function(tr){
var ok=(!v||tr.dataset.rating===v)&&(!s||tr.textContent.toLowerCase().indexOf(s)>=0);tr.style.display=ok?'':'none';
var d=document.getElementById('d-'+tr.dataset.id);if(d)d.style.display=ok?'':'none';});}
q.oninput=f;r.onchange=f;
[].forEach.call(document.querySelectorAll('#t th'),function(th,i){th.onclick=function(){
var tb=document.querySelector('#t tbody'),a=[].slice.call(tb.rows),dir=th.dataset.dir=th.dataset.dir==='1'?'-1':'1';
a.sort(function(x,y){var u=x.cells[i].dataset.v||x.cells[i].textContent,w=y.cells[i].dataset.v||y.cells[i].textContent;
var n=parseFloat(u),m=parseFloat(w);return (isNaN(n)||isNaN(m)?u.localeCompare(w):n-m)*dir});
a.forEach(function(x){tb.appendChild(x)});};});
})();
"""


CONSENT_VERDICTS = {
    "reject_ignored": "ad-tech still fired after Reject",
    "fires_before_choice": "ad-tech fires before any choice is made",
    "blocked_until_consent": "ad-tech only loads after Accept",
    "no_adtech_observed": "no ad-tech observed in any mode",
    "no_consent_control_found": "could not find a consent control to click",
}


def _e(x: Any) -> str:
    return html.escape(str(x), quote=True)


def _badge(rating: str) -> str:
    cls = rating.replace(" ", "")
    return f'<span class="badge {_e(cls)}">{_e(rating)}</span>'


BASIS_HTML = (
    "<details class='basis'><summary><b>Basis and limitations</b></summary><div class='body'>"
    "<p>Basis: <i>Commissioner Initiated Investigation into Monash IVF Pty Ltd (Privacy)</i> [2026] AICmr 40 (11 June 2026) "
    "found breaches of APP 3.3, 5.1 and 7.1 where tracking pixels on a <b>health service provider's</b> website collected "
    "sensitive (health) information without consent or adequate notice and the data was used for retargeting. "
    "This tool only looks for the technical precondition: ad-tech or analytics requests made from a fresh browser before "
    "any consent is given.</p><ul>"
    "<li><b>Scope of ratings.</b> High / Medium / Low are given only to organisations whose sector label (assigned by the "
    "tool's operator) is health-related. Other organisations are labelled <b>Observed</b>: tracking was seen, but the ruling "
    "does not establish that sensitive information is involved.</li>"
    "<li><b>'Health-related page'</b> means the page URL matches health keywords. It does not show that the page "
    "reveals health information.</li>"
    "<li><b>Not observable here:</b> retargeting and Custom Audience uploads (the basis of the APP 7.1 finding), whether the "
    "data is personal or sensitive information, and whether any notice or consent mechanism was adequate (APP 5.1, 3.3). "
    "A notice-only banner may bear on APP 5 but is not consent under APP 3.3.</li>"
    "<li><b>Not detected:</b> Matomo and Jet Interactive, which the determination lists. The scan does not submit forms, "
    "so form-submission events are not observed.</li>"
    "<li><b>Scoring judgement.</b> The weighting between vendors, and treating Google Analytics with Consent Mode denied as "
    "low risk, are this tool's own judgements; the determination makes no pixel-by-pixel finding and does not address a "
    "denied-state ping.</li>"
    "<li><b>Status of the ruling.</b> It concerns one respondent. The Commissioner describes the 'reasonably identifiable' "
    "reasoning as potentially novel [74], and merits and judicial review rights exist.</li></ul></div></details>")


def render_report(results: list[SiteResult], generated: str = "") -> str:
    generated = generated or _now()
    rs = sorted(results, key=lambda r: -(r.assessment or assess(r))["score"])
    for r in rs:
        if not r.assessment:
            r.assessment = assess(r)
    counts = {k: sum(1 for r in rs if r.assessment["rating"] == k)
              for k in ("High", "Medium", "Low", "Observed", "None", "Not scanned")}
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>pixel_scan report</title><style>", _CSS, "</style></head><body><main>",
        "<h1>Pre-consent tracking scan</h1>",
        f"<p class='sub'>{_e(len(rs))} sites &middot; generated {_e(generated)} &middot; pixel_scan {_e(__version__)}</p>",
        f"<div class='banner'><b>Potential issue, not a legal finding.</b> {_e(DISCLAIMER.split('. ', 1)[1])}"
        "<br><span class='mut'>Method: one automated pass per site from a fresh browser with no consent given, "
        "robots.txt honoured, homepage + up to 3 likely-sensitive pages + privacy policy. The organisations were not contacted, "
        "findings are unverified, sites may have changed since the scan, and 'Not scanned' means the site blocked or "
        "refused automated access - not that it is compliant.</span></div>",
        BASIS_HTML,
        "<div class='tiles'>",
    ]
    for k, n in counts.items():
        parts.append(f"<div class='tile'><b>{n}</b>{_badge(k)}</div>")
    parts += [
        "</div><div class='controls'><input id='q' placeholder='Filter…' aria-label='Filter'>"
        "<select id='r' aria-label='Rating'><option value=''>All ratings</option>"
        "<option>High</option><option>Medium</option><option>Low</option><option>Observed</option><option>None</option>"
        "<option>Not scanned</option></select></div>",
        "<table id='t'><thead><tr><th>Site</th><th>Sector</th><th>Rating</th><th>Score</th>"
        "<th>Vendors firing pre-consent</th><th>CMP</th></tr></thead><tbody>",
    ]
    for i, r in enumerate(rs):
        a = r.assessment
        parts.append(
            f"<tr data-id='{i}' data-rating='{_e(a['rating'])}'><td><a href='#d-{i}'>{_e(r.domain)}</a></td>"
            f"<td>{_e(r.sector)}</td><td>{_badge(a['rating'])}</td><td data-v='{a['score']}'>{a['score']}</td>"
            f"<td>{_e(', '.join(a['vendors']) or '—')}</td><td>{_e(', '.join(r.cmps) or '—')}</td></tr>")
    parts.append("</tbody></table><h2>Site detail</h2>")
    for i, r in enumerate(rs):
        a = r.assessment
        parts.append(f"<details id='d-{i}'><summary><b>{_e(r.domain)}</b>{_badge(a['rating'])}"
                     f"<span class='mut'>score {a['score']}/100 &middot; {_e(r.sector)}</span></summary><div class='body'>")
        parts.append(f"<p><a href='{_e(r.url)}' rel='noopener noreferrer'>{_e(r.url)}</a>"
                     f" <span class='mut'>scanned {_e(r.scanned_at)}</span></p>")
        parts.append("<b>Why</b><ul>" + "".join(f"<li>{_e(x)}</li>" for x in a["reasons"]) + "</ul>")
        beacons = [h for h in r.hits if h.kind == "beacon"]
        scripts = [h for h in r.hits if h.kind == "script"]
        if r.consent_test:
            ct = r.consent_test
            parts.append(f"<b>Consent test</b> <span class='mut'>({_e(CONSENT_VERDICTS.get(ct['verdict'], ct['verdict']))})</span>"
                         "<table><thead><tr><th>Mode</th><th>Control clicked</th><th>Ad-tech / replay beacons observed</th></tr></thead><tbody>")
            for mode, label in (("none", "No interaction"), ("reject", "Reject clicked"), ("accept", "Accept clicked")):
                m = ct["modes"][mode]
                clicked = "n/a" if m["clicked"] is None else (f"yes ({m['method']})" if m["clicked"] else "not found")
                parts.append(f"<tr><td>{label}</td><td>{_e(clicked)}</td><td>{_e(', '.join(m['adtech']) or 'none')}"
                             f"{(' &middot; error: ' + _e(m['error'])) if m.get('error') else ''}</td></tr>")
            parts.append("</tbody></table>")
        if r.hits:
            parts.append("<b>Observed requests (no consent given)</b><table><thead><tr><th>Vendor</th><th>Type</th>"
                         "<th>ID</th><th>Event</th><th>Consent mode</th><th>Page URL sent</th><th>Seen on</th><th>×</th></tr></thead><tbody>")
            for h in beacons + scripts:
                parts.append(
                    f"<tr><td>{_e(h.vendor)}</td><td>{'data sent' if h.kind == 'beacon' else 'library loaded'}</td>"
                    f"<td><code>{_e(h.pixel_id or '—')}</code></td><td>{_e(h.event or '—')}"
                    f"{(' <span class=mut>(adv. matching: ' + _e(', '.join(h.adv_matching)) + ')</span>') if h.adv_matching else ''}</td>"
                    f"<td>{_e((h.gcs + ' (' + gcs_state(h.gcs) + ')') if h.gcs else '—')}</td>"
                    f"<td>{'yes' if h.page_url_sent else 'no' if h.kind == 'beacon' else '—'}</td>"
                    f"<td><code>{_e(urllib.parse.urlsplit(h.page).path or '/')}</code></td><td>{h.count}</td></tr>")
            parts.append("</tbody></table>")
        else:
            parts.append("<p class='mut'>No tracker requests matched.</p>")
        parts.append("<b>Pages visited</b><ul>" + "".join(
            f"<li>{_e(p.role)}: <code>{_e(p.url)}</code> &middot; HTTP {p.status or '—'}"
            f" &middot; forms {p.forms}{(' &middot; error: ' + _e(p.error)) if p.error else ''}</li>"
            for p in r.pages) + "</ul>")
        shots = [p for p in r.pages if p.screenshot]
        if shots:
            parts.append("<details><summary>Screenshots (no consent given)</summary>" + "".join(
                f"<figure><img class='shot' loading='lazy' alt='Screenshot of {_e(p.url)}' "
                f"src='data:image/jpeg;base64,{_e(p.screenshot)}'><figcaption>{_e(p.role)}: {_e(p.url)}</figcaption></figure>"
                for p in shots) + "</details>")
        if r.privacy_url:
            parts.append(f"<p>Privacy policy: <code>{_e(r.privacy_url)}</code> &middot; names: "
                         f"{_e(', '.join(r.privacy_mentions) or 'no tracking vendors')}</p>")
        if r.error:
            parts.append(f"<p class='mut'>Error: {_e(r.error)}</p>")
        parts.append("</div></details>")
    parts += [f"<footer>{_e(DISCLAIMER)}</footer><script>", _JS, "</script></main></body></html>"]
    return "".join(parts)


def save_report(results: list[SiteResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_report(results))


# --------------------------------------------------------------------------- #
# discover
# --------------------------------------------------------------------------- #
def domain_of(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc.lower().split(":")[0].removeprefix("www.")


def is_excluded(domain: str) -> bool:
    if domain.endswith(".gov.au") or domain.endswith(".edu.au") or domain == "gov.au":
        return True
    return any(domain == d or domain.endswith("." + d) for d in EXCLUDED_DOMAINS)


def brave_search(query: str, api_key: str, count: int = 20, offset: int = 0) -> list[dict]:
    params = urllib.parse.urlencode({"q": query, "count": count, "offset": offset,
                                     "country": "AU", "search_lang": "en"})
    req = urllib.request.Request(
        "https://api.search.brave.com/res/v1/web/search?" + params,
        headers={"Accept": "application/json", "X-Subscription-Token": api_key,
                 "User-Agent": f"{BOT_TOKEN}/{__version__}"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.load(resp).get("web", {}).get("results", [])
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    return []


def build_targets(rows: list[tuple[str, str, dict]]) -> list[dict]:
    """rows = [(sector, city, brave_result)] -> deduped target dicts (first hit per domain wins)."""
    seen: dict[str, dict] = {}
    for sector, city, item in rows:
        url = item.get("url", "")
        d = domain_of(url)
        if not d or is_excluded(d) or d in seen:
            continue
        u = urllib.parse.urlsplit(url)
        seen[d] = {"domain": d, "url": f"{u.scheme}://{u.netloc}/", "sector": sector, "city": city,
                   "title": (item.get("title") or "")[:120]}
    return list(seen.values())


def cmd_discover(args: argparse.Namespace) -> int:
    key = os.environ.get("BRAVE_API_KEY")
    if not key:
        print("error: BRAVE_API_KEY environment variable is not set", file=sys.stderr)
        return 2
    sectors = {k: v for k, v in SECTORS.items() if not args.sector or any(s.lower() in k.lower() for s in args.sector)}
    cities = args.city or CITIES[: args.max_cities]
    rows: list[tuple[str, str, dict]] = []
    for sector, templates in sectors.items():
        for city in cities:
            for tpl in templates:
                q = tpl.format(city=city)
                try:
                    items = brave_search(q, key, count=args.per_query)
                except Exception as e:  # noqa: BLE001
                    print(f"  ! {q!r}: {e}", file=sys.stderr)
                    continue
                print(f"  {q!r}: {len(items)} results", file=sys.stderr)
                rows.extend((sector, city, it) for it in items)
                time.sleep(1.1)  # free-tier rate limit
    targets = build_targets(rows)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["domain", "url", "sector", "city", "title"])
        w.writeheader()
        w.writerows(targets)
    print(f"wrote {len(targets)} targets to {args.out}")
    return 0


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
              f"Chrome/124.0.0.0 Safari/537.36 {BOT_TOKEN}/{__version__} (privacy research)")


def load_targets(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        url = (r.get("url") or r.get("domain") or "").strip()
        if not url:
            continue
        if not re.match(r"^https?://", url):
            url = "https://" + url
        out.append({"domain": r.get("domain") or domain_of(url), "url": url,
                    "sector": r.get("sector", ""), "city": r.get("city", "")})
    return out


class Robots:
    """robots.txt cache; fetched with our own UA token. Missing/unreachable robots = allowed."""

    def __init__(self, ignore: bool = False) -> None:
        self.ignore = ignore
        self._cache: dict[str, Optional[urllib.robotparser.RobotFileParser]] = {}

    def _fetch(self, origin: str) -> Optional[urllib.robotparser.RobotFileParser]:
        rp = urllib.robotparser.RobotFileParser()
        req = urllib.request.Request(origin + "/robots.txt", headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                rp.parse(resp.read().decode("utf-8", "replace").splitlines())
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                rp.disallow_all = True
            else:
                rp.allow_all = True
        except Exception:  # noqa: BLE001
            return None
        return rp

    async def allowed(self, url: str) -> bool:
        if self.ignore:
            return True
        u = urllib.parse.urlsplit(url)
        origin = f"{u.scheme}://{u.netloc}"
        if origin not in self._cache:
            self._cache[origin] = await asyncio.to_thread(self._fetch, origin)
        rp = self._cache[origin]
        return True if rp is None else rp.can_fetch(BOT_TOKEN, url)


# Count real data-entry forms; site-search boxes (role=search, type=search, name q/s/search) don't count.
FORM_JS = """() => {
  const skip = i => ['hidden','submit','button','search'].includes(i.type)
                    || /^(q|s|search|query|keyword)$/i.test(i.name || '');
  let forms = 0, inputs = 0;
  for (const f of document.forms) {
    if (f.matches('[role=search]') || f.closest('[role=search]')) continue;
    const n = [...f.querySelectorAll('input, textarea, select')].filter(i => !skip(i)).length;
    if (n > 0) { forms++; inputs += n; }
  }
  return {forms, inputs};
}"""

# --- consent interaction (only used with --consent-test) ---------------------
CMP_BUTTONS: dict[str, list[str]] = {
    "accept": ["#onetrust-accept-btn-handler", "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
               "#CybotCookiebotDialogBodyButtonAccept", ".cky-btn-accept", ".cmplz-accept",
               "#cookie_action_close_header", "[data-tid='banner-accept']", "#didomi-notice-agree-button",
               ".osano-cm-accept-all", "button[data-testid='uc-accept-all-button']"],
    "reject": ["#onetrust-reject-all-handler", ".ot-pc-refuse-all-handler", "#CybotCookiebotDialogBodyButtonDecline",
               ".cky-btn-reject", ".cmplz-deny", "#cookie_action_close_header_reject",
               "[data-tid='banner-decline']", "#didomi-notice-disagree-button", ".osano-cm-denyAll",
               "button[data-testid='uc-deny-all-button']"],
}
CONSENT_TEXT: dict[str, re.Pattern] = {
    "accept": re.compile(r"^\s*(accept( all)?( cookies)?( & close)?|allow all( cookies)?|i agree|agree|got it|ok(ay)?)\s*$", re.I),
    "reject": re.compile(r"^\s*(reject( all)?( cookies)?|decline( all)?( cookies)?|deny( all)?|refuse( all)?|"
                         r"(only )?(use )?(strictly )?(necessary|essential)( cookies)?( only)?|no,? thanks|"
                         r"continue without accepting)\s*$", re.I),
}
# Fallback for banners we don't recognise: a fixed/sticky element whose text talks about cookies/pixels.
BANNER_JS = """() => {
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.position !== 'fixed' && cs.position !== 'sticky') continue;
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const r = el.getBoundingClientRect();
    if (r.width < 150 || r.height < 20) continue;
    const t = (el.innerText || '').trim();
    if (t.length > 0 && t.length < 1500 && /cookie|tracking pixel|your privacy/i.test(t)) return true;
  }
  return false;
}"""
UNRECOGNISED_BANNER = "Cookie notice (unrecognised platform)"
ADTECH_CATEGORIES = ("advertising", "session_replay")


def adtech_vendors(hits: list[TrackerHit]) -> list[str]:
    return sorted({h.vendor for h in hits if h.kind == "beacon" and h.category in ADTECH_CATEGORIES})


def consent_verdict(baseline: list[TrackerHit], reject: dict, accept: dict, cmps: Optional[list[str]] = None) -> dict:
    """Compare no-interaction vs Reject vs Accept. `reject`/`accept` are pass summaries:
    {"clicked": bool, "method": str, "hits": [TrackerHit]}. Pure function."""
    base_ad = adtech_vendors(baseline)
    rej_ad = adtech_vendors(reject.get("hits", []))
    acc_ad = adtech_vendors(accept.get("hits", []))
    rej_clicked, acc_clicked = reject.get("clicked", False), accept.get("clicked", False)
    notes: list[str] = []
    if not rej_clicked and not acc_clicked:
        verdict = "no_consent_control_found"
        notes.append("Could not find or click an Accept/Reject control" + (
            f"; ad-tech fired with no interaction: {', '.join(base_ad)}" if base_ad else ""))
        if cmps:
            notes.append("A cookie banner/notice was detected (" + ", ".join(cmps) + ") but offers no recognisable Accept/Reject "
                         "button (notice-only, or an unrecognised design) - check the screenshot. A notice may bear on APP 5 but is not "
                         "itself consent under APP 3.3")
    elif rej_clicked and rej_ad:
        verdict = "reject_ignored"
        notes.append("Ad-tech/replay still fired after clicking Reject: " + ", ".join(rej_ad))
    elif base_ad:
        verdict = "fires_before_choice"
        notes.append("Ad-tech/replay fired before any choice was made: " + ", ".join(base_ad))
        if rej_clicked:
            notes.append("...and stopped after Reject (so Reject works, but nothing gated the initial load)")
    elif acc_clicked and set(acc_ad) - set(base_ad):
        verdict = "blocked_until_consent"
        notes.append("No ad-tech/replay before consent; loaded only after Accept: " + ", ".join(sorted(set(acc_ad) - set(base_ad))))
    else:
        verdict = "no_adtech_observed"
        notes.append("No ad-tech/replay beacons in any mode")
    if not rej_clicked and acc_clicked:
        notes.append("Accept control found but no Reject control located (a missing first-layer Reject is worth checking manually)")
    return {"verdict": verdict, "notes": notes,
            "modes": {
                "none": {"clicked": None, "method": "", "adtech": base_ad},
                "reject": {"clicked": rej_clicked, "method": reject.get("method", ""), "adtech": rej_ad,
                           "error": reject.get("error", "")},
                "accept": {"clicked": acc_clicked, "method": accept.get("method", ""), "adtech": acc_ad,
                           "error": accept.get("error", "")}}}


async def click_consent(page: Any, mode: str) -> tuple[bool, str]:
    """Try to click the Accept/Reject control: known CMP selectors first, then button/link text
    (all frames; Playwright pierces open shadow DOM). Returns (clicked, how)."""
    for sel in CMP_BUTTONS[mode]:
        try:
            loc = page.locator(sel).first
            if await loc.is_visible(timeout=400):
                await loc.click(timeout=3000)
                return True, sel
        except Exception:  # noqa: BLE001
            continue
    for frame in page.frames:
        for role in ("button", "link"):
            try:
                loc = frame.get_by_role(role, name=CONSENT_TEXT[mode]).first
                if await loc.is_visible(timeout=300):
                    await loc.click(timeout=3000)
                    return True, f"{role} by text"
            except Exception:  # noqa: BLE001
                continue
    return False, ""


def _recorder(state: dict, hits: list[TrackerHit], cmps: set[str]) -> Callable:
    """Build a request listener that records tracker/CMP hits into the given sinks."""
    def on_request(req: Any) -> None:
        try:
            url = req.url
            if url.startswith(("data:", "blob:")) or not state.get("rec", True):
                return
            c = match_cmp(url)
            if c:
                cmps.add(c)
            try:
                body = req.post_data
            except Exception:  # noqa: BLE001 - binary bodies
                body = None
            for h in match_request(url, req.method, body, state["page"]):
                merge_hit(hits, h)
        except Exception:  # noqa: BLE001 - never let a listener kill the scan
            pass
    return on_request


async def _visit(page: Any, url: str, role: str, nav_timeout: int, settle: float, state: dict,
                 screenshot: Any = False) -> tuple[PageInfo, list]:
    info = PageInfo(url=url, role=role)
    links: list = []
    state["page"] = url
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout)
        info.status = resp.status if resp else 0
        try:
            await page.wait_for_load_state("networkidle", timeout=min(nav_timeout, 8000))
        except Exception:  # noqa: BLE001 - chatty sites never go idle; that's fine
            pass
        await asyncio.sleep(settle)  # let delayed tags (GTM, Hotjar, chat) fire
        info.url = page.url
        state["page"] = page.url
        info.title = (await page.title())[:150]
        if screenshot is True or screenshot == "all" or (screenshot == "home" and role == "home"):
            try:  # viewport only, taken with no consent given: shows the banner state at scan time
                shot = await page.screenshot(type="jpeg", quality=55, timeout=8000)
                info.screenshot = base64.b64encode(shot).decode("ascii")
            except Exception:  # noqa: BLE001
                pass
        links = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => [e.href, (e.innerText || e.getAttribute('aria-label') || '').trim().slice(0,100)])")
        counts = await page.evaluate(FORM_JS)
        info.forms, info.inputs = counts["forms"], counts["inputs"]
    except Exception as e:  # noqa: BLE001
        info.error = f"{type(e).__name__}: {str(e).splitlines()[0][:150]}"
    return info, links


async def _consent_pass(browser: Any, mode: str, home_url: str, urls: list[str], *, nav_timeout: int,
                        settle: float, delay: float, context_hook: Optional[Callable]) -> dict:
    """Fresh context -> load home (not recorded) -> click Accept/Reject -> record home + sensitive pages."""
    out: dict[str, Any] = {"mode": mode, "clicked": False, "method": "", "hits": [], "error": ""}
    ctx = await browser.new_context(user_agent=USER_AGENT, locale="en-AU", timezone_id="Australia/Sydney",
                                    viewport={"width": 1366, "height": 850})
    state: dict[str, Any] = {"page": home_url, "rec": False}
    try:
        if context_hook:
            await context_hook(ctx)
        ctx.on("request", _recorder(state, out["hits"], set()))
        page = await ctx.new_page()
        page.set_default_timeout(nav_timeout)
        first, _ = await _visit(page, home_url, "home", nav_timeout, settle, state)
        if first.error:
            out["error"] = first.error
            return out
        out["clicked"], out["method"] = await click_consent(page, mode)
        if not out["clicked"]:
            return out
        await asyncio.sleep(settle)
        state["rec"] = True
        for u in [home_url] + urls:  # reload with the stored decision, then the sensitive pages
            await asyncio.sleep(delay)
            info, _ = await _visit(page, u, "consent-pass", nav_timeout, settle, state)
            if info.error and not out["error"]:
                out["error"] = info.error
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {str(e).splitlines()[0][:150]}"
    finally:
        try:
            await ctx.close()
        except Exception:  # noqa: BLE001
            pass
    return out


async def scan_site(browser: Any, target: dict, *, max_pages: int = 3, nav_timeout: int = 25000,
                    settle: float = 3.0, delay: float = 1.0, robots: Optional[Robots] = None,
                    context_hook: Optional[Callable] = None, screenshots: bool = False,
                    consent_test: bool = False) -> SiteResult:
    """Scan one site in a fresh, consent-less browser context."""
    res = SiteResult(domain=target["domain"], url=target["url"], sector=target.get("sector", ""),
                     city=target.get("city", ""), scanned_at=_now())
    robots = robots or Robots()
    if not await robots.allowed(target["url"]):
        res.status, res.error = "skipped_robots", "disallowed by robots.txt"
        res.assessment = assess(res)
        return res
    ctx = await browser.new_context(user_agent=USER_AGENT, locale="en-AU", timezone_id="Australia/Sydney",
                                    viewport={"width": 1366, "height": 850})
    state: dict[str, Any] = {"page": target["url"]}
    cmp_seen: set[str] = set()
    try:
        if context_hook:
            await context_hook(ctx)
        ctx.on("request", _recorder(state, res.hits, cmp_seen))
        page = await ctx.new_page()
        page.set_default_timeout(nav_timeout)
        page.on("framenavigated", lambda f: state.update(page=f.url) if f == page.main_frame and f.url.startswith("http") else None)

        home, links = await _visit(page, target["url"], "home", nav_timeout, settle, state, screenshots)
        if home.error and re.search(r"ERR_NAME_NOT_RESOLVED|ERR_CONNECTION|ERR_EMPTY|ERR_TIMED_OUT|Timeout", home.error):
            u = urllib.parse.urlsplit(target["url"])
            alt_host = u.netloc[4:] if u.netloc.startswith("www.") else "www." + u.netloc
            alt = urllib.parse.urlunsplit((u.scheme, alt_host, u.path, u.query, ""))
            if await robots.allowed(alt):
                home2, links2 = await _visit(page, alt, "home", nav_timeout, settle, state, screenshots)
                if not home2.error:
                    home, links = home2, links2
        res.pages.append(home)
        if home.error and not home.status:
            res.status, res.error = "error", home.error
        else:
            for name, sel in CMP_DOM.items():
                try:
                    if await page.locator(sel).first.is_visible(timeout=300):
                        cmp_seen.add(name)
                except Exception:  # noqa: BLE001
                    pass
            if not cmp_seen:
                try:
                    if await page.evaluate(BANNER_JS):
                        cmp_seen.add(UNRECOGNISED_BANNER)
                except Exception:  # noqa: BLE001
                    pass
            base = home.url
            for url in score_links([(h, t) for h, t in links], base, max_pages):
                if not await robots.allowed(url):
                    continue
                await asyncio.sleep(delay)
                info, _ = await _visit(page, url, "sensitive", nav_timeout, settle, state, screenshots)
                info.score = text_sensitivity(urllib.parse.urlsplit(url).path)
                res.pages.append(info)
            priv = find_privacy_link(links, base)
            if priv and await robots.allowed(priv):
                await asyncio.sleep(delay)
                info, _ = await _visit(page, priv, "privacy", nav_timeout, settle, state, screenshots)
                res.pages.append(info)
                res.privacy_url = info.url
                if not info.error:
                    try:
                        res.privacy_mentions = privacy_mentions((await page.inner_text("body"))[:200000])
                    except Exception:  # noqa: BLE001
                        pass
        res.cmps = sorted(cmp_seen)
    except Exception as e:  # noqa: BLE001
        res.status, res.error = "error", f"{type(e).__name__}: {str(e).splitlines()[0][:150]}"
    finally:
        try:
            await ctx.close()
        except Exception:  # noqa: BLE001
            pass

    if consent_test and res.status == "ok":
        urls = [p.url for p in res.pages if p.role == "sensitive" and not p.error]
        passes = {}
        for mode in ("reject", "accept"):
            passes[mode] = await _consent_pass(browser, mode, res.pages[0].url, urls, nav_timeout=nav_timeout,
                                               settle=settle, delay=delay, context_hook=context_hook)
        res.consent_test = consent_verdict(res.hits, passes["reject"], passes["accept"], res.cmps)
    res.assessment = assess(res)
    return res


async def scan_all(targets: list[dict], *, concurrency: int = 2, max_pages: int = 3,
                   nav_timeout: int = 25000, settle: float = 3.0, delay: float = 1.0,
                   ignore_robots: bool = False, headed: bool = False,
                   context_hook: Optional[Callable] = None, screenshots: bool = False,
                   consent_test: bool = False,
                   progress: Optional[Callable[[int, int, SiteResult], None]] = None) -> list[SiteResult]:
    from playwright.async_api import async_playwright  # lazy: only `scan` needs it

    robots = Robots(ignore=ignore_robots)
    sem = asyncio.Semaphore(max(1, concurrency))
    results: list[Optional[SiteResult]] = [None] * len(targets)
    done = 0
    passes = 3 if consent_test else 1
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=not headed)
        try:
            async def work(i: int, t: dict) -> None:
                nonlocal done
                async with sem:
                    # hard per-site ceiling so one hung site can't stall the run
                    ceiling = ((nav_timeout / 1000 + settle + 10) * (max_pages + 2) + 30) * passes
                    try:
                        r = await asyncio.wait_for(scan_site(
                            browser, t, max_pages=max_pages, nav_timeout=nav_timeout, settle=settle,
                            delay=delay, robots=robots, context_hook=context_hook,
                            screenshots=screenshots, consent_test=consent_test), ceiling)
                    except Exception as e:  # noqa: BLE001
                        r = SiteResult(domain=t["domain"], url=t["url"], sector=t.get("sector", ""),
                                       city=t.get("city", ""), status="error", scanned_at=_now(),
                                       error=f"{type(e).__name__}: {str(e)[:150] or 'timed out'}")
                        r.assessment = assess(r)
                    results[i] = r
                    done += 1
                    if progress:
                        progress(done, len(targets), r)

            await asyncio.gather(*(work(i, t) for i, t in enumerate(targets)))
        finally:
            await browser.close()
    return [r for r in results if r is not None]


def cmd_scan(args: argparse.Namespace) -> int:
    targets = load_targets(args.targets)
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        print("error: no targets", file=sys.stderr)
        return 2
    if args.ignore_robots:
        print("warning: --ignore-robots set; robots.txt will NOT be honoured", file=sys.stderr)
    if args.consent_test:
        print("note: --consent-test clicks Accept/Reject on consent banners (3 passes per site; no forms are submitted)",
              file=sys.stderr)

    os.makedirs(args.outdir, exist_ok=True)
    partial = os.path.join(args.outdir, "results.partial.jsonl")
    prior: list[SiteResult] = []
    if args.resume and os.path.exists(partial):
        with open(partial, encoding="utf-8") as f:
            prior = [result_from_dict(json.loads(line)) for line in f if line.strip()]
        done_domains = {r.domain for r in prior}
        targets = [t for t in targets if t["domain"] not in done_domains]
        print(f"resuming: {len(prior)} already done, {len(targets)} to go", file=sys.stderr)
    elif os.path.exists(partial):
        os.remove(partial)

    def progress(n: int, total: int, r: SiteResult) -> None:
        with open(partial, "a", encoding="utf-8") as f:  # checkpoint every site so a crash loses nothing
            f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
        a = r.assessment
        extra = f" [consent: {r.consent_test['verdict']}]" if r.consent_test else ""
        print(f"[{n}/{total}] {r.domain}: {a['rating']} ({a['score']}){extra}"
              + (f" - {r.error}" if r.status != "ok" else ""), file=sys.stderr)

    try:
        results = asyncio.run(scan_all(
            targets, concurrency=args.concurrency, max_pages=args.max_pages, nav_timeout=args.timeout * 1000,
            settle=args.settle, delay=args.delay, ignore_robots=args.ignore_robots, headed=args.headed,
            screenshots=args.screenshots, consent_test=args.consent_test, progress=progress))
    except ImportError:
        print("error: playwright is not installed. Run: pip install playwright && python -m playwright install chromium",
              file=sys.stderr)
        return 2
    results = prior + results
    results.sort(key=lambda r: -r.assessment["score"])
    save_json(results, os.path.join(args.outdir, "results.json"))
    save_csv(results, os.path.join(args.outdir, "results.csv"))
    save_report(results, os.path.join(args.outdir, "report.html"))
    print(f"wrote results.json, results.csv, report.html to {args.outdir}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    results = load_json(args.json)
    for r in results:
        r.assessment = assess(r)  # re-score so rule changes apply to old scans
    save_report(results, args.out)
    print(f"wrote {args.out}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="pixel_scan", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="find targets via Brave Search (needs BRAVE_API_KEY)")
    d.add_argument("--out", default="targets.csv")
    d.add_argument("--sector", action="append", help="substring of sector name; repeatable")
    d.add_argument("--city", action="append", help="override city list; repeatable")
    d.add_argument("--max-cities", type=int, default=len(CITIES))
    d.add_argument("--per-query", type=int, default=20)
    d.set_defaults(fn=cmd_discover)

    s = sub.add_parser("scan", help="scan targets for pre-consent trackers")
    s.add_argument("--targets", default="targets.csv")
    s.add_argument("--outdir", default=".")
    s.add_argument("--limit", type=int, default=0, help="scan only the first N targets")
    s.add_argument("--concurrency", type=int, default=2)
    s.add_argument("--max-pages", type=int, default=3, help="likely-sensitive pages per site")
    s.add_argument("--timeout", type=int, default=25, help="navigation timeout, seconds")
    s.add_argument("--settle", type=float, default=3.0, help="seconds to wait after load for delayed tags")
    s.add_argument("--delay", type=float, default=1.0, help="seconds between page loads on one site")
    s.add_argument("--ignore-robots", action="store_true", help="do NOT honour robots.txt (use only with authorisation)")
    s.add_argument("--headed", action="store_true")
    s.add_argument("--screenshots", nargs="?", const="all", choices=["home", "all"],
                   help="embed viewport screenshots in the report: 'home' = homepage only, 'all' (default if flag given) = every page")
    s.add_argument("--resume", action="store_true", help="skip targets already in <outdir>/results.partial.jsonl and continue")
    s.add_argument("--consent-test", action="store_true",
                   help="also rescan with Reject and Accept clicked, to check whether the consent platform really blocks tracking")
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("report", help="rebuild report.html from results.json")
    r.add_argument("--json", default="results.json")
    r.add_argument("--out", default="report.html")
    r.set_defaults(fn=cmd_report)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
