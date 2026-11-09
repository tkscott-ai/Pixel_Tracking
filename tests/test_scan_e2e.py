"""End-to-end: real Chromium against a local http.server test site (vendors stubbed offline)."""
import asyncio

import pytest

pytest.importorskip("playwright")
import pixel_scan as ps
from harness import serve, vendor_stub_hook


def run(targets, **kw):
    kw.setdefault("settle", 1.0)
    kw.setdefault("delay", 0.1)
    kw.setdefault("context_hook", vendor_stub_hook)
    try:
        return asyncio.run(ps.scan_all(targets, **kw))
    except Exception as e:  # chromium not installed etc.
        if "Executable doesn't exist" in str(e):
            pytest.skip("chromium not installed")
        raise


@pytest.fixture(scope="module")
def site():
    srv, base = serve()
    yield base
    srv.shutdown()


@pytest.fixture(scope="module")
def result(site):
    return run([{"domain": "127.0.0.1", "url": site + "/", "sector": "IVF", "city": "T"}], concurrency=1)[0]


def beacons(r, key):
    return [h for h in r.hits if h.key == key and h.kind == "beacon"]


def test_pages_visited(result, site):
    roles = {(p.role, p.url.replace(site, "")) for p in result.pages}
    assert roles == {("home", "/"), ("sensitive", "/ivf-treatment"), ("sensitive", "/contact"), ("privacy", "/privacy-policy")}
    assert all(p.status == 200 and not p.error for p in result.pages)


def test_not_sensitive_or_external_links_skipped(result):
    urls = " ".join(p.url for p in result.pages)
    assert "/about" not in urls and ".pdf" not in urls and "other.example" not in urls


def test_form_detected(result):
    f = next(p for p in result.pages if p.url.endswith("/ivf-treatment"))
    assert f.forms == 1 and f.inputs == 3


def test_site_search_box_not_counted_as_form(result):
    home = next(p for p in result.pages if p.role == "home")
    assert home.forms == 0 and home.inputs == 0


def test_meta_pixel(result, site):
    evs = {(h.event, h.page.replace(site, "")) for h in beacons(result, "meta")}
    assert ("PageView", "/") in evs and ("Lead", "/ivf-treatment") in evs
    assert {h.pixel_id for h in beacons(result, "meta")} == {"1234567890123456"}
    assert all(h.page_url_sent for h in beacons(result, "meta"))


def test_ga4_consent_mode_denied(result):
    b = beacons(result, "ga4")
    assert b and {h.gcs for h in b} == {"G100"} and {h.pixel_id for h in b} == {"G-TEST12345"}
    assert ps.gcs_state(b[0].gcs) == "denied"


def test_hotjar(result):
    assert {h.pixel_id for h in beacons(result, "hotjar")} == {"6543210"}


def test_banner_detected_and_privacy(result):
    assert result.cmps  # DOM-detected cookie banner
    assert result.privacy_url.endswith("/privacy-policy")
    assert result.privacy_mentions == ["ga4"]


def test_assessment(result):
    a = result.assessment
    assert a["rating"] == "High" and 60 <= a["score"] <= 100
    assert set(a["vendors"]) == {"Meta Pixel", "Hotjar", "Google Analytics (GA4)"}
    assert any("Lead" in r for r in a["reasons"])


def test_robots_disallow_is_honoured():
    srv, base = serve(robots="User-agent: *\nDisallow: /\n")
    try:
        r = run([{"domain": "x", "url": base + "/"}], concurrency=1)[0]
        assert r.status == "skipped_robots" and not r.hits and r.assessment["rating"] == "Not scanned"
        r2 = run([{"domain": "x", "url": base + "/"}], concurrency=1, ignore_robots=True)[0]
        assert r2.status == "ok" and r2.hits
    finally:
        srv.shutdown()


def test_robots_disallow_single_page_skips_only_that_page():
    srv, base = serve(robots="User-agent: pixel_scan\nDisallow: /ivf-treatment\n")
    try:
        r = run([{"domain": "x", "url": base + "/"}], concurrency=1)[0]
        assert not any(p.url.endswith("/ivf-treatment") for p in r.pages)
        assert not any(h.event == "Lead" for h in r.hits)
    finally:
        srv.shutdown()


def test_unreachable_site_is_an_error_not_a_crash(site):
    targets = [{"domain": "dead", "url": "http://127.0.0.1:9/"}, {"domain": "ok", "url": site + "/"}]
    rs = run(targets, concurrency=2, nav_timeout=5000)
    by = {r.domain: r for r in rs}
    assert by["dead"].status == "error" and by["dead"].error
    assert by["ok"].status == "ok" and by["ok"].hits


def test_concurrency_and_order(site):
    targets = [{"domain": f"s{i}", "url": site + "/"} for i in range(4)]
    rs = run(targets, concurrency=3)
    assert [r.domain for r in rs] == ["s0", "s1", "s2", "s3"]
    assert all(r.assessment["rating"] == "High" for r in rs)  # contexts are isolated, results identical


def test_fresh_context_no_state_leak(site):
    """Same site scanned twice gets the same hits (no cookies/consent carried over)."""
    a, b = run([{"domain": "a", "url": site + "/"}, {"domain": "b", "url": site + "/"}], concurrency=1)
    key = lambda r: sorted((h.key, h.kind, h.event, h.page) for h in r.hits)
    assert key(a) == key(b)


def test_cli_scan_writes_outputs(site, tmp_path, monkeypatch):
    """Drive cmd_scan end to end (vendors stubbed via monkeypatched scan_all)."""
    import csv, functools
    t = tmp_path / "targets.csv"
    t.write_text(f"domain,url,sector,city\n127.0.0.1,{site}/,IVF,T\n")
    real = ps.scan_all
    monkeypatch.setattr(ps, "scan_all", functools.partial(real, context_hook=vendor_stub_hook))
    assert ps.main(["scan", "--targets", str(t), "--outdir", str(tmp_path), "--settle", "1", "--delay", "0.1", "--limit", "5"]) == 0
    for f in ("results.json", "results.csv", "report.html"):
        assert (tmp_path / f).exists()
    rows = list(csv.DictReader(open(tmp_path / "results.csv")))
    assert rows[0]["rating"] == "High"


# ---- advanced matching -------------------------------------------------------
def test_meta_advanced_matching_detected_without_storing_hashes(result):
    adv = [h for h in beacons(result, "meta") if h.adv_matching]
    assert adv and adv[0].page.endswith("/contact")
    assert set(adv[0].adv_matching) == {"em", "ph"}
    import hashlib
    assert hashlib.sha256(b"jane@example.com").hexdigest() not in adv[0].url  # redacted evidence
    assert "[redacted]" in adv[0].url
    assert any("advanced matching" in r for r in result.assessment["reasons"])


# ---- screenshots -------------------------------------------------------------
def test_screenshots_embedded_in_self_contained_report(site):
    import base64, re
    r = run([{"domain": "127.0.0.1", "url": site + "/"}], concurrency=1, screenshots=True)[0]
    assert all(p.screenshot for p in r.pages)
    assert base64.b64decode(r.pages[0].screenshot)[:3] == b"\xff\xd8\xff"  # JPEG
    out = ps.render_report([r])
    assert "data:image/jpeg;base64," in out
    assert not re.findall(r"(?:src|href)=['\"]https?://(?!127\.0\.0\.1)", out)
    assert not any(p.screenshot for p in run([{"domain": "x", "url": site + "/"}], concurrency=1)[0].pages)  # opt-in


# ---- consent test ------------------------------------------------------------
def test_consent_test_good_cmp_blocks_until_accept(site):
    r = run([{"domain": "good", "url": site + "/consent-good/"}], concurrency=1, consent_test=True)[0]
    ct = r.consent_test
    assert ct["verdict"] == "blocked_until_consent", ct
    assert ct["modes"]["none"]["adtech"] == [] and ct["modes"]["reject"]["adtech"] == []
    assert ct["modes"]["accept"]["adtech"] == ["Meta Pixel"]
    assert ct["modes"]["reject"]["clicked"] and ct["modes"]["accept"]["clicked"]
    assert r.assessment["rating"] == "None"  # nothing fired pre-consent


def test_consent_test_bad_cmp_ignores_reject(site):
    r = run([{"domain": "bad", "url": site + "/consent-bad/"}], concurrency=1, consent_test=True)[0]
    ct = r.consent_test
    assert ct["verdict"] == "reject_ignored", ct
    assert ct["modes"]["reject"]["adtech"] == ["Meta Pixel"]
    assert "onetrust" in ct["modes"]["reject"]["method"]     # known-CMP selector path
    assert r.assessment["rating"] in ("Medium", "High")
    assert any(x.startswith("Consent test:") for x in r.assessment["reasons"])
    assert "ad-tech still fired after Reject" in ps.render_report([r])


def test_consent_test_good_cmp_text_fallback_path(site):
    r = run([{"domain": "good", "url": site + "/consent-good/"}], concurrency=1, consent_test=True)[0]
    assert r.consent_test["modes"]["reject"]["method"] == "button by text"


def test_consent_test_off_by_default(result):
    assert result.consent_test is None


def test_notice_only_banner_detected_and_reported(site):
    r = run([{"domain": "n", "url": site + "/consent-notice/"}], concurrency=1, consent_test=True)[0]
    assert r.cmps == [ps.UNRECOGNISED_BANNER]
    ct = r.consent_test
    assert ct["verdict"] == "no_consent_control_found"
    assert any("notice-only" in n for n in ct["notes"]) and "Meta Pixel" in ct["notes"][0]

