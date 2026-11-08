"""Unit tests for the pure logic: matching, parsing, link scoring, scoring, serialisation, report."""
import csv
import json

import pytest

import pixel_scan as ps


# ---- request matching -------------------------------------------------------
PAGE = "https://clinic.example.com.au/ivf-treatment"


def one(url, post=None, method="GET", page=PAGE):
    hits = ps.match_request(url, method, post, page)
    assert len(hits) == 1, hits
    return hits[0]


def test_meta_beacon_parsed():
    h = one("https://www.facebook.com/tr/?id=1234567890&ev=Lead&dl=https%3A%2F%2Fclinic.example.com.au%2Fivf-treatment&rl=")
    assert (h.key, h.kind, h.pixel_id, h.event) == ("meta", "beacon", "1234567890", "Lead")
    assert h.page_url_sent is True


def test_meta_script_is_not_a_beacon():
    h = one("https://connect.facebook.net/en_US/fbevents.js")
    assert h.kind == "script" and h.page_url_sent is False


def test_meta_beacon_without_page_url():
    h = one("https://www.facebook.com/tr/?id=99&ev=PageView")
    assert h.page_url_sent is False


@pytest.mark.parametrize("gcs,state", [("G100", "denied"), ("G111", "granted"), ("G110", "partial"),
                                       ("G101", "partial"), ("", "unknown"), ("junk", "unknown")])
def test_gcs_state(gcs, state):
    assert ps.gcs_state(gcs) == state


def test_ga4_beacon_with_consent_mode():
    h = one("https://www.google-analytics.com/g/collect?v=2&tid=G-ABC123&gcs=G100&en=page_view&dl=" +
            "https%3A%2F%2Fclinic.example.com.au%2Fivf-treatment")
    assert (h.key, h.pixel_id, h.event, h.gcs) == ("ga4", "G-ABC123", "page_view", "G100")
    assert h.page_url_sent


def test_ga4_multiple_events_in_post_body():
    h = one("https://region1.google-analytics.com/g/collect?v=2&tid=G-X&en=page_view",
            post="en=scroll&_et=1\nen=form_start&_et=2", method="POST")
    assert h.event == "page_view,scroll,form_start"


def test_ga4_gtag_script_loader():
    h = one("https://www.googletagmanager.com/gtag/js?id=G-LOAD1")
    assert h.kind == "script" and h.pixel_id == "G-LOAD1"


def test_gtm_is_script_only_tag_manager():
    h = one("https://www.googletagmanager.com/gtm.js?id=GTM-ABCD12")
    assert (h.category, h.kind, h.pixel_id) == ("tag_manager", "script", "GTM-ABCD12")


def test_hotjar_variants():
    assert one("https://static.hotjar.com/c/hotjar-3456789.js?sv=6").pixel_id == "3456789"
    assert one("https://in.hotjar.com/api/v2/client/sites/3456789/visit-data?sv=6").pixel_id == "3456789"
    assert one("https://in.hotjar.com/api/v2/client/sites/3456789/visit-data").category == "session_replay"


def test_pinterest_tiktok_linkedin_bing_clarity():
    p = one("https://ct.pinterest.com/v3/?tid=2612345678&event=pagevisit")
    assert (p.key, p.pixel_id, p.event) == ("pinterest", "2612345678", "pagevisit")
    t = one("https://analytics.tiktok.com/api/v2/pixel", post=json.dumps({"context": {"pixel": {"code": "C1ABC"}}, "event": "Contact"}), method="POST")
    assert (t.key, t.pixel_id) == ("tiktok", "C1ABC")
    assert one("https://px.ads.linkedin.com/collect?pid=555&fmt=gif").pixel_id == "555"
    b = one("https://bat.bing.com/action/0?ti=4012345&Ver=2&evt=pageLoad")
    assert (b.pixel_id, b.event) == ("4012345", "pageLoad")
    assert one("https://www.clarity.ms/tag/abc123xyz").kind == "script"
    assert one("https://k.clarity.ms/collect", method="POST").kind == "beacon"


def test_google_ads_conversion():
    h = one("https://www.googleadservices.com/pagead/conversion/1122334455/?label=abc&gcs=G111")
    assert (h.key, h.pixel_id, h.kind) == ("google_ads", "1122334455", "beacon")


@pytest.mark.parametrize("url", [
    "https://clinic.example.com.au/wp-content/theme.css",
    "https://fonts.googleapis.com/css?family=Roboto",
    "https://www.facebook.com/clinic",             # a link, not the pixel
    "https://cdn.example.com/hotjar-notes.js",
    "https://example.com/?next=https://www.facebook.com/tr/?id=1",
])
def test_non_trackers_do_not_match(url):
    assert ps.match_request(url, "GET", None, PAGE) == []


@pytest.mark.parametrize("url,name", [
    ("https://cdn.cookielaw.org/scripttemplates/otSDKStub.js", "OneTrust"),
    ("https://consent.cookiebot.com/uc.js?cbid=1", "Cookiebot"),
    ("https://app.usercentrics.eu/browser-ui/latest/loader.js", "Usercentrics"),
    ("https://cdn-cookieyes.com/client_data/x/script.js", "CookieYes"),
    ("https://app.termly.io/resource-blocker/abc", "Termly"),
])
def test_cmp_detection(url, name):
    assert ps.match_cmp(url) == name


def test_cmp_none():
    assert ps.match_cmp("https://example.com/app.js") is None


def test_page_url_detection_edge_cases():
    f = ps.page_url_in_request
    assert f("https://a.com.au/x", "https://t.com/c?dl=https%3A%2F%2Fa.com.au%2Fx", None)
    assert f("https://a.com.au/x/", "https://t.com/c?dl=https%3A%2F%2Fa.com.au%2Fx", None)   # trailing slash
    assert f("https://a.com.au/x", "https://t.com/c", '{"url":"https://a.com.au/x"}')       # in POST body
    assert f("https://a.com.au/", "https://t.com/c?u=https%3A%2F%2Fa.com.au%2F", None)       # homepage
    assert not f("https://a.com.au/", "https://t.com/c?id=1", None)
    assert not f("https://a.com.au/x", "https://t.com/c?dl=https%3A%2F%2Fa.com.au%2Fy", None)
    assert not f("about:blank", "https://t.com/c?about:blank", None)


def test_merge_hit_dedupes():
    hits = []
    for _ in range(3):
        ps.merge_hit(hits, one("https://www.facebook.com/tr/?id=1&ev=PageView"))
    ps.merge_hit(hits, one("https://www.facebook.com/tr/?id=1&ev=Lead"))
    assert [(h.event, h.count) for h in hits] == [("PageView", 3), ("Lead", 1)]


# ---- link scoring -----------------------------------------------------------
BASE = "https://clinic.example.com.au/"


def test_score_links_picks_sensitive_same_site_only():
    links = [
        ("/ivf-treatment", "IVF treatment"), ("/about-us", "About"), ("/book-appointment", "Book now"),
        ("https://other.example/ivf", "IVF"), ("/files/ivf.pdf", "IVF brochure"),
        ("mailto:a@b.c", "Email"), ("/privacy-policy", "Privacy"), ("/", "Home"),
        ("https://www.clinic.example.com.au/fertility-assessment", "Fertility assessment"),
    ]
    got = ps.score_links(links, BASE, 3)
    assert "https://clinic.example.com.au/ivf-treatment" in got
    assert "https://clinic.example.com.au/book-appointment" in got
    assert all("other.example" not in u and not u.endswith(".pdf") and "privacy" not in u and "about" not in u for u in got)
    assert len(got) == 3


def test_score_links_respects_limit_and_dedupes():
    links = [("/ivf", "a"), ("/ivf#top", "b"), ("/ivf/", "c"), ("/fertility", "d")]
    got = ps.score_links(links, BASE, 5)
    assert len(got) == len(set(got))


def test_score_links_empty_when_nothing_sensitive():
    assert ps.score_links([("/about", "About"), ("/news", "News")], BASE, 3) == []


def test_find_privacy_link():
    links = [("/terms", "Terms"), ("/privacy-policy", "Privacy Policy"), ("https://x.com/privacy", "x")]
    assert ps.find_privacy_link(links, BASE) == "https://clinic.example.com.au/privacy-policy"
    assert ps.find_privacy_link([("/about", "About")], BASE) == ""


def test_privacy_mentions():
    assert set(ps.privacy_mentions("We use Google Analytics and the Meta Pixel; Hotjar too")) == {"ga4", "meta", "hotjar"}
    assert ps.privacy_mentions("We value your privacy") == []


# ---- assessment -------------------------------------------------------------
def site(hits=(), pages=(), cmps=(), privacy_url="", mentions=(), status="ok"):
    return ps.SiteResult(domain="x.com.au", url="https://x.com.au/", status=status, hits=list(hits),
                         pages=list(pages), cmps=list(cmps), privacy_url=privacy_url,
                         privacy_mentions=list(mentions))


def H(key, kind="beacon", page="https://x.com.au/", **kw):
    t = ps.TRACKER_BY_KEY[key]
    return ps.TrackerHit(key=key, vendor=t.vendor, category=t.category, kind=kind, page=page, **kw)


def test_rating_thresholds():
    assert [ps.rating_for(s) for s in (0, 1, 29, 30, 59, 60, 100)] == ["None", "Low", "Low", "Medium", "Medium", "High", "High"]


def test_assess_clean_site_is_none():
    a = ps.assess(site())
    assert (a["score"], a["rating"]) == (0, "None")


def test_assess_gtm_only_is_none():
    assert ps.assess(site([H("gtm", "script")]))["rating"] == "None"


def test_assess_ga4_denied_is_low_and_granted_is_higher():
    denied = ps.assess(site([H("ga4", gcs="G100")]))
    granted = ps.assess(site([H("ga4", gcs="G111")]))
    assert denied["rating"] == "Low" and granted["score"] > denied["score"]


def test_assess_meta_alone_is_medium():
    a = ps.assess(site([H("meta", pixel_id="1", event="PageView")]))
    assert a["rating"] == "Medium" and a["vendors"] == ["Meta Pixel"]


def test_assess_script_only_weaker_than_beacon():
    assert ps.assess(site([H("meta", "script")]))["score"] < ps.assess(site([H("meta")]))["score"]


def test_assess_full_monash_pattern_is_high():
    page = "https://x.com.au/ivf-treatment"
    hits = [H("meta", page=page, event="Lead", pixel_id="1", page_url_sent=True),
            H("hotjar", page=page, pixel_id="2", page_url_sent=True), H("ga4", page=page, gcs="G100")]
    pages = [ps.PageInfo(url=page, role="sensitive", forms=1)]
    a = ps.assess(site(hits, pages, cmps=["OneTrust"]))
    assert a["rating"] == "High" and a["score"] <= 100
    text = " ".join(a["reasons"])
    assert "Conversion-type" in text and "Sensitive page URL" in text and "Form present" in text and "OneTrust" in text


def test_conversion_event_on_non_sensitive_page_not_flagged():
    a = ps.assess(site([H("meta", page="https://x.com.au/news", event="Lead")]))
    assert not any("Conversion-type" in r for r in a["reasons"])


def test_assess_cmp_present_and_clean():
    a = ps.assess(site(cmps=["Cookiebot"]))
    assert a["rating"] == "None" and any("no tracker beacons" in r for r in a["reasons"])


def test_assess_privacy_disclosure_note():
    a = ps.assess(site([H("meta")], privacy_url="https://x.com.au/privacy", mentions=["ga4"]))
    assert any("does not appear to name: Meta Pixel" in r for r in a["reasons"])
    b = ps.assess(site([H("meta")], privacy_url="https://x.com.au/privacy", mentions=["meta"]))
    assert not any("does not appear to name" in r for r in b["reasons"])


def test_assess_not_scanned():
    a = ps.assess(site(status="skipped_robots"))
    assert a["rating"] == "Not scanned"


def test_score_capped_at_100():
    page = "https://x.com.au/ivf"
    keys = ["meta", "tiktok", "pinterest", "linkedin", "bing", "google_ads", "hotjar", "clarity", "ga4"]
    hits = [H(k, page=page, event="Lead", page_url_sent=True) for k in keys]
    assert ps.assess(site(hits, [ps.PageInfo(url=page, forms=1)], cmps=["x"]))["score"] == 100


# ---- discovery helpers ------------------------------------------------------
@pytest.mark.parametrize("d,ex", [
    ("health.gov.au", True), ("www.dhhs.vic.gov.au", True), ("healthengine.com.au", True),
    ("au.indeed.com", True), ("facebook.com", True), ("monashivf.com", False),
    ("mygovclinic.com.au", False), ("notfacebook.com", False),
])
def test_is_excluded(d, ex):
    assert ps.is_excluded(d) is ex


def test_build_targets_dedupes_and_filters():
    rows = [
        ("IVF", "Sydney", {"url": "https://www.clinic.com.au/ivf?x=1", "title": "Clinic"}),
        ("IVF", "Melbourne", {"url": "https://clinic.com.au/other", "title": "Dup"}),
        ("IVF", "Sydney", {"url": "https://www.healthengine.com.au/ivf", "title": "Dir"}),
        ("IVF", "Sydney", {"url": "https://health.nsw.gov.au/ivf"}),
        ("Mental", "Perth", {"url": "http://psych.example.com.au/"}),
    ]
    t = ps.build_targets(rows)
    assert [x["domain"] for x in t] == ["clinic.com.au", "psych.example.com.au"]
    assert t[0]["url"] == "https://www.clinic.com.au/" and t[0]["city"] == "Sydney"


def test_sector_templates_all_have_city_placeholder():
    for sector, tpls in ps.SECTORS.items():
        assert tpls and all("{city}" in t for t in tpls), sector


def test_discover_requires_key(monkeypatch, capsys):
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    assert ps.main(["discover"]) == 2
    assert "BRAVE_API_KEY" in capsys.readouterr().err


def test_discover_writes_csv_with_mocked_brave(monkeypatch, tmp_path):
    monkeypatch.setenv("BRAVE_API_KEY", "k")
    monkeypatch.setattr(ps.time, "sleep", lambda s: None)
    monkeypatch.setattr(ps, "brave_search", lambda q, key, count=20, offset=0: [
        {"url": "https://ivf.example.com.au/", "title": q}, {"url": "https://www.hotdoc.com.au/x"}])
    out = tmp_path / "t.csv"
    assert ps.main(["discover", "--out", str(out), "--sector", "IVF", "--city", "Sydney"]) == 0
    rows = list(csv.DictReader(open(out)))
    assert [r["domain"] for r in rows] == ["ivf.example.com.au"]


# ---- serialisation + report -------------------------------------------------
def sample_results():
    page = "https://x.com.au/ivf-treatment"
    a = site([H("meta", page=page, event="Lead", pixel_id="123", page_url_sent=True)],
             [ps.PageInfo(url=page, role="sensitive", forms=1, status=200)], cmps=["OneTrust"])
    a.sector, a.scanned_at = "IVF", "now"
    a.assessment = ps.assess(a)
    b = ps.SiteResult(domain="evil<script>.com", url="https://evil.com/\"onmouseover=\"x", status="error", error="<b>boom</b>")
    b.assessment = ps.assess(b)
    return [a, b]


def test_json_roundtrip(tmp_path):
    p = tmp_path / "r.json"
    rs = sample_results()
    ps.save_json(rs, str(p))
    back = ps.load_json(str(p))
    assert [r.domain for r in back] == [r.domain for r in rs]
    assert back[0].hits[0].pixel_id == "123" and back[0].pages[0].forms == 1
    assert json.load(open(p))["disclaimer"].startswith("Potential issue, not a legal finding")


def test_csv_output(tmp_path):
    p = tmp_path / "r.csv"
    ps.save_csv(sample_results(), str(p))
    rows = list(csv.DictReader(open(p)))
    assert rows[0]["rating"] in ("Medium", "High") and "Meta Pixel=123" in rows[0]["pixel_ids"]
    assert rows[1]["rating"] == "Not scanned"


def test_report_is_self_contained_and_escaped():
    out = ps.render_report(sample_results())
    assert "Potential issue, not a legal finding" in out
    for bad in ("http://", "https://cdn", "<link", "src=\"http", "src='http", "@import"):
        assert bad not in out.replace("href='https://x.com.au", "").replace("href='https://evil", "") or bad == "http://"
    assert "<script>.com" not in out and "evil&lt;script&gt;.com" in out
    assert "&lt;b&gt;boom&lt;/b&gt;" in out
    assert "onmouseover=\"x" not in out  # attribute injection neutralised
    assert out.count("<script") == 1      # only our inline JS


def test_report_has_no_external_resource_refs():
    import re
    out = ps.render_report(sample_results())
    assert not re.findall(r"(?:src|href)=['\"]https?://(?!x\.com\.au|evil)", out)
    assert "url(" not in out


def test_report_cli_rebuilds(tmp_path):
    j, o = tmp_path / "r.json", tmp_path / "o.html"
    ps.save_json(sample_results(), str(j))
    assert ps.main(["report", "--json", str(j), "--out", str(o)]) == 0
    assert "Pre-consent tracking scan" in o.read_text()


# ---- Meta advanced matching ---------------------------------------------------
def test_advanced_matching_fields_names_only():
    h = one("https://www.facebook.com/tr/?id=1&ev=Lead&ud%5Bem%5D=" + "a" * 64 + "&ud[ph]=" + "b" * 64 + "&udff[fn]=" + "c" * 64)
    assert h.adv_matching == ["em", "form:fn", "ph"]


def test_advanced_matching_in_post_body_and_none_by_default():
    h = one("https://www.facebook.com/tr/", post="id=1&ev=Lead&ud[em]=" + "a" * 64, method="POST")
    assert h.adv_matching == ["em"]
    assert one("https://www.facebook.com/tr/?id=1&ev=PageView").adv_matching == []
    assert one("https://www.google-analytics.com/g/collect?v=2&tid=G-1&ud[em]=x").adv_matching == []  # Meta only


def test_hashed_values_never_stored():
    h = one("https://www.facebook.com/tr/?id=1&ev=Lead&ud%5Bem%5D=" + "a" * 64 + "&udff%5Bph%5D=" + "b" * 64)
    assert "a" * 10 not in h.url and "b" * 10 not in h.url and "[redacted]" in h.url
    assert "id=1" in h.url


def test_advanced_matching_scored():
    hit = H("meta", adv_matching=["em", "ph"])
    base = ps.assess(site([H("meta")]))
    adv = ps.assess(site([hit]))
    assert adv["score"] == base["score"] + 10
    assert any("advanced matching" in r and "em, ph" in r for r in adv["reasons"])


# ---- consent verdicts ----------------------------------------------------------
def _pass(clicked=True, hits=(), method="x"):
    return {"clicked": clicked, "method": method, "hits": list(hits)}


def test_verdict_reject_ignored():
    v = ps.consent_verdict([], _pass(hits=[H("meta")]), _pass(hits=[H("meta")]))
    assert v["verdict"] == "reject_ignored" and v["modes"]["reject"]["adtech"] == ["Meta Pixel"]


def test_verdict_blocked_until_consent():
    v = ps.consent_verdict([], _pass(), _pass(hits=[H("meta"), H("hotjar")]))
    assert v["verdict"] == "blocked_until_consent"


def test_verdict_fires_before_choice_but_reject_works():
    v = ps.consent_verdict([H("meta")], _pass(), _pass(hits=[H("meta")]))
    assert v["verdict"] == "fires_before_choice" and any("Reject works" in n for n in v["notes"])


def test_verdict_no_controls_found():
    v = ps.consent_verdict([H("meta")], _pass(False), _pass(False))
    assert v["verdict"] == "no_consent_control_found" and "Meta Pixel" in v["notes"][0]


def test_verdict_clean_and_missing_reject_note():
    assert ps.consent_verdict([], _pass(), _pass())["verdict"] == "no_adtech_observed"
    v = ps.consent_verdict([], _pass(False), _pass(hits=[H("meta")]))
    assert v["verdict"] == "blocked_until_consent" and any("no Reject control" in n for n in v["notes"])


def test_ga4_alone_is_not_adtech_for_verdict():
    assert ps.consent_verdict([], _pass(hits=[H("ga4")]), _pass())["verdict"] == "no_adtech_observed"


def test_reject_ignored_raises_score_by_15():
    base = site([H("meta")])
    withct = site([H("meta")])
    withct.consent_test = ps.consent_verdict(withct.hits, _pass(hits=[H("meta")]), _pass(hits=[H("meta")]))
    assert ps.assess(withct)["score"] == ps.assess(base)["score"] + 15


@pytest.mark.parametrize("mode,text,ok", [
    ("accept", "Accept all", True), ("accept", "Accept All Cookies", True), ("accept", "I agree", True),
    ("accept", "Accept cookies & manage preferences", False), ("accept", "Reject all", False),
    ("reject", "Reject all", True), ("reject", "Decline", True), ("reject", "Necessary only", True),
    ("reject", "Only necessary cookies", True), ("reject", "Manage preferences", False),
    ("reject", "Accept all", False),
])
def test_consent_button_text_patterns(mode, text, ok):
    assert bool(ps.CONSENT_TEXT[mode].match(text)) is ok


def test_report_renders_consent_table_and_adv_matching(tmp_path):
    r = site([H("meta", adv_matching=["em"])])
    r.consent_test = ps.consent_verdict([], _pass(hits=[H("meta")], method="#onetrust-reject-all-handler"), _pass())
    r.assessment = ps.assess(r)
    out = ps.render_report([r])
    assert "Consent test" in out and "Reject clicked" in out and "adv. matching: em" in out
    p = tmp_path / "r.json"
    ps.save_json([r], str(p))
    assert ps.load_json(str(p))[0].consent_test["verdict"] == "reject_ignored"
    c = tmp_path / "r.csv"
    ps.save_csv([r], str(c))
    row = list(csv.DictReader(open(c)))[0]
    assert row["consent_test"] == "reject_ignored" and row["meta_advanced_matching"] == "em"


def test_verdict_notice_only_banner_note():
    v = ps.consent_verdict([H("meta")], _pass(False), _pass(False), ["Cookie notice (unrecognised platform)"])
    assert v["verdict"] == "no_consent_control_found" and any("notice-only" in n for n in v["notes"])
