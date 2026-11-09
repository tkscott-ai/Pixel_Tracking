import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "briefs"))
import pixel_scan as ps
import make_data as md
from test_logic import H, site


def test_opaque_google_ads_labels_are_dropped_but_real_events_kept():
    assert md.clean_events({"IUh0CKCXs7QcEOvx_dtD", "I567CKzI2_EBEOir2sAD", "PageView", "gtag.config", "page_view", ""}) == \
        {"PageView", "gtag.config", "page_view"}


def test_build_exports_evidence_but_no_rating_or_score(tmp_path):
    page = "https://x.com.au/ivf-treatment"
    r = site([H("meta", page=page, event="PageView", pixel_id="123", page_url_sent=False),
              H("google_ads", page=page, pixel_id="999", page_url_sent=True)],
             [ps.PageInfo(url="https://x.com.au/", role="home"), ps.PageInfo(url=page, role="sensitive", forms=1)], cmps=["Cookie notice (unrecognised platform)"])
    r.sector = "IVF / fertility"
    r.consent_test = ps.consent_verdict(r.hits, {"clicked": False, "method": "", "hits": []}, {"clicked": False, "method": "", "hits": []}, r.cmps)
    d = md.build(r, str(tmp_path))
    blob = json.dumps(d)
    assert "rating" not in blob.lower() and "score" not in blob.lower()
    assert d["n_health_pages"] == 1 and d["n_health_pages_with_adtech"] == 1
    assert d["health_pages"][0]["url_sent_to"] == ["Google Ads / DoubleClick"]
    assert [m["adtech"] for m in d["consent_modes"][1:]] == ["Not tested (no control to click)"] * 2   # no false "None observed"
    assert d["consent_verdict"] == "no_consent_control_found"
