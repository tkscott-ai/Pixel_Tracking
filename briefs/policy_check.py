#!/usr/bin/env python3
"""Read each organisation's published privacy information and record what it says about tracking.

Usage: python briefs/policy_check.py <results.json> <outdir>
Writes <outdir>/policy/<domain>.json. Keyword analysis only - NOT a legal review of the policy.
robots.txt is checked (fail-closed) before every page fetch.
"""
import asyncio
import json
import os
import re
import sys
import urllib.parse as up

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pixel_scan as ps  # noqa: E402
from playwright.async_api import async_playwright  # noqa: E402

VENDOR_RX = {
    "Meta Pixel": r"facebook|meta pixel|\bmeta\b|instagram",
    "Google Analytics (GA4)": r"google analytics|analytics\.google",
    "Google Ads / DoubleClick": r"google ads|adwords|doubleclick|google remarketing|remarketing|google advertis",
    "LinkedIn Insight Tag": r"linkedin",
    "Pinterest Tag": r"pinterest",
    "Hotjar": r"hotjar",
    "TikTok Pixel": r"tiktok",
    "Microsoft Clarity": r"clarity",
}
OBSERVED_TO_POLICY = {"meta": "Meta Pixel", "ga4": "Google Analytics (GA4)", "ga_audiences": "Google Analytics (GA4)",
                      "google_ads": "Google Ads / DoubleClick", "linkedin": "LinkedIn Insight Tag", "pinterest": "Pinterest Tag",
                      "hotjar": "Hotjar", "tiktok": "TikTok Pixel", "clarity": "Microsoft Clarity"}
TOPICS = {
    "cookies": r"\bcookies?\b",
    "pixels_or_tracking_technology": r"\bpixels?\b|web beacons?|tracking technolog|tracking tools?|tags?\b.{0,20}(track|analytic)",
    "advertising_or_retargeting": r"advertis|remarket|retarget|interest-based|personalised ads|targeted ads",
    "health_or_sensitive_information": r"sensitive information|health information|medical information",
    "choices_or_opt_out": r"opt[- ]?out|withdraw (your )?consent|cookie (settings|preferences)|manage (your )?cookies|ad settings|your choices|disable cookies",
}
LINK_RX = re.compile(r"cookie|tracking|digital|online[- ]privacy|website[- ]privacy", re.I)
SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


def sentences(text):
    return [s.strip() for s in SENT_SPLIT.split(text) if 25 < len(s.strip()) < 400]


def analyse(text):
    t = text.lower()
    sents0 = sentences(text)
    TRACK = re.compile(r"pixel|\btags?\b|cookie|track|analytic|advertis|remarket|retarget|audience|conversion|insight|measure|ads\b", re.I)
    # a vendor counts as "named" only where it appears in a sentence about tracking/advertising/analytics
    named = {v: any(re.search(rx, s0, re.I) and TRACK.search(s0) for s0 in sents0) for v, rx in VENDOR_RX.items()}
    mentioned_anywhere = {v: bool(re.search(rx, t)) for v, rx in VENDOR_RX.items()}
    topics = {k: bool(re.search(rx, t)) for k, rx in TOPICS.items()}
    ev = {}
    sents = sentences(text)
    for k, rx in TOPICS.items():
        hits = [s for s in sents if re.search(rx, s, re.I)]
        ev[k] = [h[:240] for h in hits[:2]]
    for v, rx in VENDOR_RX.items():
        if named[v]:
            hits = [s for s in sents if re.search(rx, s, re.I) and TRACK.search(s)]
            ev["vendor:" + v] = [h[:240] for h in hits[:1]]
    m = re.search(r"(?:last\s+)?(?:updated|reviewed|effective|revised)[^\d]{0,25}(\d{1,2}\s+\w+\s+\d{4}|\w+\s+\d{4}|\d{1,2}/\d{1,2}/\d{2,4})", text, re.I)
    return {"named": named, "mentioned_anywhere": mentioned_anywhere, "topics": topics, "evidence": ev, "words": len(text.split()), "last_updated": m.group(1) if m else ""}


async def run(results_path, outdir):
    results = [r for r in ps.load_json(results_path) if r.status == "ok"]
    os.makedirs(os.path.join(outdir, "policy"), exist_ok=True)
    async with async_playwright() as pw:
        b = await pw.chromium.launch()
        ctx = await b.new_context(user_agent=ps.USER_AGENT, locale="en-AU", timezone_id="Australia/Sydney")

        async def fetch(origin):
            resp = await ctx.request.get(origin + "/robots.txt", timeout=20000)
            return resp.status, (await resp.text()) if resp.ok else ""
        robots = ps.Robots(fetch=fetch)
        for r in results:
            out = {"domain": r.domain, "docs": [], "skipped": [], "error": ""}
            if not r.privacy_url:
                out["error"] = "no privacy policy link was found by the scan"
            else:
                page = await ctx.new_page()
                texts, queue, seen = [], [r.privacy_url], set()
                try:
                    while queue and len(out["docs"]) < 3:
                        u = queue.pop(0)
                        if u in seen:
                            continue
                        seen.add(u)
                        if not await robots.allowed(u):
                            out["skipped"].append({"url": u, "why": robots.why_not(u)})
                            continue
                        try:
                            await page.goto(u, wait_until="domcontentloaded", timeout=45000)
                            try:
                                await page.wait_for_load_state("networkidle", timeout=8000)
                            except Exception:
                                pass
                            await asyncio.sleep(1.5)
                            txt = await page.inner_text("body")
                            texts.append(txt[:400000])
                            out["docs"].append({"url": page.url, "words": len(txt.split())})
                            if len(out["docs"]) == 1:   # one hop to a linked cookie/tracking page on the same site
                                base = up.urlsplit(page.url).netloc.lower().removeprefix("www.")
                                links = await page.eval_on_selector_all("a[href]", "els=>els.map(e=>[e.href,(e.innerText||'').trim().slice(0,80)])")
                                for href, label in links:
                                    h = up.urlsplit(href)
                                    if h.scheme in ("http", "https") and h.netloc.lower().removeprefix("www.") == base and (LINK_RX.search(h.path) or LINK_RX.search(label)) \
                                            and not re.search(r"\.(pdf|docx?)$", h.path, re.I) and href.split("#")[0] not in seen:
                                        queue.append(href.split("#")[0])
                                        if len(queue) >= 2:
                                            break
                        except Exception as e:  # noqa: BLE001
                            out["skipped"].append({"url": u, "why": f"{type(e).__name__}: {str(e).splitlines()[0][:80]}"})
                finally:
                    await page.close()
                if texts:
                    out.update(analyse("\n".join(texts)))
                else:
                    out["error"] = "could not read the privacy policy page"
            with open(os.path.join(outdir, "policy", r.domain.replace(".", "_") + ".json"), "w", encoding="utf-8") as f:
                json.dump(out, f, indent=1, ensure_ascii=False)
            print(f"{r.domain}: docs={len(out['docs'])} words={out.get('words', 0)} named={[k for k, v in out.get('named', {}).items() if v]} err={out['error']}")
        await b.close()


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1], sys.argv[2]))
