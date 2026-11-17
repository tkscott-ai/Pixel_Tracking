#!/usr/bin/env python3
"""Build external-wording data for the top-10 briefs: scan evidence + privacy-policy findings.
Usage: python briefs/make_top10.py <results.json> <policy_dir_parent> <outdir>"""
import json, os, sys, urllib.parse as up
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..")); sys.path.insert(0, HERE)
import pixel_scan as ps, make_data as md

OBS2POL = {"Meta Pixel": ["Meta Pixel"], "Google Ads / DoubleClick": ["Google Ads / DoubleClick"],
           "Google Analytics (GA4)": ["Google Analytics (GA4)", "Google Ads / DoubleClick"],
           "Google Analytics audiences (advertising features)": ["Google Analytics (GA4)", "Google Ads / DoubleClick"],
           "LinkedIn Insight Tag": ["LinkedIn Insight Tag"], "Pinterest Tag": ["Pinterest Tag"], "Hotjar": ["Hotjar"],
           "TikTok Pixel": ["TikTok Pixel"], "Microsoft Clarity": ["Microsoft Clarity"]}
TOPIC_LABEL = {"cookies": "Cookies", "pixels_or_tracking_technology": "Pixels or tracking technology",
               "advertising_or_retargeting": "Advertising or retargeting", "health_or_sensitive_information": "Health or sensitive information",
               "choices_or_opt_out": "How to opt out or change choices"}

def main():
    src, polroot, out = sys.argv[1:4]
    os.makedirs(os.path.join(out, "data"), exist_ok=True)
    priv = ["# PRIVATE - verbatim policy sentences behind each deck (do NOT send). Verify against the live policy.", ""]
    for r in ps.load_json(src):
        if r.status != "ok": print("skip", r.domain); continue
        d = md.build(r, out); d["external"] = True; d["insurer"] = False
        pf = os.path.join(polroot, "policy", r.domain.replace(".", "_") + ".json")
        p = json.load(open(pf)) if os.path.exists(pf) else {"error": "not read", "docs": []}
        named = {k for k, v in p.get("named", {}).items() if v}
        obs = [v["vendor"] for v in d["vendors"] if v["vendor"] in OBS2POL]
        rows = [{"vendor": v, "named": any(x in named for x in OBS2POL[v])} for v in obs]
        d["policy"] = {"read": bool(p.get("docs")), "error": p.get("error", ""), "docs": [x["url"] for x in p.get("docs", [])],
                       "words": p.get("words", 0), "last_updated": p.get("last_updated", ""),
                       "topics": [{"label": TOPIC_LABEL[k], "yes": bool(v)} for k, v in p.get("topics", {}).items()],
                       "vendors": rows, "unnamed": [x["vendor"] for x in rows if not x["named"]]}
        json.dump(d, open(os.path.join(out, "data", r.domain.replace(".", "_") + ".json"), "w"), indent=1)
        priv += [f"## {r.domain}", f"Documents read: {', '.join(d['policy']['docs']) or 'none'}", f"Observed but not named: {d['policy']['unnamed'] or 'none'}"]
        for k, v in p.get("evidence", {}).items():
            for s in v[:2]: priv.append(f"- [{k}] {s}")
        priv.append("")
        print(r.domain, "policy read:", d["policy"]["read"], "| unnamed:", d["policy"]["unnamed"])
    open(os.path.join(out, "00_PRIVATE_policy_evidence.md"), "w").write("\n".join(priv))
main()
