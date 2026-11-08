import asyncio, csv, json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pixel_scan as ps
from harness import serve, vendor_stub_hook

srv, base = serve()
targets = [{"domain": "127.0.0.1", "url": base + "/", "sector": "IVF / fertility", "city": "Test"}]
res = asyncio.run(ps.scan_all(targets, concurrency=1, settle=1.0, delay=0.2, context_hook=vendor_stub_hook))
r = res[0]
print("status", r.status, r.error)
print("pages:", [(p.role, p.url.replace(base, ""), p.status, p.forms, p.error) for p in r.pages])
print("cmps:", r.cmps, "privacy:", r.privacy_url.replace(base, ""), r.privacy_mentions)
for h in r.hits:
    print(f"  {h.vendor:24} {h.kind:6} id={h.pixel_id:18} ev={h.event:12} gcs={h.gcs:5} urlsent={h.page_url_sent!s:5} x{h.count} {h.page.replace(base,'')}")
print(json.dumps(r.assessment, indent=1))
