"""Local test harness: serves tests/site over http.server and stubs vendor hosts
so the scan is hermetic (no real beacons are sent to Meta/Google/Hotjar)."""
import functools
import http.server
import os
import threading

SITE_DIR = os.path.join(os.path.dirname(__file__), "site")
GIF = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")

FBEVENTS = """(function(){var q=(window.fbq&&window.fbq.queue)||[],id=null;
function send(ev){var i=new Image();i.src='https://www.facebook.com/tr/?id='+id+'&ev='+ev+
'&dl='+encodeURIComponent(location.href)+ud+'&rl=&if=false&ts='+Date.now();}
var ud='';function h(a){a=[].slice.call(a);if(a[0]==='init'){id=a[1];if(a[2]){ud='';for(var k in a[2])ud+='&ud['+k+']='+a[2][k];}}else if(a[0]==='track')send(a[1]);}
q.forEach(h);window.fbq=function(){h(arguments)};})();"""

GTAG = """(function(){var dl=window.dataLayer||[];dl.forEach(function(a){a=[].slice.call(a);
if(a[0]==='config'){var i=new Image();i.src='https://www.google-analytics.com/g/collect?v=2&tid='+a[1]+
'&gcs=G100&gcd=13l3l3l3l1&en=page_view&dl='+encodeURIComponent(location.href)+'&dt='+encodeURIComponent(document.title);}});})();"""

HOTJAR = """(function(){var i=new Image();i.src='https://in.hotjar.com/api/v2/client/sites/6543210/visit-data?sv=6&url='+
encodeURIComponent(location.href);})();"""


class Handler(http.server.SimpleHTTPRequestHandler):
    """http.server with extensionless URLs (/ivf-treatment -> ivf-treatment.html)."""
    def translate_path(self, path):
        p = super().translate_path(path)
        if not os.path.exists(p) and os.path.exists(p + ".html"):
            return p + ".html"
        return p

    robots = None  # set per server in serve()

    def do_GET(self):
        if self.path == "/robots.txt" and self.robots is not None:
            body = self.robots.encode()
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self):  # the test form posts here; never really used
        self.send_response(204); self.end_headers()

    def log_message(self, *a):
        pass


def serve(robots=None):
    handler = type("H", (Handler,), {"robots": robots})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(handler, directory=SITE_DIR))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


async def vendor_stub_hook(ctx):
    async def handler(route):
        url = route.request.url
        host = url.split("/")[2]
        if host.startswith("127.0.0.1"):
            return await route.continue_()
        if "connect.facebook.net" in host:
            return await route.fulfill(status=200, content_type="application/javascript", body=FBEVENTS)
        if "googletagmanager.com" in host:
            return await route.fulfill(status=200, content_type="application/javascript", body=GTAG)
        if "static.hotjar.com" in host:
            return await route.fulfill(status=200, content_type="application/javascript", body=HOTJAR)
        # beacons + anything else: answer locally, never touch the network
        return await route.fulfill(status=200, content_type="image/gif", body=GIF)
    await ctx.route("**/*", handler)
