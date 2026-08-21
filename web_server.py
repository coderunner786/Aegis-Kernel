import http.server
import json
import os
import queue
import subprocess
import sys
import threading
import urllib.parse

# Thread-safe queue for UI streaming
telemetry_queue = queue.Queue(maxsize=150)


def get_asset_path(filename: str):
    """
    Locates static assets (HTML/JS) whether running as raw Python
    or inside a compiled PyInstaller onefile binary.
    """
    if hasattr(sys, "_MEIPASS"):
        bundle_path = os.path.join(sys._MEIPASS, filename)
        if os.path.exists(bundle_path):
            return bundle_path

    local_path = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(local_path):
        return local_path

    return filename


class AegisWebHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. Serve Dashboard HTML
        if path in ("/", "/dashboard.html"):
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()

            html_path = get_asset_path("dashboard.html")
            if os.path.exists(html_path):
                with open(html_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>Error: dashboard.html not found.</h1>")

        # 2. Serve Local vis-network.min.js (Offline Graph Engine)
        elif path == "/vis-network.min.js":
            self.send_response(200)
            self.send_header("Content-type", "application/javascript")
            self.end_headers()

            js_path = get_asset_path("vis-network.min.js")
            if os.path.exists(js_path):
                with open(js_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"// vis-network.min.js not found")

        # 3. Server-Sent Events (SSE) Live Feed
        elif path == "/events":
            self.send_response(200)
            self.send_header("Content-type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            while True:
                try:
                    event_data = telemetry_queue.get(timeout=20)
                    msg = f"data: {json.dumps(event_data)}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # Keepalive ping
                    try:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
                except Exception:
                    break

        # 4. 1-Click Terminate Process Endpoint
        elif path == "/kill":
            query = urllib.parse.parse_qs(parsed.query)
            pid = query.get("pid", [None])[0]
            success = False
            if pid:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True,
                        creationflags=0x08000000,  # CREATE_NO_WINDOW
                    )
                    success = True
                except Exception:
                    pass

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": success, "pid": pid}).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence routine HTTP request console logs
        pass


def broadcast_telemetry(pid: int, parent_pid: int, app: str, score: float, cmd: str):
    """Call this from your main detection loop to stream events to the dashboard."""
    payload = {
        "pid": pid,
        "parent_pid": parent_pid,
        "app": app,
        "score": float(score),
        "cmd": cmd,
    }
    try:
        telemetry_queue.put_nowait(payload)
    except queue.Full:
        pass


def start_dashboard_server(port=8000):
    """Starts the web server in a background daemon thread."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), AegisWebHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return port