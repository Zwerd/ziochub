#!/usr/bin/env python3
"""
ThreatGate - HTTP to HTTPS Redirect Server
===========================================
Lightweight HTTP server that responds to every request with a 301 redirect
to the same URL over HTTPS on the configured port.

Runs as a systemd service alongside the main ThreatGate HTTPS service.

Environment variables:
    REDIRECT_HTTP_PORT  - port to listen on for HTTP  (default: 8080)
    REDIRECT_HTTPS_PORT - HTTPS port to redirect to   (default: 8443)
"""

import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler


HTTPS_PORT = int(os.environ.get('REDIRECT_HTTPS_PORT', '8443'))


class RedirectHandler(BaseHTTPRequestHandler):
    def _redirect(self):
        host = self.headers.get('Host', '')
        if ':' in host:
            host = host.split(':')[0]
        target = f"https://{host}:{HTTPS_PORT}{self.path}"
        self.send_response(301)
        self.send_header('Location', target)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        self._redirect()

    def do_POST(self):
        self._redirect()

    def do_HEAD(self):
        self._redirect()

    def do_PUT(self):
        self._redirect()

    def do_DELETE(self):
        self._redirect()

    def log_message(self, format, *args):
        print(f"[http-redirect] {self.client_address[0]} -> HTTPS: {args[0] if args else ''}")


def main():
    http_port = int(os.environ.get('REDIRECT_HTTP_PORT', '8080'))
    print(f"[http-redirect] Listening on port {http_port}, redirecting to HTTPS port {HTTPS_PORT}")
    server = HTTPServer(('0.0.0.0', http_port), RedirectHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[http-redirect] Shutting down.")
        server.server_close()


if __name__ == '__main__':
    main()
