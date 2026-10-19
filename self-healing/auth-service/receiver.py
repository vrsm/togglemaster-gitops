#!/usr/bin/env python3
import hmac
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
LOG = logging.getLogger("auth-self-healer")

TOKEN_FILE = os.getenv("WEBHOOK_TOKEN_FILE", "/var/run/webhook/token")
MAX_BODY = 1024 * 1024
EXPECTED_ALERT = "AuthServiceHighHTTP5xxRate"


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, message):
        body = json.dumps({"status": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.respond(200, "ok")
        return self.respond(404, "not found")

    def do_POST(self):
        if self.path != "/webhook":
            return self.respond(404, "not found")

        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as token_file:
                expected_token = token_file.read().strip()
        except OSError:
            LOG.error("Webhook token unavailable")
            return self.respond(503, "receiver not configured")

        supplied = self.headers.get("Authorization", "")
        if not supplied.startswith("Bearer ") or not hmac.compare_digest(
            supplied[7:], expected_token
        ):
            return self.respond(401, "unauthorized")

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > MAX_BODY:
                return self.respond(413, "invalid body size")
            payload = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return self.respond(400, "invalid JSON")

        alerts = payload.get("alerts")
        if not isinstance(alerts, list) or not alerts:
            return self.respond(400, "missing alerts")

        accepted = 0
        for alert in alerts:
            labels = alert.get("labels") or {}
            if (
                labels.get("alertname") != EXPECTED_ALERT
                or labels.get("service") != "auth-service"
                or labels.get("severity") != "critical"
                or alert.get("status") != "firing"
            ):
                continue

            accepted += 1
            # Fase inicial: nenhuma ação no cluster.
            # Não registrar payloads, tokens ou fingerprints.
            LOG.warning(
                "DRY_RUN: alerta válido recebido; nenhuma recuperação executada"
            )

        if accepted == 0:
            return self.respond(202, "no eligible firing alerts")

        return self.respond(200, "accepted; dry-run only")

    def log_message(self, fmt, *args):
        LOG.info("HTTP %s", fmt % args)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 9099), Handler)
    LOG.info("Webhook receiver listening; recovery mode is DRY_RUN")
    server.serve_forever()
