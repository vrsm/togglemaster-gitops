#!/usr/bin/env python3
import datetime
import hashlib
import hmac
import json
import logging
import os
import ssl
import threading
import urllib.error
import urllib.request

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
LOG = logging.getLogger("auth-self-healer")

TOKEN_FILE = os.getenv(
    "WEBHOOK_TOKEN_FILE",
    "/var/run/webhook/token",
)
MAX_BODY = 1024 * 1024

EXPECTED_ALERT = "AuthServiceHighHTTP5xxRate"
EXPECTED_SERVICE = "auth-service"
EXPECTED_SEVERITY = "critical"

MODE = os.getenv("SELF_HEALER_MODE", "DRY_RUN").upper()
COOLDOWN_SECONDS = int(os.getenv("SELF_HEALER_COOLDOWN_SECONDS", "600"))

TARGET_NAMESPACE = "togglemaster"
TARGET_DEPLOYMENT = "auth-service"

SA_TOKEN_FILE = (
    "/var/run/secrets/kubernetes.io/serviceaccount/token"
)
SA_CA_FILE = (
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

API_HOST = os.getenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
API_PORT = os.getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")

API_BASE = (
    f"https://{API_HOST}:{API_PORT}"
    f"/apis/apps/v1/namespaces/{TARGET_NAMESPACE}"
    f"/deployments/{TARGET_DEPLOYMENT}"
)

ACTION_LOCK = threading.Lock()


def utc_now():
    return datetime.datetime.now(
        datetime.timezone.utc
    ).replace(microsecond=0)


def iso_timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def alert_fingerprint(labels):
    relevant = {
        "alertname": labels.get("alertname", ""),
        "service": labels.get("service", ""),
        "severity": labels.get("severity", ""),
        "instance": labels.get("instance", ""),
    }
    raw = json.dumps(
        relevant,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def read_service_account_credentials():
    with open(SA_TOKEN_FILE, "r", encoding="utf-8") as token_file:
        token = token_file.read().strip()

    if not token:
        raise RuntimeError("Kubernetes ServiceAccount token is empty")

    context = ssl.create_default_context(cafile=SA_CA_FILE)
    return token, context


def kubernetes_request(method, payload=None):
    token, tls_context = read_service_account_credentials()

    body = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/merge-patch+json"

    request = urllib.request.Request(
        API_BASE,
        data=body,
        headers=headers,
        method=method,
    )

    with urllib.request.urlopen(
        request,
        context=tls_context,
        timeout=5,
    ) as response:
        response_body = response.read()

    if not response_body:
        return {}

    return json.loads(response_body)


def restart_auth_service(fingerprint):
    with ACTION_LOCK:
        deployment = kubernetes_request("GET")

        metadata = deployment.get("metadata", {})
        annotations = metadata.get("annotations") or {}

        previous_restart = annotations.get(
            "self-healer.togglemaster.io/last-restart-at"
        )

        now = utc_now()

        if previous_restart:
            try:
                previous = datetime.datetime.fromisoformat(
                    previous_restart.replace("Z", "+00:00")
                )
                elapsed = (now - previous).total_seconds()

                if elapsed < COOLDOWN_SECONDS:
                    LOG.warning(
                        "Restart skipped: cooldown active "
                        "(remaining_seconds=%d)",
                        int(COOLDOWN_SECONDS - elapsed),
                    )
                    return "cooldown"
            except ValueError:
                LOG.warning(
                    "Previous restart timestamp invalid; "
                    "continuing with controlled evaluation"
                )

        resource_version = metadata.get("resourceVersion")
        if not resource_version:
            raise RuntimeError(
                "Deployment response has no resourceVersion"
            )

        restarted_at = iso_timestamp(now)

        patch = {
            "metadata": {
                "resourceVersion": resource_version,
                "annotations": {
                    "self-healer.togglemaster.io/last-restart-at":
                        restarted_at,
                    "self-healer.togglemaster.io/last-alert-key":
                        fingerprint,
                },
            },
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt":
                                restarted_at,
                        }
                    }
                }
            },
        }

        kubernetes_request("PATCH", patch)

        LOG.warning(
            "ROLLout restart requested for deployment=%s namespace=%s",
            TARGET_DEPLOYMENT,
            TARGET_NAMESPACE,
        )

        return "restarted"


def eligible_alert(alert):
    if not isinstance(alert, dict):
        return False

    labels = alert.get("labels")
    if not isinstance(labels, dict):
        return False

    return (
        labels.get("alertname") == EXPECTED_ALERT
        and labels.get("service") == EXPECTED_SERVICE
        and labels.get("severity") == EXPECTED_SEVERITY
        and alert.get("status") == "firing"
    )


class Handler(BaseHTTPRequestHandler):

    def respond(self, status, message):
        body = json.dumps(
            {"status": message}
        ).encode("utf-8")

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
            with open(
                TOKEN_FILE,
                "r",
                encoding="utf-8",
            ) as token_file:
                expected_token = token_file.read().strip()
        except OSError:
            LOG.error("Webhook token unavailable")
            return self.respond(503, "receiver not configured")

        if not expected_token:
            LOG.error("Webhook token is empty")
            return self.respond(503, "receiver not configured")

        supplied = self.headers.get("Authorization", "")

        if (
            not supplied.startswith("Bearer ")
            or not hmac.compare_digest(
                supplied[7:],
                expected_token,
            )
        ):
            return self.respond(401, "unauthorized")

        try:
            length = int(self.headers.get("Content-Length", "0"))

            if length < 1 or length > MAX_BODY:
                return self.respond(413, "invalid body size")

            raw_body = self.rfile.read(length)
            payload = json.loads(raw_body)

        except (ValueError, json.JSONDecodeError):
            return self.respond(400, "invalid JSON")

        if not isinstance(payload, dict):
            return self.respond(400, "invalid payload")

        alerts = payload.get("alerts")

        if not isinstance(alerts, list) or not alerts:
            return self.respond(400, "missing alerts")

        accepted = 0
        restarted = 0
        skipped = 0

        for alert in alerts:
            if not eligible_alert(alert):
                continue

            accepted += 1
            labels = alert["labels"]
            fingerprint = alert_fingerprint(labels)

            if MODE != "ACTIVE":
                LOG.warning(
                    "DRY_RUN: valid alert received; "
                    "no Kubernetes action executed"
                )
                continue

            try:
                result = restart_auth_service(fingerprint)

                if result == "restarted":
                    restarted += 1
                else:
                    skipped += 1

            except (
                OSError,
                RuntimeError,
                ValueError,
                urllib.error.URLError,
            ):
                LOG.exception(
                    "Self-Healer action failed; "
                    "deployment=%s namespace=%s",
                    TARGET_DEPLOYMENT,
                    TARGET_NAMESPACE,
                )
                return self.respond(502, "recovery action failed")

        if accepted == 0:
            return self.respond(202, "no eligible firing alerts")

        if MODE != "ACTIVE":
            return self.respond(200, "accepted; dry-run only")

        return self.respond(
            200,
            f"accepted={accepted}; restarted={restarted}; skipped={skipped}",
        )

    def log_message(self, fmt, *args):
        LOG.info("HTTP %s", fmt % args)


if __name__ == "__main__":
    if MODE not in ("DRY_RUN", "ACTIVE"):
        raise SystemExit(
            "Invalid SELF_HEALER_MODE: use DRY_RUN or ACTIVE"
        )

    if COOLDOWN_SECONDS < 60:
        raise SystemExit(
            "Cooldown must be at least 60 seconds"
        )

    server = ThreadingHTTPServer(
        ("0.0.0.0", 9099),
        Handler,
    )

    LOG.info(
        "Webhook receiver listening; mode=%s; target=%s/%s",
        MODE,
        TARGET_NAMESPACE,
        TARGET_DEPLOYMENT,
    )

    server.serve_forever()
