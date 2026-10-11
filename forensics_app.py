#!/usr/bin/env python3
"""ForensiQ — dependency-free digital forensics investigation prototype.

Run with: python3 forensics_app.py
Then visit: http://127.0.0.1:8088

The sample data is fictional and is intentionally designed for demonstrations.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import re
from copy import deepcopy
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "forensics_web"
HOST, PORT = "127.0.0.1", 8088


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def demo_state() -> dict[str, Any]:
    return {
        "workspace": {"name": "ForensiQ Lab", "analyst": "A. Sharma", "mode": "Training workspace"},
        "active_case_id": "CASE-2026-042",
        "cases": [
            {
                "id": "CASE-2026-042",
                "title": "Operation Glasswire",
                "type": "Credential theft & data staging",
                "status": "Investigation",
                "priority": "Critical",
                "opened": "2026-10-10T08:42:00Z",
                "lead": "A. Sharma",
                "evidence_count": 27,
                "integrity": 100,
                "summary": "Suspicious access to a finance share followed by encrypted archive creation and staged outbound transfer.",
            },
            {
                "id": "CASE-2026-039",
                "title": "Northstar mobile extraction",
                "type": "Mobile device examination",
                "status": "Review",
                "priority": "High",
                "opened": "2026-10-09T12:16:00Z",
                "lead": "R. Mehta",
                "evidence_count": 14,
                "integrity": 100,
                "summary": "Preserved Android image awaiting application artifact review.",
            },
            {
                "id": "CASE-2026-037",
                "title": "Orchid invoice fraud",
                "type": "Email investigation",
                "status": "Contained",
                "priority": "Medium",
                "opened": "2026-10-08T06:33:00Z",
                "lead": "S. Iyer",
                "evidence_count": 19,
                "integrity": 100,
                "summary": "Mailbox evidence and sender infrastructure correlated.",
            },
        ],
        "evidence": [
            {
                "id": "EV-042-001",
                "name": "FIN-WS-17.dd",
                "kind": "Disk image",
                "source": "Finance workstation",
                "size": "476.8 GB",
                "hash": "a5c8…9f13",
                "algorithm": "SHA-256",
                "status": "Verified",
                "collected": "10 Oct · 08:51",
                "custodian": "A. Sharma",
                "tags": ["Endpoint", "Primary"],
                "note": "Bit-for-bit image acquired with write blocker; hash verified at acquisition and ingest.",
            },
            {
                "id": "EV-042-002",
                "name": "auth-events.jsonl",
                "kind": "Log export",
                "source": "Identity provider",
                "size": "82.4 MB",
                "hash": "1b77…0ad4",
                "algorithm": "SHA-256",
                "status": "Verified",
                "collected": "10 Oct · 09:03",
                "custodian": "A. Sharma",
                "tags": ["Identity", "Timeline"],
                "note": "Export contains 30-day sign-in, token, and administrative activity window.",
            },
            {
                "id": "EV-042-003",
                "name": "outbound-traffic.pcapng",
                "kind": "Network capture",
                "source": "Core firewall",
                "size": "2.1 GB",
                "hash": "b3f0…e122",
                "algorithm": "SHA-256",
                "status": "Verified",
                "collected": "10 Oct · 09:19",
                "custodian": "N. Rao",
                "tags": ["Network", "Exfiltration"],
                "note": "Filtered capture around 198.51.100.42 and the suspected staging window.",
            },
            {
                "id": "EV-042-004",
                "name": "mailbox-export.pst",
                "kind": "Mailbox archive",
                "source": "c.fern@northstar.test",
                "size": "4.7 GB",
                "hash": "c901…54ee",
                "algorithm": "SHA-256",
                "status": "Verified",
                "collected": "10 Oct · 09:37",
                "custodian": "N. Rao",
                "tags": ["Email", "Credential theft"],
                "note": "Custodian-approved archive retained in evidence vault with legal-hold flag.",
            },
            {
                "id": "EV-042-005",
                "name": "memory-FIN-WS-17.raw",
                "kind": "Memory image",
                "source": "Finance workstation",
                "size": "16.0 GB",
                "hash": "8e17…234a",
                "algorithm": "SHA-256",
                "status": "Queued",
                "collected": "10 Oct · 10:11",
                "custodian": "A. Sharma",
                "tags": ["Endpoint", "Volatile"],
                "note": "Capture complete; awaiting malware and credential artifact extraction.",
            },
        ],
        "timeline": [
            {
                "time": "08:42",
                "title": "Impossible sign-in identified",
                "detail": "c.fern authenticated from an unfamiliar ASN shortly after a local session.",
                "kind": "alert",
            },
            {
                "time": "08:47",
                "title": "Archive staged on FIN-WS-17",
                "detail": "finance_q3.zip created under a temporary profile path.",
                "kind": "artifact",
            },
            {
                "time": "08:51",
                "title": "Disk image acquired",
                "detail": "EV-042-001 secured; SHA-256 acquisition hash recorded.",
                "kind": "evidence",
            },
            {
                "time": "09:12",
                "title": "Outbound TLS session correlated",
                "detail": "18.4 GB transfer candidate linked to 198.51.100.42.",
                "kind": "network",
            },
            {
                "time": "10:11",
                "title": "Volatile memory preserved",
                "detail": "Memory acquisition moved to analysis queue.",
                "kind": "evidence",
            },
        ],
        "custody": [
            {"time": "10 Oct · 08:51", "action": "Acquired", "actor": "A. Sharma", "ref": "EV-042-001", "seal": "Q7M-82A"},
            {"time": "10 Oct · 09:03", "action": "Imported", "actor": "A. Sharma", "ref": "EV-042-002", "seal": "D3P-19C"},
            {"time": "10 Oct · 09:19", "action": "Transferred", "actor": "N. Rao", "ref": "EV-042-003", "seal": "V4K-70B"},
            {"time": "10 Oct · 10:11", "action": "Verified", "actor": "ForensiQ Vault", "ref": "EV-042-005", "seal": "H1F-09R"},
        ],
        "findings": [
            {"label": "Risk signal", "value": "92", "detail": "High-confidence compromise pattern", "tone": "danger"},
            {"label": "Evidence integrity", "value": "100%", "detail": "27 of 27 artifacts hashed", "tone": "good"},
            {"label": "Staged transfer", "value": "18.4 GB", "detail": "Potential outbound data volume", "tone": "warning"},
            {"label": "Entities linked", "value": "14", "detail": "Users, hosts, accounts & IPs", "tone": "info"},
        ],
        "tasks": [
            {"id": "TASK-01", "title": "Review browser credential artifacts", "owner": "A. Sharma", "due": "Today · 14:00", "state": "In progress"},
            {"id": "TASK-02", "title": "Validate egress destination", "owner": "N. Rao", "due": "Today · 15:30", "state": "Queued"},
            {"id": "TASK-03", "title": "Prepare preservation notice", "owner": "Legal liaison", "due": "Tomorrow", "state": "Queued"},
        ],
        "notifications": 3,
        "last_scan": "10:24 UTC",
        "scan_message": "Correlation engine has identified 3 high-value review paths.",
    }


STATE = demo_state()


def active_case(state: dict[str, Any]) -> dict[str, Any]:
    return next(case for case in state["cases"] if case["id"] == state["active_case_id"])


def dashboard_payload() -> dict[str, Any]:
    case = active_case(STATE)
    evidence = STATE["evidence"]
    return {
        "workspace": STATE["workspace"],
        "case": case,
        "cases": STATE["cases"],
        "metrics": {
            "risk_score": 92,
            "integrity": 100,
            "evidence_total": case["evidence_count"],
            "hash_verified": sum(item["status"] == "Verified" for item in evidence),
            "linked_entities": 14,
            "open_tasks": sum(task["state"] != "Done" for task in STATE["tasks"]),
        },
        "findings": STATE["findings"],
        "evidence": evidence,
        "timeline": STATE["timeline"],
        "custody": STATE["custody"],
        "tasks": STATE["tasks"],
        "notifications": STATE["notifications"],
        "last_scan": STATE["last_scan"],
        "scan_message": STATE["scan_message"],
        "generated_at": now_iso(),
    }


class ForensicsHandler(SimpleHTTPRequestHandler):
    server_version = "ForensiQPrototype/1.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self.send_json({"ok": True, "service": "forensiq-prototype", "time": now_iso()})
        elif parsed.path == "/api/dashboard":
            self.send_json(dashboard_payload())
        elif parsed.path == "/api/report":
            self.send_report()
        else:
            self.serve_web_asset(parsed.path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        body = self.read_body()
        if body is None:
            return

        if parsed.path == "/api/cases/active":
            case_id = str(body.get("case_id", ""))
            if not any(case["id"] == case_id for case in STATE["cases"]):
                self.send_json({"error": "Unknown case"}, HTTPStatus.NOT_FOUND)
                return
            STATE["active_case_id"] = case_id
            self.send_json(dashboard_payload())
            return

        if parsed.path == "/api/evidence/acquire":
            self.acquire_evidence(body)
            return

        if parsed.path == "/api/analysis/run":
            self.run_analysis()
            return

        task_match = re.fullmatch(r"/api/tasks/([A-Za-z0-9-]+)/complete", parsed.path)
        if task_match:
            task = next((item for item in STATE["tasks"] if item["id"] == task_match.group(1)), None)
            if task is None:
                self.send_json({"error": "Unknown task"}, HTTPStatus.NOT_FOUND)
                return
            task["state"] = "Done"
            STATE["timeline"].insert(0, {"time": datetime.now().strftime("%H:%M"), "title": "Investigation task completed", "detail": task["title"], "kind": "evidence"})
            self.send_json(dashboard_payload())
            return

        self.send_json({"error": "Unknown endpoint"}, HTTPStatus.NOT_FOUND)

    def read_body(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1_000_000:
                self.send_json({"error": "Request body is too large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return None
            raw = self.rfile.read(length)
            return json.loads(raw or b"{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Invalid JSON payload"}, HTTPStatus.BAD_REQUEST)
            return None

    def acquire_evidence(self, body: dict[str, Any]) -> None:
        name = str(body.get("name", "")).strip()
        kind = str(body.get("kind", "Unknown artifact")).strip()
        source = str(body.get("source", "Manual collection")).strip()
        if not name:
            self.send_json({"error": "Evidence name is required"}, HTTPStatus.BAD_REQUEST)
            return
        fingerprint = hashlib.sha256(f"{name}:{source}:{now_iso()}".encode()).hexdigest()
        evidence_id = f"EV-042-{len(STATE['evidence']) + 1:03d}"
        item = {
            "id": evidence_id,
            "name": name,
            "kind": kind,
            "source": source,
            "size": "Pending",
            "hash": f"{fingerprint[:4]}…{fingerprint[-4:]}",
            "algorithm": "SHA-256",
            "status": "Queued",
            "collected": datetime.now().strftime("%d %b · %H:%M"),
            "custodian": STATE["workspace"]["analyst"],
            "tags": ["New acquisition"],
            "note": "Artifact registered through prototype acquisition flow; verify the source image before analytical use.",
        }
        STATE["evidence"].insert(0, item)
        active_case(STATE)["evidence_count"] += 1
        STATE["custody"].insert(0, {"time": item["collected"], "action": "Registered", "actor": item["custodian"], "ref": evidence_id, "seal": fingerprint[:3].upper() + "-" + fingerprint[3:6].upper()})
        STATE["timeline"].insert(0, {"time": datetime.now().strftime("%H:%M"), "title": "Evidence registered", "detail": f"{name} added to secured acquisition queue.", "kind": "evidence"})
        self.send_json(dashboard_payload(), HTTPStatus.CREATED)

    def run_analysis(self) -> None:
        STATE["last_scan"] = datetime.now().strftime("%H:%M UTC")
        STATE["scan_message"] = "Fresh correlation found a likely link between the credential event, archive staging, and outbound TLS session."
        STATE["timeline"].insert(0, {"time": datetime.now().strftime("%H:%M"), "title": "Correlation pass completed", "detail": "New relationship path added to analyst review queue.", "kind": "alert"})
        STATE["notifications"] += 1
        self.send_json(dashboard_payload())

    def serve_web_asset(self, request_path: str) -> None:
        path = "/index.html" if request_path in {"", "/"} else request_path
        target = (WEB_ROOT / unquote(path).lstrip("/")).resolve()
        if WEB_ROOT not in target.parents and target != WEB_ROOT:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith("text/") else content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_report(self) -> None:
        data = dashboard_payload()
        case = data["case"]
        report = "\n".join([
            f"# ForensiQ Investigation Brief — {case['id']}",
            "",
            f"**Case:** {case['title']}",
            f"**Status:** {case['status']} · **Priority:** {case['priority']}",
            f"**Generated:** {data['generated_at']}",
            "",
            "## Scope",
            case["summary"],
            "",
            "## Evidence register",
            *[f"- `{item['id']}` — {item['name']} ({item['kind']}); {item['algorithm']} {item['hash']}; {item['status']}" for item in data["evidence"]],
            "",
            "## Current observation",
            data["scan_message"],
            "",
            "_Prototype data only. Validate all findings under your organisation's evidence-handling process._",
        ])
        encoded = report.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Disposition", "attachment; filename=forensiq-investigation-brief.md")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_json(self, data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the classroom prototype's console focused on its launch message.
        return


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), ForensicsHandler)
    print(f"ForensiQ prototype ready at http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nForensiQ stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
