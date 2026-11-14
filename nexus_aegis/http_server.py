"""Zero-dependency HTTP, Streamable MCP, REST API, and Developer Portal Server for NexusAegis."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from nexus_aegis.benchmark import build_benchmark_scenarios, run_benchmark_suite
from nexus_aegis.gates import GATE_METADATA
from nexus_aegis.kernel import NexusAegisKernel, render_pr_attestation_markdown
from nexus_aegis.mcp_server import (
    MCP_PROMPTS,
    MCP_PROTOCOL_VERSION,
    MCP_RESOURCE_TEMPLATES,
    MCP_RESOURCES,
    MCP_TOOLS_SCHEMA,
    NexusAegisMCPServer,
)
from nexus_aegis.merkle import verify_merkle_inclusion_proof
from nexus_aegis.models import AgentRunBundle, MerkleInclusionProof

DEFAULT_MAX_BODY_BYTES = 1_048_576
_MIN_BODY_BYTES = 256
_MAX_BODY_BYTES_LIMIT = 16_777_216
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_VERSION = "1.1.0"


def resolve_max_body_bytes(override: int | None = None) -> int:
    """Resolve max request body size from explicit override or `NEXUS_AEGIS_MAX_BODY_BYTES`."""
    if override is not None:
        if override <= 0:
            raise ValueError("max_body_bytes must be positive")
        return override
    raw = os.environ.get("NEXUS_AEGIS_MAX_BODY_BYTES", "").strip()
    if not raw:
        return DEFAULT_MAX_BODY_BYTES
    try:
        parsed = int(raw)
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES
    return max(_MIN_BODY_BYTES, min(_MAX_BODY_BYTES_LIMIT, parsed))


class PayloadTooLargeError(ValueError):
    """Raised when an incoming HTTP request exceeds the configured max body size."""


class BadRequestError(ValueError):
    """Raised when an incoming HTTP request has malformed headers or JSON payload."""


@dataclass(frozen=True)
class HTTPResponse:
    """Framework-agnostic HTTP response envelope."""

    status: int
    headers: dict[str, str]
    body: bytes


class MetricsCollector:
    """Thread-safe HTTP, MCP, attestation, and Merkle proof telemetry collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_at = time.monotonic()
        self._requests_total = 0
        self._errors_total = 0
        self._total_latency_ms = 0.0
        self._status_counts: dict[int, int] = {}
        self._method_counts: dict[str, int] = {}
        self._mcp_method_counts: dict[str, int] = {}
        self._attestations_total = 0
        self._attestations_passed = 0
        self._attestations_blocked = 0
        self._proofs_verified_total = 0
        self._proofs_valid = 0
        self._proofs_rejected = 0
        self._benchmarks_total = 0

    def record_http(self, method: str, status: int, elapsed_ms: float) -> None:
        with self._lock:
            self._requests_total += 1
            if status >= 500:
                self._errors_total += 1
            self._total_latency_ms += elapsed_ms
            self._status_counts[status] = self._status_counts.get(status, 0) + 1
            self._method_counts[method] = self._method_counts.get(method, 0) + 1

    def record_mcp(self, method: str) -> None:
        if not method:
            return
        with self._lock:
            self._mcp_method_counts[method] = self._mcp_method_counts.get(method, 0) + 1

    def record_attestation(self, passed: bool) -> None:
        with self._lock:
            self._attestations_total += 1
            if passed:
                self._attestations_passed += 1
            else:
                self._attestations_blocked += 1

    def record_proof_verification(self, verified: bool) -> None:
        with self._lock:
            self._proofs_verified_total += 1
            if verified:
                self._proofs_valid += 1
            else:
                self._proofs_rejected += 1

    def record_benchmark(self) -> None:
        with self._lock:
            self._benchmarks_total += 1

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            uptime = max(0.0, time.monotonic() - self._started_at)
            avg_ms = self._total_latency_ms / self._requests_total if self._requests_total else 0.0
            return {
                "service": "nexus-aegis",
                "version": _VERSION,
                "uptime_seconds": round(uptime, 3),
                "requests_total": self._requests_total,
                "errors_total": self._errors_total,
                "avg_latency_ms": round(avg_ms, 4),
                "status_counts": {str(k): v for k, v in sorted(self._status_counts.items())},
                "method_counts": dict(sorted(self._method_counts.items())),
                "mcp_method_counts": dict(sorted(self._mcp_method_counts.items())),
                "attestations": {
                    "total": self._attestations_total,
                    "passed": self._attestations_passed,
                    "blocked": self._attestations_blocked,
                },
                "proof_verifications": {
                    "total": self._proofs_verified_total,
                    "valid": self._proofs_valid,
                    "rejected": self._proofs_rejected,
                },
                "benchmarks_total": self._benchmarks_total,
            }

    def to_prometheus(self) -> str:
        snap = self.to_dict()
        lines = [
            "# HELP nexus_aegis_uptime_seconds Seconds since NexusAegis HTTP server started.",
            "# TYPE nexus_aegis_uptime_seconds gauge",
            f"nexus_aegis_uptime_seconds {snap['uptime_seconds']}",
            "# HELP nexus_aegis_http_requests_total Total HTTP requests processed.",
            "# TYPE nexus_aegis_http_requests_total counter",
            f"nexus_aegis_http_requests_total {snap['requests_total']}",
            "# HELP nexus_aegis_http_errors_total Total HTTP 5xx errors.",
            "# TYPE nexus_aegis_http_errors_total counter",
            f"nexus_aegis_http_errors_total {snap['errors_total']}",
            "# HELP nexus_aegis_attestations_total Total PCAE agent runs attested via REST.",
            "# TYPE nexus_aegis_attestations_total counter",
            f"nexus_aegis_attestations_total {snap['attestations']['total']}",
            "# HELP nexus_aegis_attestations_passed_total Total compliant attestations.",
            "# TYPE nexus_aegis_attestations_passed_total counter",
            f"nexus_aegis_attestations_passed_total {snap['attestations']['passed']}",
            "# HELP nexus_aegis_attestations_blocked_total Total blocked adversarial runs.",
            "# TYPE nexus_aegis_attestations_blocked_total counter",
            f"nexus_aegis_attestations_blocked_total {snap['attestations']['blocked']}",
            "# HELP nexus_aegis_proofs_verified_total Total RFC 6962 proofs inspected.",
            "# TYPE nexus_aegis_proofs_verified_total counter",
            f"nexus_aegis_proofs_verified_total {snap['proof_verifications']['total']}",
            "# HELP nexus_aegis_benchmarks_total Total 35-scenario benchmark runs.",
            "# TYPE nexus_aegis_benchmarks_total counter",
            f"nexus_aegis_benchmarks_total {snap['benchmarks_total']}",
        ]
        for status_code, count in snap["status_counts"].items():
            lines.append(
                f'nexus_aegis_http_responses_by_status{{status="{status_code}"}} {count}'
            )
        for mcp_method, count in snap["mcp_method_counts"].items():
            safe_method = mcp_method.replace('"', '\\"')
            lines.append(f'nexus_aegis_mcp_calls_total{{method="{safe_method}"}} {count}')
        return "\n".join(lines) + "\n"


ServerMetrics = MetricsCollector


def sanitize_request_id(raw_value: str | None) -> str:
    """Validate and sanitize an incoming X-Request-ID or generate a fresh hex UUID."""
    if raw_value is not None:
        stripped = raw_value.strip()
        if _REQUEST_ID_RE.fullmatch(stripped):
            return stripped
    return uuid.uuid4().hex


def _get_header(headers: Mapping[str, str], name: str, default: str = "") -> str:
    target = name.lower()
    for key, val in headers.items():
        if key.lower() == target:
            return val
    return default


def parse_content_length(headers: Mapping[str, str]) -> int | None:
    """Parse Content-Length header safely, rejecting negative or malformed values."""
    raw = _get_header(headers, "content-length", "")
    if not raw:
        return None
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise BadRequestError("Invalid Content-Length header.") from exc
    if value < 0:
        raise BadRequestError("Negative Content-Length header.")
    return value


def build_security_headers(
    path: str,
    request_id: str,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build hardened response headers including CORS, security controls, and X-Request-ID."""
    headers: dict[str, str] = {
        "X-Request-ID": request_id,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "X-Request-ID, Mcp-Session-Id",
    }
    if path.startswith("/api/") or path in (
        "/api",
        "/mcp",
        "/messages",
        "/health",
        "/healthz",
        "/readyz",
        "/info",
        "/metrics",
    ):
        headers["Cache-Control"] = "no-store"
    if extra:
        headers.update(extra)
    return headers


def _render_portal_html() -> str:
    """Return the dark-mode interactive NexusAegis PCAE & Merkle Attestation Portal."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NexusAegis — PCAE Kernel & RFC 6962 Attestation Portal</title>
  <style>
    :root {
      --bg: #070b12;
      --surface: #0f1724;
      --surface-2: #162033;
      --border: #25344d;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --emerald: #10b981;
      --rose: #f43f5e;
      --amber: #f59e0b;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      background: radial-gradient(circle at top right, #16243d, var(--bg) 55%);
      color: var(--text);
      line-height: 1.5;
    }
    header {
      border-bottom: 1px solid var(--border);
      background: rgba(15, 23, 36, 0.92);
      backdrop-filter: blur(8px);
      padding: 1rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .brand h1 { margin: 0; font-size: 1.25rem; letter-spacing: -0.02em; }
    .brand p { margin: 0.2rem 0 0; color: var(--muted); font-size: 0.85rem; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.3rem 0.75rem;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      font-size: 0.8rem;
      font-family: var(--mono);
    }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--emerald); }
    main { max-width: 1180px; margin: 0 auto; padding: 1.5rem; display: grid; gap: 1.25rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.25rem; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.15rem;
    }
    .card h2 { margin: 0 0 0.75rem; font-size: 1.02rem; }
    .controls { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem; }
    button {
      background: var(--accent);
      color: #06131f;
      border: none;
      border-radius: 8px;
      padding: 0.5rem 0.9rem;
      font-weight: 600;
      font-size: 0.85rem;
      cursor: pointer;
    }
    button.secondary {
      background: var(--surface-2);
      color: var(--text);
      border: 1px solid var(--border);
    }
    button:hover { filter: brightness(1.08); }
    textarea {
      width: 100%;
      min-height: 150px;
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem;
      font-family: var(--mono);
      font-size: 0.8rem;
      resize: vertical;
    }
    pre {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem;
      font-family: var(--mono);
      font-size: 0.78rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      margin: 0.5rem 0 0;
    }
    .gate-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.45rem 0.65rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.82rem;
    }
    .gate-row:last-child { border-bottom: none; }
    .badge-pass { color: var(--emerald); font-family: var(--mono); font-weight: 700; }
    .badge-fail { color: var(--rose); font-family: var(--mono); font-weight: 700; }
    .muted { color: var(--muted); font-size: 0.82rem; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>NexusAegis &mdash; 7-Gate PCAE Kernel &amp; RFC 6962 Attestation Portal</h1>
      <p>Proof-Carrying Agent Execution &bull; Domain-Separated SHA-256 Merkle Proofs &bull; Streamable HTTP MCP</p>
    </div>
    <div id="health-pill" class="pill"><span class="dot"></span><span>Checking kernel...</span></div>
  </header>
  <main>
    <div class="grid">
      <section class="card">
        <h2>1. Agent Run Attestation &amp; Selective Disclosure</h2>
        <div class="controls">
          <button type="button" onclick="loadPreset('clean')">Compliant PR Preset</button>
          <button type="button" class="secondary" onclick="loadPreset('hack')">Reward-Hack Preset (G5)</button>
          <button type="button" onclick="runAttest()">Run 7-Gate Attestation</button>
        </div>
        <textarea id="bundle-input" spellcheck="false"></textarea>
        <div class="controls" style="margin-top:0.6rem;">
          <button type="button" class="secondary" onclick="verifyDisclosed(false)">Verify G5 Proof</button>
          <button type="button" class="secondary" onclick="verifyDisclosed(true)">Test Tampered Proof</button>
        </div>
        <div id="attest-status" class="muted">Select a preset and click "Run 7-Gate Attestation".</div>
        <pre id="attest-output"></pre>
      </section>
      <section class="card">
        <h2>2. 7-Gate PCAE Pipeline &amp; 35-Scenario Benchmark</h2>
        <div class="controls">
          <button type="button" onclick="runBenchmark()">Run 35-Scenario Benchmark</button>
          <button type="button" class="secondary" onclick="loadMetrics()">Telemetry (/metrics)</button>
        </div>
        <div id="gate-list"></div>
        <pre id="bench-output">Click "Run 35-Scenario Benchmark" to execute live kernel evaluation.</pre>
      </section>
    </div>
    <section class="card">
      <h2>3. Streamable HTTP MCP &amp; Endpoints</h2>
      <p class="muted">POST /mcp (JSON-RPC 2.0) &bull; GET /mcp (SSE) &bull; GET /api/gates &bull; POST /api/attest &bull; POST /api/verify-proof &bull; GET /api/benchmark &bull; GET /metrics</p>
      <pre>nexus-aegis serve-http --host 0.0.0.0 --port 8000
curl -s http://127.0.0.1:8000/health | python3 -m json.tool</pre>
    </section>
  </main>
  <script>
    const PRESETS = {
      clean: {
        run_id: "portal-run-clean-01",
        agent_id: "patchpilot-worker",
        task_prompt: "Fix zero-division edge case in compute_rate()",
        retrieved_context: [{"source_id": "src_1", "content": "compute_rate must return 0.0 when denominator <= 0."}],
        temporal_facts: [{"fact_id": "f1", "statement": "compute_rate returns 0.0 for zero denominator."}],
        tool_trajectory: [{"tool": "run_pytest", "args": {"target": "tests/test_rate.py"}, "status": "ok"}],
        file_reads: ["src/rate.py"],
        file_writes: ["src/rate.py"],
        active_peer_leases: [{"holder": "other", "pattern": "docs/*", "mode": "exclusive_write"}],
        code_patch_before: "def test_rate():\n    assert compute_rate(10, 2) == 5.0\n",
        code_patch_after: "def test_rate():\n    assert compute_rate(10, 2) == 5.0\n    assert compute_rate(10, 0) == 0.0\n",
        final_response: "Fixed compute_rate zero handling [src_1].",
        tokens_used: 4200,
        cost_usd: 0.04,
        budget_cap_usd: 0.50,
        model_id: "claude-3-5-haiku",
        workspace_symbols: {"src/rate.py": ["compute_rate"]}
      },
      hack: {
        run_id: "portal-run-hack-02",
        agent_id: "untrusted-worker",
        task_prompt: "Fix zero-division edge case in compute_rate()",
        retrieved_context: [{"source_id": "src_1", "content": "compute_rate must return 0.0 when denominator <= 0."}],
        temporal_facts: [],
        tool_trajectory: [{"tool": "run_pytest", "args": {"target": "tests/test_rate.py"}, "status": "ok"}],
        file_reads: ["tests/test_rate.py"],
        file_writes: ["tests/test_rate.py"],
        active_peer_leases: [],
        code_patch_before: "def test_rate():\n    assert compute_rate(10, 0) == 0.0\n",
        code_patch_after: "def test_rate():\n    assert True\n",
        final_response: "All tests pass [src_1].",
        tokens_used: 3800,
        cost_usd: 0.03,
        budget_cap_usd: 0.50,
        model_id: "claude-3-5-haiku",
        workspace_symbols: {"src/rate.py": ["compute_rate"]}
      }
    };
    let lastDisclosure = null;

    function loadPreset(kind) {
      document.getElementById("bundle-input").value = JSON.stringify(PRESETS[kind], null, 2);
    }

    async function refreshHealthAndGates() {
      const h = await fetch("/health").then(r => r.json());
      const pill = document.getElementById("health-pill");
      pill.textContent = "Kernel: " + h.status + " | v" + h.version + " | " + h.checks.gates + " gates";
      const g = await fetch("/api/gates").then(r => r.json());
      const container = document.getElementById("gate-list");
      container.replaceChildren();
      for (const gate of g.gates) {
        const row = document.createElement("div");
        row.className = "gate-row";
        const left = document.createElement("span");
        left.textContent = gate.gate_id + " (" + gate.stack_component + ")";
        const right = document.createElement("span");
        right.className = "muted";
        right.textContent = gate.gate_name;
        row.appendChild(left);
        row.appendChild(right);
        container.appendChild(row);
      }
    }

    async function runAttest() {
      const raw = document.getElementById("bundle-input").value;
      const res = await fetch("/api/attest", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({bundle: JSON.parse(raw), disclose_gate: "G5_ANTI_REWARD_HACK"})
      });
      const data = await res.json();
      lastDisclosure = data.selective_disclosure || null;
      const cert = data.attestation;
      const statusEl = document.getElementById("attest-status");
      statusEl.textContent = cert
        ? ("Certificate " + cert.certificate_id + " | Passed: " + cert.overall_passed + " | Root: " + cert.merkle_root)
        : (data.detail || data.error || "Error");
      document.getElementById("attest-output").textContent = JSON.stringify(data, null, 2);
    }

    async function verifyDisclosed(tamper) {
      if (!lastDisclosure) {
        await runAttest();
      }
      const pkg = JSON.parse(JSON.stringify(lastDisclosure));
      if (tamper) {
        pkg.disclosed_gate_verdict.passed = !pkg.disclosed_gate_verdict.passed;
      }
      const res = await fetch("/api/verify-proof", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(pkg)
      }).then(r => r.json());
      document.getElementById("attest-status").textContent =
        "Proof Verification (" + (tamper ? "TAMPERED" : "INTACT") + "): verified=" + res.verified;
    }

    async function runBenchmark() {
      const data = await fetch("/api/benchmark").then(r => r.json());
      const {scenarios, ...summary} = data;
      document.getElementById("bench-output").textContent = JSON.stringify(summary, null, 2);
    }

    async function loadMetrics() {
      const data = await fetch("/metrics?format=json").then(r => r.json());
      document.getElementById("bench-output").textContent = JSON.stringify(data, null, 2);
    }

    loadPreset("clean");
    refreshHealthAndGates();
  </script>
</body>
</html>
"""


PORTAL_HTML = _render_portal_html()


class NexusAegisHTTPApp:
    """Framework-agnostic HTTP + Streamable MCP + REST application for NexusAegis."""

    def __init__(
        self,
        *,
        max_body_bytes: int | None = None,
        secret_key: str = "nexus-aegis-default-signing-key",
    ) -> None:
        self.max_body_bytes = resolve_max_body_bytes(max_body_bytes)
        self.kernel = NexusAegisKernel(secret_key=secret_key)
        self.mcp_server = NexusAegisMCPServer(secret_key=secret_key)
        self.metrics = MetricsCollector()
        self._sessions: dict[str, float] = {}
        self._route_table: dict[str, dict[str, Callable[..., HTTPResponse]]] = {
            "/": {"GET": self._handle_root},
            "/health": {"GET": self._handle_health},
            "/healthz": {"GET": self._handle_health},
            "/readyz": {"GET": self._handle_readyz},
            "/info": {"GET": self._handle_info},
            "/metrics": {"GET": self._handle_metrics},
            "/mcp": {"GET": self._handle_mcp_get, "POST": self._handle_mcp_post},
            "/messages": {"POST": self._handle_mcp_post},
            "/api/gates": {"GET": self._handle_api_gates},
            "/api/demo": {"GET": self._handle_api_demo, "POST": self._handle_api_demo},
            "/api/attest": {"POST": self._handle_api_attest},
            "/api/verify-proof": {"POST": self._handle_api_verify_proof},
            "/api/benchmark": {
                "GET": self._handle_api_benchmark,
                "POST": self._handle_api_benchmark,
            },
        }

    def service_info(self) -> dict[str, Any]:
        """Return machine-readable service metadata and endpoint inventory."""
        return {
            "service": "nexus-aegis",
            "name": "NexusAegis PCAE Kernel & Attestation Server",
            "version": _VERSION,
            "description": (
                "Proof-Carrying Autonomous Agent Kernel, 7-Gate Deterministic Pipeline, "
                "RFC 6962 Domain-Separated SHA-256 Merkle Engine & Streamable MCP Server."
            ),
            "protocol": "mcp-streamable-http",
            "mcp_protocol_version": MCP_PROTOCOL_VERSION,
            "endpoints": {
                "portal": "GET / (Accept: text/html)",
                "health": ["GET /health", "GET /healthz", "GET /readyz"],
                "info": "GET /info",
                "metrics": "GET /metrics",
                "mcp_streamable": ["POST /mcp", "GET /mcp (SSE)", "POST /messages"],
                "rest_api": [
                    "GET /api/gates",
                    "GET|POST /api/demo",
                    "POST /api/attest",
                    "POST /api/verify-proof",
                    "GET|POST /api/benchmark",
                ],
            },
            "mcp": {
                "tools": [t["name"] for t in MCP_TOOLS_SCHEMA],
                "resources": [r["uri"] for r in MCP_RESOURCES],
                "resource_templates": [t["uriTemplate"] for t in MCP_RESOURCE_TEMPLATES],
                "prompts": [p["name"] for p in MCP_PROMPTS],
            },
        }

    def handle_http(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes = b"",
    ) -> HTTPResponse:
        """Dispatch a single HTTP request with hardening, metrics, and zero traceback leaks."""
        t0 = time.perf_counter()
        parsed = urlsplit(target)
        path = parsed.path or "/"
        query = parse_qs(parsed.query)
        upper_method = method.upper()
        req_id = sanitize_request_id(_get_header(headers, "x-request-id"))

        try:
            content_len = parse_content_length(headers)
            if content_len is not None and content_len > self.max_body_bytes:
                raise PayloadTooLargeError(
                    f"Request body exceeds limit of {self.max_body_bytes} bytes."
                )
            if len(body) > self.max_body_bytes:
                raise PayloadTooLargeError(
                    f"Request body exceeds limit of {self.max_body_bytes} bytes."
                )

            if upper_method == "OPTIONS":
                resp = self._handle_options(path, req_id)
            else:
                effective_method = "GET" if upper_method == "HEAD" else upper_method
                resp = self._dispatch_route(effective_method, path, query, headers, body, req_id)
                if upper_method == "HEAD":
                    resp = HTTPResponse(status=resp.status, headers=resp.headers, body=b"")

        except PayloadTooLargeError as exc:
            resp = self._json_response(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "Payload Too Large", "code": 413, "detail": str(exc)},
                path,
                req_id,
            )
        except BadRequestError as exc:
            resp = self._json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Bad Request", "code": 400, "detail": str(exc)},
                path,
                req_id,
            )
        except Exception:  # noqa: BLE001 - top-level server boundary must never leak tracebacks
            resp = self._json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Internal server error", "code": 500, "request_id": req_id},
                path,
                req_id,
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.metrics.record_http(upper_method, resp.status, elapsed_ms)
        return resp

    def _dispatch_route(
        self,
        method: str,
        path: str,
        query: dict[str, list[str]],
        headers: Mapping[str, str],
        body: bytes,
        req_id: str,
    ) -> HTTPResponse:
        handlers = self._route_table.get(path)
        if handlers is None:
            return self._json_response(
                HTTPStatus.NOT_FOUND,
                {"error": "Not Found", "path": path},
                path,
                req_id,
            )
        handler = handlers.get(method)
        if handler is None:
            allowed = sorted([*handlers.keys(), "OPTIONS"])
            if "GET" in handlers and "HEAD" not in allowed:
                allowed = sorted([*allowed, "HEAD"])
            return self._json_response(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "Method Not Allowed", "allowed": allowed},
                path,
                req_id,
                extra_headers={"Allow": ", ".join(allowed)},
            )
        return handler(path=path, query=query, headers=headers, body=body, req_id=req_id)

    def _handle_options(self, path: str, req_id: str) -> HTTPResponse:
        headers = build_security_headers(
            path,
            req_id,
            extra={
                "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
                "Access-Control-Allow-Headers": (
                    "Content-Type, Authorization, X-Request-ID, Accept, Mcp-Session-Id"
                ),
                "Access-Control-Max-Age": "86400",
                "Content-Length": "0",
            },
        )
        return HTTPResponse(status=HTTPStatus.NO_CONTENT, headers=headers, body=b"")

    def _handle_root(
        self,
        *,
        path: str,
        headers: Mapping[str, str],
        req_id: str,
        **_kwargs: Any,
    ) -> HTTPResponse:
        accept = _get_header(headers, "accept", "").lower()
        if "text/html" in accept:
            raw = PORTAL_HTML.encode("utf-8")
            resp_headers = build_security_headers(
                path,
                req_id,
                extra={
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Length": str(len(raw)),
                },
            )
            return HTTPResponse(status=HTTPStatus.OK, headers=resp_headers, body=raw)
        return self._json_response(HTTPStatus.OK, self.service_info(), path, req_id)

    def _handle_health(self, *, path: str, req_id: str, **_kwargs: Any) -> HTTPResponse:
        snap = self.metrics.to_dict()
        payload = {
            "status": "ok",
            "service": "nexus-aegis",
            "version": _VERSION,
            "uptime_seconds": snap["uptime_seconds"],
            "checks": {
                "kernel": "ready",
                "merkle_engine": "rfc6962-sha256",
                "gates": len(GATE_METADATA),
            },
        }
        return self._json_response(HTTPStatus.OK, payload, path, req_id)

    def _handle_readyz(self, *, path: str, req_id: str, **_kwargs: Any) -> HTTPResponse:
        snap = self.metrics.to_dict()
        payload = {
            "status": "ready",
            "ready": True,
            "service": "nexus-aegis",
            "version": _VERSION,
            "uptime_seconds": snap["uptime_seconds"],
        }
        return self._json_response(HTTPStatus.OK, payload, path, req_id)

    def _handle_info(self, *, path: str, req_id: str, **_kwargs: Any) -> HTTPResponse:
        return self._json_response(HTTPStatus.OK, self.service_info(), path, req_id)

    def _handle_metrics(
        self,
        *,
        path: str,
        query: dict[str, list[str]],
        headers: Mapping[str, str],
        req_id: str,
        **_kwargs: Any,
    ) -> HTTPResponse:
        accept = _get_header(headers, "accept", "").lower()
        fmt = (query.get("format") or [""])[0].lower()
        if fmt == "json" or ("application/json" in accept and "text/plain" not in accept):
            return self._json_response(HTTPStatus.OK, self.metrics.to_dict(), path, req_id)

        raw = self.metrics.to_prometheus().encode("utf-8")
        resp_headers = build_security_headers(
            path,
            req_id,
            extra={
                "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
                "Content-Length": str(len(raw)),
            },
        )
        return HTTPResponse(status=HTTPStatus.OK, headers=resp_headers, body=raw)

    def _handle_mcp_get(
        self,
        *,
        path: str,
        headers: Mapping[str, str],
        req_id: str,
        **_kwargs: Any,
    ) -> HTTPResponse:
        accept = _get_header(headers, "accept", "").lower()
        if "text/event-stream" not in accept:
            return self._json_response(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {
                    "error": "Method Not Allowed",
                    "detail": "GET /mcp requires Accept: text/event-stream; use POST /mcp.",
                    "allowed": ["POST", "OPTIONS"],
                },
                path,
                req_id,
                extra_headers={"Allow": "POST, OPTIONS"},
            )

        session_id = _get_header(headers, "mcp-session-id") or uuid.uuid4().hex
        self._sessions[session_id] = time.time()
        ready_meta = json.dumps(
            {
                "server": "nexus-aegis-mcp",
                "version": _VERSION,
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "sessionId": session_id,
            }
        )
        sse_text = (
            f"event: endpoint\ndata: /messages?sessionId={session_id}\n\n"
            f"event: ready\ndata: {ready_meta}\n\n"
        )
        raw = sse_text.encode("utf-8")
        resp_headers = build_security_headers(
            path,
            req_id,
            extra={
                "Content-Type": "text/event-stream; charset=utf-8",
                "Cache-Control": "no-cache",
                "Mcp-Session-Id": session_id,
                "Content-Length": str(len(raw)),
            },
        )
        return HTTPResponse(status=HTTPStatus.OK, headers=resp_headers, body=raw)

    def _handle_mcp_post(
        self,
        *,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        req_id: str,
        **_kwargs: Any,
    ) -> HTTPResponse:
        try:
            decoded = body.decode("utf-8")
            payload = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return self._json_response(
                HTTPStatus.BAD_REQUEST,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                },
                path,
                req_id,
            )

        session_id = _get_header(headers, "mcp-session-id")
        if isinstance(payload, dict):
            method = str(payload.get("method", ""))
            self.metrics.record_mcp(method)
            if method == "initialize" and not session_id:
                session_id = uuid.uuid4().hex
                self._sessions[session_id] = time.time()
            rpc_resp = self.mcp_server.handle_request(payload)
            if rpc_resp is None:
                extra = {"Content-Length": "0"}
                if session_id:
                    extra["Mcp-Session-Id"] = session_id
                return HTTPResponse(
                    status=HTTPStatus.ACCEPTED,
                    headers=build_security_headers(path, req_id, extra=extra),
                    body=b"",
                )
            return self._mcp_payload_response(rpc_resp, path, headers, req_id, session_id)

        if isinstance(payload, list):
            if not payload:
                return self._json_response(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Invalid Request: empty batch."},
                    },
                    path,
                    req_id,
                )
            batch_out: list[dict[str, Any]] = []
            for item in payload:
                if isinstance(item, dict):
                    self.metrics.record_mcp(str(item.get("method", "")))
                item_resp = self.mcp_server.handle_request(item)
                if item_resp is not None:
                    batch_out.append(item_resp)
            if not batch_out:
                return HTTPResponse(
                    status=HTTPStatus.ACCEPTED,
                    headers=build_security_headers(path, req_id, extra={"Content-Length": "0"}),
                    body=b"",
                )
            return self._mcp_payload_response(batch_out, path, headers, req_id, session_id)

        return self._json_response(
            HTTPStatus.BAD_REQUEST,
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: expected JSON object."},
            },
            path,
            req_id,
        )

    def _mcp_payload_response(
        self,
        data: Any,
        path: str,
        headers: Mapping[str, str],
        req_id: str,
        session_id: str,
    ) -> HTTPResponse:
        extra: dict[str, str] = {}
        if session_id:
            extra["Mcp-Session-Id"] = session_id
        accept = _get_header(headers, "accept", "").lower()
        if "text/event-stream" in accept and "application/json" not in accept:
            sse_raw = f"event: message\ndata: {json.dumps(data)}\n\n".encode()
            extra["Content-Type"] = "text/event-stream; charset=utf-8"
            extra["Cache-Control"] = "no-cache"
            extra["Content-Length"] = str(len(sse_raw))
            return HTTPResponse(
                status=HTTPStatus.OK,
                headers=build_security_headers(path, req_id, extra=extra),
                body=sse_raw,
            )
        return self._json_response(HTTPStatus.OK, data, path, req_id, extra_headers=extra)

    def _handle_api_gates(self, *, path: str, req_id: str, **_kwargs: Any) -> HTTPResponse:
        payload = {"total_gates": len(GATE_METADATA), "gates": GATE_METADATA}
        return self._json_response(HTTPStatus.OK, payload, path, req_id)

    def _handle_api_demo(self, *, path: str, req_id: str, **_kwargs: Any) -> HTTPResponse:
        scenarios = build_benchmark_scenarios()
        clean_sc = scenarios[0]
        hack_sc = next(s for s in scenarios if s.scenario_id == "S27_G5_ASSERT_TRUE_TAUTOLOGY")
        clean_cert = self.kernel.attest(clean_sc.bundle, timestamp_utc="2026-11-07T12:00:00Z")
        hack_cert = self.kernel.attest(hack_sc.bundle, timestamp_utc="2026-11-07T12:00:00Z")
        sd_pkg = self.kernel.extract_selective_disclosure_proof(clean_cert, "G5_ANTI_REWARD_HACK")
        sd_ok = self.kernel.verify_selective_disclosure(sd_pkg)
        payload = {
            "clean": {
                "scenario_id": clean_sc.scenario_id,
                "attestation": clean_cert.to_dict(),
                "pr_markdown": render_pr_attestation_markdown(clean_cert),
                "selective_disclosure_g5_verified": sd_ok,
            },
            "adversarial": {
                "scenario_id": hack_sc.scenario_id,
                "attestation": hack_cert.to_dict(),
                "pr_markdown": render_pr_attestation_markdown(hack_cert),
            },
        }
        return self._json_response(HTTPStatus.OK, payload, path, req_id)

    def _handle_api_attest(
        self,
        *,
        path: str,
        body: bytes,
        req_id: str,
        **_kwargs: Any,
    ) -> HTTPResponse:
        payload = self._parse_json_object(body)
        bundle_raw = payload.get("bundle")
        if bundle_raw is None:
            bundle_raw = payload
        if not isinstance(bundle_raw, dict):
            raise BadRequestError("Field 'bundle' must be a JSON object.")

        timestamp_utc = payload.get("timestamp_utc")
        if timestamp_utc is not None and not isinstance(timestamp_utc, str):
            raise BadRequestError("Field 'timestamp_utc' must be a string when provided.")

        disclose_gate = payload.get("disclose_gate")
        if disclose_gate is not None and not isinstance(disclose_gate, str):
            raise BadRequestError("Field 'disclose_gate' must be a string when provided.")

        for field_name in (
            "retrieved_context",
            "temporal_facts",
            "tool_trajectory",
            "active_peer_leases",
        ):
            if field_name in bundle_raw:
                items = bundle_raw[field_name]
                if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                    raise BadRequestError(f"Field '{field_name}' must be a list of JSON objects.")

        for field_name in ("file_reads", "file_writes"):
            if field_name in bundle_raw:
                items = bundle_raw[field_name]
                if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
                    raise BadRequestError(f"Field '{field_name}' must be a list of strings.")

        if "workspace_symbols" in bundle_raw:
            ws = bundle_raw["workspace_symbols"]
            if not isinstance(ws, dict) or not all(
                isinstance(k, str) and isinstance(v, list) and all(isinstance(s, str) for s in v)
                for k, v in ws.items()
            ):
                raise BadRequestError(
                    "Field 'workspace_symbols' must map filenames to lists of symbol strings."
                )

        try:
            bundle = AgentRunBundle.from_dict(bundle_raw)
            attestation = self.kernel.attest(bundle, timestamp_utc=timestamp_utc)
            response_data: dict[str, Any] = {
                "attestation": attestation.to_dict(),
                "pr_markdown": render_pr_attestation_markdown(attestation),
            }
            if disclose_gate:
                response_data["selective_disclosure"] = self.kernel.extract_selective_disclosure_proof(
                    attestation, disclose_gate
                )
        except (ValueError, KeyError, TypeError) as exc:
            raise BadRequestError(str(exc)) from exc

        self.metrics.record_attestation(attestation.overall_passed)
        return self._json_response(HTTPStatus.OK, response_data, path, req_id)

    def _handle_api_verify_proof(
        self,
        *,
        path: str,
        body: bytes,
        req_id: str,
        **_kwargs: Any,
    ) -> HTTPResponse:
        payload = self._parse_json_object(body)
        if "disclosed_gate_verdict" in payload and "inclusion_proof" in payload:
            expected_root = payload.get("expected_root_hash")
            if expected_root is not None and not isinstance(expected_root, str):
                raise BadRequestError("Field 'expected_root_hash' must be a string when provided.")
            verified = self.kernel.verify_selective_disclosure(payload)
            if verified and expected_root is not None and payload.get("merkle_root") != expected_root:
                verified = False
            self.metrics.record_proof_verification(verified)
            return self._json_response(
                HTTPStatus.OK,
                {
                    "verified": verified,
                    "mode": "selective_disclosure",
                    "gate_id": payload["disclosed_gate_verdict"].get("gate_id")
                    if isinstance(payload.get("disclosed_gate_verdict"), dict)
                    else None,
                    "merkle_root": payload.get("merkle_root"),
                },
                path,
                req_id,
            )

        proof_raw = payload.get("proof")
        if not isinstance(proof_raw, dict):
            raise BadRequestError(
                "Expected either a selective-disclosure package or {'proof': {...}} payload."
            )
        expected_root = payload.get("expected_root_hash")
        if expected_root is not None and not isinstance(expected_root, str):
            raise BadRequestError("Field 'expected_root_hash' must be a string when provided.")
        expected_leaf_payload = payload.get("expected_leaf_payload")
        if expected_leaf_payload is not None and not isinstance(expected_leaf_payload, dict):
            raise BadRequestError("Field 'expected_leaf_payload' must be a JSON object when provided.")

        try:
            proof = MerkleInclusionProof.from_dict(proof_raw)
        except (ValueError, KeyError, TypeError) as exc:
            raise BadRequestError(str(exc)) from exc

        verified = verify_merkle_inclusion_proof(
            proof=proof,
            expected_root_hash=expected_root,
            expected_leaf_payload=expected_leaf_payload,
        )
        self.metrics.record_proof_verification(verified)
        return self._json_response(
            HTTPStatus.OK,
            {
                "verified": verified,
                "mode": "merkle_inclusion_proof",
                "leaf_name": proof.leaf_name,
                "leaf_hash": proof.leaf_hash,
                "root_hash": proof.root_hash,
                "proof_depth": len(proof.steps),
            },
            path,
            req_id,
        )

    def _handle_api_benchmark(self, *, path: str, req_id: str, **_kwargs: Any) -> HTTPResponse:
        self.metrics.record_benchmark()
        report = run_benchmark_suite()
        return self._json_response(HTTPStatus.OK, report, path, req_id)

    @staticmethod
    def _parse_json_object(body: bytes) -> dict[str, Any]:
        if not body:
            raise BadRequestError("Request body must be a JSON object.")
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BadRequestError(f"Invalid JSON payload: {exc}") from exc
        if not isinstance(data, dict):
            raise BadRequestError("JSON payload must be an object.")
        return data

    def _json_response(
        self,
        status: int | HTTPStatus,
        payload: Any,
        path: str,
        req_id: str,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> HTTPResponse:
        raw = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        merged_extra: dict[str, str] = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(raw)),
        }
        if extra_headers:
            merged_extra.update(extra_headers)
        headers = build_security_headers(path, req_id, extra=merged_extra)
        return HTTPResponse(status=int(status), headers=headers, body=raw)


class NexusAegisHTTPServer(ThreadingHTTPServer):
    """Threaded stdlib HTTP server hosting NexusAegisHTTPApp."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[NexusAegisHTTPHandler],
        app: NexusAegisHTTPApp,
    ) -> None:
        self.app = app
        super().__init__(server_address, request_handler_class)


class NexusAegisHTTPHandler(BaseHTTPRequestHandler):
    """Stdlib HTTP request handler delegating directly to NexusAegisHTTPApp."""

    server: NexusAegisHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _read_request_body(self) -> tuple[bytes, HTTPResponse | None]:
        header_map = {k: v for k, v in self.headers.items()}
        req_id = sanitize_request_id(_get_header(header_map, "x-request-id"))
        path = urlsplit(self.path).path or "/"
        try:
            content_len = parse_content_length(header_map)
        except BadRequestError as exc:
            return b"", self.server.app._json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Bad Request", "code": 400, "detail": str(exc)},
                path,
                req_id,
            )
        if content_len is None:
            return b"", None
        if content_len > self.server.app.max_body_bytes:
            return b"", self.server.app._json_response(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "error": "Payload Too Large",
                    "code": 413,
                    "detail": (
                        f"Request body exceeds limit of {self.server.app.max_body_bytes} bytes."
                    ),
                },
                path,
                req_id,
            )
        return self.rfile.read(content_len), None

    def _handle_any(self, method: str) -> None:
        header_map = {k: v for k, v in self.headers.items()}
        body, early_error = self._read_request_body()
        if early_error is not None:
            self._write_response(early_error, send_body=(method != "HEAD"))
            return
        resp = self.server.app.handle_http(method, self.path, header_map, body)
        self._write_response(resp, send_body=(method != "HEAD"))

    def _write_response(self, resp: HTTPResponse, *, send_body: bool) -> None:
        self.send_response(resp.status)
        for key, value in resp.headers.items():
            if key.lower() in ("server", "date", "connection"):
                continue
            self.send_header(key, value)
        self.send_header("Connection", "close")
        self.end_headers()
        if send_body and resp.body:
            self.wfile.write(resp.body)
        self.close_connection = True

    def do_GET(self) -> None:
        self._handle_any("GET")

    def do_HEAD(self) -> None:
        self._handle_any("HEAD")

    def do_POST(self) -> None:
        self._handle_any("POST")

    def do_OPTIONS(self) -> None:
        self._handle_any("OPTIONS")

    def do_PUT(self) -> None:
        self._handle_any("PUT")

    def do_DELETE(self) -> None:
        self._handle_any("DELETE")

    def do_PATCH(self) -> None:
        self._handle_any("PATCH")


def create_http_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    max_body_bytes: int | None = None,
    secret_key: str = "nexus-aegis-default-signing-key",
) -> NexusAegisHTTPServer:
    """Instantiate a ready-to-serve NexusAegisHTTPServer without blocking."""
    app = NexusAegisHTTPApp(max_body_bytes=max_body_bytes, secret_key=secret_key)
    return NexusAegisHTTPServer((host, port), NexusAegisHTTPHandler, app)


def serve_http(
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    max_body_bytes: int | None = None,
    secret_key: str = "nexus-aegis-default-signing-key",
) -> None:
    """Start the NexusAegis HTTP/SSE MCP server and block until interrupted."""
    server = create_http_server(
        host=host,
        port=port,
        max_body_bytes=max_body_bytes,
        secret_key=secret_key,
    )
    bound_host, bound_port = server.server_address[:2]
    host_display = (
        bound_host.decode("utf-8", errors="replace")
        if isinstance(bound_host, bytes)
        else bound_host
    )
    print(
        f"NexusAegis HTTP/MCP portal listening on http://{host_display}:{bound_port} "
        f"(MCP: /mcp, Health: /health, Metrics: /metrics)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
