"""Tests for NexusAegis HTTP, Streamable MCP, REST portal, and ASGI wrapper."""

from __future__ import annotations

import http.client
import json
import threading
from typing import Any

from nexus_aegis.benchmark import build_benchmark_scenarios
from nexus_aegis.http_server import NexusAegisHTTPApp, create_http_server


def _decode(raw: bytes) -> dict[str, Any]:
    return json.loads(raw.decode("utf-8"))


def test_health_readyz_info_metrics_and_head() -> None:
    app = NexusAegisHTTPApp()

    health = app.handle_http("GET", "/health", {"X-Request-ID": "req-aegis-01"})
    assert health.status == 200
    assert health.headers["X-Request-ID"] == "req-aegis-01"
    assert health.headers["X-Content-Type-Options"] == "nosniff"
    assert _decode(health.body)["checks"]["gates"] == 7

    head = app.handle_http("HEAD", "/healthz", {})
    assert head.status == 200
    assert head.body == b""

    ready = app.handle_http("GET", "/readyz", {})
    assert ready.status == 200
    assert _decode(ready.body)["ready"] is True

    info = app.handle_http("GET", "/info", {})
    assert info.status == 200
    assert _decode(info.body)["service"] == "nexus-aegis"

    root_html = app.handle_http("GET", "/", {"Accept": "text/html"})
    assert root_html.status == 200
    assert "NexusAegis" in root_html.body.decode("utf-8")

    root_json = app.handle_http("GET", "/", {"Accept": "application/json"})
    assert root_json.status == 200
    assert "endpoints" in _decode(root_json.body)

    prom = app.handle_http("GET", "/metrics", {})
    assert prom.status == 200
    assert "nexus_aegis_http_requests_total" in prom.body.decode("utf-8")

    metrics_json = app.handle_http("GET", "/metrics?format=json", {})
    assert metrics_json.status == 200
    assert _decode(metrics_json.body)["requests_total"] >= 5


def test_rest_attest_verify_proof_gates_demo_and_benchmark() -> None:
    app = NexusAegisHTTPApp()

    gates_resp = app.handle_http("GET", "/api/gates", {})
    assert gates_resp.status == 200
    assert _decode(gates_resp.body)["total_gates"] == 7

    demo_resp = app.handle_http("GET", "/api/demo", {})
    assert demo_resp.status == 200
    demo_data = _decode(demo_resp.body)
    assert demo_data["clean"]["attestation"]["overall_passed"] is True
    assert demo_data["adversarial"]["attestation"]["overall_passed"] is False

    clean_bundle = build_benchmark_scenarios()[0].bundle.to_dict()
    attest_resp = app.handle_http(
        "POST",
        "/api/attest",
        {"Content-Type": "application/json"},
        json.dumps({"bundle": clean_bundle, "disclose_gate": "G5_ANTI_REWARD_HACK"}).encode("utf-8"),
    )
    assert attest_resp.status == 200
    attested = _decode(attest_resp.body)
    assert attested["attestation"]["overall_passed"] is True
    assert "NexusAegis" in attested["pr_markdown"]

    sd_pkg = attested["selective_disclosure"]
    verify_ok = app.handle_http(
        "POST",
        "/api/verify-proof",
        {"Content-Type": "application/json"},
        json.dumps(sd_pkg).encode("utf-8"),
    )
    assert verify_ok.status == 200
    assert _decode(verify_ok.body)["verified"] is True

    tampered = json.loads(json.dumps(sd_pkg))
    tampered["disclosed_gate_verdict"]["passed"] = False
    verify_bad = app.handle_http(
        "POST",
        "/api/verify-proof",
        {"Content-Type": "application/json"},
        json.dumps(tampered).encode("utf-8"),
    )
    assert verify_bad.status == 200
    assert _decode(verify_bad.body)["verified"] is False

    raw_proof = sd_pkg["inclusion_proof"]
    verify_raw = app.handle_http(
        "POST",
        "/api/verify-proof",
        {"Content-Type": "application/json"},
        json.dumps(
            {"proof": raw_proof, "expected_root_hash": sd_pkg["merkle_root"]}
        ).encode("utf-8"),
    )
    assert verify_raw.status == 200
    assert _decode(verify_raw.body)["verified"] is True

    bench_resp = app.handle_http("GET", "/api/benchmark", {})
    assert bench_resp.status == 200
    bench_data = _decode(bench_resp.body)
    assert bench_data["total_scenarios"] == 35
    assert bench_data["adversarial_recall_pct"] == 100.0


def test_mcp_streamable_http_and_sse_endpoints() -> None:
    app = NexusAegisHTTPApp()

    get_405 = app.handle_http("GET", "/mcp", {})
    assert get_405.status == 405
    assert "POST" in get_405.headers["Allow"]

    get_sse = app.handle_http("GET", "/mcp", {"Accept": "text/event-stream"})
    assert get_sse.status == 200
    assert "text/event-stream" in get_sse.headers["Content-Type"]
    assert "Mcp-Session-Id" in get_sse.headers
    assert "event: ready" in get_sse.body.decode("utf-8")

    init_resp = app.handle_http(
        "POST",
        "/mcp",
        {"Content-Type": "application/json"},
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode("utf-8"),
    )
    assert init_resp.status == 200
    session_id = init_resp.headers["Mcp-Session-Id"]

    notif_resp = app.handle_http(
        "POST",
        "/mcp",
        {"Content-Type": "application/json", "Mcp-Session-Id": session_id},
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode("utf-8"),
    )
    assert notif_resp.status == 202
    assert notif_resp.body == b""

    batch_resp = app.handle_http(
        "POST",
        "/mcp",
        {"Content-Type": "application/json", "Accept": "text/event-stream"},
        json.dumps(
            [
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
            ]
        ).encode("utf-8"),
    )
    assert batch_resp.status == 200
    assert "event: message" in batch_resp.body.decode("utf-8")


def test_hardening_guards_and_sanitized_errors() -> None:
    app = NexusAegisHTTPApp(max_body_bytes=512)

    options_resp = app.handle_http("OPTIONS", "/api/attest", {})
    assert options_resp.status == 204
    assert options_resp.headers["Access-Control-Allow-Origin"] == "*"

    not_found = app.handle_http("GET", "/does-not-exist", {})
    assert not_found.status == 404

    method_405 = app.handle_http("DELETE", "/health", {})
    assert method_405.status == 405

    too_big = app.handle_http("POST", "/api/attest", {}, b"x" * 600)
    assert too_big.status == 413

    bad_len = app.handle_http("POST", "/api/attest", {"Content-Length": "abc"}, b"{}")
    assert bad_len.status == 400

    bad_json = app.handle_http("POST", "/api/attest", {}, b"{not-json")
    assert bad_json.status == 400

    bad_bundle = app.handle_http("POST", "/api/attest", {}, json.dumps({"bundle": {}}).encode("utf-8"))
    assert bad_bundle.status == 400

    # Sanitized request ID regeneration when untrusted chars appear
    sanitized = app.handle_http("GET", "/health", {"X-Request-ID": "bad\nheader\x00value"})
    assert "\n" not in sanitized.headers["X-Request-ID"]

    # Simulated unexpected internal failure must never expose traceback text
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("secret-db-password-leak")

    app._dispatch_route = _boom  # type: ignore[method-assign]
    err_resp = app.handle_http("GET", "/health", {"X-Request-ID": "trace-500"})
    assert err_resp.status == 500
    assert "secret-db-password-leak" not in err_resp.body.decode("utf-8")
    assert _decode(err_resp.body)["request_id"] == "trace-500"


def test_live_tcp_http_server_roundtrip() -> None:
    server = create_http_server(host="127.0.0.1", port=0, max_body_bytes=2048)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        body = _decode(resp.read())
        conn.close()
        assert resp.status == 200
        assert body["status"] == "ok"

        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request(
            "POST",
            "/api/attest",
            body=b"x" * 3000,
            headers={"Content-Type": "application/json"},
        )
        oversized = conn.getresponse()
        oversized.read()
        conn.close()
        assert oversized.status == 413
    finally:
        server.shutdown()
        server.server_close()


def test_mcp_resources_prompts_and_stdio_dispatch() -> None:
    import io

    app = NexusAegisHTTPApp()
    rpc_calls = [
        {"jsonrpc": "2.0", "id": 10, "method": "ping"},
        {"jsonrpc": "2.0", "id": 11, "method": "resources/templates/list"},
        {"jsonrpc": "2.0", "id": 12, "method": "resources/read", "params": {"uri": "aegis://gates/catalog"}},
        {"jsonrpc": "2.0", "id": 13, "method": "resources/read", "params": {"uri": "aegis://merkle/rfc6962-spec"}},
        {"jsonrpc": "2.0", "id": 14, "method": "resources/read", "params": {"uri": "aegis://benchmark/summary"}},
        {
            "jsonrpc": "2.0",
            "id": 15,
            "method": "resources/read",
            "params": {"uri": "aegis://gates/G5_ANTI_REWARD_HACK"},
        },
        {"jsonrpc": "2.0", "id": 16, "method": "resources/read", "params": {"uri": "aegis://gates/MISSING"}},
        {"jsonrpc": "2.0", "id": 17, "method": "prompts/list"},
        {
            "jsonrpc": "2.0",
            "id": 18,
            "method": "prompts/get",
            "params": {"name": "audit-agent-pr", "arguments": {"run_summary": "diff summary"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 19,
            "method": "prompts/get",
            "params": {"name": "verify-selective-disclosure", "arguments": {"gate_id": "G1_SECURITY"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 20,
            "method": "prompts/get",
            "params": {
                "name": "remediate-gate-violation",
                "arguments": {"gate_id": "G5_ANTI_REWARD_HACK", "violations": "assert True"},
            },
        },
        {"jsonrpc": "2.0", "id": 21, "method": "unknown/method"},
    ]
    batch = app.handle_http(
        "POST",
        "/messages",
        {"Content-Type": "application/json"},
        json.dumps(rpc_calls).encode("utf-8"),
    )
    assert batch.status == 200
    items = _decode(batch.body)
    assert isinstance(items, list) and len(items) == len(rpc_calls)
    assert items[0]["result"] == {}
    assert items[2]["result"]["contents"][0]["mimeType"] == "application/json"
    assert "error" in items[6]
    assert items[8]["result"]["messages"][0]["role"] == "user"
    assert "error" in items[-1]

    stdin = io.StringIO(
        '{"jsonrpc":"2.0","id":1,"method":"ping"}\n{invalid-json\n'
    )
    stdout = io.StringIO()
    app.mcp_server.serve_stdio(stdin=stdin, stdout=stdout)
    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    assert len(lines) == 2
    assert lines[0]["result"] == {}
    assert lines[1]["error"]["code"] == -32700

