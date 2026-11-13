"""
Command-Line Interface (`nexus-aegis`) for Proof-Carrying Agent Execution (PCAE).

Supported subcommands:
- `nexus-aegis demo`               -> Runs a live demonstration comparing a compliant PR vs an adversarial reward-hacked PR
- `nexus-aegis attest <file.json>` -> Runs all 7 PCAE gates on an AgentRunBundle JSON file and outputs the certificate/PR card
- `nexus-aegis verify-proof <f>`   -> Verifies a selective-disclosure gate proof JSON file against its RFC 6962 Merkle root
- `nexus-aegis gates`              -> Displays all 7 PCAE verification gates and upstream Codesphere stack engines
- `nexus-aegis benchmark [--json]` -> Runs the 35-scenario multi-agent benchmark suite
- `nexus-aegis mcp`                -> Starts the JSON-RPC 2.0 Stdio MCP server
- `nexus-aegis serve-http`         -> Starts the HTTP/SSE MCP portal and REST verification server
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from nexus_aegis.benchmark import build_benchmark_scenarios, run_benchmark_suite
from nexus_aegis.gates import GATE_METADATA
from nexus_aegis.http_server import DEFAULT_MAX_BODY_BYTES, serve_http
from nexus_aegis.kernel import NexusAegisKernel, render_pr_attestation_markdown
from nexus_aegis.mcp_server import NexusAegisMCPServer
from nexus_aegis.merkle import verify_merkle_inclusion_proof
from nexus_aegis.models import AgentRunBundle, MerkleInclusionProof


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexus-aegis",
        description="NexusAegis: Proof-Carrying Autonomous Agent Kernel & Cryptographic PR Attestation Engine",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # demo
    sub.add_parser(
        "demo",
        help="Run a side-by-side demonstration of a compliant PR vs an adversarial reward-hacked PR",
    )

    # attest
    p_attest = sub.add_parser(
        "attest",
        help="Attest an AgentRunBundle JSON file and emit an RFC 6962 AegisAttestationBundle or PR Markdown Card",
    )
    p_attest.add_argument("input_file", help="Path to AgentRunBundle JSON file (or '-' for stdin)")
    p_attest.add_argument("--markdown", action="store_true", help="Output GitHub PR Attestation Markdown Card")
    p_attest.add_argument("--disclose-gate", help="Emit a redacted selective-disclosure proof package for a single gate ID")

    # verify-proof
    p_verify = sub.add_parser(
        "verify-proof",
        help="Verify a selective-disclosure proof package or MerkleInclusionProof JSON file",
    )
    p_verify.add_argument("proof_file", help="Path to selective-disclosure or MerkleInclusionProof JSON file")
    p_verify.add_argument("--root", help="Optional expected 64-char SHA-256 Merkle root override")

    # gates
    p_gates = sub.add_parser(
        "gates",
        help="List all 7 deterministic PCAE verification gates and their Codesphere stack mappings",
    )
    p_gates.add_argument("--json", action="store_true", help="Output gate metadata as JSON")

    # benchmark
    p_bench = sub.add_parser(
        "benchmark",
        help="Run the 35-scenario multi-agent PCAE benchmark suite",
    )
    p_bench.add_argument("--json", action="store_true", help="Output full benchmark results as JSON")

    # mcp
    sub.add_parser(
        "mcp",
        help="Start the JSON-RPC 2.0 Stdio MCP server",
    )

    # serve-http
    p_http = sub.add_parser(
        "serve-http",
        help="Start the HTTP/SSE MCP portal and REST verification server",
    )
    p_http.add_argument(
        "--host",
        default=os.environ.get("HOST", "127.0.0.1"),
        help="Bind host (default: HOST env or 127.0.0.1)",
    )
    p_http.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8000")),
        help="Bind port (default: PORT env or 8000)",
    )
    p_http.add_argument(
        "--max-body-bytes",
        type=int,
        default=None,
        help=(
            "Maximum allowed request body size in bytes "
            f"(default: NEXUS_AEGIS_MAX_BODY_BYTES or {DEFAULT_MAX_BODY_BYTES})"
        ),
    )

    return parser


def _cmd_demo() -> int:
    kernel = NexusAegisKernel()
    scenarios = build_benchmark_scenarios()
    clean_sc = scenarios[0]  # S01_CLEAN_COMPLIANT
    hack_sc = next(s for s in scenarios if s.scenario_id == "S27_G5_ASSERT_TRUE_TAUTOLOGY")

    clean_cert = kernel.attest(clean_sc.bundle, timestamp_utc="2026-11-07T12:00:00Z")
    hack_cert = kernel.attest(hack_sc.bundle, timestamp_utc="2026-11-07T12:00:00Z")

    print("=" * 84)
    print("NEXUS-AEGIS v1.0.0 — PROOF-CARRYING AGENT EXECUTION (PCAE) LIVE DEMO")
    print("=" * 84)
    print("\n[1] COMPLIANT AUTONOMOUS PULL REQUEST ATTESTATION:")
    print(render_pr_attestation_markdown(clean_cert))

    sd_pkg = kernel.extract_selective_disclosure_proof(clean_cert, "G5_ANTI_REWARD_HACK")
    sd_ok = kernel.verify_selective_disclosure(sd_pkg)
    print(
        f"[Selective Disclosure Audit] Gate: G5_ANTI_REWARD_HACK | "
        f"Merkle Root: {clean_cert.merkle_root[:24]}... | "
        f"Proof Steps: {len(sd_pkg['inclusion_proof']['steps'])} | "
        f"Verified: {sd_ok}\n"
    )

    print("-" * 84)
    print("\n[2] ADVERSARIAL REWARD-HACKED PULL REQUEST (`assert True` TAUTOLOGY):")
    print(render_pr_attestation_markdown(hack_cert))
    return 0


def _cmd_attest(args: argparse.Namespace) -> int:
    try:
        raw = (
            sys.stdin.read()
            if args.input_file == "-"
            else Path(args.input_file).read_text(encoding="utf-8")
        )
        data = json.loads(raw)
        bundle = AgentRunBundle.from_dict(data)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"nexus-aegis attest error: {exc}", file=sys.stderr)
        return 2
    kernel = NexusAegisKernel()
    cert = kernel.attest(bundle)

    if args.disclose_gate:
        pkg = kernel.extract_selective_disclosure_proof(cert, args.disclose_gate)
        print(json.dumps(pkg, indent=2, sort_keys=True))
    elif args.markdown:
        print(render_pr_attestation_markdown(cert), end="")
    else:
        print(json.dumps(cert.to_dict(), indent=2, sort_keys=True))
    return 0


def _cmd_verify_proof(args: argparse.Namespace) -> int:
    raw = Path(args.proof_file).read_text(encoding="utf-8")
    data = json.loads(raw)

    if "disclosed_gate_verdict" in data and "inclusion_proof" in data:
        if args.root and data.get("merkle_root") != args.root:
            print(json.dumps({"verified": False, "reason": "merkle_root mismatch against --root"}, indent=2))
            return 1
        verified = NexusAegisKernel.verify_selective_disclosure(data)
        print(
            json.dumps(
                {
                    "verified": verified,
                    "mode": "selective_disclosure",
                    "gate_id": data["disclosed_gate_verdict"].get("gate_id"),
                    "merkle_root": data.get("merkle_root"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if verified else 1

    proof = MerkleInclusionProof.from_dict(data)
    verified = verify_merkle_inclusion_proof(proof, expected_root_hash=args.root)
    print(
        json.dumps(
            {
                "verified": verified,
                "mode": "merkle_inclusion_proof",
                "leaf_name": proof.leaf_name,
                "root_hash": proof.root_hash,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if verified else 1


def _cmd_gates(as_json: bool) -> int:
    if as_json:
        print(json.dumps({"gates": GATE_METADATA}, indent=2, sort_keys=True))
        return 0

    print("NexusAegis 7-Gate Proof-Carrying Agent Execution (PCAE) Pipeline:")
    print("-" * 92)
    for g in GATE_METADATA:
        print(f"  {g['gate_id']:<22} | {g['stack_component']:<28} | {g['gate_name']}")
        print(f"    Invariant: {g['invariant']}")
    return 0


def _cmd_benchmark(as_json: bool) -> int:
    report = run_benchmark_suite()
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print("=" * 84)
    print("NEXUS-AEGIS v1.0.0 — 35-SCENARIO MULTI-AGENT BENCHMARK REPORT")
    print("=" * 84)
    print(f"Total Scenarios Evaluated         : {report['total_scenarios']} (10 Clean + 25 Adversarial)")
    print(f"Adversarial Detection Recall      : {report['adversarial_recall_pct']:.2f}% ({report['true_positives']}/{report['adversarial_scenarios']})")
    print(f"Clean Run False-Positive Rate     : {report['false_positive_rate_pct']:.2f}% ({report['false_positives']}/{report['clean_scenarios']})")
    print(f"Selective-Disclosure Proof Verify : {report['selective_disclosure_accuracy_pct']:.2f}% ({report['selective_disclosure_proofs_tested']} proofs)")
    print(f"Tampered Proof Rejection Rate     : {report['tamper_rejection_rate_pct']:.2f}% ({report['selective_disclosure_proofs_tested']} mutations)")
    print(f"Pipeline + Merkle P50 Latency     : {report['latency_p50_ms']:.4f} ms")
    print(f"Pipeline + Merkle P95 Latency     : {report['latency_p95_ms']:.4f} ms")
    print("-" * 84)
    print("Per-Gate Adversarial Recall Breakdown:")
    for gate_id, gstat in report["per_gate_detection"].items():
        print(f"  - {gate_id:<22}: {gstat['detected']}/{gstat['targeted']} ({gstat['recall_pct']:.1f}%)")
    print("=" * 84)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "demo":
        return _cmd_demo()
    if args.command == "attest":
        return _cmd_attest(args)
    if args.command == "verify-proof":
        return _cmd_verify_proof(args)
    if args.command == "gates":
        return _cmd_gates(as_json=args.json)
    if args.command == "benchmark":
        return _cmd_benchmark(as_json=args.json)
    if args.command == "mcp":
        server = NexusAegisMCPServer()
        server.serve_stdio()
        return 0
    if args.command == "serve-http":
        serve_http(host=args.host, port=args.port, max_body_bytes=args.max_body_bytes)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
