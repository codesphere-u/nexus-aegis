"""
JSON-RPC 2.0 Model Context Protocol (MCP) Server for NexusAegis (`nexus_aegis.mcp_server`).

Exposes 4 deterministic tools over stdio JSON-RPC 2.0:
1. `aegis_attest_agent_run`
2. `aegis_verify_merkle_proof`
3. `aegis_list_gates`
4. `aegis_run_benchmark`
"""

from __future__ import annotations

import json
import sys
from typing import Any

from nexus_aegis.benchmark import run_benchmark_suite
from nexus_aegis.gates import GATE_METADATA
from nexus_aegis.kernel import NexusAegisKernel, render_pr_attestation_markdown
from nexus_aegis.merkle import verify_merkle_inclusion_proof
from nexus_aegis.models import AgentRunBundle, MerkleInclusionProof


MCP_TOOLS_SCHEMA: list[dict[str, Any]] = [
    {
        "name": "aegis_attest_agent_run",
        "description": (
            "Execute the 7-Gate Proof-Carrying Agent Execution (PCAE) verification pipeline "
            "on an AgentRunBundle and return a signed RFC 6962 AegisAttestationBundle plus "
            "a GitHub Pull Request Attestation Markdown Card."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle": {
                    "type": "object",
                    "description": "Serialized AgentRunBundle dictionary.",
                },
                "timestamp_utc": {
                    "type": "string",
                    "description": "Optional ISO-8601 UTC timestamp override for deterministic replay.",
                },
            },
            "required": ["bundle"],
        },
    },
    {
        "name": "aegis_verify_merkle_proof",
        "description": (
            "Verify an O(log N) RFC 6962 domain-separated MerkleInclusionProof or a "
            "selective-disclosure gate proof package against a Merkle root."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "proof": {
                    "type": "object",
                    "description": "MerkleInclusionProof dictionary (`leaf_name`, `leaf_hash`, `root_hash`, `steps`).",
                },
                "expected_root_hash": {
                    "type": "string",
                    "description": "Expected 64-hex-char SHA-256 Merkle root.",
                },
                "expected_leaf_payload": {
                    "type": "object",
                    "description": "Optional canonical gate verdict payload to verify against `leaf_hash`.",
                },
            },
            "required": ["proof"],
        },
    },
    {
        "name": "aegis_list_gates",
        "description": (
            "List all 7 deterministic verification gates in the NexusAegis PCAE pipeline "
            "and their upstream Codesphere Agentic Stack repositories."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "aegis_run_benchmark",
        "description": (
            "Run the 35-scenario NexusAegis multi-agent benchmark suite (10 clean runs + "
            "25 adversarial runs across G1..G7) and return recall, FPR, and P50/P95 latency."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


class NexusAegisMCPServer:
    """
    Stateless JSON-RPC 2.0 MCP Server for NexusAegis.
    """

    def __init__(self, secret_key: str = "nexus-aegis-default-signing-key") -> None:
        self.kernel = NexusAegisKernel(secret_key=secret_key)

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params") or {}

        # Notifications without id require no response
        if req_id is None and method.startswith("notifications/"):
            return None

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "nexus-aegis-mcp",
                        "version": "1.0.0",
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                }
                return {"jsonrpc": "2.0", "id": req_id, "result": result}

            if method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": MCP_TOOLS_SCHEMA},
                }

            if method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments") or {}
                tool_output = self._call_tool(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(tool_output, indent=2, sort_keys=True),
                            }
                        ],
                        "structuredContent": tool_output,
                        "isError": False,
                    },
                }

            if method == "ping":
                return {"jsonrpc": "2.0", "id": req_id, "result": {"status": "pong"}}

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": str(exc),
                },
            }

    def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "aegis_attest_agent_run":
            bundle_dict = arguments.get("bundle")
            if not isinstance(bundle_dict, dict):
                raise ValueError("'bundle' argument must be a JSON object")
            timestamp_utc = arguments.get("timestamp_utc")
            run_bundle = AgentRunBundle.from_dict(bundle_dict)
            attestation = self.kernel.attest(run_bundle, timestamp_utc=timestamp_utc)
            pr_markdown = render_pr_attestation_markdown(attestation)
            return {
                "attestation": attestation.to_dict(),
                "pr_markdown": pr_markdown,
            }

        if tool_name == "aegis_verify_merkle_proof":
            proof_dict = arguments.get("proof")
            if not isinstance(proof_dict, dict):
                raise ValueError("'proof' argument must be a JSON object")
            proof = MerkleInclusionProof.from_dict(proof_dict)
            expected_root = arguments.get("expected_root_hash")
            expected_leaf_payload = arguments.get("expected_leaf_payload")
            verified = verify_merkle_inclusion_proof(
                proof=proof,
                expected_root_hash=expected_root,
                expected_leaf_payload=expected_leaf_payload,
            )
            return {
                "verified": verified,
                "leaf_name": proof.leaf_name,
                "leaf_hash": proof.leaf_hash,
                "root_hash": proof.root_hash,
                "proof_depth": len(proof.steps),
            }

        if tool_name == "aegis_list_gates":
            return {
                "total_gates": len(GATE_METADATA),
                "gates": GATE_METADATA,
            }

        if tool_name == "aegis_run_benchmark":
            return run_benchmark_suite()

        raise ValueError(f"Unknown MCP tool: {tool_name!r}")

    def serve_stdio(self) -> None:
        """Run the JSON-RPC 2.0 MCP server loop over standard input/output."""
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            resp = self.handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
