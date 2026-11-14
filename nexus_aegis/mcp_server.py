"""
JSON-RPC 2.0 Model Context Protocol (MCP) Server for NexusAegis (`nexus_aegis.mcp_server`).

Exposes 4 deterministic tools, 3 curated resources (plus resource templates), and
3 verification prompts over stdio and HTTP/SSE JSON-RPC 2.0:
1. `aegis_attest_agent_run`
2. `aegis_verify_merkle_proof`
3. `aegis_list_gates`
4. `aegis_run_benchmark`
"""

from __future__ import annotations

import json
import sys
from typing import IO, Any

from nexus_aegis.benchmark import run_benchmark_suite
from nexus_aegis.gates import GATE_METADATA
from nexus_aegis.kernel import NexusAegisKernel, render_pr_attestation_markdown
from nexus_aegis.merkle import LEAF_PREFIX, NODE_PREFIX, verify_merkle_inclusion_proof
from nexus_aegis.models import AgentRunBundle, MerkleInclusionProof

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "nexus-aegis-mcp"
SERVER_VERSION = "1.1.0"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602

_GATE_BY_ID: dict[str, dict[str, str]] = {item["gate_id"]: item for item in GATE_METADATA}


MCP_TOOLS_SCHEMA: list[dict[str, Any]] = [
    {
        "name": "aegis_attest_agent_run",
        "description": (
            "Execute the 7-Gate Proof-Carrying Agent Execution (PCAE) verification pipeline "
            "on an AgentRunBundle and return a signed RFC 6962 AegisAttestationBundle plus "
            "a GitHub Pull Request Attestation Markdown Card."
        ),
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
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
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
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
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
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
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]

MCP_RESOURCES: list[dict[str, Any]] = [
    {
        "uri": "aegis://gates/catalog",
        "name": "NexusAegis 7-Gate PCAE Catalog",
        "description": (
            "Complete specification of the 7 deterministic Proof-Carrying Agent Execution (PCAE) "
            "gates (G1_SECURITY through G7_TEMPORAL_MEMORY) and their Codesphere stack engines."
        ),
        "mimeType": "application/json",
    },
    {
        "uri": "aegis://merkle/rfc6962-spec",
        "name": "RFC 6962 Domain-Separated SHA-256 Merkle Specification",
        "description": (
            "Cryptographic leaf ordering (INPUT_DIGEST, G1..G7, OUTPUT_DIGEST), 0x00/0x01 "
            "second-preimage domain separation, and O(log N) selective-disclosure verification."
        ),
        "mimeType": "application/json",
    },
    {
        "uri": "aegis://benchmark/summary",
        "name": "35-Scenario Multi-Agent PCAE Benchmark Report",
        "description": (
            "Live deterministic evaluation across 10 clean runs and 25 adversarial runs "
            "measuring recall, false-positive rate, selective-disclosure proof accuracy, and latency."
        ),
        "mimeType": "application/json",
    },
]

MCP_RESOURCE_TEMPLATES: list[dict[str, Any]] = [
    {
        "uriTemplate": "aegis://gates/{gate_id}",
        "name": "Single PCAE Gate Metadata",
        "description": "Retrieve metadata and invariant specification for a specific gate (e.g. G5_ANTI_REWARD_HACK).",
        "mimeType": "application/json",
    },
]

MCP_PROMPTS: list[dict[str, Any]] = [
    {
        "name": "audit-agent-pr",
        "description": (
            "Audit an autonomous agent pull request across all 7 NexusAegis PCAE gates and "
            "produce an attestation verification summary."
        ),
        "arguments": [
            {
                "name": "run_summary",
                "description": "JSON or summary of the AgentRunBundle (prompt, diff, tool trajectory, response).",
                "required": True,
            },
            {
                "name": "target_gate",
                "description": "Optional specific gate ID to focus the audit on (e.g. G5_ANTI_REWARD_HACK).",
                "required": False,
            },
        ],
    },
    {
        "name": "verify-selective-disclosure",
        "description": (
            "Guide an external CI/compliance auditor through verifying an O(log N) RFC 6962 "
            "selective-disclosure proof for a single gate without exposing prompts or diffs."
        ),
        "arguments": [
            {
                "name": "gate_id",
                "description": "PCAE gate identifier to verify (e.g. G1_SECURITY or G5_ANTI_REWARD_HACK).",
                "required": True,
            },
            {
                "name": "merkle_root",
                "description": "Optional 64-char SHA-256 Merkle root hash of the signed certificate.",
                "required": False,
            },
        ],
    },
    {
        "name": "remediate-gate-violation",
        "description": (
            "Diagnose why a NexusAegis PCAE gate blocked an autonomous run and generate "
            "deterministic remediation steps."
        ),
        "arguments": [
            {
                "name": "gate_id",
                "description": "Failing gate identifier (G1_SECURITY .. G7_TEMPORAL_MEMORY).",
                "required": True,
            },
            {
                "name": "violations",
                "description": "Violation strings reported in the GateVerdict.",
                "required": True,
            },
        ],
    },
]


class NexusAegisMCPServer:
    """
    Stateless JSON-RPC 2.0 MCP Server for NexusAegis.
    """

    def __init__(self, secret_key: str = "nexus-aegis-default-signing-key") -> None:
        self.kernel = NexusAegisKernel(secret_key=secret_key)
        self.initialized = False

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return MCP tool schemas exposed by NexusAegis."""
        return list(MCP_TOOLS_SCHEMA)

    def get_resource_definitions(self) -> list[dict[str, Any]]:
        """Return static MCP resources exposed by NexusAegis."""
        return list(MCP_RESOURCES)

    def get_resource_template_definitions(self) -> list[dict[str, Any]]:
        """Return MCP resource templates exposed by NexusAegis."""
        return list(MCP_RESOURCE_TEMPLATES)

    def get_prompt_definitions(self) -> list[dict[str, Any]]:
        """Return MCP prompt templates exposed by NexusAegis."""
        return list(MCP_PROMPTS)

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Dispatch one JSON-RPC 2.0 MCP message. Returns None for notifications."""
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return _rpc_error(
                request.get("id") if isinstance(request, dict) else None,
                INVALID_REQUEST,
                "Invalid JSON-RPC 2.0 request.",
            )

        req_id = request.get("id")
        method = request.get("method")
        if not isinstance(method, str) or not method:
            return _rpc_error(req_id, INVALID_REQUEST, "Missing or non-string method name.")

        raw_params = request.get("params")
        if raw_params is not None and not isinstance(raw_params, dict):
            return _rpc_error(req_id, INVALID_PARAMS, "Field 'params' must be a JSON object.")
        params: dict[str, Any] = raw_params or {}

        is_notification = "id" not in request or (
            req_id is None and method.startswith("notifications/")
        )
        if is_notification:
            if method.startswith("notifications/"):
                self.initialized = True
            return None

        if method == "initialize":
            self.initialized = True
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.get_tool_definitions()},
            }

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resources": self.get_resource_definitions()},
            }

        if method == "resources/templates/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resourceTemplates": self.get_resource_template_definitions()},
            }

        if method in ("resources/subscribe", "resources/unsubscribe", "logging/setLevel"):
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str) or not uri:
                return _rpc_error(req_id, INVALID_PARAMS, "Missing 'uri' parameter.")
            try:
                res = self._read_resource(uri)
                return {"jsonrpc": "2.0", "id": req_id, "result": res}
            except KeyError as exc:
                return _rpc_error(req_id, INVALID_PARAMS, str(exc))

        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"prompts": self.get_prompt_definitions()},
            }

        if method == "prompts/get":
            prompt_name = params.get("name")
            prompt_args = params.get("arguments")
            if not isinstance(prompt_name, str) or not prompt_name:
                return _rpc_error(req_id, INVALID_PARAMS, "Missing prompt 'name'.")
            if prompt_args is not None and not isinstance(prompt_args, dict):
                return _rpc_error(req_id, INVALID_PARAMS, "Prompt 'arguments' must be a JSON object.")
            try:
                prompt_res = self._get_prompt(prompt_name, prompt_args)
                return {"jsonrpc": "2.0", "id": req_id, "result": prompt_res}
            except (KeyError, ValueError) as exc:
                return _rpc_error(req_id, INVALID_PARAMS, str(exc))

        if method == "tools/call":
            tool_name = params.get("name")
            raw_arguments = params.get("arguments")
            if not isinstance(tool_name, str) or not tool_name:
                return _rpc_error(req_id, INVALID_PARAMS, "Missing tool 'name' in tools/call.")
            if raw_arguments is not None and not isinstance(raw_arguments, dict):
                return _rpc_error(req_id, INVALID_PARAMS, "Field 'arguments' must be a JSON object.")
            arguments: dict[str, Any] = raw_arguments or {}
            try:
                tool_output = self._call_tool(tool_name, arguments)
            except (ValueError, KeyError, TypeError) as exc:
                return _rpc_error(req_id, INVALID_PARAMS, str(exc))
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

        return _rpc_error(req_id, METHOD_NOT_FOUND, f"Method not found: {method}")

    def _read_resource(self, uri: str) -> dict[str, Any]:
        if uri == "aegis://gates/catalog":
            payload: dict[str, Any] = {
                "total_gates": len(GATE_METADATA),
                "gates": GATE_METADATA,
            }
            return _resource_text(uri, payload)

        if uri == "aegis://merkle/rfc6962-spec":
            spec_payload = {
                "standard": "RFC 6962 (Certificate Transparency)",
                "hash_algorithm": "SHA-256",
                "leaf_domain_prefix_hex": LEAF_PREFIX.hex(),
                "node_domain_prefix_hex": NODE_PREFIX.hex(),
                "leaf_order": [
                    "INPUT_DIGEST",
                    *[g["gate_id"] for g in GATE_METADATA],
                    "OUTPUT_DIGEST",
                ],
                "leaf_count": 9,
                "inclusion_proof_complexity": "O(log N)",
                "signature_algorithm": "HMAC-SHA256",
            }
            return _resource_text(uri, spec_payload)

        if uri == "aegis://benchmark/summary":
            report = run_benchmark_suite()
            summary = {k: v for k, v in report.items() if k != "scenarios"}
            return _resource_text(uri, summary)

        if uri.startswith("aegis://gates/"):
            gate_id = uri.removeprefix("aegis://gates/")
            gate_meta = _GATE_BY_ID.get(gate_id)
            if gate_meta is not None:
                return _resource_text(uri, gate_meta)

        raise KeyError(f"Unknown resource URI: {uri}")

    def _get_prompt(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        args = arguments or {}
        if name == "audit-agent-pr":
            run_summary = str(args.get("run_summary", "")).strip()
            if not run_summary:
                raise ValueError("Prompt 'audit-agent-pr' requires 'run_summary'.")
            target_gate = str(args.get("target_gate", "ALL (G1..G7)"))
            return {
                "description": "Audit an autonomous agent pull request through NexusAegis 7-Gate PCAE",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": (
                                "Evaluate the following autonomous agent run through the NexusAegis "
                                f"7-Gate Proof-Carrying Agent Execution (PCAE) pipeline (focus: {target_gate}).\n\n"
                                f"Run Summary:\n{run_summary}\n\n"
                                "1. Invoke `aegis_attest_agent_run` to compute deterministic gate verdicts, "
                                "RFC 6962 Merkle Root, and HMAC-SHA256 signature.\n"
                                "2. Report any policy violations across G1_SECURITY .. G7_TEMPORAL_MEMORY.\n"
                                "3. Emit the GitHub PR Cryptographic Attestation Card."
                            ),
                        },
                    }
                ],
            }

        if name == "verify-selective-disclosure":
            gate_id = str(args.get("gate_id", "")).strip()
            if not gate_id:
                raise ValueError("Prompt 'verify-selective-disclosure' requires 'gate_id'.")
            merkle_root = str(args.get("merkle_root", "<MERKLE_ROOT>"))
            return {
                "description": "Selective-disclosure O(log N) Merkle proof audit instructions",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": (
                                f"Audit selective-disclosure gate proof for `{gate_id}` against "
                                f"RFC 6962 Merkle Root `{merkle_root}`.\n\n"
                                "1. Call `aegis_verify_merkle_proof` with the inclusion proof and `expected_root_hash`.\n"
                                "2. Confirm domain separation (`0x00` leaf, `0x01` internal node) reconstructs the root.\n"
                                "3. Certify gate compliance without requesting redacted prompts or proprietary diffs."
                            ),
                        },
                    }
                ],
            }

        if name == "remediate-gate-violation":
            gate_id = str(args.get("gate_id", "")).strip()
            violations = str(args.get("violations", "")).strip()
            if not gate_id or not violations:
                raise ValueError("Prompt 'remediate-gate-violation' requires 'gate_id' and 'violations'.")
            return {
                "description": "Remediate blocked NexusAegis PCAE gate violation",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": (
                                f"The NexusAegis PCAE kernel blocked execution at gate `{gate_id}`.\n\n"
                                f"Detected Violations:\n{violations}\n\n"
                                "Provide minimal, deterministic remediation steps so the agent run "
                                "passes all 7 PCAE gates on re-attestation."
                            ),
                        },
                    }
                ],
            }

        raise KeyError(f"Unknown prompt: {name}")

    def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "aegis_attest_agent_run":
            bundle_dict = arguments.get("bundle")
            if not isinstance(bundle_dict, dict):
                raise ValueError("'bundle' argument must be a JSON object")
            timestamp_utc = arguments.get("timestamp_utc")
            if timestamp_utc is not None and not isinstance(timestamp_utc, str):
                raise ValueError("'timestamp_utc' must be a string when provided")
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
            if expected_root is not None and not isinstance(expected_root, str):
                raise ValueError("'expected_root_hash' must be a string when provided")
            expected_leaf_payload = arguments.get("expected_leaf_payload")
            if expected_leaf_payload is not None and not isinstance(expected_leaf_payload, dict):
                raise ValueError("'expected_leaf_payload' must be a JSON object when provided")
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

    def serve_stdio(
        self,
        stdin: IO[str] | None = None,
        stdout: IO[str] | None = None,
    ) -> None:
        """Run the JSON-RPC 2.0 MCP server loop over standard input/output."""
        in_stream = stdin or sys.stdin
        out_stream = stdout or sys.stdout
        for raw_line in in_stream:
            line = raw_line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": PARSE_ERROR, "message": f"Parse error: {exc}"},
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()
                continue

            resp = self.handle_request(req)
            if resp is not None:
                out_stream.write(json.dumps(resp) + "\n")
                out_stream.flush()


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def _resource_text(uri: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "contents": [
            {
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(payload, indent=2, sort_keys=True),
            }
        ]
    }
