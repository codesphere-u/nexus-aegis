"""
Data models and canonical serialization primitives for Proof-Carrying Agent Execution (PCAE).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
import hashlib
import json
from typing import Any, Literal


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Deterministically serialize any JSON-compatible Python structure into UTF-8 bytes
    with sorted keys and compact separators (`(",", ":")`).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    """Compute a lowercase hexadecimal SHA-256 digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class AgentRunBundle:
    """
    Complete deterministic capture of an autonomous agent execution under audit.
    Encapsulates inputs, context, memory facts, tool trajectory, file locks, code diffs,
    final synthesis response, token/cost telemetry, and workspace AST symbol inventory.
    """
    run_id: str
    agent_id: str
    task_prompt: str
    retrieved_context: list[dict[str, Any]] = field(default_factory=list)
    temporal_facts: list[dict[str, Any]] = field(default_factory=list)
    tool_trajectory: list[dict[str, Any]] = field(default_factory=list)
    file_reads: list[str] = field(default_factory=list)
    file_writes: list[str] = field(default_factory=list)
    active_peer_leases: list[dict[str, Any]] = field(default_factory=list)
    code_patch_before: str = ""
    code_patch_after: str = ""
    final_response: str = ""
    tokens_used: int = 0
    cost_usd: float = 0.0
    budget_cap_usd: float = 1.0
    model_id: str = "claude-3-5-sonnet"
    workspace_symbols: dict[str, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.run_id or not isinstance(self.run_id, str):
            raise ValueError("run_id must be a non-empty string")
        if not self.agent_id or not isinstance(self.agent_id, str):
            raise ValueError("agent_id must be a non-empty string")
        if self.tokens_used < 0:
            raise ValueError("tokens_used must be non-negative")
        if self.cost_usd < 0.0:
            raise ValueError("cost_usd must be non-negative")
        if self.budget_cap_usd <= 0.0:
            raise ValueError("budget_cap_usd must be positive")

    def compute_input_digest(self) -> str:
        """Compute canonical SHA-256 digest over the execution inputs and environment constraints."""
        payload = {
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "task_prompt": self.task_prompt,
            "retrieved_context": self.retrieved_context,
            "temporal_facts": self.temporal_facts,
            "active_peer_leases": self.active_peer_leases,
            "code_patch_before": self.code_patch_before,
            "budget_cap_usd": round(self.budget_cap_usd, 8),
            "workspace_symbols": self.workspace_symbols,
        }
        return sha256_hex(canonical_json_bytes(payload))

    def compute_output_digest(self) -> str:
        """Compute canonical SHA-256 digest over the agent's actions, patches, and final output."""
        payload = {
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "tool_trajectory": self.tool_trajectory,
            "file_reads": self.file_reads,
            "file_writes": self.file_writes,
            "code_patch_after": self.code_patch_after,
            "final_response": self.final_response,
            "tokens_used": self.tokens_used,
            "cost_usd": round(self.cost_usd, 8),
            "model_id": self.model_id,
        }
        return sha256_hex(canonical_json_bytes(payload))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentRunBundle:
        return cls(
            run_id=str(data["run_id"]),
            agent_id=str(data["agent_id"]),
            task_prompt=str(data.get("task_prompt", "")),
            retrieved_context=list(data.get("retrieved_context", [])),
            temporal_facts=list(data.get("temporal_facts", [])),
            tool_trajectory=list(data.get("tool_trajectory", [])),
            file_reads=list(data.get("file_reads", [])),
            file_writes=list(data.get("file_writes", [])),
            active_peer_leases=list(data.get("active_peer_leases", [])),
            code_patch_before=str(data.get("code_patch_before", "")),
            code_patch_after=str(data.get("code_patch_after", "")),
            final_response=str(data.get("final_response", "")),
            tokens_used=int(data.get("tokens_used", 0)),
            cost_usd=float(data.get("cost_usd", 0.0)),
            budget_cap_usd=float(data.get("budget_cap_usd", 1.0)),
            model_id=str(data.get("model_id", "claude-3-5-sonnet")),
            workspace_symbols=dict(data.get("workspace_symbols", {})),
        )


@dataclass(frozen=True)
class GateVerdict:
    """
    Deterministic evaluation result for a single verification gate in the 7-Gate PCAE pipeline.
    Note: `elapsed_ms` is recorded for observability, while `canonical_verdict_payload()`
    excludes wall-clock timing jitter so that `leaf_hash` is 100% reproducible across machines.
    """
    gate_id: str
    gate_name: str
    passed: bool
    score: float
    violations: list[str]
    metrics: dict[str, Any]
    elapsed_ms: float
    leaf_hash: str

    def canonical_verdict_payload(self) -> dict[str, Any]:
        """Return the deterministic, wall-clock-independent payload hashed into the Merkle leaf."""
        return {
            "gate_id": self.gate_id,
            "gate_name": self.gate_name,
            "passed": self.passed,
            "score": round(self.score, 6),
            "violations": list(self.violations),
            "metrics": self.metrics,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "gate_name": self.gate_name,
            "passed": self.passed,
            "score": round(self.score, 6),
            "violations": list(self.violations),
            "metrics": self.metrics,
            "elapsed_ms": round(self.elapsed_ms, 4),
            "leaf_hash": self.leaf_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GateVerdict:
        return cls(
            gate_id=str(data["gate_id"]),
            gate_name=str(data["gate_name"]),
            passed=bool(data["passed"]),
            score=float(data["score"]),
            violations=list(data.get("violations", [])),
            metrics=dict(data.get("metrics", {})),
            elapsed_ms=float(data.get("elapsed_ms", 0.0)),
            leaf_hash=str(data["leaf_hash"]),
        )


@dataclass(frozen=True)
class MerkleProofStep:
    """
    Single sibling step in a binary Merkle inclusion proof path.
    `direction` indicates whether the sibling hash sits to the Left ('L') or Right ('R')
    of the running node hash during upward path reconstruction.
    """
    direction: Literal["L", "R"]
    sibling_hash: str

    def __post_init__(self) -> None:
        if self.direction not in ("L", "R"):
            raise ValueError(f"Invalid MerkleProofStep direction: {self.direction!r}; expected 'L' or 'R'")
        if len(self.sibling_hash) != 64:
            raise ValueError("sibling_hash must be a 64-character hex SHA-256 digest")

    def to_dict(self) -> dict[str, str]:
        return {"direction": self.direction, "sibling_hash": self.sibling_hash}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MerkleProofStep:
        return cls(direction=data["direction"], sibling_hash=str(data["sibling_hash"]))


@dataclass(frozen=True)
class MerkleInclusionProof:
    """
    RFC 6962 domain-separated Merkle inclusion proof for selective disclosure of a single leaf
    (e.g. proving `G5_ANTI_REWARD_HACK` passed without revealing prompts or other leaves).
    """
    leaf_name: str
    leaf_hash: str
    root_hash: str
    steps: list[MerkleProofStep]

    def to_dict(self) -> dict[str, Any]:
        return {
            "leaf_name": self.leaf_name,
            "leaf_hash": self.leaf_hash,
            "root_hash": self.root_hash,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MerkleInclusionProof:
        return cls(
            leaf_name=str(data["leaf_name"]),
            leaf_hash=str(data["leaf_hash"]),
            root_hash=str(data["root_hash"]),
            steps=[MerkleProofStep.from_dict(s) for s in data.get("steps", [])],
        )


@dataclass(frozen=True)
class AegisAttestationBundle:
    """
    Proof-Carrying Agent Certificate (`AegisAttestationBundle`).
    Contains the 7 deterministic gate verdicts, the input/output digests, the RFC 6962
    Merkle root, O(log N) selective-disclosure inclusion proofs for every leaf, and an
    HMAC-SHA256 authenticity signature.
    """
    certificate_id: str
    run_id: str
    agent_id: str
    timestamp_utc: str
    overall_passed: bool
    merkle_root: str
    input_digest: str
    output_digest: str
    gate_verdicts: list[GateVerdict]
    inclusion_proofs: dict[str, MerkleInclusionProof]
    signature_hmac: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "timestamp_utc": self.timestamp_utc,
            "overall_passed": self.overall_passed,
            "merkle_root": self.merkle_root,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "gate_verdicts": [v.to_dict() for v in self.gate_verdicts],
            "inclusion_proofs": {k: p.to_dict() for k, p in self.inclusion_proofs.items()},
            "signature_hmac": self.signature_hmac,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AegisAttestationBundle:
        return cls(
            certificate_id=str(data["certificate_id"]),
            run_id=str(data["run_id"]),
            agent_id=str(data["agent_id"]),
            timestamp_utc=str(data["timestamp_utc"]),
            overall_passed=bool(data["overall_passed"]),
            merkle_root=str(data["merkle_root"]),
            input_digest=str(data["input_digest"]),
            output_digest=str(data["output_digest"]),
            gate_verdicts=[GateVerdict.from_dict(v) for v in data.get("gate_verdicts", [])],
            inclusion_proofs={
                k: MerkleInclusionProof.from_dict(v)
                for k, v in data.get("inclusion_proofs", {}).items()
            },
            signature_hmac=str(data["signature_hmac"]),
        )
