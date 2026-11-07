"""
NexusAegis Kernel (`NexusAegisKernel`) & Pull Request Cryptographic Attestation Renderer.

Orchestrates the 7-Gate PCAE Pipeline, builds the RFC 6962 domain-separated
SHA-256 Merkle Tree over (`INPUT_DIGEST`, `G1`..`G7`, `OUTPUT_DIGEST`), signs the
`AegisAttestationBundle` with HMAC-SHA256, extracts zero-knowledge / selective-disclosure
gate proofs, and renders GitHub Pull Request Attestation Markdown Cards.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from nexus_aegis.gates import GATE_METADATA, SevenGatePipeline
from nexus_aegis.merkle import (
    MerkleTreeEngine,
    compute_bundle_hmac,
    hash_leaf_verdict,
    verify_bundle_integrity,
    verify_merkle_inclusion_proof,
)
from nexus_aegis.models import (
    AegisAttestationBundle,
    AgentRunBundle,
    GateVerdict,
    MerkleInclusionProof,
    sha256_hex,
)

_GATE_STACK_LOOKUP: dict[str, str] = {
    item["gate_id"]: item["stack_component"] for item in GATE_METADATA
}


class NexusAegisKernel:
    """
    Proof-Carrying Autonomous Agent Kernel (`NexusAegisKernel`).
    """

    def __init__(
        self,
        secret_key: str = "nexus-aegis-default-signing-key",
        max_trajectory_steps: int = 25,
    ) -> None:
        if not secret_key:
            raise ValueError("secret_key must be non-empty")
        self._secret_key = secret_key
        self.pipeline = SevenGatePipeline(max_trajectory_steps=max_trajectory_steps)

    def attest(
        self,
        bundle: AgentRunBundle,
        timestamp_utc: str | None = None,
    ) -> AegisAttestationBundle:
        """
        Execute the 7-Gate PCAE verification pipeline on `bundle` and return a signed
        `AegisAttestationBundle` with RFC 6962 Merkle inclusion proofs for every leaf.
        """
        if timestamp_utc is None:
            timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        verdicts = self.pipeline.evaluate_all(bundle)
        overall_passed = all(v.passed for v in verdicts)

        input_digest = bundle.compute_input_digest()
        output_digest = bundle.compute_output_digest()

        input_leaf_hash = hash_leaf_verdict({"leaf_type": "INPUT_DIGEST", "digest": input_digest})
        output_leaf_hash = hash_leaf_verdict({"leaf_type": "OUTPUT_DIGEST", "digest": output_digest})

        ordered_leaves: list[tuple[str, str]] = [("INPUT_DIGEST", input_leaf_hash)]
        for verdict in verdicts:
            ordered_leaves.append((verdict.gate_id, verdict.leaf_hash))
        ordered_leaves.append(("OUTPUT_DIGEST", output_leaf_hash))

        tree = MerkleTreeEngine(ordered_leaves)
        merkle_root = tree.root_hash
        inclusion_proofs = tree.generate_all_proofs()

        cert_seed = f"{bundle.run_id}:{bundle.agent_id}:{merkle_root}:{timestamp_utc}"
        certificate_id = f"pcae-cert-{sha256_hex(cert_seed)[:16]}"

        signature_hmac = compute_bundle_hmac(
            certificate_id=certificate_id,
            run_id=bundle.run_id,
            agent_id=bundle.agent_id,
            timestamp_utc=timestamp_utc,
            overall_passed=overall_passed,
            merkle_root=merkle_root,
            input_digest=input_digest,
            output_digest=output_digest,
            secret_key=self._secret_key,
        )

        return AegisAttestationBundle(
            certificate_id=certificate_id,
            run_id=bundle.run_id,
            agent_id=bundle.agent_id,
            timestamp_utc=timestamp_utc,
            overall_passed=overall_passed,
            merkle_root=merkle_root,
            input_digest=input_digest,
            output_digest=output_digest,
            gate_verdicts=verdicts,
            inclusion_proofs=inclusion_proofs,
            signature_hmac=signature_hmac,
        )

    def verify_bundle(self, attestation: AegisAttestationBundle) -> tuple[bool, list[str]]:
        """Verify full cryptographic integrity and HMAC signature of an `AegisAttestationBundle`."""
        return verify_bundle_integrity(attestation, secret_key=self._secret_key)

    @staticmethod
    def extract_selective_disclosure_proof(
        attestation: AegisAttestationBundle,
        gate_id: str,
    ) -> dict[str, Any]:
        """
        Extract a redacted, selective-disclosure proof package for a single gate
        (e.g. `G5_ANTI_REWARD_HACK`). Allows an external CI auditor to verify that
        the gate passed and is cryptographically bound to `merkle_root` without
        exposing task prompts, proprietary code patches, or other gate telemetry.
        """
        matching_verdicts = [v for v in attestation.gate_verdicts if v.gate_id == gate_id]
        if not matching_verdicts:
            raise KeyError(f"Gate {gate_id!r} not found in attestation bundle")
        verdict = matching_verdicts[0]
        proof = attestation.inclusion_proofs[gate_id]
        return {
            "certificate_id": attestation.certificate_id,
            "run_id": attestation.run_id,
            "agent_id": attestation.agent_id,
            "merkle_root": attestation.merkle_root,
            "disclosed_gate_verdict": verdict.to_dict(),
            "inclusion_proof": proof.to_dict(),
        }

    @staticmethod
    def verify_selective_disclosure(disclosure_payload: dict[str, Any]) -> bool:
        """
        Verify a selective-disclosure gate proof package against its claimed `merkle_root`.
        Checks both:
        1. `hash_leaf_verdict(verdict.canonical_verdict_payload()) == proof.leaf_hash`
        2. The O(log N) RFC 6962 `MerkleInclusionProof` reconstructs `merkle_root`.
        """
        try:
            merkle_root = str(disclosure_payload["merkle_root"])
            verdict = GateVerdict.from_dict(disclosure_payload["disclosed_gate_verdict"])
            proof = MerkleInclusionProof.from_dict(disclosure_payload["inclusion_proof"])
        except (KeyError, TypeError, ValueError):
            return False

        if verdict.gate_id != proof.leaf_name:
            return False
        if verdict.leaf_hash != proof.leaf_hash:
            return False

        return verify_merkle_inclusion_proof(
            proof=proof,
            expected_root_hash=merkle_root,
            expected_leaf_payload=verdict.canonical_verdict_payload(),
        )


def render_pr_attestation_markdown(attestation: AegisAttestationBundle) -> str:
    """
    Render a drop-in GitHub Pull Request Cryptographic Attestation Markdown Card
    for CI pipelines (`render_pr_attestation_markdown`).
    """
    status_icon = "PASSED (VERIFIED)" if attestation.overall_passed else "BLOCKED (VIOLATION DETECTED)"
    badge = "🟢 **PCAE ATTESTATION: PASSED**" if attestation.overall_passed else "🔴 **PCAE ATTESTATION: BLOCKED**"
    total_ms = sum(v.elapsed_ms for v in attestation.gate_verdicts)

    lines: list[str] = [
        f"## 🛡️ NexusAegis Proof-Carrying Agent Execution (PCAE) Certificate",
        "",
        f"{badge} — `{status_icon}`",
        "",
        "| Field | Cryptographic Value |",
        "| :--- | :--- |",
        f"| **Certificate ID** | `{attestation.certificate_id}` |",
        f"| **Run ID / Agent ID** | `{attestation.run_id}` / `{attestation.agent_id}` |",
        f"| **Timestamp (UTC)** | `{attestation.timestamp_utc}` |",
        f"| **RFC 6962 Merkle Root** | `{attestation.merkle_root}` |",
        f"| **Task Input Digest** | `{attestation.input_digest[:24]}...` |",
        f"| **Agent Output Digest** | `{attestation.output_digest[:24]}...` |",
        f"| **HMAC-SHA256 Signature** | `{attestation.signature_hmac[:24]}...` |",
        f"| **Total Verification Latency** | `{total_ms:.3f} ms` |",
        "",
        "### 7-Gate Deterministic Verification Matrix",
        "",
        "| Gate ID | Codesphere Engine | Verdict | Score | Latency | RFC 6962 Leaf Hash (`0x00`) |",
        "| :--- | :--- | :--- | :---: | :---: | :--- |",
    ]

    all_violations: list[tuple[str, str]] = []
    for v in attestation.gate_verdicts:
        engine_repo = _GATE_STACK_LOOKUP.get(v.gate_id, "codesphere-u/nexus-aegis")
        verdict_cell = "✅ `PASS`" if v.passed else "❌ `FAIL`"
        lines.append(
            f"| `{v.gate_id}` | `{engine_repo}` | {verdict_cell} | `{v.score:.2f}` | "
            f"`{v.elapsed_ms:.3f} ms` | `{v.leaf_hash[:16]}...` |"
        )
        for viol in v.violations:
            all_violations.append((v.gate_id, viol))

    if all_violations:
        lines.extend(
            [
                "",
                "### 🚨 Deterministic Policy Violations Blocked",
                "",
            ]
        )
        for gate_id, viol in all_violations:
            lines.append(f"- **`{gate_id}`**: `{viol}`")
    else:
        lines.extend(
            [
                "",
                "> **Zero-Knowledge / Selective Disclosure Ready:** Any single gate verdict above can be "
                "independently verified against the RFC 6962 Merkle Root (`O(log N)` = 4 sibling hashes) "
                "using `nexus-aegis verify-proof` without disclosing proprietary prompts or workspace diffs.",
            ]
        )

    return "\n".join(lines) + "\n"
