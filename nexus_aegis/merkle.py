"""
RFC 6962 Domain-Separated Binary SHA-256 Merkle Tree Engine (`MerkleTreeEngine`).

Implements:
- Leaf domain separation (`SHA256(0x00 || leaf_payload_bytes)`)
- Internal node domain separation (`SHA256(0x01 || left_bytes || right_bytes)`)
  to prevent second-preimage attacks where an attacker substitutes a 64-byte leaf
  for two concatenated 32-byte child digests.
- O(log N) Merkle inclusion proof construction and standalone verification
  (`verify_merkle_inclusion_proof`) for zero-knowledge / selective-disclosure audits.
- Full cryptographic bundle integrity & HMAC-SHA256 signature verification
  (`verify_bundle_integrity`).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from nexus_aegis.models import (
    AegisAttestationBundle,
    MerkleInclusionProof,
    MerkleProofStep,
    canonical_json_bytes,
)

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def hash_leaf_bytes(payload_bytes: bytes) -> str:
    """
    Compute RFC 6962 domain-separated leaf hash:
        H_leaf(d) = SHA-256(0x00 || d)
    Returns 64-char lowercase hex string.
    """
    return hashlib.sha256(LEAF_PREFIX + payload_bytes).hexdigest()


def hash_leaf_verdict(verdict_payload: dict[str, Any]) -> str:
    """
    Compute RFC 6962 leaf hash over a canonical JSON gate verdict or digest descriptor.
    """
    return hash_leaf_bytes(canonical_json_bytes(verdict_payload))


def hash_internal_node(left_hex: str, right_hex: str) -> str:
    """
    Compute RFC 6962 domain-separated internal node hash:
        H_node(L, R) = SHA-256(0x01 || bytes.fromhex(L) || bytes.fromhex(R))
    Using raw 32-byte digest concatenation prefixed by 0x01 guarantees strict
    domain separation between leaves and internal nodes.
    """
    left_bytes = bytes.fromhex(left_hex)
    right_bytes = bytes.fromhex(right_hex)
    if len(left_bytes) != 32 or len(right_bytes) != 32:
        raise ValueError("Internal node children must be 32-byte (64-hex-char) SHA-256 digests")
    return hashlib.sha256(NODE_PREFIX + left_bytes + right_bytes).hexdigest()


class MerkleTreeEngine:
    """
    Constructs a binary RFC 6962 domain-separated SHA-256 Merkle tree over named leaves
    and produces O(log N) inclusion proofs for selective-disclosure verification.

    When a tree level has an odd number of nodes (> 1), the trailing odd node is
    paired with itself via a domain-separated internal node hash (`H_node(last, last)`)
    so every leaf has a uniform, deterministic inclusion path to the root.
    """

    def __init__(self, ordered_leaves: list[tuple[str, str]]) -> None:
        """
        Initialize the Merkle tree from an ordered list of `(leaf_name, leaf_hash_hex)` pairs.
        """
        if not ordered_leaves:
            raise ValueError("Cannot construct MerkleTreeEngine with zero leaves")

        seen_names: set[str] = set()
        for name, digest in ordered_leaves:
            if not name:
                raise ValueError("Leaf name must be non-empty")
            if name in seen_names:
                raise ValueError(f"Duplicate leaf name in Merkle tree: {name!r}")
            seen_names.add(name)
            try:
                raw = bytes.fromhex(digest)
            except ValueError as exc:
                raise ValueError(f"Invalid hex digest for leaf {name!r}") from exc
            if len(raw) != 32:
                raise ValueError(f"Leaf {name!r} digest must be 32 bytes (64 hex chars)")

        self._ordered_leaves: list[tuple[str, str]] = list(ordered_leaves)
        self._leaf_index_by_name: dict[str, int] = {
            name: idx for idx, (name, _) in enumerate(self._ordered_leaves)
        }
        self._levels: list[list[str]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        current_level = [digest for _, digest in self._ordered_leaves]
        self._levels = [current_level]

        while len(current_level) > 1:
            next_level: list[str] = []
            n = len(current_level)
            for i in range(0, n, 2):
                left = current_level[i]
                right = current_level[i + 1] if (i + 1) < n else current_level[i]
                next_level.append(hash_internal_node(left, right))
            self._levels.append(next_level)
            current_level = next_level

    @property
    def root_hash(self) -> str:
        """Return the 64-character hex SHA-256 Merkle root."""
        return self._levels[-1][0]

    @property
    def leaf_names(self) -> list[str]:
        return [name for name, _ in self._ordered_leaves]

    @property
    def levels(self) -> list[list[str]]:
        return [list(level) for level in self._levels]

    def generate_inclusion_proof(self, leaf_name: str) -> MerkleInclusionProof:
        """
        Generate an O(log N) `MerkleInclusionProof` for `leaf_name`.
        """
        if leaf_name not in self._leaf_index_by_name:
            raise KeyError(f"Unknown leaf name: {leaf_name!r}")

        idx = self._leaf_index_by_name[leaf_name]
        leaf_hash = self._ordered_leaves[idx][1]
        steps: list[MerkleProofStep] = []

        for level in self._levels[:-1]:
            n = len(level)
            if idx % 2 == 0:
                sibling_idx = idx + 1 if (idx + 1) < n else idx
                steps.append(MerkleProofStep(direction="R", sibling_hash=level[sibling_idx]))
            else:
                sibling_idx = idx - 1
                steps.append(MerkleProofStep(direction="L", sibling_hash=level[sibling_idx]))
            idx //= 2

        return MerkleInclusionProof(
            leaf_name=leaf_name,
            leaf_hash=leaf_hash,
            root_hash=self.root_hash,
            steps=steps,
        )

    def generate_all_proofs(self) -> dict[str, MerkleInclusionProof]:
        """Generate inclusion proofs for all leaves in the tree."""
        return {name: self.generate_inclusion_proof(name) for name, _ in self._ordered_leaves}


def verify_merkle_inclusion_proof(
    proof: MerkleInclusionProof,
    expected_root_hash: str | None = None,
    expected_leaf_payload: dict[str, Any] | None = None,
) -> bool:
    """
    Standalone O(log N) verifier for an RFC 6962 `MerkleInclusionProof`.

    Supports selective-disclosure / zero-knowledge gate auditing:
    - Recomputes the upward path from `proof.leaf_hash` through `proof.steps` using
      domain-separated internal node hashing (`0x01`).
    - If `expected_root_hash` is provided, checks that the reconstructed root equals
      both `proof.root_hash` and `expected_root_hash`.
    - If `expected_leaf_payload` (e.g. `gate_verdict.canonical_verdict_payload()`) is
      provided, also verifies that `hash_leaf_verdict(expected_leaf_payload) == proof.leaf_hash`.
    """
    try:
        raw_leaf = bytes.fromhex(proof.leaf_hash)
        if len(raw_leaf) != 32:
            return False
    except ValueError:
        return False

    if expected_leaf_payload is not None:
        recomputed_leaf = hash_leaf_verdict(expected_leaf_payload)
        if not hmac.compare_digest(recomputed_leaf, proof.leaf_hash):
            return False

    current = proof.leaf_hash
    for step in proof.steps:
        try:
            if step.direction == "R":
                current = hash_internal_node(current, step.sibling_hash)
            elif step.direction == "L":
                current = hash_internal_node(step.sibling_hash, current)
            else:
                return False
        except ValueError:
            return False

    if not hmac.compare_digest(current, proof.root_hash):
        return False

    return not (expected_root_hash is not None and not hmac.compare_digest(current, expected_root_hash))


def compute_bundle_hmac(
    certificate_id: str,
    run_id: str,
    agent_id: str,
    timestamp_utc: str,
    overall_passed: bool,
    merkle_root: str,
    input_digest: str,
    output_digest: str,
    secret_key: str,
) -> str:
    """Compute canonical HMAC-SHA256 signature over the attestation header and Merkle root."""
    signing_payload = {
        "certificate_id": certificate_id,
        "run_id": run_id,
        "agent_id": agent_id,
        "timestamp_utc": timestamp_utc,
        "overall_passed": overall_passed,
        "merkle_root": merkle_root,
        "input_digest": input_digest,
        "output_digest": output_digest,
    }
    return hmac.new(
        secret_key.encode("utf-8"),
        canonical_json_bytes(signing_payload),
        hashlib.sha256,
    ).hexdigest()


def verify_bundle_integrity(
    bundle: AegisAttestationBundle,
    secret_key: str = "nexus-aegis-default-signing-key",
) -> tuple[bool, list[str]]:
    """
    Perform a complete cryptographic integrity audit on an `AegisAttestationBundle`:
    1. Verify each GateVerdict's `leaf_hash` matches its canonical RFC 6962 `0x00` leaf hash.
    2. Rebuild the Merkle tree from `INPUT_DIGEST`, the 7 `GateVerdict` leaves, and `OUTPUT_DIGEST`,
       and confirm the reconstructed root matches `bundle.merkle_root`.
    3. Verify every `MerkleInclusionProof` in `bundle.inclusion_proofs` against `bundle.merkle_root`.
    4. Confirm `bundle.overall_passed` equals `all(v.passed for v in bundle.gate_verdicts)`.
    5. Verify `bundle.signature_hmac` using constant-time HMAC-SHA256 comparison.
    """
    errors: list[str] = []

    if len(bundle.gate_verdicts) != 7:
        errors.append(f"Expected 7 gate verdicts, found {len(bundle.gate_verdicts)}")

    expected_overall = all(v.passed for v in bundle.gate_verdicts) and len(bundle.gate_verdicts) == 7
    if bundle.overall_passed != expected_overall:
        errors.append(
            f"overall_passed mismatch: bundle has {bundle.overall_passed}, "
            f"gate verdicts evaluate to {expected_overall}"
        )

    input_leaf_hash = hash_leaf_verdict({"leaf_type": "INPUT_DIGEST", "digest": bundle.input_digest})
    output_leaf_hash = hash_leaf_verdict({"leaf_type": "OUTPUT_DIGEST", "digest": bundle.output_digest})

    ordered_leaves: list[tuple[str, str]] = [("INPUT_DIGEST", input_leaf_hash)]

    for verdict in bundle.gate_verdicts:
        expected_leaf = hash_leaf_verdict(verdict.canonical_verdict_payload())
        if not hmac.compare_digest(expected_leaf, verdict.leaf_hash):
            errors.append(
                f"Tampered gate verdict leaf_hash for {verdict.gate_id}: "
                f"expected {expected_leaf}, got {verdict.leaf_hash}"
            )
        ordered_leaves.append((verdict.gate_id, verdict.leaf_hash))

    ordered_leaves.append(("OUTPUT_DIGEST", output_leaf_hash))

    try:
        engine = MerkleTreeEngine(ordered_leaves)
        if not hmac.compare_digest(engine.root_hash, bundle.merkle_root):
            errors.append(
                f"Merkle root mismatch: recomputed {engine.root_hash}, bundle has {bundle.merkle_root}"
            )
    except ValueError as exc:
        errors.append(f"Merkle tree reconstruction failed: {exc}")

    for leaf_name, expected_hash in ordered_leaves:
        proof = bundle.inclusion_proofs.get(leaf_name)
        if proof is None:
            errors.append(f"Missing inclusion proof for leaf {leaf_name}")
            continue
        if not hmac.compare_digest(proof.leaf_hash, expected_hash):
            errors.append(f"Inclusion proof leaf_hash mismatch for {leaf_name}")
        if not verify_merkle_inclusion_proof(proof, expected_root_hash=bundle.merkle_root):
            errors.append(f"Invalid MerkleInclusionProof path for {leaf_name}")

    expected_hmac = compute_bundle_hmac(
        certificate_id=bundle.certificate_id,
        run_id=bundle.run_id,
        agent_id=bundle.agent_id,
        timestamp_utc=bundle.timestamp_utc,
        overall_passed=bundle.overall_passed,
        merkle_root=bundle.merkle_root,
        input_digest=bundle.input_digest,
        output_digest=bundle.output_digest,
        secret_key=secret_key,
    )
    if not hmac.compare_digest(expected_hmac, bundle.signature_hmac):
        errors.append("Invalid HMAC-SHA256 signature on AegisAttestationBundle")

    return (len(errors) == 0, errors)
