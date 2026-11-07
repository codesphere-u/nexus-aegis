"""
NexusAegis (`nexus-aegis`) v1.0.0
Proof-Carrying Autonomous Agent Kernel & Cryptographic PR Attestation Engine.

Unifies the 7 deterministic safety, routing, concurrency, trajectory,
anti-reward-hacking, grounding, and temporal memory gates of the
Codesphere Agentic Stack into an RFC 6962 domain-separated SHA-256 Merkle
Attestation Certificate (`AegisAttestationBundle`) with selective-disclosure
inclusion proofs and an MCP Server.
"""

from nexus_aegis.models import (
    AgentRunBundle,
    GateVerdict,
    MerkleProofStep,
    MerkleInclusionProof,
    AegisAttestationBundle,
    canonical_json_bytes,
    sha256_hex,
)
from nexus_aegis.merkle import (
    MerkleTreeEngine,
    verify_merkle_inclusion_proof,
    verify_bundle_integrity,
)
from nexus_aegis.gates import SevenGatePipeline, GATE_METADATA
from nexus_aegis.kernel import NexusAegisKernel, render_pr_attestation_markdown
from nexus_aegis.benchmark import run_benchmark_suite

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "AgentRunBundle",
    "GateVerdict",
    "MerkleProofStep",
    "MerkleInclusionProof",
    "AegisAttestationBundle",
    "canonical_json_bytes",
    "sha256_hex",
    "MerkleTreeEngine",
    "verify_merkle_inclusion_proof",
    "verify_bundle_integrity",
    "SevenGatePipeline",
    "GATE_METADATA",
    "NexusAegisKernel",
    "render_pr_attestation_markdown",
    "run_benchmark_suite",
]
