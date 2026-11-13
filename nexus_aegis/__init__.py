"""
NexusAegis (`nexus-aegis`) v1.0.0
Proof-Carrying Autonomous Agent Kernel & Cryptographic PR Attestation Engine.

Unifies the 7 deterministic safety, routing, concurrency, trajectory,
anti-reward-hacking, grounding, and temporal memory gates of the
Codesphere Agentic Stack into an RFC 6962 domain-separated SHA-256 Merkle
Attestation Certificate (`AegisAttestationBundle`) with selective-disclosure
inclusion proofs and an MCP Server.
"""

from nexus_aegis.benchmark import run_benchmark_suite
from nexus_aegis.gates import GATE_METADATA, SevenGatePipeline
from nexus_aegis.kernel import NexusAegisKernel, render_pr_attestation_markdown
from nexus_aegis.merkle import (
    MerkleTreeEngine,
    verify_bundle_integrity,
    verify_merkle_inclusion_proof,
)
from nexus_aegis.models import (
    AegisAttestationBundle,
    AgentRunBundle,
    GateVerdict,
    MerkleInclusionProof,
    MerkleProofStep,
    canonical_json_bytes,
    sha256_hex,
)

__version__ = "1.0.0"

__all__ = [
    "GATE_METADATA",
    "AegisAttestationBundle",
    "AgentRunBundle",
    "GateVerdict",
    "MerkleInclusionProof",
    "MerkleProofStep",
    "MerkleTreeEngine",
    "NexusAegisKernel",
    "SevenGatePipeline",
    "__version__",
    "canonical_json_bytes",
    "render_pr_attestation_markdown",
    "run_benchmark_suite",
    "sha256_hex",
    "verify_bundle_integrity",
    "verify_merkle_inclusion_proof",
]
