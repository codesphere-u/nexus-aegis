# Changelog

All notable changes to `nexus-aegis` will be documented in this file.

## [1.0.0] - 2026-11-07

### Added
- **Proof-Carrying Agent Execution (PCAE) Kernel (`NexusAegisKernel`)**: Orchestrates the 7 deterministic safety, routing, concurrency, trajectory, anti-reward-hacking, grounding, and temporal memory gates across the Codesphere Agentic Stack.
- **RFC 6962 Domain-Separated Binary SHA-256 Merkle Tree Engine (`MerkleTreeEngine`)**: Implements `0x00` leaf domain separation and `0x01` internal node domain separation with `O(log N)` selective-disclosure inclusion proofs (`verify_merkle_inclusion_proof`).
- **7-Gate Deterministic Verification Pipeline (`SevenGatePipeline`)**:
  - `G1_SECURITY` (`AgentShield`): Direct/indirect prompt injection, Base64/zero-width smuggling, cloud metadata SSRF (`169.254.169.254`), and sensitive credential access detection.
  - `G2_BUDGET_ROUTING` (`SynapseRouter`): USD budget enforcement, 120k token ceiling, and frontier-model over-provisioning detection on trivial tasks.
  - `G3_SWARM_LEASES` (`SwarmWeaver`): Multi-agent `exclusive_write` and `shared_read` glob lease collision detection.
  - `G4_TRAJECTORY_HEALTH` (`AgentFlight`): `A<->B` tool oscillation loop detection, consecutive tool failure detection, and MCP schema validation.
  - `G5_ANTI_REWARD_HACK` (`PatchPilot`): Python `ast` diff inspector blocking deleted `test_*` functions, weakened assertions, `assert True` tautologies, `@pytest.mark.skip` injection, `PYTEST_CURRENT_TEST` env snooping, and bare `except: pass` blocks.
  - `G6_TRUTH_GROUNDING` (`TruthGate`): Clause-local citation grounding checking phantom citations, antonym/negation polarity flips, numeric metric drift, and hallucinated workspace AST symbols.
  - `G7_TEMPORAL_MEMORY` (`Cortex-MCP`): Bi-temporal fact freshness verification blocking expired (`valid_until != None`) or superseded (`superseded_by != None`) facts.
- **GitHub Pull Request Attestation Markdown Card Renderer (`render_pr_attestation_markdown`)**.
- **35-Scenario Multi-Agent Benchmark Suite (`run_benchmark_suite`)**: `100.0%` adversarial detection recall (`25/25`), `0.0%` clean false-positive rate (`0/10`), `100.0%` selective-disclosure proof accuracy (`245/245`), and `0.27 ms` P50 pipeline + Merkle attestation latency.
- **JSON-RPC 2.0 Stdio MCP Server (`nexus-aegis mcp`)** & full CLI (`demo`, `attest`, `verify-proof`, `gates`, `benchmark`).
