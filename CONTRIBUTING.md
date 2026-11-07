# Contributing to NexusAegis (`nexus-aegis`)

Thank you for contributing to **NexusAegis**, the Proof-Carrying Autonomous Agent Kernel & Cryptographic PR Attestation Engine.

## Development Workflow

1. Clone the repository and install in editable mode with development dependencies:
   ```bash
   git clone https://github.com/codesphere-u/nexus-aegis.git
   cd nexus-aegis
   pip install -e ".[dev]"
   ```
2. Run the full 77-test suite and 35-scenario benchmark:
   ```bash
   pytest -v
   nexus-aegis benchmark
   ```

## Architectural Rules for New Verification Rules

- **Zero External Runtime Dependencies**: All core gate evaluators, AST analyzers, and Merkle tree primitives must use the Python 3.11+ standard library (`hashlib`, `hmac`, `ast`, `fnmatch`, `re`, `json`).
- **Wall-Clock Independence**: `GateVerdict.leaf_hash` must never include wall-clock timing (`elapsed_ms`) so that Merkle roots remain 100% deterministic across machines and CI runners.
- **Sub-Millisecond Latency**: Full 7-gate evaluation plus RFC 6962 Merkle tree attestation must maintain a P50 latency below `0.5 ms`.
