# MCP Server, HTTP Portal & Selective-Disclosure Attestation

## 1. CLI Attestation & Offline Proof Verification

```bash
nexus-aegis attest run_bundle.json --markdown > pr_card.md
nexus-aegis attest run_bundle.json --disclose-gate G5_ANTI_REWARD_HACK > g5_proof.json
nexus-aegis verify-proof g5_proof.json --root <64-hex-merkle-root>
```

## 2. Stdio JSON-RPC 2.0 MCP Server (`2024-11-05`)

```bash
nexus-aegis mcp
```

- Tools: `aegis_attest_agent_run`, `aegis_verify_merkle_proof`, `aegis_list_gates`, `aegis_run_benchmark`.
- Resources: `aegis://gates/catalog`, `aegis://merkle/rfc6962-spec`, `aegis://benchmark/summary`, `aegis://gates/{gate_id}`.
- Prompts: `audit-agent-pr`, `verify-selective-disclosure`, `remediate-gate-violation`.

## 3. Streamable HTTP/SSE Portal & REST API

```bash
nexus-aegis serve-http --host 127.0.0.1 --port 8000
```

Routes: `/`, `/health`, `/healthz`, `/readyz`, `/info`, `/metrics`, `POST /mcp`, `GET /mcp`, `POST /messages`, `GET /api/gates`, `GET|POST /api/demo`, `POST /api/attest`, `POST /api/verify-proof`, `GET|POST /api/benchmark`.
