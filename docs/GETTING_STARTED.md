# Getting Started with NexusAegis v1.1.0

Interactive Website: https://codesphere-u.github.io/nexus-aegis/
Docs & Studio: https://codesphere-u.github.io/nexus-aegis/studio.html

## 1. Install (Python 3.11+, 0 Core Dependencies)

```bash
git clone https://github.com/codesphere-u/nexus-aegis.git
cd nexus-aegis
pip install -e .
```

Optional HTTP/ASGI extras and developer tooling:

```bash
pip install -e ".[server,dev]"
```

## 2. Run Demo, Gates & Benchmark

```bash
nexus-aegis demo
nexus-aegis gates --json
nexus-aegis benchmark
```

## 3. Embed `NexusAegisKernel` in Python

```python
from nexus_aegis import AgentRunBundle, NexusAegisKernel, render_pr_attestation_markdown

kernel = NexusAegisKernel()
cert = kernel.attest(bundle)
disclosure = kernel.extract_selective_disclosure_proof(cert, "G5_ANTI_REWARD_HACK")
assert kernel.verify_selective_disclosure(disclosure) is True
print(render_pr_attestation_markdown(cert))
```
