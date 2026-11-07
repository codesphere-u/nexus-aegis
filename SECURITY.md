# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Cryptographic & Threat Model Guarantees

`nexus-aegis` enforces **RFC 6962 Domain-Separated Binary SHA-256 Merkle Trees**:
- **Leaf Prefix (`0x00`)**: Every leaf digest is computed as `SHA256(0x00 || canonical_json_bytes(payload))`.
- **Internal Node Prefix (`0x01`)**: Every internal node is computed as `SHA256(0x01 || left_32_bytes || right_32_bytes)`.
- **Constant-Time Verification**: All digest and HMAC-SHA256 comparisons use `hmac.compare_digest` to prevent timing side-channels.

## Reporting a Vulnerability

If you discover a security or cryptographic vulnerability in `nexus-aegis` (such as a gate bypass, AST anti-reward-hacking evasion, or Merkle proof verification edge case), please report it privately to **Akandwanaho Ivan Alvin** at `codesphere.innovations@gmail.com`. We respond to all verified disclosures within 48 hours.
