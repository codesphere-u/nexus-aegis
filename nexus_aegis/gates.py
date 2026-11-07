"""
Seven-Gate Deterministic Verification Pipeline (`SevenGatePipeline`) for
Proof-Carrying Agent Execution (PCAE).

Unifies the 7 core verification algorithms of the Codesphere Agentic Stack:
- G1_SECURITY        -> AgentShield (Direct/indirect prompt injection, smuggling, SSRF/exfil tool calls)
- G2_BUDGET_ROUTING  -> SynapseRouter (USD budget cap, token efficiency, frontier model over-provisioning)
- G3_SWARM_LEASES    -> SwarmWeaver (Multi-agent file lock & glob lease collision detection)
- G4_TRAJECTORY_HEALTH -> AgentFlight (A<->B tool oscillation loops, repeated failures, schema errors)
- G5_ANTI_REWARD_HACK -> PatchPilot (AST diff audit blocking deleted tests, `assert True`, skip injection, bare except)
- G6_TRUTH_GROUNDING -> TruthGate (Phantom citations, negation polarity flips, numeric drift, phantom AST symbols)
- G7_TEMPORAL_MEMORY -> Cortex-MCP (Bi-temporal memory check blocking superseded/expired architectural facts)
"""

from __future__ import annotations

import ast
import base64
import fnmatch
import re
import time
from typing import Any

from nexus_aegis.merkle import hash_leaf_verdict
from nexus_aegis.models import AgentRunBundle, GateVerdict


GATE_METADATA: list[dict[str, str]] = [
    {
        "gate_id": "G1_SECURITY",
        "gate_name": "AgentShield Security & Injection Gate",
        "stack_component": "codesphere-u/agentshield",
        "invariant": "Zero prompt injections, zero-width/Base64 smuggling, SSRF, or credential exfiltration tool calls.",
    },
    {
        "gate_id": "G2_BUDGET_ROUTING",
        "gate_name": "SynapseRouter Cost & Tier Efficiency Gate",
        "stack_component": "codesphere-u/synapse-router",
        "invariant": "Execution cost within USD budget cap, bounded token burn, and no frontier model over-provisioning on trivial tasks.",
    },
    {
        "gate_id": "G3_SWARM_LEASES",
        "gate_name": "SwarmWeaver Concurrency Lease Gate",
        "stack_component": "codesphere-u/swarmweaver",
        "invariant": "Zero write-write or read-write file glob lock collisions against active peer subagent leases.",
    },
    {
        "gate_id": "G4_TRAJECTORY_HEALTH",
        "gate_name": "AgentFlight Trajectory & Loop Health Gate",
        "stack_component": "codesphere-u/agentflight",
        "invariant": "Zero A<->B tool oscillation loops, bounded consecutive tool errors, and valid MCP tool schemas.",
    },
    {
        "gate_id": "G5_ANTI_REWARD_HACK",
        "gate_name": "PatchPilot AST Anti-Reward-Hacking Gate",
        "stack_component": "codesphere-u/patchpilot",
        "invariant": "Zero deleted unit tests, weakened assertions, `assert True` tautologies, skip decorators, or swallowed exceptions.",
    },
    {
        "gate_id": "G6_TRUTH_GROUNDING",
        "gate_name": "TruthGate Epistemic & AST Grounding Gate",
        "stack_component": "codesphere-u/truthgate",
        "invariant": "Zero phantom citations, negation/antonym polarity inversions, numeric metric drift, or hallucinated workspace AST symbols.",
    },
    {
        "gate_id": "G7_TEMPORAL_MEMORY",
        "gate_name": "Cortex-MCP Temporal Memory Freshness Gate",
        "stack_component": "codesphere-u/cortex-mcp",
        "invariant": "Zero reliance on expired (`valid_until != None`) or superseded (`superseded_by != None`) bi-temporal facts.",
    },
]


# Pre-compiled patterns for sub-millisecond gate execution
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "prompt_injection_override",
        re.compile(
            r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
            r"disregard\s+(?:all\s+)?(?:system|safety|prior)\s+(?:rules|instructions|directives)|"
            r"system\s+override\s*:|"
            r"you\s+are\s+now\s+in\s+(?:developer|dan|unrestricted|god)\s+mode|"
            r"<\|im_start\|>\s*system|"
            r"\[system\s*override\])",
            re.IGNORECASE,
        ),
    ),
    (
        "secret_exfiltration_directive",
        re.compile(
            r"(?:exfiltrate|upload|post|send)\s+(?:the\s+)?(?:contents\s+of\s+)?(?:\.env|\.ssh|id_rsa|/etc/shadow|aws_secret_access_key)",
            re.IGNORECASE,
        ),
    ),
]

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")

_DANGEROUS_COMMAND_RE = re.compile(
    r"(?:rm\s+-rf\s+(?:/|~|\*)|"
    r"169\.254\.169\.254|"
    r"metadata\.google\.internal|"
    r"curl\s+[^\n|]*\|\s*(?:ba)?sh|"
    r"wget\s+[^\n|]*\|\s*(?:ba)?sh|"
    r"/etc/shadow|"
    r"\.ssh/id_rsa|"
    r"cat\s+[^\n]*\.env\b)",
    re.IGNORECASE,
)

_SENSITIVE_PATHS_RE = re.compile(
    r"(?:^|/)(?:\.env(?:\.local|\.production)?|id_rsa|shadow|credentials\.json)$",
    re.IGNORECASE,
)

_CITATION_RE = re.compile(r"\[(doc_[A-Za-z0-9_-]+|src_[A-Za-z0-9_-]+|ctx_[A-Za-z0-9_-]+|ref_[A-Za-z0-9_-]+)\]")
_NUMBER_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])(\$?\d+(?:,\d{3})*(?:\.\d+)?%?)(?![A-Za-z0-9_])")
_BACKTICK_SYMBOL_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\(\)`")

_POLARITY_ANTONYM_PAIRS: list[tuple[str, str, re.Pattern[str], re.Pattern[str]]] = [
    (
        pos,
        neg,
        re.compile(rf"\b{re.escape(pos)}\b"),
        re.compile(rf"\b{re.escape(neg)}\b"),
    )
    for pos, neg in [
        ("enabled", "disabled"),
        ("required", "optional"),
        ("mandatory", "optional"),
        ("encrypted", "unencrypted"),
        ("authenticated", "unauthenticated"),
        ("allowed", "prohibited"),
        ("permitted", "forbidden"),
        ("passed", "failed"),
        ("safe", "unsafe"),
        ("compliant", "non-compliant"),
        ("decreased", "increased"),
        ("reduced", "increased"),
        ("immutable", "mutable"),
        ("synchronous", "asynchronous"),
        ("deterministic", "non-deterministic"),
    ]
]

_CLAUSE_SPLIT_RE = re.compile(
    r"([^[\]]+?\[(?:doc_[A-Za-z0-9_-]+|src_[A-Za-z0-9_-]+|ctx_[A-Za-z0-9_-]+|ref_[A-Za-z0-9_-]+)\])"
)
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")

_FRONTIER_MODELS = {
    "claude-3-opus",
    "claude-opus-4",
    "gpt-4-32k",
    "o1-pro",
    "gpt-4.5-preview",
}

_TRIVIAL_TASK_HINTS_RE = re.compile(
    r"\b(?:fix\s+typo|format\s+readme|bump\s+version\s+string|rename\s+comment|whitespace\s+cleanup|trivial\s+task)\b",
    re.IGNORECASE,
)


def _build_verdict(
    gate_id: str,
    gate_name: str,
    violations: list[str],
    metrics: dict[str, Any],
    start_ns: int,
) -> GateVerdict:
    passed = len(violations) == 0
    score = max(0.0, round(1.0 - 0.25 * len(violations), 4)) if not passed else 1.0
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
    payload = {
        "gate_id": gate_id,
        "gate_name": gate_name,
        "passed": passed,
        "score": round(score, 6),
        "violations": list(violations),
        "metrics": metrics,
    }
    leaf_hash = hash_leaf_verdict(payload)
    return GateVerdict(
        gate_id=gate_id,
        gate_name=gate_name,
        passed=passed,
        score=score,
        violations=violations,
        metrics=metrics,
        elapsed_ms=elapsed_ms,
        leaf_hash=leaf_hash,
    )


class SevenGatePipeline:
    """
    Executes all 7 deterministic verification gates over an `AgentRunBundle`.
    """

    def __init__(self, max_trajectory_steps: int = 25) -> None:
        self.max_trajectory_steps = max_trajectory_steps

    def evaluate_all(self, bundle: AgentRunBundle) -> list[GateVerdict]:
        """Run all 7 gates in canonical order G1..G7 and return their deterministic `GateVerdict`s."""
        return [
            self.evaluate_g1_security(bundle),
            self.evaluate_g2_budget_routing(bundle),
            self.evaluate_g3_swarm_leases(bundle),
            self.evaluate_g4_trajectory_health(bundle),
            self.evaluate_g5_anti_reward_hack(bundle),
            self.evaluate_g6_truth_grounding(bundle),
            self.evaluate_g7_temporal_memory(bundle),
        ]

    # ------------------------------------------------------------------
    # GATE 1: G1_SECURITY (AgentShield)
    # ------------------------------------------------------------------
    def evaluate_g1_security(self, bundle: AgentRunBundle) -> GateVerdict:
        start_ns = time.perf_counter_ns()
        violations: list[str] = []

        texts_to_scan: list[tuple[str, str]] = [("task_prompt", bundle.task_prompt)]
        for idx, ctx in enumerate(bundle.retrieved_context):
            ctx_id = str(ctx.get("id", f"ctx_{idx}"))
            ctx_text = str(ctx.get("text", ctx.get("content", "")))
            texts_to_scan.append((f"retrieved_context[{ctx_id}]", ctx_text))

        injection_hits = 0
        smuggling_hits = 0
        dangerous_tool_hits = 0

        for source_label, text in texts_to_scan:
            for rule_name, pattern in _INJECTION_PATTERNS:
                if pattern.search(text):
                    injection_hits += 1
                    violations.append(f"G1:{rule_name} detected in {source_label}")

            if _ZERO_WIDTH_RE.search(text):
                smuggling_hits += 1
                violations.append(f"G1:zero_width_smuggling detected in {source_label}")

            for b64_match in _BASE64_CANDIDATE_RE.findall(text):
                try:
                    decoded = base64.b64decode(b64_match, validate=True).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if any(p.search(decoded) for _, p in _INJECTION_PATTERNS) or _DANGEROUS_COMMAND_RE.search(decoded):
                    smuggling_hits += 1
                    violations.append(f"G1:base64_payload_smuggling detected in {source_label}")

        for step_idx, step in enumerate(bundle.tool_trajectory):
            tool_name = str(step.get("tool", ""))
            args_str = str(step.get("args", ""))
            combined = f"{tool_name} {args_str}"
            if _DANGEROUS_COMMAND_RE.search(combined):
                dangerous_tool_hits += 1
                violations.append(f"G1:dangerous_tool_invocation in step {step_idx} ({tool_name})")

        for fpath in list(bundle.file_reads) + list(bundle.file_writes):
            if _SENSITIVE_PATHS_RE.search(fpath):
                dangerous_tool_hits += 1
                violations.append(f"G1:sensitive_credential_file_access on {fpath!r}")

        metrics = {
            "scanned_sources": len(texts_to_scan),
            "injection_hits": injection_hits,
            "smuggling_hits": smuggling_hits,
            "dangerous_tool_hits": dangerous_tool_hits,
        }
        return _build_verdict(
            "G1_SECURITY",
            "AgentShield Security & Injection Gate",
            violations,
            metrics,
            start_ns,
        )

    # ------------------------------------------------------------------
    # GATE 2: G2_BUDGET_ROUTING (SynapseRouter)
    # ------------------------------------------------------------------
    def evaluate_g2_budget_routing(self, bundle: AgentRunBundle) -> GateVerdict:
        start_ns = time.perf_counter_ns()
        violations: list[str] = []

        utilization = round(bundle.cost_usd / bundle.budget_cap_usd, 4)
        if bundle.cost_usd > bundle.budget_cap_usd:
            violations.append(
                f"G2:budget_cap_exceeded: cost_usd=${bundle.cost_usd:.4f} > budget_cap_usd=${bundle.budget_cap_usd:.4f}"
            )

        if bundle.tokens_used > 120_000:
            violations.append(
                f"G2:token_budget_runaway: tokens_used={bundle.tokens_used} exceeds 120,000 token ceiling"
            )

        is_trivial_task = bool(_TRIVIAL_TASK_HINTS_RE.search(bundle.task_prompt))
        is_frontier_model = bundle.model_id.lower() in _FRONTIER_MODELS
        if is_trivial_task and is_frontier_model:
            violations.append(
                f"G2:frontier_model_overprovisioned: model={bundle.model_id!r} used on trivial task"
            )

        metrics = {
            "cost_usd": round(bundle.cost_usd, 6),
            "budget_cap_usd": round(bundle.budget_cap_usd, 6),
            "budget_utilization_ratio": utilization,
            "tokens_used": bundle.tokens_used,
            "model_id": bundle.model_id,
            "trivial_task_detected": is_trivial_task,
        }
        return _build_verdict(
            "G2_BUDGET_ROUTING",
            "SynapseRouter Cost & Tier Efficiency Gate",
            violations,
            metrics,
            start_ns,
        )

    # ------------------------------------------------------------------
    # GATE 3: G3_SWARM_LEASES (SwarmWeaver)
    # ------------------------------------------------------------------
    def evaluate_g3_swarm_leases(self, bundle: AgentRunBundle) -> GateVerdict:
        start_ns = time.perf_counter_ns()
        violations: list[str] = []
        write_Set = list(bundle.file_writes)
        read_Set = list(bundle.file_reads)

        write_conflicts = 0
        read_conflicts = 0

        for lease in bundle.active_peer_leases:
            if not lease.get("active", True):
                continue
            owner = str(lease.get("owner_agent_id", lease.get("agent_id", "")))
            if not owner or owner == bundle.agent_id:
                continue
            pattern = str(lease.get("glob_pattern", lease.get("pattern", "")))
            mode = str(lease.get("mode", "exclusive_write")).lower()
            if not pattern:
                continue

            for wfile in write_Set:
                if _path_matches_lease(wfile, pattern):
                    write_conflicts += 1
                    violations.append(
                        f"G3:lease_write_collision: file {wfile!r} conflicts with {mode} lease {pattern!r} held by {owner!r}"
                    )

            if mode == "exclusive_write":
                for rfile in read_Set:
                    if _path_matches_lease(rfile, pattern):
                        read_conflicts += 1
                        violations.append(
                            f"G3:lease_read_dirty_collision: file {rfile!r} read while locked under exclusive_write lease {pattern!r} by {owner!r}"
                        )

        metrics = {
            "file_reads_count": len(read_Set),
            "file_writes_count": len(write_Set),
            "active_peer_leases_checked": len(bundle.active_peer_leases),
            "write_conflicts": write_conflicts,
            "read_conflicts": read_conflicts,
        }
        return _build_verdict(
            "G3_SWARM_LEASES",
            "SwarmWeaver Concurrency Lease Gate",
            violations,
            metrics,
            start_ns,
        )

    # ------------------------------------------------------------------
    # GATE 4: G4_TRAJECTORY_HEALTH (AgentFlight)
    # ------------------------------------------------------------------
    def evaluate_g4_trajectory_health(self, bundle: AgentRunBundle) -> GateVerdict:
        start_ns = time.perf_counter_ns()
        violations: list[str] = []
        traj = bundle.tool_trajectory

        if len(traj) > self.max_trajectory_steps:
            violations.append(
                f"G4:trajectory_step_limit_exceeded: {len(traj)} steps > max {self.max_trajectory_steps}"
            )

        schema_errors = 0
        consecutive_failures = 0
        max_consecutive_failures = 0
        signatures: list[str] = []

        for idx, step in enumerate(traj):
            if not isinstance(step, dict):
                schema_errors += 1
                violations.append(f"G4:malformed_step_object at index {idx}")
                continue

            tool_name = step.get("tool")
            args = step.get("args", {})
            status = str(step.get("status", "ok")).lower()

            if not tool_name or not isinstance(tool_name, str) or not isinstance(args, dict):
                schema_errors += 1
                violations.append(f"G4:invalid_mcp_tool_schema at index {idx} (tool={tool_name!r})")
                continue

            sig = f"{tool_name}:{sorted(args.items())}"
            signatures.append(sig)

            if status in ("error", "failed", "timeout"):
                consecutive_failures += 1
                max_consecutive_failures = max(max_consecutive_failures, consecutive_failures)
            else:
                consecutive_failures = 0

        if max_consecutive_failures >= 3:
            violations.append(
                f"G4:repeated_tool_failure_loop: {max_consecutive_failures} consecutive failed tool calls"
            )

        # Detect A <-> B ping-pong oscillation (A, B, A, B) or identical 3x loop (A, A, A)
        oscillation_detected = False
        for i in range(len(signatures) - 2):
            if signatures[i] == signatures[i + 1] == signatures[i + 2]:
                oscillation_detected = True
                violations.append(
                    f"G4:identical_tool_stagnation_loop at steps {i}..{i+2} ({signatures[i]})"
                )
                break

        if not oscillation_detected:
            for i in range(len(signatures) - 3):
                if (
                    signatures[i] == signatures[i + 2]
                    and signatures[i + 1] == signatures[i + 3]
                    and signatures[i] != signatures[i + 1]
                ):
                    oscillation_detected = True
                    violations.append(
                        f"G4:ab_oscillation_loop detected across steps {i}..{i+3} ({signatures[i]} <-> {signatures[i+1]})"
                    )
                    break

        metrics = {
            "trajectory_length": len(traj),
            "schema_errors": schema_errors,
            "max_consecutive_failures": max_consecutive_failures,
            "oscillation_detected": oscillation_detected,
        }
        return _build_verdict(
            "G4_TRAJECTORY_HEALTH",
            "AgentFlight Trajectory & Loop Health Gate",
            violations,
            metrics,
            start_ns,
        )

    # ------------------------------------------------------------------
    # GATE 5: G5_ANTI_REWARD_HACK (PatchPilot)
    # ------------------------------------------------------------------
    def evaluate_g5_anti_reward_hack(self, bundle: AgentRunBundle) -> GateVerdict:
        start_ns = time.perf_counter_ns()
        violations: list[str] = []

        before_src = bundle.code_patch_before.strip()
        after_src = bundle.code_patch_after.strip()

        if not before_src and not after_src:
            return _build_verdict(
                "G5_ANTI_REWARD_HACK",
                "PatchPilot AST Anti-Reward-Hacking Gate",
                violations,
                {"patch_present": False, "tests_before": 0, "tests_after": 0},
                start_ns,
            )

        try:
            before_tree = ast.parse(before_src) if before_src else ast.Module(body=[], type_ignores=[])
        except SyntaxError as exc:
            violations.append(f"G5:before_patch_syntax_error: {exc.msg}")
            before_tree = ast.Module(body=[], type_ignores=[])

        try:
            after_tree = ast.parse(after_src) if after_src else ast.Module(body=[], type_ignores=[])
        except SyntaxError as exc:
            violations.append(f"G5:after_patch_syntax_error: {exc.msg}")
            return _build_verdict(
                "G5_ANTI_REWARD_HACK",
                "PatchPilot AST Anti-Reward-Hacking Gate",
                violations,
                {"patch_present": True, "syntax_error": True},
                start_ns,
            )

        before_tests = _extract_test_functions(before_tree)
        after_tests = _extract_test_functions(after_tree)

        # 1. Deleted test functions
        for test_name, before_info in before_tests.items():
            if test_name not in after_tests:
                violations.append(f"G5:deleted_test_function: {test_name!r} was removed")
            else:
                after_info = after_tests[test_name]
                if after_info["assert_count"] < before_info["assert_count"]:
                    violations.append(
                        f"G5:weakened_test_assertions: {test_name!r} assertions dropped from "
                        f"{before_info['assert_count']} to {after_info['assert_count']}"
                    )

        # 2. Scan after_tree for tautological assertions, skip injection, bare except pass, and pytest env snooping
        tautologies = 0
        skip_injections = 0
        swallowed_exceptions = 0
        env_bypasses = 0

        for node in ast.walk(after_tree):
            if isinstance(node, ast.Assert):
                if _is_tautological_assert(node.test):
                    tautologies += 1
                    violations.append("G5:tautological_assertion detected (e.g. `assert True` or constant truthy)")

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_str = ast.unparse(dec)
                    if any(
                        skip_kw in dec_str
                        for skip_kw in ("pytest.mark.skip", "pytest.mark.xfail", "unittest.skip")
                    ):
                        skip_injections += 1
                        violations.append(f"G5:test_skip_decorator_injected on {node.name!r} (@{dec_str})")

            elif isinstance(node, ast.Call):
                call_str = ast.unparse(node.func)
                if call_str in ("pytest.skip", "unittest.SkipTest"):
                    skip_injections += 1
                    violations.append(f"G5:runtime_test_skip_call detected ({call_str})")
                if "PYTEST_CURRENT_TEST" in ast.unparse(node):
                    env_bypasses += 1
                    violations.append("G5:test_harness_env_snooping detected (`PYTEST_CURRENT_TEST`)")

            elif isinstance(node, ast.ExceptHandler):
                if _is_swallowed_exception_handler(node):
                    swallowed_exceptions += 1
                    violations.append("G5:swallowed_exception_handler (`except ...: pass` or constant return)")

        metrics = {
            "patch_present": True,
            "tests_before": len(before_tests),
            "tests_after": len(after_tests),
            "tautologies": tautologies,
            "skip_injections": skip_injections,
            "swallowed_exceptions": swallowed_exceptions,
            "env_bypasses": env_bypasses,
        }
        return _build_verdict(
            "G5_ANTI_REWARD_HACK",
            "PatchPilot AST Anti-Reward-Hacking Gate",
            violations,
            metrics,
            start_ns,
        )

    # ------------------------------------------------------------------
    # GATE 6: G6_TRUTH_GROUNDING (TruthGate)
    # ------------------------------------------------------------------
    def evaluate_g6_truth_grounding(self, bundle: AgentRunBundle) -> GateVerdict:
        start_ns = time.perf_counter_ns()
        violations: list[str] = []

        context_by_id: dict[str, str] = {}
        for idx, ctx in enumerate(bundle.retrieved_context):
            cid = str(ctx.get("id", ctx.get("doc_id", f"doc_{idx + 1}")))
            text = str(ctx.get("text", ctx.get("content", "")))
            context_by_id[cid] = text

        cited_ids = _CITATION_RE.findall(bundle.final_response)
        phantom_citations = 0
        polarity_inversions = 0
        numeric_drifts = 0
        phantom_symbols = 0

        # 1. Check phantom citations
        for cid in cited_ids:
            if cid not in context_by_id:
                phantom_citations += 1
                violations.append(f"G6:phantom_citation: [{cid}] not present in retrieved_context")

        # 2. Sentence/clause-level grounding checks for cited claims
        sentences = [s.strip() for s in _SENTENCE_SPLIT_RE.split(bundle.final_response) if s.strip()]
        for sentence in sentences:
            sent_citations = _CITATION_RE.findall(sentence)
            if not sent_citations:
                continue

            # Split sentence into citation-anchored clauses so text after [doc_X] (e.g. a temporal fact)
            # is not falsely attributed to [doc_X], while single-citation sentences still inspect the clause.
            clauses = _CLAUSE_SPLIT_RE.findall(sentence)
            if not clauses:
                clauses = [sentence]

            for clause in clauses:
                clause_citations = _CITATION_RE.findall(clause)
                clause_lower = clause.lower()
                clause_numbers = [_normalize_num(n) for n in _NUMBER_TOKEN_RE.findall(clause)]

                for cid in clause_citations:
                    if cid not in context_by_id:
                        continue
                    ctx_text = context_by_id[cid]
                    ctx_lower = ctx_text.lower()
                    ctx_numbers = {_normalize_num(n) for n in _NUMBER_TOKEN_RE.findall(ctx_text)}

                    # Check antonym / negation polarity inversion between context and clause
                    for pos_word, neg_word, pos_re, neg_re in _POLARITY_ANTONYM_PAIRS:
                        if (
                            pos_re.search(ctx_lower)
                            and not neg_re.search(ctx_lower)
                            and neg_re.search(clause_lower)
                        ) or (
                            neg_re.search(ctx_lower)
                            and not pos_re.search(ctx_lower)
                            and pos_re.search(clause_lower)
                        ):
                            polarity_inversions += 1
                            violations.append(
                                f"G6:polarity_inversion against [{cid}]: context vs response flipped ({pos_word!r} <-> {neg_word!r})"
                            )
                            break

                    # Check explicit negation flip ("must never be X" vs "can be X" / "is not X" vs "is X")
                    if _has_negation_flip(ctx_lower, clause_lower):
                        polarity_inversions += 1
                        violations.append(
                            f"G6:negation_polarity_flip against [{cid}]: response contradicts negation in source context"
                        )

                    # Check numeric drift: if context has numbers and clause states a number not in context
                    if ctx_numbers and clause_numbers:
                        for s_num in clause_numbers:
                            if s_num not in ctx_numbers:
                                numeric_drifts += 1
                                violations.append(
                                    f"G6:numeric_metric_drift against [{cid}]: stated {s_num!r}, context has {sorted(ctx_numbers)}"
                                )

        # 3. Check backticked AST function/method references against workspace_symbols
        if bundle.workspace_symbols:
            known_symbols: set[str] = set()
            for mod_name, sym_list in bundle.workspace_symbols.items():
                for sym in sym_list:
                    known_symbols.add(sym)
                    known_symbols.add(f"{mod_name}.{sym}")

            referenced_symbols = _BACKTICK_SYMBOL_RE.findall(bundle.final_response)
            for ref_sym in referenced_symbols:
                short_sym = ref_sym.split(".")[-1]
                if ref_sym not in known_symbols and short_sym not in known_symbols:
                    phantom_symbols += 1
                    violations.append(
                        f"G6:hallucinated_ast_symbol: `{ref_sym}()` does not exist in workspace_symbols"
                    )

        metrics = {
            "citations_found": len(cited_ids),
            "phantom_citations": phantom_citations,
            "polarity_inversions": polarity_inversions,
            "numeric_drifts": numeric_drifts,
            "phantom_symbols": phantom_symbols,
        }
        return _build_verdict(
            "G6_TRUTH_GROUNDING",
            "TruthGate Epistemic & AST Grounding Gate",
            violations,
            metrics,
            start_ns,
        )

    # ------------------------------------------------------------------
    # GATE 7: G7_TEMPORAL_MEMORY (Cortex-MCP)
    # ------------------------------------------------------------------
    def evaluate_g7_temporal_memory(self, bundle: AgentRunBundle) -> GateVerdict:
        start_ns = time.perf_counter_ns()
        violations: list[str] = []

        stale_facts_total = 0
        stale_facts_used = 0
        response_lower = bundle.final_response.lower()
        trajectory_str = str(bundle.tool_trajectory).lower()

        for idx, fact in enumerate(bundle.temporal_facts):
            fact_id = str(fact.get("fact_id", fact.get("id", f"fact_{idx + 1}")))
            valid_until = fact.get("valid_until")
            superseded_by = fact.get("superseded_by")
            is_stale = (valid_until is not None) or (superseded_by is not None)
            if not is_stale:
                continue

            stale_facts_total += 1
            stale_value = str(fact.get("value", fact.get("claim", ""))).strip()
            explicitly_used = bool(fact.get("used_by_agent", False))

            value_referenced = (
                bool(stale_value)
                and len(stale_value) >= 4
                and (stale_value.lower() in response_lower or stale_value.lower() in trajectory_str)
            )
            id_referenced = fact_id.lower() in response_lower

            if explicitly_used or value_referenced or id_referenced:
                stale_facts_used += 1
                reason = (
                    f"superseded_by={superseded_by!r}"
                    if superseded_by is not None
                    else f"valid_until={valid_until!r}"
                )
                violations.append(
                    f"G7:stale_temporal_fact_contamination: agent relied on stale fact {fact_id!r} "
                    f"({stale_value!r}, {reason})"
                )

        metrics = {
            "temporal_facts_checked": len(bundle.temporal_facts),
            "stale_facts_present": stale_facts_total,
            "stale_facts_used": stale_facts_used,
        }
        return _build_verdict(
            "G7_TEMPORAL_MEMORY",
            "Cortex-MCP Temporal Memory Freshness Gate",
            violations,
            metrics,
            start_ns,
        )


# ----------------------------------------------------------------------
# Helper functions for AST, glob lease matching, and polarity grounding
# ----------------------------------------------------------------------

def _path_matches_lease(file_path: str, lease_pattern: str) -> bool:
    norm_file = file_path.strip().lstrip("./")
    norm_pat = lease_pattern.strip().lstrip("./")
    if norm_file == norm_pat:
        return True
    if fnmatch.fnmatchcase(norm_file, norm_pat):
        return True
    if norm_pat.endswith("/**") and norm_file.startswith(norm_pat[:-2]):
        return True
    return False


def _extract_test_functions(tree: ast.AST) -> dict[str, dict[str, int]]:
    tests: dict[str, dict[str, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            assert_count = sum(1 for sub in ast.walk(node) if isinstance(sub, ast.Assert))
            tests[node.name] = {"assert_count": assert_count}
    return tests


def _is_tautological_assert(test_expr: ast.expr) -> bool:
    if isinstance(test_expr, ast.Constant) and bool(test_expr.value) is True:
        return True
    if isinstance(test_expr, ast.UnaryOp) and isinstance(test_expr.op, ast.Not):
        if isinstance(test_expr.operand, ast.Constant) and bool(test_expr.operand.value) is False:
            return True
    if isinstance(test_expr, ast.Compare) and len(test_expr.ops) == 1 and isinstance(test_expr.ops[0], ast.Eq):
        left = test_expr.left
        right = test_expr.comparators[0]
        if isinstance(left, ast.Constant) and isinstance(right, ast.Constant) and left.value == right.value:
            return True
    return False


def _is_swallowed_exception_handler(handler: ast.ExceptHandler) -> bool:
    if not handler.body:
        return True
    if len(handler.body) == 1:
        stmt = handler.body[0]
        if isinstance(stmt, ast.Pass):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
            return True
    return False


def _normalize_num(token: str) -> str:
    cleaned = token.replace(",", "").strip()
    return cleaned


_NEGATION_CTX_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bmust\s+never\s+be\s+([a-z_]+)\b"), r"\b(?:can|may|should)\s+be\s+{word}\b"),
    (re.compile(r"\bcannot\s+be\s+([a-z_]+)\b"), r"\b(?:can|is)\s+be\s+{word}\b"),
    (re.compile(r"\bis\s+not\s+([a-z_]+)\b"), r"\bis\s+{word}\b"),
    (re.compile(r"\bzero\s+([a-z_]+\s+[a-z_]+)\b"), r"\b(?:multiple|several|high)\s+{word}\b"),
]


def _has_negation_flip(ctx_lower: str, sent_lower: str) -> bool:
    """
    Detect explicit negation flips such as:
    - context: "must never be disabled" / "is not supported" / "cannot bypass"
    - sentence: "can be disabled" / "is supported" / "can bypass"
    """
    for ctx_re, sent_template in _NEGATION_CTX_PATTERNS:
        m = ctx_re.search(ctx_lower)
        if m:
            word = m.group(1)
            resolved_sent_pat = sent_template.format(word=re.escape(word))
            if (
                re.search(resolved_sent_pat, sent_lower)
                and f"not {word}" not in sent_lower
                and f"never be {word}" not in sent_lower
            ):
                return True
    return False
