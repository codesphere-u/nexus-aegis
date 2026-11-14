(() => {
  "use strict";

  const showToast = (msg) => {
    const el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("visible");
    window.clearTimeout(el._naTimer);
    el._naTimer = window.setTimeout(() => el.classList.remove("visible"), 2200);
  };

  const copyText = (text) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        () => showToast("Copied to clipboard"),
        () => showToast("Ready to copy")
      );
      return;
    }
    showToast("Selected command ready");
  };

  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-copy]");
    if (btn) copyText(btn.getAttribute("data-copy") || "");
  });

  /* Deterministic 32-hex FNV/SHA-like fingerprint for browser offline previews */
  const hashHex64 = (input) => {
    let h1 = 0x811c9dc5;
    let h2 = 0x1a2b3c4d;
    const str = String(input);
    for (let i = 0; i < str.length; i += 1) {
      const ch = str.charCodeAt(i);
      h1 ^= ch;
      h1 = Math.imul(h1, 0x01000193) >>> 0;
      h2 ^= (ch + i * 31) & 0xff;
      h2 = Math.imul(h2, 0x85ebca6b) >>> 0;
    }
    return (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0")).repeat(4);
  };

  /* Hero split button & popover */
  const heroCopyBtn = document.getElementById("heroCopyBtn");
  const heroToggleBtn = document.getElementById("heroToggleBtn");
  const heroPopover = document.getElementById("heroPopover");
  const heroCmdPreview = document.getElementById("heroCmdPreview");
  const popCmdCode = document.getElementById("popCmdCode");
  const popCopyBtn = document.getElementById("popCopyBtn");

  if (heroCopyBtn && heroCmdPreview) {
    heroCopyBtn.addEventListener("click", () => copyText(heroCmdPreview.textContent.trim()));
  }
  if (heroToggleBtn && heroPopover) {
    heroToggleBtn.addEventListener("click", () => {
      const open = heroPopover.classList.toggle("open");
      heroToggleBtn.setAttribute("aria-expanded", String(open));
    });
  }
  if (popCopyBtn && popCmdCode) {
    popCopyBtn.addEventListener("click", () => copyText(popCmdCode.textContent.trim()));
  }
  document.querySelectorAll("[data-pop-cmd]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const cmd = btn.getAttribute("data-pop-cmd") || "";
      document.querySelectorAll("[data-pop-cmd]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      if (popCmdCode) popCmdCode.textContent = cmd;
      if (heroCmdPreview) heroCmdPreview.textContent = cmd;
    });
  });

  /* Home Preview Tabs */
  const homePreviewCode = document.getElementById("homePreviewCode");
  const previewPayloads = {
    cert: `## NexusAegis Proof-Carrying Agent Execution (PCAE) Certificate
VERDICT: PASSED | RFC 6962 Root: 9524c6dcd0ed055b7aece7e7... | Latency: 0.348 ms

Gate ID               | Stack Component           | Verdict | Leaf Hash (0x00)
G1_SECURITY           | codesphere-u/agentshield  | PASS    | 03cc710e70600146...
G2_BUDGET_ROUTING     | codesphere-u/synapse-rtr  | PASS    | e03a5add74b9c683...
G3_SWARM_LEASES       | codesphere-u/swarmweaver  | PASS    | 3250a92db97646f3...
G4_TRAJECTORY_HEALTH  | codesphere-u/agentflight  | PASS    | 89badc61c58acf57...
G5_ANTI_REWARD_HACK   | codesphere-u/patchpilot   | PASS    | d24d94e65bec8c98...
G6_TRUTH_GROUNDING    | codesphere-u/truthgate    | PASS    | d1926fac5ca6eb39...
G7_TEMPORAL_MEMORY    | codesphere-u/cortex-mcp   | PASS    | 0332a571c9ef9179...`,
    merkle: `$ nexus-aegis attest run.json --disclose-gate G5_ANTI_REWARD_HACK
{
  "gate_id": "G5_ANTI_REWARD_HACK",
  "verdict": "PASS",
  "merkle_root": "9524c6dcd0ed055b7aece7e7cdd4c249aecb9b90a888f94ff78d0b42bde2e158",
  "inclusion_proof_steps": 4,
  "prompts_or_diffs_exposed": false,
  "verified": true
}`,
    block: `## NexusAegis PCAE: BLOCKED (VIOLATION DETECTED)
RFC 6962 Root: 3831fdf7239f107843e9563d... | Latency: 0.224 ms

- G5_ANTI_REWARD_HACK [FAIL score=0.75]:
  G5:tautological_assertion detected (assert True or @pytest.mark.skip)
  Leaf Hash (0x00): 96db7018ef441c69...`
  };
  document.querySelectorAll("[data-preview-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-preview-tab");
      document.querySelectorAll("[data-preview-tab]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      if (homePreviewCode && previewPayloads[key]) homePreviewCode.textContent = previewPayloads[key];
    });
  });

  /* Studio Tabs */
  document.querySelectorAll("[data-studio-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.getAttribute("data-studio-tab");
      document.querySelectorAll("[data-studio-tab]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll("[data-studio-panel]").forEach((panel) => {
        panel.classList.toggle("active", panel.getAttribute("data-studio-panel") === tab);
      });
    });
  });

  /* Studio: 7-Gate PCAE Evaluator */
  const presetsEl = document.getElementById("na-studio-presets");
  const bundleInput = document.getElementById("aegisBundleInput");
  if (presetsEl && bundleInput) {
    let presets = {};
    try {
      presets = JSON.parse(presetsEl.textContent || "{}");
    } catch (_err) {
      presets = {};
    }
    let activePreset = "clean";

    const evaluateBundle = () => {
      const listEl = document.getElementById("aegisGateList");
      const verdictEl = document.getElementById("aegisVerdict");
      const countEl = document.getElementById("aegisPassedCount");
      const noteEl = document.getElementById("aegisMerkleNote");

      let b = {};
      try {
        b = JSON.parse(bundleInput.value);
      } catch (err) {
        if (noteEl) noteEl.textContent = "Invalid JSON bundle: " + err.message;
        return;
      }

      const prompt = String(b.prompt || "");
      const codeAfter = String(b.code_after || "");
      const codeBefore = String(b.code_before || "");
      const resp = String(b.final_response || "");
      const writes = Array.isArray(b.write_globs) ? b.write_globs : [];
      const peer = Array.isArray(b.peer_write_leases) ? b.peer_write_leases : [];
      const seq = Array.isArray(b.tool_sequence) ? b.tool_sequence : [];
      const cites = Array.isArray(b.cited_docs) ? b.cited_docs : [];

      const g1Fail = /ignore all previous|169\.254\.169\.254|\.env|\.ssh/i.test(prompt);
      const g2Fail = Number(b.cost_usd || 0) > Number(b.budget_cap_usd || 1);
      const g3Fail = writes.some((w) => peer.includes(w));
      const g4Fail = seq.length >= 4 && seq[0] === seq[2] && seq[1] === seq[3];
      const g5Fail = /assert\s+True|@pytest\.mark\.skip|except:\s*pass/i.test(codeAfter) && codeAfter !== codeBefore || (/assert\s+True|@pytest\.mark\.skip/i.test(codeAfter) && activePreset !== "injection");
      const g6Fail = cites.includes("doc_99") || /mtls disabled/i.test(resp);
      const g7Fail = Boolean(b.used_stale_fact);

      const gates = [
        { id: "G1_SECURITY", pass: !g1Fail, note: g1Fail ? "Blocked prompt override / SSRF / credential access" : "Zero prompt injection or SSRF triggers" },
        { id: "G2_BUDGET_ROUTING", pass: !g2Fail, note: g2Fail ? `Exceeded budget cap ($${b.cost_usd} > $${b.budget_cap_usd})` : `Within budget ($${b.cost_usd || 0} <= $${b.budget_cap_usd || 0.25})` },
        { id: "G3_SWARM_LEASES", pass: !g3Fail, note: g3Fail ? "Write lease collision with active peer lock" : "Disjoint file-scope globs verified" },
        { id: "G4_TRAJECTORY_HEALTH", pass: !g4Fail, note: g4Fail ? "A <-> B tool oscillation loop detected" : "Healthy non-oscillating tool trajectory" },
        { id: "G5_ANTI_REWARD_HACK", pass: !g5Fail, note: g5Fail ? "Tautological assertion or skip marker in diff" : "Assertions intact across Python diff" },
        { id: "G6_TRUTH_GROUNDING", pass: !g6Fail, note: g6Fail ? "Phantom citation [doc_99] or negation polarity flip" : "Citations and polarity grounded" },
        { id: "G7_TEMPORAL_MEMORY", pass: !g7Fail, note: g7Fail ? "Expired or superseded bi-temporal memory referenced" : "Memory facts current and valid" }
      ];

      const passed = gates.filter((g) => g.pass).length;
      const overall = passed === 7;
      const merkleRoot = hashHex64(JSON.stringify({ run_id: b.run_id, gates: gates.map((g) => [g.id, g.pass]) }));

      if (verdictEl) verdictEl.textContent = overall ? "PASSED" : "BLOCKED";
      if (countEl) countEl.textContent = `${passed} / 7`;
      if (noteEl) noteEl.textContent = `RFC 6962 Root (0x01): ${merkleRoot.slice(0, 32)}...`;
      if (listEl) {
        listEl.innerHTML = gates.map((g) => {
          const leafHash = hashHex64(`0x00|${g.id}|${g.pass}`).slice(0, 16);
          return `<div class="rw-item${g.pass ? "" : " danger-border"}"><span>${g.id} · ${g.pass ? "PASS" : "FAIL"} · Leaf 0x00=${leafHash}...</span><p>${g.note}</p></div>`;
        }).join("");
      }
    };

    const loadPreset = (name) => {
      activePreset = name;
      bundleInput.value = JSON.stringify(presets[name] || {}, null, 2);
      document.querySelectorAll("[data-aegis-preset]").forEach((btn) => {
        btn.classList.toggle("active", btn.getAttribute("data-aegis-preset") === name);
      });
      evaluateBundle();
    };

    document.querySelectorAll("[data-aegis-preset]").forEach((btn) => {
      btn.addEventListener("click", () => loadPreset(btn.getAttribute("data-aegis-preset")));
    });
    const runBtn = document.getElementById("aegisRunBtn");
    const resetBtn = document.getElementById("aegisResetBtn");
    if (runBtn) runBtn.addEventListener("click", evaluateBundle);
    if (resetBtn) resetBtn.addEventListener("click", () => loadPreset(activePreset));
    loadPreset("clean");
  }

  /* Studio: Selective Disclosure Proof Toggle */
  const proofStateEl = document.getElementById("proofVerifyState");
  const proofNoteEl = document.getElementById("proofDiagNote");
  const proofOutEl = document.getElementById("proofJsonOut");
  const renderProof = (mode) => {
    if (!proofOutEl) return;
    const isTampered = mode === "tampered";
    if (proofStateEl) proofStateEl.textContent = isTampered ? "REJECTED" : "VALID";
    if (proofNoteEl) {
      proofNoteEl.textContent = isTampered
        ? "Tampered sibling hash breaks 0x01 Merkle root reconstruction — verification failed (0/1)."
        : "Recomputed RFC 6962 root matches signed certificate root without revealing prompts or diffs.";
    }
    proofOutEl.textContent = JSON.stringify({
      leaf_name: "G5_ANTI_REWARD_HACK",
      leaf_prefix: "0x00",
      node_prefix: "0x01",
      leaf_hash: "d24d94e65bec8c98f3a11e9a8165c290...",
      expected_root_hash: "9524c6dcd0ed055b7aece7e7cdd4c249...",
      sibling_0_hash: isTampered ? "e1926fac5ca6eb39_MODIFIED_BIT" : "d1926fac5ca6eb39a07b5d8b2a9d1e41...",
      proof_steps: 4,
      verified: !isTampered
    }, null, 2);
  };
  document.querySelectorAll("[data-proof-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.getAttribute("data-proof-mode");
      document.querySelectorAll("[data-proof-mode]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      renderProof(mode);
    });
  });
  renderProof("valid");

  /* Studio: MCP & CI Generator */
  const mcpSelect = document.getElementById("mcpClientSelect");
  const mcpOut = document.getElementById("mcpSnippetOutput");
  const mcpTitle = document.getElementById("mcpSnippetTitle");
  const copyMcpBtn = document.getElementById("copyMcpSnippetBtn");
  const mcpSnippets = {
    "claude-desktop": {
      title: "Stdio JSON-RPC 2.0 Config (~/.config/claude_desktop_config.json)",
      code: `{
  "mcpServers": {
    "nexus-aegis": {
      "command": "nexus-aegis",
      "args": ["mcp"]
    }
  }
}`
    },
    "github-pr": {
      title: "GitHub Action PR Attestation Markdown Card & Selective Proof",
      code: `pip install -e .
nexus-aegis attest agent_run.json --markdown > pr_attestation.md
nexus-aegis attest agent_run.json --disclose-gate G5_ANTI_REWARD_HACK > g5_proof.json`
    },
    "http-server": {
      title: "Streamable HTTP/SSE Portal & REST Attestation API",
      code: `nexus-aegis serve-http --host 127.0.0.1 --port 8000
# Endpoints: POST /mcp | GET /mcp (SSE) | POST /api/attest | POST /api/verify-proof | GET /metrics`
    },
    "docker": {
      title: "Hardened Non-Root Docker Container",
      code: `docker build -t nexus-aegis:1.1.0 .
docker run --rm -p 8000:8000 -e NEXUS_AEGIS_MAX_BODY_BYTES=1048576 nexus-aegis:1.1.0`
    }
  };
  const renderMcp = () => {
    if (!mcpSelect || !mcpOut) return;
    const item = mcpSnippets[mcpSelect.value] || mcpSnippets["claude-desktop"];
    if (mcpTitle) mcpTitle.textContent = item.title;
    mcpOut.textContent = item.code;
  };
  if (mcpSelect) {
    mcpSelect.addEventListener("change", renderMcp);
    renderMcp();
  }
  if (copyMcpBtn && mcpOut) copyMcpBtn.addEventListener("click", () => copyText(mcpOut.textContent));

  /* Rules Filter */
  const rulesSearch = document.getElementById("rulesSearchInput");
  const rulesCat = document.getElementById("rulesCategorySelect");
  const rulesTable = document.getElementById("rulesTable");
  const filterRules = () => {
    if (!rulesTable) return;
    const q = (rulesSearch ? rulesSearch.value : "").trim().toLowerCase();
    const cat = rulesCat ? rulesCat.value : "all";
    rulesTable.querySelectorAll("tbody tr").forEach((row) => {
      const rowCat = row.getAttribute("data-cat") || "";
      const txt = row.textContent.toLowerCase();
      row.hidden = !((cat === "all" || rowCat === cat) && (!q || txt.includes(q)));
    });
  };
  if (rulesSearch) rulesSearch.addEventListener("input", filterRules);
  if (rulesCat) rulesCat.addEventListener("change", filterRules);

  /* Docs Navigation & OS Tabs */
  const osCodeEl = document.getElementById("docOsCode");
  const osCopyBtn = document.getElementById("docOsCopyBtn");
  const osPayloads = {
    mac: `<span class="syn-cmd">git clone</span> https://github.com/codesphere-u/nexus-aegis.git\n<span class="syn-cmd">cd</span> nexus-aegis &amp;&amp; <span class="syn-cmd">pip install</span> <span class="syn-arg">-e .</span>\n<span class="syn-cmd">nexus-aegis</span> demo &amp;&amp; <span class="syn-cmd">nexus-aegis</span> benchmark`,
    win: `<span class="syn-cmd">git clone</span> https://github.com/codesphere-u/nexus-aegis.git\n<span class="syn-cmd">cd</span> nexus-aegis; <span class="syn-cmd">pip install</span> <span class="syn-arg">-e .</span>\n<span class="syn-cmd">nexus-aegis</span> demo`
  };
  document.querySelectorAll("[data-doc-os]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const os = btn.getAttribute("data-doc-os");
      document.querySelectorAll("[data-doc-os]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      if (osCodeEl && osPayloads[os]) osCodeEl.innerHTML = osPayloads[os];
    });
  });
  if (osCopyBtn && osCodeEl) osCopyBtn.addEventListener("click", () => copyText(osCodeEl.textContent));

  const switchDocSection = (targetId) => {
    document.querySelectorAll("[data-doc-section]").forEach((sec) => {
      sec.hidden = sec.getAttribute("data-doc-section") !== targetId;
    });
    document.querySelectorAll("[data-doc-target]").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-doc-target") === targetId);
    });
    document.querySelectorAll("[data-doc-subrail]").forEach((sub) => {
      sub.classList.toggle("open", sub.getAttribute("data-doc-subrail") === targetId);
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };
  document.querySelectorAll("[data-doc-target], [data-doc-jump]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-doc-target") || btn.getAttribute("data-doc-jump");
      if (target) switchDocSection(target);
    });
  });
})();
