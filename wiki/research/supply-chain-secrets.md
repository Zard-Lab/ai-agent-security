---
type: Research
title: Supply Chain and Secrets Leakage
description: npm and PyPI supply-chain attack patterns and API-key leakage vectors that inform agentsec's supply-chain guard detection logic.
tags: [research, supply-chain, secrets]
timestamp: "2026-06-09T00:00:00Z"
captured: 2026-06-09
source: parallel research agent (RapidFort, Unit 42, GitGuardian, Trend Micro, arXiv, Snyk)
---

# Supply Chain + Secrets Leakage (2024-2025)

## Supply Chain — New Attack Patterns

### Shai-Hulud Worm (September 2025)
First documented npm worm. 796 packages with 132M monthly downloads compromised. Published
malicious packages with valid SLSA Build Level 3 provenance signatures.

**Key insight:** SLSA provenance only confirms *which pipeline* built the code, not whether
that pipeline's internal state was compromised. Signed artifacts ≠ safe artifacts.

The supply-chain guards (`js_supply_chain.py`, `python_supply_chain.py`) address the pre-infection
defense (lockfiles, release-age cooldown, lifecycle hooks). Post-infection detection requires runtime
behavioral analysis.

**Source:** https://www.rapidfort.com/blog/pypi-npm-and-the-new-frontline-of-software-supply-chain-attacks

---

### TeamPCP — Lockfile Bypass via Tag Injection (Feb-Mar 2026)
Attackers forced new tags on legitimate packages (`trivy-action`, `setup-trivy`). Existing CI/CD
workflows with pinned version references silently resolved to attacker-controlled code despite
lockfile protection.

**Implication:** Pinning by tag (not by commit SHA) is insufficient. SHA-pinning required for
full supply chain integrity.

---

### Coordinated Multi-Platform Campaign (April 21-23, 2026)
60+ packages targeted across npm, PyPI, and Docker Hub simultaneously. Targets included TanStack,
Mistral AI, UiPath, OpenSearch. Industrial-scale; no single platform defense is sufficient.

**Source:** https://blog.gitguardian.com/three-supply-chain-campaigns-hit-npm-pypi-and-docker-hub-in-48-hours/

---

### Static Detection Patterns (npm-scan approach)
Tools like npm-scan detect:
1. **Eval chains** — `eval()`, `Function()`, dynamic `require()` with obfuscated paths
2. **Environment probing** — `process.env.CI`, hostname checks, time-based activation
3. **Credential harvesting** — direct FS targeting: `.npmrc`, SSH keys, `~/.aws/`, `~/.docker/`
4. **Sensitive env var access** — `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`
5. **Network exfiltration** — GitHub API calls, DNS tunneling in postinstall scripts
6. **Lifecycle script anomalies** — `preinstall` hooks (legitimate packages rarely use these)

Entropy analysis catches 2-layer obfuscation (Base64 + XOR). Misses: 4.2MB eval payloads with
runtime AES-128-GCM decryption, dormant backdoors with time-based activation.

**Source:** https://github.com/lateos-ai/npm-scan

---

## Secrets Leakage in LLM Apps

### LiteLLM Supply Chain Backdoor (Aug 2025)
LiteLLM 1.82.8 shipped with a 34,628-byte `LiteLLM_init.pth` file that silently exfiltrated all
secrets to attacker-controlled servers on import. Captured:
- OpenAI keys (`sk-*`)
- Anthropic API keys
- Azure AI credentials
- AWS keys (`AKIA*`)
- GitHub PATs (`ghp_*`)
- Supabase service_role keys

**Lesson:** Even widely-deployed, trusted AI libraries are supply chain targets. Version-lock +
hash-pin critical AI dependencies.

**Source:** https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html

---

### Agent Skill Credential Leakage (Large-Scale Study, 2025)
**Key stat:** 283 of 3,984 skills analyzed (7.1%) expose credentials during normal execution.
**Key stat:** 89.6% exploitable without elevated privileges; 75.8% via stdout leakage.

Leakage patterns found:
1. **Verbatim output** — skill instructions say "share the inbox URL (which contains the API key)"
2. **Credential in curl commands** — `buy-anything` skill embeds credit card + CVC in curl `-d` args → provider tokenizes PII
3. **Memory storage** — instructions say "save API key in memory" → persistent artifact that other skills can exfiltrate
4. **Log re-exposure** — `prompt-log` skill outputs `.jsonl` without redaction, re-surfacing prior leaked credentials

**76.3% of leakage** only detectable by analyzing both natural-language skill descriptions AND code
together (cross-modal analysis). Single-modality tools miss it.

**Key stat:** Deleted credentials remain live across 50+ independent GitHub forks.

**Sources:**
- https://arxiv.org/html/2604.03070v1
- https://snyk.io/blog/openclaw-skills-credential-leaks-research/

---

### 12,000+ Hardcoded API Keys Found in Public Datasets (Feb 2025)
11,908 valid DeepSeek API keys discovered hardcoded across public web pages. 72% of hardcoded cases
showed AI-assisted development signatures — LLM coding assistants inserting keys inline.

**Detection patterns to scan for:**

| Provider | Pattern |
|---|---|
| OpenAI | `OPENAI_API_KEY`, `sk-` prefix (20+ chars) |
| Anthropic | `ANTHROPIC_API_KEY`, `sk-ant-` prefix |
| Stripe (secret) | `sk_live_`, `sk_test_` |
| Stripe (public) | `pk_live_`, `pk_test_` (lower risk but still PII surface) |
| GitHub | `GITHUB_TOKEN`, `ghp_` prefix |
| AWS | `AKIA` prefix (20 chars, all caps+digits) |
| Supabase service_role | `SUPABASE_SERVICE_ROLE_KEY`, JWT starting with `eyJ` + `service_role` in payload |
| Generic placeholders | `YOUR_API_KEY`, `API_KEY_HERE`, `REPLACE_ME` |

**Source:** https://thehackernews.com/2025/02/12000-api-keys-and-passwords-found-in.html

---

## Summary table

| Threat | Statically detectable | Guard status |
|---|---|---|
| npm lifecycle scripts / eval chains | YES | `js_supply_chain.py` done |
| PyPI dependency integrity | YES | `python_supply_chain.py` done |
| Release-age cooldown (pnpm/npm/uv) | YES | enforced within the supply-chain guards |
| Tag-pinned (not SHA-pinned) CI actions | PARTIAL | No guard yet |
| Hardcoded API keys in Python/JS | YES | gitleaks runner |
| Supabase service_role in frontend | YES | `service_role_key.py` guard |
| Agent skill credential leakage | PARTIAL (cross-modal needed) | No guard yet |
| LiteLLM-style .pth backdoor | NO (binary payload) | Dependency auditing + hash-pin |
