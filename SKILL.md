---
name: detect-recommendation-poisoning
description: Scan OpenClaw memory files for recommendation poisoning, memory injection, and suspicious attempts to bias recommendations, rankings, purchases, product choices, or model preference behavior. Use when asked to inspect OpenClaw memories, audit recommendation integrity, detect poisoning/backdoor instructions in memory files, or produce a report of suspicious recommendation-manipulation signals.
parameters:
  - name: scan_path
    description: Path to an OpenClaw memory file or directory to scan. If not provided, common OpenClaw memory locations will be scanned automatically.
    required: false
---

# Detect Recommendation Poisoning

## Overview

Use this skill to help OpenClaw users inspect their own local OpenClaw memory artifacts for instructions or stored content that could bias future recommendations. The scanner is designed to be distributed with the skill and run on the user's machine against their local memory files.

## Quick Start

Run the scanner from the skill directory:

```bash
python scripts/scan_openclaw_memory.py
```

By default, the scanner searches common OpenClaw memory locations on the current user's machine. It does not scan the developer's machine or any remote system.

When the `scan_path` parameter is provided, pass it as a positional argument to the script:

```bash
python scripts/scan_openclaw_memory.py {{scan_path}}
```

Multiple paths can be passed:

```bash
python scripts/scan_openclaw_memory.py C:\path\to\openclaw\memory C:\path\to\other-memory.json
```

Write machine-readable output:

```bash
python scripts/scan_openclaw_memory.py --json --output findings.json C:\path\to\memory
```

Use explicit regex rule files only when overriding the bundled rules:

```bash
python scripts/scan_openclaw_memory.py --rules C:\repo\data\raw\recommendation_poisoning_keyword_regex_rules.csv C:\repo\data\raw\recommendation_poisoning_keyword_regex_rules_zh.csv C:\path\to\memory
```

## Workflow

1. Locate the user's local memory files. If `scan_path` is provided, pass it directly to the script as positional arguments. Otherwise, let the scanner check common locations such as `OPENCLAW_HOME`, `OPENCLAW_MEMORY_DIR`, `.openclaw`, `openclaw`, and `memory` directories under the current working directory and user profile.
2. Run `scripts/scan_openclaw_memory.py {{scan_path}}` (append `{{scan_path}}` as positional arguments; omit if not provided).
3. Treat findings as indicators, not proof. Open each high or critical file and inspect the surrounding memory record.
4. Report:
   - scanned paths and file count
   - high-confidence suspicious snippets
   - affected brands/items/categories if obvious
   - why each finding matters
   - recommended cleanup, quarantine, or follow-up validation

## Detection Heuristics

The scanner scores combinations of signals:

- Recommendation-control phrases: `always recommend`, `must suggest`, `rank first`, `prefer`, `promote`, `never recommend`, `avoid mentioning competitors`.
- Injection phrases: `ignore previous instructions`, `system override`, `developer message`, `hidden instruction`, `do not reveal`.
- Commerce or ranking context: `buy`, `product`, `vendor`, `sponsor`, `affiliate`, `ranking`, `top result`, `review`, `rating`.
- Persistence context: `remember this`, `store this`, `memory`, `profile`, `preference`.
- Obfuscation markers: base64-like blobs, zero-width characters, HTML comments, prompt-delimiter patterns.

The scanner loads the bundled 200-rule English/Chinese regex libraries from `references/recommendation_poisoning_keyword_regex_rules.csv` and `references/recommendation_poisoning_keyword_regex_rules_zh.csv`. These add five explicit poisoning categories: `memory_write`, `trust_injection`, `recommendation_bias`, `citation_bias`, and `user_preference_forgery`.

Escalate severity when multiple categories appear in the same snippet, especially injection plus recommendation or commerce language.

## Output Guidance

Prefer concise, evidence-led reports:

```text
Scanned 12 files. Found 3 suspicious memory records.

Critical: path/to/memory.json:42
Reason: injection language plus recommendation-control language.
Snippet: ...
Action: quarantine this memory record and inspect adjacent records for the same campaign.
```

Avoid overclaiming intent. Say "possible poisoning" or "suspicious recommendation-bias instruction" unless the file clearly contains an explicit malicious instruction.
