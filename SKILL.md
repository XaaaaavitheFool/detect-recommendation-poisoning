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

When preparing a user-facing report, run JSON output and review the regex candidates before reporting:

```bash
python scripts/scan_openclaw_memory.py --json C:\path\to\memory
```

The scanner itself does not configure or call a separate model. Its output is an unreviewed candidate list, not the final assessment.

Use explicit regex rule files only when overriding the bundled rules:

```bash
python scripts/scan_openclaw_memory.py --rules C:\repo\data\raw\recommendation_poisoning_keyword_regex_rules.csv C:\repo\data\raw\recommendation_poisoning_keyword_regex_rules_zh.csv -- C:\path\to\memory
```

Use `--` to separate rule files from scan paths, especially when the scan target is also a `.csv` file.

## Workflow

1. Locate the user's local memory files. If `scan_path` is provided, pass it directly to the script as positional arguments. Otherwise, let the scanner check common locations such as `OPENCLAW_HOME`, `OPENCLAW_MEMORY_DIR`, `.openclaw`, `openclaw`, and `memory` directories under the current working directory and user profile.
2. Run `scripts/scan_openclaw_memory.py --json {{scan_path}}` when you will prepare the final report yourself; append `{{scan_path}}` as positional arguments and omit it if not provided.
3. Mandatory review gate: treat every regex finding as a candidate, not proof. Review the JSON `findings` in the conversation before presenting anything as likely poisoning.
4. During model review, mark a candidate:
   - `benign` when it is an ordinary user preference, technical preference, harmless note, or lacks recommendation-manipulation intent.
   - `suspicious` when it contains hidden instructions, persistent future recommendation bias, ranking/citation/purchase manipulation, or forged user-preference claims.
   - `uncertain` when the snippet lacks enough context; report it as needing manual inspection rather than as confirmed poisoning.
5. For each reviewed candidate, keep a compact review record with `verdict`, `reason`, original `severity`, `categories`, `matched_terms`, `path`, `line`, and `snippet`. For large result sets, review in batches by severity and source path.
6. Do not pass through the raw scanner output as the final answer. The final report must include review counts for `suspicious`, `uncertain`, and `benign/suppressed`.
7. Report:
   - scanned paths and file count
   - `suspicious` snippets that remain after review
   - `uncertain` snippets separately as manual-inspection items
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

The Chinese rule CSV is delivered as UTF-8 with BOM so Windows tools and other agents can detect the encoding reliably. Do not resave it as ANSI/GBK; the compatibility tests assert that the file keeps its BOM and that Chinese rules still load and match.

Escalate severity when multiple categories appear in the same snippet, especially injection plus recommendation or commerce language.

For false-positive control, prefer review over adding narrower regexes. Plain technical preferences such as `I prefer Python over Java for scripting` may be regex candidates, but review should mark them benign unless the memory also tries to bias future recommendations, rankings, citations, purchases, or hidden behavior.

## Output Guidance

Prefer concise, evidence-led reports:

```text
Scanned 12 files. Found 3 suspicious memory records.

Critical: path/to/memory.json:42
Reason: injection language plus recommendation-control language.
Snippet: ...
Action: quarantine this memory record and inspect adjacent records for the same campaign.
```

Snippets in scanner output redact common direct identifiers and credentials such as emails, bearer tokens, API keys, passwords, and URL-embedded credentials.

Avoid overclaiming intent. Say "possible poisoning" or "suspicious recommendation-bias instruction" unless the file clearly contains an explicit malicious instruction.
