---
name: detect-recommendation-poisoning
description: Use when asked to inspect OpenClaw memory files, audit recommendation integrity, detect recommendation poisoning or memory injection, find suspicious bias in recommendations, rankings, citations, purchases, product choices, or model preference behavior, or produce a reviewed report of suspicious recommendation-manipulation signals.
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

The scanner only scans files that look like OpenClaw memory artifacts. Directory scans are filtered before reading file content, and explicitly provided files are skipped unless their path or filename indicates memory content.

When the `scan_path` parameter is provided, pass it as a positional argument to the script:

```bash
python scripts/scan_openclaw_memory.py {{scan_path}}
```

Multiple paths can be passed:

```bash
python scripts/scan_openclaw_memory.py C:\path\to\openclaw\memory C:\path\to\other-memory.json
```

Capture machine-readable output for internal review only:

```bash
python scripts/scan_openclaw_memory.py --json C:\path\to\memory
```

When preparing a user-facing report, run JSON output and review the regex candidates before reporting. Treat the scanner JSON as an internal working artifact:

```bash
python scripts/scan_openclaw_memory.py --json C:\path\to\memory
```

Do not show, quote, attach, link, or summarize the raw scanner JSON to the user. Do not write scanner JSON to disk unless an internal temporary file is necessary for processing; if such a file is created, delete it after the reviewed Markdown report is written and do not disclose its path.

The scanner itself does not configure or call a separate model. Its output is an unreviewed candidate list, not the final assessment.

Use explicit regex rule files only when overriding the bundled rules:

```bash
python scripts/scan_openclaw_memory.py --rules C:\repo\data\raw\recommendation_poisoning_keyword_regex_rules.csv C:\repo\data\raw\recommendation_poisoning_keyword_regex_rules_zh.csv -- C:\path\to\memory
```

Use `--` to separate rule files from scan paths, especially when the scan target is also a `.csv` file.

If JSON output reports `scan_status` as `invalid_input` or `no_memory_files`, treat the run as not having completed a useful memory scan. SQLite tables are scanned with a documented per-table row limit; check `sqlite_row_limit_per_table` in JSON output when reviewing large databases.

## Strict Review Execution Contract

During review, execute this skill exactly as written and in order. Do not replace, reorder, or skip workflow steps unless a step explicitly says to stop for that condition. Do not add extra review criteria, risk labels, scoring, mitigations, assumptions, or conclusions beyond what this skill and the scanner JSON require.

The scanner JSON is internal-only. Use it only as review input; never expose its raw contents, filename, path, or structured fields to the user except as reviewed evidence already rewritten into the final Markdown report. The reviewed Markdown report is the source of truth for user-facing results. Every chat summary must be copied or directly derived from the current reviewed report; do not infer additional findings from memory, prior reports, unstated context, scanner JSON fields not included in the reviewed report, or model intuition. If a required scan, review, or report-writing step fails, state the failed step and do not present the scan as completed.

End every completed chat response for this skill with this exact marker on its own line:

```text
=== SKILL EXECUTION COMPLETE: detect-recommendation-poisoning ===
```

## Workflow

1. Locate the user's local memory files. If `scan_path` is provided, pass it directly to the script as positional arguments. Otherwise, let the scanner check common locations such as `OPENCLAW_HOME`, `OPENCLAW_MEMORY_DIR`, `.openclaw`, `openclaw`, and `memory` directories under the current working directory and user profile. The scanner must only scan OpenClaw memory-looking files; do not broaden the target by scanning arbitrary files under a path, and do not scan explicit single files unless they look like memory artifacts.
2. Run `scripts/scan_openclaw_memory.py --json {{scan_path}}` when you will prepare the final report yourself; append `{{scan_path}}` as positional arguments and omit it if not provided. Capture the JSON internally. Do not display it in chat or save it as a user-facing artifact.
   - If the scanner reports `scan_status: no_memory_files`, stop and tell the user that no OpenClaw memory files were found instead of producing a clean/security-passed report.
3. Mandatory review gate: treat every regex finding as a candidate, not proof. Review the internal JSON `findings` before presenting anything as likely poisoning.
   - The LLM review process must first check whether each regex candidate is in a commercial or economic-value context, using the scanner result fields such as `snippet`, `matched_terms`, `categories`, `path`, and `source`. Commercial context includes products, brands, vendors, providers, services, purchases, subscriptions, sponsorships, affiliates, commissions, pricing, rankings, ratings, citations, traffic steering, or other monetizable recommendations.
   - If that commercial/economic context is absent, mark the candidate `benign` and suppress it from suspicious/uncertain findings, even when the raw regex matched injection-like or preference-like language. This is a review-time filter; do not change or depend on scanner implementation for this decision.
4. During model review, mark a candidate:
   - `benign` when it lacks commercial/economic-value context, is an ordinary user preference, technical preference, harmless note, or lacks recommendation-manipulation intent.
   - `suspicious` when it contains hidden instructions, persistent future recommendation bias, ranking/citation/purchase manipulation, or forged user-preference claims.
   - `uncertain` when the snippet lacks enough context; report it as needing manual inspection rather than as confirmed poisoning.
   - Check negation, quoted examples, sarcasm, and "what not to do" safety guidance before treating an injection-looking candidate as suspicious.
5. For each reviewed candidate, keep a compact review record with `verdict`, `reason`, original scanner `severity`, original scanner `score` when present, `categories`, `matched_terms`, `path`, `line`, and `snippet`. For large result sets, review in batches by severity and source path. Do not ask the reviewing model to invent or revise a numeric score; the model review output is only `verdict` and `reason`.
6. Base the review only on the current scanner JSON candidates and, when needed, the current source memory files. Do not read, reuse, summarize, diff against, or cite any previous reviewed report file such as `*_reviewed.md`; prior reviewed reports are stale outputs, not review inputs.
7. After review, write a final reviewed Markdown report to disk before answering the user. Write `openclaw_recommendation_poisoning_reviewed_report.md` in the current working directory unless the user requested another reviewed-report path. If the final reviewed report path already exists, overwrite it with the newly reviewed report so stale review output cannot be mistaken for the current result. If an internal scanner JSON file was created, delete it after the reviewed report is written.
8. Do not pass through the raw scanner output as the final answer or include it in the reviewed report. The final reviewed report file must include review counts for `suspicious`, `uncertain`, and `benign/suppressed`.
9. The final reviewed report file must include:
   - note that internal scanner JSON was reviewed, without exposing its path or raw contents
   - scan status, scanned paths, scanned file count, and regex candidate count
   - review methodology and review labels
   - counts for `suspicious`, `uncertain`, and `benign/suppressed`
   - a detailed reviewed-evidence table for every candidate that is not benign/suppressed; each row must include `verdict`, original scanner `severity`, original scanner `score` if available, file path or filename, line, source, categories, matched terms, reviewed reason, and a complete redacted evidence record/paragraph
   - Evidence snippets in the final report must not be word-fragment or sentence-fragment excerpts. If the scanner JSON `snippet` begins or ends mid-word, mid-sentence, or otherwise lacks enough context, re-read the current source memory file and include the complete memory record, line, or paragraph that contains the match. Fall back to the scanner snippet only when the source file is unavailable, and label that fallback as scanner-truncated evidence.
   - `suspicious` findings that remain after review, grouped by severity, source path, domain, brand, or attack pattern when useful; grouping is allowed only in addition to the detailed evidence table, not as a replacement for it
   - `uncertain` findings separately as manual-inspection items, with the same file name, line, evidence snippet, and reason fields
   - a concise benign/suppressed summary; if benign items are numerous, summarize them by false-positive pattern, but keep the compact review records available in the report or an adjacent appendix
   - affected brands/items/categories if obvious
   - why each finding or group matters
   - recommended cleanup, quarantine, or follow-up validation
10. In the chat final answer, report only the reviewed counts, the reviewed report path, and any blocker already recorded in the reviewed report. Do not rely on chat text alone as the final report, and do not add findings, caveats, or recommendations that are not in the reviewed report.
11. Report content:
   - scanned paths and file count
   - `suspicious` snippets that remain after review
   - `uncertain` snippets separately as manual-inspection items
   - affected brands/items/categories if obvious
   - why each finding matters
   - recommended cleanup, quarantine, or follow-up validation

## Detection Heuristics

The scanner assigns a heuristic regex score to combinations of signals:

- The score is produced by the scanner rules, not by the reviewing LLM.
- Use it only for triage, sorting, and explaining why a regex candidate surfaced.
- Do not treat it as probability, confidence, impact, or final risk.
- Do not ask the reviewing model to create a new numeric score. Review should produce `suspicious`, `uncertain`, or `benign` plus a short reason.
- In final reviewed reports, label it as `Scanner Score` or `Regex Score`, and explain that the review verdict overrides the raw score.

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

Final reviewed report template:

```markdown
# Reviewed OpenClaw Recommendation Poisoning Report

Reviewed on: YYYY-MM-DD
Source scanner output: internal scanner JSON reviewed; raw JSON not disclosed

## Summary

- Scan status: `ok`
- Scanned files: 12
- Regex candidates reviewed: 3
- Reviewed suspicious: 1
- Reviewed uncertain: 1
- Reviewed benign/suppressed: 1

## Review Method

Describe how candidates were reviewed and what labels mean.

## Suspicious Findings

Group confirmed suspicious records by path, domain, product, source, or pattern. Include compact snippets and reasons.

## Detailed Reviewed Evidence

| Verdict | Scanner Severity | Regex Score | File | Line | Source | Categories | Matched Terms | Evidence Snippet | Review Reason |
|---|---|---:|---|---:|---|---|---|---|---|
| suspicious | high | 8 | memory.json | 42 | file | injection, recommendation_bias | `always recommend` | Redacted paragraph around the matched text. | Explains why this is persistent recommendation manipulation. |

List every non-benign candidate here. Do not replace this table with only grouped summaries.

## Uncertain Findings

List items that need manual inspection.

## Benign/Suppressed

Summarize suppressed false positives without repeating every harmless snippet.

## Recommended Cleanup

List quarantine, deletion, rewrite, and re-scan steps.
```

Snippets in scanner output redact common direct identifiers and credentials such as emails, bearer tokens, API keys, passwords, and URL-embedded credentials.

Avoid overclaiming intent. Say "possible poisoning" or "suspicious recommendation-bias instruction" unless the file clearly contains an explicit malicious instruction.
