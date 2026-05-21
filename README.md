# Detect Recommendation Poisoning

`detect-recommendation-poisoning` is an OpenClaw skill for scanning local AI memory files for recommendation poisoning signals. It looks for suspicious attempts to make an AI assistant remember, trust, cite, prefer, rank, or recommend a specific brand, vendor, product, source, or domain in future answers.

The skill is designed for local use. It does not upload memory files, does not call a separate model by itself, and does not automatically delete or modify memories. Its scanner produces regex candidates that should be reviewed before they are treated as real poisoning.

## Why This Exists

AI assistants are becoming search, comparison, purchasing, and decision-support interfaces. At the same time, many assistants and agent frameworks now keep long-term memory. That creates a new attack surface: a prompt hidden behind a normal-looking "Summarize with AI" or "Ask AI about this" link can try to write persistent bias into an assistant's memory.

Microsoft Defender Security Research publicly described this pattern as AI Recommendation Poisoning in February 2026, including prompts that try to make AI assistants remember a company as trusted, cite a source in the future, or recommend a product first. This skill focuses on the local memory layer: after suspicious content has entered OpenClaw memory, it helps users find and review it.

## What It Detects

The bundled scanner checks for combinations of signals across English and Chinese rule libraries, including:

- Memory write attempts such as `remember`, `keep in memory`, `for future reference`, or similar Chinese phrases.
- Trust injection such as `trusted source`, `authoritative`, `source of expertise`, or equivalent Chinese wording.
- Recommendation bias such as `always recommend`, `prefer`, `prioritize`, `default to`, or "recommend first" language.
- Citation bias such as `cite`, `citation source`, or instructions to use a source as an authority.
- User preference forgery such as claims that the user has always trusted, verified, preferred, or chosen a specific entity.
- Combined signals where an AI prompt URL, brand/domain, future reference, memory write, and recommendation control appear together.

Supported memory scan targets include common text and memory formats such as Markdown, JSON, JSONL, TXT, YAML, TOML, logs, CSV files, and SQLite databases. The scanner only selects files that appear to be OpenClaw memory artifacts, such as files under an OpenClaw `memory` or `memories` directory or files whose own name indicates memory content.

## OpenClaw Skill Installation

Install the skill from GitHub into OpenClaw's `skills` directory. If `OPENCLAW_HOME` is not configured, the examples below use the default local OpenClaw home directory.

### Windows PowerShell

```powershell
$OpenClawHome = if ($env:OPENCLAW_HOME) { $env:OPENCLAW_HOME } else { "$env:USERPROFILE\.openclaw" }
New-Item -ItemType Directory -Force "$OpenClawHome\skills" | Out-Null
git clone git@github.com:XaaaaavitheFool/detect-recommendation-poisoning.git "$OpenClawHome\skills\detect-recommendation-poisoning"
```

If you do not use SSH keys for GitHub, clone with HTTPS instead:

```powershell
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git "$OpenClawHome\skills\detect-recommendation-poisoning"
```

### macOS or Linux

```bash
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
mkdir -p "$OPENCLAW_HOME/skills"
git clone git@github.com:XaaaaavitheFool/detect-recommendation-poisoning.git "$OPENCLAW_HOME/skills/detect-recommendation-poisoning"
```

HTTPS clone alternative:

```bash
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git "$OPENCLAW_HOME/skills/detect-recommendation-poisoning"
```

After cloning, restart or reload OpenClaw so it can discover the new skill. The installed skill should exist at:

```text
<OPENCLAW_HOME>/skills/detect-recommendation-poisoning/SKILL.md
```

## Skill Usage in OpenClaw

Ask OpenClaw to use the skill directly:

```text
Use the detect-recommendation-poisoning skill to scan my OpenClaw memory files and report suspicious findings.
```

To scan a specific memory directory or file:

```text
Use the detect-recommendation-poisoning skill to scan C:\path\to\openclaw\memory and produce a reviewed report.
```

The expected workflow is:

1. Locate the OpenClaw memory files, or provide an explicit path.
2. Run the scanner with JSON output when preparing a reviewed report.
3. Treat every scanner match as a candidate, not proof.
4. Review each candidate as `suspicious`, `uncertain`, or `benign`.
5. Write a final reviewed Markdown report after review. If the scanner JSON was saved as `scan_report.json`, write `scan_report_reviewed.md` next to it.
6. Report suspicious findings separately from uncertain items.
7. Quarantine or clean affected memory records only after review.

## Command-Line Usage

You can also run the scanner directly from the skill directory.

```bash
cd detect-recommendation-poisoning
python scripts/scan_openclaw_memory.py
```

When no path is provided, the scanner checks common OpenClaw memory locations, including `OPENCLAW_MEMORY_DIR`, `OPENCLAW_HOME`, `.openclaw`, `openclaw`, `memory`, and `memories` directories under the current workspace or user profile.

Directory and explicit-file scans are filtered before file content is read. Passing a broad path such as a project root will not scan every supported text file below it; only OpenClaw memory-looking files are considered. Passing an ordinary non-memory file explicitly will be skipped.

Scan one or more explicit paths:

```bash
python scripts/scan_openclaw_memory.py /path/to/openclaw/memory /path/to/other-memory.json
```

Write JSON output for review or automation:

```bash
python scripts/scan_openclaw_memory.py --json --output findings.json /path/to/openclaw/memory
```

Use verbose logs while keeping the report on stdout:

```bash
python scripts/scan_openclaw_memory.py --verbose /path/to/openclaw/memory
```

Override the bundled rule files only when needed:

```bash
python scripts/scan_openclaw_memory.py --rules references/recommendation_poisoning_keyword_regex_rules.csv references/recommendation_poisoning_keyword_regex_rules_zh.csv -- /path/to/openclaw/memory
```

Use `--` before scan paths when `--rules` is present, especially if any scan target is also a CSV file.

## Output

The default output is a Markdown candidate report. Use `--json` for machine-readable output. Each finding can include:

- File path and line number.
- Scanner severity and scanner regex score for triage.
- Matched categories and terms.
- A redacted snippet for review.
- Source information for SQLite rows when applicable.

The scanner redacts common direct identifiers and secrets such as emails, bearer tokens, API keys, passwords, and URL-embedded credentials in snippets.

JSON output includes `scan_status` and `scan_message`. Treat `invalid_input` and `no_memory_files` as runs that did not complete a useful memory scan. If `no_memory_files` is reported, tell the user no OpenClaw memory files were found instead of presenting the result as clean. SQLite scanning also reports `sqlite_row_limit_per_table`; if a table reaches that limit, the scanner logs a warning so large databases are not mistaken for fully scanned tables.

## Review Guidance

Mark a candidate as `benign` when it is an ordinary user preference, harmless technical note, or lacks recommendation-manipulation intent.

Mark a candidate as `suspicious` when it contains hidden instructions, persistent future recommendation bias, ranking manipulation, citation manipulation, purchase/vendor steering, trust injection, or forged user-preference claims.

Mark a candidate as `uncertain` when the snippet lacks enough context. Report uncertain items as manual-inspection work, not confirmed poisoning.

Before marking an injection-looking candidate suspicious, check whether it is negated, quoted as an example, sarcastic, or part of "what not to do" safety guidance.

After review, create a final Markdown report file rather than only summarizing in chat. The report should include the source scanner JSON, scan status, scanned file count, regex candidate count, reviewed counts for `suspicious`, `uncertain`, and `benign/suppressed`, grouped suspicious findings, uncertain manual-inspection items, affected domains or products, and cleanup recommendations.

The reviewed report must also include detailed evidence for every non-benign candidate. Each evidence row must include verdict, original scanner severity, original scanner score if available, filename or path, line number, source, categories, matched terms, the complete redacted matched record or paragraph, and the review reason. If the scanner JSON snippet starts or ends in the middle of a word or sentence, re-read the current source memory file and expand the final report evidence to the complete memory record, line, or paragraph. Grouped domain or pattern summaries are useful, but they must not replace the detailed evidence table.

The numeric score is a scanner-generated regex triage score, not an LLM judgment. Use it only for sorting and explaining why a candidate was surfaced. Do not ask the reviewing model to invent or revise a score; the review step should produce only a verdict (`suspicious`, `uncertain`, or `benign`) and a reason.

Base the review only on the current scanner JSON candidates and, when needed, the current source memory files. Do not read, reuse, summarize, diff against, or cite any previous reviewed report file such as `*_reviewed.md`; previous reviewed reports are stale outputs, not review inputs.

Recommended report naming:

- Saved scanner output `scan_report.json` -> reviewed report `scan_report_reviewed.md`.
- Saved scanner output `findings.json` -> reviewed report `findings_reviewed.md`.
- Stdout-only scanner output -> reviewed report `openclaw_recommendation_poisoning_reviewed_report.md`.

If the reviewed report path already exists, overwrite it with the current reviewed report. Do not inspect or reuse the old report before overwriting it, and do not create timestamped or numbered alternates unless the user explicitly requests versioned reports.

## Testing

Run the regression suite with either command:

```bash
python -m unittest -v
python -m unittest discover -s tests -v
```

## Limitations

This skill is an offline detector, not a runtime firewall. It does not intercept links, block prompts, delete memories, or decide whether a commercial recommendation is true. It focuses on explainable and reviewable text signals in memory files.

It may miss attacks that use no obvious keywords, heavy paraphrasing, images, dynamic scripts, multi-turn slow poisoning, or behavior that can only be confirmed through model-output analysis. Use it as a first local memory audit layer, then combine findings with context review and normal incident-response practice.

## Project Layout

```text
detect-recommendation-poisoning/
  SKILL.md
  agents/openai.yaml
  references/recommendation_poisoning_keyword_regex_rules.csv
  references/recommendation_poisoning_keyword_regex_rules_zh.csv
  scripts/scan_openclaw_memory.py
  tests/test_sqlite_scanning.py
```

## References

- Microsoft Security Blog: https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/
