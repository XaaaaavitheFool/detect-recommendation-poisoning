---
name: detect-recommendation-poisoning
description: Use when asked to inspect Hermes USER.md- or MEMORY.md-style profile memory for commercial recommendation poisoning or general memory poisoning, including persistent behavioral control, forged authority, safety bypass, tool hijacking, exfiltration, concealment, propagation, or obfuscated instructions.
---
# Detect Hermes Memory Poisoning

Use this file only to ask the user to choose a review route, then select the scan
scope and load one review procedure.

## Choose Review Route First

Before resolving any scan target, enumerating or reading files, reading `.env`,
installing dependencies, or loading either reference, show the following two
options in the language of the user's request and wait for an explicit choice:

1. **Local model direct review**
   - Advantage: When local model performance is good, the local model can
     complete the review directly, and memory files are not uploaded to a third
     party.
   - Disadvantage: Review quality depends on local model performance and may be
     weaker when that performance is average.
2. **`deepseek-v4-pro` prefilter + local model review**
   - Advantage: When local model performance is average, `deepseek-v4-pro` can
     prefilter first and the local model reviews the resulting candidates.
   - Disadvantage: The full content and source metadata of the memory files will
     be uploaded to DeepSeek's official service and may contain sensitive
     information.
   - Authorization: Selecting option 2 is explicit consent to external
     processing for the current invocation. No second confirmation is required.

There is no default. A missing or ambiguous choice must stop and wait for the
user to choose; do not begin either route. Model identity, an API key,
configuration, a prior invocation's choice or consent, and a generic scan
request do not select a route. Each invocation requires a new choice.

If the user revokes option 2 before the external call, stop and show this route
chooser again. Do not switch to local review automatically.

Load and follow exactly one reference:

- Load `references/direct.md` only after the user unambiguously chooses option 1.
- Load `references/review.md` only after the user unambiguously chooses option 2.

After selecting the route, read that reference completely. Do not load the other
reference during the same invocation. If the route-choice gate in
`references/review.md` fails or the user revokes consent before the external
call, stop the external procedure and return to the route chooser.

## Scan Scope

Resolve the scan scope only after the route has been selected. Accept a
`scan_path` pointing to a file or directory. Review only Markdown files named
`USER.md` or `MEMORY.md`, or whose stem ends in `_USER` or `_MEMORY`. When
`scan_path` is omitted, use `HERMES_MEMORY_DIR`, `HERMES_HOME`, the current
working directory, and the user profile to check common `.hermes`, `hermes`, and
`memories` locations.

When walking a directory, compare directory names case-insensitively and do not
follow directory symlinks. Prune these directories before traversal: `.git`,
`.venv`, `venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`,
`.cache`, `.tox`, `.nox`, `node_modules`, `site-packages`, `vendor`, `build`,
`dist`, `target`, and `out`. Apply this rule to the supplied directory itself
and every descendant. An explicitly supplied matching file remains eligible
even when its parent directory would be skipped during a directory scan.
