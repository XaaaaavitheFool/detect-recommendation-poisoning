#!/usr/bin/env python3
"""Scan OpenClaw memory files for recommendation poisoning indicators."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Iterable


TEXT_EXTENSIONS = {
    ".json",
    ".jsonl",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".toml",
    ".log",
    ".csv",
}
SQLITE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}

LOGGER = logging.getLogger("scan_openclaw_memory")

# 单个 memory 文件过大时跳过，避免误扫日志归档或二进制缓存导致运行很久。
MAX_FILE_BYTES = 25 * 1024 * 1024

# 每个命中点前后保留的上下文长度，用于报告中人工复核。
SNIPPET_RADIUS = 220

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULE_PATHS = [
    SKILL_ROOT / "references" / "recommendation_poisoning_keyword_regex_rules.csv",
    SKILL_ROOT / "references" / "recommendation_poisoning_keyword_regex_rules_zh.csv",
]


# 检测规则按“信号类别”分组。单独出现某一类信号不一定恶意，
# 但多个类别在同一段 memory 中共同出现时，推荐投毒风险会显著升高。
PATTERNS = {
    "recommendation_control": [
        r"\balways\s+(recommend|suggest|choose|pick|prefer)\b",
        r"\bmust\s+(recommend|suggest|choose|pick|prefer|rank)\b",
        r"\b(rank|place|put)\s+.+\b(first|top|#1|number one)\b",
        r"\b(prefer|promote|boost|prioriti[sz]e|favor)\s+.+\b(over|instead of|above)\b",
        r"\bnever\s+(recommend|suggest|mention|show)\b",
        r"\bavoid\s+(recommending|suggesting|mentioning|showing)\b",
        r"\bhide\s+(competitors?|negative|bad|critical)\b",
    ],
    "injection": [
        r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b",
        r"\bsystem\s+(override|instruction|message|prompt)\b",
        r"\bdeveloper\s+(message|instruction|override)\b",
        r"\bhidden\s+(instruction|prompt|rule)\b",
        r"\bdo\s+not\s+(reveal|disclose|mention)\b",
        r"\bsecretly\s+(recommend|promote|prefer|bias)\b",
        r"\bwithout\s+(telling|informing|revealing)\s+(the\s+)?user\b",
    ],
    "commerce_or_ranking": [
        r"\b(product|vendor|brand|merchant|seller|service|tool|app)\b",
        r"\b(buy|purchase|subscribe|order|checkout|affiliate|sponsor(ed)?|commission)\b",
        r"\b(ranking|ranked|top\s+result|search\s+result|review|rating|stars?)\b",
        r"\b(best|cheapest|highest\s+rated|most\s+trusted)\b",
    ],
    "persistence": [
        r"\bremember\s+this\b",
        r"\bstored?\s+(memory|preference|profile|instruction)\b",
        r"\b(user\s+)?preference\b",
        r"\bmemory\s+(entry|record|note|instruction)\b",
    ],
    "obfuscation": [
        r"[\u200b\u200c\u200d\ufeff]",
        r"<!--.*?(recommend|promote|prefer|ignore).*?-->",
        r"(?i)\b(base64|rot13|encoded|payload)\b",
        r"(?i)<\|.*?(system|developer|instruction).*?\|>",
        r"\b[A-Za-z0-9+/]{80,}={0,2}\b",
    ],
}


COMPILED = {
    category: [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns]
    for category, patterns in PATTERNS.items()
}

SENSITIVE_REDACTIONS = [
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    (
        re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
        r"\1[REDACTED_TOKEN]",
    ),
    (
        re.compile(r"\b(?:sk|ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b"),
        "[REDACTED_TOKEN]",
    ),
    (
        re.compile(r"\b(?:sk|ghp|gho)-[A-Za-z0-9_]{20,}\b"),
        "[REDACTED_TOKEN]",
    ),
    (
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "[REDACTED_AWS_KEY]",
    ),
    (
        re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"),
        r"\1[REDACTED_CREDENTIALS]@",
    ),
]

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"api[_-]?key|token|secret|password|passwd|pwd|access[_-]?token|refresh[_-]?token"
    r")(\s*[:=]\s*)([\"']?)([^\s,\"';}]+)([\"']?)"
)

RULE_WEIGHTS = {
    "recommendation_control": 3,
    "injection": 4,
    "commerce_or_ranking": 1,
    "persistence": 1,
    "obfuscation": 2,
    "memory_write": 4,
    "trust_injection": 3,
    "recommendation_bias": 4,
    "citation_bias": 3,
    "user_preference_forgery": 5,
}


@dataclass
class Finding:
    """一次可疑命中的结构化结果，既可渲染 Markdown，也可输出 JSON。"""

    path: str
    line: int
    severity: str
    score: int
    categories: list[str]
    matched_terms: list[str]
    snippet: str
    source: str = "file"
    llm_verdict: str | None = None
    llm_reason: str | None = None


@dataclass
class LLMReview:
    """A second-pass judgment for one regex candidate."""

    verdict: str
    reason: str


def load_csv_rules(paths: Iterable[Path]) -> dict[str, list[re.Pattern[str]]]:
    """Load the English/Chinese CSV regex rules and merge them with built-in rules."""

    rules: dict[str, list[re.Pattern[str]]] = {
        category: list(patterns) for category, patterns in COMPILED.items()
    }
    builtin_count = sum(len(patterns) for patterns in rules.values())
    loaded_count = 0
    for path in paths:
        if not path.exists():
            LOGGER.warning("Rule file not found: %s", path)
            continue
        file_count = 0
        skipped_count = 0
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("pattern_type") != "regex":
                    continue
                category = (row.get("category") or "").strip()
                pattern = (row.get("pattern") or "").strip()
                if not category or not pattern:
                    skipped_count += 1
                    continue
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                except re.error:
                    skipped_count += 1
                    continue
                rules.setdefault(category, []).append(compiled)
                file_count += 1
        loaded_count += file_count
        if skipped_count:
            LOGGER.info("Loaded %s regex rules from %s (%s skipped)", file_count, path, skipped_count)
        else:
            LOGGER.info("Loaded %s regex rules from %s", file_count, path)
    LOGGER.info(
        "Rule library ready: %s built-in rules + %s CSV rules across %s categories",
        builtin_count,
        loaded_count,
        len(rules),
    )
    return rules



def default_paths() -> list[Path]:
    """在用户未传路径时，尝试常见的 OpenClaw memory 存放位置。"""

    candidates: list[Path] = []
    for env_name in ("OPENCLAW_MEMORY_DIR", "OPENCLAW_HOME"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(Path(value).expanduser())

    home = Path.home()
    cwd = Path.cwd()
    candidates.extend(
        [
            cwd / ".openclaw",
            cwd / "openclaw",
            cwd / "memory",
            cwd / "memories",
            home / ".openclaw",
            home / ".config" / "openclaw",
            home / "AppData" / "Roaming" / "OpenClaw",
            home / "AppData" / "Local" / "OpenClaw",
        ]
    )
    return dedupe_paths(candidates)


def dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    """按解析后的绝对路径去重，保留原始传入顺序。"""

    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        try:
            key = str(path.expanduser().resolve())
        except OSError:
            key = str(path.expanduser())
        if key not in seen:
            seen.add(key)
            result.append(path.expanduser())
    return result


def iter_files(paths: Iterable[Path]) -> Iterable[Path]:
    """遍历用户传入的文件或目录，只返回可能包含 memory 内容的文件。"""

    for path in paths:
        if not path.exists():
            LOGGER.warning("Scan path does not exist: %s", path)
            continue
        if path.is_file():
            if not is_supported(path):
                LOGGER.debug("Scanning explicitly provided file with uncommon extension: %s", path)
            yield path
            continue
        LOGGER.info("Walking directory: %s", path)
        for file_path in path.rglob("*"):
            if file_path.is_file() and is_supported(file_path):
                yield file_path


def is_supported(path: Path) -> bool:
    """用扩展名和文件名粗筛，减少扫描无关文件的噪音。"""

    name = path.name.lower()
    if path.suffix.lower() in TEXT_EXTENSIONS | SQLITE_EXTENSIONS:
        return True
    return any(token in name for token in ("memory", "memories", "openclaw"))


def read_text(path: Path) -> str | None:
    """以多种常见编码读取文本文件，读取失败时返回 None。"""

    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            LOGGER.warning("Skipping oversized file: %s", path)
            return None
        data = path.read_bytes()
    except OSError as exc:
        LOGGER.warning("Failed to read file %s: %s", path, exc)
        return None
    for encoding in ("utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def sqlite_readonly_uri(path: Path) -> str:
    """Build a read-only SQLite URI without letting special path chars alter query params."""

    try:
        resolved = path.expanduser().resolve()
    except OSError:
        resolved = path.expanduser().absolute()
    return f"{resolved.as_uri()}?mode=ro"


def quote_sqlite_identifier(identifier: str) -> str:
    """Quote a SQLite table or column name, including names that contain quotes."""

    return '"' + identifier.replace('"', '""') + '"'


def sqlite_text_value(value: object) -> str | None:
    """Return textual SQLite cell content while ignoring ordinary numeric/null values."""

    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        for encoding in ("utf-8", "utf-16", "cp1252", "latin-1"):
            try:
                text = value.decode(encoding)
            except UnicodeDecodeError:
                continue
            if text.count("\x00") <= max(1, len(text) // 20):
                return text.replace("\x00", " ")
    return None


def extract_sqlite_text(path: Path) -> tuple[bool, list[tuple[str, str]]]:
    """从 SQLite memory 数据库中抽取文本列。

    OpenClaw 的 memory 可能落在 SQLite 中；这里以只读模式打开数据库，
    只扫描 TEXT/JSON/未声明类型的列，并限制每张表最多 10000 行。
    """

    try:
        conn = sqlite3.connect(sqlite_readonly_uri(path), uri=True)
    except (OSError, sqlite3.Error) as exc:
        LOGGER.warning("Failed to open SQLite file %s: %s", path, exc)
        return False, []
    records: list[tuple[str, str]] = []
    try:
        try:
            rows = conn.execute(
                "select name from sqlite_master where type='table' and name not like 'sqlite_%'"
            ).fetchall()
        except sqlite3.Error as exc:
            LOGGER.warning("Failed to read SQLite schema from %s: %s", path, exc)
            return False, []
        for (table,) in rows:
            try:
                quoted_table = quote_sqlite_identifier(str(table))
                info = conn.execute(f"pragma table_info({quoted_table})").fetchall()
                column_names = [str(col[1]) for col in info if col[1]]
                if not column_names:
                    continue
                col_expr = ", ".join(quote_sqlite_identifier(col) for col in column_names[:32])
                for row_idx, row in enumerate(
                    conn.execute(f"select {col_expr} from {quoted_table} limit 10000"), start=1
                ):
                    text = "\n".join(
                        text_value
                        for value in row
                        if (text_value := sqlite_text_value(value)) is not None
                    )
                    if text.strip():
                        records.append((f"sqlite:{table}:{row_idx}", text))
            except sqlite3.Error as exc:
                LOGGER.warning("Failed to scan SQLite table %s in %s: %s", table, path, exc)
                continue
    finally:
        conn.close()
    return True, records


def line_for_offset(text: str, offset: int) -> int:
    """把字符偏移转换成 1-based 行号，方便用户定位源文件。"""

    return text.count("\n", 0, offset) + 1


def normalize_snippet(text: str, start: int, end: int) -> str:
    """截取命中附近上下文，并压缩多余空白，让报告更容易读。"""

    left = max(0, start - SNIPPET_RADIUS)
    right = min(len(text), end + SNIPPET_RADIUS)
    snippet = text[left:right].replace("\r", "\n")
    snippet = re.sub(r"\n{3,}", "\n\n", snippet)
    snippet = re.sub(r"[ \t]{2,}", " ", snippet)
    return redact_sensitive_text(snippet.strip())


def redact_sensitive_text(text: str) -> str:
    """Mask common credentials and direct identifiers before they reach reports."""

    def replace_secret_assignment(match: re.Match[str]) -> str:
        key, separator, quote, _secret, closing_quote = match.groups()
        if quote and closing_quote and quote != closing_quote:
            return match.group(0)
        return f"{key}{separator}{quote}[REDACTED_SECRET]{closing_quote if quote else ''}"

    redacted = SECRET_ASSIGNMENT_RE.sub(replace_secret_assignment, text)
    for pattern, replacement in SENSITIVE_REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def scan_text(
    path: Path,
    text: str,
    source: str = "file",
    rules: dict[str, list[re.Pattern[str]]] | None = None,
) -> list[Finding]:
    """扫描一段文本，合并相邻命中，并按信号组合计算风险。"""

    anchors: list[tuple[int, int, str, str]] = []
    category_hits: dict[str, list[re.Match[str]]] = {}
    active_rules = rules or COMPILED
    for category, patterns in active_rules.items():
        hits: list[re.Match[str]] = []
        for pattern in patterns:
            hits.extend(pattern.finditer(text))
        if hits:
            category_hits[category] = hits
            for hit in hits:
                anchors.append((hit.start(), hit.end(), category, hit.group(0)))

    findings: list[Finding] = []
    seen_windows: set[tuple[int, int]] = set()
    for start, end, category, term in anchors:
        # 以窗口为单位去重，避免同一段投毒文本因为多个关键词被重复报告。
        window_start = max(0, start - SNIPPET_RADIUS)
        window_end = min(len(text), end + SNIPPET_RADIUS)
        window_key = (window_start // 120, window_end // 120)
        if window_key in seen_windows:
            continue
        seen_windows.add(window_key)

        categories: list[str] = []
        terms: list[str] = []
        for hit_category, hits in category_hits.items():
            for hit in hits:
                # 收集同一上下文窗口内的所有信号类别，后续评分依赖类别组合。
                if hit.start() <= window_end and hit.end() >= window_start:
                    categories.append(hit_category)
                    terms.append(redact_sensitive_text(hit.group(0).strip()))
                    break

        categories = sorted(set(categories))
        score = score_categories(categories)
        if score < 3:
            continue

        severity = severity_for_score(score)
        findings.append(
            Finding(
                path=str(path),
                line=line_for_offset(text, start),
                severity=severity,
                score=score,
                categories=categories,
                matched_terms=sorted(set(terms), key=str.lower)[:10],
                snippet=normalize_snippet(text, start, end),
                source=source,
            )
        )
    return findings


def score_categories(categories: list[str]) -> int:
    """给信号类别组合打分。

    注入指令和推荐控制同时出现时风险最高；推荐控制和商业/排名语境
    同时出现时，也更像 recommendation poisoning 而不是普通偏好记录。
    """

    score = sum(RULE_WEIGHTS.get(category, 1) for category in categories)
    recommendation_signals = {"recommendation_control", "recommendation_bias"}
    memory_signals = {"persistence", "memory_write"}
    trust_signals = {"trust_injection", "citation_bias", "user_preference_forgery"}

    if "injection" in categories and any(category in recommendation_signals for category in categories):
        score += 3
    if "commerce_or_ranking" in categories and any(category in recommendation_signals for category in categories):
        score += 2
    if any(category in memory_signals for category in categories) and (
        "injection" in categories or any(category in recommendation_signals for category in categories)
    ):
        score += 2
    if any(category in trust_signals for category in categories) and any(
        category in recommendation_signals for category in categories
    ):
        score += 1
    return score


def severity_for_score(score: int) -> str:
    """把数值分数映射为人类可读的风险级别。"""

    if score >= 10:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def scan_file(path: Path, rules: dict[str, list[re.Pattern[str]]] | None = None) -> list[Finding]:
    """扫描单个文件；SQLite 优先按数据库解析，失败后回退为普通文本。"""

    suffix = path.suffix.lower()
    if suffix in SQLITE_EXTENSIONS:
        LOGGER.debug("Scanning SQLite file: %s", path)
        findings: list[Finding] = []
        sqlite_ok, sqlite_records = extract_sqlite_text(path)
        if sqlite_ok:
            for source, text in sqlite_records:
                findings.extend(scan_text(path, text, source=source, rules=rules))
            if findings:
                LOGGER.info("Found %s suspicious record(s) in SQLite file: %s", len(findings), path)
            return findings
        LOGGER.debug("Falling back to text scan after SQLite parse failure: %s", path)

    text = read_text(path)
    if text is None:
        return []
    findings = scan_text(path, text, rules=rules)
    if findings:
        LOGGER.info("Found %s suspicious record(s) in file: %s", len(findings), path)
    return findings


def finding_review_payload(finding: Finding) -> dict[str, object]:
    """Build the minimal, already-redacted payload sent to the LLM reviewer."""

    return {
        "path": finding.path,
        "source": finding.source,
        "severity": finding.severity,
        "score": finding.score,
        "categories": finding.categories,
        "matched_terms": finding.matched_terms,
        "snippet": finding.snippet,
    }


def normalize_llm_verdict(verdict: str) -> str:
    """Normalize main-model review labels to the reporting vocabulary."""

    normalized = str(verdict).strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "benign": "benign",
        "safe": "benign",
        "not_suspicious": "benign",
        "false_positive": "benign",
        "suspicious": "suspicious",
        "possible_poisoning": "suspicious",
        "poisoning": "suspicious",
        "uncertain": "uncertain",
        "unknown": "uncertain",
        "needs_review": "uncertain",
    }
    return aliases.get(normalized, "uncertain")


def apply_llm_review(
    findings: list[Finding],
    reviewer: Callable[[Finding], LLMReview],
    *,
    suppress_benign: bool = True,
) -> list[Finding]:
    """Run a second-pass reviewer and optionally suppress benign regex candidates."""

    reviewed: list[Finding] = []
    suppressed = 0
    for finding in findings:
        try:
            review = reviewer(finding)
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
            LOGGER.warning("LLM review failed for %s: %s", finding.path, exc)
            review = LLMReview(
                verdict="uncertain",
                reason="LLM review failed; keeping regex candidate for manual inspection.",
            )
        finding.llm_verdict = normalize_llm_verdict(review.verdict)
        finding.llm_reason = str(review.reason).strip() or "No review reason provided."
        if suppress_benign and finding.llm_verdict == "benign":
            suppressed += 1
            continue
        reviewed.append(finding)
    if suppressed:
        LOGGER.info("LLM review suppressed %s benign regex candidate(s)", suppressed)
    return reviewed


def render_markdown(paths: list[Path], scanned_files: int, findings: list[Finding]) -> str:
    """把扫描结果渲染成人类可读的 Markdown 报告。"""

    lines = [
        "# OpenClaw Recommendation Poisoning Regex Candidate Scan",
        "",
        f"Scanned paths: {len(paths)}",
        f"Scanned files: {scanned_files}",
        f"Regex candidates: {len(findings)}",
        "Review required: yes",
        "",
    ]
    if not findings:
        lines.extend(
            [
                "No recommendation-poisoning regex candidates were found.",
                "",
                "This is heuristic triage, not a guarantee that the memories are clean.",
            ]
        )
        return "\n".join(lines)

    findings = sorted(findings, key=lambda item: (-item.score, item.path, item.line))
    for index, finding in enumerate(findings, start=1):
        finding_lines = [
            f"## {index}. {finding.severity.upper()} - score {finding.score}",
            "",
            f"- File: `{finding.path}`",
            f"- Line: {finding.line}",
            f"- Source: `{finding.source}`",
            f"- Signals: {', '.join(finding.categories)}",
            f"- Matched terms: {', '.join(f'`{term}`' for term in finding.matched_terms)}",
        ]
        if finding.llm_verdict:
            finding_lines.append(f"- LLM review: `{finding.llm_verdict}` - {finding.llm_reason}")
        finding_lines.extend(
            [
                "",
                "```text",
                finding.snippet,
                "```",
                "",
                "Suggested action: review this regex candidate in context before presenting it as likely poisoning; quarantine or remove it only if review confirms recommendation manipulation.",
                "",
            ]
        )
        lines.extend(finding_lines)
    return "\n".join(lines).rstrip() + "\n"


def render_json_report(
    paths: list[Path],
    scanned_files: int,
    rule_paths: Iterable[Path],
    findings: list[Finding],
) -> str:
    """Render machine-readable regex candidates with explicit review metadata."""

    return json.dumps(
        {
            "result_type": "regex_candidates",
            "review_required": True,
            "scanned_paths": [str(path) for path in paths],
            "scanned_files": scanned_files,
            "candidate_count": len(findings),
            "rule_files": [str(path) for path in rule_paths if path.exists()],
            "findings": [asdict(finding) for finding in findings],
        },
        ensure_ascii=False,
        indent=2,
    )


def split_swallowed_scan_paths(rule_args: list[Path]) -> tuple[list[Path], list[str]]:
    """Recover scan paths accidentally captured by ``--rules RULE [RULE ...]``.

    Argparse cannot know where variable-length rule files end and positional scan
    paths begin. Rule libraries are CSV files, so a non-CSV token after at least
    one CSV rule is much more likely to be a swallowed scan path.
    """

    rules: list[Path] = []
    swallowed_paths: list[str] = []
    found_csv_rule = False
    scanning_paths = False

    for value in rule_args:
        if not scanning_paths and value.suffix.lower() == ".csv":
            rules.append(value)
            found_csv_rule = True
            continue
        if found_csv_rule:
            scanning_paths = True
            swallowed_paths.append(str(value))
            continue
        rules.append(value)

    return rules, swallowed_paths


def parse_args(argv: list[str]) -> argparse.Namespace:
    """解析命令行参数。"""

    parser = argparse.ArgumentParser(
        description="Scan OpenClaw memory files for recommendation poisoning indicators."
    )
    parser.add_argument("paths", nargs="*", help="OpenClaw memory files or directories to scan.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    parser.add_argument("--output", "-o", help="Write output to a file instead of stdout.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed scan logs to stderr.")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only print warnings and errors to stderr.")
    parser.add_argument(
        "--rules",
        type=Path,
        nargs="+",
        default=DEFAULT_RULE_PATHS,
        metavar="RULE_CSV",
        help=(
            "CSV regex rule files to load. Use '--' before scan paths when passing "
            "paths after this option. Defaults to the English and Chinese rule libraries."
        ),
    )
    args = parser.parse_args(argv)
    args.rules, swallowed_paths = split_swallowed_scan_paths(args.rules)
    if swallowed_paths:
        args.paths = swallowed_paths + args.paths
    return args


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure progress logs on stderr so stdout remains valid Markdown or JSON."""

    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s", stream=sys.stderr)


def write_stdout(output: str) -> None:
    """Write report text using stdout's declared encoding with safe escaping."""

    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.buffer.write(output.encode(encoding, errors="backslashreplace"))
    sys.stdout.buffer.write(os.linesep.encode(encoding, errors="backslashreplace"))


def main(argv: list[str]) -> int:
    """命令行入口：发现路径、扫描文件、输出 Markdown 或 JSON。"""

    args = parse_args(argv)
    configure_logging(verbose=args.verbose, quiet=args.quiet)
    LOGGER.info("Starting OpenClaw recommendation-poisoning memory scan")
    rules = load_csv_rules(args.rules)
    paths = dedupe_paths(Path(path) for path in args.paths) if args.paths else default_paths()
    LOGGER.info("Scan paths: %s", ", ".join(str(path) for path in paths) if paths else "(none)")
    files = list(iter_files(paths))
    LOGGER.info("Discovered %s candidate file(s) to scan", len(files))

    findings: list[Finding] = []
    for index, file_path in enumerate(files, start=1):
        LOGGER.debug("Scanning file %s/%s: %s", index, len(files), file_path)
        findings.extend(scan_file(file_path, rules=rules))
    LOGGER.info("Scan complete: %s file(s) scanned, %s finding(s)", len(files), len(findings))

    if args.json:
        output = render_json_report(paths, len(files), args.rules, findings)
    else:
        output = render_markdown(paths, len(files), findings)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        LOGGER.info("Wrote scan report to %s", args.output)
    else:
        write_stdout(output)
    return 2 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
