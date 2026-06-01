#!/usr/bin/env python3
"""Scan OpenClaw and Hermes memory files for recommendation poisoning indicators."""

from __future__ import annotations

import argparse
import csv
from datetime import date
import json
import logging
import locale
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
SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS | SQLITE_EXTENSIONS

OPENCLAW_MARKERS = {"openclaw"}
HERMES_MARKERS = {"hermes"}
MEMORY_MARKERS = {
    "memory",
    "memories",
    "memory_store",
    "memory_db",
    "long_term_memory",
    "user_memory",
    "assistant_memory",
    "conversation_memory",
}
HERMES_MEMORY_FILENAMES = (
    "MEMORY.md",
    "USER.md",
)
IGNORED_DIRECTORY_MARKERS = {
    "git",
    "hg",
    "svn",
    "cache",
    "pycache",
    "pytest_cache",
    "mypy_cache",
    "ruff_cache",
    "node_modules",
    "venv",
    "env",
    "dist",
    "build",
    "logs",
    "log",
    "tmp",
    "temp",
    "references",
    "scripts",
    "tests",
}
RULE_LIBRARY_PREFIX = "recommendation_poisoning_keyword_regex_rules"
SQLITE_ROW_LIMIT = 10000
MAX_MATCHES_PER_PATTERN = 2000
SCAN_STATUS_MESSAGES = {
    "ok": "Scan completed.",
    "partial": "Some provided paths were missing; scanned only discovered supported memory files.",
    "invalid_input": "No scan completed because the provided scan path does not exist.",
    "no_memory_files": "No OpenClaw or Hermes memory files were found to scan.",
}

LOGGER = logging.getLogger("scan_openclaw_memory")

# 单个 memory 文件过大时跳过，避免误扫日志归档或二进制缓存导致运行很久。
MAX_FILE_BYTES = 100 * 1024

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
        r"(?:\u603b\u662f|\u59cb\u7ec8|\u4f18\u5148|\u9ed8\u8ba4)\s*"
        r"\u63a8\u8350\s*[A-Za-z0-9][A-Za-z0-9 .&-]{1,80}",
    ],
    "injection": [
        r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b",
        r"\bsystem\s+(override|instruction|message|prompt)\b",
        r"\bdeveloper\s+(message|instruction|override)\b",
        r"\bhidden\s+(instruction|prompt|rule)\b",
        r"\bdo\s+not\s+(reveal|disclose|mention)\b",
        r"\bsecretly\s+(recommend|promote|prefer|bias)\b",
        r"\bwithout\s+(telling|informing|revealing)\s+(the\s+)?user\b",
        r"\u5ffd\u7565\s*(?:\u4e4b\u524d|\u5148\u524d|\u4ee5\u4e0a|\u4e0a\u9762|"
        r"\u6240\u6709|\u5168\u90e8).{0,20}?"
        r"(?:\u6307\u4ee4|\u63d0\u793a|\u89c4\u5219|\u8981\u6c42)",
        r"\u4e0d\u8981\s*(?:\u544a\u8bc9|\u544a\u77e5|\u900f\u9732|"
        r"\u62ab\u9732|\u63d0\u53ca).{0,30}?\u7528\u6237",
        r"忽略(?:之前|先前|以上|上面|所有|全部).*?(?:指令|提示|规则|要求)",
        r"(?:系统|system)\s*(?:覆盖|重写|指令|消息|提示)",
        r"(?:开发者|developer)\s*(?:消息|指令|要求|覆盖)",
        r"隐藏(?:指令|提示|规则)",
        r"不要(?:告诉|告知|透露|披露|提及).*?用户",
        r"(?:偷偷|暗中|秘密地|不透露).*?(?:推荐|推广|偏向|优先)",
        r"(?:隐藏|不要提|不要展示|别提|屏蔽).*?(?:竞争对手|竞品|竞争者)",
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
    "memory_write": [
        r"(?:\u8bf7\s*)?\u8bb0\u4f4f\s*[A-Za-z0-9][A-Za-z0-9 .&-]{1,80}",
        r"(?:\u628a|\u5c06)\s*[A-Za-z0-9][A-Za-z0-9 .&-]{1,80}\s*"
        r"(?:\u8bb0\u4f4f|\u5b58\u5165\u8bb0\u5fc6|\u4fdd\u5b58\u5230\u8bb0\u5fc6|"
        r"\u52a0\u5165\u8bb0\u5fc6|\u5199\u5165\u8bb0\u5fc6)",
    ],
    "obfuscation": [
        r"[\u200b\u200c\u200d]",
        r"<!--.{0,2000}?(recommend|promote|prefer|ignore).{0,2000}?-->",
        r"(?i)\b(base64|rot13|encoded|payload)\b",
        r"(?i)<\|.{0,1000}?(system|developer|instruction).{0,1000}?\|>",
        r"\b[A-Za-z0-9+/]{80,}(?:={1,2})?(?=$|[^A-Za-z0-9+/=])",
    ],
    "trust_injection": [
        r"\b(?:the\s+)?user\s+has\s+(?:always\s+)?trusted\s+[A-Z][A-Za-z0-9 .&-]{1,80}",
        r"\b(?:the\s+)?user\s+has\s+verified\s+[A-Z][A-Za-z0-9 .&-]{1,80}\s+as\s+(?:reliable|trusted|authoritative|the\s+most\s+reliable)",
        r"\b[A-Z][A-Za-z0-9 .&-]{1,80}\s+is\s+(?:the\s+)?user'?s\s+(?:trusted|default|preferred)\s+(?:source|vendor|provider|tool|brand)",
        r"\b(?:trusted|authoritative)\s+source\b",
        r"\bsource\s+of\s+expertise\b",
    ],
    "user_preference_forgery": [
        r"\b(?:the\s+)?user\s+(?:has\s+)?(?:always\s+)?(?:prefers|preferred|chosen|chooses|relies\s+on)\s+[A-Z][A-Za-z0-9 .&-]{1,80}",
        r"\b(?:the\s+)?user\s+has\s+(?:always\s+)?trusted\s+[A-Z][A-Za-z0-9 .&-]{1,80}",
        r"\b(?:the\s+)?user\s+has\s+verified\s+[A-Z][A-Za-z0-9 .&-]{1,80}\s+as\s+(?:reliable|trusted|preferred|the\s+best)",
    ],
}


COMPILED = {
    category: [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns]
    for category, patterns in PATTERNS.items()
}

SENSITIVE_REDACTIONS = [
    (
        re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"),
        r"\1[REDACTED_CREDENTIALS]@",
    ),
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
]

NEGATED_SIGNAL_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|must\s+not|should\s+not)\s+"
    r"(?:always\s+recommend|ignore\s+(?:previous|prior|above)\s+instructions|"
    r"hide\s+competitors|secretly\s+(?:promote|recommend|prefer))\b"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"api[_-]?key|token|secret|password|passwd|pwd|access[_-]?token|refresh[_-]?token"
    r")(\s*[:=]\s*)([\"']?)([^\s,\"';}]+)([\"']?)"
)

RULE_WEIGHTS = {
    "recommendation_control": 3,
    "injection": 5,
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


@dataclass
class EvidenceRecord:
    """Resolved user-facing evidence for a reviewed finding."""

    text: str
    source_label: str
    scanner_truncated: bool = False


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

    hermes_memory_dir = os.environ.get("HERMES_MEMORY_DIR")
    if hermes_memory_dir:
        root = Path(hermes_memory_dir).expanduser()
        candidates.extend(root / filename for filename in HERMES_MEMORY_FILENAMES)

    hermes_home = os.environ.get("HERMES_HOME")
    if hermes_home:
        root = Path(hermes_home).expanduser()
        candidates.extend(root / "memories" / filename for filename in HERMES_MEMORY_FILENAMES)

    home = Path.home()
    cwd = Path.cwd()
    candidates.extend(
        [
            cwd / ".openclaw",
            cwd / "openclaw",
            cwd / ".hermes",
            cwd / "hermes",
            cwd / "memory",
            cwd / "memories",
            home / ".openclaw",
            home / ".config" / "openclaw",
            home / "AppData" / "Roaming" / "OpenClaw",
            home / "AppData" / "Local" / "OpenClaw",
            home / ".hermes",
            home / ".config" / "hermes",
            home / "AppData" / "Roaming" / "Hermes",
            home / "AppData" / "Local" / "Hermes",
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
    """遍历用户传入的文件或目录，只返回 OpenClaw memory 候选文件。"""

    for path in paths:
        if not path.exists():
            LOGGER.warning("Scan path does not exist: %s", path)
            continue
        if path.is_file():
            if is_explicit_memory_file(path):
                yield path
            else:
                LOGGER.warning("Skipping non-memory file: %s", path)
            continue
        LOGGER.info("Walking directory: %s", path)
        for file_path in path.rglob("*"):
            if file_path.is_file() and is_openclaw_memory_file(file_path, scan_root=path):
                yield file_path


def is_supported(path: Path) -> bool:
    """用扩展名和文件名粗筛，减少扫描无关文件的噪音。"""

    name = path.name.lower()
    if path.suffix.lower() in SUPPORTED_EXTENSIONS:
        return True
    return any(token in name for token in ("memory", "memories", "openclaw", "hermes"))


def normalized_path_marker(value: str) -> str:
    """Normalize a path component so marker checks handle dots, spaces, and hyphens."""

    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def path_markers(path: Path) -> list[str]:
    """Return normalized markers for all parts of a path."""

    return [marker for part in path.parts if (marker := normalized_path_marker(part))]


def has_openclaw_marker(markers: Iterable[str]) -> bool:
    """Return whether path markers indicate an OpenClaw-owned location."""

    return any(
        known_marker in marker
        for marker in markers
        for known_marker in OPENCLAW_MARKERS
    )


def has_hermes_marker(markers: Iterable[str]) -> bool:
    """Return whether path markers indicate a Hermes-owned location."""

    return any(marker in HERMES_MARKERS for marker in markers)


def has_memory_marker(markers: Iterable[str]) -> bool:
    """Return whether path markers indicate a memory-owned location or file."""

    return any(
        marker in MEMORY_MARKERS
        or "memory" in marker
        or "memories" in marker
        for marker in markers
    )


def is_known_hermes_memory_file(path: Path) -> bool:
    """Return whether the filename is a known Hermes memory artifact."""

    return path.name in HERMES_MEMORY_FILENAMES


def is_ignored_directory(path: Path, scan_root: Path | None = None) -> bool:
    """Skip project, cache, and skill-support directories during recursive discovery."""

    if scan_root is not None:
        try:
            parts = path.relative_to(scan_root).parts[:-1]
        except ValueError:
            parts = path.parts[:-1]
    else:
        parts = path.parts[:-1]
    markers = path_markers(Path(*parts)) if parts else []
    return any(marker in IGNORED_DIRECTORY_MARKERS for marker in markers)


def is_rule_library_file(path: Path) -> bool:
    """Return whether the file is one of this scanner's regex rule libraries."""

    return normalized_path_marker(path.stem).startswith(RULE_LIBRARY_PREFIX)


def is_memory_scan_root(path: Path) -> bool:
    """Return whether the supplied directory itself appears to be a memory root."""

    try:
        root = path.expanduser().resolve()
    except OSError:
        root = path.expanduser().absolute()
    markers = path_markers(root)
    return bool(markers) and has_memory_marker([markers[-1]])


def is_explicit_memory_file(path: Path) -> bool:
    """Return true for an explicitly provided file that looks like memory."""

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return False
    if is_rule_library_file(path):
        return False
    markers = path_markers(path)
    if has_hermes_marker(markers):
        return is_known_hermes_memory_file(path)
    if is_known_hermes_memory_file(path):
        return True
    if has_memory_marker(markers):
        return True
    return False


def is_openclaw_memory_file(path: Path, scan_root: Path | None = None) -> bool:
    """Return true for files that look like OpenClaw or Hermes memory artifacts.

    Directory scans are intentionally narrower than explicit single-file scans:
    they require an app context plus a memory path/name, or an explicitly
    supplied memory directory root. This keeps broad paths from scanning every
    supported text file under the target.
    """

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return False
    if is_rule_library_file(path) or is_ignored_directory(path, scan_root):
        return False

    markers = path_markers(path)
    if has_hermes_marker(markers):
        return is_known_hermes_memory_file(path)

    if scan_root is not None and is_memory_scan_root(scan_root):
        return True

    has_openclaw = has_openclaw_marker(markers)
    has_memory = has_memory_marker(markers)
    if has_openclaw and has_memory:
        return True

    filename_markers = path_markers(Path(path.name))
    return has_openclaw_marker(filename_markers) and has_memory_marker(filename_markers)


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
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1"):
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
                    conn.execute(
                        f"select {col_expr} from {quoted_table} limit {SQLITE_ROW_LIMIT + 1}"
                    ),
                    start=1,
                ):
                    if row_idx > SQLITE_ROW_LIMIT:
                        LOGGER.warning(
                            "SQLite table %s in %s reached the per-table row scan limit (%s)",
                            table,
                            path,
                            SQLITE_ROW_LIMIT,
                        )
                        break
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

    text = text.lstrip("\ufeff")
    anchors: list[tuple[int, int, str, str]] = []
    active_rules = rules or COMPILED
    for category, patterns in active_rules.items():
        for pattern in patterns:
            for match_count, hit in enumerate(pattern.finditer(text), start=1):
                anchors.append((hit.start(), hit.end(), category, hit.group(0)))
                if match_count >= MAX_MATCHES_PER_PATTERN:
                    LOGGER.warning(
                        "Pattern match limit reached for category %s while scanning %s",
                        category,
                        path,
                    )
                    break

    findings: list[Finding] = []
    if not anchors:
        return findings

    anchors.sort(key=lambda item: (item[0], item[1]))
    windows: list[tuple[int, int, list[tuple[int, int, str, str]]]] = []
    for start, end, category, term in anchors:
        window_start = max(0, start - SNIPPET_RADIUS)
        window_end = min(len(text), end + SNIPPET_RADIUS)
        if windows and window_start <= windows[-1][1]:
            previous_start, previous_end, previous_hits = windows[-1]
            previous_hits.append((start, end, category, term))
            windows[-1] = (previous_start, max(previous_end, window_end), previous_hits)
        else:
            windows.append((window_start, window_end, [(start, end, category, term)]))

    for _window_start, _window_end, window_hits in windows:
        categories = sorted({category for _start, _end, category, _term in window_hits})
        terms = [
            redact_sensitive_text(term.strip())
            for _start, _end, _category, term in window_hits
            if term.strip()
        ]
        start = min(hit_start for hit_start, _hit_end, _category, _term in window_hits)
        end = max(hit_end for _hit_start, hit_end, _category, _term in window_hits)

        score = score_categories(categories)
        score = adjust_score_for_context(score, categories, text, start, end)
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


def context_window(text: str, start: int, end: int) -> str:
    """Return surrounding text used for context-sensitive filters."""

    window_start = max(0, start - SNIPPET_RADIUS)
    window_end = min(len(text), end + SNIPPET_RADIUS)
    return text[window_start:window_end]


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


def adjust_score_for_context(
    score: int,
    categories: list[str],
    text: str,
    start: int,
    end: int,
) -> int:
    """Dampen obvious false-positive contexts without hiding the regex candidate."""

    context = context_window(text, start, end)
    category_set = set(categories)
    if NEGATED_SIGNAL_RE.search(context) and "memory_write" not in category_set:
        return min(score, 4)
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


def is_truncated_snippet(snippet: str) -> bool:
    """Return whether a scanner snippet appears to start or end mid-record."""

    stripped = snippet.strip()
    if not stripped:
        return True
    if stripped.startswith(("...", "…")) or stripped.endswith(("...", "…")):
        return True
    first = stripped[0]
    if first.islower() or first.isdigit():
        return True
    if re.search(r"[A-Za-z0-9]$", stripped):
        return True
    return False


def normalize_evidence_text(text: str) -> str:
    """Normalize and redact evidence after re-reading it from the source."""

    normalized = text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n").strip()
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return redact_sensitive_text(normalized)


def extract_text_record_at_line(text: str, line: int, suffix: str = "") -> str | None:
    """Return a complete line or blank-line-delimited paragraph containing ``line``."""

    normalized = text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    if not lines:
        return None
    index = min(max(line - 1, 0), len(lines) - 1)
    if suffix.lower() == ".jsonl":
        return lines[index].strip() or None

    start = index
    while start > 0 and lines[start - 1].strip():
        start -= 1
    end = index
    while end + 1 < len(lines) and lines[end + 1].strip():
        end += 1
    paragraph = "\n".join(lines[start : end + 1]).strip()
    return paragraph or lines[index].strip() or None


def scanner_snippet_evidence(finding: Finding) -> EvidenceRecord:
    """Fall back to the already-redacted scanner snippet and label it explicitly."""

    text = normalize_evidence_text(finding.snippet) or "[no scanner evidence available]"
    return EvidenceRecord(
        text=text,
        source_label="scanner-truncated evidence",
        scanner_truncated=True,
    )


def resolve_evidence_record(finding: Finding) -> EvidenceRecord:
    """Re-read the current source memory record for final reviewed reports.

    Scanner snippets are review hints only. Final reviewed evidence should use
    the complete source row, line, or paragraph whenever the source is available.
    """

    path = Path(finding.path)
    if not path.exists():
        return scanner_snippet_evidence(finding)

    if path.suffix.lower() in SQLITE_EXTENSIONS and finding.source.startswith("sqlite:"):
        sqlite_ok, records = extract_sqlite_text(path)
        if sqlite_ok:
            for source, text in records:
                if source == finding.source:
                    return EvidenceRecord(
                        text=normalize_evidence_text(text),
                        source_label="source memory record",
                    )
        return scanner_snippet_evidence(finding)

    text = read_text(path)
    if text is None:
        return scanner_snippet_evidence(finding)
    record = extract_text_record_at_line(text, finding.line, path.suffix)
    if record is None:
        return scanner_snippet_evidence(finding)
    return EvidenceRecord(
        text=normalize_evidence_text(record),
        source_label="source memory record",
    )


def detect_report_language(
    language: str | None = "auto",
    user_request: str | None = None,
) -> str:
    """Choose the reviewed report language from user intent, then local locale."""

    requested = (language or "auto").strip().lower()
    if requested in {"zh", "zh-cn", "zh_hans", "chinese", "cn", "中文"}:
        return "zh"
    if requested in {"en", "en-us", "en_gb", "english"}:
        return "en"
    if user_request and re.search(r"[\u3400-\u9fff]", user_request):
        return "zh"
    locale_candidates = [
        os.environ.get("LC_ALL", ""),
        os.environ.get("LC_MESSAGES", ""),
        os.environ.get("LANG", ""),
        locale.getlocale()[0] or "",
    ]
    if any(candidate.lower().startswith("zh") for candidate in locale_candidates):
        return "zh"
    return "en"


def reviewed_verdict(finding: Finding) -> str:
    """Return a normalized reviewed verdict for report grouping."""

    return normalize_llm_verdict(finding.llm_verdict or "uncertain")


def markdown_table_cell(value: object) -> str:
    """Escape compact table cell content without touching evidence blocks."""

    return str(value).replace("|", "\\|").replace("\n", " ").strip()


REVIEWED_REPORT_TEXT = {
    "zh": {
        "title": "# 已复核 OpenClaw/Hermes 推荐投毒报告",
        "reviewed_on": "复核时间",
        "source_note": "源扫描输出：已复核内部 scanner JSON；未披露原始 JSON",
        "summary": "摘要",
        "scan_status": "扫描状态",
        "scan_message": "扫描说明",
        "scanned_paths": "扫描路径",
        "scanned_files": "扫描文件数",
        "regex_candidates": "已复核 regex 候选数",
        "suspicious": "复核后可疑",
        "uncertain": "需人工检查",
        "benign": "良性/已抑制",
        "method": "复核方法",
        "method_text": "每个 regex 命中都先视为候选而非证据。复核时检查商业、经济价值、推荐、排名、引用或流量导向上下文，再判断是否存在持久化记忆、信任注入、引用偏置或推荐操控。Scanner 分数只用于排序和溯源，最终结论以复核标签为准。",
        "suspicious_findings": "可疑发现",
        "uncertain_findings": "需人工检查",
        "benign_findings": "良性/已抑制",
        "detailed_evidence": "详细证据",
        "evidence_index": "证据索引",
        "no_suspicious": "没有复核后仍为可疑的候选。",
        "no_uncertain": "没有需要人工检查的候选。",
        "benign_summary": "良性或被抑制的候选只计数汇总，不在详细证据中重复展开。",
        "number": "编号",
        "verdict": "结论",
        "severity": "严重度",
        "score": "分数",
        "file": "文件",
        "categories": "类别",
        "evidence": "证据",
        "line": "行号",
        "source": "Source",
        "matched_terms": "Matched terms",
        "evidence_source": "证据来源",
        "review_reason": "复核理由",
        "source_record": "源 memory 记录",
        "scanner_truncated": "扫描器截断证据",
        "cleanup": "建议处理",
        "cleanup_items": [
            "隔离或删除复核后仍可疑的 memory 记录。",
            "如果存在 memory 索引，删除后重建或刷新索引。",
            "清理后重新运行扫描，确认可疑计数下降。",
            "用中性提示验证受影响主题的推荐和引用行为。",
        ],
    },
    "en": {
        "title": "# Reviewed OpenClaw/Hermes Recommendation Poisoning Report",
        "reviewed_on": "Reviewed on",
        "source_note": "Source scanner output: internal scanner JSON reviewed; raw JSON not disclosed",
        "summary": "Summary",
        "scan_status": "Scan status",
        "scan_message": "Scan message",
        "scanned_paths": "Scanned paths",
        "scanned_files": "Scanned files",
        "regex_candidates": "Regex candidates reviewed",
        "suspicious": "Reviewed suspicious",
        "uncertain": "Reviewed uncertain",
        "benign": "Reviewed benign/suppressed",
        "method": "Review Method",
        "method_text": "Every regex hit was treated as a candidate, not proof. Review checked for commercial, economic-value, recommendation, ranking, citation, or traffic-steering context, then judged whether the record persisted memory, trust injection, citation bias, or recommendation manipulation. Scanner scores are only triage and sorting values; the reviewed label is authoritative.",
        "suspicious_findings": "Suspicious Findings",
        "uncertain_findings": "Uncertain Findings",
        "benign_findings": "Benign/Suppressed",
        "detailed_evidence": "Detailed Evidence",
        "evidence_index": "Evidence Index",
        "no_suspicious": "No reviewed candidates remained suspicious.",
        "no_uncertain": "No candidates require manual inspection.",
        "benign_summary": "Benign or suppressed candidates are counted here and not repeated in detailed evidence.",
        "number": "#",
        "verdict": "Verdict",
        "severity": "Severity",
        "score": "Score",
        "file": "File",
        "categories": "Categories",
        "evidence": "Evidence",
        "line": "Line",
        "source": "Source",
        "matched_terms": "Matched terms",
        "evidence_source": "Evidence source",
        "review_reason": "Review reason",
        "source_record": "source memory record",
        "scanner_truncated": "scanner-truncated evidence",
        "cleanup": "Recommended Cleanup",
        "cleanup_items": [
            "Quarantine or delete memory records that remain suspicious after review.",
            "Rebuild or refresh any memory index after deleting records.",
            "Re-run the scan after cleanup and confirm the suspicious count drops.",
            "Validate recommendation and citation behavior with neutral prompts in affected topics.",
        ],
    },
}


def render_reviewed_markdown_report(
    paths: list[Path],
    scanned_files: int,
    findings: list[Finding],
    *,
    candidate_count: int | None = None,
    benign_suppressed: int = 0,
    scan_status: str = "ok",
    missing_paths: Iterable[Path] | None = None,
    scan_message: str | None = None,
    reviewed_on: str | None = None,
    language: str | None = "auto",
    user_request: str | None = None,
) -> str:
    """Render the final user-facing reviewed report in a stable localized format."""

    report_language = detect_report_language(language=language, user_request=user_request)
    text = REVIEWED_REPORT_TEXT[report_language]
    reviewed_on = reviewed_on or date.today().isoformat()
    message = scan_message or SCAN_STATUS_MESSAGES.get(scan_status, "")
    sorted_findings = sorted(findings, key=lambda item: (-item.score, item.path, item.line))
    benign_included = sum(1 for finding in sorted_findings if reviewed_verdict(finding) == "benign")
    benign_total = benign_suppressed + benign_included
    report_findings = [
        finding for finding in sorted_findings if reviewed_verdict(finding) != "benign"
    ]
    suspicious_findings = [
        finding for finding in report_findings if reviewed_verdict(finding) == "suspicious"
    ]
    uncertain_findings = [
        finding for finding in report_findings if reviewed_verdict(finding) == "uncertain"
    ]
    reviewed_count = candidate_count if candidate_count is not None else len(findings) + benign_suppressed
    path_text = ", ".join(f"`{path}`" for path in paths) if paths else "`(none)`"

    lines = [
        text["title"],
        "",
        f"{text['reviewed_on']}: {reviewed_on}",
        text["source_note"],
        "",
        f"## {text['summary']}",
        "",
        f"- {text['scan_status']}: `{scan_status}`",
        f"- {text['scan_message']}: {message}",
        f"- {text['scanned_paths']}: {path_text}",
        f"- {text['scanned_files']}: {scanned_files}",
        f"- {text['regex_candidates']}: {reviewed_count}",
        f"- {text['suspicious']}: {len(suspicious_findings)}",
        f"- {text['uncertain']}: {len(uncertain_findings)}",
        f"- {text['benign']}: {benign_total}",
        f"- SQLite row limit per table: {SQLITE_ROW_LIMIT}",
        "",
    ]
    missing_path_list = [str(path) for path in missing_paths or []]
    if missing_path_list:
        missing_label = "缺失路径" if report_language == "zh" else "Missing paths"
        lines.extend([f"{missing_label}:"] + [f"- `{path}`" for path in missing_path_list] + [""])

    lines.extend(
        [
            f"## {text['method']}",
            "",
            text["method_text"],
            "",
            f"## {text['suspicious_findings']}",
            "",
            (
                f"{len(suspicious_findings)} "
                + ("个候选复核后仍为可疑。" if report_language == "zh" else "reviewed candidate(s) remained suspicious.")
                if suspicious_findings
                else text["no_suspicious"]
            ),
            "",
            f"## {text['uncertain_findings']}",
            "",
            (
                f"{len(uncertain_findings)} "
                + ("个候选需要人工检查。" if report_language == "zh" else "candidate(s) need manual inspection.")
                if uncertain_findings
                else text["no_uncertain"]
            ),
            "",
            f"## {text['benign_findings']}",
            "",
            f"{text['benign']}: {benign_total}. {text['benign_summary']}",
            "",
            f"## {text['detailed_evidence']}",
            "",
        ]
    )

    if report_findings:
        lines.extend(
            [
                f"{text['evidence_index']}:",
                "",
                f"| {text['number']} | {text['verdict']} | {text['severity']} | {text['score']} | {text['file']} | {text['categories']} |",
                "|---:|---|---|---:|---|---|",
            ]
        )
        for index, finding in enumerate(report_findings, start=1):
            categories = ", ".join(finding.categories)
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(index),
                        f"`{markdown_table_cell(reviewed_verdict(finding))}`",
                        f"`{markdown_table_cell(finding.severity)}`",
                        str(finding.score),
                        f"`{markdown_table_cell(Path(finding.path).name)}`",
                        markdown_table_cell(categories),
                    ]
                )
                + " |"
            )
        lines.append("")

        for index, finding in enumerate(report_findings, start=1):
            evidence = resolve_evidence_record(finding)
            evidence_label = (
                text["scanner_truncated"] if evidence.scanner_truncated else text["source_record"]
            )
            matched_terms = ", ".join(f"`{term}`" for term in finding.matched_terms) or "`(none)`"
            reason = finding.llm_reason or (
                "需要人工检查。" if report_language == "zh" else "Manual inspection needed."
            )
            lines.extend(
                [
                    f"### {text['evidence']} {index}",
                    "",
                    f"- {text['verdict']}: `{reviewed_verdict(finding)}`",
                    f"- {text['file']}: `{Path(finding.path).name}`",
                    f"- {text['line']}: {finding.line}",
                    f"- {text['source']}: `{finding.source}`",
                    f"- {text['matched_terms']}: {matched_terms}",
                    f"- {text['evidence_source']}: {evidence_label}",
                    f"- {text['review_reason']}: {reason}",
                    "",
                    "```text",
                    evidence.text,
                    "```",
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "No non-benign reviewed evidence."
                if report_language == "en"
                else "没有需要展开的非良性证据。",
                "",
            ]
        )

    lines.extend([f"## {text['cleanup']}", ""])
    for index, item in enumerate(text["cleanup_items"], start=1):
        lines.append(f"{index}. {item}")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(
    paths: list[Path],
    scanned_files: int,
    findings: list[Finding],
    *,
    scan_status: str = "ok",
    missing_paths: Iterable[Path] | None = None,
    scan_message: str | None = None,
) -> str:
    """把扫描结果渲染成人类可读的 Markdown 报告。"""

    missing_path_list = [str(path) for path in missing_paths or []]
    message = scan_message or SCAN_STATUS_MESSAGES.get(scan_status, "")
    lines = [
        "# OpenClaw/Hermes Recommendation Poisoning Regex Candidate Scan",
        "",
        f"Scan status: {scan_status}",
        f"Scan message: {message}",
        f"Scanned paths: {len(paths)}",
        f"Scanned files: {scanned_files}",
        f"Regex candidates: {len(findings)}",
        f"SQLite row limit per table: {SQLITE_ROW_LIMIT}",
        "Review required: yes",
        "",
    ]
    if missing_path_list:
        lines.extend(["Missing paths:", *[f"- `{path}`" for path in missing_path_list], ""])
    if not findings:
        if scan_status == "no_memory_files":
            lines.extend(
                [
                    "No OpenClaw or Hermes memory files were found, so no memory content was scanned.",
                    "",
                    "Provide an OpenClaw or Hermes memory file or directory and run the scanner again.",
                ]
            )
            return "\n".join(lines)
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
    *,
    scan_status: str = "ok",
    missing_paths: Iterable[Path] | None = None,
    scan_message: str | None = None,
) -> str:
    """Render machine-readable regex candidates with explicit review metadata."""

    missing_path_list = [str(path) for path in missing_paths or []]
    message = scan_message or SCAN_STATUS_MESSAGES.get(scan_status, "")
    return json.dumps(
        {
            "result_type": "regex_candidates",
            "scan_status": scan_status,
            "scan_message": message,
            "review_required": True,
            "scanned_paths": [str(path) for path in paths],
            "missing_paths": missing_path_list,
            "scanned_files": scanned_files,
            "candidate_count": len(findings),
            "sqlite_row_limit_per_table": SQLITE_ROW_LIMIT,
            "rule_files": [str(path) for path in rule_paths if path.exists()],
            "findings": [asdict(finding) for finding in findings],
        },
        ensure_ascii=False,
        indent=2,
    )


RULE_CSV_COLUMNS = {"category", "pattern_type", "pattern"}


def looks_like_rule_csv(path: Path) -> bool:
    """Return whether an existing CSV has the expected regex rule columns."""

    if path.suffix.lower() != ".csv":
        return False
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = {name.strip() for name in reader.fieldnames or [] if name}
    except OSError:
        return False
    return RULE_CSV_COLUMNS.issubset(fieldnames)


def split_swallowed_scan_paths(rule_args: list[Path]) -> tuple[list[Path], list[str]]:
    """Recover scan paths accidentally captured by ``--rules RULE [RULE ...]``.

    Argparse cannot know where variable-length rule files end and positional scan
    paths begin. Rule libraries are CSV files with known columns, so an existing
    non-rule CSV after at least one rule file is treated as a swallowed scan path.
    """

    rules: list[Path] = []
    swallowed_paths: list[str] = []
    found_rule = False
    scanning_paths = False

    for value in rule_args:
        if scanning_paths:
            swallowed_paths.append(str(value))
            continue
        if looks_like_rule_csv(value):
            rules.append(value)
            found_rule = True
            continue
        if found_rule or value.suffix.lower() == ".csv":
            scanning_paths = True
            swallowed_paths.append(str(value))
            continue
        rules.append(value)

    return rules, swallowed_paths


def parse_args(argv: list[str]) -> argparse.Namespace:
    """解析命令行参数。"""

    parser = argparse.ArgumentParser(
        description="Scan OpenClaw and Hermes memory files for recommendation poisoning indicators."
    )
    parser.add_argument("paths", nargs="*", help="OpenClaw or Hermes memory files or directories to scan.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    parser.add_argument("--output", "-o", help="Write output to a file instead of stdout.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed scan logs to stderr.")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only print warnings and errors to stderr.")
    parser.add_argument(
        "--rules",
        type=Path,
        nargs="+",
        default=None,
        metavar="RULE_CSV",
        help=(
            "CSV regex rule files to load. Use '--' before scan paths when passing "
            "paths after this option. Defaults to the English and Chinese rule libraries."
        ),
    )
    args = parser.parse_args(argv)
    if args.rules is None:
        args.rules = DEFAULT_RULE_PATHS
    else:
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
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        stream=sys.stderr,
        force=True,
    )


def write_stdout(output: str) -> None:
    """Write report text using stdout's declared encoding with safe escaping."""

    encoding = sys.stdout.encoding or "utf-8"
    encoded = output.encode(encoding, errors="backslashreplace")
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(encoded)
        buffer.write(os.linesep.encode(encoding, errors="backslashreplace"))
        return
    sys.stdout.write(encoded.decode(encoding, errors="strict"))
    sys.stdout.write(os.linesep)


def main(argv: list[str]) -> int:
    """命令行入口：发现路径、扫描文件、输出 Markdown 或 JSON。"""

    args = parse_args(argv)
    configure_logging(verbose=args.verbose, quiet=args.quiet)
    LOGGER.info("Starting OpenClaw/Hermes recommendation-poisoning memory scan")
    rules = load_csv_rules(args.rules)
    explicit_paths = bool(args.paths)
    paths = dedupe_paths(Path(path) for path in args.paths) if args.paths else default_paths()
    LOGGER.info("Scan paths: %s", ", ".join(str(path) for path in paths) if paths else "(none)")
    missing_paths = [path for path in paths if not path.exists()]
    files = list(iter_files(paths))
    LOGGER.info("Discovered %s candidate file(s) to scan", len(files))

    findings: list[Finding] = []
    for index, file_path in enumerate(files, start=1):
        LOGGER.debug("Scanning file %s/%s: %s", index, len(files), file_path)
        findings.extend(scan_file(file_path, rules=rules))
    LOGGER.info("Scan complete: %s file(s) scanned, %s finding(s)", len(files), len(findings))

    if explicit_paths and missing_paths and not files:
        scan_status = "invalid_input"
    elif not files:
        scan_status = "no_memory_files"
    elif explicit_paths and missing_paths:
        scan_status = "partial"
    else:
        scan_status = "ok"
    scan_message = SCAN_STATUS_MESSAGES.get(scan_status, "")

    if args.json:
        output = render_json_report(
            paths,
            len(files),
            args.rules,
            findings,
            scan_status=scan_status,
            missing_paths=missing_paths,
            scan_message=scan_message,
        )
    else:
        output = render_markdown(
            paths,
            len(files),
            findings,
            scan_status=scan_status,
            missing_paths=missing_paths,
            scan_message=scan_message,
        )

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        LOGGER.info("Wrote scan report to %s", args.output)
    else:
        write_stdout(output)
    if findings:
        return 2
    return 1 if scan_status in {"invalid_input", "no_memory_files"} else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
