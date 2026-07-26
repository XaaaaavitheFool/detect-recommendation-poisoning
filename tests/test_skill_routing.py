import re
import unittest
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
WRAPPER_PATH = SKILL_DIR / "SKILL.md"
DIRECT_PATH = SKILL_DIR / "references" / "direct.md"
REVIEW_PATH = SKILL_DIR / "references" / "review.md"
OPENAI_YAML_PATH = SKILL_DIR / "agents" / "openai.yaml"
README_PATH = SKILL_DIR / "README.md"

GENERAL_POISONING_TYPES = (
    "instruction_override",
    "priority_authority_escalation",
    "role_identity_hijacking",
    "goal_redirection",
    "persistent_directive",
    "constraint_safety_bypass",
    "conditional_sleeper_trigger",
    "tool_action_hijacking",
    "data_exfiltration",
    "concealment_anti_audit",
    "correction_resistance",
    "propagation_instruction",
    "context_boundary_evasion",
    "obfuscated_instruction",
)

COMMERCIAL_SCOPE_MARKERS = (
    "recommendation",
    "ranking",
    "citation",
    "vendor",
    "product",
    "forged user",
    "conceal",
)

REPORT_SHAPE_MARKERS = (
    "# Hermes Recommendation Poisoning Review",
    "## Summary",
    "## Method",
    "## Suspicious Findings",
    "## Uncertain Findings",
    "## Benign Summary",
    "## Recommended Follow-Up",
)

SKIPPED_DIRECTORY_NAMES = (
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    ".tox",
    ".nox",
    "node_modules",
    "site-packages",
    "vendor",
    "build",
    "dist",
    "target",
    "out",
)

COMPLETION_MARKER = (
    "=== skill execution complete: detect-recommendation-poisoning ==="
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def route_bullet(wrapper: str, reference_path: str) -> str:
    match = re.search(
        rf"^- Load `{re.escape(reference_path)}`(?P<body>.*?)(?=^- Load `|\n\n)",
        wrapper,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing route bullet for {reference_path}")
    return match.group(0).lower()


def bullet_containing(section: str, marker: str) -> str:
    for match in re.finditer(
        r"^- .*?(?=^- |\Z)",
        section,
        re.MULTILINE | re.DOTALL,
    ):
        bullet = match.group(0).lower()
        if marker.lower() in bullet:
            return bullet
    raise AssertionError(f"missing bullet containing {marker!r}")


class SkillRoutingTests(unittest.TestCase):
    def test_wrapper_requires_route_choice_before_scan_or_configuration_access(self):
        wrapper = read(WRAPPER_PATH)
        lowered = wrapper.lower()
        choice_heading = "## choose review route first"
        scan_heading = "## scan scope"
        choice_section = lowered.split(choice_heading, 1)[1].split(
            scan_heading,
            1,
        )[0]
        direct_rule = " ".join(
            route_bullet(wrapper, "references/direct.md").split()
        )
        review_rule = " ".join(
            route_bullet(wrapper, "references/review.md").split()
        )

        self.assertLess(
            lowered.index(choice_heading),
            lowered.index(scan_heading),
        )
        for blocked_action in (
            "resolving any scan target",
            "enumerating or reading files",
            "reading `.env`",
            "installing dependencies",
        ):
            self.assertIn(blocked_action, choice_section)
        self.assertIn("no default", choice_section)
        self.assertIn("missing or ambiguous", choice_section)
        self.assertIn("stop and wait", choice_section)
        self.assertIn("option 1", direct_rule)
        self.assertIn("option 2", review_rule)
        self.assertNotIn("default", direct_rule)
        for obsolete_model_route in (
            "allowlist",
            "every other model",
            "trusted runtime model",
            "trusted model metadata",
            "cannot be obtained",
        ):
            self.assertNotIn(obsolete_model_route, lowered)
        self.assertIn("exactly one", lowered)
        self.assertIn("do not load the other", lowered)

    def test_route_chooser_explains_tradeoffs_and_option_two_is_consent(self):
        wrapper = read(WRAPPER_PATH).lower()
        choice_section = " ".join(
            wrapper.split(
                "## choose review route first",
                1,
            )[1].split("## scan scope", 1)[0].split()
        )

        for marker in (
            "local model direct review",
            "local model performance is good",
            "not uploaded to a third party",
            "`deepseek-v4-pro` prefilter + local model review",
            "local model performance is average",
            "full content and source metadata",
            "deepseek",
            "sensitive information",
            "selecting option 2",
            "explicit consent",
            "current invocation",
            "no second confirmation",
        ):
            self.assertIn(marker, choice_section)

        for non_selector in (
            "model identity",
            "api key",
            "configuration",
            "prior invocation",
            "generic scan request",
        ):
            self.assertIn(non_selector, choice_section)

    def test_review_verifies_current_choice_and_revocation_returns_to_chooser(self):
        content = read(REVIEW_PATH).lower()
        gate = " ".join(
            content.split(
                "## external processing route-choice gate",
                1,
            )[1].split("## scope", 1)[0].split()
        )
        workflow_step = " ".join(
            content.split("## workflow", 1)[1].split(
                "2. create or use the project virtual environment",
                1,
            )[0].split()
        )

        for marker in (
            "mandatory route chooser",
            "unambiguously selected option 2",
            "current invocation",
            "selection itself is explicit consent",
            "do not ask for a second confirmation",
            "before installing dependencies",
            "reading `.env`",
            "enumerating scan targets",
        ):
            self.assertIn(marker, gate)
        for marker in (
            "absent",
            "ambiguous",
            "revoked",
            "return to the route chooser",
            "do not switch to local review automatically",
        ):
            self.assertIn(marker, workflow_step)

    def test_openai_prompt_starts_with_route_choice(self):
        openai_yaml = read(OPENAI_YAML_PATH).lower()
        self.assertIn("local", openai_yaml)
        self.assertIn("deepseek-v4-pro", openai_yaml)
        self.assertIn("advantages and disadvantages", openai_yaml)
        self.assertIn("before inspecting", openai_yaml)
        self.assertIn(
            "selecting the deepseek route is explicit consent",
            openai_yaml,
        )
        self.assertNotIn("review hermes memory locally", openai_yaml)
        self.assertNotIn("unless i separately request it", openai_yaml)

    def test_readme_documents_mandatory_choice_in_both_languages(self):
        content = " ".join(read(README_PATH).lower().split())

        for marker in (
            "choose a review route before any scan or configuration access",
            "there is no default route",
            "selecting option 2 is explicit consent",
            "在扫描或读取配置之前选择审查路径",
            "没有默认路径",
            "选择选项 2 即表示明确同意",
        ):
            self.assertIn(marker, content)
        self.assertNotIn("local direct review is the default", content)
        self.assertNotIn("本地直接审查是默认流程", content)
        self.assertIn("--confirm-external-processing", content)

    def test_scan_documents_share_exclusions_and_deterministic_record_splitting(self):
        for path in (WRAPPER_PATH, DIRECT_PATH, REVIEW_PATH):
            with self.subTest(path=path.name):
                content = read(path).lower()
                for directory_name in SKIPPED_DIRECTORY_NAMES:
                    self.assertIn(f"`{directory_name}`", content)
                self.assertIn("case-insensitive", content)
                self.assertIn("explicitly supplied matching file", content)

        for path in (DIRECT_PATH, REVIEW_PATH):
            with self.subTest(path=path.name):
                content = read(path).lower()
                self.assertIn(
                    "blank-line-delimited non-empty blocks",
                    content,
                )
                self.assertNotIn(
                    "otherwise review the whole file as one record",
                    content,
                )

    def test_completion_marker_is_reserved_for_completed_scan_final_response(self):
        for path in (DIRECT_PATH, REVIEW_PATH):
            with self.subTest(path=path.name):
                content = read(path).lower()
                hard_rules = content.split(
                    "## hard rules",
                    1,
                )[1].split("## workflow", 1)[0]
                marker_rule = bullet_containing(
                    hard_rules,
                    COMPLETION_MARKER,
                )
                workflow = content.split(
                    "## workflow",
                    1,
                )[1].split("## review guidance", 1)[0]
                final_marker_rule = next(
                    line
                    for line in workflow.splitlines()
                    if COMPLETION_MARKER in line
                )

                self.assertNotIn(
                    "end every completed chat response",
                    marker_rule,
                )
                for required_phrase in (
                    "only",
                    "final chat response",
                    "entire scan task",
                    "report",
                    "consent",
                    "progress",
                    "blocker",
                    "failure",
                    "incomplete",
                    "no matching files",
                    "local",
                ):
                    self.assertIn(required_phrase, marker_rule)
                for required_phrase in (
                    "only",
                    "entire scan task",
                    "report",
                ):
                    self.assertIn(required_phrase, final_marker_rule)

    def test_direct_and_review_both_preserve_commercial_detection_and_add_all_general_types(self):
        for path in (DIRECT_PATH, REVIEW_PATH):
            with self.subTest(path=path.name):
                content = read(path).lower()
                for marker in COMMERCIAL_SCOPE_MARKERS:
                    self.assertIn(marker, content)
                for poisoning_type in GENERAL_POISONING_TYPES:
                    self.assertIn(poisoning_type, content)

    def test_references_keep_original_verdicts_and_report_shape(self):
        for path in (DIRECT_PATH, REVIEW_PATH):
            with self.subTest(path=path.name):
                content = read(path)
                for verdict in ("suspicious", "uncertain", "benign"):
                    self.assertIn(f"`{verdict}`", content)
                for marker in REPORT_SHAPE_MARKERS:
                    self.assertIn(marker, content)

    def test_review_keeps_original_prefilter_command_and_jsonl_fields(self):
        content = read(REVIEW_PATH)

        self.assertIn("scripts/deepseek_pro_prefilter.py", content)
        for field in (
            "file_path",
            "record_index",
            "line_range",
            "record_text",
            "prefilter_verdict",
            "reason",
            "needs_final_review",
        ):
            self.assertIn(field, content)
        self.assertNotIn("poisoning_types", content)
        self.assertNotIn("general_poisoning_types", content)

    def test_review_limits_scripts_to_prefilter_and_requires_direct_host_review(self):
        content = read(REVIEW_PATH)
        lowered = content.lower()
        hard_rules = lowered.split("## hard rules", 1)[1].split("## workflow", 1)[0]
        prefilter_rule = bullet_containing(
            hard_rules,
            "bundled deepseek pro prefilter script",
        )
        final_script_rule = bullet_containing(
            hard_rules,
            "once step 6 begins",
        )
        final_review_match = re.search(
            r"^6\. review every row.*?(?=^7\. write the final markdown detail report)",
            lowered,
            re.MULTILINE | re.DOTALL,
        )
        report_step_match = re.search(
            r"^7\. write the final markdown detail report.*?"
            r"(?=^8\. answer in chat)",
            lowered,
            re.MULTILINE | re.DOTALL,
        )

        self.assertIsNotNone(final_review_match)
        self.assertIsNotNone(report_step_match)
        final_review = final_review_match.group(0)
        report_step = report_step_match.group(0)
        self.assertRegex(
            prefilter_rule,
            r"bundled deepseek pro prefilter script[\s\S]*"
            r"(?:allowed|permitted)[\s\S]*only[\s\S]*"
            r"(?:initial semantic screening|prefiltering)[\s\S]*step 5",
        )
        self.assertRegex(
            final_script_rule,
            r"once[\s\S]*step 6[\s\S]*(?:do not|must not|never)[\s\S]*"
            r"create or run[\s\S]*(?:python|javascript|powershell|shell)"
            r"[\s\S]*scripts or scripted pipelines[\s\S]*classify"
            r"[\s\S]*filter[\s\S]*score[\s\S]*validate[\s\S]*"
            r"final verdicts[\s\S]*final review reasons",
        )
        for marker in (
            "candidate_suspicious",
            "candidate_uncertain",
            "contract-exhausted",
        ):
            self.assertIn(marker, final_review)
        self.assertRegex(
            final_review,
            r"host model itself[\s\S]*read[\s\S]*assign[\s\S]*"
            r"final verdict[\s\S]*reason[\s\S]*"
            r"before continuing to the next row",
        )
        self.assertRegex(
            report_step,
            r"(?=[\s\S]*method section)"
            r"(?=[\s\S]*deepseek pro)"
            r"(?=[\s\S]*script)"
            r"(?=[\s\S]*initial)"
            r"(?=[\s\S]*host model)"
            r"(?=[\s\S]*without scripts or scripted pipelines)",
        )


if __name__ == "__main__":
    unittest.main()
