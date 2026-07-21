import re
import unittest
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
WRAPPER_PATH = SKILL_DIR / "SKILL.md"
DIRECT_PATH = SKILL_DIR / "references" / "direct.md"
REVIEW_PATH = SKILL_DIR / "references" / "review.md"

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

DIRECT_MODEL_ALLOWLIST = (
    "gpt-5",
    "gpt-5.5",
    "gpt-5.6-sol",
    "opus-4.6",
    "opus-4.7",
    "opus-4.8",
    "fable5",
)

NON_ALLOWLISTED_MODEL_EXAMPLES = (
    "gpt-6.0",
    "gpt-5.7-sol",
    "opus-4.9",
    "fable-6",
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
    def test_wrapper_routes_only_explicit_allowlist_direct(self):
        wrapper = read(WRAPPER_PATH)
        direct_rule = " ".join(
            route_bullet(wrapper, "references/direct.md").split()
        )

        self.assertIn("allowlist", direct_rule)
        backtick_values = set(re.findall(r"`([^`]+)`", direct_rule))
        self.assertEqual(
            backtick_values,
            {"references/direct.md", *DIRECT_MODEL_ALLOWLIST},
        )
        for model in DIRECT_MODEL_ALLOWLIST:
            self.assertIn(f"`{model}`", direct_rule)
        for model in NON_ALLOWLISTED_MODEL_EXAMPLES:
            self.assertNotIn(model, direct_rule)

    def test_wrapper_routes_every_other_model_to_review_without_inference(self):
        wrapper = read(WRAPPER_PATH)
        direct_rule = " ".join(
            route_bullet(wrapper, "references/direct.md").split()
        )
        review_rule = " ".join(
            route_bullet(wrapper, "references/review.md").split()
        )

        self.assertRegex(review_rule, r"every other model")
        for model in NON_ALLOWLISTED_MODEL_EXAMPLES:
            self.assertNotIn(model, direct_rule)

        selection_rule = wrapper.lower().split(
            "## select exactly one procedure",
            1,
        )[1]
        for obsolete_marker in (
            "numeric version",
            "at least",
            "provider prefix",
            "case-insensitive",
            "equivalent forms",
            "extra variant suffix",
            "capability guesses",
        ):
            self.assertNotIn(obsolete_marker, selection_rule)
        self.assertIn("exactly one", wrapper.lower())
        self.assertIn("do not load the other", wrapper.lower())
        self.assertRegex(
            wrapper.lower(),
            r"cannot\s+be\s+obtained,\s+conservatively\s+load\s+"
            r"`references/review\.md`",
        )

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
