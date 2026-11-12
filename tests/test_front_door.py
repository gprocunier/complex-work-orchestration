"""The README front door: present value, setup, one example, limits and glossary.

It also pins that the proposed in-thread scaffold tier stays unreachable: the
docs describe it as unavailable and both the planner and the CLI refuse it.
"""
from __future__ import annotations

import re
import subprocess
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8")


OLD_SECTION_ANCHORS = (
    "put-specialist-findings-to-work",
    "preserve-the-project-requirements-when-work-changes",
    "inspect-the-implementation-and-recorded-work",
    "status-and-detailed-controls",
)
GUIDE_BASE = "https://gprocunier.github.io/complex-work-orchestration"
PUBLISHED_GUIDE_PAGES = (
    "local-workers.html",
    "zero-trust-consensus.html#tested-example",
    "continue-project.html",
    "explanation.html#ecosystem",
    "workflows.html#operator",
    "use-cases.html#local-review-checks",
    "use-cases.html#claim-comparison",
    "use-cases.html#migration-evaluation",
    "use-cases.html#retry-decision",
)


from cwo_core.routing import classify_work
from scaffold_workgraph import planned_graph
def _active_markdown(source: str) -> str:
    """Mask explicit inactive syntax for a bounded GFM source check.

    The consumed Markdown dialect is GitHub-flavored Markdown (GFM). This
    lexical recognizer handles comments, top-level fences, backtick spans and
    escapes; the destination helper handles simple inline links and autolinks.
    It does not classify indented code, whose meaning depends on list context,
    or render reference links, nested labels or arbitrary block HTML. Inactive
    witnesses therefore use explicit code delimiters or comments.
    """
    parts: list[str] = []
    i = 0
    while i < len(source):
        if i == 0 or source[i - 1] == "\n":
            line_end = source.find("\n", i)
            if line_end == -1:
                line_end = len(source)
            line = source[i:line_end]
            fence = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
            if fence and (fence.group(1)[0] != "`" or "`" not in fence.group(2)):
                marker = fence.group(1)
                closing = re.search(
                    r"(?m)^ {0,3}" + re.escape(marker[0])
                    + r"{" + str(len(marker)) + r",}[ \t]*(?:\n|$)",
                    source[line_end:],
                )
                i = line_end + closing.end() if closing else len(source)
                parts.append("\n")
                continue
        if source.startswith("<!--", i):
            end = source.find("-->", i + 4)
            i = end + 3 if end != -1 else len(source)
            parts.append(" ")
            continue
        if source[i] == "\\" and i + 1 < len(source):
            parts.append("  ")
            i += 2
            continue
        if source[i] == "`":
            run = re.match(r"`+", source[i:]).group(0)
            end = re.search(
                r"(?<!`)" + re.escape(run) + r"(?!`)", source[i + len(run):],
            )
            if end:
                parts.append(" ")
                i += len(run) + end.end()
                continue
        parts.append(source[i])
        i += 1
    return "".join(parts)


class _AnchorIDs(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.ids.update(
                value for name, value in attrs if name == "id" and value is not None
            )

    handle_startendtag = handle_starttag


def _active_anchor_ids(source: str) -> set[str]:
    parser = _AnchorIDs()
    parser.feed(_active_markdown(source))
    parser.close()
    return parser.ids


def _markdown_link_destinations(source: str) -> set[str]:
    """Extract the docs' simple inline links and HTTP(S) GFM autolinks.

    This is a lexical subset, not a full GFM parser. Inline images consume their
    destinations without adding links; bare autolinks use GFM start boundaries
    and trim trailing punctuation and unmatched closing parentheses.
    """
    destinations: set[str] = set()
    tokens = re.finditer(
        r"(!?)\[[^\[\]\n]+\]\(([^()\s]+)\)"
        r"|<(https?://[^<>\s]+)>"
        r"|(?<![^\s*_~(])(https?://[^\s<>]+)",
        _active_markdown(source),
    )
    for token in tokens:
        image, inline, angle, bare = token.groups()
        if inline is not None:
            if not image:
                destinations.add(inline)
        elif angle is not None:
            destinations.add(angle)
        else:
            url = bare.rstrip("?!.,:*_~")
            while url.endswith(")") and url.count(")") > url.count("("):
                url = url[:-1]
            destinations.add(url)
    return destinations


def section(heading: str) -> str:
    start = README.index(f"\n## {heading}\n")
    end = README.find("\n## ", start + 1)
    return " ".join(README[start:end if end != -1 else None].split())


class FrontDoorTests(unittest.TestCase):
    def test_value_setup_and_example_come_before_the_architecture_tour(self) -> None:
        order = ["\n## What CWO does today\n", "\n## Setup\n",
                 "\n## Example: one project across two fresh sessions\n",
                 "connected-ecosystem.svg", "\n## Limits\n", "\n## Glossary\n"]
        positions = [README.index(marker) for marker in order]
        self.assertEqual(positions, sorted(positions))

    def test_exact_commands_profile_and_models_stay_searchable_and_match_the_source(self) -> None:
        for identity in (
            "./scripts/install.sh --yes",
            "python3 scripts/check_installed_skill.py --check",
            "python3 scripts/manage_instruction_profile.py install --profile operator-e",
            "python3 scripts/manage_instruction_profile.py verify --profile operator-e",
            'cwo-codex -C "$PWD"',
            'codex --profile cwo-sol-operator-e -C "$PWD"',
            "python3 scripts/scaffold_workgraph.py",
            "--scaffold-size tight",
            "gpt-5.6-sol",
            "gpt-5.6-luna",
            "gpt-5.6-terra",
            "gpt-5.3-codex-spark",
        ):
            with self.subTest(identity=identity):
                self.assertIn(identity, README)
        profile = (ROOT / "scripts/manage_instruction_profile.py").read_text(encoding="utf-8")
        self.assertIn("cwo-sol-operator-e", profile)
        self.assertIn('model = "gpt-5.6-sol"', profile)
        routing = (ROOT / "policy/native-worker-execution.yaml").read_text(encoding="utf-8")
        for model in ("gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.3-codex-spark"):
            self.assertIn(f'"{model}"', routing)

    def test_disabled_routes_are_described_as_disabled(self) -> None:
        limits = section("Limits")
        self.assertIn("Disabled in this version:", limits)
        for route in ("local HTTP dispatch", "live browser dispatch", "browser model confirmation",
                      "live native activation", "successful closure", "risk narrowing",
                      "ordinary productive pool plans"):
            with self.subTest(route=route):
                self.assertIn(route, limits)
        value = section("What CWO does today")
        self.assertIn("`dispatch_work.py --execute-local`", value)
        self.assertIn("are disabled", value)
        self.assertIn("`pending-acceptance`", value)
        self.assertNotRegex(README, r"(?i)send a focused question to an approved")

    def test_the_example_is_labelled_recorded_and_keeps_its_limits_beside_it(self) -> None:
        example = section("Example: one project across two fresh sessions")
        for phrase in ("This is recorded work, not an illustration.",
                       "Limits of this record:", "not a novice study, benchmark or cost claim",
                       "`pending-acceptance`", "examples/first-project/VALIDATION.md",
                       "guided practice example"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, example)

    def test_glossary_is_concise_and_defines_the_terms_used_above(self) -> None:
        glossary = README.split("\n## Glossary\n", 1)[1].split("\n## ", 1)[0]
        terms = re.findall(r"^- \*\*([^*]+):\*\*", glossary, re.MULTILINE)
        self.assertLessEqual(len(terms), 12)
        for term in ("Lead", "Worker", "Reviewer", "Bead", "Scaffold", "Route",
                     "Adjudication", "Acceptance", "Operator continuation packet"):
            with self.subTest(term=term):
                self.assertIn(term, terms)

    def test_optional_detail_moved_to_a_reference_keeps_its_qualifications(self) -> None:
        moved = " ".join((ROOT / "references/reviews-and-requirements.md").read_text(encoding="utf-8").split())
        self.assertIn("references/reviews-and-requirements.md", README)
        for phrase in ("is disabled in this version", "Local review does not make a cloud session offline",
                       "more models do not guarantee better answers",
                       "cannot detect every unrecorded change in intent",
                       "not live provider conversations or endpoint qualification",
                       "Designs to adapt, not completed demonstrations"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, moved)

    def test_old_section_anchors_are_preserved(self) -> None:
        anchors = _active_anchor_ids(README)
        for anchor in OLD_SECTION_ANCHORS:
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, anchors)

    def test_moved_content_keeps_published_guide_destinations(self) -> None:
        moved = (ROOT / "references/reviews-and-requirements.md").read_text(encoding="utf-8")
        destinations = _markdown_link_destinations(moved)
        for page in PUBLISHED_GUIDE_PAGES:
            with self.subTest(page=page):
                self.assertIn(f"{GUIDE_BASE}/{page}", destinations)


class FrontDoorMarkupRegressionTests(unittest.TestCase):
    """Exercise the actual assertions with only their document inputs replaced."""

    @staticmethod
    def _inactive_forms(markup: str) -> dict[str, str]:
        return {
            "HTML comment": f"<!-- {markup} -->",
            "inline code": f"`{markup}`",
            "wide inline code": f"``{markup}``",
            "backtick fence": f"\n```text\n{markup}\n```\n",
            "tilde fence": f"\n~~~text\n{markup}\n~~~\n",
        }

    def _assert_rejected(self, result: unittest.TestResult) -> None:
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.failures), 1)

    def test_current_documents_pass_the_assertion_consumers(self) -> None:
        result = unittest.TestResult()
        for name in (
            "test_old_section_anchors_are_preserved",
            "test_moved_content_keeps_published_guide_destinations",
        ):
            FrontDoorTests(name).run(result)
        self.assertEqual(result.testsRun, 2)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])

    def test_inactive_anchor_mutations_fail_the_actual_anchor_assertions(self) -> None:
        for anchor in OLD_SECTION_ANCHORS:
            markup = f'<a id="{anchor}"></a>'
            self.assertEqual(README.count(markup), 1)
            forms = self._inactive_forms(markup)
            forms["escaped markup"] = "\\" + markup
            for form, replacement in forms.items():
                with self.subTest(anchor=anchor, form=form):
                    mutated = README.replace(markup, replacement, 1)
                    # The former substring checks still accept every mutated document.
                    for required in OLD_SECTION_ANCHORS:
                        self.assertIn(f'<a id="{required}">', mutated)
                    result = unittest.TestResult()
                    with patch.object(sys.modules[__name__], "README", mutated):
                        FrontDoorTests("test_old_section_anchors_are_preserved").run(result)
                    self._assert_rejected(result)

    def test_inactive_link_mutations_fail_the_actual_link_assertions(self) -> None:
        moved = (ROOT / "references/reviews-and-requirements.md").read_text(encoding="utf-8")
        for page in PUBLISHED_GUIDE_PAGES:
            url = f"{GUIDE_BASE}/{page}"
            links = re.findall(r"\[[^\[\]\n]+\]\(" + re.escape(url) + r"\)", moved)
            self.assertEqual(len(links), 1)
            link = links[0]
            forms = self._inactive_forms(link)
            forms.update({
                "code-quoted URL": f"`{url}`",
                "code-quoted prefixed URL": f"`guide: {url}`",
                "image": "!" + link,
            })
            for form, replacement in forms.items():
                with self.subTest(page=page, form=form):
                    mutated = moved.replace(link, replacement, 1)
                    # The former substring checks still accept every mutated document.
                    for required in PUBLISHED_GUIDE_PAGES:
                        self.assertIn(f"{GUIDE_BASE}/{required}", mutated)
                    result = unittest.TestResult()
                    with patch.object(Path, "read_text", autospec=True, return_value=mutated) as read:
                        FrontDoorTests("test_moved_content_keeps_published_guide_destinations").run(result)
                    read.assert_called_once_with(
                        ROOT / "references/reviews-and-requirements.md", encoding="utf-8",
                    )
                    self._assert_rejected(result)

    def test_four_space_list_continuations_pass_the_actual_anchor_assertions(self) -> None:
        for anchor in OLD_SECTION_ANCHORS:
            markup = f'<a id="{anchor}"></a>'
            self.assertEqual(README.count(markup), 1)
            replacement = f"\n- Anchor\n\n    {markup}\n"
            with self.subTest(anchor=anchor):
                mutated = README.replace(markup, replacement, 1)
                result = unittest.TestResult()
                with patch.object(sys.modules[__name__], "README", mutated):
                    FrontDoorTests("test_old_section_anchors_are_preserved").run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.failures, [])

    def test_active_link_forms_pass_the_actual_link_assertions(self) -> None:
        moved = (ROOT / "references/reviews-and-requirements.md").read_text(encoding="utf-8")
        for page in PUBLISHED_GUIDE_PAGES:
            url = f"{GUIDE_BASE}/{page}"
            links = re.findall(r"\[[^\[\]\n]+\]\(" + re.escape(url) + r"\)", moved)
            self.assertEqual(len(links), 1)
            link = links[0]
            forms = {
                "four-space list continuation": f"\n- Guide\n\n    {link}\n",
                "bare HTTPS autolink": url,
                "prefixed bare HTTPS autolink": f"guide: {url}",
                "angle HTTPS autolink": f"<{url}>",
                "punctuated bare HTTPS autolink": f"{url}.",
                "parenthesized HTTPS autolink": f"({url})",
                "escaped label with bare autolink": "\\" + link,
            }
            for form, replacement in forms.items():
                with self.subTest(page=page, form=form):
                    mutated = moved.replace(link, replacement, 1)
                    result = unittest.TestResult()
                    with patch.object(Path, "read_text", autospec=True, return_value=mutated) as read:
                        FrontDoorTests("test_moved_content_keeps_published_guide_destinations").run(result)
                    read.assert_called_once_with(
                        ROOT / "references/reviews-and-requirements.md", encoding="utf-8",
                    )
                    self.assertEqual(result.testsRun, 1)
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.failures, [])


class InThreadTierUnavailableTests(unittest.TestCase):
    """Activation of a smaller tier waits on verified successful closure (issue #37)."""

    def test_docs_describe_the_in_thread_tier_as_unavailable(self) -> None:
        self.assertIn("No smaller scaffold tier is available", " ".join(README.split()))
        coach = (ROOT / "references/prompt-coach.md").read_text(encoding="utf-8")
        self.assertIn("### Proposed in-thread tier (not available)", coach)
        self.assertIn("issue #37", coach)
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("no smaller scaffold tier exists", skill)


    def test_the_cli_refuses_a_minimal_size_before_any_output(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "scaffold_workgraph.py"), "--title", "Typo",
             "--description", "Fix one typo in the docs guide.", "--scaffold-size", "minimal",
             "--dry-run", "--format", "cwo"],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("invalid choice: 'minimal'", result.stderr)

    def test_a_minimal_scaffold_request_gets_the_tight_chain(self) -> None:
        result = coach_orchestration_prompt(
            "Use $complex-work-orchestration to create a minimal scaffold for a docs fix."
        )
        self.assertEqual(result["scaffold_sizing"]["recommended_size"], "tight")

    def test_the_planner_refuses_any_tier_but_full_and_tight(self) -> None:
        route = classify_work("Fix one typo in the docs guide.")
        for size in ("minimal", "in-thread", "small", ""):
            with self.subTest(size=size):
                with self.assertRaisesRegex(ValueError, "scaffold_size must be 'full' or 'tight'"):
                    planned_graph("Typo", route, scaffold_size=size)


if __name__ == "__main__":
    unittest.main()
