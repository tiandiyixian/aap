import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTCASE_DIR = REPO_ROOT / "joern" / "testcases"
RULE_SCRIPT = REPO_ROOT / "joern" / "rules" / "cpp_security_rules.sc"

CASE_PATTERNS = {
    "C001": ("buffer_overflow.c", [(r"strcpy\s*\(", 1)]),
    "C002": ("array_index_taint.c", [(r"atoi\s*\(", 1), (r"values\[index\]", 1)]),
    "C003": ("null_pointer_deref.c", [(r"malloc\s*\(", 1), (r"buffer\[0\]", 1)]),
    "C004": ("double_free.c", [(r"free\s*\(\s*ptr\s*\)", 2)]),
    "C005": ("use_after_free.c", [(r"free\s*\(\s*ptr\s*\)", 1), (r"ptr\[0\]", 1)]),
    "C006": ("format_string.c", [(r"printf\s*\(argv\[1\]\)", 1)]),
    "C007": ("command_injection.c", [(r"fgets\s*\(", 1), (r"system\s*\(buffer\)", 1)]),
    "C008": ("path_traversal.c", [(r"strcpy\s*\(", 1), (r"open\s*\(path", 1)]),
    "C009": ("resource_leak.c", [(r"fopen", 1), (r"return -2", 1)]),
    "C010": ("hardcoded_secret.c", [(r"API_SECRET_TOKEN_123", 1)]),
}


@pytest.mark.parametrize("rule_id", sorted(CASE_PATTERNS))
def test_security_testcases_contain_expected_patterns(rule_id):
    filename, patterns = CASE_PATTERNS[rule_id]
    source_path = TESTCASE_DIR / filename
    assert source_path.exists(), f"Missing testcase for {rule_id}: {filename}"
    content = source_path.read_text(encoding="utf-8")
    for pattern, min_count in patterns:
        matches = re.findall(pattern, content)
        assert len(matches) >= min_count, f"Pattern {pattern} appears {len(matches)} times in {filename}, expected >= {min_count}"


def test_rule_script_declares_all_rules():
    script = RULE_SCRIPT.read_text(encoding="utf-8")
    for rule_id in CASE_PATTERNS:
        assert rule_id in script, f"Rule {rule_id} missing from cpp_security_rules.sc"


def test_testcase_readme_mentions_every_rule():
    readme = (TESTCASE_DIR / "README.md").read_text(encoding="utf-8")
    for rule_id in CASE_PATTERNS:
        assert rule_id in readme, f"Rule {rule_id} missing from testcase README"


@pytest.mark.skipif(
    shutil.which("joern") is None or shutil.which("joern-parse") is None,
    reason="Joern CLI tooling not available in the test environment",
)
def test_cpp_security_rules_end_to_end(tmp_path):
    output_cpg = tmp_path / "testcases.bin"
    subprocess.run(
        ["joern-parse", str(TESTCASE_DIR), "-o", str(output_cpg)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    run = subprocess.run(
        [
            "joern",
            "--script",
            str(RULE_SCRIPT),
            "--params",
            f"cpgFile={output_cpg}",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    for rule_id in CASE_PATTERNS:
        assert rule_id in run.stdout, f"Expected findings for {rule_id} not reported"
