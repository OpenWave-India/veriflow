"""
Tests for --changed scope narrowing.

The property that matters most here is the fallback. A narrowed run that
cannot narrow must widen, never shrink to nothing: an empty change set and
"git is not available" look identical from the outside, and only one of them
is safe to treat as "nothing to do". A scanner that reports PASS over zero
files is the exact failure Veriflow exists to prevent, so several tests below
assert the fallback fires and states a reason rather than checking the happy
path twice.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "skills" / "veriflow" / "scripts"

_spec = importlib.util.spec_from_file_location(
    "veriflow_changed_files", SCRIPTS / "changed_files.py"
)
changed_files = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(changed_files)

_rc_spec = importlib.util.spec_from_file_location("run_checks_mod", SCRIPTS / "run-checks.py")
run_checks_mod = importlib.util.module_from_spec(_rc_spec)
_rc_spec.loader.exec_module(run_checks_mod)

GIT = shutil.which("git")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [GIT, *args], cwd=str(root), capture_output=True, text=True
    )


def _init_repo(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "commit.gpgsign", "false")


@unittest.skipUnless(GIT, "git is not installed")
class TestResolveChangedFiles(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)
        _init_repo(self.root)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_untracked_source_file_is_detected(self):
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        result = changed_files.resolve_changed_files(self.root)
        self.assertTrue(result.narrowed)
        self.assertIn("app.py", result.files)

    def test_modified_tracked_file_is_detected(self):
        target = self.root / "app.py"
        target.write_text("x = 1\n", encoding="utf-8")
        _git(self.root, "add", "app.py")
        _git(self.root, "commit", "-q", "-m", "init")
        target.write_text("x = 2\n", encoding="utf-8")
        result = changed_files.resolve_changed_files(self.root)
        self.assertIn("app.py", result.files)

    def test_non_source_files_are_filtered_by_default(self):
        (self.root / "README.md").write_text("# hi\n", encoding="utf-8")
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        result = changed_files.resolve_changed_files(self.root)
        self.assertIn("app.py", result.files)
        self.assertNotIn("README.md", result.files)

    def test_source_only_false_keeps_every_file(self):
        (self.root / "README.md").write_text("# hi\n", encoding="utf-8")
        result = changed_files.resolve_changed_files(self.root, source_only=False)
        self.assertIn("README.md", result.files)

    def test_deleted_file_is_not_reported(self):
        target = self.root / "gone.py"
        target.write_text("x = 1\n", encoding="utf-8")
        _git(self.root, "add", "gone.py")
        _git(self.root, "commit", "-q", "-m", "init")
        target.unlink()
        result = changed_files.resolve_changed_files(self.root)
        self.assertNotIn("gone.py", result.files)

    def test_base_revision_is_honoured(self):
        (self.root / "a.py").write_text("x = 1\n", encoding="utf-8")
        _git(self.root, "add", "a.py")
        _git(self.root, "commit", "-q", "-m", "first")
        (self.root / "b.py").write_text("y = 2\n", encoding="utf-8")
        _git(self.root, "add", "b.py")
        _git(self.root, "commit", "-q", "-m", "second")

        result = changed_files.resolve_changed_files(self.root, base="HEAD~1")
        self.assertTrue(result.narrowed)
        self.assertIn("b.py", result.files)
        self.assertNotIn("a.py", result.files)

    def test_unknown_base_falls_back_with_a_reason(self):
        result = changed_files.resolve_changed_files(self.root, base="no-such-ref")
        self.assertFalse(result.narrowed)
        self.assertIn("no-such-ref", result.fallback_reason)


class TestFallbackBehaviour(unittest.TestCase):
    """Without git, the run must widen and say why."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_not_a_repository_falls_back(self):
        """Mocked rather than relying on a temp dir being outside a repo.

        A developer whose home directory is itself a git repository (which does
        happen) makes every temp directory "inside a work tree", so asserting
        on real filesystem placement would pass or fail by accident.
        """
        with unittest.mock.patch.object(
            changed_files, "is_git_repository", return_value=False
        ):
            result = changed_files.resolve_changed_files(self.root)
        self.assertFalse(result.narrowed)
        self.assertIn("not inside a git repository", result.fallback_reason)

    def test_missing_git_falls_back_with_a_reason(self):
        with unittest.mock.patch.object(changed_files.shutil, "which", return_value=None):
            result = changed_files.resolve_changed_files(self.root)
        self.assertFalse(result.narrowed)
        self.assertIn("not installed", result.fallback_reason)

    def test_fallback_never_raises(self):
        """A git problem must degrade, not abort the verification run."""
        with unittest.mock.patch.object(
            changed_files.subprocess, "run", side_effect=OSError("boom")
        ):
            result = changed_files.resolve_changed_files(self.root)
        self.assertFalse(result.narrowed)

    def test_narrowed_is_false_whenever_a_reason_exists(self):
        """The invariant the rest of the code relies on."""
        for reason in ("", "git exploded"):
            with self.subTest(reason=reason):
                cs = changed_files.ChangeSet(["a.py"], reason)
                self.assertEqual(cs.narrowed, not reason)

    def test_describe_states_full_run_on_fallback(self):
        cs = changed_files.ChangeSet([], "git is not installed")
        self.assertIn("full run", changed_files.describe(cs))


class TestRelatedTestDiscovery(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)
        (self.root / "tests").mkdir()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_finds_test_for_a_changed_module(self):
        (self.root / "math_ops.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        (self.root / "tests" / "test_math_ops.py").write_text("# test\n", encoding="utf-8")
        related = changed_files.related_test_files(self.root, ["math_ops.py"])
        self.assertIn("tests/test_math_ops.py", related)

    def test_finds_tests_in_nested_directories(self):
        nested = self.root / "tests" / "unit"
        nested.mkdir()
        (nested / "test_widget.py").write_text("# test\n", encoding="utf-8")
        related = changed_files.related_test_files(self.root, ["src/widget.py"])
        self.assertIn("tests/unit/test_widget.py", related)

    def test_a_changed_test_file_is_its_own_related_test(self):
        related = changed_files.related_test_files(self.root, ["tests/test_thing.py"])
        self.assertEqual(related, ["tests/test_thing.py"])

    def test_no_matching_test_returns_empty(self):
        """Nothing is invented. An empty result drives the caller to widen."""
        (self.root / "orphan.py").write_text("x = 1\n", encoding="utf-8")
        self.assertEqual(changed_files.related_test_files(self.root, ["orphan.py"]), [])


@unittest.skipUnless(GIT, "git is not installed")
class TestRunChecksChangedIntegration(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)
        _init_repo(self.root)
        (self.root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        (self.root / "tests").mkdir()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _test_check(self, result):
        return next(c for c in result["discovered_checks"] if c["name"] == "test")

    def test_changed_narrows_the_test_command(self):
        (self.root / "math_ops.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        (self.root / "tests" / "test_math_ops.py").write_text("# test\n", encoding="utf-8")
        result = run_checks_mod.discover_checks(self.root, changed=True)
        check = self._test_check(result)
        self.assertIn("tests/test_math_ops.py", check["command"])
        self.assertEqual(check["changed_scope"], ["tests/test_math_ops.py"])

    def test_changed_scope_is_reported(self):
        (self.root / "math_ops.py").write_text("x = 1\n", encoding="utf-8")
        (self.root / "tests" / "test_math_ops.py").write_text("# test\n", encoding="utf-8")
        result = run_checks_mod.discover_checks(self.root, changed=True)
        self.assertTrue(result["changed_scope"]["narrowed"])
        self.assertIn("--changed limited the test run", " ".join(result["limitations"]))

    def test_no_related_tests_leaves_full_scope(self):
        """Narrowing to nothing would run the whole suite while claiming otherwise."""
        (self.root / "orphan.py").write_text("x = 1\n", encoding="utf-8")
        result = run_checks_mod.discover_checks(self.root, changed=True)
        check = self._test_check(result)
        self.assertNotIn("changed_scope", check)
        self.assertIn("left at full scope", " ".join(result["limitations"]))

    def test_outside_a_repo_falls_back_and_says_so(self):
        """git unavailable -> widen and state the reason, never shrink."""
        with unittest.mock.patch.object(
            run_checks_mod._changed_files_mod.shutil, "which", return_value=None
        ):
            result = run_checks_mod.discover_checks(self.root, changed=True)
        self.assertFalse(result["changed_scope"]["narrowed"])
        self.assertIn("could not narrow", " ".join(result["limitations"]))

    def test_nested_project_paths_resolve_against_the_project_root(self):
        """A project inside a larger repository must not inherit its paths.

        Without `git diff --relative`, paths come back relative to the
        repository root and resolve to nothing under the project root, so the
        scope silently becomes empty.
        """
        nested = self.root / "subproject"
        nested.mkdir()
        (nested / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        (nested / "tests").mkdir()
        (nested / "widget.py").write_text("x = 1\n", encoding="utf-8")
        (nested / "tests" / "test_widget.py").write_text("# test\n", encoding="utf-8")

        result = run_checks_mod.discover_checks(nested, changed=True)
        self.assertTrue(result["changed_scope"]["narrowed"])
        self.assertIn("widget.py", result["changed_scope"]["changed_files"])

    def test_scope_appears_in_the_skipped_section(self):
        (self.root / "math_ops.py").write_text("x = 1\n", encoding="utf-8")
        (self.root / "tests" / "test_math_ops.py").write_text("# test\n", encoding="utf-8")
        result = run_checks_mod.discover_checks(self.root, changed=True)
        text = run_checks_mod.format_summary(result)
        self.assertIn("Suppressed / skipped:", text)
        self.assertIn("[SCOPE]", text)

    def test_cli_accepts_bare_changed_flag(self):
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "run-checks.py"), str(self.root), "--changed", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIsNotNone(json.loads(proc.stdout)["changed_scope"])

    def test_cli_accepts_changed_with_a_base(self):
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        _git(self.root, "add", ".")
        _git(self.root, "commit", "-q", "-m", "init")
        proc = subprocess.run(
            [
                sys.executable, str(SCRIPTS / "run-checks.py"), str(self.root),
                "--changed", "HEAD", "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["changed_scope"]["base"], "HEAD")

    def test_project_directory_is_not_mistaken_for_a_base(self):
        """`--changed <dir>` must still treat <dir> as the project root."""
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "run-checks.py"), "--changed", str(self.root), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["project_root"], str(self.root.resolve()))
        self.assertIsNone(parsed["changed_scope"]["base"])


@unittest.skipUnless(GIT, "git is not installed")
class TestSecurityScanChangedIntegration(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)
        _init_repo(self.root)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _run(self, *extra: str) -> dict:
        proc = subprocess.run(
            [
                sys.executable, str(SCRIPTS / "run-security-tests.py"), str(self.root),
                "--json", *extra,
            ],
            capture_output=True,
            text=True,
        )
        return json.loads(proc.stdout)

    def test_changed_restricts_the_scanned_file_set(self):
        (self.root / "old.py").write_text('q = "SELECT 1"\n', encoding="utf-8")
        _git(self.root, "add", ".")
        _git(self.root, "commit", "-q", "-m", "init")
        (self.root / "new.py").write_text("x = 1\n", encoding="utf-8")

        payload = self._run("--changed")
        self.assertEqual(payload["static"]["included_paths"], ["new.py"])
        self.assertGreaterEqual(payload["static"]["files_outside_scope"], 1)

    def test_narrowed_scan_discloses_that_it_was_narrowed(self):
        (self.root / "new.py").write_text("x = 1\n", encoding="utf-8")
        payload = self._run("--changed")
        self.assertTrue(
            any("not a clean bill of health" in l for l in payload["static"]["limitations"]),
            payload["static"]["limitations"],
        )

    def test_no_changes_widens_rather_than_scanning_nothing(self):
        """A clean scan over zero files is indistinguishable from a clean project."""
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        _git(self.root, "add", ".")
        _git(self.root, "commit", "-q", "-m", "init")

        payload = self._run("--changed")
        self.assertFalse(payload["changed_scope"]["narrowed"])
        self.assertEqual(payload["static"]["included_paths"], [])
        self.assertGreaterEqual(payload["static"]["files_scanned"], 1)

    def test_unknown_base_scans_everything_and_says_why(self):
        """The fallback path, driven through the real CLI.

        Uses an unknown revision rather than deleting .git, because a home
        directory that is itself a repository would keep the temp tree inside
        a work tree regardless.
        """
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        payload = self._run("--changed", "no-such-revision")
        self.assertFalse(payload["changed_scope"]["narrowed"])
        self.assertEqual(payload["static"]["included_paths"], [])
        self.assertGreaterEqual(payload["static"]["files_scanned"], 1)
        self.assertTrue(
            any("could not narrow" in l for l in payload["static"]["limitations"])
        )


if __name__ == "__main__":
    unittest.main()
