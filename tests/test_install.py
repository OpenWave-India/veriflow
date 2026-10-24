"""
Tests for the Veriflow skill installer.

The installer writes into a user's home directory or project, so the property
that matters most is that it is reversible and idempotent. Every test here
installs into a temporary directory; none of them touch the real ~/.claude.

The most important test in this file is
``test_repository_contains_exactly_one_skill_md``. The repository once shipped
three copies of the skill (source, plus committed .claude/ and .agents/
copies). Any importer that scans a tree -- a downloaded zip, the plugin
loader, the marketplace -- then found three SKILL.md files and refused to
install. One copy in version control is the invariant that keeps installation
working, and .gitignore is what holds the line.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALLER = REPO_ROOT / "install.py"
SOURCE_SKILL = REPO_ROOT / "skills" / "veriflow"

_spec = importlib.util.spec_from_file_location("veriflow_installer", INSTALLER)
installer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(installer)


def run_installer(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Invoke the installer as a user would."""
    return subprocess.run(
        [sys.executable, str(INSTALLER), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
    )


class TestRepositoryLayout(unittest.TestCase):
    """The single-source invariant that makes every install path work."""

    def test_repository_contains_exactly_one_skill_md(self):
        """Multiple SKILL.md files break zip import, plugin install and the
        marketplace alike. Only skills/veriflow/SKILL.md belongs in git."""
        tracked = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        ).stdout.splitlines()
        skill_files = [p for p in tracked if p.endswith("SKILL.md")]
        self.assertEqual(
            skill_files,
            ["skills/veriflow/SKILL.md"],
            f"expected exactly one tracked SKILL.md, found: {skill_files}",
        )

    def test_no_committed_install_destinations(self):
        """A committed .claude/skills or .agents/ copy is what created the
        duplicate-SKILL.md failure. .gitignore must keep them out."""
        tracked = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        ).stdout.splitlines()
        offenders = [p for p in tracked if p.startswith((".claude/skills/", ".agents/"))]
        self.assertEqual(offenders, [], f"install destinations must not be tracked: {offenders}")

    def test_source_skill_has_frontmatter(self):
        text = (SOURCE_SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---"))
        head = text[: text.index("\n---", 4)]
        self.assertIn("name:", head)
        self.assertIn("description:", head)


class TestSourceFiles(unittest.TestCase):
    def test_includes_skill_md(self):
        self.assertIn(Path("SKILL.md"), installer.source_files())

    def test_excludes_caches_and_bytecode(self):
        for relative in installer.source_files():
            parts = relative.parts
            with self.subTest(path=relative.as_posix()):
                self.assertNotIn("__pycache__", parts)
                self.assertNotIn(relative.suffix, installer.SKIP_SUFFIXES)

    def test_finds_scripts_and_references(self):
        found = {p.as_posix() for p in installer.source_files()}
        self.assertIn("scripts/run-checks.py", found)
        self.assertIn("references/repair-workflow.md", found)


class TestProjectInstall(unittest.TestCase):
    """--project installs into ./.claude/skills/veriflow relative to cwd."""

    def test_installs_then_uninstalls(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            destination = project / ".claude" / "skills" / "veriflow"

            result = run_installer("--project", cwd=project)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((destination / "SKILL.md").is_file())
            self.assertTrue((destination / "scripts" / "run-checks.py").is_file())

            result = run_installer("--project", "--uninstall", cwd=project)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(destination.exists())

    def test_install_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            destination = project / ".claude" / "skills" / "veriflow"

            first = run_installer("--project", cwd=project)
            listing = sorted(p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file())
            second = run_installer("--project", cwd=project)
            again = sorted(p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file())

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(listing, again)

    def test_installs_every_source_file(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            destination = project / ".claude" / "skills" / "veriflow"
            run_installer("--project", cwd=project)
            for relative in installer.source_files():
                with self.subTest(path=relative.as_posix()):
                    self.assertTrue((destination / relative).is_file())

    def test_uninstall_on_nothing_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run_installer("--project", "--uninstall", cwd=Path(temp))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_reinstall_removes_files_dropped_from_the_source(self):
        """A merge-style copy would leave a removed file behind to shadow the
        real one, so an update must replace the directory outright."""
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            destination = project / ".claude" / "skills" / "veriflow"
            run_installer("--project", cwd=project)

            stale = destination / "references" / "dropped-in-a-later-version.md"
            stale.write_text("stale", encoding="utf-8")

            run_installer("--project", cwd=project)
            self.assertFalse(stale.exists())
            self.assertTrue((destination / "SKILL.md").is_file())

    def test_refuses_a_destination_that_is_not_a_skill(self):
        """Replacing the directory makes this guard load-bearing: without it an
        unrelated directory at that path would be deleted."""
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            destination = project / ".claude" / "skills" / "veriflow"
            destination.mkdir(parents=True)
            keep = destination / "someone-elses-work.txt"
            keep.write_text("do not delete", encoding="utf-8")

            result = run_installer("--project", cwd=project)
            self.assertEqual(result.returncode, 2)
            self.assertTrue(keep.is_file())


class TestCommandLine(unittest.TestCase):
    def test_help_works(self):
        result = run_installer("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--project", result.stdout)

    def test_unknown_flag_is_a_usage_error(self):
        result = run_installer("--platform", "codex")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
