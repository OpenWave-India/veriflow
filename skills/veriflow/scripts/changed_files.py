#!/usr/bin/env python3
"""
Resolve the set of files changed in a working tree, via git.

Shared by ``run-checks.py`` and ``run-security-tests.py`` so ``--changed``
means the same thing in both: the same file set, the same fallback rule, and
the same wording when the fallback fires.

The governing rule is that a narrowed run must never be mistaken for a full
one. Every function here returns an explicit reason alongside its result, and
when git cannot answer, the caller is told to run everything instead of
quietly scanning nothing -- an empty change set and "git is unavailable" are
indistinguishable from the outside, and only one of them is safe to treat as
"nothing to do".
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
from typing import List, Optional, Sequence, Tuple

#: Suffixes worth running checks against. A changed README should not trigger
#: a test run, and a changed lockfile is handled by the dependency audit.
SOURCE_SUFFIXES = frozenset(
    {
        ".py", ".pyi",
        ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
        ".rs", ".go", ".java", ".kt", ".cs",
        ".rb", ".php", ".swift", ".scala",
    }
)

#: How long to wait on any single git invocation. A repository with a slow or
#: unresponsive filesystem must degrade to a full run, not hang the scan.
GIT_TIMEOUT_SECONDS = 15


class ChangeSet:
    """The outcome of resolving changed files.

    ``fallback_reason`` is the whole point of this type: it is empty only when
    git genuinely answered. A caller that ignores it and treats an empty
    ``files`` list as "nothing changed" would report a clean run for a project
    it never looked at.
    """

    def __init__(
        self,
        files: Sequence[str],
        fallback_reason: str = "",
        base: Optional[str] = None,
        source: str = "git",
    ):
        self.files: List[str] = list(files)
        self.fallback_reason = fallback_reason
        self.base = base
        self.source = source

    @property
    def narrowed(self) -> bool:
        """True when the run may legitimately be limited to ``files``."""
        return not self.fallback_reason

    def to_dict(self) -> dict:
        return {
            "changed_files": list(self.files),
            "file_count": len(self.files),
            "base": self.base,
            "narrowed": self.narrowed,
            "fallback_reason": self.fallback_reason,
            "source": self.source,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ChangeSet(files={len(self.files)}, narrowed={self.narrowed})"


def _run_git(root: Path, args: Sequence[str]) -> Tuple[bool, str]:
    """Run a read-only git command. Returns ``(ok, stdout)``.

    Only ever invoked with the subcommands below, all of which inspect history
    without modifying it.
    """
    git = shutil.which("git")
    if not git:
        return False, ""
    try:
        proc = subprocess.run(
            [git, *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False, ""
    if proc.returncode != 0:
        return False, proc.stderr or ""
    return True, proc.stdout


def is_git_repository(root: Path) -> bool:
    ok, out = _run_git(root, ["rev-parse", "--is-inside-work-tree"])
    return ok and out.strip() == "true"


def resolve_changed_files(
    root: Path | str,
    base: Optional[str] = None,
    source_only: bool = True,
) -> ChangeSet:
    """Return the files changed in ``root``, or a reason to run everything.

    With ``base``, compares that revision against the working tree. Without it,
    collects staged, unstaged and untracked files, which is what a developer
    means by "what I am working on right now".

    Never raises: any git problem becomes a ``fallback_reason``, because a
    failure to narrow must widen the run, not abort it.
    """
    root_path = Path(root).resolve()

    if not shutil.which("git"):
        return ChangeSet([], "git is not installed, so changed files could not be determined")
    if not is_git_repository(root_path):
        return ChangeSet([], f"{root_path} is not inside a git repository")

    collected: List[str] = []

    # --relative keeps paths relative to the project root rather than to the
    # repository root. Without it, a project nested inside a larger repository
    # (or a user whose home directory is itself a repo) gets paths that do not
    # resolve against the scan root, and the resulting scope is wrong.
    if base:
        ok, out = _run_git(root_path, ["diff", "--name-only", "--relative", base])
        if not ok:
            return ChangeSet(
                [],
                f"git could not diff against '{base}' (unknown revision or no history)",
                base=base,
            )
        collected.extend(out.splitlines())
    else:
        unstaged_ok, unstaged = _run_git(root_path, ["diff", "--name-only", "--relative"])
        staged_ok, staged = _run_git(
            root_path, ["diff", "--name-only", "--relative", "--cached"]
        )
        if not (unstaged_ok and staged_ok):
            return ChangeSet([], "git diff failed, so changed files could not be determined")
        collected.extend(unstaged.splitlines())
        collected.extend(staged.splitlines())
        untracked_ok, untracked = _run_git(
            root_path, ["ls-files", "--others", "--exclude-standard"]
        )
        if untracked_ok:
            collected.extend(untracked.splitlines())

    # Deduplicate, drop deletions, and keep paths relative to the project root.
    seen: List[str] = []
    for raw in collected:
        name = raw.strip()
        if not name:
            continue
        if source_only and Path(name).suffix not in SOURCE_SUFFIXES:
            continue
        if not (root_path / name).is_file():
            # Deleted or moved away: nothing left to scan or test.
            continue
        if name not in seen:
            seen.append(name)

    return ChangeSet(sorted(seen), "", base=base)


def _test_name_candidates(stem: str) -> List[str]:
    return [f"test_{stem}.py", f"{stem}_test.py", f"test_{stem}.js", f"{stem}.test.js",
            f"{stem}.test.ts", f"{stem}.spec.ts", f"{stem}.spec.js"]


def related_test_files(root: Path | str, changed: Sequence[str]) -> List[str]:
    """Return test files associated with ``changed``, by naming convention.

    Convention-based and therefore incomplete: a test that exercises a module
    without naming it after that module will not be found. That is why
    ``--changed`` is documented as a narrowing optimisation and the report says
    which files it covered, rather than claiming the change is fully verified.
    """
    root_path = Path(root).resolve()
    found: List[str] = []

    for name in changed:
        path = Path(name)
        # A changed test file is its own related test.
        if path.name.startswith("test_") or ".test." in path.name or ".spec." in path.name:
            if name not in found:
                found.append(name)
            continue

        for candidate_name in _test_name_candidates(path.stem):
            for directory in (
                root_path / "tests",
                root_path / "test",
                root_path / path.parent,
                root_path,
            ):
                candidate = directory / candidate_name
                if candidate.is_file():
                    try:
                        rel = str(candidate.relative_to(root_path)).replace("\\", "/")
                    except ValueError:
                        continue
                    if rel not in found:
                        found.append(rel)
            # Nested test trees, e.g. tests/unit/test_foo.py
            for base_dir in (root_path / "tests", root_path / "test"):
                if not base_dir.is_dir():
                    continue
                try:
                    matches = list(base_dir.glob(f"**/{candidate_name}"))
                except OSError:
                    continue
                for match in matches:
                    try:
                        rel = str(match.relative_to(root_path)).replace("\\", "/")
                    except ValueError:
                        continue
                    if rel not in found:
                        found.append(rel)

    return sorted(found)


def describe(change_set: ChangeSet, related: Optional[Sequence[str]] = None) -> str:
    """One-line human summary, suitable for a report's skipped section."""
    if not change_set.narrowed:
        return f"full run: {change_set.fallback_reason}"
    scope = f"{len(change_set.files)} changed file(s)"
    if change_set.base:
        scope += f" since {change_set.base}"
    if related:
        scope += f", {len(related)} related test file(s)"
    return f"narrowed to {scope}"
