#!/usr/bin/env python3
"""
Install the Veriflow skill for Claude Code.

Claude Code discovers skills by scanning two places for a ``<name>/SKILL.md``:

    ~/.claude/skills/        every project you open   (default here)
    <project>/.claude/skills/   that one repository   (--project)

Veriflow's source is ``skills/veriflow/``, which Claude Code does not scan, so
installing means copying that one directory into one of those two locations.

    python install.py                 # all your projects
    python install.py --project       # just the current directory
    python install.py --uninstall
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / "skills" / "veriflow"

# Caches would ship stale bytecode that shadows the real module.
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".pyd"}


def source_files() -> list[Path]:
    """Every file to install, relative to SOURCE."""
    found = []
    for current, dirs, names in os.walk(SOURCE):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            if Path(name).suffix not in SKIP_SUFFIXES:
                found.append((Path(current) / name).relative_to(SOURCE))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install the Veriflow skill for Claude Code.",
    )
    parser.add_argument(
        "--project",
        action="store_true",
        help="Install into ./.claude/skills/ instead of ~/.claude/skills/.",
    )
    parser.add_argument("--uninstall", action="store_true", help="Remove the installed skill.")
    args = parser.parse_args()

    if not SOURCE.is_dir():
        print(f"Error: {SOURCE} not found. Run this from a Veriflow checkout.", file=sys.stderr)
        return 2

    root = Path.cwd() if args.project else Path.home()
    destination = root / ".claude" / "skills" / "veriflow"

    if args.uninstall:
        if not destination.exists():
            print(f"Nothing installed at {destination}")
            return 0
        shutil.rmtree(destination)
        print(f"Removed {destination}")
        print("Restart Claude Code so it stops offering the skill.")
        return 0

    if destination.exists() and not (destination / "SKILL.md").is_file():
        print(f"Error: {destination} exists but is not a skill directory.", file=sys.stderr)
        print("Move it aside first; refusing to overwrite something unrecognised.", file=sys.stderr)
        return 2

    files = source_files()
    try:
        # Replace rather than merge, so a file dropped from a later version
        # does not linger at the destination and shadow the real one.
        if destination.exists():
            shutil.rmtree(destination)
        for relative in files:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SOURCE / relative, target)
    except PermissionError as exc:
        print(f"Error: permission denied: {exc}", file=sys.stderr)
        return 2

    print(f"Installed {len(files)} files to {destination}")
    print()
    print("Restart Claude Code, then ask: \"what skills do you have available?\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
