from __future__ import annotations

from pathlib import Path
import json
import sys


def detect_python_package_manager(root: Path) -> str:
    """Identify the Python package manager from its lockfile, else pip.

    A lockfile is the only reliable signal: pyproject.toml alone says nothing,
    since uv, poetry, pdm and plain pip all read it. Reported separately from
    the JavaScript ``package_manager`` field because that value is interpolated
    into npm-style commands -- putting "uv" there would build `uv run test`.

    Returns "unknown" when nothing identifies the project as Python at all, so
    a caller can tell "no Python here" from "Python, manager unidentified".
    """
    for name, marker in (
        ("uv", "uv.lock"),
        ("poetry", "poetry.lock"),
        ("pdm", "pdm.lock"),
        ("pipenv", "Pipfile.lock"),
    ):
        if (root / marker).is_file():
            return name

    if (root / "pyproject.toml").is_file():
        return "pip"
    try:
        if any(root.glob("requirements*.txt")):
            return "pip"
    except OSError:
        pass
    if (root / "setup.py").is_file() or (root / "setup.cfg").is_file():
        return "pip"
    return "unknown"


def detect_project(root: Path | str) -> dict:
    """Detect common project types from their configuration files."""

    root = Path(root).resolve()

    checks = {
        "python": [
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
            "Pipfile",
            "poetry.lock",
            "uv.lock",
            # Test-only and tool-only Python projects carry no packaging manifest.
            # Without these markers a test suite driven solely by pytest.ini or a
            # conftest.py is reported as having no ecosystem at all.
            "pytest.ini",
            "tox.ini",
            "conftest.py",
        ],
        "javascript": ["package.json"],
        "typescript": ["tsconfig.json"],
        "rust": ["Cargo.toml"],
        "go": ["go.mod"],
        "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
        "dotnet": [],
    }

    detected = []

    for language, markers in checks.items():
        if any((root / marker).is_file() for marker in markers):
            detected.append(language)

    if (
        any(root.glob("*.csproj"))
        or any(root.glob("*.sln"))
        or any(root.glob("*/*.csproj"))
        or any(root.glob("src/*/*.csproj"))
    ):
        detected.append("dotnet")

    if (root / "package.json").is_file():
        package_json = root / "package.json"
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
            scripts = data.get("scripts", {})
        except (json.JSONDecodeError, OSError):
            data = {}
            scripts = {}

        package_manager = next(
            (
                name
                for name, marker in [
                    ("pnpm", "pnpm-lock.yaml"),
                    ("yarn", "yarn.lock"),
                    ("npm", "package-lock.json"),
                    ("bun", "bun.lock"),
                    ("bun", "bun.lockb"),
                ]
                if (root / marker).is_file()
            ),
            None,
        )

        if not package_manager:
            pm_field = str(data.get("packageManager", "")).lower()
            for name in ("pnpm", "yarn", "npm", "bun"):
                if pm_field.startswith(name):
                    package_manager = name
                    break

        if not package_manager:
            package_manager = "unknown"
    else:
        scripts = {}
        package_manager = "unknown"

    return {
        "project_root": str(root.resolve()),
        "detected_types": detected,
        "package_manager": package_manager,
        "python_package_manager": detect_python_package_manager(root),
        "available_scripts": scripts,
    }


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("Usage: detect-project.py [PROJECT_DIRECTORY]")
        print("Detects project types, package managers, and scripts from project configuration.")
        sys.exit(0)

    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()

    if not root.is_dir():
        print(f"Error: project directory does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    result = detect_project(root)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()