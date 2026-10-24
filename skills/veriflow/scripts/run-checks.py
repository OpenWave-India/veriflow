"""
Veriflow — Check Discovery and Preview Runner

Discovers available test, lint, type-check, and build validation commands
from project configuration files without executing them.
"""

from __future__ import annotations

from pathlib import Path
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import time


def _load_detector():
    """Load detect_project from detect-project.py in the same directory."""
    script_path = Path(__file__).parent / "detect-project.py"
    if script_path.is_file():
        try:
            spec = importlib.util.spec_from_file_location("detect_project_module", script_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.detect_project
        except Exception:
            return None
    return None


_detect_project_fn = _load_detector()


def _load_changed_files():
    """Load the shared changed-files helper from the same directory."""
    script_path = Path(__file__).parent / "changed_files.py"
    if script_path.is_file():
        try:
            spec = importlib.util.spec_from_file_location("veriflow_changed_files", script_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        except Exception:
            return None
    return None


_changed_files_mod = _load_changed_files()


def _load_browser_detector():
    """Load detect_browser_environment from browser_detector.py in the same directory."""
    script_path = Path(__file__).parent / "browser_detector.py"
    if script_path.is_file():
        try:
            spec = importlib.util.spec_from_file_location("browser_detector_module", script_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = mod
                spec.loader.exec_module(mod)
                return mod.detect_browser_environment
        except Exception:
            return None
    return None


_detect_browser_fn = _load_browser_detector()


def _read_file_safe(path: Path) -> str:
    """Read a text file safely, returning empty string on failure."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return ""


def _find_python_environment(root: Path) -> dict | None:
    """
    Find a project-local virtual environment in the target project root.
    Only inspects direct subdirectories (e.g. .venv, venv, env)
    without searching parent directories or unrelated filesystem locations.
    """
    venv_candidates = [".venv", "venv", "env"]
    for name in venv_candidates:
        candidate = root / name
        if not candidate.is_dir():
            continue

        python_candidates = [
            candidate / "Scripts" / "python.exe",
            candidate / "Scripts" / "python",
            candidate / "bin" / "python",
            candidate / "bin" / "python.exe",
        ]
        python_exe = next((p for p in python_candidates if p.is_file()), None)

        scripts_dirs = [d for d in [candidate / "Scripts", candidate / "bin"] if d.is_dir()]
        if python_exe or scripts_dirs:
            return {
                "venv_dir": candidate,
                "python_exe": python_exe,
                "scripts_dirs": scripts_dirs,
            }
    return None


def _interpreter_version(python_exe: Path) -> str | None:
    """Return an interpreter's version without running it.

    Executing a binary found on PATH during *discovery* would break the
    preview-by-default rule, so the version is read off the filesystem:

    1. ``pyvenv.cfg`` beside the environment root records ``version = 3.13.3``.
    2. A POSIX install exposes ``lib/python3.13/``.
    3. A Windows install exposes ``python313.dll``.

    Returns None when none of those are present, in which case the caller says
    "unknown version" rather than guessing.
    """
    try:
        bin_dir = python_exe.parent
        for cfg in (bin_dir.parent / "pyvenv.cfg", bin_dir / "pyvenv.cfg"):
            if cfg.is_file():
                for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
                    key, _, value = line.partition("=")
                    if key.strip() in ("version", "version_info"):
                        return value.strip()

        # Search the interpreter's own directory as well as one level up: a
        # virtual environment keeps python in Scripts/ or bin/ with lib/ beside
        # it, while a system install puts python.exe in the root next to
        # python313.dll. Checking only the parent misses the system layout and
        # silently degrades every version to "unknown".
        for directory in (bin_dir, bin_dir / "lib", bin_dir / "Lib", bin_dir.parent, bin_dir.parent / "lib"):
            if not directory.is_dir():
                continue
            for child in directory.iterdir():
                name = child.name
                if child.is_dir() and name.startswith("python3") and "." in name:
                    return name[len("python"):]
                if name.lower().startswith("python3") and name.lower().endswith(".dll"):
                    digits = name[len("python"):-len(".dll")]
                    if digits.isdigit() and len(digits) >= 2:
                        return f"{digits[0]}.{digits[1:]}"
    except (OSError, PermissionError):
        return None
    return None


def _describe_interpreter(python_exe: Path | str) -> str:
    """Return 'path (version X)' for a limitation message."""
    path = Path(python_exe)
    version = _interpreter_version(path)
    return f"{path} (Python {version})" if version else f"{path} (version unknown)"


def _interpreter_behind_script(script_path: Path) -> Path | None:
    """Return the interpreter a console script would run under.

    Two layouts to cover, and missing the second one silently disables the
    mismatch warning this exists to produce:

    - A virtual environment puts ``python`` and ``pytest`` side by side in
      ``Scripts/`` (Windows) or ``bin/`` (POSIX).
    - A system install puts ``pytest.exe`` in ``Scripts/`` but ``python.exe``
      one level up, in the installation root.
    """
    bin_dir = script_path.parent
    for directory in (bin_dir, bin_dir.parent):
        for name in ("python.exe", "python", "python3.exe", "python3"):
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _same_interpreter(left: Path | str, right: Path | str) -> bool:
    try:
        return Path(left).resolve() == Path(right).resolve()
    except (OSError, ValueError):
        return str(left) == str(right)


#: Checks proposed because the tool is installed, not because the project asked
#: for it. Kept distinct from "proposed" so a caller can offer them separately
#: and a report can say the configuration is the tool's default, not the
#: project's: running a linter under defaults it was never tuned for produces
#: findings the project may have deliberately disabled.
STATUS_OPTIONAL = "proposed_optional"


def _propose_default_config_check(
    name: str,
    ecosystem: str,
    tool: str,
    argv_tail: list[str],
    root: Path,
    venv_info: dict | None = None,
    use_python_module: bool = False,
) -> dict | None:
    """Propose an installed-but-unconfigured tool as an optional check.

    Returns None when the tool is not installed, in which case there is nothing
    to offer and the caller records a limitation instead. Skipping a tool the
    user already has installed is a silent loss of coverage; proposing it with
    the label makes the trade-off visible and declinable.
    """
    res = resolve_executable(tool, root, allow_global=False if venv_info else True)
    if res["resolution_source"] == "not_found":
        return None

    if use_python_module and res.get("python_exe"):
        command = [res["python_exe"], "-m", tool, *argv_tail]
        resolved = res["python_exe"]
    else:
        command = [res["resolved_path"], *argv_tail]
        resolved = res["resolved_path"]

    return {
        "name": name,
        "ecosystem": ecosystem,
        "command": command,
        "reason": (
            f"'{tool}' is installed but this project has no {tool} configuration. "
            f"Proposed as an optional check using {tool}'s default config, which may "
            f"report issues the project would have configured away."
        ),
        "resolved_executable": resolved,
        "resolution_source": res["resolution_source"],
        "config_source": "default config",
        "optional": True,
        "executed": False,
        "status": STATUS_OPTIONAL,
    }


def _find_node_modules_bin(root: Path, tool_name: str) -> Path | None:
    """
    Find a project-local executable in node_modules/.bin.
    Checks Unix and Windows launcher extensions (.cmd, .bat, .exe).
    """
    bin_dir = root / "node_modules" / ".bin"
    if not bin_dir.is_dir():
        return None

    candidates = [
        bin_dir / f"{tool_name}.cmd",
        bin_dir / f"{tool_name}.bat",
        bin_dir / f"{tool_name}.exe",
        bin_dir / tool_name,
    ]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def resolve_executable(raw_exe: str, cwd: Path | str, allow_global: bool = True) -> dict:
    """
    Resolve an executable using Veriflow's predictable multi-tier policy:
      1. Project-local Python virtual environment (.venv, venv, env)
      2. Project-local node_modules/.bin
      3. Project root direct scripts/wrappers (e.g. gradlew.bat, mvnw)
      4. System PATH via shutil.which (if allow_global=True)
      5. Not found

    Returns a dict with:
      - 'resolved_path': str | None
      - 'resolution_source': 'project_venv' | 'node_modules' | 'project_root' | 'system_path' | 'not_found'
      - 'python_exe': str | None (if resolved via a Python venv)
      - 'venv_dir': str | None
    """
    cwd_path = Path(cwd).resolve()

    # Direct file check
    direct_file = Path(raw_exe)
    if not direct_file.is_absolute():
        direct_candidate = (cwd_path / raw_exe).resolve()
        if direct_candidate.is_file():
            direct_file = direct_candidate
    else:
        direct_file = direct_file.resolve()

    if direct_file.is_file():
        source = "direct_path"
        resolved_str = str(direct_file)
        if resolved_str.startswith(str(cwd_path)):
            parts = direct_file.parts
            if any(p in (".venv", "venv", "env") for p in parts):
                source = "project_venv"
            elif "node_modules" in parts:
                source = "node_modules"
            else:
                source = "project_root"
        return {
            "resolved_path": resolved_str,
            "resolution_source": source,
            "python_exe": None,
            "venv_dir": None,
        }

    # Tier 1: Project-local Python virtual environment
    venv_info = _find_python_environment(cwd_path)
    if venv_info:
        for sdir in venv_info["scripts_dirs"]:
            candidates = [
                sdir / f"{raw_exe}.exe",
                sdir / f"{raw_exe}.cmd",
                sdir / f"{raw_exe}.bat",
                sdir / raw_exe,
            ]
            for cand in candidates:
                if cand.is_file():
                    return {
                        "resolved_path": str(cand.resolve()),
                        "resolution_source": "project_venv",
                        "python_exe": str(venv_info["python_exe"].resolve()) if venv_info["python_exe"] else None,
                        "venv_dir": str(venv_info["venv_dir"].resolve()),
                    }

    # Tier 2: Project-local node_modules/.bin
    local_bin = _find_node_modules_bin(cwd_path, raw_exe)
    if local_bin:
        return {
            "resolved_path": str(local_bin.resolve()),
            "resolution_source": "node_modules",
            "python_exe": None,
            "venv_dir": None,
        }

    # Tier 3: Direct project root files (e.g. gradlew.bat, run.cmd)
    local_candidate = (cwd_path / raw_exe).resolve()
    if local_candidate.is_file():
        return {
            "resolved_path": str(local_candidate),
            "resolution_source": "project_root",
            "python_exe": None,
            "venv_dir": None,
        }
    if sys.platform == "win32":
        for ext in (".cmd", ".bat", ".exe"):
            cand_ext = (cwd_path / f"{raw_exe}{ext}").resolve()
            if cand_ext.is_file():
                return {
                    "resolved_path": str(cand_ext),
                    "resolution_source": "project_root",
                    "python_exe": None,
                    "venv_dir": None,
                }

    # Tier 4: Global PATH
    if allow_global:
        global_exe = shutil.which(raw_exe)
        if global_exe:
            return {
                "resolved_path": str(Path(global_exe).resolve()),
                "resolution_source": "system_path",
                "python_exe": None,
                "venv_dir": None,
            }

    # Tier 5: Not found
    return {
        "resolved_path": None,
        "resolution_source": "not_found",
        "python_exe": None,
        "venv_dir": None,
    }


def _discover_python_checks(root: Path) -> tuple[list[dict], list[str]]:
    """Discover Python test, lint, and type-check commands."""
    checks = []
    limitations = []

    pyproject_text = _read_file_safe(root / "pyproject.toml")
    setup_cfg_text = _read_file_safe(root / "setup.cfg")
    tox_ini_text = _read_file_safe(root / "tox.ini")
    venv_info = _find_python_environment(root)

    # 1. pytest discovery
    has_pytest_config = False
    pytest_reason = ""

    if (root / "pytest.ini").is_file():
        has_pytest_config = True
        pytest_reason = "Found pytest.ini configuration"
    elif "[tool.pytest" in pyproject_text:
        has_pytest_config = True
        pytest_reason = "Found pytest configuration in pyproject.toml"
    elif "[tool:pytest]" in setup_cfg_text or "[pytest]" in setup_cfg_text:
        has_pytest_config = True
        pytest_reason = "Found pytest configuration in setup.cfg"
    elif "[pytest]" in tox_ini_text:
        has_pytest_config = True
        pytest_reason = "Found pytest configuration in tox.ini"

    has_test_files = False
    if (root / "tests").is_dir():
        try:
            if any((root / "tests").glob("**/*.py")):
                has_test_files = True
                if not pytest_reason:
                    pytest_reason = "Found tests/ directory with Python test files"
        except OSError:
            pass
    elif (root / "test").is_dir():
        try:
            if any((root / "test").glob("**/*.py")):
                has_test_files = True
                if not pytest_reason:
                    pytest_reason = "Found test/ directory with Python test files"
        except OSError:
            pass

    if not has_test_files:
        try:
            if any(root.glob("test_*.py")) or any(root.glob("*_test.py")):
                has_test_files = True
                if not pytest_reason:
                    pytest_reason = "Found top-level Python test files"
        except OSError:
            pass

    if has_pytest_config or has_test_files:
        # Always invoke pytest as `<interpreter> -m pytest`. A bare `pytest`
        # runs whichever launcher PATH happens to resolve first, which can
        # import a different site-packages than the project's -- tests then
        # pass or fail for reasons that have nothing to do with the code.
        if venv_info and venv_info.get("python_exe"):
            interpreter = str(venv_info["python_exe"].resolve())
            resolution_source = "project_venv"
            reason_str = f"{pytest_reason} (project-local venv interpreter, invoked as -m pytest)"
        else:
            interpreter = sys.executable
            resolution_source = "veriflow_interpreter"
            reason_str = (
                f"{pytest_reason} (no project venv found; using the interpreter "
                "running Veriflow, invoked as -m pytest)"
            )

        checks.append({
            "name": "test",
            "ecosystem": "python",
            "command": [interpreter, "-m", "pytest"],
            "reason": reason_str,
            "resolved_executable": interpreter,
            "resolution_source": resolution_source,
            "executed": False,
            "status": "proposed",
        })

        # Warn when a pytest launcher on PATH belongs to a different Python
        # than the one that will be used, because that is the case where a
        # user running `pytest` by hand gets different results from Veriflow.
        path_pytest = shutil.which("pytest")
        if path_pytest:
            path_interpreter = _interpreter_behind_script(Path(path_pytest))
            if path_interpreter and not _same_interpreter(path_interpreter, interpreter):
                limitations.append(
                    "WARNING: a 'pytest' on PATH belongs to a different Python than the "
                    f"one Veriflow will use. Veriflow: {_describe_interpreter(interpreter)}; "
                    f"PATH pytest: {path_pytest} -> {_describe_interpreter(path_interpreter)}. "
                    "Running 'pytest' directly may import different packages and give a "
                    "different result."
                )

        # Report installation state separately from command construction: the
        # command is still correct when pytest is absent, it just cannot run,
        # and that must surface as a limitation rather than a silent pass.
        pytest_present = resolve_executable(
            "pytest", root, allow_global=False if venv_info else True
        )["resolution_source"] != "not_found"
        if not pytest_present:
            where = (
                "the project virtual environment"
                if venv_info
                else "the interpreter running Veriflow"
            )
            limitations.append(
                f"pytest configured or tests found, but 'pytest' is not installed in {where}. "
                f"The check will report COMMAND_NOT_FOUND rather than PASS."
            )
    else:
        limitations.append("No pytest configuration or test files discovered for Python.")

    # 2. Ruff discovery
    has_ruff_config = False
    ruff_reason = ""
    if (root / "ruff.toml").is_file():
        has_ruff_config = True
        ruff_reason = "Found ruff.toml"
    elif (root / ".ruff.toml").is_file():
        has_ruff_config = True
        ruff_reason = "Found .ruff.toml"
    elif "[tool.ruff]" in pyproject_text or "[tool.ruff." in pyproject_text:
        has_ruff_config = True
        ruff_reason = "Found ruff configuration in pyproject.toml"

    if has_ruff_config:
        res = resolve_executable("ruff", root, allow_global=False if venv_info else True)
        if res["resolution_source"] == "project_venv":
            cmd = [res["resolved_path"], "check", "."]
            checks.append({
                "name": "lint",
                "ecosystem": "python",
                "command": cmd,
                "reason": f"{ruff_reason} (using project-local venv)",
                "resolved_executable": res["resolved_path"],
                "resolution_source": "project_venv",
                "executed": False,
                "status": "proposed",
            })
        elif res["resolution_source"] == "system_path":
            checks.append({
                "name": "lint",
                "ecosystem": "python",
                "command": ["ruff", "check", "."],
                "reason": ruff_reason,
                "resolved_executable": res["resolved_path"],
                "resolution_source": "system_path",
                "executed": False,
                "status": "proposed",
            })
        else:
            checks.append({
                "name": "lint",
                "ecosystem": "python",
                "command": ["ruff", "check", "."],
                "reason": f"{ruff_reason} (not found in project venv or PATH)",
                "resolved_executable": None,
                "resolution_source": "not_found",
                "executed": False,
                "status": "proposed",
            })
            if venv_info:
                limitations.append("Ruff configuration discovered, but 'ruff' is not installed in the project virtual environment.")
            else:
                limitations.append("Ruff configuration discovered, but 'ruff' is not installed on PATH.")
    else:
        optional = _propose_default_config_check(
            "lint", "python", "ruff", ["check", "."], root, venv_info
        )
        if optional:
            checks.append(optional)
            limitations.append(
                "No Ruff configuration discovered, but 'ruff' is installed. Proposed as an "
                "optional 'lint' check using Ruff's default rules."
            )
        else:
            limitations.append("No Ruff configuration discovered for Python, and 'ruff' is not installed.")

    # 3. mypy discovery
    has_mypy_config = False
    mypy_reason = ""
    if (root / "mypy.ini").is_file():
        has_mypy_config = True
        mypy_reason = "Found mypy.ini"
    elif (root / ".mypy.ini").is_file():
        has_mypy_config = True
        mypy_reason = "Found .mypy.ini"
    elif "[tool.mypy]" in pyproject_text or "[tool.mypy." in pyproject_text:
        has_mypy_config = True
        mypy_reason = "Found mypy configuration in pyproject.toml"
    elif "[mypy]" in setup_cfg_text:
        has_mypy_config = True
        mypy_reason = "Found mypy configuration in setup.cfg"

    if has_mypy_config:
        res = resolve_executable("mypy", root, allow_global=False if venv_info else True)
        if res["resolution_source"] == "project_venv":
            if res.get("python_exe"):
                cmd = [res["python_exe"], "-m", "mypy", "."]
                resolved_exe = res["python_exe"]
                reason_str = f"{mypy_reason} (using project-local venv interpreter)"
            else:
                cmd = [res["resolved_path"], "."]
                resolved_exe = res["resolved_path"]
                reason_str = f"{mypy_reason} (using project-local venv)"
            checks.append({
                "name": "typecheck",
                "ecosystem": "python",
                "command": cmd,
                "reason": reason_str,
                "resolved_executable": resolved_exe,
                "resolution_source": "project_venv",
                "executed": False,
                "status": "proposed",
            })
        elif res["resolution_source"] == "system_path":
            checks.append({
                "name": "typecheck",
                "ecosystem": "python",
                "command": ["mypy", "."],
                "reason": mypy_reason,
                "resolved_executable": res["resolved_path"],
                "resolution_source": "system_path",
                "executed": False,
                "status": "proposed",
            })
        else:
            checks.append({
                "name": "typecheck",
                "ecosystem": "python",
                "command": ["mypy", "."],
                "reason": f"{mypy_reason} (not found in project venv or PATH)",
                "resolved_executable": None,
                "resolution_source": "not_found",
                "executed": False,
                "status": "proposed",
            })
            if venv_info:
                limitations.append("mypy configuration discovered, but 'mypy' is not installed in the project virtual environment.")
            else:
                limitations.append("mypy configuration discovered, but 'mypy' is not installed on PATH.")
    else:
        optional = _propose_default_config_check(
            "typecheck", "python", "mypy", ["."], root, venv_info, use_python_module=True
        )
        if optional:
            checks.append(optional)
            limitations.append(
                "No mypy configuration discovered, but 'mypy' is installed. Proposed as an "
                "optional 'typecheck' check using mypy's default settings, which are "
                "stricter than most projects configure."
            )
        else:
            limitations.append("No mypy configuration discovered for Python, and 'mypy' is not installed.")

    return checks, limitations


def _discover_javascript_checks(root: Path, detection: dict) -> tuple[list[dict], list[str]]:
    """Discover JavaScript and TypeScript checks from package.json and tsconfig.json."""
    checks = []
    limitations = []

    package_json_path = root / "package.json"
    if not package_json_path.is_file():
        return checks, limitations

    package_manager = detection.get("package_manager", "unknown")
    pm = package_manager if package_manager != "unknown" else "npm"

    scripts = detection.get("available_scripts", {})
    if not isinstance(scripts, dict):
        scripts = {}

    def _make_pm_cmd(script_name: str) -> list[str]:
        if script_name == "test":
            return [pm, "test"]
        return [pm, "run", script_name]

    candidates = [
        ("test", "test"),
        ("lint", "lint"),
        ("typecheck", "typecheck"),
        ("type-check", "typecheck"),
        ("check", "check"),
        ("build", "build"),
    ]

    seen_check_names = set()
    pm_resolved = shutil.which(pm)
    for script_key, check_name in candidates:
        if script_key in scripts and check_name not in seen_check_names:
            checks.append({
                "name": check_name,
                "ecosystem": "javascript",
                "command": _make_pm_cmd(script_key),
                "reason": f"Found '{script_key}' script in package.json using {pm}",
                "resolved_executable": pm_resolved,
                "resolution_source": "package_manager",
                "executed": False,
                "status": "proposed",
            })
            seen_check_names.add(check_name)

    # Check for project-local ESLint in node_modules/.bin or config if 'lint' not defined in scripts
    if "lint" not in seen_check_names:
        local_eslint = _find_node_modules_bin(root, "eslint")
        has_eslint_config = (
            (root / ".eslintrc.json").is_file()
            or (root / ".eslintrc.js").is_file()
            or (root / ".eslintrc.cjs").is_file()
            or (root / ".eslintrc.yaml").is_file()
            or (root / ".eslintrc.yml").is_file()
            or (root / ".eslintrc").is_file()
            or (root / "eslint.config.js").is_file()
            or (root / "eslint.config.mjs").is_file()
            or (root / "eslint.config.cjs").is_file()
        )
        if local_eslint:
            checks.append({
                "name": "lint",
                "ecosystem": "javascript",
                "command": [str(local_eslint), "."],
                "reason": "Found project-local ESLint in node_modules/.bin",
                "resolved_executable": str(local_eslint),
                "resolution_source": "node_modules",
                "executed": False,
                "status": "proposed",
            })
            seen_check_names.add("lint")
        elif has_eslint_config:
            global_eslint = shutil.which("eslint")
            if global_eslint:
                checks.append({
                    "name": "lint",
                    "ecosystem": "javascript",
                    "command": ["eslint", "."],
                    "reason": "Found ESLint configuration (using system PATH)",
                    "resolved_executable": str(global_eslint),
                    "resolution_source": "system_path",
                    "executed": False,
                    "status": "proposed",
                })
                limitations.append("ESLint was not found in project node_modules/.bin; falling back to globally installed 'eslint'.")
            else:
                checks.append({
                    "name": "lint",
                    "ecosystem": "javascript",
                    "command": ["eslint", "."],
                    "reason": "Found ESLint configuration (missing from node_modules and PATH)",
                    "resolved_executable": None,
                    "resolution_source": "not_found",
                    "executed": False,
                    "status": "proposed",
                })
                limitations.append("ESLint configuration discovered, but 'eslint' is not installed in node_modules/.bin or PATH.")
            seen_check_names.add("lint")
        else:
            global_eslint = shutil.which("eslint")
            if global_eslint:
                checks.append({
                    "name": "lint",
                    "ecosystem": "javascript",
                    "command": ["eslint", "."],
                    "reason": (
                        "'eslint' is installed but this project has no ESLint configuration. "
                        "Proposed as an optional check using ESLint's default config, which "
                        "may report issues the project would have configured away."
                    ),
                    "resolved_executable": str(global_eslint),
                    "resolution_source": "system_path",
                    "config_source": "default config",
                    "optional": True,
                    "executed": False,
                    "status": STATUS_OPTIONAL,
                })
                limitations.append(
                    "No ESLint configuration discovered, but 'eslint' is installed. Proposed "
                    "as an optional 'lint' check using ESLint's default rules."
                )
                seen_check_names.add("lint")

    # TypeScript fallback if typecheck not explicitly defined in scripts
    if "typecheck" not in seen_check_names and (root / "tsconfig.json").is_file():
        local_tsc = _find_node_modules_bin(root, "tsc")
        if local_tsc:
            checks.append({
                "name": "typecheck",
                "ecosystem": "typescript",
                "command": [str(local_tsc), "--noEmit"],
                "reason": "Found tsconfig.json and project-local tsc in node_modules/.bin",
                "resolved_executable": str(local_tsc),
                "resolution_source": "node_modules",
                "executed": False,
                "status": "proposed",
            })
        else:
            global_tsc = shutil.which("tsc")
            if global_tsc:
                checks.append({
                    "name": "typecheck",
                    "ecosystem": "typescript",
                    "command": ["tsc", "--noEmit"],
                    "reason": "Found tsconfig.json in TypeScript project (using system PATH)",
                    "resolved_executable": str(global_tsc),
                    "resolution_source": "system_path",
                    "executed": False,
                    "status": "proposed",
                })
                limitations.append("TypeScript compiler was not found in project node_modules/.bin; falling back to globally installed 'tsc'.")
            else:
                checks.append({
                    "name": "typecheck",
                    "ecosystem": "typescript",
                    "command": ["tsc", "--noEmit"],
                    "reason": "Found tsconfig.json in TypeScript project (missing from node_modules and PATH)",
                    "resolved_executable": None,
                    "resolution_source": "not_found",
                    "executed": False,
                    "status": "proposed",
                })
                limitations.append("tsconfig.json found, but 'tsc' is not installed in node_modules/.bin or PATH.")
        seen_check_names.add("typecheck")

    # tsc installed but the project has no tsconfig.json. Only worth proposing
    # when TypeScript sources actually exist: `tsc --noEmit` with no config and
    # no file arguments compiles nothing and would report a hollow PASS.
    elif "typecheck" not in seen_check_names:
        try:
            has_ts_sources = any(root.glob("*.ts")) or any(root.glob("src/**/*.ts"))
        except OSError:
            has_ts_sources = False
        if has_ts_sources:
            tsc_path = _find_node_modules_bin(root, "tsc") or shutil.which("tsc")
            if tsc_path:
                checks.append({
                    "name": "typecheck",
                    "ecosystem": "typescript",
                    "command": [str(tsc_path), "--noEmit", "--strict"],
                    "reason": (
                        "'tsc' is installed and TypeScript sources exist, but this project "
                        "has no tsconfig.json. Proposed as an optional check using tsc's "
                        "default compiler options, which may differ from the project's intent."
                    ),
                    "resolved_executable": str(tsc_path),
                    "resolution_source": "node_modules" if _find_node_modules_bin(root, "tsc") else "system_path",
                    "config_source": "default config",
                    "optional": True,
                    "executed": False,
                    "status": STATUS_OPTIONAL,
                })
                limitations.append(
                    "No tsconfig.json discovered, but 'tsc' is installed and TypeScript "
                    "sources exist. Proposed as an optional 'typecheck' check using default "
                    "compiler options."
                )
                seen_check_names.add("typecheck")

    if "test" not in seen_check_names:
        limitations.append("No 'test' script found in package.json.")
    if "lint" not in seen_check_names:
        limitations.append("No 'lint' script or ESLint tool found.")
    if "typecheck" not in seen_check_names:
        limitations.append("No 'typecheck' script or tsconfig.json found.")

    return checks, limitations


def _discover_rust_checks(root: Path) -> tuple[list[dict], list[str]]:
    """Discover Rust check commands."""
    checks = []
    limitations = []
    if (root / "Cargo.toml").is_file():
        cargo_exe = shutil.which("cargo")
        checks.append({
            "name": "test",
            "ecosystem": "rust",
            "command": ["cargo", "test"],
            "reason": "Found Cargo.toml in Rust project",
            "resolved_executable": cargo_exe,
            "resolution_source": "system_path" if cargo_exe else "not_found",
            "executed": False,
            "status": "proposed",
        })
        checks.append({
            "name": "check",
            "ecosystem": "rust",
            "command": ["cargo", "check"],
            "reason": "Found Cargo.toml in Rust project",
            "resolved_executable": cargo_exe,
            "resolution_source": "system_path" if cargo_exe else "not_found",
            "executed": False,
            "status": "proposed",
        })
    return checks, limitations


def _discover_go_checks(root: Path) -> tuple[list[dict], list[str]]:
    """Discover Go check commands."""
    checks = []
    limitations = []
    if (root / "go.mod").is_file():
        go_exe = shutil.which("go")
        checks.append({
            "name": "test",
            "ecosystem": "go",
            "command": ["go", "test", "./..."],
            "reason": "Found go.mod in Go project",
            "resolved_executable": go_exe,
            "resolution_source": "system_path" if go_exe else "not_found",
            "executed": False,
            "status": "proposed",
        })
        checks.append({
            "name": "vet",
            "ecosystem": "go",
            "command": ["go", "vet", "./..."],
            "reason": "Found go.mod in Go project",
            "resolved_executable": go_exe,
            "resolution_source": "system_path" if go_exe else "not_found",
            "executed": False,
            "status": "proposed",
        })
    return checks, limitations


def _discover_dotnet_checks(root: Path, detection: dict) -> tuple[list[dict], list[str]]:
    """Discover .NET check commands."""
    checks = []
    limitations = []
    if "dotnet" in detection.get("detected_types", []):
        dotnet_exe = shutil.which("dotnet")
        checks.append({
            "name": "test",
            "ecosystem": "dotnet",
            "command": ["dotnet", "test"],
            "reason": "Found .NET solution or project file",
            "resolved_executable": dotnet_exe,
            "resolution_source": "system_path" if dotnet_exe else "not_found",
            "executed": False,
            "status": "proposed",
        })
        checks.append({
            "name": "build",
            "ecosystem": "dotnet",
            "command": ["dotnet", "build"],
            "reason": "Found .NET solution or project file",
            "resolved_executable": dotnet_exe,
            "resolution_source": "system_path" if dotnet_exe else "not_found",
            "executed": False,
            "status": "proposed",
        })
    return checks, limitations


def _discover_dependency_audit_checks(root: Path, detection: dict) -> tuple[list[dict], list[str]]:
    """Offer a dependency vulnerability audit, or state what is blocking it.

    Veriflow bundles no CVE data, so this delegates to the ecosystem's real
    auditing tool. Two rules shape the result:

    - **Nothing is installed automatically.** A missing tool yields a BLOCKED
      check carrying the exact install command, never an attempt to fetch it.
    - **It is optional, so it is not run by a bare --execute.** Both pip-audit
      and npm audit query a remote advisory database, and Veriflow does not
      make network calls unless asked. Request it by name to run it.
    """
    checks: list[dict] = []
    limitations: list[str] = []
    detected = detection.get("detected_types", [])

    is_python = "python" in detected
    if is_python:
        res = resolve_executable("pip-audit", root, allow_global=True)
        if res["resolution_source"] != "not_found":
            checks.append({
                "name": "dependency-audit",
                "ecosystem": "python",
                "command": [res["resolved_path"], "--strict"],
                "reason": (
                    "'pip-audit' is installed. Optional: queries the PyPI advisory "
                    "database over the network, so it runs only when requested by name."
                ),
                "resolved_executable": res["resolved_path"],
                "resolution_source": res["resolution_source"],
                "optional": True,
                "requires_network": True,
                "executed": False,
                "status": STATUS_OPTIONAL,
            })
        else:
            checks.append({
                "name": "dependency-audit",
                "ecosystem": "python",
                "command": ["pip-audit", "--strict"],
                "reason": "Python project detected, but 'pip-audit' is not installed.",
                "resolved_executable": None,
                "resolution_source": "not_found",
                "optional": True,
                "requires_network": True,
                "remediation": "pip install pip-audit",
                "executed": False,
                "status": "BLOCKED",
            })
            limitations.append(
                "Dependency audit is BLOCKED for Python: 'pip-audit' is not installed. "
                "Install it with 'pip install pip-audit'. Veriflow does not install it for you. "
                "No CVE data was consulted, so dependency vulnerabilities are UNKNOWN, not absent."
            )

    # A package.json that does not parse is not a usable npm project: npm audit
    # would fail on it too, so offering the check would promise coverage that
    # cannot exist.
    has_valid_package_json = False
    package_json = root / "package.json"
    if package_json.is_file():
        try:
            json.loads(package_json.read_text(encoding="utf-8"))
            has_valid_package_json = True
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            limitations.append(
                "package.json could not be parsed, so no dependency audit was offered "
                "for JavaScript. Dependency vulnerabilities are UNKNOWN, not absent."
            )

    if has_valid_package_json:
        npm_exe = shutil.which("npm")
        if npm_exe:
            checks.append({
                "name": "dependency-audit-npm" if is_python else "dependency-audit",
                "ecosystem": "javascript",
                "command": [npm_exe, "audit"],
                "reason": (
                    "'npm' is installed and package.json exists. Optional: queries the npm "
                    "advisory database over the network, so it runs only when requested by name."
                ),
                "resolved_executable": str(npm_exe),
                "resolution_source": "system_path",
                "optional": True,
                "requires_network": True,
                "executed": False,
                "status": STATUS_OPTIONAL,
            })
        else:
            checks.append({
                "name": "dependency-audit-npm" if is_python else "dependency-audit",
                "ecosystem": "javascript",
                "command": ["npm", "audit"],
                "reason": "package.json exists, but 'npm' is not installed.",
                "resolved_executable": None,
                "resolution_source": "not_found",
                "optional": True,
                "requires_network": True,
                "remediation": "Install Node.js, which provides npm (https://nodejs.org)",
                "executed": False,
                "status": "BLOCKED",
            })
            limitations.append(
                "Dependency audit is BLOCKED for JavaScript: 'npm' is not installed. "
                "Install Node.js to get it. No CVE data was consulted, so dependency "
                "vulnerabilities are UNKNOWN, not absent."
            )

    return checks, limitations


def _discover_browser_checks(root: Path) -> tuple[list[dict], list[str]]:
    """Discover browser automation checks when test files or configs are present."""
    checks = []
    limitations = []

    has_playwright_config = (
        (root / "playwright.config.ts").is_file()
        or (root / "playwright.config.js").is_file()
    )
    has_browser_tests = False
    tests_dir = root / "tests"
    if tests_dir.is_dir():
        try:
            has_browser_tests = any(tests_dir.glob("test_browser_*.py")) or (tests_dir / "browser").is_dir()
        except OSError:
            pass

    if has_playwright_config or has_browser_tests:
        detector_fn = _load_browser_detector()
        env = detector_fn(probe_launch=False) if detector_fn else None

        if env and getattr(env, "status", None) == "AVAILABLE":
            res = resolve_executable("python", root)
            exe = res["resolved_path"] or sys.executable
            cmd = [exe, "-m", "unittest", "discover", "tests", "-p", "test_browser_*.py"]
            checks.append({
                "name": "browser",
                "ecosystem": "browser",
                "command": cmd,
                "reason": f"Discovered browser automation test suite (channel: {env.default_channel})",
                "resolved_executable": exe,
                "resolution_source": res["resolution_source"] or "system_path",
                "timeout": 120,
                "executed": False,
                "status": "proposed",
            })
        elif env:
            checks.append({
                "name": "browser",
                "ecosystem": "browser",
                "command": ["python", "-m", "unittest", "discover", "tests", "-p", "test_browser_*.py"],
                "reason": f"Discovered browser test files, but automation is blocked: {env.reason}",
                "resolved_executable": None,
                "resolution_source": "not_found",
                "executed": False,
                "status": "proposed",
            })
            limitations.append(f"Browser testing is BLOCKED: {env.reason} {env.remediation or ''}")
        else:
            limitations.append("Browser tests found, but browser detector could not be loaded.")

    return checks, limitations


def _discover_api_checks(root: Path) -> tuple[list[dict], list[str]]:
    """Discover API and integration verification checks when API test files, specs, or runners are present."""
    checks = []
    limitations = []

    has_api_spec = any(
        (root / name).is_file()
        for name in (
            "openapi.json", "openapi.yaml", "openapi.yml",
            "swagger.json", "swagger.yaml", "swagger.yml"
        )
    )

    tests_dir = root / "tests"
    has_api_tests = False
    if tests_dir.is_dir():
        try:
            has_api_tests = any(tests_dir.glob("test_api_*.py")) or (tests_dir / "api").is_dir()
        except OSError:
            pass

    api_runner = Path(__file__).parent / "run-api-tests.py"
    if not api_runner.is_file():
        api_runner = root / "skills" / "veriflow" / "scripts" / "run-api-tests.py"

    has_mapping = (root / "skills" / "veriflow" / "references" / "api-test-mapping.json").is_file()

    if has_api_spec or has_api_tests or has_mapping:
        res = resolve_executable("python", root)
        exe = res["resolved_path"] or sys.executable
        if api_runner.is_file():
            cmd = [exe, str(api_runner), "--execute"]
            checks.append({
                "name": "api",
                "ecosystem": "api",
                "command": cmd,
                "reason": "Discovered API verification engine and test suite",
                "resolved_executable": exe,
                "resolution_source": res["resolution_source"] or "system_path",
                "timeout": 60,
                "executed": False,
                "status": "proposed",
            })
        elif has_api_tests:
            cmd = [exe, "-m", "unittest", "discover", "tests", "-p", "test_api_*.py"]
            checks.append({
                "name": "api",
                "ecosystem": "api",
                "command": cmd,
                "reason": "Discovered API unit/integration tests in tests/",
                "resolved_executable": exe,
                "resolution_source": res["resolution_source"] or "system_path",
                "timeout": 60,
                "executed": False,
                "status": "proposed",
            })
        else:
            limitations.append("API specification discovered, but no API verification runner or tests were found.")

    return checks, limitations


def _has_scannable_source(root: Path, limit: int = 400) -> bool:
    """Return True when the tree holds at least one file the scanner can read.

    Walks at most ``limit`` entries and stops at the first match, so this stays
    cheap on a large repository. Vendored and generated directories are skipped
    for the same reason the scanner skips them: a finding there describes
    someone else's code.
    """
    source_suffixes = {
        ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".rb", ".php",
        ".go", ".rs", ".java", ".kt", ".cs", ".sh", ".ps1", ".sql",
        ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".tf",
        ".html", ".vue", ".svelte",
    }
    skip_dirs = {
        ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
        ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        "dist", "build", "target", "vendor", "site-packages", "coverage",
    }
    seen = 0
    stack = [root]
    while stack and seen < limit:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            seen += 1
            if seen >= limit:
                break
            try:
                if entry.is_dir():
                    if entry.name not in skip_dirs and not entry.is_symlink():
                        stack.append(entry)
                elif entry.suffix in source_suffixes or entry.name.startswith(".env"):
                    return True
            except OSError:
                continue
    return False


def _discover_security_checks(root: Path) -> tuple[list[dict], list[str]]:
    """Discover the security phase.

    Unlike the browser, API and OpenAPI phases, the static half of the security
    scan has no prerequisite at all: it reads source files and needs no running
    service, no spec and no optional package. It is therefore proposed for every
    project that contains scannable source, which makes it the one security
    check that is always available.
    """
    checks: list[dict] = []
    limitations: list[str] = []

    security_runner = Path(__file__).parent / "run-security-tests.py"
    if not security_runner.is_file():
        security_runner = root / "skills" / "veriflow" / "scripts" / "run-security-tests.py"

    if not security_runner.is_file():
        limitations.append(
            "Security verification runner (run-security-tests.py) was not found beside the "
            "skill scripts, so the security phase is unavailable."
        )
        return checks, limitations

    # Nothing to scan means nothing to propose. Offering a security scan for an
    # empty directory would report a clean result over zero files, which is the
    # kind of vacuous pass Veriflow exists to prevent.
    if not _has_scannable_source(root):
        return checks, limitations

    res = resolve_executable("python", root)
    exe = res["resolved_path"] or sys.executable

    checks.append({
        "name": "security",
        "ecosystem": "security",
        "command": [exe, str(security_runner), str(root)],
        "reason": (
            "Static security scan (read-only): secrets, injection, deserialisation, "
            "crypto, configuration, error hygiene and AI-agent supply-chain patterns"
        ),
        "resolved_executable": exe,
        "resolution_source": res["resolution_source"] or "system_path",
        "timeout": 120,
        "executed": False,
        "status": "proposed",
    })

    limitations.append(
        "Security phase covers the STATIC scan only. Live security checks (headers, "
        "cookie flags, output encoding, access control, cross-user isolation, error "
        "disclosure, redirects, CSRF) need a running service and are opt-in: "
        "run-security-tests.py --url <loopback-url> --execute."
    )

    return checks, limitations


def _discover_openapi_checks(root: Path) -> tuple[list[dict], list[str]]:
    """Discover OpenAPI contract verification checks when OpenAPI specifications, tests, or runners are present."""
    checks = []
    limitations = []

    spec_candidates = [
        root / "openapi.json",
        root / "openapi.yaml",
        root / "openapi.yml",
        root / "swagger.json",
        root / "swagger.yaml",
        root / "swagger.yml",
        root / "specs" / "openapi.json",
        root / "specs" / "openapi.yaml",
        root / "specs" / "openapi.yml",
        root / "api" / "openapi.json",
        root / "api" / "openapi.yaml",
        root / "api" / "openapi.yml",
    ]
    discovered_spec = next((p for p in spec_candidates if p.is_file()), None)

    tests_dir = root / "tests"
    has_openapi_tests = False
    if tests_dir.is_dir():
        try:
            has_openapi_tests = any(tests_dir.glob("test_openapi_*.py"))
        except OSError:
            pass

    openapi_runner = Path(__file__).parent / "run-openapi-tests.py"
    if not openapi_runner.is_file():
        openapi_runner = root / "skills" / "veriflow" / "scripts" / "run-openapi-tests.py"

    has_mapping = (root / "skills" / "veriflow" / "references" / "openapi-test-mapping.json").is_file()

    if discovered_spec or has_openapi_tests or has_mapping:
        res = resolve_executable("python", root)
        exe = res["resolved_path"] or sys.executable

        if discovered_spec and openapi_runner.is_file():
            try:
                rel_spec = discovered_spec.relative_to(root)
            except ValueError:
                rel_spec = discovered_spec
            cmd = [exe, str(openapi_runner), "--spec", str(discovered_spec), "--execute"]
            checks.append({
                "name": "openapi",
                "ecosystem": "openapi",
                "command": cmd,
                "reason": f"Discovered OpenAPI contract verification specification ({rel_spec})",
                "resolved_executable": exe,
                "resolution_source": res["resolution_source"] or "system_path",
                "timeout": 60,
                "executed": False,
                "status": "proposed",
            })
        elif has_openapi_tests:
            cmd = [exe, "-m", "unittest", "discover", "tests", "-p", "test_openapi_*.py"]
            checks.append({
                "name": "openapi",
                "ecosystem": "openapi",
                "command": cmd,
                "reason": "Discovered OpenAPI contract unit tests in tests/",
                "resolved_executable": exe,
                "resolution_source": res["resolution_source"] or "system_path",
                "timeout": 60,
                "executed": False,
                "status": "proposed",
            })
        elif discovered_spec:
            limitations.append(
                f"OpenAPI specification discovered ({discovered_spec.name}), but OpenAPI runner was not found."
            )

    return checks, limitations


MAX_OUTPUT_LENGTH = 100_000


def _load_redactor():
    """Return the shared credential redaction function, or None.

    The API, OpenAPI, browser and security engines all redact through
    api_reporter. The core runner did not, so a credential appearing in a test
    failure, a traceback, an environment dump or a verbose build log was written
    verbatim into the JSON report and the terminal. Reports get pasted into
    issues, so that was a leak path.
    """
    scripts_dir = Path(__file__).resolve().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from skills.veriflow.scripts.api_reporter import redact_api_data

        return redact_api_data
    except ImportError:
        pass
    try:
        from api_reporter import redact_api_data

        return redact_api_data
    except ImportError:
        return None


_REDACT_FN = _load_redactor()


def _redaction_available() -> bool:
    """True when captured output is redacted before it is reported."""
    return _REDACT_FN is not None


def redact_output(text: str) -> str:
    """Mask credentials in captured process output."""
    if not text or _REDACT_FN is None:
        return text
    return _REDACT_FN(text)


def _truncate_output(text: str, max_len: int = MAX_OUTPUT_LENGTH) -> str:
    """Redact credentials, then cap excessively long process output.

    Redaction runs first: truncating first could split a credential across the
    boundary so neither half matches a pattern, leaving the leading fragment in
    the report.
    """
    text = redact_output(text)
    if text and len(text) > max_len:
        omitted = len(text) - max_len
        return text[:max_len] + f"\n... [output truncated: {omitted} characters omitted] ..."
    return text


TS_PATTERN_1 = re.compile(
    r"^((?:[a-zA-Z]:[\\/])?[a-zA-Z0-9_\-./\\ ]+\.[a-zA-Z0-9]+)\((\d+),(\d+)\):\s*error\s+(TS\d+):\s*(.+)$",
    re.MULTILINE,
)
TS_PATTERN_2 = re.compile(
    r"^((?:[a-zA-Z]:[\\/])?[a-zA-Z0-9_\-./\\ ]+\.[a-zA-Z0-9]+):(\d+):(\d+)\s*(?:-\s*)?error\s+(TS\d+):\s*(.+)$",
    re.MULTILINE,
)

ESLINT_COMPACT_1 = re.compile(
    r"^((?:[a-zA-Z]:[\\/])?[a-zA-Z0-9_\-./\\ ]+\.[a-zA-Z0-9]+):\s*line\s*(\d+),\s*col\s*(\d+),\s*(?:Error|Warning)\s*-\s*(.+?)(?:\s*\(([^)]+)\))?$",
    re.MULTILINE | re.IGNORECASE,
)
ESLINT_COMPACT_2 = re.compile(
    r"^((?:[a-zA-Z]:[\\/])?[a-zA-Z0-9_\-./\\ ]+\.[a-zA-Z0-9]+):(\d+):(\d+):\s*(?:(?:error|warning)\s+)?(.+?)(?:\s*\[([a-zA-Z0-9\-_/]+)\]|\s*\(([a-zA-Z0-9\-_/]+)\))?$",
    re.MULTILINE,
)

RUFF_PATTERN = re.compile(
    r"^((?:[a-zA-Z]:[\\/])?[a-zA-Z0-9_\-./\\ ]+\.py):(\d+):(\d+):\s+([A-Z]\d+)\s+(.+)$",
    re.MULTILINE,
)

MYPY_PATTERN = re.compile(
    r"^((?:[a-zA-Z]:[\\/])?[a-zA-Z0-9_\-./\\ ]+\.py):(\d+):\s*error:\s*(.+?)(?:\s*\[([a-zA-Z0-9\-_]+)\])?$",
    re.MULTILINE,
)

PYTEST_FAILED_LINE = re.compile(
    r"^FAILED\s+([^:]+)::([^\s]+)\s+-\s+(?:([A-Za-z_][A-Za-z0-9_]*Error|[A-Za-z_][A-Za-z0-9_]*Exception):\s*)?(.+)$",
    re.MULTILINE,
)

PY_FRAME_RE = re.compile(r'File\s+"([^"]+)",\s*line\s*(\d+)(?:,\s*in\s*(\w+))?')
PY_EXC_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception))(?::\s*(.*))?$", re.MULTILINE)

RUST_PATTERN = re.compile(
    r"^error(?:\[(E\d+)\])?:\s*(.+)\n\s*-->\s+((?:[a-zA-Z]:[\\/])?[^:]+):(\d+):(\d+)",
    re.MULTILINE,
)

GO_PATTERN = re.compile(
    r"^((?:[a-zA-Z]:[\\/])?[a-zA-Z0-9_\-./\\ ]+\.go):(\d+):(\d+):\s*(.+)$",
    re.MULTILINE,
)

NODE_MODULE_PATTERN = re.compile(r"Error:\s*Cannot find module ['\"]([^'\"]+)['\"]")
PY_MODULE_PATTERN = re.compile(r"ModuleNotFoundError:\s*No module named ['\"]([^'\"]+)['\"]")


def diagnose_failure(
    check: dict,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
    status: str = "FAIL",
) -> list[dict]:
    """
    Extract structured diagnostic information from command failure outputs.

    Never invents causes when output is insufficient. Distinguishes parsed
    evidence from explanations. Returns UNCLASSIFIED if no known pattern matches.
    """
    check_info = check if isinstance(check, dict) else {}
    diagnostics = []

    if status == "TIMEOUT":
        evidence_text = (stderr or stdout).strip()[:500]
        return [{
            "category": "TIMEOUT",
            "summary": check_info.get("error_message") or "Command execution timed out",
            "file": None,
            "line": None,
            "column": None,
            "rule": None,
            "evidence": evidence_text or "Process exceeded execution timeout",
        }]

    if status == "COMMAND_NOT_FOUND":
        cmd = check_info.get("command", [])
        raw_exe = cmd[0] if cmd else "unknown"
        evidence_text = (stderr or stdout).strip()[:500]
        return [{
            "category": "COMMAND_NOT_FOUND",
            "summary": check_info.get("error_message") or f"Executable not found: '{raw_exe}'",
            "file": None,
            "line": None,
            "column": None,
            "rule": None,
            "evidence": evidence_text or check_info.get("error_message") or f"Executable '{raw_exe}' could not be resolved on PATH or project environment",
        }]

    if status == "ERROR":
        err_msg = check_info.get("error_message") or "Execution error"
        evidence_text = (stderr or stdout).strip()[:500] or err_msg
        return [{
            "category": "BUILD_ERROR",
            "summary": err_msg,
            "file": None,
            "line": None,
            "column": None,
            "rule": None,
            "evidence": evidence_text,
        }]

    combined = f"{stdout}\n{stderr}"

    # 1. TypeScript diagnostics
    for m in TS_PATTERN_1.finditer(combined):
        diagnostics.append({
            "category": "TYPE_ERROR",
            "summary": f"{m.group(4)}: {m.group(5).strip()}",
            "file": m.group(1).strip(),
            "line": int(m.group(2)),
            "column": int(m.group(3)),
            "rule": m.group(4),
            "evidence": m.group(0).strip(),
        })

    for m in TS_PATTERN_2.finditer(combined):
        diagnostics.append({
            "category": "TYPE_ERROR",
            "summary": f"{m.group(4)}: {m.group(5).strip()}",
            "file": m.group(1).strip(),
            "line": int(m.group(2)),
            "column": int(m.group(3)),
            "rule": m.group(4),
            "evidence": m.group(0).strip(),
        })

    # 2. ESLint compact diagnostics
    for m in ESLINT_COMPACT_1.finditer(combined):
        rule = m.group(5)
        msg = m.group(4).strip()
        summary = f"{msg} ({rule})" if rule else msg
        diagnostics.append({
            "category": "LINT_VIOLATION",
            "summary": summary,
            "file": m.group(1).strip(),
            "line": int(m.group(2)),
            "column": int(m.group(3)),
            "rule": rule,
            "evidence": m.group(0).strip(),
        })

    for m in ESLINT_COMPACT_2.finditer(combined):
        rule = m.group(4) or m.group(5)
        msg = m.group(3).strip()
        summary = f"{msg} ({rule})" if rule else msg
        diagnostics.append({
            "category": "LINT_VIOLATION",
            "summary": summary,
            "file": m.group(1).strip(),
            "line": int(m.group(2)),
            "column": int(m.group(3)),
            "rule": rule,
            "evidence": m.group(0).strip(),
        })

    # 3. ESLint stylish diagnostics
    stylish_pattern = re.compile(
        r"^\s*(\d+):(\d+)\s+(error|warning)\s+(.*?)(?:\s{2,}([a-zA-Z0-9\-_/]+))?$",
        re.IGNORECASE,
    )
    file_candidate_exts = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro")
    curr_file = None
    for line in combined.splitlines():
        stripped = line.strip()
        if stripped and any(stripped.endswith(ext) for ext in file_candidate_exts) and not line.startswith(" "):
            curr_file = stripped
            continue
        sm = stylish_pattern.match(line)
        if sm and curr_file:
            rule = sm.group(5)
            msg = sm.group(4).strip()
            summary = f"{msg} ({rule})" if rule else msg
            diagnostics.append({
                "category": "LINT_VIOLATION",
                "summary": summary,
                "file": curr_file,
                "line": int(sm.group(1)),
                "column": int(sm.group(2)),
                "rule": rule,
                "evidence": line.strip(),
            })

    # 4. Ruff diagnostics
    for m in RUFF_PATTERN.finditer(combined):
        diagnostics.append({
            "category": "LINT_VIOLATION",
            "summary": f"{m.group(4)}: {m.group(5).strip()}",
            "file": m.group(1).strip(),
            "line": int(m.group(2)),
            "column": int(m.group(3)),
            "rule": m.group(4),
            "evidence": m.group(0).strip(),
        })

    # 5. Mypy diagnostics
    for m in MYPY_PATTERN.finditer(combined):
        rule = m.group(3)
        msg = m.group(2).strip()
        summary = f"{msg} [{rule}]" if rule else msg
        diagnostics.append({
            "category": "TYPE_ERROR",
            "summary": summary,
            "file": m.group(1).strip(),
            "line": int(m.group(2)),
            "column": None,
            "rule": rule,
            "evidence": m.group(0).strip(),
        })

    # 6. Pytest failure summary lines
    pytest_matched_files = set()
    for m in PYTEST_FAILED_LINE.finditer(combined):
        test_file = m.group(1).strip()
        test_name = m.group(2).strip()
        exc_name = m.group(3)
        detail = m.group(4).strip()
        is_assert = (exc_name == "AssertionError") or ("assert" in detail.lower())
        cat = "TEST_ASSERTION_FAILURE" if is_assert else "PYTHON_TRACEBACK"
        summary = (
            f"Assertion failure in {test_name}: {detail}"
            if is_assert
            else f"Test failure in {test_name}: {detail}"
        )
        pytest_matched_files.add(test_file)

        line_num = None
        escaped_file = re.escape(test_file)
        loc_match = re.search(rf"^{escaped_file}:(\d+):", combined, re.MULTILINE)
        if loc_match:
            line_num = int(loc_match.group(1))

        diagnostics.append({
            "category": cat,
            "summary": summary,
            "file": test_file,
            "line": line_num,
            "column": None,
            "rule": None,
            "evidence": m.group(0).strip(),
        })

    # 7. Python Tracebacks
    if "Traceback (most recent call last):" in combined:
        tb_blocks = combined.split("Traceback (most recent call last):")[1:]
        for block in tb_blocks:
            frames = list(PY_FRAME_RE.finditer(block))
            last_frame = frames[-1] if frames else None
            exc_match = PY_EXC_RE.search(block)

            f_path = last_frame.group(1).strip() if last_frame else None
            f_line = int(last_frame.group(2)) if last_frame else None

            exc_class = exc_match.group(1) if exc_match else "Exception"
            exc_msg = exc_match.group(2).strip() if exc_match and exc_match.group(2) else ""

            if exc_class == "AssertionError":
                cat = "TEST_ASSERTION_FAILURE"
            elif exc_class == "SyntaxError":
                cat = "SYNTAX_ERROR"
            elif exc_class in ("ModuleNotFoundError", "ImportError"):
                cat = "IMPORT_OR_MODULE_ERROR"
            else:
                cat = "PYTHON_TRACEBACK"

            summary = f"{exc_class}: {exc_msg}" if exc_msg else exc_class
            evidence_lines = []
            if last_frame:
                evidence_lines.append(f'File "{f_path}", line {f_line}')
            if exc_match:
                evidence_lines.append(exc_match.group(0).strip())
            evidence = "\n".join(evidence_lines) if evidence_lines else block.strip()[:300]

            if not (f_path in pytest_matched_files and cat == "TEST_ASSERTION_FAILURE"):
                diagnostics.append({
                    "category": cat,
                    "summary": summary,
                    "file": f_path,
                    "line": f_line,
                    "column": None,
                    "rule": None,
                    "evidence": evidence,
                })

    # 8. Python SyntaxError (direct without traceback)
    if not any(d["category"] == "SYNTAX_ERROR" for d in diagnostics):
        syn_match = re.search(r'File\s+"([^"]+)",\s*line\s*(\d+).*?\n(?:.*?SyntaxError:\s*(.+))', combined, re.DOTALL)
        if syn_match:
            diagnostics.append({
                "category": "SYNTAX_ERROR",
                "summary": f"SyntaxError: {syn_match.group(3).strip()}",
                "file": syn_match.group(1).strip(),
                "line": int(syn_match.group(2)),
                "column": None,
                "rule": None,
                "evidence": syn_match.group(0).strip()[:300],
            })

    # 9. Node / Python Module Not Found
    for m in NODE_MODULE_PATTERN.finditer(combined):
        mod_name = m.group(1).strip()
        diagnostics.append({
            "category": "IMPORT_OR_MODULE_ERROR",
            "summary": f"Cannot find module '{mod_name}'",
            "file": None,
            "line": None,
            "column": None,
            "rule": None,
            "evidence": m.group(0).strip(),
        })

    for m in PY_MODULE_PATTERN.finditer(combined):
        mod_name = m.group(1).strip()
        diagnostics.append({
            "category": "IMPORT_OR_MODULE_ERROR",
            "summary": f"No module named '{mod_name}'",
            "file": None,
            "line": None,
            "column": None,
            "rule": None,
            "evidence": m.group(0).strip(),
        })

    # 10. Rust compiler errors
    for m in RUST_PATTERN.finditer(combined):
        code = m.group(1)
        msg = m.group(2).strip()
        f_path = m.group(3).strip()
        f_line = int(m.group(4))
        f_col = int(m.group(5))
        diagnostics.append({
            "category": "BUILD_ERROR",
            "summary": f"{msg} ({code})" if code else msg,
            "file": f_path,
            "line": f_line,
            "column": f_col,
            "rule": code,
            "evidence": m.group(0).strip(),
        })

    # 11. Go build errors
    for m in GO_PATTERN.finditer(combined):
        diagnostics.append({
            "category": "BUILD_ERROR",
            "summary": m.group(4).strip(),
            "file": m.group(1).strip(),
            "line": int(m.group(2)),
            "column": int(m.group(3)),
            "rule": None,
            "evidence": m.group(0).strip(),
        })

    # Deduplicate diagnostics preserving order
    deduped = []
    seen = set()
    for d in diagnostics:
        key = (d["category"], d.get("file"), d.get("line"), d.get("summary"))
        if key not in seen:
            seen.add(key)
            deduped.append(d)

    # 12. Fallback: Unclassified failure if non-zero exit and no specific diagnostic
    if not deduped and status != "PASS":
        non_empty_stderr = [l.strip() for l in stderr.splitlines() if l.strip()]
        non_empty_stdout = [l.strip() for l in stdout.splitlines() if l.strip()]

        if non_empty_stderr:
            first_err = non_empty_stderr[0][:120]
            summary = (
                f"Process failed with exit code {exit_code}: {first_err}"
                if exit_code is not None
                else first_err
            )
            evidence = "\n".join(non_empty_stderr[:5])[:300]
        elif non_empty_stdout:
            first_out = non_empty_stdout[0][:120]
            summary = (
                f"Process failed with exit code {exit_code}: {first_out}"
                if exit_code is not None
                else first_out
            )
            evidence = "\n".join(non_empty_stdout[:5])[:300]
        else:
            summary = (
                f"Process failed with exit code {exit_code} (no error output recorded)"
                if exit_code is not None
                else "Process failed with no error output"
            )
            evidence = ""

        deduped.append({
            "category": "UNCLASSIFIED",
            "summary": summary,
            "file": None,
            "line": None,
            "column": None,
            "rule": None,
            "evidence": evidence,
        })

    return deduped


def execute_check(check: dict, cwd: Path | str, timeout: int = 30) -> dict:
    """
    Safely execute a single check command using subprocess without shell=True.

    Outcomes:
      PASS: Process exited with code 0.
      FAIL: Process exited with non-zero code.
      TIMEOUT: Process exceeded the timeout limit.
      COMMAND_NOT_FOUND: Executable was not found on PATH or filesystem.
      ERROR: Operating system or execution error.
    """
    cwd_path = Path(cwd).resolve()
    result = dict(check)
    result["executed"] = True
    result["stdout"] = ""
    result["stderr"] = ""
    result["exit_code"] = None
    result["duration_seconds"] = 0.0
    result["error_message"] = None
    result["diagnostics"] = []

    cmd = check.get("command", [])
    if not cmd or not isinstance(cmd, list):
        result["status"] = "ERROR"
        result["error_message"] = "Invalid command format (expected non-empty list of arguments)"
        result["diagnostics"] = diagnose_failure(result, status="ERROR")
        return result

    raw_exe = cmd[0]

    # Resolve executable using the multi-tier policy
    if check.get("resolution_source") == "not_found" or ("resolved_executable" in check and check["resolved_executable"] is None):
        res = resolve_executable(raw_exe, cwd_path)
        if not res["resolved_path"]:
            result["status"] = "COMMAND_NOT_FOUND"
            result["resolved_executable"] = None
            result["resolution_source"] = "not_found"
            result["error_message"] = f"Executable not found on system PATH or project environment: '{raw_exe}'"
            result["diagnostics"] = diagnose_failure(result, status="COMMAND_NOT_FOUND")
            return result
        resolved_exe = res["resolved_path"]
        result["resolved_executable"] = resolved_exe
        result["resolution_source"] = res["resolution_source"]
    elif check.get("resolved_executable") and Path(check["resolved_executable"]).is_file():
        resolved_exe = check["resolved_executable"]
        result["resolved_executable"] = resolved_exe
        result["resolution_source"] = check.get("resolution_source", "unknown")
    else:
        res = resolve_executable(raw_exe, cwd_path)
        if not res["resolved_path"]:
            result["status"] = "COMMAND_NOT_FOUND"
            result["resolved_executable"] = None
            result["resolution_source"] = "not_found"
            result["error_message"] = f"Executable not found on system PATH or project environment: '{raw_exe}'"
            result["diagnostics"] = diagnose_failure(result, status="COMMAND_NOT_FOUND")
            return result
        resolved_exe = res["resolved_path"]
        result["resolved_executable"] = resolved_exe
        result["resolution_source"] = res["resolution_source"]

    exec_cmd = [resolved_exe] + [str(arg) for arg in cmd[1:]]
    start_time = time.perf_counter()

    try:
        proc = subprocess.run(
            exec_cmd,
            cwd=str(cwd_path),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        duration = time.perf_counter() - start_time
        result["duration_seconds"] = round(duration, 3)
        raw_stdout = proc.stdout or ""
        raw_stderr = proc.stderr or ""
        result["stdout"] = _truncate_output(raw_stdout)
        result["stderr"] = _truncate_output(raw_stderr)
        result["exit_code"] = proc.returncode

        if proc.returncode == 0:
            result["status"] = "PASS"
            result["diagnostics"] = []
        else:
            result["status"] = "FAIL"
            result["error_message"] = f"Process exited with non-zero return code {proc.returncode}"
            result["diagnostics"] = diagnose_failure(
                result,
                stdout=result["stdout"],
                stderr=result["stderr"],
                exit_code=proc.returncode,
                status="FAIL",
            )

    except subprocess.TimeoutExpired as exc:
        duration = time.perf_counter() - start_time
        result["duration_seconds"] = round(duration, 3)
        result["status"] = "TIMEOUT"
        stdout_val = exc.stdout or ""
        stderr_val = exc.stderr or ""
        stdout_str = stdout_val if isinstance(stdout_val, str) else stdout_val.decode("utf-8", errors="replace")
        stderr_str = stderr_val if isinstance(stderr_val, str) else stderr_val.decode("utf-8", errors="replace")
        result["stdout"] = _truncate_output(stdout_str)
        result["stderr"] = _truncate_output(stderr_str)
        result["error_message"] = f"Command timed out after {timeout} seconds"
        result["diagnostics"] = diagnose_failure(
            result,
            stdout=result["stdout"],
            stderr=result["stderr"],
            exit_code=None,
            status="TIMEOUT",
        )

    except FileNotFoundError as exc:
        duration = time.perf_counter() - start_time
        result["duration_seconds"] = round(duration, 3)
        result["status"] = "COMMAND_NOT_FOUND"
        result["error_message"] = f"Executable not found: {exc}"
        result["diagnostics"] = diagnose_failure(result, status="COMMAND_NOT_FOUND")

    except PermissionError as exc:
        duration = time.perf_counter() - start_time
        result["duration_seconds"] = round(duration, 3)
        result["status"] = "ERROR"
        result["error_message"] = f"Permission denied executing '{raw_exe}': {exc}"
        result["diagnostics"] = diagnose_failure(result, status="ERROR")

    except OSError as exc:
        duration = time.perf_counter() - start_time
        result["duration_seconds"] = round(duration, 3)
        result["status"] = "ERROR"
        result["error_message"] = f"Operating system error executing '{raw_exe}': {exc}"
        result["diagnostics"] = diagnose_failure(result, status="ERROR")

    except Exception as exc:
        duration = time.perf_counter() - start_time
        result["duration_seconds"] = round(duration, 3)
        result["status"] = "ERROR"
        result["error_message"] = f"Unexpected execution error: {exc}"
        result["diagnostics"] = diagnose_failure(result, status="ERROR")

    return result


def discover_checks(
    root: Path | str,
    execute: bool = False,
    timeout: int = 30,
    check_name: str | None = None,
    changed: bool = False,
    changed_base: str | None = None,
) -> dict:
    """
    Discover validation checks for a project.

    If execute=False (default), returns preview of proposed checks without executing them.
    If execute=True, executes each discovered check safely and captures outcomes.
    If check_name is provided, filters to only that exact check name.
    If changed=True, narrows the test check to files changed according to git,
    falling back to a full run (with the reason recorded) when git cannot answer.
    """
    root_path = Path(root).resolve()

    if not root_path.is_dir():
        raise FileNotFoundError(f"Project directory does not exist: {root_path}")

    if _detect_project_fn:
        detection = _detect_project_fn(root_path)
    else:
        detection = {
            "project_root": str(root_path),
            "detected_types": [],
            "package_manager": "unknown",
            "available_scripts": {},
        }

    detected_types = list(detection.get("detected_types", []))
    package_manager = detection.get("package_manager", "unknown")

    all_checks = []
    all_limitations = []

    # Check for python presence either through detected_types or python test/config files
    is_python = (
        "python" in detected_types
        or (root_path / "pytest.ini").is_file()
        or (root_path / "ruff.toml").is_file()
        or (root_path / ".ruff.toml").is_file()
        or (root_path / "mypy.ini").is_file()
        or (root_path / ".mypy.ini").is_file()
        or (
            (root_path / "tests").is_dir()
            and any((root_path / "tests").glob("*.py"))
        )
    )

    if is_python:
        if "python" not in detected_types:
            detected_types.append("python")
        py_checks, py_limits = _discover_python_checks(root_path)
        all_checks.extend(py_checks)
        all_limitations.extend(py_limits)

    if (
        "javascript" in detected_types
        or "typescript" in detected_types
        or (root_path / "package.json").is_file()
    ):
        js_checks, js_limits = _discover_javascript_checks(root_path, detection)
        all_checks.extend(js_checks)
        all_limitations.extend(js_limits)

    if "rust" in detected_types or (root_path / "Cargo.toml").is_file():
        if "rust" not in detected_types:
            detected_types.append("rust")
        rust_checks, rust_limits = _discover_rust_checks(root_path)
        all_checks.extend(rust_checks)
        all_limitations.extend(rust_limits)

    if "go" in detected_types or (root_path / "go.mod").is_file():
        if "go" not in detected_types:
            detected_types.append("go")
        go_checks, go_limits = _discover_go_checks(root_path)
        all_checks.extend(go_checks)
        all_limitations.extend(go_limits)

    if "dotnet" in detected_types:
        dotnet_checks, dotnet_limits = _discover_dotnet_checks(root_path, detection)
        all_checks.extend(dotnet_checks)
        all_limitations.extend(dotnet_limits)

    browser_checks, browser_limits = _discover_browser_checks(root_path)
    all_checks.extend(browser_checks)
    all_limitations.extend(browser_limits)

    api_checks, api_limits = _discover_api_checks(root_path)
    all_checks.extend(api_checks)
    all_limitations.extend(api_limits)

    openapi_checks, openapi_limits = _discover_openapi_checks(root_path)
    all_checks.extend(openapi_checks)
    all_limitations.extend(openapi_limits)

    security_checks, security_limits = _discover_security_checks(root_path)
    all_checks.extend(security_checks)
    all_limitations.extend(security_limits)

    audit_checks, audit_limits = _discover_dependency_audit_checks(root_path, detection)
    all_checks.extend(audit_checks)
    all_limitations.extend(audit_limits)

    if not all_checks and not detected_types:
        all_limitations.append("No recognizable project configuration or checks found for the directory.")

    change_info: dict | None = None
    if changed:
        if _changed_files_mod is None:
            change_info = {
                "narrowed": False,
                "fallback_reason": "the changed-files helper could not be loaded",
                "changed_files": [],
                "file_count": 0,
                "base": changed_base,
                "related_tests": [],
            }
            all_limitations.append(
                "--changed was requested but the helper could not be loaded; "
                "ran the full set of checks instead."
            )
        else:
            change_set = _changed_files_mod.resolve_changed_files(root_path, changed_base)
            related = (
                _changed_files_mod.related_test_files(root_path, change_set.files)
                if change_set.narrowed
                else []
            )
            change_info = change_set.to_dict()
            change_info["related_tests"] = related

            if not change_set.narrowed:
                all_limitations.append(
                    f"--changed could not narrow the run ({change_set.fallback_reason}); "
                    "ran the full set of checks instead."
                )
            elif not change_set.files:
                all_limitations.append(
                    "--changed found no modified source files. Checks were left at full "
                    "scope rather than reporting a pass over nothing."
                )
            else:
                # Narrow only the test check, and only when related tests were
                # actually found. Appending nothing would run the entire suite
                # while the report claimed a narrowed scope.
                if related:
                    for check in all_checks:
                        if check["name"] == "test" and check["ecosystem"] == "python":
                            check["command"] = [*check["command"], *related]
                            check["reason"] = (
                                f"{check['reason']} [--changed: limited to "
                                f"{len(related)} related test file(s)]"
                            )
                            check["changed_scope"] = list(related)
                    all_limitations.append(
                        f"--changed limited the test run to {len(related)} test file(s) "
                        f"related to {len(change_set.files)} changed source file(s). "
                        "Tests that do not follow the test_<module> naming convention were "
                        "not selected, so this is a narrowed run, not full verification."
                    )
                else:
                    all_limitations.append(
                        f"--changed found {len(change_set.files)} changed file(s) but no "
                        "test files matching the test_<module> naming convention. The test "
                        "check was left at full scope."
                    )

    if check_name is not None:
        target_name = check_name.strip() if isinstance(check_name, str) else check_name
        available_names = sorted(list({c["name"] for c in all_checks}))
        matching_checks = [c for c in all_checks if c["name"] == target_name]
        if not matching_checks:
            if available_names:
                avail_str = ", ".join(available_names)
                raise ValueError(
                    f"Check '{target_name}' not found. Available checks: {avail_str}."
                )
            else:
                raise ValueError(
                    f"Check '{target_name}' not found. No checks were discovered for this project."
                )
        all_checks = matching_checks

    if execute:
        # An explicit --check NAME is a request to run that check, including an
        # optional one. Without it, optional checks stay offered but unrun:
        # several reach the network, and none were asked for by the project.
        explicitly_requested = check_name is not None
        executed_checks = []
        for check in all_checks:
            if check.get("status") == "BLOCKED":
                # Cannot run and must never read as a pass. Left exactly as
                # discovered, with its remediation intact.
                executed_checks.append(check)
                continue
            if check.get("optional") and not explicitly_requested:
                skipped = dict(check)
                skipped["status"] = "NOT_RUN"
                skipped["skip_reason"] = (
                    "optional check, not requested; rerun with "
                    f"--check {check['name']} to execute it"
                )
                executed_checks.append(skipped)
                continue
            check_timeout = check.get("timeout", timeout)
            executed_check = execute_check(check, root_path, timeout=check_timeout)
            executed_checks.append(executed_check)

        summary = {
            "total": len(executed_checks),
            "passed": sum(1 for c in executed_checks if c["status"] == "PASS"),
            "failed": sum(1 for c in executed_checks if c["status"] == "FAIL"),
            "timed_out": sum(1 for c in executed_checks if c["status"] == "TIMEOUT"),
            "command_not_found": sum(1 for c in executed_checks if c["status"] == "COMMAND_NOT_FOUND"),
            "error": sum(1 for c in executed_checks if c["status"] == "ERROR"),
            "blocked": sum(1 for c in executed_checks if c["status"] == "BLOCKED"),
            "not_run": sum(1 for c in executed_checks if c["status"] == "NOT_RUN"),
        }

        return {
            "project_root": str(root_path),
            "detected_types": detected_types,
            "package_manager": package_manager,
            "python_package_manager": detection.get("python_package_manager", "unknown"),
            "discovered_checks": executed_checks,
            "limitations": all_limitations,
            "changed_scope": change_info,
            "executed": True,
            "summary": summary,
            "note": "Execution completed. Check results reflect actual process execution outcomes.",
        }
    else:
        for c in all_checks:
            c.setdefault("diagnostics", [])

        summary = {
            "total": len(all_checks),
            "proposed": len(all_checks),
            "passed": 0,
            "failed": 0,
            "timed_out": 0,
            "command_not_found": 0,
            "error": 0,
            "blocked": sum(1 for c in all_checks if c.get("status") == "BLOCKED"),
            "optional": sum(1 for c in all_checks if c.get("optional")),
        }

        return {
            "project_root": str(root_path),
            "detected_types": detected_types,
            "package_manager": package_manager,
            "python_package_manager": detection.get("python_package_manager", "unknown"),
            "discovered_checks": all_checks,
            "limitations": all_limitations,
            "changed_scope": change_info,
            "executed": False,
            "summary": summary,
            "note": "Discovery only. Proposed commands have not been executed. Discovery does not guarantee dependencies are installed or checks will pass.",
        }


def run_checks(
    root: Path | str,
    timeout: int = 30,
    check_name: str | None = None,
) -> dict:
    """Convenience function to discover and execute checks on a project."""
    return discover_checks(root, execute=True, timeout=timeout, check_name=check_name)


def _format_skipped_section(data: dict) -> list[str]:
    """Render the 'Suppressed / skipped' block.

    Always rendered. An absent section reads as "nothing was hidden" whether or
    not that is true, so the block states explicitly when it has nothing to
    report rather than disappearing.
    """
    lines = ["Suppressed / skipped:"]
    anything = False
    checks = data.get("discovered_checks", [])

    blocked = [c for c in checks if c.get("status") == "BLOCKED"]
    if blocked:
        anything = True
        for check in blocked:
            remediation = check.get("remediation") or "no remediation recorded"
            lines.append(f"  - [BLOCKED] {check['name']} ({check['ecosystem']}): {remediation}")

    not_run = [c for c in checks if c.get("status") == "NOT_RUN"]
    if not_run:
        anything = True
        for check in not_run:
            reason = check.get("skip_reason") or "not run"
            lines.append(f"  - [NOT_RUN] {check['name']} ({check['ecosystem']}): {reason}")

    if not data.get("executed"):
        optional = [
            c for c in checks if c.get("optional") and c.get("status") != "BLOCKED"
        ]
        if optional:
            anything = True
            for check in optional:
                label = check.get("config_source") or "optional"
                lines.append(
                    f"  - [OPTIONAL] {check['name']} ({check['ecosystem']}): offered using "
                    f"{label}; run it with --check {check['name']}"
                )

    missing = [c for c in checks if c.get("resolution_source") == "not_found"
               and c.get("status") not in ("BLOCKED", "NOT_RUN")]
    if missing:
        anything = True
        for check in missing:
            lines.append(
                f"  - [TOOL MISSING] {check['name']} ({check['ecosystem']}): "
                f"{' '.join(str(p) for p in check['command'])} could not be resolved"
            )

    scope = data.get("changed_scope")
    if scope:
        anything = True
        if scope.get("narrowed"):
            lines.append(
                f"  - [SCOPE] --changed limited this run to {scope.get('file_count', 0)} "
                f"changed file(s) and {len(scope.get('related_tests') or [])} related test "
                "file(s). Unrelated code was not verified."
            )
        else:
            lines.append(
                f"  - [SCOPE] --changed could not narrow the run "
                f"({scope.get('fallback_reason')}); everything was run instead."
            )

    if not anything:
        lines.append("  Nothing was skipped, blocked or left unrun.")
    return lines


def format_summary(data: dict) -> str:
    """Format discovery or execution results as a human-readable summary."""
    is_executed = data.get("executed", False)
    header_title = (
        "Veriflow -- Verification Check Execution Report"
        if is_executed
        else "Veriflow -- Check Discovery Preview"
    )

    lines = [
        "=" * 60,
        header_title,
        "=" * 60,
        f"Project Root:        {data['project_root']}",
        f"Detected Ecosystems: {', '.join(data['detected_types']) if data['detected_types'] else 'none'}",
        f"Package Manager:     {data['package_manager']}",
        "",
    ]

    checks = data.get("discovered_checks", [])

    if not is_executed:
        lines.append(f"Discovered Checks ({len(checks)} proposed):")
        if not checks:
            lines.append("  (No validation checks discovered)")
        else:
            for check in checks:
                cmd_display = " ".join(check["command"])
                lines.append(f"  * [{check['name']}] ({check['ecosystem']})")
                lines.append(f"    Command:    {cmd_display}")
                lines.append(f"    Argv:       {json.dumps(check['command'])}")
                lines.append(f"    Executable: {check.get('resolved_executable') or 'Not resolved'} (source: {check.get('resolution_source', 'unknown')})")
                lines.append(f"    Reason:     {check['reason']}")
                lines.append(f"    Status:     {check['status']} (executed: False)")
                lines.append("")
    else:
        lines.append(f"Execution Results ({len(checks)} checks executed):")
        if not checks:
            lines.append("  (No validation checks found to execute)")
        else:
            for check in checks:
                cmd_display = " ".join(check["command"])
                status = check.get("status", "UNKNOWN")
                duration = check.get("duration_seconds", 0.0)
                lines.append(f"  [{status}] {check['name']} ({check['ecosystem']}) ({duration}s)")
                lines.append(f"    Command:    {cmd_display}")
                lines.append(f"    Executable: {check.get('resolved_executable') or 'Not resolved'} (source: {check.get('resolution_source', 'unknown')})")
                lines.append(f"    Reason:     {check.get('reason', '')}")
                if check.get("exit_code") is not None:
                    lines.append(f"    Exit Code:  {check['exit_code']}")
                if check.get("error_message"):
                    lines.append(f"    Error:      {check['error_message']}")

                if status in ("FAIL", "ERROR", "TIMEOUT", "COMMAND_NOT_FOUND"):
                    diagnostics = check.get("diagnostics", [])
                    if diagnostics:
                        lines.append(f"    Diagnostics ({len(diagnostics)}):")
                        for diag in diagnostics[:5]:
                            loc = ""
                            if diag.get("file"):
                                loc = f" in {diag['file']}"
                                if diag.get("line"):
                                    loc += f":{diag['line']}"
                                    if diag.get("column"):
                                        loc += f":{diag['column']}"
                            rule_str = f" [{diag['rule']}]" if diag.get("rule") else ""
                            lines.append(f"      * [{diag['category']}]{rule_str}{loc} - {diag['summary']}")
                        if len(diagnostics) > 5:
                            lines.append(f"      * ... and {len(diagnostics) - 5} more diagnostic(s)")
                    else:
                        snippet = (check.get("stderr") or check.get("stdout") or "").strip()
                        if snippet:
                            snippet_lines = snippet.splitlines()[:5]
                            lines.append("    Output Snippet:")
                            for sline in snippet_lines:
                                lines.append(f"      {sline}")
                lines.append("")

        summary = data.get("summary", {})
        lines.append("Summary:")
        lines.append(
            f"  Total: {summary.get('total', 0)} | "
            f"Passed: {summary.get('passed', 0)} | "
            f"Failed: {summary.get('failed', 0)} | "
            f"Timed Out: {summary.get('timed_out', 0)} | "
            f"Missing Commands: {summary.get('command_not_found', 0)} | "
            f"Errors: {summary.get('error', 0)}"
        )
        # Blocked and not-run counts belong on the headline, not only in the
        # skipped section: a reader scanning "Passed: 0 | Failed: 2" out of a
        # total of 3 would otherwise have to work out where the third went.
        lines.append(
            f"  Blocked: {summary.get('blocked', 0)} | "
            f"Not Run: {summary.get('not_run', 0)}"
        )
        lines.append("")

    lines.extend(_format_skipped_section(data))
    lines.append("")

    if data.get("limitations"):
        lines.append("Limitations:")
        for lim in data["limitations"]:
            lines.append(f"  - {lim}")
        lines.append("")

    lines.append("Safety Notice:")
    lines.append(f"  {data['note']}")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: run-checks.py [PROJECT_DIRECTORY] [--json] [--execute] [--timeout SECONDS] [--check NAME] [--changed [BASE]]")
        print("")
        print("Discovers and optionally executes validation commands from project configuration.")
        print("")
        print("Arguments:")
        print("  PROJECT_DIRECTORY  Path to the target project (defaults to current directory)")
        print("  --execute          Opt-in to execute discovered checks (default is discovery preview)")
        print("  --timeout SECONDS  Timeout in seconds for each command execution (default: 30)")
        print("  --check NAME       Filter to preview or execute only the specified check name")
        print("  --changed [BASE]   Limit tests to files changed according to git. With BASE,")
        print("                     compares against that revision; without it, uses staged,")
        print("                     unstaged and untracked changes. Falls back to a full run,")
        print("                     with the reason stated, when git cannot answer.")
        print("  --json             Output results as formatted JSON")
        print("  -h, --help         Show this help message and exit")
        sys.exit(0)

    as_json = "--json" in sys.argv
    do_execute = "--execute" in sys.argv
    use_changed = False
    changed_base = None

    timeout = 30
    check_filter = None
    filtered_args = []
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--json", "--execute"):
            i += 1
            continue
        if arg == "--timeout":
            if i + 1 < len(sys.argv):
                try:
                    timeout = int(sys.argv[i + 1])
                except ValueError:
                    pass
                i += 2
                continue
            else:
                i += 1
                continue
        if arg.startswith("--timeout="):
            try:
                timeout = int(arg.split("=", 1)[1])
            except ValueError:
                pass
            i += 1
            continue
        if arg == "--check":
            if i + 1 < len(sys.argv):
                check_filter = sys.argv[i + 1]
                i += 2
                continue
            else:
                print("Error: --check requires a check name argument", file=sys.stderr)
                sys.exit(1)
        if arg.startswith("--check="):
            check_filter = arg.split("=", 1)[1]
            i += 1
            continue
        if arg == "--changed":
            use_changed = True
            # BASE is optional, so only consume the next argument when it is
            # not another flag and not the project directory. A bare --changed
            # at the end of the line is valid.
            if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("-"):
                candidate = sys.argv[i + 1]
                if not Path(candidate).is_dir():
                    changed_base = candidate
                    i += 2
                    continue
            i += 1
            continue
        if arg.startswith("--changed="):
            use_changed = True
            changed_base = arg.split("=", 1)[1] or None
            i += 1
            continue
        filtered_args.append(arg)
        i += 1

    target_dir = Path(filtered_args[0]).resolve() if filtered_args else Path.cwd()

    if not target_dir.is_dir():
        print(f"Error: project directory does not exist: {target_dir}", file=sys.stderr)
        sys.exit(1)

    try:
        result = discover_checks(
            target_dir,
            execute=do_execute,
            timeout=timeout,
            check_name=check_filter,
            changed=use_changed,
            changed_base=changed_base,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error discovering or executing checks: {exc}", file=sys.stderr)
        sys.exit(1)

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print(format_summary(result))

    if do_execute:
        summary = result.get("summary", {})
        has_failure = (
            summary.get("failed", 0) > 0
            or summary.get("timed_out", 0) > 0
            or summary.get("command_not_found", 0) > 0
            or summary.get("error", 0) > 0
        )
        if has_failure:
            sys.exit(1)


if __name__ == "__main__":
    main()