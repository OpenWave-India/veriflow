from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Load detect-project.py dynamically since the filename contains a hyphen
SCRIPT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "veriflow"
    / "scripts"
    / "detect-project.py"
).resolve()

spec = importlib.util.spec_from_file_location("detect_project_module", SCRIPT_PATH)
detect_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detect_module)
detect_project = detect_module.detect_project


class TestDetectProject(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_empty_directory(self):
        result = detect_project(self.root)
        self.assertEqual(result["project_root"], str(self.root.resolve()))
        self.assertEqual(result["detected_types"], [])
        self.assertEqual(result["package_manager"], "unknown")
        self.assertEqual(result["available_scripts"], {})

    def test_str_input_support(self):
        result = detect_project(str(self.root))
        self.assertEqual(result["project_root"], str(self.root.resolve()))

    def test_python_detection_markers(self):
        for marker in (
            "pyproject.toml",
            "setup.py",
            "requirements.txt",
            "Pipfile",
            # Regression: a Python project whose only marker is a test
            # configuration (no packaging manifest) must still be detected.
            "pytest.ini",
            "tox.ini",
            "conftest.py",
        ):
            with self.subTest(marker=marker):
                sub = self.root / f"proj_{marker}"
                sub.mkdir()
                (sub / marker).write_text("# marker", encoding="utf-8")
                res = detect_project(sub)
                self.assertIn("python", res["detected_types"])

    def test_javascript_and_package_managers(self):
        pkg_json = self.root / "package.json"
        pkg_json.write_text(
            json.dumps({"scripts": {"test": "mocha", "build": "vite build"}}),
            encoding="utf-8",
        )

        # No lockfile
        res = detect_project(self.root)
        self.assertIn("javascript", res["detected_types"])
        self.assertEqual(res["package_manager"], "unknown")
        self.assertEqual(res["available_scripts"]["test"], "mocha")

        # pnpm lockfile
        (self.root / "pnpm-lock.yaml").write_text("", encoding="utf-8")
        res_pnpm = detect_project(self.root)
        self.assertEqual(res_pnpm["package_manager"], "pnpm")

    def test_package_manager_field_fallback(self):
        pkg_json = self.root / "package.json"
        pkg_json.write_text(
            json.dumps({"packageManager": "yarn@4.1.0"}),
            encoding="utf-8",
        )
        res = detect_project(self.root)
        self.assertEqual(res["package_manager"], "yarn")

    def test_typescript_detection(self):
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        (self.root / "tsconfig.json").write_text("{}", encoding="utf-8")
        res = detect_project(self.root)
        self.assertIn("javascript", res["detected_types"])
        self.assertIn("typescript", res["detected_types"])

    def test_rust_go_java_detection(self):
        (self.root / "Cargo.toml").write_text("", encoding="utf-8")
        (self.root / "go.mod").write_text("", encoding="utf-8")
        (self.root / "pom.xml").write_text("", encoding="utf-8")
        res = detect_project(self.root)
        self.assertIn("rust", res["detected_types"])
        self.assertIn("go", res["detected_types"])
        self.assertIn("java", res["detected_types"])

    def test_dotnet_detection(self):
        nested = self.root / "src" / "Services"
        nested.mkdir(parents=True)
        (nested / "Services.csproj").write_text("", encoding="utf-8")
        res = detect_project(self.root)
        self.assertIn("dotnet", res["detected_types"])

    def test_cli_execution_with_explicit_directory(self):
        (self.root / "package.json").write_text(
            json.dumps({"scripts": {"lint": "eslint ."}}),
            encoding="utf-8",
        )
        cmd = [sys.executable, str(SCRIPT_PATH), str(self.root)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["project_root"], str(self.root.resolve()))
        self.assertIn("javascript", data["detected_types"])
        self.assertEqual(data["available_scripts"]["lint"], "eslint .")

    def test_cli_execution_nonexistent_directory(self):
        cmd = [sys.executable, str(SCRIPT_PATH), str(self.root / "does_not_exist")]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Error: project directory does not exist", proc.stderr)

    def test_cli_help_flag(self):
        cmd = [sys.executable, str(SCRIPT_PATH), "--help"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Usage: detect-project.py", proc.stdout)


class TestPythonPackageManager(unittest.TestCase):
    """Python's manager is reported in its own field.

    Deliberately NOT folded into `package_manager`: run-checks.py interpolates
    that value into npm-style commands, so "uv" landing there would produce
    `uv run test` for a JavaScript check.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_lockfiles_identify_the_manager(self):
        for marker, expected in (
            ("uv.lock", "uv"),
            ("poetry.lock", "poetry"),
            ("pdm.lock", "pdm"),
            ("Pipfile.lock", "pipenv"),
        ):
            with self.subTest(marker=marker):
                for stale in ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"):
                    (self.root / stale).unlink(missing_ok=True)
                (self.root / marker).write_text("", encoding="utf-8")
                self.assertEqual(
                    detect_project(self.root)["python_package_manager"], expected
                )

    def test_pyproject_without_a_lockfile_is_pip(self):
        (self.root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        self.assertEqual(detect_project(self.root)["python_package_manager"], "pip")

    def test_requirements_variants_are_pip(self):
        for name in ("requirements.txt", "requirements-dev.txt"):
            with self.subTest(name=name):
                for stale in self.root.glob("requirements*.txt"):
                    stale.unlink()
                (self.root / name).write_text("pytest\n", encoding="utf-8")
                self.assertEqual(
                    detect_project(self.root)["python_package_manager"], "pip"
                )

    def test_a_lockfile_outranks_pyproject(self):
        (self.root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        (self.root / "uv.lock").write_text("", encoding="utf-8")
        self.assertEqual(detect_project(self.root)["python_package_manager"], "uv")

    def test_non_python_project_reports_unknown(self):
        """"unknown" must mean "not Python", distinct from "Python, unidentified"."""
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        self.assertEqual(detect_project(self.root)["python_package_manager"], "unknown")

    def test_javascript_package_manager_field_is_untouched(self):
        """The regression this separation exists to prevent."""
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        (self.root / "yarn.lock").write_text("", encoding="utf-8")
        (self.root / "uv.lock").write_text("", encoding="utf-8")
        result = detect_project(self.root)
        self.assertEqual(result["package_manager"], "yarn")
        self.assertEqual(result["python_package_manager"], "uv")


if __name__ == "__main__":
    unittest.main()