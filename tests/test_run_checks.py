from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

# Load run-checks.py dynamically since the filename contains a hyphen
SCRIPT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "veriflow"
    / "scripts"
    / "run-checks.py"
).resolve()

spec = importlib.util.spec_from_file_location("run_checks_module", SCRIPT_PATH)
run_checks_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_checks_module)
discover_checks = run_checks_module.discover_checks
execute_check = run_checks_module.execute_check
run_checks = run_checks_module.run_checks
resolve_executable = run_checks_module.resolve_executable
diagnose_failure = run_checks_module.diagnose_failure


class TestRunChecksDiscovery(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_1_python_with_pytest_config(self):
        pyproject = self.root / "pyproject.toml"
        pyproject.write_text(
            "[project]\nname = 'sample'\n\n[tool.pytest.ini_options]\nminversion = '6.0'\n\n[tool.ruff]\nline-length = 88\n\n[tool.mypy]\nstrict = true\n",
            encoding="utf-8",
        )
        res = discover_checks(self.root)
        self.assertIn("python", res["detected_types"])
        check_names = {c["name"] for c in res["discovered_checks"]}
        self.assertIn("test", check_names)
        self.assertIn("lint", check_names)
        self.assertIn("typecheck", check_names)

        test_check = next(c for c in res["discovered_checks"] if c["name"] == "test")
        # No project venv here, so pytest runs under the interpreter running
        # Veriflow -- never a bare "pytest", which would resolve to whatever
        # launcher PATH happens to find first.
        self.assertEqual(test_check["command"], [sys.executable, "-m", "pytest"])
        self.assertEqual(test_check["ecosystem"], "python")
        self.assertFalse(test_check["executed"])
        self.assertEqual(test_check["status"], "proposed")

    def test_2_python_without_recognizable_tests(self):
        (self.root / "setup.py").write_text("# setup script\n", encoding="utf-8")
        (self.root / "app.py").write_text("print('hello')\n", encoding="utf-8")

        res = discover_checks(self.root)
        self.assertIn("python", res["detected_types"])
        check_names = {c["name"] for c in res["discovered_checks"]}
        self.assertNotIn("test", check_names)
        self.assertTrue(
            any("No pytest configuration or test files discovered" in lim for lim in res["limitations"])
        )

    def test_3_javascript_multiple_package_scripts(self):
        package_json = self.root / "package.json"
        package_json.write_text(
            json.dumps({
                "scripts": {
                    "test": "jest",
                    "lint": "eslint .",
                    "typecheck": "tsc --noEmit",
                    "check": "biome check .",
                    "build": "vite build",
                }
            }),
            encoding="utf-8",
        )
        res = discover_checks(self.root)
        check_names = [c["name"] for c in res["discovered_checks"]]
        self.assertIn("test", check_names)
        self.assertIn("lint", check_names)
        self.assertIn("typecheck", check_names)
        self.assertIn("check", check_names)
        self.assertIn("build", check_names)

    def test_4_package_manager_detection(self):
        # Case A: pnpm with lockfile
        (self.root / "package.json").write_text(
            json.dumps({"scripts": {"test": "vitest", "lint": "eslint ."}}),
            encoding="utf-8",
        )
        (self.root / "pnpm-lock.yaml").write_text("", encoding="utf-8")
        res_pnpm = discover_checks(self.root)
        self.assertEqual(res_pnpm["package_manager"], "pnpm")
        test_check = next(c for c in res_pnpm["discovered_checks"] if c["name"] == "test")
        lint_check = next(c for c in res_pnpm["discovered_checks"] if c["name"] == "lint")
        self.assertEqual(test_check["command"], ["pnpm", "test"])
        self.assertEqual(lint_check["command"], ["pnpm", "run", "lint"])

        # Case B: yarn declared in packageManager field without lockfile
        sub = self.root / "yarn_sub"
        sub.mkdir()
        (sub / "package.json").write_text(
            json.dumps({
                "packageManager": "yarn@4.1.0",
                "scripts": {"test": "jest"},
            }),
            encoding="utf-8",
        )
        res_yarn = discover_checks(sub)
        self.assertEqual(res_yarn["package_manager"], "yarn")
        sub_test = next(c for c in res_yarn["discovered_checks"] if c["name"] == "test")
        self.assertEqual(sub_test["command"], ["yarn", "test"])

    def test_5_malformed_package_json(self):
        (self.root / "package.json").write_text("{invalid json: broken", encoding="utf-8")
        # Must not raise an exception
        res = discover_checks(self.root)
        self.assertIsInstance(res, dict)
        # Intent: a malformed package.json yields no JavaScript checks and does
        # not raise. Asserted by ecosystem rather than by total count, so an
        # unrelated phase (such as the read-only security scan, which a .json
        # file makes applicable) does not break the assertion.
        js_checks = [c for c in res["discovered_checks"] if c["ecosystem"] in ("javascript", "typescript")]
        self.assertEqual(js_checks, [])
        self.assertTrue(
            any("No 'test' script found" in lim for lim in res["limitations"])
        )

    def test_6_missing_target_directory(self):
        nonexistent = self.root / "nonexistent_dir"
        with self.assertRaises(FileNotFoundError):
            discover_checks(nonexistent)

        # Also verify CLI exit code 1
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(nonexistent)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Error: project directory does not exist", proc.stderr)

    def test_7_empty_or_unsupported_project(self):
        res = discover_checks(self.root)
        self.assertEqual(res["discovered_checks"], [])
        self.assertFalse(res["executed"])
        self.assertTrue(
            any("No recognizable project configuration" in lim for lim in res["limitations"])
        )

    def test_8_discovery_does_not_execute_project_scripts(self):
        canary = self.root / "canary.txt"
        dangerous_script = f"python -c \"import pathlib; pathlib.Path(r'{canary}').touch()\""

        (self.root / "package.json").write_text(
            json.dumps({"scripts": {"test": dangerous_script}}),
            encoding="utf-8",
        )

        res = discover_checks(self.root)
        self.assertFalse(canary.exists(), "Discovery function must never execute scripts!")
        self.assertFalse(res["executed"])
        self.assertEqual(res["discovered_checks"][0]["executed"], False)
        self.assertEqual(res["discovered_checks"][0]["status"], "proposed")

        # Also test CLI execution preview
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(canary.exists(), "CLI discovery run must never execute scripts!")

    def test_9_commands_are_argument_lists(self):
        # Create a multi-language fixture
        (self.root / "package.json").write_text(
            json.dumps({"scripts": {"test": "npm test", "lint": "eslint ."}}),
            encoding="utf-8",
        )
        (self.root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text("[package]\nname = 'test'\n", encoding="utf-8")

        res = discover_checks(self.root)
        self.assertGreaterEqual(len(res["discovered_checks"]), 3)
        for check in res["discovered_checks"]:
            cmd = check["command"]
            self.assertIsInstance(cmd, list, f"Command for {check['name']} must be a list")
            self.assertGreater(len(cmd), 0, f"Command list for {check['name']} must not be empty")
            for arg in cmd:
                self.assertIsInstance(arg, str, f"Command argument {arg} must be a string")

    def test_10_paths_containing_spaces(self):
        spaced_dir = self.root / "my target project with spaces"
        spaced_dir.mkdir()
        (spaced_dir / "pyproject.toml").write_text(
            "[tool.pytest.ini_options]\nminversion = '6.0'\n",
            encoding="utf-8",
        )

        res = discover_checks(spaced_dir)
        self.assertEqual(res["project_root"], str(spaced_dir.resolve()))
        self.assertEqual(
            res["discovered_checks"][0]["command"], [sys.executable, "-m", "pytest"]
        )

        # CLI subprocess with space in argument
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(spaced_dir), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["project_root"], str(spaced_dir.resolve()))
        self.assertEqual(
            parsed["discovered_checks"][0]["command"], [sys.executable, "-m", "pytest"]
        )

    def test_11_cli_help_and_exit_behavior(self):
        # --help flag
        proc_help = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_help.returncode, 0)
        self.assertIn("Usage: run-checks.py", proc_help.stdout)

        # -h flag
        proc_h = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "-h"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_h.returncode, 0)
        self.assertIn("Usage: run-checks.py", proc_h.stdout)

        # Valid project human-readable output
        proc_summary = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_summary.returncode, 0)
        self.assertIn("Veriflow -- Check Discovery Preview", proc_summary.stdout)


class TestRunChecksExecution(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_execute_check_pass(self):
        check = {
            "name": "test",
            "ecosystem": "python",
            "command": [sys.executable, "-c", "import sys; sys.stdout.write('test-passed'); sys.exit(0)"],
            "reason": "Test runner simulation",
            "executed": False,
            "status": "proposed",
        }
        res = execute_check(check, self.root)
        self.assertTrue(res["executed"])
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["exit_code"], 0)
        self.assertEqual(res["stdout"], "test-passed")
        self.assertEqual(res["stderr"], "")
        self.assertGreaterEqual(res["duration_seconds"], 0.0)
        self.assertIsNone(res["error_message"])

    def test_execute_check_fail(self):
        check = {
            "name": "lint",
            "ecosystem": "python",
            "command": [sys.executable, "-c", "import sys; sys.stderr.write('syntax error on line 1'); sys.exit(2)"],
            "reason": "Linter simulation",
            "executed": False,
            "status": "proposed",
        }
        res = execute_check(check, self.root)
        self.assertTrue(res["executed"])
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["exit_code"], 2)
        self.assertEqual(res["stderr"], "syntax error on line 1")
        self.assertIn("non-zero return code 2", res["error_message"])

    def test_execute_check_timeout(self):
        check = {
            "name": "long_task",
            "ecosystem": "python",
            "command": [sys.executable, "-c", "import time; time.sleep(10)"],
            "reason": "Timeout simulation",
            "executed": False,
            "status": "proposed",
        }
        res = execute_check(check, self.root, timeout=0.2)
        self.assertTrue(res["executed"])
        self.assertEqual(res["status"], "TIMEOUT")
        self.assertIsNone(res["exit_code"])
        self.assertIn("timed out after 0.2 seconds", res["error_message"])

    def test_execute_check_command_not_found(self):
        check = {
            "name": "missing_tool",
            "ecosystem": "custom",
            "command": ["nonexistent_binary_tool_xyz_987654", "--check"],
            "reason": "Missing binary simulation",
            "executed": False,
            "status": "proposed",
        }
        res = execute_check(check, self.root)
        self.assertTrue(res["executed"])
        self.assertEqual(res["status"], "COMMAND_NOT_FOUND")
        self.assertIsNone(res["exit_code"])
        self.assertIn("Executable not found", res["error_message"])

    def test_execute_check_invalid_command_error(self):
        check = {
            "name": "invalid",
            "ecosystem": "custom",
            "command": [],
            "reason": "Invalid command list",
            "executed": False,
            "status": "proposed",
        }
        res = execute_check(check, self.root)
        self.assertTrue(res["executed"])
        self.assertEqual(res["status"], "ERROR")
        self.assertIn("Invalid command format", res["error_message"])

    def test_discover_checks_opt_in_execution_vs_preview(self):
        pyproject = self.root / "pyproject.toml"
        pyproject.write_text("[tool.pytest.ini_options]\nminversion = '6.0'\n", encoding="utf-8")

        # 1. Preview mode (execute=False, default)
        preview = discover_checks(self.root, execute=False)
        self.assertFalse(preview["executed"])
        # Intent: every proposed check stays unexecuted in preview mode. Asserted
        # across all checks instead of a fixed total, so adding a phase cannot
        # weaken the guarantee this test exists to protect.
        self.assertTrue(preview["discovered_checks"])
        for check in preview["discovered_checks"]:
            # The guarantee is that nothing RAN. Status may be "proposed",
            # "proposed_optional" (installed but unconfigured, or network-bound)
            # or "BLOCKED" (tool absent) -- none of which are executed, and none
            # of which can read as a pass.
            self.assertIn(
                check["status"],
                ("proposed", run_checks_module.STATUS_OPTIONAL, "BLOCKED"),
            )
            self.assertFalse(check["executed"])
        self.assertEqual(preview["summary"]["passed"], 0)
        self.assertEqual(preview["summary"]["total"], len(preview["discovered_checks"]))

        # 2. Opt-in execution mode (execute=True)
        executed = discover_checks(self.root, execute=True, check_name="test")
        self.assertTrue(executed["executed"])
        self.assertTrue(executed["discovered_checks"][0]["executed"])
        self.assertIn(executed["discovered_checks"][0]["status"], ("PASS", "FAIL", "COMMAND_NOT_FOUND"))
        self.assertIn("summary", executed)
        self.assertEqual(executed["summary"]["total"], 1)

    def test_cli_execute_flag_report(self):
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_sample.py").write_text("def test_ok(): assert 1 == 1\n", encoding="utf-8")

        # Scoped with --check so the expected total stays deterministic as
        # phases are added. The unscoped path is covered by test_8.
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root), "--check", "test", "--execute", "--json"],
            capture_output=True,
            text=True,
        )
        data = json.loads(proc.stdout)
        self.assertTrue(data["executed"])
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["total"], 1)
        self.assertEqual(data["discovered_checks"][0]["name"], "test")

    def test_cli_execute_flag_failing_exit_code(self):
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_bad.py").write_text("def test_fail(): assert False\n", encoding="utf-8")

        proc_exec = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root), "--execute"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_exec.returncode, 1)
        self.assertIn("Verification Check Execution Report", proc_exec.stdout)
        self.assertIn("[FAIL]", proc_exec.stdout)

        proc_preview = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_preview.returncode, 0)
        self.assertIn("Check Discovery Preview", proc_preview.stdout)
        self.assertIn("proposed (executed: False)", proc_preview.stdout)

    def test_windows_batch_launcher_execution(self):
        if sys.platform != "win32":
            self.skipTest("Windows-only batch execution test")
        bat = self.root / "harmless_tool.bat"
        bat.write_text("@echo off\necho BATCH_OK: %1\nexit /b 0\n", encoding="utf-8")

        check = {
            "name": "batch_check",
            "ecosystem": "custom",
            "command": [str(bat), "test_arg"],
            "reason": "Harmless batch test",
            "executed": False,
            "status": "proposed",
        }
        res = execute_check(check, self.root)
        self.assertTrue(res["executed"])
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("BATCH_OK: test_arg", res["stdout"])

    def test_windows_cmd_launcher_execution_failure(self):
        if sys.platform != "win32":
            self.skipTest("Windows-only cmd execution test")
        cmd_file = self.root / "failing_tool.cmd"
        cmd_file.write_text("@echo off\necho CMD_FAILURE 1>&2\nexit /b 4\n", encoding="utf-8")

        check = {
            "name": "cmd_check",
            "ecosystem": "custom",
            "command": [str(cmd_file)],
            "reason": "Harmless failing cmd test",
            "executed": False,
            "status": "proposed",
        }
        res = execute_check(check, self.root)
        self.assertTrue(res["executed"])
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["exit_code"], 4)
        self.assertIn("CMD_FAILURE", res["stderr"])

    def test_windows_cwd_relative_batch_launcher_resolution(self):
        if sys.platform != "win32":
            self.skipTest("Windows-only launcher resolution test")
        bat = self.root / "runner.bat"
        bat.write_text("@echo off\necho RUNNER_CALLED\nexit /b 0\n", encoding="utf-8")

        check = {
            "name": "local_runner",
            "ecosystem": "custom",
            "command": ["runner.bat"],
            "reason": "Local launcher test",
            "executed": False,
            "status": "proposed",
        }
        res = execute_check(check, self.root)
        self.assertTrue(res["executed"])
        self.assertEqual(res["status"], "PASS")
        self.assertIn("RUNNER_CALLED", res["stdout"])


class TestLocalToolResolution(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_1_python_venv_local_pytest(self):
        """1. Python virtual environment with local pytest."""
        (self.root / "pyproject.toml").write_text(
            "[tool.pytest.ini_options]\nminversion = '6.0'\n",
            encoding="utf-8",
        )
        venv_scripts = self.root / ".venv" / "Scripts"
        venv_scripts.mkdir(parents=True)
        py_exe = venv_scripts / ("python.exe" if sys.platform == "win32" else "python")
        py_exe.write_text("# mock python interpreter\n", encoding="utf-8")
        pytest_exe = venv_scripts / ("pytest.exe" if sys.platform == "win32" else "pytest")
        pytest_exe.write_text("# mock pytest executable\n", encoding="utf-8")

        res = discover_checks(self.root)
        test_check = next(c for c in res["discovered_checks"] if c["name"] == "test")
        self.assertEqual(test_check["resolution_source"], "project_venv")
        self.assertEqual(test_check["command"], [str(py_exe.resolve()), "-m", "pytest"])
        self.assertEqual(test_check["resolved_executable"], str(py_exe.resolve()))
        self.assertIn("project-local venv", test_check["reason"])
        self.assertFalse(test_check["executed"])

    def test_2_python_venv_missing_linter(self):
        """2. Python virtual environment with a missing linter."""
        (self.root / "pyproject.toml").write_text(
            "[tool.pytest.ini_options]\n\n[tool.ruff]\nline-length = 88\n",
            encoding="utf-8",
        )
        venv_scripts = self.root / ".venv" / "Scripts"
        venv_scripts.mkdir(parents=True)
        py_exe = venv_scripts / ("python.exe" if sys.platform == "win32" else "python")
        py_exe.write_text("# mock python\n", encoding="utf-8")
        pytest_exe = venv_scripts / ("pytest.exe" if sys.platform == "win32" else "pytest")
        pytest_exe.write_text("# mock pytest\n", encoding="utf-8")
        # Notice ruff is NOT installed in .venv

        res = discover_checks(self.root)
        lint_check = next(c for c in res["discovered_checks"] if c["name"] == "lint")
        self.assertEqual(lint_check["resolution_source"], "not_found")
        self.assertIsNone(lint_check["resolved_executable"])
        self.assertTrue(
            any("not installed in the project virtual environment" in lim for lim in res["limitations"])
        )

        exec_res = execute_check(lint_check, self.root)
        self.assertEqual(exec_res["status"], "COMMAND_NOT_FOUND")

    def test_3_javascript_local_eslint(self):
        """3. JavaScript project with local ESLint."""
        (self.root / "package.json").write_text(
            json.dumps({"scripts": {"test": "node --test"}}),
            encoding="utf-8",
        )
        (self.root / ".eslintrc.json").write_text("{}", encoding="utf-8")
        bin_dir = self.root / "node_modules" / ".bin"
        bin_dir.mkdir(parents=True)
        eslint_tool = bin_dir / ("eslint.cmd" if sys.platform == "win32" else "eslint")
        eslint_tool.write_text("# mock eslint\n", encoding="utf-8")

        res = discover_checks(self.root)
        lint_check = next(c for c in res["discovered_checks"] if c["name"] == "lint")
        self.assertEqual(lint_check["resolution_source"], "node_modules")
        self.assertEqual(lint_check["resolved_executable"], str(eslint_tool.resolve()))
        self.assertEqual(lint_check["command"], [str(eslint_tool.resolve()), "."])

    def test_4_windows_and_unix_style_paths(self):
        """4. Correct handling of Windows and Unix-style paths."""
        # Unix layout: .venv/bin/
        unix_root = self.root / "unix_proj"
        unix_bin = unix_root / ".venv" / "bin"
        unix_bin.mkdir(parents=True)
        py_unix = unix_bin / "python"
        py_unix.write_text("#!/bin/sh\n", encoding="utf-8")
        pytest_unix = unix_bin / "pytest"
        pytest_unix.write_text("#!/bin/sh\n", encoding="utf-8")
        (unix_root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")

        res_unix = discover_checks(unix_root)
        test_unix = next(c for c in res_unix["discovered_checks"] if c["name"] == "test")
        self.assertEqual(test_unix["resolution_source"], "project_venv")
        self.assertEqual(test_unix["resolved_executable"], str(py_unix.resolve()))

        # Windows layout: .venv/Scripts/
        win_root = self.root / "win_proj"
        win_scripts = win_root / ".venv" / "Scripts"
        win_scripts.mkdir(parents=True)
        py_win = win_scripts / "python.exe"
        py_win.write_text("dummy", encoding="utf-8")
        pytest_win = win_scripts / "pytest.exe"
        pytest_win.write_text("dummy", encoding="utf-8")
        (win_root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")

        res_win = discover_checks(win_root)
        test_win = next(c for c in res_win["discovered_checks"] if c["name"] == "test")
        self.assertEqual(test_win["resolution_source"], "project_venv")
        self.assertEqual(test_win["resolved_executable"], str(py_win.resolve()))

    def test_5_local_tool_preference_over_global_fallback(self):
        """5. Local tool preference over a global fallback."""
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        (self.root / ".eslintrc.json").write_text("{}", encoding="utf-8")
        bin_dir = self.root / "node_modules" / ".bin"
        bin_dir.mkdir(parents=True)
        local_eslint = bin_dir / ("eslint.cmd" if sys.platform == "win32" else "eslint")
        local_eslint.write_text("local tool", encoding="utf-8")

        fake_global = "C:\\global_tools\\eslint.cmd" if sys.platform == "win32" else "/usr/bin/eslint"
        with unittest.mock.patch("shutil.which", return_value=fake_global):
            res = discover_checks(self.root)
            lint_check = next(c for c in res["discovered_checks"] if c["name"] == "lint")
            self.assertEqual(lint_check["resolution_source"], "node_modules")
            self.assertEqual(lint_check["resolved_executable"], str(local_eslint.resolve()))
            self.assertNotEqual(lint_check["resolved_executable"], fake_global)

    def test_6_missing_local_tools_with_no_global_fallback(self):
        """6. Missing local tools with no global fallback."""
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        (self.root / ".eslintrc.json").write_text("{}", encoding="utf-8")

        with unittest.mock.patch("shutil.which", return_value=None):
            res = discover_checks(self.root)
            lint_check = next(c for c in res["discovered_checks"] if c["name"] == "lint")
            self.assertEqual(lint_check["resolution_source"], "not_found")
            self.assertIsNone(lint_check["resolved_executable"])
            self.assertTrue(
                any("not installed in node_modules/.bin or PATH" in lim for lim in res["limitations"])
            )

            exec_res = execute_check(lint_check, self.root)
            self.assertEqual(exec_res["status"], "COMMAND_NOT_FOUND")

    def test_7_package_manager_and_lockfile_consistency(self):
        """7. Package-manager and lockfile consistency."""
        managers = [
            ("pnpm-lock.yaml", "pnpm"),
            ("yarn.lock", "yarn"),
            ("bun.lockb", "bun"),
            ("package-lock.json", "npm"),
        ]
        for lockfile, expected_pm in managers:
            sub = self.root / f"proj_{expected_pm}"
            sub.mkdir()
            (sub / "package.json").write_text(
                json.dumps({"scripts": {"test": "vitest"}}),
                encoding="utf-8",
            )
            (sub / lockfile).write_text("# lockfile marker\n", encoding="utf-8")

            res = discover_checks(sub)
            self.assertEqual(res["package_manager"], expected_pm)
            test_check = next(c for c in res["discovered_checks"] if c["name"] == "test")
            self.assertEqual(test_check["command"], [expected_pm, "test"])
            self.assertTrue((sub / lockfile).is_file())

    def test_8_discovery_mode_never_executes_commands(self):
        """8. Discovery mode still never executes commands."""
        canary = self.root / "canary.txt"
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        venv_scripts = self.root / ".venv" / "Scripts"
        venv_scripts.mkdir(parents=True)
        py_exe = venv_scripts / ("python.exe" if sys.platform == "win32" else "python")
        py_exe.write_text(f"touch {canary}", encoding="utf-8")
        pytest_exe = venv_scripts / ("pytest.exe" if sys.platform == "win32" else "pytest")
        pytest_exe.write_text(f"touch {canary}", encoding="utf-8")

        res = discover_checks(self.root, execute=False)
        self.assertFalse(canary.exists(), "Discovery preview must never execute commands!")
        self.assertFalse(res["executed"])
        self.assertFalse(res["discovered_checks"][0]["executed"])
        self.assertEqual(res["discovered_checks"][0]["status"], "proposed")

    def test_9_explicit_execution_honors_timeouts_and_statuses(self):
        """9. Explicit execution still honors timeouts and result statuses."""
        pass_check = {
            "name": "pass_test",
            "ecosystem": "python",
            "command": [sys.executable, "-c", "import sys; sys.exit(0)"],
            "reason": "Passing test",
            "executed": False,
            "status": "proposed",
        }
        res_pass = execute_check(pass_check, self.root)
        self.assertEqual(res_pass["status"], "PASS")
        self.assertEqual(res_pass["exit_code"], 0)

        fail_check = {
            "name": "fail_test",
            "ecosystem": "python",
            "command": [sys.executable, "-c", "import sys; sys.stderr.write('fail err'); sys.exit(5)"],
            "reason": "Failing test",
            "executed": False,
            "status": "proposed",
        }
        res_fail = execute_check(fail_check, self.root)
        self.assertEqual(res_fail["status"], "FAIL")
        self.assertEqual(res_fail["exit_code"], 5)
        self.assertIn("fail err", res_fail["stderr"])

        timeout_check = {
            "name": "timeout_test",
            "ecosystem": "python",
            "command": [sys.executable, "-c", "import time; time.sleep(5)"],
            "reason": "Timeout test",
            "executed": False,
            "status": "proposed",
        }
        res_to = execute_check(timeout_check, self.root, timeout=0.2)
        self.assertEqual(res_to["status"], "TIMEOUT")

        missing_check = {
            "name": "missing_test",
            "ecosystem": "python",
            "command": ["totally_missing_executable_123456789"],
            "reason": "Missing tool",
            "executed": False,
            "status": "proposed",
        }
        res_missing = execute_check(missing_check, self.root)
        self.assertEqual(res_missing["status"], "COMMAND_NOT_FOUND")

    def test_10_paths_containing_spaces(self):
        """10. Paths containing spaces."""
        spaced_dir = self.root / "Project With Several Spaces"
        spaced_dir.mkdir()
        (spaced_dir / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        venv_scripts = spaced_dir / ".venv" / "Scripts"
        venv_scripts.mkdir(parents=True)
        py_exe = venv_scripts / ("python.exe" if sys.platform == "win32" else "python")
        py_exe.write_text("mock", encoding="utf-8")
        pytest_exe = venv_scripts / ("pytest.exe" if sys.platform == "win32" else "pytest")
        pytest_exe.write_text("mock", encoding="utf-8")

        res = discover_checks(spaced_dir)
        test_check = next(c for c in res["discovered_checks"] if c["name"] == "test")
        self.assertEqual(test_check["resolution_source"], "project_venv")
        self.assertEqual(test_check["command"][0], str(py_exe.resolve()))
        self.assertIn("Project With Several Spaces", test_check["command"][0])

        exec_check = {
            "name": "space_test",
            "ecosystem": "python",
            "command": [sys.executable, "-c", "print('spaces ok')"],
            "reason": "Spaced path test",
            "executed": False,
            "status": "proposed",
        }
        res_exec = execute_check(exec_check, spaced_dir)
        self.assertEqual(res_exec["status"], "PASS")
        self.assertIn("spaces ok", res_exec["stdout"])


class TestFailureDiagnosis(unittest.TestCase):
    def test_1_python_traceback_and_assertion_diagnosis(self):
        """1. Python traceback and assertion failure diagnosis."""
        # Case A: Pytest assertion failure
        pytest_stdout = """
=================================== FAILURES ===================================
___________________________________ test_add ___________________________________

    def test_add():
>       assert add(2, 3) == 10
E       assert 5 == 10

tests/test_calc.py:8: AssertionError
=========================== short test summary info ============================
FAILED tests/test_calc.py::test_add - assert 5 == 10
============================== 1 failed in 0.05s ===============================
"""
        diags_pytest = diagnose_failure(
            check={"name": "test", "ecosystem": "python"},
            stdout=pytest_stdout,
            stderr="",
            exit_code=1,
            status="FAIL",
        )
        self.assertGreaterEqual(len(diags_pytest), 1)
        diag = diags_pytest[0]
        self.assertEqual(diag["category"], "TEST_ASSERTION_FAILURE")
        self.assertEqual(diag["file"], "tests/test_calc.py")
        self.assertEqual(diag["line"], 8)
        self.assertIn("assert 5 == 10", diag["summary"])
        self.assertIn("FAILED tests/test_calc.py::test_add", diag["evidence"])

        # Case B: Python standard traceback
        tb_stderr = """
Traceback (most recent call last):
  File "app/calculator.py", line 42, in add
    return a + b
TypeError: unsupported operand type(s) for +: 'int' and 'str'
"""
        diags_tb = diagnose_failure(
            check={"name": "test", "ecosystem": "python"},
            stdout="",
            stderr=tb_stderr,
            exit_code=1,
            status="FAIL",
        )
        self.assertEqual(len(diags_tb), 1)
        tb_diag = diags_tb[0]
        self.assertEqual(tb_diag["category"], "PYTHON_TRACEBACK")
        self.assertEqual(tb_diag["file"], "app/calculator.py")
        self.assertEqual(tb_diag["line"], 42)
        self.assertEqual(tb_diag["summary"], "TypeError: unsupported operand type(s) for +: 'int' and 'str'")
        self.assertIn("calculator.py", tb_diag["evidence"])

    def test_2_eslint_diagnostic(self):
        """2. ESLint-style diagnostic."""
        eslint_stdout = """
/path/to/project/src/index.js
  12:5  error  'unused' is defined but never used  no-unused-vars
  20:10 warning 'console.log' statement found     no-console

✖ 2 problems (1 error, 1 warning)
"""
        diags = diagnose_failure(
            check={"name": "lint", "ecosystem": "javascript"},
            stdout=eslint_stdout,
            stderr="",
            exit_code=1,
            status="FAIL",
        )
        self.assertEqual(len(diags), 2)
        err_diag = diags[0]
        self.assertEqual(err_diag["category"], "LINT_VIOLATION")
        self.assertEqual(err_diag["file"], "/path/to/project/src/index.js")
        self.assertEqual(err_diag["line"], 12)
        self.assertEqual(err_diag["column"], 5)
        self.assertEqual(err_diag["rule"], "no-unused-vars")
        self.assertIn("'unused' is defined but never used", err_diag["summary"])
        self.assertIn("12:5", err_diag["evidence"])

        warn_diag = diags[1]
        self.assertEqual(warn_diag["category"], "LINT_VIOLATION")
        self.assertEqual(warn_diag["line"], 20)
        self.assertEqual(warn_diag["column"], 10)
        self.assertEqual(warn_diag["rule"], "no-console")

    def test_3_typescript_compiler_diagnostic(self):
        """3. TypeScript compiler diagnostic."""
        ts_stdout = """
src/services/api.ts(15,9): error TS2322: Type 'number' is not assignable to type 'string'.
src/services/api.ts:25:3 - error TS2304: Cannot find name 'fetchData'.
"""
        diags = diagnose_failure(
            check={"name": "typecheck", "ecosystem": "typescript"},
            stdout=ts_stdout,
            stderr="",
            exit_code=2,
            status="FAIL",
        )
        self.assertEqual(len(diags), 2)

        d1 = diags[0]
        self.assertEqual(d1["category"], "TYPE_ERROR")
        self.assertEqual(d1["file"], "src/services/api.ts")
        self.assertEqual(d1["line"], 15)
        self.assertEqual(d1["column"], 9)
        self.assertEqual(d1["rule"], "TS2322")
        self.assertIn("Type 'number' is not assignable to type 'string'", d1["summary"])

        d2 = diags[1]
        self.assertEqual(d2["category"], "TYPE_ERROR")
        self.assertEqual(d2["file"], "src/services/api.ts")
        self.assertEqual(d2["line"], 25)
        self.assertEqual(d2["column"], 3)
        self.assertEqual(d2["rule"], "TS2304")
        self.assertIn("Cannot find name 'fetchData'", d2["summary"])

    def test_4_unrecognized_error_output(self):
        """4. Unrecognized error output."""
        unrecognized_stderr = "Anomaly detected: code 0x88FE at memory offset 0x00FF"
        diags = diagnose_failure(
            check={"name": "custom_check", "ecosystem": "custom"},
            stdout="",
            stderr=unrecognized_stderr,
            exit_code=1,
            status="FAIL",
        )
        self.assertEqual(len(diags), 1)
        diag = diags[0]
        self.assertEqual(diag["category"], "UNCLASSIFIED")
        self.assertIsNone(diag["file"])
        self.assertIsNone(diag["line"])
        self.assertIsNone(diag["column"])
        self.assertIsNone(diag["rule"])
        self.assertIn("Process failed with exit code 1", diag["summary"])
        self.assertEqual(diag["evidence"], unrecognized_stderr)

    def test_5_empty_stderr_with_nonzero_exit_code(self):
        """5. Empty stderr with a nonzero exit code."""
        diags = diagnose_failure(
            check={"name": "silent_fail", "ecosystem": "custom"},
            stdout="",
            stderr="",
            exit_code=137,
            status="FAIL",
        )
        self.assertEqual(len(diags), 1)
        diag = diags[0]
        self.assertEqual(diag["category"], "UNCLASSIFIED")
        self.assertIsNone(diag["file"])
        self.assertIn("exit code 137 (no error output recorded)", diag["summary"])
        self.assertEqual(diag["evidence"], "")

    def test_6_multiple_errors_in_one_output(self):
        """6. Multiple errors in one output."""
        multi_output = """
src/models/user.ts(10,5): error TS2322: Type 'null' is not assignable to type 'string'.
src/models/user.ts(20,5): error TS2339: Property 'age' does not exist on type 'User'.
src/models/user.ts(30,12): error TS2304: Cannot find name 'Role'.
"""
        diags = diagnose_failure(
            check={"name": "typecheck", "ecosystem": "typescript"},
            stdout=multi_output,
            stderr="",
            exit_code=1,
            status="FAIL",
        )
        self.assertEqual(len(diags), 3)
        rules = [d["rule"] for d in diags]
        self.assertEqual(rules, ["TS2322", "TS2339", "TS2304"])
        lines = [d["line"] for d in diags]
        self.assertEqual(lines, [10, 20, 30])

    def test_7_truncated_output_handling(self):
        """7. Truncated output handling."""
        # Create output exceeding 100,000 characters
        huge_output = "info log line\n" * 10000 + "src/index.ts(1,1): error TS1005: ';' expected.\n"
        self.assertGreater(len(huge_output), 100_000)

        check = {
            "name": "typecheck",
            "ecosystem": "typescript",
            "command": ["tsc", "--noEmit"],
            "executed": False,
            "status": "proposed",
        }
        diags = diagnose_failure(
            check=check,
            stdout=huge_output,
            stderr="",
            exit_code=1,
            status="FAIL",
        )
        self.assertGreaterEqual(len(diags), 1)
        self.assertEqual(diags[0]["category"], "TYPE_ERROR")
        self.assertEqual(diags[0]["rule"], "TS1005")

        truncated = run_checks_module._truncate_output(huge_output)
        self.assertIn("[output truncated", truncated)
        self.assertLessEqual(len(truncated), 100_100)

    def test_8_diagnosis_never_changes_files_or_launches_commands(self):
        """8. Ensuring diagnosis never changes files or launches commands."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            canary_file = td_path / "sensitive.txt"
            canary_file.write_text("initial content", encoding="utf-8")
            sub_dir = td_path / "sub"
            sub_dir.mkdir()
            (sub_dir / "data.json").write_text('{"key": 1}', encoding="utf-8")

            files_before = {p: p.stat().st_mtime_ns for p in td_path.glob("**/*") if p.is_file()}

            # Mock subprocess to fail if called during diagnosis
            with unittest.mock.patch(
                "subprocess.run",
                side_effect=AssertionError("subprocess.run must never be called during diagnosis!"),
            ):
                diags = diagnose_failure(
                    check={"name": "test", "ecosystem": "python"},
                    stdout="FAILED test_a.py::test_1 - AssertionError: assert 1 == 2",
                    stderr="",
                    exit_code=1,
                    status="FAIL",
                )
                self.assertEqual(len(diags), 1)

            files_after = {p: p.stat().st_mtime_ns for p in td_path.glob("**/*") if p.is_file()}
            self.assertEqual(files_before, files_after)
            self.assertEqual(canary_file.read_text(encoding="utf-8"), "initial content")


class TestCheckFilter(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_1_exact_selection_of_valid_check_programmatic(self):
        """1. Exact selection of a valid check via Python API."""
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        (self.root / "ruff.toml").write_text("", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_a.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

        res_test = discover_checks(self.root, check_name="test")
        self.assertEqual(len(res_test["discovered_checks"]), 1)
        self.assertEqual(res_test["discovered_checks"][0]["name"], "test")
        self.assertEqual(res_test["summary"]["total"], 1)

        res_lint = discover_checks(self.root, check_name="lint")
        self.assertEqual(len(res_lint["discovered_checks"]), 1)
        self.assertEqual(res_lint["discovered_checks"][0]["name"], "lint")
        self.assertEqual(res_lint["summary"]["total"], 1)

    def test_2_invalid_check_names(self):
        """2. Invalid check name raises clear ValueError listing available check names."""
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        (self.root / "ruff.toml").write_text("", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_a.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            discover_checks(self.root, check_name="nonexistent")
        err_msg = str(ctx.exception)
        self.assertIn("Check 'nonexistent' not found", err_msg)
        self.assertIn("lint", err_msg)
        self.assertIn("test", err_msg)

    def test_3_clear_behavior_when_project_has_no_discovered_checks(self):
        """3. Clear behavior when the project has no discovered checks."""
        with self.assertRaises(ValueError) as ctx:
            discover_checks(self.root, check_name="test")
        err_msg = str(ctx.exception)
        self.assertIn("Check 'test' not found", err_msg)
        self.assertIn("No checks were discovered for this project", err_msg)

    def test_4_no_accidental_execution_of_unselected_checks(self):
        """4. Verify unselected checks are never executed."""
        package_json = {
            "name": "filter-test",
            "scripts": {
                "test": "node -v",
                "lint": "node -v",
            },
        }
        (self.root / "package.json").write_text(json.dumps(package_json), encoding="utf-8")

        executed_names = []
        original_execute_check = run_checks_module.execute_check

        def tracking_execute(check, root, timeout=30):
            executed_names.append(check["name"])
            return original_execute_check(check, root, timeout=timeout)

        with unittest.mock.patch.object(run_checks_module, "execute_check", side_effect=tracking_execute):
            res = discover_checks(self.root, execute=True, check_name="test")

        self.assertEqual(executed_names, ["test"])
        self.assertNotIn("lint", executed_names)
        self.assertEqual(len(res["discovered_checks"]), 1)
        self.assertEqual(res["discovered_checks"][0]["name"], "test")

    def test_5_filtering_in_preview_mode(self):
        """5. Filtering in preview mode does not execute and returns preview format."""
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_a.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root), "--check", "test"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Check Discovery Preview", proc.stdout)
        self.assertIn("* [test] (python)", proc.stdout)
        self.assertIn("proposed (executed: False)", proc.stdout)

    def test_6_filtering_with_execute(self):
        """6. Filtering with --execute only runs the selected check."""
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_a.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root), "--check", "test", "--execute"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Verification Check Execution Report", proc.stdout)
        self.assertIn("[PASS] test (python)", proc.stdout)
        self.assertIn("Total: 1 | Passed: 1", proc.stdout)

    def test_7_json_output_when_check_is_selected(self):
        """7. JSON output when a check is selected reflects only the selected check."""
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_a.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root), "--check", "test", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(len(data["discovered_checks"]), 1)
        self.assertEqual(data["discovered_checks"][0]["name"], "test")
        self.assertEqual(data["summary"]["total"], 1)

    def test_8_existing_behavior_when_check_is_omitted(self):
        """8. Existing behavior when --check is omitted includes all checks."""
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        (self.root / "ruff.toml").write_text("", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_a.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

        res = discover_checks(self.root)
        check_names = {c["name"] for c in res["discovered_checks"]}
        # Intent: omitting --check discovers every applicable check, so the
        # Python test and lint checks must both be present. Asserted as a subset
        # because the security phase is also applicable to this fixture.
        self.assertTrue({"test", "lint"}.issubset(check_names), check_names)
        self.assertEqual(res["summary"]["total"], len(res["discovered_checks"]))
        self.assertGreaterEqual(res["summary"]["total"], 2)

    def test_9_cli_invalid_check_returns_clear_error_and_exits_1(self):
        """9. CLI with invalid check name outputs clear error and exits with code 1."""
        (self.root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        tests_dir = self.root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_a.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), str(self.root), "--check", "invalid_name"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Check 'invalid_name' not found", proc.stderr)
        # Intent: the error names the checks that *are* available. The list is
        # alphabetical and grows with each phase, so assert membership.
        self.assertIn("Available checks:", proc.stderr)
        self.assertIn("test", proc.stderr)


if __name__ == "__main__":
    unittest.main()

class TestOutputRedaction(unittest.TestCase):
    """Captured process output must not carry credentials into a report.

    The core runner writes stdout and stderr into its JSON report. A test
    failure, traceback, environment dump or verbose build log can contain a
    credential, and reports get pasted into issues.
    """

    def test_redaction_is_active(self):
        self.assertTrue(
            run_checks_module._redaction_available(),
            "the shared redactor must be importable, or output is reported raw",
        )

    def test_credentials_are_masked_in_captured_output(self):
        cases = [
            ('{"api_key": "Kf8sLq2mXz9vNb4t"}', "Kf8sLq2mXz9vNb4t"),
            ("postgresql://admin:Qx7LbN4tKp8s@db:5432/app", "Qx7LbN4tKp8s"),
            ("DB_PASSWORD=Kf8sLq2mXz9vNb4t", "Kf8sLq2mXz9vNb4t"),
            ("Authorization: Bearer abc123def456ghi789", "abc123def456ghi789"),
        ]
        for text, secret in cases:
            with self.subTest(text=text):
                redacted = run_checks_module._truncate_output(text)
                self.assertNotIn(secret, redacted)
                self.assertIn("[REDACTED]", redacted)

    def test_ordinary_output_is_left_intact(self):
        """Redaction must not mangle the diagnostics it sits in front of."""
        text = '  File "app.py", line 3, in <module>\nNameError: name \'x\' is not defined'
        self.assertEqual(run_checks_module._truncate_output(text), text)

    def test_redaction_runs_before_truncation(self):
        """Truncating first could split a credential so neither half matches."""
        secret = "Kf8sLq2mXz9vNb4tRw7pZx2L"
        padding = "x" * (run_checks_module.MAX_OUTPUT_LENGTH - 12)
        text = f"{padding}api_key={secret}"
        redacted = run_checks_module._truncate_output(text)
        self.assertNotIn(secret, redacted)
        self.assertNotIn(secret[:10], redacted)


class TestPytestInterpreterResolution(unittest.TestCase):
    """pytest is always invoked as `<interpreter> -m pytest`.

    A bare `pytest` runs whichever launcher PATH resolves first, which can
    import a different site-packages than the project's. Tests then pass or
    fail for reasons unrelated to the code under test, and the report gives no
    hint that happened.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)
        (self.root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _mock_venv(self) -> Path:
        scripts = self.root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin")
        scripts.mkdir(parents=True)
        py = scripts / ("python.exe" if sys.platform == "win32" else "python")
        py.write_text("# mock interpreter\n", encoding="utf-8")
        (self.root / ".venv" / "pyvenv.cfg").write_text(
            "home = /usr\nversion = 3.11.9\n", encoding="utf-8"
        )
        return py

    def _test_check(self, result) -> dict:
        return next(c for c in result["discovered_checks"] if c["name"] == "test")

    def test_project_venv_interpreter_is_preferred(self):
        py = self._mock_venv()
        check = self._test_check(discover_checks(self.root))
        self.assertEqual(check["command"], [str(py.resolve()), "-m", "pytest"])
        self.assertEqual(check["resolution_source"], "project_venv")

    def test_falls_back_to_the_veriflow_interpreter(self):
        check = self._test_check(discover_checks(self.root))
        self.assertEqual(check["command"], [sys.executable, "-m", "pytest"])
        self.assertEqual(check["resolution_source"], "veriflow_interpreter")

    def test_command_is_never_a_bare_pytest(self):
        for use_venv in (True, False):
            with self.subTest(venv=use_venv):
                shutil.rmtree(self.root / ".venv", ignore_errors=True)
                if use_venv:
                    self._mock_venv()
                check = self._test_check(discover_checks(self.root))
                self.assertEqual(check["command"][1:], ["-m", "pytest"])
                self.assertNotEqual(check["command"], ["pytest"])

    def test_mismatched_path_pytest_emits_a_warning_naming_both(self):
        """The warning must name both interpreters, not just say 'mismatch'."""
        fake_bin = self.root / "otherpy" / ("Scripts" if sys.platform == "win32" else "bin")
        fake_bin.mkdir(parents=True)
        fake_pytest = fake_bin / ("pytest.exe" if sys.platform == "win32" else "pytest")
        fake_pytest.write_text("# mock\n", encoding="utf-8")
        fake_py = fake_bin / ("python.exe" if sys.platform == "win32" else "python")
        fake_py.write_text("# mock\n", encoding="utf-8")
        (self.root / "otherpy" / "pyvenv.cfg").write_text(
            "version = 3.8.1\n", encoding="utf-8"
        )

        with unittest.mock.patch.object(
            run_checks_module.shutil, "which", return_value=str(fake_pytest)
        ):
            result = discover_checks(self.root)

        warnings = [l for l in result["limitations"] if l.startswith("WARNING")]
        self.assertTrue(warnings, "no WARNING emitted for a mismatched PATH pytest")
        joined = " ".join(warnings)
        self.assertIn(str(fake_pytest), joined)
        self.assertIn("3.8.1", joined)
        self.assertIn(sys.executable, joined)

    def test_no_warning_when_path_pytest_matches(self):
        bin_dir = Path(sys.executable).parent
        fake_pytest = bin_dir / ("pytest.exe" if sys.platform == "win32" else "pytest")
        with unittest.mock.patch.object(
            run_checks_module.shutil, "which", return_value=str(fake_pytest)
        ):
            result = discover_checks(self.root)
        self.assertEqual([l for l in result["limitations"] if l.startswith("WARNING")], [])

    def test_missing_pytest_is_a_limitation_not_a_pass(self):
        self._mock_venv()
        result = discover_checks(self.root)
        self.assertTrue(
            any("not installed" in l and "COMMAND_NOT_FOUND" in l for l in result["limitations"]),
            f"absent pytest not disclosed: {result['limitations']}",
        )


class TestInterpreterVersionDetection(unittest.TestCase):
    """Version is read off the filesystem; discovery never executes a binary."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_reads_version_from_pyvenv_cfg(self):
        scripts = self.root / "bin"
        scripts.mkdir()
        (self.root / "pyvenv.cfg").write_text("version = 3.12.4\n", encoding="utf-8")
        self.assertEqual(
            run_checks_module._interpreter_version(scripts / "python"), "3.12.4"
        )

    def test_reads_version_from_a_system_install_layout(self):
        """python.exe sits beside pythonXY.dll in the install root, with no
        pyvenv.cfg. Searching only the parent directory reports "unknown" and
        silently weakens the mismatch warning."""
        install = self.root / "Python39"
        install.mkdir()
        (install / "python.exe").write_text("#\n", encoding="utf-8")
        (install / "python39.dll").write_text("#\n", encoding="utf-8")
        self.assertEqual(
            run_checks_module._interpreter_version(install / "python.exe"), "3.9"
        )

    def test_finds_interpreter_one_level_above_a_scripts_dir(self):
        """A system install keeps pytest.exe in Scripts/ and python.exe above it."""
        install = self.root / "Python39"
        scripts = install / "Scripts"
        scripts.mkdir(parents=True)
        (install / "python.exe").write_text("#\n", encoding="utf-8")
        pytest_exe = scripts / "pytest.exe"
        pytest_exe.write_text("#\n", encoding="utf-8")
        found = run_checks_module._interpreter_behind_script(pytest_exe)
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "python.exe")

    def test_unknown_version_is_reported_not_guessed(self):
        self.assertIsNone(
            run_checks_module._interpreter_version(self.root / "nowhere" / "python")
        )
        described = run_checks_module._describe_interpreter(self.root / "nowhere" / "python")
        self.assertIn("version unknown", described)

    def test_real_interpreter_is_describable(self):
        self.assertIn(str(Path(sys.executable)), run_checks_module._describe_interpreter(sys.executable))


class TestDefaultConfigOptionalChecks(unittest.TestCase):
    """An installed-but-unconfigured tool is offered, not silently skipped.

    Skipping it loses coverage the user already paid for by installing the
    tool. Proposing it unlabelled would be worse: a linter run under defaults
    it was never tuned for reports issues the project may have deliberately
    configured away. So it is proposed, marked optional, and labelled
    "default config".
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)
        (self.root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _fake_tool(self, name: str) -> Path:
        """Create a project venv containing `name`, so resolution finds it."""
        scripts = self.root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin")
        scripts.mkdir(parents=True, exist_ok=True)
        py = scripts / ("python.exe" if sys.platform == "win32" else "python")
        if not py.exists():
            py.write_text("# mock\n", encoding="utf-8")
        tool = scripts / (f"{name}.exe" if sys.platform == "win32" else name)
        tool.write_text("# mock\n", encoding="utf-8")
        return tool

    def _check(self, result, name):
        return next((c for c in result["discovered_checks"] if c["name"] == name), None)

    def test_installed_unconfigured_ruff_is_proposed_as_optional(self):
        self._fake_tool("ruff")
        lint = self._check(discover_checks(self.root), "lint")
        self.assertIsNotNone(lint, "installed ruff was skipped instead of proposed")
        self.assertEqual(lint["status"], run_checks_module.STATUS_OPTIONAL)
        self.assertEqual(lint["config_source"], "default config")
        self.assertTrue(lint["optional"])

    def test_installed_unconfigured_mypy_is_proposed_as_optional(self):
        self._fake_tool("mypy")
        tc = self._check(discover_checks(self.root), "typecheck")
        self.assertIsNotNone(tc, "installed mypy was skipped instead of proposed")
        self.assertEqual(tc["status"], run_checks_module.STATUS_OPTIONAL)
        self.assertEqual(tc["config_source"], "default config")

    def test_optional_status_is_distinct_from_proposed(self):
        """A caller must be able to tell a project's own check from an offer."""
        self._fake_tool("ruff")
        self.assertNotEqual(run_checks_module.STATUS_OPTIONAL, "proposed")
        lint = self._check(discover_checks(self.root), "lint")
        self.assertNotEqual(lint["status"], "proposed")

    def test_default_config_tradeoff_is_stated_in_the_reason(self):
        self._fake_tool("ruff")
        lint = self._check(discover_checks(self.root), "lint")
        self.assertIn("default config", lint["reason"])
        self.assertIn("installed", lint["reason"])

    def test_the_offer_is_disclosed_as_a_limitation(self):
        self._fake_tool("ruff")
        result = discover_checks(self.root)
        self.assertTrue(
            any("optional" in l and "ruff" in l.lower() for l in result["limitations"]),
            f"optional offer not disclosed: {result['limitations']}",
        )

    def test_not_installed_and_unconfigured_proposes_nothing(self):
        """No tool, no offer -- and the report says so rather than staying quiet."""
        with unittest.mock.patch.object(run_checks_module.shutil, "which", return_value=None):
            result = discover_checks(self.root)
        self.assertIsNone(self._check(result, "lint"))
        self.assertTrue(
            any("not installed" in l for l in result["limitations"]),
            f"missing tool not disclosed: {result['limitations']}",
        )

    def test_configured_tool_keeps_normal_proposed_status(self):
        """Feature 4 must not relabel a project's own configured checks."""
        (self.root / "ruff.toml").write_text("line-length = 100\n", encoding="utf-8")
        self._fake_tool("ruff")
        lint = self._check(discover_checks(self.root), "lint")
        self.assertEqual(lint["status"], "proposed")
        self.assertNotIn("config_source", lint)


class TestDependencyAudit(unittest.TestCase):
    """Dependency auditing is delegated, offered, and never silently absent.

    Veriflow bundles no CVE data. The failure mode to prevent is a clean report
    that implies dependencies were checked when no advisory database was ever
    consulted -- so a missing tool is BLOCKED with its install command, and the
    limitation says vulnerabilities are UNKNOWN rather than absent.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root = Path(self.test_dir)
        (self.root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        (self.root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _audit(self, result):
        return next(
            (c for c in result["discovered_checks"] if c["name"] == "dependency-audit"), None
        )

    def test_missing_pip_audit_is_blocked_with_install_command(self):
        with unittest.mock.patch.object(run_checks_module.shutil, "which", return_value=None):
            audit = self._audit(discover_checks(self.root))
        self.assertIsNotNone(audit)
        self.assertEqual(audit["status"], "BLOCKED")
        self.assertEqual(audit["remediation"], "pip install pip-audit")

    def test_blocked_audit_is_never_a_pass_even_under_execute(self):
        with unittest.mock.patch.object(run_checks_module.shutil, "which", return_value=None):
            result = discover_checks(self.root, execute=True)
        audit = self._audit(result)
        self.assertEqual(audit["status"], "BLOCKED")
        self.assertFalse(audit["executed"])
        self.assertGreaterEqual(result["summary"]["blocked"], 1)

    def test_blocked_audit_states_unknown_not_absent(self):
        with unittest.mock.patch.object(run_checks_module.shutil, "which", return_value=None):
            result = discover_checks(self.root)
        self.assertTrue(
            any("UNKNOWN, not absent" in l for l in result["limitations"]),
            f"BLOCKED audit implied absence of vulnerabilities: {result['limitations']}",
        )

    def test_nothing_is_installed_automatically(self):
        """The remediation is text for the user to run, never a command Veriflow runs."""
        with unittest.mock.patch.object(run_checks_module.shutil, "which", return_value=None):
            audit = self._audit(discover_checks(self.root))
        self.assertNotIn("install", " ".join(audit["command"]).lower())

    def test_available_pip_audit_is_optional_and_network_bound(self):
        scripts = self.root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin")
        scripts.mkdir(parents=True)
        (scripts / ("python.exe" if sys.platform == "win32" else "python")).write_text("#\n")
        (scripts / ("pip-audit.exe" if sys.platform == "win32" else "pip-audit")).write_text("#\n")
        audit = self._audit(discover_checks(self.root))
        self.assertEqual(audit["status"], run_checks_module.STATUS_OPTIONAL)
        self.assertTrue(audit["optional"])
        self.assertTrue(audit["requires_network"])

    def test_optional_audit_is_not_run_by_a_bare_execute(self):
        """It reaches the network. A plain --execute must not trigger that."""
        scripts = self.root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin")
        scripts.mkdir(parents=True)
        (scripts / ("python.exe" if sys.platform == "win32" else "python")).write_text("#\n")
        (scripts / ("pip-audit.exe" if sys.platform == "win32" else "pip-audit")).write_text("#\n")
        audit = self._audit(discover_checks(self.root, execute=True))
        self.assertEqual(audit["status"], "NOT_RUN")
        self.assertIn("--check dependency-audit", audit["skip_reason"])

    def test_malformed_package_json_offers_no_npm_audit(self):
        (self.root / "package.json").write_text("{ broken", encoding="utf-8")
        result = discover_checks(self.root)
        js = [c for c in result["discovered_checks"] if c["ecosystem"] == "javascript"]
        self.assertEqual(js, [])
        self.assertTrue(any("could not be parsed" in l for l in result["limitations"]))
