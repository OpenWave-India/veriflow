# Veriflow

**Verify AI-generated code with evidence, not assumptions.**

Veriflow is a verification skill for Claude Code that helps AI coding agents check their work before declaring it complete. It discovers project checks, executes them through controlled workflows, scans for common security defects, diagnoses failures, and reports what passed, failed, or could not be verified.

Instead of trusting an agent's claim that everything works, Veriflow helps you see the evidence.

## Quick Start

### Option 1: Install through the Claude Code plugin marketplace

Run these commands inside a Claude Code session:

```text
/plugin marketplace add OpenWave-India/veriflow
/plugin install veriflow@veriflow
```

Restart Claude Code if necessary, then check that Veriflow is available.

### Option 2: Install manually

Clone the repository and run the installer:

```bash
git clone https://github.com/OpenWave-India/veriflow.git
cd veriflow
```

Install for all your projects:

```bash
python install.py
```

Or install only for the current project:

```bash
python install.py --project
```

Restart Claude Code afterwards. You can then ask Claude Code to list its available skills and confirm that Veriflow is loaded.

**Update:** Pull the latest repository changes and rerun the installer for your chosen installation scope.

**Uninstall:** Run `python install.py --uninstall` using the same installation scope, after checking the installer's behavior for your version.

For plugin installations, manage updates through Claude Code's `/plugin` interface.

## Why Veriflow?

AI coding agents can produce working code, but they can also overlook broken tests, introduce unsafe patterns, recommend nonexistent dependencies, or claim success when a required tool is unavailable.

Veriflow provides a structured way to verify those claims using actual checks and explicit result states.

### Key Features

- **Project-aware check discovery:** Detects common test, lint, type-check, and build workflows across Python, JavaScript/TypeScript, Rust, Go, Java, and .NET.
- **Static security scanning:** Includes 26 static rules targeting patterns such as exposed secrets, injection, unsafe deserialization, and weak cryptography.
- **Opt-in live security checks:** Includes nine checks for areas such as security headers, cookies, authentication, IDOR, and CSRF.
- **Dependency identity checks:** Checks package identities against the relevant registries to help flag suspicious or potentially hallucinated dependencies.
- **Evidence-based diagnostics:** Uses observed failures to help explain what went wrong instead of guessing.
- **Structured result states:** Distinguishes `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN`, `NOT_APPLICABLE`, `MANUAL_REVIEW`, and `UNKNOWN`.
- **Bounded repair attempts:** Implements a persisted three-attempt limit per issue.
- **Credential redaction:** Redacts detected secrets from supported captured output before including it in reports.
- **Machine-readable reporting:** Supports JSON output, with Markdown reports available for the full audit workflow.
- **Production-readiness guidance:** Includes a 145-case catalog and a reference covering recurring AI coding failure patterns.

Feature availability depends on the engine, project, and installed optional tools.

## See It in Action

Veriflow includes a repair demo that illustrates how its audit workflow responds to clean code and deliberately introduced security defects.

Run the demo audit:

```bash
python skills/veriflow/scripts/run-audit.py examples/repair-demo --execute
```

A clean demo run can produce a result similar to:

```text
STATIC SECURITY SCAN
Findings: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0

CORE CHECKS
[PASS] test (python)

VERDICT: READY_WITH_RISKS
```

When the demo contains deliberately introduced vulnerabilities, the scanner can report findings such as:

```text
[CRITICAL] SEC-INJ-001    app.py:4
           Shell injection via shell=True

[CRITICAL] SEC-DESER-001  app.py:7
           Unsafe pickle.loads

VERDICT: NOT_READY
```

Exact output depends on the demo state and the checks available in your environment. These snippets illustrate the expected behavior rather than guaranteeing identical output on every run.

For the full audit workflow, use `--markdown report.md` to write a Markdown report.

## Verification Engines

| Engine | Purpose |
|---|---|
| Full audit | Combines available verification stages into an overall readiness verdict |
| Core runner | Discovers and runs relevant tests, linting, type checks, and builds |
| Security scanner | Applies static security rules and supported opt-in live checks |
| API verification | Checks API behavior, including authentication and error handling |
| OpenAPI verification | Checks API contracts against OpenAPI specifications |
| Browser verification | Runs supported browser journeys using Playwright |
| Dependency verification | Helps identify questionable or nonexistent package dependencies |
| Repair budget | Tracks and enforces a configured limit on repair attempts |

### Execution and Safety

Veriflow distinguishes discovery from execution so you can inspect the checks before running them.

- The core runner supports previewing discovered checks before execution.
- The static security scanner is designed to run offline and read project files without modifying them.
- Live security and API checks are intended for local services.
- Browser verification requires Playwright.
- YAML OpenAPI specifications require PyYAML; JSON specifications can be used without it.
- Missing optional tools should be reported as blocked or otherwise explicitly unavailable, rather than treated as successful verification.

Always review commands and live-check targets before executing them on an unfamiliar project.

## Requirements

- Python 3.9 or later.
- Claude Code for the skill integration.
- Optional packages for specific capabilities.

| Package | Used for | Without it |
|---|---|---|
| `playwright` | Browser journeys | Browser checks may report `BLOCKED` |
| `PyYAML` | YAML OpenAPI specifications | JSON specifications remain available |

The core runner and static security scanner are designed around the Python standard library. Individual verification engines may have additional requirements depending on the workflow.

## Running Veriflow Directly

You can invoke the scripts from the repository root without going through the Claude Code skill.

### Discover project checks

```bash
python skills/veriflow/scripts/detect-project.py .
```

### Preview discovered checks

```bash
python skills/veriflow/scripts/run-checks.py .
```

### Execute discovered checks

```bash
python skills/veriflow/scripts/run-checks.py . --execute
```

### Run the security scanner

```bash
python skills/veriflow/scripts/run-security-tests.py .
```

Use `--json` where supported to obtain machine-readable output. Consult each script's help output for the available options.

## Running the Tests

Install the development dependencies:

```bash
pip install -r requirements-dev.txt
```

Run the test suite:

```bash
python -m pytest tests -q
```

The project has reported more than 450 tests, including fault-injection tests for security rules. Run the suite against your current checkout to confirm its actual test count and results.

## Limitations

Veriflow helps improve verification; it does not guarantee that software is defect-free.

- **Pattern-based security scanning:** Static rules are not equivalent to full taint analysis or a professional penetration test.
- **No bundled CVE database:** Use dedicated tools such as `pip-audit`, `npm audit`, or `cargo audit` for vulnerability database checks.
- **Uneven diagnostic depth:** Diagnostics are strongest for Python and JavaScript/TypeScript; other ecosystems may have less detailed support.
- **Optional tooling:** Browser and YAML-based checks depend on their respective packages.
- **Catalog scope:** The production-readiness catalog summarizes its full set of cases; it is not necessarily filtered to the current project's technology or requirements.

Treat reports as evidence about the checks actually performed, not proof that every possible defect has been ruled out.

## Future Directions

Potential future work includes:

- **Codex support:** Generate compatible skill files at installation time without maintaining duplicate committed skill copies.
- **Bundled vulnerability data:** Add an optional or bundled CVE feed.
- **Deeper security analysis:** Complement pattern-based scanning with more advanced analysis techniques.

These are future directions, not claims about currently implemented functionality.

## Contributing

Contributions, bug reports, and reproducible failure cases can help improve Veriflow.

When reporting an issue, include the relevant command, expected behavior, actual result, and any sanitized logs or minimal reproduction steps. Never include API keys, passwords, or other secrets.

## License

Veriflow is released under the [MIT License](https://github.com/OpenWave-India/veriflow/blob/main/LICENSE).

