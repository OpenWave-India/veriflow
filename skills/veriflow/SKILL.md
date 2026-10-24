---
name: veriflow
description: Verify code changes by discovering the project's real checks, previewing them, executing only the relevant ones, diagnosing failures from captured evidence, applying bounded minimal repairs, and reporting honestly what passed, failed, was skipped or remains unknown. Includes static and live security scanning. Use when implementing a feature, fixing a bug, modifying existing code, reviewing a diff, investigating a failing test or build, or preparing a project for release.
---

# Veriflow

Code is not done because it was written. It is done when a check you actually
ran says so, and you can show the output.

Veriflow gives you scripts that discover a project's real checks, run them
safely, and report results in states that cannot hide a failure. Your job is to
read the evidence and make the smallest correct change.

## The three rules

1. **Never claim a check passed unless you ran it and read its output.** A
   discovered check is not a passing check. A missing tool is not a pass.
2. **Preview before executing.** Every runner previews by default and executes
   only with `--execute`. Get authorization before running anything that
   executes commands, opens sockets, or touches data.
3. **Diagnose from evidence, not from plausibility.** Separate what the output
   says from what you think it means, and say which is which.

## Scripts

All paths are relative to this skill directory. Replace `<skill>` with its
actual location (see *Locating this skill* below).

| Script | What it does | Safe by default |
| :--- | :--- | :--- |
| `scripts/detect-project.py` | Reports ecosystems, package manager, scripts | read-only |
| `scripts/run-audit.py` | **Full audit**: detection + security scan + core checks + catalog scope, as one verdict | security scan runs free; core checks need `--execute` |
| `scripts/run-checks.py` | Discovers and runs test/lint/typecheck/build checks | preview unless `--execute` |
| `scripts/run-security-tests.py` | Static security scan; opt-in live security checks | static is read-only and offline |
| `scripts/run-api-tests.py` | HTTP contract, auth, error and resilience checks | preview unless `--execute`; loopback only |
| `scripts/run-openapi-tests.py` | OpenAPI 3.0/3.1 contract verification | preview unless `--execute`; loopback only |
| `scripts/run-browser-tests.py` | Playwright user journeys | preview unless `--execute`; `BLOCKED` without Playwright |
| `scripts/check_dependencies.py` | Verifies each declared dependency exists on PyPI/npm; flags hallucinated or notably-new packages | preview unless `--execute`; only contacts `pypi.org` / `registry.npmjs.org` |
| `scripts/repair_budget.py` | Enforces the 3-attempt repair cap in code, not just in this file's prose | local file only, no network |

Everything is Python standard library. `playwright` and `PyYAML` are optional;
when absent the affected checks report `BLOCKED` with remediation, never `PASS`
and never a crash.

For a quick, shareable snapshot of a whole project -- not a specific change --
run `scripts/run-audit.py <dir> --execute --markdown report.md` instead of
invoking the engines separately. It never reports a bare "READY": the best
verdict it gives is `READY_WITH_RISKS`, because a clean run is evidence under
the conditions tested, not a guarantee.

## Reference files

Read only what the current task needs.

| File | Read it when |
| :--- | :--- |
| `references/repair-workflow.md` | a check failed and you are about to change code |
| `references/diagnostics.md` | you have an error message and need to identify its cause |
| `references/failure-patterns.json` | you want the known AI-coding failure patterns and their checks |
| `references/engines.md` | the change touches APIs, an OpenAPI spec, the browser, or security |
| `references/verification-checklist.md` | you want the full per-area review checklist |
| `references/production-readiness.md` | you are preparing a release or reviewing readiness |
| `references/production-test-catalog.json` | you need the 145-case readiness catalog |
| `references/security-test-mapping.json` | you need to know exactly what the security phase covers and does not |
| `references/report-templates.md` | you are writing the final report |

## Locating this skill

Resolve the skill directory before building any command. In order:

1. The directory containing this `SKILL.md` (that is the skill root).
2. `.claude/skills/veriflow/` under the project root.
3. `~/.claude/skills/veriflow/` (`%USERPROFILE%\.claude\skills\veriflow\` on Windows).
4. `skills/veriflow/` inside a cloned Veriflow repository.

Confirm `scripts/run-checks.py` exists at the path you resolved before using
it. If no location has it, say the skill is not fully installed and point to
the repository `README.md`. Do not guess a path and do not invent a command.

## Workflow

### 1. Inspect before changing

Read the project's own instructions (`CLAUDE.md`, `AGENTS.md`, `README.md`,
contributor guidelines) and `git status` / `git diff`. Never discard unrelated
work. Then detect the stack:

```powershell
python <skill>\scripts\detect-project.py .
```

Trust the output over your assumptions about the framework.

### 2. Select only the checks the change warrants

Do not run everything. Choose from what changed:

| Changed | Run | Skip |
| :--- | :--- | :--- |
| A pure function or module | `--check test`, lint, typecheck | browser, API, OpenAPI |
| Frontend route or component | unit tests, browser journeys, accessibility | OpenAPI, API resilience |
| Auth, session, permissions | auth and authorization tests, API, **security** | OpenAPI unless the spec changed |
| HTTP handler or status code | API checks; OpenAPI if a spec exists | browser unless the UI calls it |
| An OpenAPI/Swagger spec | OpenAPI contract verification | browser |
| A dependency or lockfile | manifest validation, a real dependency audit, build | browser, OpenAPI |
| A database migration | migration, schema, transaction and data-integrity checks | browser |
| Deployment or CI config | configuration, build and deployment-safety checks | browser, API |
| Documentation only | link and accuracy review | the application test suites |

Two things are always worth running: the test suite covering the changed code,
and the **static security scan**, which is read-only, offline and needs nothing
installed.

State which checks you selected and why, before running them.

### 3. Preview, then execute

```powershell
python <skill>\scripts\run-checks.py . --json
python <skill>\scripts\run-checks.py . --check test --execute
python <skill>\scripts\run-checks.py . --execute --timeout 120
```

To scope a run to what you just changed, add `--changed` (optionally with a
base revision). It limits the test run to changed files and the tests named
after them, and limits the security scan to changed files:

```powershell
python <skill>\scripts\run-checks.py . --changed --execute
python <skill>\scripts\run-checks.py . --changed main --execute
python <skill>\scripts\run-security-tests.py . --changed
```

`--changed` is a narrowing optimisation, not full verification. It selects
tests by the `test_<module>` naming convention, so a test that exercises a
module without naming it after that module is not picked up, and the report
says so. When git cannot answer, the run widens to everything and states why
rather than scanning nothing. Do not describe a `--changed` run as a full pass.

Two kinds of check are **offered but not run** by a bare `--execute`, and both
appear in the report's "Suppressed / skipped" section:

- **`proposed_optional`** -- either a tool that is installed but has no project
  configuration (labelled `default config`, so its findings may be ones the
  project would have configured away), or a check that reaches the network.
  Run one with `--check <name>`.
- **`BLOCKED`** -- the tool is absent. The check carries the exact install
  command. Never install it automatically; report the blockage and let the user
  decide. `dependency-audit` (pip-audit / npm audit) is BLOCKED when the tool
  is missing, which means dependency vulnerabilities are **UNKNOWN, not
  absent** -- never report a clean dependency state you did not verify.

Read the preview: the resolved executable, the resolution source
(`project_venv`, `node_modules`, `project_script`, `system_path`, `not_found`),
the reason, and the limitations. An unlisted check does not exist. A `not_found`
tool is not installed.

`--check NAME` scopes to one discovered check. Executing without `--check` runs
everything discovered, which is the broader regression pass in step 5.

For the security phase:

```powershell
python <skill>\scripts\run-security-tests.py .
python <skill>\scripts\run-security-tests.py . --json
python <skill>\scripts\run-security-tests.py . --category secrets --category injection
```

Live security checks need a running local service and are opt-in; see
`references/engines.md`.

### 4. Read the result states

Never convert a missing check into a pass.

| State | Meaning |
| :--- | :--- |
| `PASS` | Executed, exited 0, assertions held |
| `FAIL` | Executed and failed |
| `BLOCKED` | A prerequisite (tool, credential, service, dependency) is unavailable |
| `NOT_RUN` | Identified but not executed, including everything in preview mode |
| `NOT_APPLICABLE` | Does not apply to this project. Must state the reason |
| `MANUAL_REVIEW` | Needs human judgement or access you do not have |
| `UNKNOWN` | Evidence is insufficient to decide. Investigate before claiming anything |

Execution adds `TIMEOUT`, `COMMAND_NOT_FOUND` and `ERROR`; `UNCLASSIFIED`
marks output matching no known diagnostic signature.

Report skipped tests as skipped. Say how many of the project's checks you ran,
not just that "the checks passed".

Every report carries a **"Suppressed / skipped"** section. Read it and carry it
forward: it lists excluded files, inline-suppressed findings, candidate secrets
discarded as placeholders (with the reason for each), checks that were BLOCKED
or left unrun, and whether `--changed` narrowed the scope. It is printed even
when empty, so "Nothing was skipped" is a statement you can rely on rather than
an absence you have to interpret. A clean findings list above an unread skipped
section is not a clean result.

A secret finding at **LOW confidence** means the value looked like a
placeholder but carried a known provider key prefix or high entropy, so it was
reported rather than discarded. Treat it as needing a human decision, not as
noise: the alternative to a LOW finding here is a silently dropped live
credential. A dropped value is always counted and explained in the skipped
section, never removed without trace.

### 5. Repair, bounded

Read `references/repair-workflow.md` before changing code in response to a
failure. In summary:

1. Collect the exact error and the structured `diagnostics` array.
2. Separate observed facts from root-cause hypotheses; name the competing ones.
3. Make the smallest change that addresses the most likely cause.
4. Add or strengthen a regression test proving the intended behaviour.
5. Rerun the failing check with `--check <failing-check-name> --execute`.
6. Then rerun the broader suite to catch regressions.
7. Inspect the final diff for unrelated changes and weakened tests.

**Maximum 3 Repair Attempts** per issue. An attempt is counted only when you
modify project files; diagnosis costs nothing. Stop early on ambiguous evidence,
on a pre-existing failure, or when further edits would be speculative. When the
budget is exhausted, report the evidence and the next diagnostic step.

### 6. Report

Use the template in `references/report-templates.md`. State what passed, what
failed, what was blocked, what was skipped and what is still unknown.

## Prohibitions

These are not style preferences. Each one converts a real failure into a false
pass, which is the specific harm Veriflow exists to prevent.

- **Never delete or weaken tests** to get a green result: no removing cases, no
  commenting out assertions, no loosening them to match a defect.
- **Never disable linter or type-checker rules** to bypass a finding (`# noqa`,
  `eslint-disable`, `@ts-ignore`, `# type: ignore`, deleting a config rule).
- **Never suppress errors** to hide them (`except: pass`, `catch (e) {}`).
- **Never alter project configuration arbitrarily** - dependencies, lockfiles,
  manifests, CI or security policy - unless the diagnosis specifically requires
  it and you say so.
- **Never change an expected result** to match a defect without evidence that
  the original expectation was wrong.
- **Never install packages** to make an error go away. Report the missing
  dependency.
- **Never fabricate command output, test counts, coverage figures or logs.**
- **Never print a secret** into output, a report or a log.
- **Never claim** zero bugs, complete security, or guaranteed deployment. A
  passing suite means the checks you ran passed under the conditions you ran
  them in.

## Division of responsibility

The runner discovers, resolves executables, executes with argument lists
(`shell=False`), captures bounded output and parses diagnostics. It is
**preview-only by default** and contains **no automatic file modification
logic**. You analyse its output and make changes with your own editing tools,
inside the user's permissions.

## Honesty about what this covers

Veriflow reduces common, detectable failures and makes the remaining
uncertainty visible. It does not prove software correct or secure.

- The static security scanner is a pattern and configuration scanner, not a
  taint analyser. It cannot prove a matched value reaches a dangerous sink, and
  a clean scan is not evidence of absence.
- Veriflow bundles no vulnerability database. For CVE coverage, run the
  ecosystem's own audit tool and treat its output as the evidence.
- Live checks target loopback addresses by default. Reaching anything else is an
  explicit opt-in for a system the user owns and is permitted to test.
- Automated coverage differs sharply by ecosystem. Project detection is broad;
  deep check support is strongest for Python and JavaScript/TypeScript.
- `references/security-test-mapping.json` lists, per check, what it covers and
  what it explicitly does not.
