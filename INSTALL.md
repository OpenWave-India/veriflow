# Installing Veriflow

## Claude Code — paste two lines, done

```text
/plugin marketplace add OpenWave-India/veriflow
/plugin install veriflow@veriflow
```

No cloning, no script. The repo's `.claude-plugin/marketplace.json` tells
Claude Code exactly where the skill lives, so installing is a plugin
operation, not a file copy.

From a shell instead of inside a session:

```powershell
claude plugin marketplace add OpenWave-India/veriflow
claude plugin install veriflow@veriflow
```

**Updating:** `/plugin` → **Installed** → `veriflow` → **Update now**, or
`claude plugin update veriflow@veriflow` from a shell. Turn on auto-update
from the **Marketplaces** tab in `/plugin` if you'd rather it stay current
on its own — it's off by default for non-Anthropic marketplaces.

Everyone else — skip ahead to whichever applies:

---

## Codex, or a manual Claude Code install

For everything below, Veriflow is a plain installable skill for **Claude
Code** and **Codex**.
Both agents use the same open Agent Skills shape — a directory with a
`SKILL.md` describing when to use it — but each scans a different folder:

| Scope | Claude Code scans | Codex scans | Applies to |
| :--- | :--- | :--- | :--- |
| **Project** | `<project>/.claude/skills/veriflow/SKILL.md` | `<project>/.agents/skills/veriflow/SKILL.md` | that one repository |
| **Personal** | `~/.claude/skills/veriflow/SKILL.md` | `~/.agents/skills/veriflow/SKILL.md` | every project you open |

On Windows, `~` is `%USERPROFILE%`, so the personal paths are
`C:\Users\<you>\.claude\skills\veriflow\SKILL.md` and
`C:\Users\<you>\.agents\skills\veriflow\SKILL.md`.

Veriflow's source lives at `skills/veriflow/`, which neither agent scans
directly. Installing means copying that one directory into whichever path(s)
above you ask for — the content is identical for both agents, so nothing is
maintained twice.

---

## Requirements

- **Python 3.9 or newer.** Veriflow is pure standard library; nothing to install
  for the core engines, project detection, the verification runner, the static
  security scanner, or the API and OpenAPI engines.
- **Claude Code and/or Codex**, if you want Veriflow as a skill. The scripts
  also work standalone from a terminal with neither agent installed.

Two optional dependencies, each needed only for one capability:

| Package | Enables | Without it |
| :--- | :--- | :--- |
| `playwright` | browser and user-journey checks | those checks report `BLOCKED` with remediation |
| `PyYAML` | YAML OpenAPI specifications | YAML specs report `BLOCKED`; JSON specs still work |

Veriflow never installs a package for you.

```powershell
# Only if you want the optional capabilities:
pip install -r requirements-optional.txt
python -m playwright install chromium   # browser binaries, a separate step
```

---

## Install

### Project installation (one repository)

Use this when a team should get Veriflow by cloning the repo.

```powershell
git clone https://github.com/OpenWave-India/veriflow.git
cd Veriflow

python install.py --project --dry-run   # see exactly what will be written
python install.py --project             # write it -- both agents by default
```

`--platform` scopes this to one agent if you only use one:

```powershell
python install.py --project --platform claude   # Claude Code only
python install.py --project --platform codex    # Codex only
```

To install into a *different* project:

```powershell
python D:\Veriflow\install.py --project --project-root C:\work\my-app
```

That creates `C:\work\my-app\.claude\skills\veriflow\` and
`C:\work\my-app\.agents\skills\veriflow\`. Commit whichever you want your team
to get automatically; add the rest to `.gitignore` if not.

### Personal installation (all your projects)

```powershell
python install.py --personal --dry-run
python install.py --personal
```

This writes `~/.claude/skills/veriflow/` and `~/.agents/skills/veriflow/` (or
just one, with `--platform`) and nothing else. It does **not** change any
agent setting, registry key, `PATH` entry or environment variable.

### What the installer will not do

- It never runs without `--project` or `--personal`. There is no default
  scope. (`--platform` does default to `both`, since installing for an agent
  you don't use costs nothing and is one flag away to restrict.)
- It never overwrites a `veriflow` skill directory it did not create. If one
  exists without Veriflow's `.veriflow-install.json` marker, the installer stops
  and tells you your options. `--force` replaces it, and keeps a timestamped
  backup next to it first.
- It never touches a sibling skill.
- `--dry-run` writes nothing, ever.

---

## Confirm it was found

1. **Restart the agent**, or start a new session.
   - Claude Code scans skills at session start, so an installation mid-session
     is not visible until the next one.
   - Codex detects new skills automatically; restart only if a newly added
     skill still doesn't appear.

2. **Check the installation itself:**

   ```powershell
   python install.py --project --verify
   # or
   python install.py --personal --verify
   ```

   This verifies both platforms by default (narrow with `--platform claude` /
   `--platform codex`). It confirms `SKILL.md` exists with valid frontmatter,
   that every required script and reference is present, and that the
   installed copy is not out of date relative to the source. Exit code 0
   means OK.

3. **Ask the agent:**

   > what skills do you have available?

   `veriflow` should be listed. In Codex you can also explicitly invoke it
   with `$veriflow` or `/skills`.

4. **Invoke it.** You don't usually need to call it by name — describe the
   work and the agent loads the skill when its description matches:

   > I changed the login handler. Verify it.

   > Run Veriflow's security scan over this project.

   > The build is failing. Diagnose it before changing anything.

---

## Run a safe demo

Every command below is read-only or preview-only. None of them executes project
code or opens a network connection unless the text says so.

```powershell
# 1. What does Veriflow see in this project?
python skills\veriflow\scripts\detect-project.py .

# 2. What checks exist? (discovery only, nothing runs)
python skills\veriflow\scripts\run-checks.py .

# 3. Static security scan (read-only, offline, no prerequisites)
python skills\veriflow\scripts\run-security-tests.py .

# 4. Full audit: detection + security scan + core checks + catalog scope, one verdict
python skills\veriflow\scripts\run-audit.py examples\repair-demo --execute

# 5. Dependency identity check (preview lists packages; --execute queries PyPI/npm)
python skills\veriflow\scripts\check_dependencies.py .
python skills\veriflow\scripts\check_dependencies.py . --execute

# 6. Repair-attempt budget: a real counter, not just an instruction
python skills\veriflow\scripts\repair_budget.py --root . --attempt demo-issue --note "example"
python skills\veriflow\scripts\repair_budget.py --root . --status demo-issue
python skills\veriflow\scripts\repair_budget.py --root . --reset demo-issue

# 7. The bounded-repair demo: a deliberately broken project
python skills\veriflow\scripts\run-checks.py examples\repair-demo
type examples\repair-demo\README.md
```

Demos that execute something, each self-contained on a loopback port:

```powershell
# API verification against a local fixture server
python examples\api-demo\run-demo.py

# OpenAPI contract verification
python examples\openapi-demo\run-demo.py --preview
python examples\openapi-demo\run-demo.py

# Live security checks against the local security fixture
python examples\security-demo\run-demo.py --preview
python examples\security-demo\run-demo.py
```

Run the test suite:

```powershell
pip install -r requirements-dev.txt
python -m pytest tests -q
```

---

## Troubleshooting

### `/plugin install` fails with "Plugin couldn't be installed"

1. Re-run `/plugin marketplace update OpenWave-India` to pull the latest
   manifest, then retry `/plugin install veriflow@veriflow`.
2. If it still fails, open `/plugin` → **Errors** tab for the exact message.
3. The [manual install](#codex-or-a-manual-claude-code-install) below always
   works as a fallback.

### The agent does not list the skill

1. Confirm the file is where the agent looks:
   ```powershell
   dir .claude\skills\veriflow\SKILL.md
   dir .agents\skills\veriflow\SKILL.md
   dir $env:USERPROFILE\.claude\skills\veriflow\SKILL.md
   dir $env:USERPROFILE\.agents\skills\veriflow\SKILL.md
   ```
2. Run `python install.py --project --verify`. It names the specific problem
   for each platform.
3. Start a **new session** (Claude Code scans once, at session start; Codex
   usually detects changes live, but a restart rules it out).
4. Check the frontmatter is intact. `SKILL.md` must begin with `---` on line 1,
   and contain `name:` and `description:` before the closing `---`.
5. Confirm you are in the project you installed into. A project installation
   only applies to that directory tree.

### "Python package 'playwright' is not installed"

Expected, and not an error. Browser checks report `BLOCKED` and everything else
continues. Install it only if you want browser journeys:

```powershell
pip install playwright
python -m playwright install chromium
```

### "PyYAML is not installed" on a YAML OpenAPI spec

Either `pip install pyyaml`, or convert the spec to JSON. JSON specs need
nothing.

### A check reports `COMMAND_NOT_FOUND`

The tool genuinely is not installed, or not where Veriflow looked. The preview
output names the resolution source it tried (`project_venv`, `node_modules`,
`project_script`, `system_path`, `not_found`). Install the tool, or activate the
right virtual environment, and rerun. Veriflow will not install it for you.

### The security scan reports findings in my test fixtures

Expected if those files deliberately contain vulnerable samples. Exclude them,
and the report will disclose that it did:

```powershell
python skills\veriflow\scripts\run-security-tests.py . --exclude "tests/fixtures/*"
```

Or commit a `.veriflow-security-ignore` file at your project root, one path glob
per line. Veriflow's own repository has one; use it as a template. Exclusions
are always reported, never silent.

For a single line, add the inline marker `veriflow: allow-security` in a
comment. Suppressed findings are counted and disclosed in the report.

### `install.py` refuses to overwrite

There is already a `veriflow` skill directory that Veriflow did not install.
Look at it first. Then either `--force` (which backs it up), install to the
other scope, or move it aside yourself.

### Permission denied

You cannot write to the destination. Choose the other scope, or fix the
directory's permissions. Veriflow does not need and does not request elevation.

---

## Update

```powershell
cd Veriflow
git pull
python install.py --project    # or --personal; both agents by default
```

The installer reports what it added, updated and removed, deletes files that no
longer exist in the new version, and says "Already up to date" when there is
nothing to do. Restart the agent(s) afterwards.

If you edit `skills/veriflow/` in a Veriflow checkout, re-run
`python install.py --project` to re-sync the committed copies at
`.claude/skills/veriflow/` and `.agents/skills/veriflow/`. A test
(`tests/test_install.py`) fails if either drifts from the source.

---

## Uninstall

```powershell
python install.py --project --uninstall --dry-run
python install.py --project --uninstall
```

Removes both platforms' copies by default; add `--platform claude` or
`--platform codex` to remove only one. This removes only the directory it
installed, and refuses to remove one without Veriflow's marker file. It also
removes the parent `skills/` directory if left empty, so a sibling skill is
never affected. Restart the agent afterwards so it stops offering the skill.

Nothing else needs undoing: the installer changed no setting outside that
directory.

---

## Using the scripts without Claude Code or Codex

Every script is a standalone CLI with `--help`:

```powershell
python skills\veriflow\scripts\run-audit.py --help
python skills\veriflow\scripts\run-checks.py --help
python skills\veriflow\scripts\run-security-tests.py --help
python skills\veriflow\scripts\run-api-tests.py --help
python skills\veriflow\scripts\run-openapi-tests.py --help
python skills\veriflow\scripts\run-browser-tests.py --help
python skills\veriflow\scripts\check_dependencies.py --help
python skills\veriflow\scripts\repair_budget.py --help
```

Add `--json` to any of them for machine-readable output suitable for CI.

Exit codes are consistent: `0` means the executed checks passed, `1` means
something failed, `2` means a usage error, an unsafe target or an unknown
filter. A usage error is never reported as a pass.
