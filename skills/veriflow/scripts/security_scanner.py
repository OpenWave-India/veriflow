#!/usr/bin/env python3
"""
Veriflow Static Security Scanner (Phase 5).

Performs read-only, offline inspection of project source files for the security
defects that AI-assisted code changes introduce most often. The scanner never
executes project code, never opens a network connection, and never writes to the
project tree.

Design rules this module is built around:

- **Secret values never leave the scanner.** A finding reports the rule, the
  location and a redacted excerpt. The matched credential itself is replaced
  before it reaches any report, log, terminal or JSON document.
- **Evidence over inference.** Every finding carries the file, line and the
  redacted source line that triggered it, so a reviewer can confirm or dismiss
  it without rerunning the scan.
- **Confidence is reported, not hidden.** Static patterns produce false
  positives. Each rule declares a confidence level and the documented false
  positives for that rule, and the scanner filters obvious placeholders rather
  than reporting them as credentials.
- **Nothing is auto-fixed.** The scanner reports; the agent and the user decide.

Scope and limitations are deliberate: this is a pattern and configuration
scanner, not a taint-tracking analyser. It cannot prove the absence of a
vulnerability, and `MANUAL_REVIEW` is a first-class outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# --------------------------------------------------------------------------- #
# Scan boundaries
# --------------------------------------------------------------------------- #

#: Directories never scanned. These hold third-party or generated content, where
#: a finding would describe someone else's code rather than the project's.
DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".env.d",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "bin",
    "obj",
    "vendor",
    "site-packages",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "coverage",
    "htmlcov",
    ".idea",
    ".vscode-test",
}

#: Extensions the scanner understands well enough to report on.
SCANNABLE_EXTENSIONS: Set[str] = {
    ".py", ".pyi",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".rb", ".php", ".go", ".rs", ".java", ".kt", ".kts", ".cs", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1",
    ".sql",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".env", ".tf", ".tfvars",
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks", ".keystore",
    ".html", ".htm", ".vue", ".svelte",
    ".md", ".txt",
    ".dockerfile", ".Dockerfile",
}

#: Files without an extension that are still worth scanning.
SCANNABLE_FILENAMES: Set[str] = {
    "Dockerfile",
    "dockerfile",
    "Makefile",
    "Procfile",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

#: A file larger than this is skipped. Minified bundles and data fixtures
#: produce noise, not findings, and reading them costs more than it returns.
MAX_FILE_BYTES = 2_000_000

#: Longer lines are almost always minified or generated output.
MAX_LINE_LENGTH = 2_000

#: Bound on the excerpt stored per finding, so one long line cannot bloat a report.
MAX_EVIDENCE_CHARS = 240

#: Inline marker that suppresses findings on a line. Suppressions are counted
#: and reported, so a reviewer can see what was silenced.
SUPPRESSION_MARKER = "veriflow: allow-security"

#: Optional project-root file listing path globs to exclude from the scan, one
#: per line, '#' for comments. It exists for files that deliberately contain
#: vulnerable samples -- a security rule set, a scanner's own test fixtures, a
#: training exercise -- where every match is expected and a finding is noise.
#: Exclusions are never silent: the report states which patterns were applied
#: and how many files they removed.
IGNORE_FILENAME = ".veriflow-security-ignore"

# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

#: Unambiguous placeholders. These are the only substrings that justify
#: dropping a match outright: each is a value no real credential would contain,
#: so there is nothing for a reviewer to confirm.
_OBVIOUS_PLACEHOLDER_TOKENS: Tuple[str, ...] = (
    "redacted", "changeme", "change_me", "placeholder", "replace-me",
    "replace_me", "your-", "your_", "yourkey", "yourtoken",
    "<your", "<insert", "<token", "<secret", "<password", "<api",
    "xxxx", "aaaa", "0000", "insert", "todo", "s3cr3t-placeholder",
)

#: Words that *suggest* a value is synthetic but do not prove it. A real
#: credential committed to a file named `test_settings.py`, or named
#: `EXAMPLE_API_KEY`, contains one of these and is still a real credential.
#: Dropping on these words alone is how live keys get missed, so a match here
#: is downgraded to LOW confidence rather than discarded -- and only when no
#: stronger signal (entropy, known prefix) contradicts it.
#:
#: Matched as whole delimiter-separated segments, so `sk_live_example_1` and
#: `test-key` match while `latest` and `attestation` do not.
_SOFT_PLACEHOLDER_WORDS: frozenset = frozenset(
    {
        "test", "tests", "testing", "example", "examples", "dummy", "fake",
        "sample", "samples", "mock", "stub", "demo", "notreal", "foobar",
        "abcdef", "deadbeef", "123456", "placeholder",
    }
)

#: Distinctive enough that a bare substring match carries no false-positive
#: risk, which catches run-together spellings like `examplekey` or `dummydata`.
_SOFT_PLACEHOLDER_SUBSTRINGS: Tuple[str, ...] = (
    "example", "dummy", "notreal", "foobar", "deadbeef", "testkey",
)

#: Provider-issued key prefixes. These are assigned by the issuing service, so
#: a value carrying one is a real key shape regardless of surrounding wording.
#: A prefix match always outranks a soft placeholder word.
_KNOWN_KEY_PREFIXES: Tuple[str, ...] = (
    "sk_live_", "sk_test_", "pk_live_", "rk_live_", "AKIA", "ASIA",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xapp-",
    "AIza", "ya29.", "SG.", "glpat-", "dop_v1_", "shpat_", "npm_",
    "sq0atp-", "sq0csp-", "EAACEdEose0cBA", "hf_", "sk-ant-", "sk-proj-",
)

#: Entropy at or above this threshold means the value's character
#: distribution looks generated rather than written, which is what separates
#: `EXAMPLE_KEY = "aB3xK9mQ7pL2wZ8n"` from `EXAMPLE_KEY = "example_value"`.
_HIGH_ENTROPY_BITS = 3.5

#: Verdicts returned by :func:`classify_secret_value`.
VERDICT_DROP = "drop"
VERDICT_LOW = "low"
VERDICT_REPORT = "report"

#: Indicators that the value is read from configuration rather than hard-coded.
_INDIRECTION_TOKENS: Tuple[str, ...] = (
    "os.environ", "os.getenv", "process.env", "getenv(", "environ[",
    "${", "{{", "%(", "config.", "settings.", "secrets.", "vault",
    "systemenvironment", "configuration[", "env(", "dotenv",
)


def _shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per character) of ``value``.

    A hard-coded credential is usually high-entropy; an English identifier is
    not. Entropy alone is a weak signal, so it is only ever used to *suppress*
    an otherwise matching pattern, never to raise a finding on its own.
    """
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def redact_secret(value: str) -> str:
    """Return a non-reversible marker for a matched credential.

    Keeps only the length and a 2-character prefix so a reviewer can locate the
    value in their own editor, while the report itself carries nothing usable.
    """
    if not value:
        return "[REDACTED]"
    stripped = value.strip().strip("'\"`")
    if len(stripped) <= 4:
        return "[REDACTED]"
    return f"{stripped[:2]}...[REDACTED:{len(stripped)} chars]"


def redact_line(line: str, matched_values: Sequence[str]) -> str:
    """Return ``line`` with every matched credential replaced by a marker.

    This is the only function that produces the ``evidence`` field of a secret
    finding, which guarantees a raw credential cannot reach a report by being
    copied out of the source line.
    """
    redacted = line.rstrip("\r\n")
    for value in sorted(set(matched_values), key=len, reverse=True):
        candidate = value.strip().strip("'\"`")
        if len(candidate) >= 4 and candidate in redacted:
            redacted = redacted.replace(candidate, redact_secret(candidate))
    redacted = escape_unprintable(redacted)
    if len(redacted) > MAX_EVIDENCE_CHARS:
        redacted = redacted[:MAX_EVIDENCE_CHARS] + " ...[truncated]"
    return redacted.strip()


def _contains_soft_placeholder(lowered: str) -> bool:
    """Return True when the value carries a word suggesting it is synthetic.

    Segment-aware on purpose: splitting on non-alphanumerics means `test` matches
    in `sk_live_test_1` and `test-key`, but `latest` and `attestation` stay clear,
    which a bare substring check would wrongly flag.
    """
    segments = set(re.split(r"[^a-z0-9]+", lowered))
    if segments & _SOFT_PLACEHOLDER_WORDS:
        return True
    return any(token in lowered for token in _SOFT_PLACEHOLDER_SUBSTRINGS)


def _has_known_key_prefix(candidate: str) -> bool:
    """Return True when the value starts with a provider-issued key prefix.

    Case-sensitive on purpose: ``AKIA`` and ``sk_live_`` are issued with a
    fixed case, and lowercasing would match prose like "akia" in a comment.
    """
    return any(candidate.startswith(prefix) for prefix in _KNOWN_KEY_PREFIXES)


def classify_secret_value(value: str) -> Tuple[str, str]:
    """Classify a matched credential as drop / LOW-confidence / report.

    Returns ``(verdict, reason)`` where verdict is one of
    :data:`VERDICT_DROP`, :data:`VERDICT_LOW` or :data:`VERDICT_REPORT`, and
    reason explains the decision for the report's skipped section.

    The distinction that matters: a value is discarded only when it cannot
    possibly be a credential (an obvious placeholder, an environment lookup, a
    regex source). Merely *looking* synthetic -- living in a file called
    ``test_config.py``, or named ``EXAMPLE_TOKEN`` -- is not enough, because
    real keys get committed under exactly those names. Those are reported at
    LOW confidence so a reviewer sees them and decides, which is the whole
    point: a silent drop is indistinguishable from a scanner that missed it.
    """
    candidate = value.strip().strip("'\"`")

    if not candidate:
        return VERDICT_DROP, "empty value"
    if any(token in value for token in _INDIRECTION_TOKENS):
        return VERDICT_DROP, "value is read from configuration or the environment, not hard-coded"
    if any(meta in candidate for meta in ("[A-Za-z", "\\d", "\\w", "(?:", ".*", "+=*")):
        return VERDICT_DROP, "value is a regex source or format template, not a literal"

    lowered = candidate.lower()
    has_prefix = _has_known_key_prefix(candidate)
    entropy = _shannon_entropy(candidate)

    # A provider-issued prefix is decisive: report it whatever the wording
    # around it says. `sk_live_` in a file named example.py is still a live key.
    if has_prefix:
        if _contains_soft_placeholder(lowered):
            return (
                VERDICT_LOW,
                "contains a placeholder-looking word but carries a known provider key prefix",
            )
        return VERDICT_REPORT, ""

    if len(candidate) < 8:
        return VERDICT_DROP, "value is shorter than 8 characters"
    if len(set(lowered)) <= 2:
        return VERDICT_DROP, "value is a single repeated character"
    if any(token in lowered for token in _OBVIOUS_PLACEHOLDER_TOKENS):
        return VERDICT_DROP, "value is an unambiguous placeholder"

    if _contains_soft_placeholder(lowered):
        if entropy >= _HIGH_ENTROPY_BITS:
            return (
                VERDICT_LOW,
                f"contains a placeholder-looking word but has high entropy ({entropy:.2f} bits/char)",
            )
        return VERDICT_DROP, "value is a low-entropy placeholder"

    # Low-entropy English-looking values are identifiers, not credentials.
    if entropy < 2.6:
        return VERDICT_DROP, f"value has low entropy ({entropy:.2f} bits/char), reads as an identifier"

    return VERDICT_REPORT, ""


# --------------------------------------------------------------------------- #
# Rule definitions
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SecurityRule:
    """A single static detection rule.

    Attributes:
        rule_id: Stable identifier, cited by findings and regression tests.
        title: Short human-readable name.
        category: Scanner category, used for ``--category`` filtering.
        severity: CRITICAL | HIGH | MEDIUM | LOW.
        confidence: HIGH | MEDIUM | LOW - how often this pattern is a true positive.
        pattern: Compiled regex applied per line.
        extensions: Restrict the rule to these suffixes; empty means all.
        catalog_ids: Production-catalog test IDs this rule contributes evidence to.
        references: Primary-source URLs supporting the rule.
        remediation: The safe corrective action.
        false_positives: Documented cases where this rule fires without a defect.
        redact_match: True when the captured group is a credential to redact.
        capture_group: Which regex group holds the sensitive value.
        multiline: True when the pattern spans more than one physical line and
            must be matched against the whole file rather than line by line
            (for example, an ``except`` clause whose body is on the next line).
    """

    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    pattern: re.Pattern
    remediation: str
    false_positives: str
    extensions: Tuple[str, ...] = ()
    catalog_ids: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    redact_match: bool = False
    capture_group: int = 0
    multiline: bool = False


_OWASP_A01 = "OWASP Top 10:2025 A01 Broken Access Control (https://top10.owasp.org/2025/)"
_OWASP_A02 = "OWASP Top 10:2025 A02 Security Misconfiguration (https://top10.owasp.org/2025/)"
_OWASP_A03 = "OWASP Top 10:2025 A03 Software Supply Chain Failures (https://top10.owasp.org/2025/)"
_OWASP_A04 = "OWASP Top 10:2025 A04 Cryptographic Failures (https://top10.owasp.org/2025/)"
_OWASP_A05 = "OWASP Top 10:2025 A05 Injection (https://top10.owasp.org/2025/)"
_OWASP_A08 = "OWASP Top 10:2025 A08 Software or Data Integrity Failures (https://top10.owasp.org/2025/)"
_OWASP_A09 = "OWASP Top 10:2025 A09 Security Logging and Alerting Failures (https://top10.owasp.org/2025/)"
_OWASP_AI = (
    "OWASP Secure Coding with AI Cheat Sheet "
    "(https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.html)"
)

_CODE_EXT = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".rb", ".php", ".go", ".rs", ".java", ".cs")

#: Code plus the template formats where an output-encoding defect lives.
_TEMPLATE_EXT = _CODE_EXT + (".html", ".htm", ".vue", ".svelte")

SECURITY_RULES: Tuple[SecurityRule, ...] = (
    # ---------------------- Hard-coded secrets ---------------------------- #
    SecurityRule(
        rule_id="SEC-SECRET-001",
        title="Hard-coded credential assigned in source",
        category="secrets",
        severity="CRITICAL",
        confidence="MEDIUM",
        pattern=re.compile(
            r"""(?ix)
            \b(?:password|passwd|pwd|secret|secret_key|api_key|apikey|
               access_token|auth_token|private_key|client_secret|
               db_password|database_password)\b
            \s*[:=]\s*
            (?P<value>['"][^'"\n]{8,}['"])
            """,
        ),
        remediation=(
            "Read the value from an environment variable or a secret manager at runtime. "
            "Rotate the exposed credential - it must be treated as compromised the moment "
            "it reaches version control."
        ),
        false_positives=(
            "Test fixtures and documentation examples assign synthetic credentials. "
            "Placeholder-looking and low-entropy values are already filtered; confirm the "
            "file is a fixture before dismissing."
        ),
        catalog_ids=("SEC-006", "CONF-003"),
        references=(_OWASP_A04, _OWASP_AI),
        redact_match=True,
        capture_group=0,
    ),
    SecurityRule(
        rule_id="SEC-SECRET-002",
        title="Private key material committed to the repository",
        category="secrets",
        severity="CRITICAL",
        confidence="HIGH",
        pattern=re.compile(
            r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?:\s+BLOCK)?-----"
        ),
        remediation=(
            "Remove the key from the working tree and from Git history, then rotate the key "
            "pair. Distribute private keys through a secret store, never through the repository."
        ),
        false_positives="A test suite may embed a throwaway key to exercise parsing code.",
        catalog_ids=("SEC-006", "CONF-003"),
        references=(_OWASP_A04,),
    ),
    SecurityRule(
        rule_id="SEC-SECRET-003",
        title="Cloud provider access key identifier in source",
        category="secrets",
        severity="CRITICAL",
        confidence="HIGH",
        pattern=re.compile(r"\b(?P<value>(?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        remediation=(
            "Deactivate and delete the access key in the provider console, then use a role "
            "or an injected environment credential instead of an embedded key."
        ),
        false_positives="A deliberately invalid identifier used in documentation or a test.",
        catalog_ids=("SEC-006", "CONF-003"),
        references=(_OWASP_A04,),
        redact_match=True,
        capture_group=0,
    ),
    SecurityRule(
        rule_id="SEC-SECRET-004",
        title="Credentials embedded in a connection URL",
        category="secrets",
        severity="CRITICAL",
        confidence="HIGH",
        pattern=re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|ftp|https?)"
            r"://[^\s:/@'\"]+:(?P<value>[^\s/@'\"]{4,})@"
        ),
        remediation=(
            "Build the connection string at runtime from separately injected credentials. "
            "Rotate the embedded password."
        ),
        false_positives=(
            "Local development URLs with a well-known throwaway password such as "
            "postgres:postgres. Still worth removing, but not an exposure."
        ),
        catalog_ids=("SEC-006", "CONF-002"),
        references=(_OWASP_A04,),
        redact_match=True,
        capture_group=0,
    ),
    # ---------------------- Injection ------------------------------------- #
    SecurityRule(
        rule_id="SEC-INJ-001",
        title="Shell command executed through a shell with a constructed string",
        category="injection",
        severity="CRITICAL",
        confidence="HIGH",
        pattern=re.compile(r"(?i)\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True"),
        remediation=(
            "Pass an argument list and leave shell=False (the default). When a shell is "
            "genuinely required, validate every interpolated value against an allowlist."
        ),
        false_positives=(
            "A fully literal command with no interpolation is far lower risk, though still "
            "a poor default."
        ),
        catalog_ids=("SEC-012",),
        references=(_OWASP_A05, _OWASP_AI),
        extensions=(".py",),
    ),
    SecurityRule(
        rule_id="SEC-INJ-002",
        title="Operating-system command executed from an interpolated string",
        category="injection",
        severity="CRITICAL",
        confidence="HIGH",
        pattern=re.compile(
            r"(?i)\b(?:os\.system|os\.popen|commands\.getoutput)\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format))"
        ),
        remediation="Replace with subprocess and an argument list; never interpolate input into a command string.",
        false_positives="None known for the interpolated form; a fully literal argument does not match.",
        catalog_ids=("SEC-012",),
        references=(_OWASP_A05,),
        extensions=(".py",),
    ),
    SecurityRule(
        rule_id="SEC-INJ-003",
        title="Node child process spawned through a shell with an interpolated command",
        category="injection",
        severity="CRITICAL",
        confidence="HIGH",
        pattern=re.compile(r"(?i)\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)"),
        remediation="Use execFile or spawn with an argument array instead of exec with a template string.",
        false_positives="A literal command with no interpolation does not match this rule.",
        catalog_ids=("SEC-012",),
        references=(_OWASP_A05,),
        extensions=(".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
    ),
    SecurityRule(
        rule_id="SEC-INJ-004",
        title="SQL statement assembled by string interpolation",
        category="injection",
        severity="CRITICAL",
        confidence="MEDIUM",
        pattern=re.compile(
            r"""(?ix)
            (?:
              # An f-string passed straight to a cursor: the value is spliced in.
              (?:execute|executemany|raw|query|exec_driver_sql)\s*\(\s*
              f['"][^'"]*\b(?:select|insert|update|delete|drop|alter)\b
            |
              # SQL text joined to a variable, a template literal, or .format().
              # The driver placeholder "%s" is deliberately NOT treated as
              # interpolation: it is the correct, parameterised form.
              \b(?:select|insert\s+into|update|delete\s+from|drop\s+table)\b[^'"\n;]*
              (?:\+\s*\w+|\$\{|\{\w+\}|\.format\s*\()
            |
              # A completed SQL literal followed by %-formatting or concatenation.
              (?:execute|executemany|raw|query)\s*\(\s*
              ['"][^'"]*\b(?:select|insert|update|delete)\b[^'"]*['"]\s*(?:%|\+|\.format)
            )
            """
        ),
        remediation=(
            "Use parameterised queries: pass the SQL text and the parameters separately so "
            "the driver binds values rather than splicing them into the statement."
        ),
        false_positives=(
            "A statement built with a driver's own placeholder syntax and a parameter tuple "
            "can match the broad form. Confirm whether the interpolated value is a bound "
            "parameter or spliced text."
        ),
        catalog_ids=("SEC-002",),
        references=(_OWASP_A05,),
        extensions=_CODE_EXT,
    ),
    SecurityRule(
        rule_id="SEC-INJ-005",
        title="Untrusted value evaluated as code",
        category="injection",
        severity="CRITICAL",
        confidence="MEDIUM",
        pattern=re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*(?:f['\"]|request|input\s*\(|req\.|params|body|query|argv)"),
        remediation=(
            "Remove the dynamic evaluation. Parse structured input with a data parser "
            "(json.loads, ast.literal_eval) instead of an interpreter."
        ),
        false_positives="A REPL, a template engine or a sandboxed plugin loader may evaluate by design.",
        catalog_ids=("SEC-012",),
        references=(_OWASP_A05,),
        extensions=_CODE_EXT,
    ),
    SecurityRule(
        rule_id="SEC-INJ-006",
        title="Server-rendered output marked as trusted HTML",
        category="injection",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?i)(?:dangerouslySetInnerHTML|\.innerHTML\s*=\s*(?:`|[a-z_$]\w*\s*\+|f?['\"][^'\"]*\$\{)"
            r"|\|\s*safe\b|\{\{\{|mark_safe\s*\(|v-html\s*=)"
        ),
        remediation=(
            "Render untrusted values as text so the framework escapes them. When HTML is "
            "required, sanitise with a maintained allowlist sanitiser before rendering."
        ),
        false_positives=(
            "Content already sanitised upstream, or a value that is provably author-controlled "
            "rather than user-supplied."
        ),
        catalog_ids=("SEC-001",),
        references=(_OWASP_A05,),
        extensions=_TEMPLATE_EXT,
    ),
    # ---------------------- Deserialisation ------------------------------- #
    SecurityRule(
        rule_id="SEC-DESER-001",
        title="Unsafe deserialisation of untrusted data",
        category="deserialization",
        severity="CRITICAL",
        confidence="HIGH",
        pattern=re.compile(
            r"(?i)\b(?:pickle\.loads?|cPickle\.loads?|marshal\.loads|dill\.loads|shelve\.open"
            r"|yaml\.load\s*\((?![^)]*Safe)|torch\.load\s*\((?![^)]*weights_only\s*=\s*True)"
            r"|Marshal\.load|unserialize\s*\()"
        ),
        remediation=(
            "Use a data-only format: json.loads, yaml.safe_load, or torch.load(..., "
            "weights_only=True). These formats cannot instantiate arbitrary objects."
        ),
        false_positives=(
            "Deserialising a file the application itself wrote to a trusted location is lower "
            "risk, but still breaks if the location becomes writable."
        ),
        catalog_ids=("SEC-014",),
        references=(_OWASP_A08,),
        extensions=_CODE_EXT,
    ),
    # ---------------------- Path traversal / SSRF ------------------------- #
    SecurityRule(
        rule_id="SEC-PATH-001",
        title="Filesystem path built from request input without validation",
        category="path_traversal",
        severity="HIGH",
        confidence="LOW",
        pattern=re.compile(
            r"(?i)(?:open|readFile(?:Sync)?|sendFile|send_file|createReadStream|Path)\s*\(\s*"
            r"(?:os\.path\.join\s*\(\s*)?[^)\n]*\b(?:request\.|req\.|params|query|body|args\.get|form\.get|argv)\b"
        ),
        remediation=(
            "Resolve the candidate path and confirm it stays inside the intended base "
            "directory (compare resolved paths), and reject absolute paths and '..' segments."
        ),
        false_positives=(
            "Reported at LOW confidence on purpose: the input may already be validated or "
            "constrained to an allowlist. Treat as a prompt to inspect, not as a defect."
        ),
        catalog_ids=("SEC-013",),
        references=(_OWASP_A01,),
        extensions=_CODE_EXT,
    ),
    SecurityRule(
        rule_id="SEC-SSRF-001",
        title="Outbound request to a URL taken from request input",
        category="ssrf",
        severity="HIGH",
        confidence="LOW",
        pattern=re.compile(
            r"(?i)\b(?:requests\.(?:get|post|put|delete|head)|urlopen|httpx\.(?:get|post)|fetch|axios(?:\.\w+)?)"
            r"\s*\(\s*[^)\n]*\b(?:request\.|req\.|params|query|body|args\.get|form\.get)\b"
        ),
        remediation=(
            "Validate the destination against an allowlist of hosts and schemes before the "
            "request, and reject loopback, link-local and private address ranges."
        ),
        false_positives=(
            "LOW confidence: the URL may be a fixed base with only a validated path segment "
            "taken from input."
        ),
        catalog_ids=("SEC-015",),
        references=(_OWASP_A01,),
        extensions=_CODE_EXT,
    ),
    SecurityRule(
        rule_id="SEC-REDIR-001",
        title="Redirect destination taken from request input",
        category="open_redirect",
        severity="MEDIUM",
        confidence="LOW",
        pattern=re.compile(
            r"(?i)\b(?:redirect|res\.redirect|HttpResponseRedirect|location\s*=|window\.location(?:\.href)?\s*=)"
            r"\s*\(?\s*[^)\n]*"
            # The destination must come from an actual accessor. A bare mention
            # of "next" matched any assignment, e.g. redirect_param = "next".
            r"(?:request\.|req\.|\bparams\b|\bquery\b|args\.get|form\.get"
            r"|\[['\"](?:next|returnUrl|return_url|redirect_uri)['\"]\]"
            r"|get\(['\"](?:next|returnUrl|return_url|redirect_uri)['\"]\))"
        ),
        remediation=(
            "Accept only relative paths, or validate the destination against an allowlist of "
            "hosts before redirecting."
        ),
        false_positives="LOW confidence: the destination may already be validated or be a fixed route name.",
        catalog_ids=("SEC-005",),
        references=(_OWASP_A01,),
        extensions=_CODE_EXT,
    ),
    # ---------------------- Cryptography ---------------------------------- #
    SecurityRule(
        rule_id="SEC-CRYPTO-001",
        title="Weak hash used for a credential or signature",
        category="cryptography",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?i)\b(?:hashlib\.(?:md5|sha1)|createHash\s*\(\s*['\"](?:md5|sha1)['\"]"
            r"|MD5\.new|Digest::MD5|MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"])"
        ),
        remediation=(
            "Hash passwords with a memory-hard password hash (argon2, scrypt or bcrypt). "
            "Use SHA-256 or stronger for integrity and signatures."
        ),
        false_positives=(
            "MD5 and SHA-1 remain acceptable for non-security uses such as cache keys, "
            "content addressing and ETags. Confirm the purpose before acting."
        ),
        catalog_ids=("SEC-016",),
        references=(_OWASP_A04,),
        extensions=_CODE_EXT,
    ),
    SecurityRule(
        rule_id="SEC-CRYPTO-002",
        title="Non-cryptographic randomness used for a security value",
        category="cryptography",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?i)\b(?:random\.(?:random|randint|choice|randrange|sample|shuffle)|Math\.random)\s*\([^)]*\)"
            r"[^\n]{0,80}\b(?:token|secret|password|nonce|salt|otp|session|csrf|api_?key|reset)\b"
            r"|\b(?:token|secret|password|nonce|salt|otp|session|csrf|api_?key|reset)\w*\s*[:=][^\n]{0,60}"
            r"\b(?:random\.(?:random|randint|choice|randrange|sample)|Math\.random)\s*\("
        ),
        remediation=(
            "Generate security values with a cryptographically secure source: Python "
            "secrets.token_urlsafe / os.urandom, or Node crypto.randomBytes / randomUUID."
        ),
        false_positives="A variable that merely contains one of these words but holds no security value.",
        catalog_ids=("SEC-016",),
        references=(_OWASP_A04,),
        extensions=_CODE_EXT,
    ),
    SecurityRule(
        rule_id="SEC-TLS-001",
        title="TLS certificate verification disabled",
        category="transport",
        severity="HIGH",
        confidence="HIGH",
        pattern=re.compile(
            r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false"
            r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|_create_unverified_context"
            r"|CERT_NONE|InsecureSkipVerify\s*:\s*true|curl\s+(?:-k\b|--insecure))"
        ),
        remediation=(
            "Keep verification enabled. For a private certificate authority, install its "
            "root certificate and point the client's trust store at it."
        ),
        false_positives=(
            "A local test harness against a self-signed fixture. Confirm the setting cannot "
            "reach a production code path or configuration file."
        ),
        catalog_ids=("CONF-005",),
        references=(_OWASP_A04,),
    ),
    # ---------------------- Configuration --------------------------------- #
    SecurityRule(
        rule_id="SEC-CONF-001",
        title="Debug mode enabled in committed configuration",
        category="configuration",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?im)^\s*(?:DEBUG|debug|FLASK_DEBUG|APP_DEBUG|DJANGO_DEBUG)\s*[:=]\s*"
            r"(?:True|true|1|['\"](?:true|1|on)['\"])\s*(?:,|;|#.*)?$"
        ),
        remediation=(
            "Drive debug from an environment variable that defaults to off, so a production "
            "deployment cannot inherit a debug interpreter or verbose error pages."
        ),
        false_positives=(
            "A development-only settings module or a .env.development file that is never "
            "deployed. Confirm which configuration the production build loads."
        ),
        catalog_ids=("SEC-009",),
        references=(_OWASP_A02,),
    ),
    SecurityRule(
        rule_id="SEC-CONF-002",
        title="Host or origin allowlist set to a wildcard",
        category="configuration",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?i)(?:ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]"
            r"|CORS_ALLOW_ALL_ORIGINS\s*=\s*True"
            r"|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]"
            r"|origin\s*:\s*['\"]\*['\"]"
            r"|cors\s*\(\s*\{\s*origin\s*:\s*true)"
        ),
        remediation=(
            "List the exact hosts or origins the service serves. A wildcard origin combined "
            "with credentialed requests removes the browser's cross-origin protection."
        ),
        false_positives=(
            "A genuinely public, unauthenticated, read-only API may intend a wildcard origin. "
            "It is still wrong wherever credentials are accepted."
        ),
        catalog_ids=("SEC-008",),
        references=(_OWASP_A02,),
    ),
    SecurityRule(
        rule_id="SEC-CONF-003",
        title="Session or authentication cookie set without security attributes",
        category="configuration",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?i)(?:set_cookie|setCookie|cookies\.set)\s*\([^)\n]*"
            r"(?:session|sid|auth|token|jwt|csrf|remember)[^)\n]*\)"
        ),
        remediation=(
            "Set HttpOnly, Secure and SameSite on every session or authentication cookie, "
            "and scope it to the narrowest path that works."
        ),
        false_positives=(
            "Attributes may be applied through framework defaults or a central configuration "
            "rather than at the call site. The live cookie-attribute check "
            "(SEC-LIVE-COOKIE-001) is the authoritative evidence."
        ),
        catalog_ids=("SEC-007",),
        references=(_OWASP_A02,),
    ),
    SecurityRule(
        rule_id="SEC-CONF-004",
        title="Dependency declared without a pinned version",
        category="supply_chain",
        severity="MEDIUM",
        confidence="MEDIUM",
        pattern=re.compile(r"(?m)^(?!\s*[#\-])\s*(?P<name>[A-Za-z][\w.\-\[\]]*)\s*$"),
        remediation=(
            "Pin the version and commit the lockfile, so a rebuild cannot silently pull a "
            "different (or newly malicious) release."
        ),
        false_positives=(
            "requirements.txt files that intentionally float versions and rely on a separate "
            "lockfile or constraints file for reproducibility."
        ),
        extensions=(".txt",),
        catalog_ids=("SEC-020",),
        references=(_OWASP_A03, _OWASP_AI),
        multiline=True,
    ),
    # ---------------------- Error and log hygiene ------------------------- #
    SecurityRule(
        rule_id="SEC-ERR-001",
        title="Exception silently swallowed",
        category="error_handling",
        severity="MEDIUM",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?m)(?:except[^\n:]*:\s*(?:pass|\.\.\.)\s*$"
            r"|catch\s*\([^)]*\)\s*\{\s*\}"
            r"|\.catch\s*\(\s*\(?\s*\)?\s*=>\s*\{\s*\}\s*\))"
        ),
        remediation=(
            "Log the exception with enough context to diagnose it, or re-raise. A silent "
            "handler turns a failure into a false green result."
        ),
        false_positives=(
            "A deliberate best-effort cleanup path where the failure genuinely carries no "
            "information. Those should carry a comment saying so."
        ),
        catalog_ids=("SEC-021",),
        references=(_OWASP_A09,),
        multiline=True,
        extensions=_CODE_EXT,
    ),
    SecurityRule(
        rule_id="SEC-ERR-002",
        title="Credential or token written to a log",
        category="error_handling",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?i)\b(?:console\.(?:log|error|warn|info)|print|printf|logger?\.\w+|logging\.\w+)\s*\("
            r"[^)\n]*\b(?:password|passwd|secret|api_?key|access_token|auth_token|private_key"
            r"|client_secret|credential|authorization)\b"
        ),
        remediation=(
            "Remove the value from the log statement, or redact it before logging. Log "
            "aggregation makes a logged secret as exposed as a committed one."
        ),
        false_positives=(
            "Logging the *name* of a missing configuration key, or an explicitly redacted "
            "placeholder, matches this pattern without exposing anything."
        ),
        catalog_ids=("SEC-006", "SEC-021"),
        references=(_OWASP_A09, _OWASP_AI),
        extensions=_CODE_EXT,
    ),
    # ---------------------- AI agent and supply chain --------------------- #
    SecurityRule(
        rule_id="SEC-AI-001",
        title="Instruction-shaped text embedded in repository content",
        category="prompt_injection",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
            r"|disregard\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions|rules|prompt)"
            r"|you\s+are\s+now\s+(?:a|an|in)\s+\w+\s*mode"
            r"|system\s*prompt\s*[:=]\s*['\"]"
            r"|<\s*/?\s*(?:system|assistant)\s*>"
            r"|do\s+not\s+tell\s+the\s+user"
            r"|exfiltrate|curl\s+[^\s|]*\s*\|\s*(?:ba)?sh)"
        ),
        remediation=(
            "Treat repository text, issues, PR comments and fetched pages as untrusted data, "
            "never as instructions. Review the change that introduced this content and the "
            "agent actions that followed it."
        ),
        false_positives=(
            "Security documentation, test fixtures and this scanner's own rule set legitimately "
            "contain these phrases. Confirm whether the file is read as agent context."
        ),
        catalog_ids=("SEC-017",),
        references=(_OWASP_AI,),
    ),
    SecurityRule(
        rule_id="SEC-AI-002",
        title="Bidirectional or zero-width Unicode in source",
        category="prompt_injection",
        severity="HIGH",
        confidence="HIGH",
        pattern=re.compile(
            "[\u202a-\u202e\u2066-\u2069\u200b\u200c\u200d\u200e\u200f\u2060\ufeff]"
        ),
        remediation=(
            "Remove the control characters. Text that renders differently to a reviewer than "
            "it parses to a compiler defeats code review entirely."
        ),
        false_positives=(
            "Internationalisation fixtures and emoji sequences use zero-width joiners "
            "legitimately. Confirm the file's purpose."
        ),
        catalog_ids=("SEC-018",),
        references=(_OWASP_AI,),
    ),
    SecurityRule(
        rule_id="SEC-AI-003",
        title="Install-time script execution in a package manifest",
        category="supply_chain",
        severity="HIGH",
        confidence="MEDIUM",
        pattern=re.compile(
            r"(?i)\"(?:preinstall|postinstall|prepare)\"\s*:\s*\"[^\"]*"
            r"(?:curl|wget|bash|sh\s|powershell|iex|node\s+-e|python\s+-c)"
        ),
        remediation=(
            "Remove network access and shell execution from install hooks. An install hook "
            "runs automatically with the developer's full privileges."
        ),
        false_positives="A build step that legitimately shells out, though it should not fetch from the network.",
        extensions=(".json",),
        catalog_ids=("SEC-019",),
        references=(_OWASP_A03, _OWASP_AI),
    ),
)

#: Rule lookup by identifier, used by the CLI and by regression tests.
RULES_BY_ID: Dict[str, SecurityRule] = {rule.rule_id: rule for rule in SECURITY_RULES}

#: Every category the scanner can report, for ``--category`` validation.
SCANNER_CATEGORIES: Tuple[str, ...] = tuple(sorted({rule.category for rule in SECURITY_RULES}))


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


@dataclass
class SecurityFinding:
    """One located, redacted static security finding."""

    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    file: str
    line: int
    evidence: str
    remediation: str
    false_positives: str
    catalog_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    #: True only when the placeholder classifier downgraded this finding from
    #: its rule's confidence. Several rules are natively LOW, so counting
    #: `confidence == "LOW"` would report those as downgrades and make the
    #: skipped section state something untrue.
    confidence_downgraded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "known_false_positives": self.false_positives,
            "catalog_ids": list(self.catalog_ids),
            "references": list(self.references),
        }


@dataclass
class ScanReport:
    """Aggregate result of a static security scan."""

    root: str
    findings: List[SecurityFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    suppressed: int = 0
    excluded_files: int = 0
    exclusion_patterns: List[str] = field(default_factory=list)
    rules_applied: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    #: Candidate secrets discarded as placeholders, each with the reason.
    #: Disclosed in the report so a drop is never indistinguishable from a miss.
    dropped_placeholders: List[Dict[str, Any]] = field(default_factory=list)
    #: Set when the scan was restricted to specific paths (``--changed``).
    included_paths: List[str] = field(default_factory=list)
    #: Files present in the tree but outside a restricted scan's scope.
    files_outside_scope: int = 0

    def dropped_reason_counts(self) -> Dict[str, int]:
        """Group discarded candidates by reason, for the skipped section."""
        counts: Dict[str, int] = {}
        for item in self.dropped_placeholders:
            reason = str(item.get("reason", "unspecified"))
            counts[reason] = counts.get(reason, 0) + 1
        return counts

    def low_confidence_count(self) -> int:
        """Findings the placeholder classifier downgraded.

        Deliberately not `confidence == "LOW"`: SEC-PATH-001 and SEC-REDIR-001
        are LOW by rule definition, and counting them here would claim they
        were rescued from a placeholder drop when they never were.
        """
        return sum(1 for f in self.findings if f.confidence_downgraded)

    def severity_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": "veriflow-static-security-scanner",
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "suppressed_findings": self.suppressed,
            "excluded_files": self.excluded_files,
            "exclusion_patterns": list(self.exclusion_patterns),
            "rules_applied": list(self.rules_applied),
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
            "limitations": list(self.limitations),
            "low_confidence_findings": self.low_confidence_count(),
            "dropped_placeholders": list(self.dropped_placeholders),
            "dropped_placeholder_reasons": self.dropped_reason_counts(),
            "included_paths": list(self.included_paths),
            "files_outside_scope": self.files_outside_scope,
        }


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


def load_ignore_patterns(root: Path) -> List[str]:
    """Read path-glob exclusions from the project's ignore file.

    Returns an empty list when the file is absent or unreadable: a missing
    ignore file must never prevent a scan.
    """
    ignore_file = root / IGNORE_FILENAME
    try:
        if not ignore_file.is_file():
            return []
        lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, PermissionError):
        return []
    patterns: List[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped.replace("\\", "/"))
    return patterns


def _is_excluded(relative_path: str, patterns: Sequence[str]) -> bool:
    """Return True when ``relative_path`` matches any exclusion glob.

    Matching is performed on forward-slash form so one pattern works on both
    Windows and POSIX. A pattern also matches a whole directory subtree, so
    ``tests/fixtures`` excludes everything beneath it.
    """
    if not patterns:
        return False
    normalized = relative_path.replace("\\", "/")
    for pattern in patterns:
        if fnmatch(normalized, pattern):
            return True
        # Directory-prefix form: "tests/fixtures" excludes the subtree.
        if normalized == pattern or normalized.startswith(pattern.rstrip("/") + "/"):
            return True
        if fnmatch(normalized, pattern.rstrip("/") + "/*"):
            return True
    return False


def _is_scannable(path: Path) -> bool:
    """Return True when ``path`` is a file type the scanner reports on."""
    if path.name in SCANNABLE_FILENAMES:
        return True
    if path.name.startswith(".env"):
        return True
    return path.suffix in SCANNABLE_EXTENSIONS


def iter_scannable_files(
    root: Path,
    excluded_dirs: Optional[Set[str]] = None,
) -> Iterable[Path]:
    """Yield every scannable file beneath ``root``, skipping excluded directories.

    Symbolic links to directories are not followed: a link out of the project
    tree would put files the user never asked to scan into a report.
    """
    excluded = DEFAULT_EXCLUDED_DIRS if excluded_dirs is None else excluded_dirs
    stack: List[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if entry.name in excluded or entry.is_symlink():
                        continue
                    stack.append(entry)
                elif entry.is_file() and _is_scannable(entry):
                    yield entry
            except OSError:
                continue


def _applicable_rules(
    path: Path,
    rules: Sequence[SecurityRule],
) -> List[SecurityRule]:
    """Return the subset of ``rules`` whose extension filter admits ``path``."""
    applicable: List[SecurityRule] = []
    for rule in rules:
        if rule.extensions and path.suffix not in rule.extensions:
            continue
        # SEC-CONF-004 only means anything inside a dependency manifest.
        if rule.rule_id == "SEC-CONF-004" and not path.name.startswith("requirements"):
            continue
        # SEC-AI-003 only means anything inside a package manifest.
        if rule.rule_id == "SEC-AI-003" and path.name != "package.json":
            continue
        applicable.append(rule)
    return applicable


def scan_file(
    path: Path,
    root: Path,
    rules: Sequence[SecurityRule] = SECURITY_RULES,
) -> Tuple[List[SecurityFinding], int, List[Dict[str, Any]]]:
    """Scan a single file.

    Returns:
        ``(findings, suppressed_count, dropped)``. Secret values are redacted
        before they are placed in any finding, so the return value is always
        safe to print. ``dropped`` records each candidate discarded as a
        placeholder, with the reason, so the report can disclose it instead of
        the scan silently shrinking.
    """
    findings: List[SecurityFinding] = []
    suppressed = 0
    dropped: List[Dict[str, Any]] = []

    applicable = _applicable_rules(path, rules)
    if not applicable:
        return findings, suppressed, dropped

    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return findings, suppressed, dropped
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings, suppressed, dropped

    try:
        relative = str(path.relative_to(root))
    except ValueError:
        relative = str(path)

    lines = text.splitlines()

    # Rules whose pattern spans a line boundary are matched against the whole
    # file, then mapped back to a line number. Scanning those line by line
    # would silently never match, which reads as a clean result.
    multiline_rules = [r for r in applicable if r.multiline]
    line_rules = [r for r in applicable if not r.multiline]

    for rule in multiline_rules:
        for match in rule.pattern.finditer(text):
            line_number = text.count(chr(10), 0, match.start()) + 1
            source_line = lines[line_number - 1] if line_number <= len(lines) else ""
            if SUPPRESSION_MARKER in source_line:
                suppressed += 1
                continue
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    file=relative,
                    line=line_number,
                    evidence=_bounded(match.group(0)),
                    remediation=rule.remediation,
                    false_positives=rule.false_positives,
                    catalog_ids=list(rule.catalog_ids),
                    references=list(rule.references),
                )
            )

    for index, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        line_has_suppression = SUPPRESSION_MARKER in line
        for rule in line_rules:
            match = rule.pattern.search(line)
            if not match:
                continue

            raw_value = ""
            confidence = rule.confidence
            downgrade_reason = ""
            if rule.redact_match:
                raw_value = _matched_value(match, rule)
                verdict, reason = classify_secret_value(raw_value)
                if verdict == VERDICT_DROP:
                    dropped.append(
                        {
                            "rule_id": rule.rule_id,
                            "file": relative,
                            "line": index,
                            "reason": reason,
                        }
                    )
                    continue
                if verdict == VERDICT_LOW:
                    confidence = "LOW"
                    downgrade_reason = reason

            if line_has_suppression:
                suppressed += 1
                continue

            evidence = redact_line(line, [raw_value]) if raw_value else _bounded(line)
            false_positives = rule.false_positives
            if downgrade_reason:
                false_positives = (
                    f"Reported at LOW confidence: {downgrade_reason}. {rule.false_positives}"
                )
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=confidence,
                    file=relative,
                    line=index,
                    evidence=evidence,
                    remediation=rule.remediation,
                    false_positives=false_positives,
                    catalog_ids=list(rule.catalog_ids),
                    references=list(rule.references),
                    confidence_downgraded=bool(downgrade_reason),
                )
            )

    return findings, suppressed, dropped


def _matched_value(match: re.Match, rule: SecurityRule) -> str:
    """Return the sensitive substring a redacting rule captured.

    Prefers the rule's named ``value`` group and falls back to the configured
    capture group, so a rule can be added without changing this function.
    """
    value: Optional[str]
    if "value" in (match.re.groupindex or {}):
        value = match.group("value")
    else:
        value = match.group(rule.capture_group)
    return value or ""


def escape_unprintable(text: str) -> str:
    """Replace characters that cannot be shown safely with their codepoint.

    Two reasons this is not cosmetic:

    - A report printed to a Windows cp1252 console raises UnicodeEncodeError on
      a character outside that codepage, which crashed the whole scan rather
      than reporting the finding.
    - SEC-AI-002 exists precisely because bidirectional and zero-width
      characters are invisible. Echoing them verbatim would reproduce the
      problem in the report; ``<U+202E>`` makes the finding readable.
    """
    out: List[str] = []
    for char in text:
        codepoint = ord(char)
        if char in ("	",):
            out.append(" ")
        elif codepoint < 32 or codepoint == 127:
            out.append(f"<U+{codepoint:04X}>")
        elif codepoint > 126:
            out.append(f"<U+{codepoint:04X}>")
        else:
            out.append(char)
    return "".join(out)


def _bounded(line: str) -> str:
    """Return a trimmed, single-line, length-bounded, printable excerpt.

    A multi-line rule's match spans a line boundary; collapsing the whitespace
    keeps one finding on one report line.
    """
    trimmed = escape_unprintable(" ".join(line.split()))
    if len(trimmed) > MAX_EVIDENCE_CHARS:
        return trimmed[:MAX_EVIDENCE_CHARS] + " ...[truncated]"
    return trimmed


def scan_project(
    root: Path | str,
    categories: Optional[Sequence[str]] = None,
    rule_ids: Optional[Sequence[str]] = None,
    excluded_dirs: Optional[Set[str]] = None,
    exclude_paths: Optional[Sequence[str]] = None,
    use_ignore_file: bool = True,
    max_files: int = 20_000,
    include_paths: Optional[Sequence[str]] = None,
) -> ScanReport:
    """Run the static security scan over a project tree.

    Args:
        root: Project directory to scan.
        categories: Restrict to these scanner categories. ``None`` means all.
        rule_ids: Restrict to these rule identifiers. ``None`` means all.
        excluded_dirs: Override the default excluded directory names.
        exclude_paths: Additional path globs to exclude, relative to ``root``.
        use_ignore_file: Read extra globs from the project's
            ``.veriflow-security-ignore`` file when present.
        max_files: Upper bound on files inspected, so a scan cannot run away on
            an unexpectedly large tree.
        include_paths: Restrict the scan to exactly these relative paths. Used
            by ``--changed``. An empty sequence is treated as "no restriction"
            rather than "scan nothing", because scanning zero files would
            otherwise produce a clean report that looks identical to a scan
            that found no problems.

    Returns:
        A :class:`ScanReport` whose findings are already redacted.

    Raises:
        ValueError: if ``root`` is not a directory, or a filter names an unknown
            category or rule. Filters fail loudly rather than silently matching
            nothing, which would otherwise read as a clean result.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise ValueError(f"Scan root is not a directory: {root_path}")

    selected: List[SecurityRule] = list(SECURITY_RULES)

    if categories:
        unknown = sorted(set(categories) - set(SCANNER_CATEGORIES))
        if unknown:
            raise ValueError(
                f"Unknown security category/categories: {', '.join(unknown)}. "
                f"Available: {', '.join(SCANNER_CATEGORIES)}"
            )
        wanted = set(categories)
        selected = [r for r in selected if r.category in wanted]

    if rule_ids:
        unknown = sorted(set(rule_ids) - set(RULES_BY_ID))
        if unknown:
            raise ValueError(
                f"Unknown security rule id(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(RULES_BY_ID))}"
            )
        wanted_ids = set(rule_ids)
        selected = [r for r in selected if r.rule_id in wanted_ids]

    patterns: List[str] = list(exclude_paths or [])
    if use_ignore_file:
        patterns.extend(load_ignore_patterns(root_path))

    report = ScanReport(
        root=str(root_path),
        rules_applied=[r.rule_id for r in selected],
        exclusion_patterns=patterns,
    )

    include_set: Optional[Set[str]] = None
    if include_paths:
        include_set = {str(p).replace("\\", "/") for p in include_paths}
        report.included_paths = sorted(include_set)

    for path in iter_scannable_files(root_path, excluded_dirs=excluded_dirs):
        if report.files_scanned >= max_files:
            report.limitations.append(
                f"Scan stopped at the {max_files}-file limit; the tree was not fully covered."
            )
            break
        try:
            relative = str(path.relative_to(root_path))
        except ValueError:
            relative = str(path)
        if include_set is not None and relative.replace("\\", "/") not in include_set:
            report.files_outside_scope += 1
            continue
        if _is_excluded(relative, patterns):
            report.excluded_files += 1
            continue
        findings, suppressed, dropped = scan_file(path, root_path, selected)
        report.files_scanned += 1
        report.suppressed += suppressed
        report.findings.extend(findings)
        report.dropped_placeholders.extend(dropped)

    report.findings.sort(
        key=lambda f: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.severity, 4),
            f.file,
            f.line,
        )
    )

    report.limitations.extend(
        [
            "Static pattern analysis only: no project code was executed and no network "
            "request was made. A clean scan is not proof that the project is secure.",
            "The scanner does not perform taint tracking, so it cannot confirm whether a "
            "matched value actually reaches a dangerous sink.",
            "Dependency vulnerability data is not bundled. Run a real auditing tool "
            "(pip-audit, npm audit, cargo audit) for CVE coverage.",
        ]
    )
    if report.excluded_files:
        report.limitations.append(
            f"{report.excluded_files} file(s) were excluded from the scan by "
            f"{len(patterns)} pattern(s) ({', '.join(patterns)}) and were not inspected."
        )
    if report.suppressed:
        report.limitations.append(
            f"{report.suppressed} finding(s) were silenced by an inline "
            f"'{SUPPRESSION_MARKER}' marker and are not listed above."
        )

    return report


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #


def format_skipped_section(report: ScanReport) -> List[str]:
    """Render the 'Suppressed / skipped' block for a scan report.

    Always rendered, even when nothing was skipped. An empty section states
    that explicitly, because the absence of a section reads as "nothing was
    hidden" whether or not that is true, and the whole point of this block is
    that a reader never has to assume.
    """
    lines = ["Suppressed / skipped:"]
    anything = False

    if report.excluded_files:
        anything = True
        patterns = ", ".join(report.exclusion_patterns) or "(none recorded)"
        lines.append(
            f"  - {report.excluded_files} file(s) excluded by ignore pattern(s): {patterns}"
        )
    if report.suppressed:
        anything = True
        lines.append(
            f"  - {report.suppressed} finding(s) silenced by an inline "
            f"'{SUPPRESSION_MARKER}' marker"
        )
    if report.files_skipped:
        anything = True
        lines.append(f"  - {report.files_skipped} file(s) skipped as unreadable or oversized")

    if report.included_paths:
        anything = True
        lines.append(
            f"  - scan restricted to {len(report.included_paths)} path(s); "
            f"{report.files_outside_scope} file(s) in the tree were outside that scope "
            "and were NOT scanned"
        )

    dropped = report.dropped_reason_counts()
    if dropped:
        anything = True
        total = sum(dropped.values())
        lines.append(f"  - {total} candidate value(s) discarded as placeholders:")
        for reason, count in sorted(dropped.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"      {count} x {reason}")

    low = report.low_confidence_count()
    if low:
        anything = True
        lines.append(
            f"  - {low} finding(s) reported at LOW confidence rather than discarded "
            "(placeholder-looking, but high entropy or a known key prefix)"
        )

    if not anything:
        lines.append("  Nothing was skipped, excluded, suppressed or downgraded.")
    return lines


def format_scan_report(report: ScanReport) -> str:
    """Render a scan report as readable text. Output contains no raw secrets."""
    counts = report.severity_counts()
    lines = [
        "=" * 60,
        "Veriflow -- Static Security Scan",
        "=" * 60,
        f"Project Root:   {report.root}",
        f"Files Scanned:  {report.files_scanned}",
        f"Files Excluded: {report.excluded_files}",
        f"Rules Applied:  {len(report.rules_applied)}",
        (
            f"Findings:       CRITICAL={counts['CRITICAL']} | HIGH={counts['HIGH']} | "
            f"MEDIUM={counts['MEDIUM']} | LOW={counts['LOW']} (total {len(report.findings)})"
        ),
        "-" * 60,
    ]

    if not report.findings:
        lines.append("No findings matched the applied rules.")
    else:
        for finding in report.findings:
            lines.append(
                f"[{finding.severity}] {finding.rule_id} ({finding.confidence} confidence)"
            )
            lines.append(f"  {finding.title}")
            lines.append(f"  Location:    {finding.file}:{finding.line}")
            lines.append(f"  Evidence:    {finding.evidence}")
            lines.append(f"  Remediation: {finding.remediation}")
            if finding.catalog_ids:
                lines.append(f"  Catalog:     {', '.join(finding.catalog_ids)}")
            lines.append("")

    lines.append("-" * 60)
    lines.extend(format_skipped_section(report))
    lines.append("-" * 60)
    lines.append("Limitations:")
    for limitation in report.limitations:
        lines.append(f"  - {limitation}")
    lines.extend(
        [
            "-" * 60,
            "Safety Notice:",
            "  Static scanning reduces common, detectable defects. It does not prove the",
            "  absence of vulnerabilities and is not a penetration test.",
            "=" * 60,
        ]
    )
    return "\n".join(lines)


def main() -> int:
    """Command-line entry point for the static scanner alone."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="security_scanner.py",
        description="Veriflow static security scanner (read-only, offline).",
    )
    parser.add_argument("root", nargs="?", default=".", help="Project directory to scan.")
    parser.add_argument("--json", action="store_true", help="Emit a structured JSON report.")
    parser.add_argument(
        "--category",
        action="append",
        dest="categories",
        help=f"Restrict to a category (repeatable). Available: {', '.join(SCANNER_CATEGORIES)}",
    )
    parser.add_argument(
        "--rule",
        action="append",
        dest="rule_ids",
        help="Restrict to a specific rule id (repeatable).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        dest="exclude_paths",
        help="Path glob to exclude, relative to the scan root (repeatable).",
    )
    parser.add_argument(
        "--no-ignore-file",
        action="store_true",
        help=f"Ignore the project's {IGNORE_FILENAME} file.",
    )
    args = parser.parse_args()

    try:
        report = scan_project(
            args.root,
            categories=args.categories,
            rule_ids=args.rule_ids,
            exclude_paths=args.exclude_paths,
            use_ignore_file=not args.no_ignore_file,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_scan_report(report))

    counts = report.severity_counts()
    return 1 if (counts["CRITICAL"] or counts["HIGH"]) else 0


if __name__ == "__main__":
    sys.exit(main())
