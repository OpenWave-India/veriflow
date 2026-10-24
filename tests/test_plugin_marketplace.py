"""
Tests for the Claude Code plugin marketplace manifest.

.claude-plugin/marketplace.json is what makes `claude plugin marketplace add
<owner>/veriflow` followed by `claude plugin install veriflow@veriflow` work
with zero file-copying: this repo is both the marketplace and the single plugin
it offers, so the entry's source is "./" and Claude Code scans `skills/` at the
plugin root automatically.

These tests exist because a typo here breaks that one-command install silently
-- Claude Code validates only when someone actually runs the command, and the
failure it reports ("Plugin couldn't be installed. Try again.") names no cause.
Keep the entry minimal; every field added here has to earn its place.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / ".claude-plugin" / "marketplace.json"


class TestMarketplaceManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_manifest_is_valid_json_at_the_required_path(self):
        """Claude Code only looks at exactly this path, nowhere else."""
        self.assertTrue(MANIFEST_PATH.is_file())

    def test_top_level_required_fields_present(self):
        for field in ("name", "owner", "plugins"):
            with self.subTest(field=field):
                self.assertIn(field, self.manifest)

    def test_owner_has_a_name(self):
        self.assertIn("name", self.manifest["owner"])
        self.assertTrue(self.manifest["owner"]["name"])

    def test_exactly_one_plugin_is_declared(self):
        """This repo is both the marketplace and the one plugin it offers,
        same shape as other single-skill plugin repos."""
        self.assertEqual(len(self.manifest["plugins"]), 1)

    def test_plugin_entry_has_required_fields(self):
        plugin = self.manifest["plugins"][0]
        for field in ("name", "source"):
            with self.subTest(field=field):
                self.assertIn(field, plugin)
                self.assertTrue(plugin[field])

    def test_plugin_name_is_veriflow(self):
        """Determines the install command: `claude plugin install veriflow@veriflow`."""
        self.assertEqual(self.manifest["plugins"][0]["name"], "veriflow")

    def test_plugin_source_is_relative_self_reference(self):
        """source must be "./" — the repo IS the plugin, same as other single-plugin repos."""
        self.assertEqual(self.manifest["plugins"][0]["source"], "./")

    def test_plugin_entry_declares_no_component_paths(self):
        """Component paths (skills/commands/agents/hooks) must start with "./" or Claude Code
        rejects the plugin at install time with "Plugin couldn't be installed".

        Declaring them at all is unnecessary here: skills/ at the plugin root is scanned
        automatically. A bare "skills/veriflow" shipped briefly and broke every install.
        """
        plugin = self.manifest["plugins"][0]
        for field in ("skills", "commands", "agents", "hooks"):
            for path in plugin.get(field, []):
                with self.subTest(field=field, path=path):
                    self.assertTrue(
                        path.startswith("./"),
                        f"{field} path {path!r} must start with './'",
                    )

    def test_version_is_declared_only_in_plugin_json(self):
        """When both files set version, plugin.json wins and validation warns on a mismatch.
        Keeping it in one place removes the chance of drift."""
        self.assertNotIn("version", self.manifest["plugins"][0])

    def test_plugin_json_exists_alongside_marketplace_json(self):
        """plugin.json is required by strict mode (the default).
        Without it, Claude Code can't install the plugin even if the marketplace loads."""
        plugin_json = REPO_ROOT / ".claude-plugin" / "plugin.json"
        self.assertTrue(plugin_json.is_file(), ".claude-plugin/plugin.json is missing")

    def test_skills_directory_exists_at_repo_root(self):
        """Claude Code resolves the skills field path relative to the plugin root."""
        skills_dir = REPO_ROOT / "skills" / "veriflow"
        self.assertTrue(skills_dir.is_dir())
        self.assertTrue((skills_dir / "SKILL.md").is_file())

    def test_plugin_json_name_matches_marketplace_entry(self):
        import json
        plugin_json = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(plugin_json["name"], self.manifest["plugins"][0]["name"])

    def test_plugin_description_states_what_and_when(self):
        """Claude Code matches a user's request against this description to
        decide whether to offer the plugin's skill -- same requirement as a
        SKILL.md description."""
        description = self.manifest["plugins"][0]["description"]
        self.assertGreater(len(description), 60)
        self.assertIn("Use when", description)

    def test_manifest_has_no_xml_tags(self):
        """Same constraint Agent Skills frontmatter enforces on descriptions."""
        text = json.dumps(self.manifest)
        self.assertNotIn("<", text.replace('"$schema"', ""))


if __name__ == "__main__":
    unittest.main()
