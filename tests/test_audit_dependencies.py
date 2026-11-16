"""Tests for dependency license classification and inventory."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_dependencies import (classify_license, cargo_records, load_decisions,
                                lockfile_records, merge_cargo_records, scan_assets, scan_manifests, load_coverage, scan_github_actions, load_upstream_evidence, scan_build_scripts)


class LicenseAuditTests(unittest.TestCase):
    def test_gpl_is_rejected(self):
        self.assertEqual("PROHIBITED_GPL", classify_license("GPL-3.0-only"))

    def test_agpl_is_rejected_before_gpl(self):
        self.assertEqual("PROHIBITED_AGPL", classify_license("AGPL-3.0-or-later"))

    def test_lgpl_is_conditional_category(self):
        self.assertEqual("LGPL", classify_license("LGPL-2.1-only"))

    def test_unknown_license_is_not_pass(self):
        self.assertEqual("UNKNOWN", classify_license(None))

    def test_other_copyleft_requires_review(self):
        self.assertEqual("COPYLEFT_REVIEW", classify_license("MPL-2.0"))

    def test_transitive_dependency_and_features(self):
        metadata = {
            "packages": [
                {"id": "root 1.0.0 (path+file:///root)", "name": "root", "version": "1.0.0"},
                {"id": "a 1.0.0 (registry)", "name": "a", "version": "1.0.0", "license": "MIT",
                 "repository": "https://example.invalid/a"},
                {"id": "b 2.0.0 (registry)", "name": "b", "version": "2.0.0", "license": "Apache-2.0"}
            ],
            "workspace_members": ["root 1.0.0 (path+file:///root)"],
            "resolve": {"nodes": [
                {"id": "root 1.0.0 (path+file:///root)", "deps": [{"pkg": "a 1.0.0 (registry)"}]},
                {"id": "a 1.0.0 (registry)", "features": ["tls"], "deps": [{"pkg": "b 2.0.0 (registry)"}]},
                {"id": "b 2.0.0 (registry)", "deps": []}
            ]}
        }
        rows = cargo_records(metadata, "fixture", {}, "all-features-x86_64")
        self.assertEqual(["a", "b"], [r["name"] for r in rows])
        self.assertEqual(["direct", "transitive"], [r["dependency_type"] for r in rows])
        self.assertEqual(["tls"], rows[0]["enabled_features"])
        self.assertEqual(["all-features-x86_64"], rows[0]["resolution_contexts"])
        self.assertTrue(all(r["status"] == "NEEDS_REVIEW" for r in rows))

    def test_human_approval_registry_requires_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "decisions.json"
            p.write_text(json.dumps({"policy_version": "0.2.0", "decisions": {
                "cargo:lib:1.0.0": {"status": "approved", "reviewer": "reviewer",
                "approved_by": "owner", "evidence": "https://example.invalid/license",
                "scope": "repo/target/release", "conditions": "retain notices"}}}))
            self.assertIn("cargo:lib:1.0.0", load_decisions(p))

    def test_lgpl_requires_verified_conditions(self):
        metadata = {
            "packages": [{"id": "lib 1.0.0 (registry)", "name": "lib", "version": "1.0.0", "license": "LGPL-2.1-only"}],
            "workspace_members": ["root"],
            "resolve": {"nodes": [{"id": "root", "deps": [{"pkg": "lib 1.0.0 (registry)"}]},
                                  {"id": "lib 1.0.0 (registry)", "deps": []}]}
        }
        base = {"status": "approved", "reviewer": "reviewer", "approved_by": "owner",
                "evidence": "license text reviewed", "scope": "target/release", "conditions": "relinking"}
        self.assertEqual("NEEDS_REVIEW", cargo_records(metadata, "fixture",
                         {"cargo:lib:1.0.0": base})[0]["status"])
        verified = dict(base, conditions_verified=True)
        self.assertEqual("APPROVED_WITH_CONDITIONS", cargo_records(metadata, "fixture",
                         {"cargo:lib:1.0.0": verified})[0]["status"])

    def test_merge_cargo_records_unions_features_and_context_evidence(self):
        rows = [
            {"package_id": "pkg 1.0.0", "name": "pkg", "version": "1.0.0",
             "dependency_type": "transitive", "enabled_features": ["tls"],
             "dependency_kinds": ["normal"], "resolution_contexts": ["default"], "targets": [["lib"]], "license": "MIT",
             "license_evidence": []},
            {"package_id": "pkg 1.0.0", "name": "pkg", "version": "1.0.0",
             "dependency_type": "direct", "enabled_features": ["std"],
             "dependency_kinds": ["build"], "resolution_contexts": ["all-features"], "targets": [["bin"]], "license": "MIT",
             "license_evidence": []},
        ]
        merged = merge_cargo_records(rows)
        self.assertEqual(1, len(merged))
        self.assertEqual("direct", merged[0]["dependency_type"])
        self.assertEqual(["std", "tls"], merged[0]["enabled_features"])
        self.assertEqual(["build", "normal"], merged[0]["dependency_kinds"])
        self.assertEqual(["all-features", "default"], merged[0]["resolution_contexts"])

    def test_asset_and_submodule_inventory_is_not_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fonts").mkdir()
            (root / "fonts" / "sample.ttf").write_bytes(b"font-data")
            (root / "vendor" / "lib").mkdir(parents=True)
            (root / "vendor" / "lib" / "lib.c").write_text("/* upstream */", encoding="utf-8")
            (root / "generated").mkdir()
            (root / "generated" / "schema.rs").write_text("// generated", encoding="utf-8")
            (root / "LICENSE").write_text("MPL-2.0", encoding="utf-8")
            (root / ".gitmodules").write_text(
                '[submodule "external"]\n path = external/lib\n url = https://example.invalid/lib.git\n',
                encoding="utf-8")
            assets, provenance = scan_assets(root, "fixture")
            self.assertEqual({"font", "vendored_source", "generated_source"},
                             {item["category"] for item in assets})
            self.assertTrue(all(item["status"] != "PASS" for item in assets))
            self.assertTrue(any(item.get("sha256") for item in provenance))
            self.assertTrue(any(item.get("url") == "https://example.invalid/lib.git" for item in provenance))

    def test_manifest_discovery_finds_multiple_ecosystems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
            (root / "settings.gradle.kts").write_text("", encoding="utf-8")
            found = scan_manifests(root, "fixture")
            self.assertEqual({"python", "gradle"}, {item["ecosystem"] for item in found})

    def test_no_manifest_coverage_requires_human_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "coverage.json"
            record = {"status": "reviewed_no_dependencies", "reviewer": "reviewer",
                      "approved_by": "owner", "evidence": "build inputs reviewed",
                      "scope": "repository main branch", "conditions": "re-review on build changes"}
            p.write_text(json.dumps({"policy_version": "0.2.0",
                                     "repositories": {"Wicofe-Docs": record}}), encoding="utf-8")
            self.assertIn("Wicofe-Docs", load_coverage(p))
            record.pop("evidence")
            p.write_text(json.dumps({"policy_version": "0.2.0",
                                     "repositories": {"Wicofe-Docs": record}}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_coverage(p)

    def test_github_actions_are_build_time_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ".github" / "workflows"
            root.mkdir(parents=True)
            (root / "ci.yml").write_text(
                "steps:\n  - uses: actions/checkout@v4\n  - uses: ./local-action\n"
                "  - uses: docker://ghcr.io/example/tool:1\n", encoding="utf-8")
            rows = scan_github_actions(Path(tmp), "fixture", {})
            self.assertEqual(2, len(rows))
            self.assertTrue(all(row["status"] == "UNKNOWN" for row in rows))
            self.assertTrue(all(row["dependency_type"] == "build-time" for row in rows))

    def test_upstream_action_license_evidence_does_not_auto_approve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ".github" / "workflows"
            root.mkdir(parents=True)
            (root / "ci.yml").write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
            catalog_path = Path(tmp) / "evidence.json"
            commit = "a" * 40
            entry = {"license": "MIT", "source_commit": commit,
                     "upstream_url": "https://github.com/actions/checkout",
                     "license_evidence": [{"url": "https://example.invalid/LICENSE"}]}
            catalog_path.write_text(json.dumps({"policy_version": "0.2.0",
                "dependencies": {"github-actions:actions/checkout:v4": entry}}), encoding="utf-8")
            evidence = load_upstream_evidence(catalog_path)
            row = scan_github_actions(Path(tmp), "fixture", {}, evidence)[0]
            self.assertEqual("MIT", row["license"])
            self.assertEqual(commit, row["source_commit"])
            self.assertFalse(row["ref_is_immutable"])
            self.assertEqual("NEEDS_REVIEW", row["status"])

    def test_build_scripts_surface_downloads_and_container_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build.sh").write_text(
                "# curl is mentioned in a comment\ncurl -fsSL https://example.invalid/tool | sh\n",
                encoding="utf-8")
            (root / "Dockerfile").write_text("FROM debian:stable-slim\n", encoding="utf-8")
            scripts, dependencies = scan_build_scripts(root, "fixture")
            self.assertEqual(2, len(scripts))
            self.assertEqual(1, len(scripts[0]["external_command_matches"]))
            self.assertEqual({"build-script-command", "container-image"},
                             {item["ecosystem"] for item in dependencies})
            self.assertTrue(all(item["status"] == "UNKNOWN" for item in dependencies))

    def test_lockfile_does_not_claim_license(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "Cargo.lock"
            p.write_text('version = 3\n[[package]]\nname = "sample"\nversion = "1.2.3"\n')
            rows = lockfile_records(p, "fixture")
            self.assertEqual("UNKNOWN", rows[0]["status"])
            self.assertIsNone(rows[0]["license"])


if __name__ == "__main__":
    unittest.main()
