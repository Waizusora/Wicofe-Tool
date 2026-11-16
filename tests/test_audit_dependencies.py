"""Tests for dependency license classification and inventory."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_dependencies import classify_license, cargo_records, load_decisions, lockfile_records


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
        rows = cargo_records(metadata, "fixture", {})
        self.assertEqual(["a", "b"], [r["name"] for r in rows])
        self.assertEqual(["direct", "transitive"], [r["dependency_type"] for r in rows])
        self.assertEqual(["tls"], rows[0]["enabled_features"])
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

    def test_lockfile_does_not_claim_license(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "Cargo.lock"
            p.write_text('version = 3\n[[package]]\nname = "sample"\nversion = "1.2.3"\n')
            rows = lockfile_records(p, "fixture")
            self.assertEqual("UNKNOWN", rows[0]["status"])
            self.assertIsNone(rows[0]["license"])


if __name__ == "__main__":
    unittest.main()
