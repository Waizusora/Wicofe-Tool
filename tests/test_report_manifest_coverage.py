"""Tests for repository-wide manifest coverage reporting."""
import json
import tempfile
import unittest
from pathlib import Path

from report_manifest_coverage import build_report, render_markdown


class ManifestCoverageReportTests(unittest.TestCase):
    def test_reports_discovered_manifests_without_attesting_empty_repositories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            (workspace / "Wicofe-Kernel").mkdir(parents=True)
            (workspace / "Wicofe-Kernel" / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
            (workspace / "Wicofe-Doc").mkdir()
            config = root / "repositories.json"
            config.write_text(json.dumps({"repositories": ["Wicofe-Kernel", "Wicofe-Doc"]}), encoding="utf-8")
            report = build_report(config, workspace)
            self.assertEqual(2, report["repository_count"])
            self.assertEqual(1, report["repositories_with_manifests"])
            self.assertEqual("MANIFESTS_DISCOVERED", report["repositories"][0]["coverage"])
            self.assertEqual("NO_SUPPORTED_MANIFEST_FOUND", report["repositories"][1]["coverage"])
            self.assertIn("not attested as dependency-free", " ".join(report["limitations"]))
            self.assertIn("Cargo.toml", render_markdown(report))

    def test_missing_repository_workspace_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "repositories.json"
            config.write_text(json.dumps({"repositories": ["Missing"]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                build_report(config, root / "workspace")


if __name__ == "__main__":
    unittest.main()
