from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_project_metadata.py"


class MetadataCheckerTests(unittest.TestCase):
    def test_accepts_repository_with_nonempty_baseline_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "sample"
            repo.mkdir()
            (repo / "README.md").write_text("# Sample\n", encoding="utf-8")
            (repo / "LICENSE").write_text("License text\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(repo)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS", result.stdout)

    def test_fails_when_license_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "sample"
            repo.mkdir()
            (repo / "README.md").write_text("# Sample\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(repo)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("LICENSE", result.stdout)

    def test_fails_when_readme_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "sample"
            repo.mkdir()
            (repo / "README.md").write_text("", encoding="utf-8")
            (repo / "LICENSE").write_text("License text\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(repo)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("README.md is empty", result.stdout)


if __name__ == "__main__":
    unittest.main()
