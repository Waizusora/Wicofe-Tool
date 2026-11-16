"""Unit tests for validate_repository_docs.py."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from validate_repository_docs import scan_markdown_file


class RepositoryDocsValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "Repo" / "docs").mkdir(parents=True)
        (self.root / "Other").mkdir()
        (self.root / "Repo" / "README.md").write_text(
            "# Project\n\n[Guide](docs/guide.md#setup)\n", encoding="utf-8"
        )
        (self.root / "Repo" / "docs" / "guide.md").write_text(
            "# Guide\n\n## Setup\n", encoding="utf-8"
        )
        (self.root / "Other" / "README.md").write_text("# Other\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_valid_relative_link_and_heading(self) -> None:
        findings = scan_markdown_file(self.root / "Repo" / "README.md", self.root, [])
        self.assertEqual([], findings)

    def test_missing_file_is_reported(self) -> None:
        path = self.root / "Repo" / "README.md"
        path.write_text("[Missing](docs/missing.md)\n", encoding="utf-8")
        findings = scan_markdown_file(path, self.root, [])
        self.assertEqual(["BROKEN_LINK"], [item.code for item in findings])

    def test_missing_heading_is_reported(self) -> None:
        path = self.root / "Repo" / "README.md"
        path.write_text("[Guide](docs/guide.md#not-there)\n", encoding="utf-8")
        findings = scan_markdown_file(path, self.root, [])
        self.assertEqual(["BROKEN_ANCHOR"], [item.code for item in findings])

    def test_forbidden_term_is_case_insensitive(self) -> None:
        path = self.root / "Repo" / "README.md"
        path.write_text("Legacy package: mypk\n", encoding="utf-8")
        findings = scan_markdown_file(path, self.root, ["MYPK"])
        self.assertEqual(["FORBIDDEN_TERM"], [item.code for item in findings])

    def test_workspace_escape_is_reported(self) -> None:
        path = self.root / "Repo" / "README.md"
        path.write_text("[Outside](../../outside.md)\n", encoding="utf-8")
        findings = scan_markdown_file(path, self.root, [])
        self.assertEqual(["PATH_ESCAPE"], [item.code for item in findings])


if __name__ == "__main__":
    unittest.main()
