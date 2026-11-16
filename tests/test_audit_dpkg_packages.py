import tempfile
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from audit_dpkg_packages import copyright_metadata, read_package_delta


class DpkgAuditTests(unittest.TestCase):
    def test_reads_package_delta_and_hashes_copyright(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            delta = root / "packages.tsv"
            delta.write_text("libfoo:amd64\tNEW\t1.2.3\n", encoding="utf-8")
            packages = read_package_delta(delta)
            self.assertEqual("libfoo", packages[0]["name"])
            self.assertEqual("amd64", packages[0]["architecture"])
            copyright = root / "usr/share/doc/libfoo/copyright"
            copyright.parent.mkdir(parents=True)
            copyright.write_text(
                "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
                "Source: https://example.invalid/libfoo\n"
                "Files: *\n"
                "License: BSD-3-clause\n", encoding="utf-8")
            item = copyright_metadata(root, packages[0])
            self.assertEqual("NEEDS_REVIEW", item["status"])
            self.assertTrue(item["license_evidence"][0]["sha256"])

    def test_gpl_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = {"name": "qemu-test", "version": "1.0", "old_version": "NEW",
                       "architecture": None}
            copyright = root / "usr/share/doc/qemu-test/copyright"
            copyright.parent.mkdir(parents=True)
            copyright.write_text("Source: https://example.invalid/qemu\nFiles: *\nLicense: GPL-2+\n",
                                 encoding="utf-8")
            item = copyright_metadata(root, package)
            self.assertEqual("REJECTED", item["status"])

    def test_secondary_gpl_notice_requires_review_not_automatic_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = {"name": "libmixed", "version": "1.0", "old_version": "NEW",
                       "architecture": None}
            copyright = root / "usr/share/doc/libmixed/copyright"
            copyright.parent.mkdir(parents=True)
            copyright.write_text(
                "Files: *\nLicense: LGPL-2.1+\n\n"
                "Files: tests/*\nLicense: GPL-2+\n", encoding="utf-8")
            item = copyright_metadata(root, package)
            self.assertEqual("NEEDS_REVIEW", item["status"])
            self.assertEqual("MIXED_REVIEW", item["license_category"])

    def test_missing_copyright_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            item = copyright_metadata(Path(tmp), {"name": "missing", "version": "1",
                                                    "old_version": "NEW", "architecture": None})
            self.assertEqual("UNKNOWN", item["status"])


    def test_gpl_or_bsd_alternative_requires_human_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = {"name": "libdual", "version": "1.0", "old_version": "NEW",
                       "architecture": None}
            copyright = root / "usr/share/doc/libdual/copyright"
            copyright.parent.mkdir(parents=True)
            copyright.write_text(
                "Source: https://example.invalid/libdual\n"
                "Files: *\nLicense: GPL-2+ or BSD-2-clause\n",
                encoding="utf-8")
            item = copyright_metadata(root, package)
            self.assertEqual("NEEDS_REVIEW", item["status"])
            self.assertEqual("GPL_OPTIONAL_ALTERNATIVE", item["license_category"])
            self.assertEqual(["BSD-2-clause"], item["primary_license_alternatives"])
            self.assertEqual(["BSD-2-clause"], item["primary_license_nonprohibited_alternatives"])

    def test_gpl_or_lgpl_alternative_is_not_auto_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = {"name": "libdual", "version": "1.0", "old_version": "NEW",
                       "architecture": None}
            copyright = root / "usr/share/doc/libdual/copyright"
            copyright.parent.mkdir(parents=True)
            copyright.write_text(
                "Files: *\nLicense: GPL-2+ or LGPL-2.1+\n",
                encoding="utf-8")
            item = copyright_metadata(root, package)
            self.assertEqual("NEEDS_REVIEW", item["status"])
            self.assertEqual(["LGPL-2.1+"], item["primary_license_nonprohibited_alternatives"])
            self.assertEqual([], item["primary_license_alternatives"])

    def test_gpl_and_mit_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = {"name": "librequired", "version": "1.0", "old_version": "NEW",
                       "architecture": None}
            copyright = root / "usr/share/doc/librequired/copyright"
            copyright.parent.mkdir(parents=True)
            copyright.write_text("Files: *\nLicense: GPL-2+ and MIT\n", encoding="utf-8")
            item = copyright_metadata(root, package)
            self.assertEqual("REJECTED", item["status"])

if __name__ == "__main__":
    unittest.main()
