"""Tests for repository inventory validation."""
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from validate_repository_inventory import load_expected, validate_inventory

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "Alpha").mkdir()
        (self.root / "Beta").mkdir()
        (self.root / ".git").mkdir()
    def tearDown(self):
        self.temp.cleanup()
    def test_exact_inventory(self):
        self.assertEqual([], validate_inventory(self.root, ["Alpha", "Beta"]))
    def test_missing_checkout(self):
        self.assertEqual(["MISSING_CHECKOUT: Gamma"], validate_inventory(self.root, ["Alpha", "Beta", "Gamma"]))
    def test_unlisted_directory(self):
        self.assertEqual(["UNLISTED_DIRECTORY: Beta"], validate_inventory(self.root, ["Alpha"]))
    def test_allow_extra(self):
        self.assertEqual([], validate_inventory(self.root, ["Alpha"], allow_extra=True))
    def test_duplicate_expected_names(self):
        p = self.root / "inventory.txt"
        p.write_text("Alpha\nAlpha\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_expected(p)

if __name__ == "__main__":
    unittest.main()
