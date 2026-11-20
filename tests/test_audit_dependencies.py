"""Tests for dependency license classification and inventory."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_dependencies import (blocked_dependency_diagnostics, classify_license, cargo_records, load_decisions,
                                lockfile_records, merge_cargo_records, scan_assets, scan_manifests, load_coverage, scan_github_actions, load_upstream_evidence, scan_build_scripts, scan_rust_toolchain)


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

    def test_lgpl_optional_permissive_branch_requires_explicit_selection(self):
        expression = "MIT OR Apache-2.0 OR LGPL-2.1-or-later"
        self.assertEqual("LGPL_OPTIONAL_ALTERNATIVE", classify_license(expression))
        metadata = {
            "packages": [{"id": "r-efi 5.3.0 (registry)", "name": "r-efi", "version": "5.3.0",
                          "license": expression}],
            "workspace_members": ["root"],
            "resolve": {"nodes": [{"id": "root", "deps": [{"pkg": "r-efi 5.3.0 (registry)"}]},
                                  {"id": "r-efi 5.3.0 (registry)", "deps": []}]}
        }
        approval = {"status": "approved", "reviewer": "reviewer", "approved_by": "owner",
                    "evidence": "selected SPDX alternative reviewed", "scope": "WDE nested compositor",
                    "conditions": "preserve selected license notice", "selected_license": "MIT"}
        row = cargo_records(metadata, "fixture", {"cargo:r-efi:5.3.0": approval})[0]
        self.assertEqual("PASS", row["status"])
        self.assertEqual(["MIT", "Apache-2.0"], row["license_alternatives"])
        lgpl = dict(approval, selected_license="LGPL-2.1-or-later", conditions_verified=True)
        row = cargo_records(metadata, "fixture", {"cargo:r-efi:5.3.0": lgpl})[0]
        self.assertEqual("APPROVED_WITH_CONDITIONS", row["status"])

    def test_cargo_lock_checksum_and_incoming_dependency_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.lock").write_text(
                'version = 4\n[[package]]\nname = "lib"\nversion = "1.0.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                'checksum = "0123456789abcdef"\n', encoding="utf-8")
            checksums = __import__("audit_dependencies").cargo_lock_checksums(root)
            metadata = {
                "packages": [
                    {"id": "root", "name": "root", "version": "1.0.0",
                     "dependencies": [{"name": "lib", "req": "^1", "kind": None,
                                       "optional": True, "uses_default_features": False,
                                       "features": ["serde"], "target": "cfg(target_arch = \"aarch64\")"}]},
                    {"id": "lib 1.0.0 (registry)", "name": "lib", "version": "1.0.0",
                     "license": "MIT", "source": "registry+https://github.com/rust-lang/crates.io-index"}
                ],
                "workspace_members": ["root"],
                "resolve": {"nodes": [
                    {"id": "root", "deps": [{"pkg": "lib 1.0.0 (registry)", "name": "lib",
                                              "dep_kinds": [{"kind": None, "target": "cfg(target_arch = \"aarch64\")"}]}]},
                    {"id": "lib 1.0.0 (registry)", "features": [], "deps": []}
                ]}
            }
            row = cargo_records(metadata, "fixture", {}, "all-features-aarch64", checksums)[0]
            self.assertEqual("0123456789abcdef", row["checksum"])
            self.assertEqual("direct", row["dependency_type"])
            self.assertEqual("root", row["required_by"][0]["parent_name"])
            self.assertTrue(row["required_by"][0]["declarations"][0]["optional"])
            self.assertEqual("normal", row["dependency_kinds"][0])

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
            scripts, dependencies = scan_build_scripts(root, "fixture", {}, {})
            self.assertEqual(2, len(scripts))
            build_script = next(item for item in scripts if item["path"] == "build.sh")
            self.assertEqual(1, len(build_script["external_command_matches"]))
            self.assertEqual({"build-script-command", "container-image"},
                             {item["ecosystem"] for item in dependencies})
            self.assertTrue(all(item["status"] == "UNKNOWN" for item in dependencies))

    def test_cargo_license_file_is_hashed_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text("[package]\nname='lib'\nversion='1.0.0'\n", encoding="utf-8")
            (root / "LICENSE").write_text("MIT License fixture", encoding="utf-8")
            metadata = {
                "packages": [{"id": "lib 1.0.0 (registry)", "name": "lib", "version": "1.0.0",
                              "license": "MIT", "license_file": "LICENSE",
                              "manifest_path": str(root / "Cargo.toml")}],
                "workspace_members": ["root"],
                "resolve": {"nodes": [{"id": "root", "deps": [{"pkg": "lib 1.0.0 (registry)"}]},
                                      {"id": "lib 1.0.0 (registry)", "deps": []}]}
            }
            rows = cargo_records(metadata, "fixture", {})
            self.assertTrue(any(item["kind"] == "license_file" and item.get("sha256")
                                for item in rows[0]["license_evidence"]))

    def test_pinned_release_archive_records_license_checksum_and_notices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checksum = "a" * 64
            url = "https://github.com/Limine-Bootloader/Limine/releases/download/v" + "$" + "{LIMINE_VERSION}/limine-binary.tar.xz"
            script = (
                'LIMINE_VERSION="12.9.6"\n'
                f'LIMINE_ARCHIVE_SHA256="{checksum}"\n'
                f'ARCHIVE_URL="{url}"\n'
                'curl -L "$ARCHIVE_URL"\n'
                'NOTICE_DEST="$ISO_ROOT/boot/limine/licenses/limine-12.9.6"\n'
                'cp COPYING 3RDPARTY.md "$NOTICE_DEST/"\n'
                'cp "$LIMINE_DIR/LICENSE" "$NOTICE_DEST/LICENSE"\n'
            )
            (root / "build.sh").write_text(script, encoding="utf-8")
            evidence = {"downloaded-artifact:Limine:12.9.6": {
                "source_commit": "b" * 40, "license": "BSD-2-Clause",
                "upstream_url": "https://github.com/Limine-Bootloader/Limine",
                "release_asset_sha256": checksum,
                "license_evidence": [{"url": "https://example.invalid/COPYING"}],
                "bundled_component_licenses": ["MIT", "BSD-2-Clause"],
                "tag_signature_verified": True,
            }}
            scripts, dependencies = scan_build_scripts(root, "fixture", {}, evidence)
            item = next(dep for dep in dependencies if dep["ecosystem"] == "downloaded-artifact")
            self.assertEqual("12.9.6", item["version"])
            self.assertEqual("b" * 40, item["source_commit"])
            self.assertTrue(item["checksum_verified_against_release_metadata"])
            self.assertIn("3RDPARTY.md", item["distribution"])
            self.assertIn("archive LICENSE", item["distribution"])
            self.assertEqual("NEEDS_REVIEW", item["status"])

    def test_workflow_runner_and_apt_packages_are_inventoried(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ".github" / "workflows"
            root.mkdir(parents=True)
            (root / "ci.yml").write_text(
                "jobs:\n  build:\n    runs-on: ubuntu-26.04\n    steps:\n"
                "      - run: |\n          sudo apt-get update\n"
                "          sudo apt-get install --yes \\\n"
                "            qemu-system-x86=1:10.2.1+ds-1ubuntu3.3 \\\n"
                "            xorriso=1:1.5.6-1.1ubuntu4\n", encoding="utf-8")
            scripts, dependencies = scan_build_scripts(Path(tmp), "fixture", {}, {})
            packages = [item for item in dependencies if item["ecosystem"] == "system-package"]
            self.assertEqual({"qemu-system-x86", "xorriso"}, {item["name"] for item in packages})
            self.assertTrue(any(item["ecosystem"] == "github-runner-image" for item in dependencies))

    def test_prohibited_apt_package_is_rejected_from_license_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ".github" / "workflows"
            root.mkdir(parents=True)
            (root / "ci.yml").write_text(
                "jobs:\n  build:\n    steps:\n      - run: sudo apt-get install --yes qemu-system-x86=1:10.2.1+ds-1ubuntu3.3\n",
                encoding="utf-8")
            key = "system-package:qemu-system-x86:1:10.2.1+ds-1ubuntu3.3"
            evidence = {key: {"license": "GPL-2.0-or-later", "source_revision": "QEMU v10.2.1",
                              "upstream_url": "https://github.com/qemu/qemu",
                              "license_evidence": [{"url": "https://example.invalid/COPYING"}]}}
            _, dependencies = scan_build_scripts(Path(tmp), "fixture", {}, evidence)
            item = next(dep for dep in dependencies if dep["ecosystem"] == "system-package")
            self.assertEqual("REJECTED", item["status"])
            self.assertEqual("GPL-2.0-or-later", item["license"])

    def test_cargo_dependency_alias_matches_hyphenated_package_name(self):
        metadata = {
            "packages": [
                {"id": "root", "name": "root", "version": "1.0.0",
                 "dependencies": [{"name": "r-efi", "req": "^5", "rename": None,
                                   "optional": False, "features": [],
                                   "target": "cfg(target_os = \"uefi\")"}]},
                {"id": "r-efi 5.3.0 (registry)", "name": "r-efi", "version": "5.3.0",
                 "license": "MIT OR Apache-2.0"}
            ],
            "workspace_members": ["root"],
            "resolve": {"nodes": [
                {"id": "root", "deps": [{"pkg": "r-efi 5.3.0 (registry)", "name": "r_efi",
                                          "dep_kinds": [{"kind": None, "target": "cfg(target_os = \"uefi\")"}]}]},
                {"id": "r-efi 5.3.0 (registry)", "features": [], "deps": []}
            ]}
        }
        row = cargo_records(metadata, "fixture", {})[0]
        self.assertEqual("r-efi", row["required_by"][0]["declarations"][0]["name"])
        self.assertEqual("cfg(target_os = \"uefi\")",
                         row["required_by"][0]["declarations"][0]["target"])

    def test_rust_toolchain_manifest_records_exact_version_and_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rust-toolchain.toml").write_text(
                '[toolchain]\nchannel = "1.100.0"\ntargets = ["x86_64-unknown-none", "aarch64-unknown-none"]\n',
                encoding="utf-8")
            evidence = {"rust-toolchain:rustc:1.100.0": {
                "source_commit": "c" * 40, "license": "MIT OR Apache-2.0",
                "upstream_url": "https://github.com/rust-lang/rust",
                "license_evidence": [{"url": "https://example.invalid/LICENSE-MIT"}]}}
            rows = scan_rust_toolchain(root, "fixture", {}, evidence)
            self.assertEqual("1.100.0", rows[0]["version"])
            self.assertEqual(["x86_64-unknown-none", "aarch64-unknown-none"], rows[0]["targets"])
            self.assertEqual("NEEDS_REVIEW", rows[0]["status"])

    def test_lockfile_does_not_claim_license(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "Cargo.lock"
            p.write_text('version = 3\n[[package]]\nname = "sample"\nversion = "1.2.3"\n')
            rows = lockfile_records(p, "fixture")
            self.assertEqual("UNKNOWN", rows[0]["status"])
            self.assertIsNone(rows[0]["license"])


    def test_gpl_or_permissive_alternative_requires_explicit_selection(self):
        expression = "GPL-2+ or BSD-2-clause"
        self.assertEqual("GPL_OPTIONAL_ALTERNATIVE", classify_license(expression))
        self.assertEqual("NEEDS_REVIEW", __import__("audit_dependencies").license_decision_status(expression, None))
        base = {"status": "approved", "reviewer": "reviewer", "approved_by": "owner",
                "evidence": "package copyright reviewed", "scope": "Wicofe CI host",
                "conditions": "use BSD branch only", "selected_license": "BSD-2-clause"}
        self.assertEqual("PASS", __import__("audit_dependencies").license_decision_status(expression, base))
        rejected = dict(base, status="rejected")
        self.assertEqual("REJECTED", __import__("audit_dependencies").license_decision_status(expression, rejected))

    def test_gpl_or_lgpl_alternative_requires_lgpl_conditions(self):
        expression = "GPL-2+ or LGPL-2.1+"
        self.assertEqual("GPL_OPTIONAL_ALTERNATIVE", classify_license(expression))
        decision = {"status": "approved", "reviewer": "reviewer", "approved_by": "owner",
                    "evidence": "Debian copyright reviewed", "scope": "Wicofe build host",
                    "conditions": "provide LGPL source and notices",
                    "selected_license": "LGPL-2.1+"}
        status_fn = __import__("audit_dependencies").license_decision_status
        self.assertEqual("NEEDS_REVIEW", status_fn(expression, decision))
        decision["conditions_verified"] = True
        self.assertEqual("APPROVED_WITH_CONDITIONS", status_fn(expression, decision))

    def test_gpl_and_permissive_license_remains_prohibited(self):
        self.assertEqual("PROHIBITED_GPL", classify_license("GPL-2+ AND MIT"))
        self.assertEqual("PROHIBITED_GPL", classify_license("GPL-2+"))
        self.assertEqual("AGPL_OPTIONAL_ALTERNATIVE", classify_license("AGPL-3.0-only OR MIT"))

    def test_or_later_is_part_of_license_identifier_not_an_alternative(self):
        self.assertEqual("PROHIBITED_GPL", classify_license("GPL-2.0-or-later"))
        self.assertEqual("PROHIBITED_AGPL", classify_license("AGPL-3.0-or-later"))

    def test_blocked_dependency_diagnostics_identify_license_and_origin(self):
        rows = [
            {"ecosystem": "system-package", "name": "qemu-system-x86",
             "version": "1:10.2.1", "license": "GPL-2.0-or-later",
             "status": "REJECTED", "dependency_type": "build-time",
             "license_evidence": [{"path": ".github/workflows/kernel-check.yml", "line": 20}]},
            {"ecosystem": "cargo", "name": "approved", "version": "1.0.0",
             "license": "MIT", "status": "PASS", "dependency_type": "direct"},
        ]
        diagnostics = blocked_dependency_diagnostics(rows)
        self.assertEqual(1, len(diagnostics))
        self.assertIn("qemu-system-x86@1:10.2.1", diagnostics[0])
        self.assertIn("GPL-2.0-or-later", diagnostics[0])
        self.assertIn(".github/workflows/kernel-check.yml:20", diagnostics[0])


    def test_uv_and_poetry_lockfiles_resolve_python_versions_and_hashes(self):
        from audit_dependencies import resolve_non_cargo_manifests
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            uv_content = "\n".join([
                '[[package]]', 'name = "uv-sample"', 'version = "1.2.3"',
                'source = { registry = "https://pypi.org/simple" }',
                'sdist = { hash = "sha256:uvhash" }', ''])
            poetry_content = "\n".join([
                '[[package]]', 'name = "poetry-sample"', 'version = "4.5.6"',
                'files = [{file = "sample.whl", hash = "sha256:poetryhash"}]', ''])
            (root / "uv.lock").write_text(uv_content, encoding="utf-8")
            (root / "poetry.lock").write_text(poetry_content, encoding="utf-8")
            rows, unresolved = resolve_non_cargo_manifests(root, "fixture", {}, {})
            self.assertEqual([], unresolved)
            self.assertEqual({"uv-sample", "poetry-sample"}, {row["name"] for row in rows})
            self.assertEqual({"1.2.3", "4.5.6"}, {row["version"] for row in rows})
            self.assertTrue(all(row["dependency_type"] == "locked" for row in rows))
            self.assertTrue(all(row["status"] == "UNKNOWN" for row in rows))
            self.assertIn("sha256:uvhash", next(r for r in rows if r["name"] == "uv-sample")["checksum"])

    def test_npm_lock_v3_resolves_exact_versions_but_keeps_license_unknown(self):
        from audit_dependencies import resolve_non_cargo_manifests
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({
                "name": "fixture", "dependencies": {"left-pad": "^1.3.0"}}), encoding="utf-8")
            (root / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"left-pad": "^1.3.0"}},
                    "node_modules/left-pad": {"version": "1.3.0",
                                               "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                                               "integrity": "sha512-fixture"}
                }}), encoding="utf-8")
            rows, unresolved = resolve_non_cargo_manifests(root, "fixture", {}, {})
            self.assertEqual([], unresolved)
            self.assertEqual(1, len(rows))
            self.assertEqual(("npm", "left-pad", "1.3.0"),
                             (rows[0]["ecosystem"], rows[0]["name"], rows[0]["version"]))
            self.assertEqual("direct", rows[0]["dependency_type"])
            self.assertEqual("UNKNOWN", rows[0]["status"])
            self.assertEqual("sha512-fixture", rows[0]["checksum"])

    def test_upstream_license_evidence_is_not_an_approval_for_resolved_npm(self):
        from audit_dependencies import resolve_non_cargo_manifests
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/sample": {"version": "1.0.0"}}
            }), encoding="utf-8")
            key = "npm:sample:1.0.0"
            evidence = {key: {"license": "MIT", "source_commit": "a" * 40,
                              "upstream_url": "https://example.invalid/sample",
                              "license_evidence": [{"url": "https://example.invalid/LICENSE"}]}}
            rows, unresolved = resolve_non_cargo_manifests(root, "fixture", {}, evidence)
            self.assertEqual([], unresolved)
            self.assertEqual("NEEDS_REVIEW", rows[0]["status"])

    def test_npm_lock_does_not_infer_license_from_lockfile(self):
        from audit_dependencies import resolve_non_cargo_manifests
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 1, "dependencies": {"legacy": {"version": "1.0.0"}}}),
                encoding="utf-8")
            rows, unresolved = resolve_non_cargo_manifests(root, "fixture", {}, {})
            self.assertEqual([], rows)
            self.assertEqual("only npm package-lock v2/v3 is supported", unresolved[0]["reason"])

    def test_go_json_stream_decoder_handles_adjacent_module_records(self):
        from audit_dependencies import _decode_concatenated_json
        rows = _decode_concatenated_json(
            json.dumps({"Path": "example.com/a", "Version": "v1.0.0"})
            + json.dumps({"Path": "example.com/b", "Version": "v2.0.0"}))
        self.assertEqual(["example.com/a", "example.com/b"], [row["Path"] for row in rows])

    def test_gradle_lockfile_resolves_modules_without_claiming_license(self):
        from audit_dependencies import resolve_non_cargo_manifests
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
            (root / "gradle.lockfile").write_text(
                "org.example:library:2.4.1=runtimeClasspath\n", encoding="utf-8")
            rows, unresolved = resolve_non_cargo_manifests(root, "fixture", {}, {})
            self.assertEqual([], unresolved)
            self.assertEqual(1, len(rows))
            self.assertEqual("gradle", rows[0]["ecosystem"])
            self.assertEqual("org.example:library", rows[0]["name"])
            self.assertEqual("2.4.1", rows[0]["version"])
            self.assertEqual("locked", rows[0]["dependency_type"])
            self.assertEqual("UNKNOWN", rows[0]["status"])

    def test_unimplemented_gradle_manifest_remains_explicitly_unresolved(self):
        from audit_dependencies import resolve_non_cargo_manifests
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
            rows, unresolved = resolve_non_cargo_manifests(root, "fixture", {}, {})
            self.assertEqual([], rows)
            self.assertEqual("gradle", unresolved[0]["ecosystem"])
            self.assertIn("no native resolver adapter", unresolved[0]["reason"])

if __name__ == "__main__":
    unittest.main()
