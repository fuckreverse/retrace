import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("collect_licenses.py")
spec = importlib.util.spec_from_file_location("collect_licenses", MODULE_PATH)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class LicenseCollectorTest(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "components": [
                {
                    "name": "Triton",
                    "version": "1.0.1599",
                    "license": "Apache-2.0",
                    "libraries": ["libtriton.dylib"],
                    "license_files": ["LICENSE.txt"],
                },
                {
                    "name": "Z3",
                    "version": "4.15.4",
                    "license": "MIT",
                    "libraries": ["libz3.*.dylib"],
                    "license_files": ["Z3-LICENSE.txt"],
                },
            ]
        }

    def test_rejects_unlisted_bundled_library(self):
        with self.assertRaisesRegex(ValueError, "libunknown.dylib"):
            collector.validate_bundled_libraries(
                ["libtriton.dylib", "libunknown.dylib"], self.manifest["components"]
            )

    def test_accepts_globbed_library_name(self):
        collector.validate_bundled_libraries(
            ["libtriton.dylib", "libz3.4.15.dylib"], self.manifest["components"]
        )

    def test_spdx_policy_accepts_permissive_alternative_and_combination(self):
        allowed = {"Apache-2.0", "MIT", "Unicode-3.0"}
        self.assertTrue(collector.is_license_allowed("MIT OR LGPL-2.1-or-later", allowed))
        self.assertTrue(collector.is_license_allowed("(MIT OR Apache-2.0) AND Unicode-3.0", allowed))
        self.assertFalse(collector.is_license_allowed("GPL-3.0-only", allowed))
        self.assertFalse(collector.is_license_allowed("MIT AND GPL-3.0-only", allowed))

    def test_builds_notice_and_copies_license_texts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "LICENSE.txt").write_text("Apache License", encoding="utf-8")
            (root / "Z3-LICENSE.txt").write_text("MIT License", encoding="utf-8")
            output = root / "output"

            collector.build_native_notices(
                self.manifest["components"], root, output, ["libtriton.dylib", "libz3.4.15.dylib"]
            )

            notice = (output / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
            self.assertIn("Triton 1.0.1599 — Apache-2.0", notice)
            self.assertIn("Z3 4.15.4 — MIT", notice)
            self.assertEqual(
                "Apache License", (output / "native" / "Triton" / "LICENSE.txt").read_text(encoding="utf-8")
            )

    def test_builds_notice_skips_components_not_actually_bundled(self):
        # Z3 has a "libraries" glob but isn't present in this platform's
        # --lib-dir listing (e.g. Triton/YARA weren't built here) — its
        # license_files (which may be a macOS-only Homebrew absolute path)
        # must not be resolved or copied, and it must not appear in the notice.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "LICENSE.txt").write_text("Apache License", encoding="utf-8")
            # Deliberately do NOT create Z3-LICENSE.txt: if build_native_notices
            # tried to resolve Z3's license_files anyway, this would raise
            # FileNotFoundError and fail the test.
            output = root / "output"

            collector.build_native_notices(self.manifest["components"], root, output, ["libtriton.dylib"])

            notice = (output / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
            self.assertIn("Triton 1.0.1599 — Apache-2.0", notice)
            self.assertNotIn("Z3", notice)
            self.assertFalse((output / "native" / "Z3").exists())

    def test_component_without_libraries_glob_is_always_bundled(self):
        always_on = {
            "name": "fmt",
            "version": "10.2.1",
            "license": "MIT",
            "license_files": ["LICENSE"],
        }
        self.assertTrue(collector._component_is_bundled(always_on, []))

    def test_manifest_is_valid_json(self):
        manifest_path = Path(__file__).parents[1] / "licenses" / "native-components.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertGreater(len(data["components"]), 10)
        self.assertNotIn("GraphGridLayout", [item["name"] for item in data["components"]])


if __name__ == "__main__":
    unittest.main()
