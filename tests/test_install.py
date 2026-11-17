import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGES = ("--prepare", "--install-platform", "--initialize-n8n", "--activate-modules")


class InstallEntryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copy2(ROOT / "install.sh", self.root / "install.sh")
        shutil.copy2(ROOT / "product-bootstrap.py", self.root / "product-bootstrap.py")
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.tools / "id").write_text("#!/bin/sh\necho 0\n")
        (self.tools / "python3").write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGUMENT_LOG\"\n"
            "shasum -a 256 \"$1\" > \"$COPY_HASH_LOG\"\n"
        )
        (self.tools / "sha256sum").write_text(
            "#!/bin/sh\nread expected file\nactual=$(shasum -a 256 \"$file\") || exit 1\n"
            "[ \"${actual%% *}\" = \"$expected\" ] || exit 1\n"
            "[ -z \"${TAMPER_SOURCE:-}\" ] || printf 'tampered\\n' > \"$TAMPER_SOURCE\"\n"
        )
        for tool in self.tools.iterdir():
            tool.chmod(0o755)
        self.log = self.root / "arguments"
        self.copy_hash_log = self.root / "copy-hash"
        self.env = dict(os.environ, PATH=f"{self.tools}:{os.environ['PATH']}",
                        ARGUMENT_LOG=str(self.log), COPY_HASH_LOG=str(self.copy_hash_log))

    def run_install(self, *args):
        return subprocess.run(["sh", str(self.root / "install.sh"), *args],
                              text=True, capture_output=True, env=self.env)

    def test_each_stage_invokes_only_pinned_local_bootstrap(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                self.log.unlink(missing_ok=True)
                result = self.run_install(stage)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = self.log.read_text().splitlines()
                self.assertNotEqual(Path(arguments[0]).resolve(), (self.root / "product-bootstrap.py").resolve())
                self.assertTrue(arguments[0].startswith("/tmp/bunker-bootstrap."))
                self.assertFalse(Path(arguments[0]).exists())
                self.assertEqual(arguments[-1], stage)
                self.assertIn("--signature-url", arguments)
                self.assertIn("--public-key-url", arguments)

    def test_source_replacement_after_copy_cannot_change_executed_bytes(self):
        self.env["TAMPER_SOURCE"] = str(self.root / "product-bootstrap.py")
        result = self.run_install("--prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "product-bootstrap.py").read_text(), "tampered\n")
        self.assertTrue(self.copy_hash_log.read_text().startswith(
            "939a33520f9b92e2a3f58fb4d3e687eb3cc5504e2ad049fa1222a2fbb6bfbcad "
        ))
        self.assertFalse(Path(self.log.read_text().splitlines()[0]).exists())

    def test_missing_or_changed_bootstrap_never_executes(self):
        bootstrap = self.root / "product-bootstrap.py"
        bootstrap.write_text("print('untrusted')\n")
        result = self.run_install("--prepare")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertFalse(self.log.exists())
        bootstrap.unlink()
        result = self.run_install("--prepare")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing regular bundled", result.stderr)
        self.assertFalse(self.log.exists())

    def test_invalid_stage_never_executes(self):
        result = self.run_install("--unknown")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())

    def test_candidate_tag_uses_only_the_public_prerelease_path(self):
        self.env["BUNKER_RELEASE_TAG"] = "v1.0.0-rc2"
        result = self.run_install("--prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.log.read_text().splitlines()
        self.assertIn("https://github.com/karpizin/bunker-installer/releases/download/"
                      "v1.0.0-rc2/release-1.0.0.json", arguments)

    def test_invalid_release_tag_never_executes(self):
        for value in ("v1.0.0-rc0", "v1.0.0-rc1/../../other", "https://example.invalid/x"):
            with self.subTest(value=value):
                self.log.unlink(missing_ok=True)
                self.env["BUNKER_RELEASE_TAG"] = value
                result = self.run_install("--prepare")
                self.assertEqual(result.returncode, 2)
                self.assertIn("Invalid BUNKER_RELEASE_TAG", result.stderr)
                self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
