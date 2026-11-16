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
        )
        (self.tools / "sha256sum").write_text(
            "#!/bin/sh\nread expected file\nactual=$(shasum -a 256 \"$file\") || exit 1\n"
            "[ \"${actual%% *}\" = \"$expected\" ]\n"
        )
        for tool in self.tools.iterdir():
            tool.chmod(0o755)
        self.log = self.root / "arguments"
        self.env = dict(os.environ, PATH=f"{self.tools}:{os.environ['PATH']}", ARGUMENT_LOG=str(self.log))

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
                self.assertEqual(Path(arguments[0]).resolve(), (self.root / "product-bootstrap.py").resolve())
                self.assertEqual(arguments[-1], stage)
                self.assertIn("--signature-url", arguments)
                self.assertIn("--public-key-url", arguments)

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


if __name__ == "__main__":
    unittest.main()
