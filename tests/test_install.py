import hashlib
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
        self.bootstrap_hash = hashlib.sha256((ROOT / "product-bootstrap.py").read_bytes()).hexdigest()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.tools / "id").write_text("#!/bin/sh\necho 0\n")
        (self.tools / "python3").write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGUMENT_LOG\"\n"
            "printf '%s\\n' \"${PYTHONDONTWRITEBYTECODE:-}\" > \"$BYTECODE_LOG\"\n"
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
        self.bytecode_log = self.root / "bytecode"
        self.env = dict(os.environ, PATH=f"{self.tools}:{os.environ['PATH']}",
                        ARGUMENT_LOG=str(self.log), COPY_HASH_LOG=str(self.copy_hash_log),
                        BYTECODE_LOG=str(self.bytecode_log))

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
                self.assertEqual(self.bytecode_log.read_text(), "1\n")

    def test_source_replacement_after_copy_cannot_change_executed_bytes(self):
        self.env["TAMPER_SOURCE"] = str(self.root / "product-bootstrap.py")
        result = self.run_install("--prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "product-bootstrap.py").read_text(), "tampered\n")
        self.assertTrue(self.copy_hash_log.read_text().startswith(self.bootstrap_hash + " "))
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

    def test_configure_uses_isolated_11_catalog_and_passes_choices_as_data(self):
        self.env.update(BUNKER_RELEASE_TAG="v1.1.0-rc1", BUNKER_ACCEPTANCE_ID="release-110-rc1")
        result = self.run_install("--configure", "--non-interactive", "--choices-json", "/tmp/with spaces.json",
                                  "--space-root", "/mnt/target volume", "--min-free-after-bytes", "85899345920")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.log.read_text().splitlines()
        self.assertIn("https://github.com/karpizin/bunker-installer/releases/download/"
                      "v1.1.0-rc1/release-1.1.0.json", arguments)
        self.assertIn("/var/lib/bunker-acceptance-11/release-110-rc1/opt/bunker/selection-releases", arguments)
        self.assertIn("/var/lib/bunker-acceptance-11/release-110-rc1/var/lib/bunker-installer/1.1.0/selection.json", arguments)
        self.assertIn("--choices-json=/tmp/with spaces.json", arguments)
        self.assertIn("--space-root=/mnt/target volume", arguments)
        self.assertIn("--min-free-after-bytes=85899345920", arguments)
        self.assertIn("--non-interactive", arguments)
        self.assertNotIn("--install-root", arguments)
        self.assertNotIn("--activate-modules", arguments)

    def test_configure_does_not_cross_release_or_allow_bootstrap_overrides(self):
        for tag, args in (
            ("v1.0.0", ("--configure",)),
            ("v1.1.0", ("--install-platform",)),
            ("v1.1.0", ("--configure", "--manifest-url", "https://example.invalid")),
            ("v1.1.0", ("--configure", "--choices-json", "/tmp/options")),
            ("v1.1.0", ("--configure", "--min-free-after-bytes", "-1")),
            ("v1.0.0", ("--prepare", "--min-free-after-bytes", "0")),
            ("v1.1.0", ("--configure", "--space-root", "/target", "--disk-layout-json", "/plan")),
        ):
            with self.subTest(tag=tag, args=args):
                self.env["BUNKER_RELEASE_TAG"] = tag
                result = self.run_install(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.log.exists())

    def test_configure_forwards_disk_layout_path_as_data(self):
        result = self.run_install("--configure", "--disk-layout-json", "/tmp/disk plan.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--disk-layout-json=/tmp/disk plan.json", self.log.read_text().splitlines())

    def test_prepare_profile_only_accepts_isolated_11_candidate(self):
        self.env.update(BUNKER_RELEASE_TAG="v1.1.0-rc1", BUNKER_ACCEPTANCE_ID="release-110-rc1")
        result = self.run_install("--prepare-profile")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.log.read_text().splitlines()
        self.assertEqual(arguments[-2:], ["--prepare-profile", "release-110-rc1"])
        self.assertIn("https://github.com/karpizin/bunker-installer/releases/download/"
                      "v1.1.0-rc1/release-1.1.0.json", arguments)
        self.assertNotIn("--install-root", arguments)
        self.log.unlink()
        for prefix, tag, extras in (
            ("", "v1.1.0-rc1", []),
            ("release-100-rc22", "v1.1.0-rc1", []),
            ("release-110-rc1", "v1.0.0-rc22", []),
            ("release-110-rc1", "v1.1.0-rc1", ["--profile", "other.json"]),
        ):
            with self.subTest(prefix=prefix, tag=tag, extras=extras):
                self.env.update(BUNKER_ACCEPTANCE_ID=prefix, BUNKER_RELEASE_TAG=tag)
                self.assertEqual(self.run_install("--prepare-profile", *extras).returncode, 2)
                self.assertFalse(self.log.exists())

    def test_geo_uses_local_11_cache_and_preserves_argument_boundaries(self):
        self.env.update(BUNKER_ACCEPTANCE_ID="release-110-geo")
        result = self.run_install("--geo", "recover", "/tmp/release trust", "--", "--profile", "/tmp/my profile")
        self.assertEqual(result.returncode, 0, result.stderr)
        opts = self.log.read_text().splitlines()[1:]
        root = "/var/lib/bunker-acceptance-11/release-110-geo"
        self.assertEqual(opts, ["--geo", "recover", "--ops-cache", root + "/var/cache/bunker-ai/1.1.0",
                                "--ops-root", root + "/opt/bunker/selection-releases",
                                "--trust-dir", "/tmp/release trust", "--", "--profile", "/tmp/my profile"])

    def test_offline_flag_is_forwarded_only_for_saved_11_profile_staging(self):
        self.env.update(BUNKER_ACCEPTANCE_ID="release-110-offline", BUNKER_RELEASE_TAG="v1.1.0-rc1")
        result = self.run_install("--prepare-profile", "--offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text().splitlines()[-3:],
                         ["--prepare-profile", "release-110-offline", "--offline"])
        self.log.unlink()
        for args in (("--configure", "--offline"), ("--prepare", "--offline"),
                     ("--prepare-profile", "--offline", "--offline")):
            self.assertEqual(self.run_install(*args).returncode, 2)
            self.assertFalse(self.log.exists())

    def test_wikipedia_passes_only_prepared_profile_ids_for_the_candidate(self):
        self.env.update(BUNKER_ACCEPTANCE_ID="release-110-rc1")
        result = self.run_install("--wikipedia", "recover", "a" * 64, "b" * 64)
        self.assertEqual(result.returncode, 0, result.stderr)
        opts = self.log.read_text().splitlines()[1:]
        root = "/var/lib/bunker-acceptance-11/release-110-rc1"
        self.assertEqual(opts, ["--wikipedia", "recover", "--acceptance-id", "release-110-rc1",
                                "--ops-cache", root + "/var/cache/bunker-ai/1.1.0",
                                "--ops-root", root + "/opt/bunker/selection-releases",
                                "--prepared-profile", "a" * 64, "--rollback-prepared", "b" * 64])
        self.log.unlink()
        for acceptance, options in (
            ("release-110-rc1", ("activate", "/tmp/profile")),
            ("release-110-rc1", ("restart", "a" * 64)),
            ("release-110-rc1", ("start-voice", "a" * 64, "b" * 64)),
            ("release-110-rc1", ("verify-chat", "a" * 64, "b" * 64)),
            ("release-110-rc1", ("start-chat", "a" * 64, "b" * 64)),
            ("release-110-rc1", ("install-base", "a" * 64, "b" * 64)),
            ("release-110-rc1", ("activate", "a" * 64, "--ops-root", "/tmp/other")),
            ("release-100-rc22", ("recover", "a" * 64)),
        ):
            self.env["BUNKER_ACCEPTANCE_ID"] = acceptance
            self.assertEqual(self.run_install("--wikipedia", *options).returncode, 2)
            self.assertFalse(self.log.exists())

    def test_base_setup_routes_through_the_prepared_signed_profile(self):
        self.env.update(BUNKER_ACCEPTANCE_ID="release-110-rc1")
        for action in ("setup-index", "start-voice", "start-operator", "verify-chat", "attach-chat",
                       "start-chat", "install-base"):
            with self.subTest(action=action):
                result = self.run_install("--wikipedia", action, "a" * 64)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = self.log.read_text().splitlines()
                self.assertEqual(arguments[1:3], ["--wikipedia", action])
                self.assertIn("/var/lib/bunker-acceptance-11/release-110-rc1/var/cache/bunker-ai/1.1.0", arguments)
                self.assertNotIn("--rollback-prepared", arguments)

    def test_prepared_geo_routes_to_the_isolated_acceptance_root(self):
        identity = "a" * 64
        result = self.run_install("--geo", "activate", f"prepared:{identity}", "--")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())
        self.env.update(BUNKER_ACCEPTANCE_ID="release-110-geo")
        result = self.run_install("--geo", "recover", f"prepared:{identity}", "--", "--rollback-prepared=" + "b" * 64)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text().splitlines()[-6:], [
            "--prepared-profile", identity, "--acceptance-id", "release-110-geo", "--", "--rollback-prepared=" + "b" * 64])

    def test_geo_refuses_invalid_action_or_legacy_acceptance_root(self):
        self.assertEqual(self.run_install("--geo", "down", "/trust", "--").returncode, 2)
        self.assertEqual(self.run_install("--geo", "restart", "/trust").returncode, 2)
        self.env["BUNKER_ACCEPTANCE_ID"] = "release-100-rc22"
        result = self.run_install("--geo", "activate", "/trust", "--")
        self.assertEqual(result.returncode, 2)
        self.assertIn("lowercase release-110-* ID", result.stderr)
        self.assertFalse(self.log.exists())

    def test_locale_is_only_forwarded_to_configure_and_uses_canonical_ids(self):
        for locale in ("en", "ru", "zh-Hans"):
            with self.subTest(locale=locale):
                result = self.run_install("--configure", "--locale", locale)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"--locale={locale}", self.log.read_text().splitlines())
        self.log.unlink()
        for args in (("--configure", "--locale"), ("--configure", "--locale", "zh-Hant"),
                     ("--configure", "--locale", "../../ru"), ("--prepare", "--locale", "ru")):
            with self.subTest(args=args):
                self.assertEqual(self.run_install(*args).returncode, 2)
                self.assertFalse(self.log.exists())

    def test_acceptance_id_routes_all_paths_to_isolated_tree(self):
        self.env["BUNKER_ACCEPTANCE_ID"] = "release-100-rc3"
        result = self.run_install("--prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.log.read_text().splitlines()
        root = "/var/lib/bunker-acceptance/release-100-rc3"
        for path in ("var/cache/bunker-ai/1.0.0", "opt/bunker/releases",
                     "opt/bunker/module-sources", "opt/bunker",
                     "var/lib/bunker-platform"):
            self.assertIn(f"{root}/{path}", arguments)

    def test_unsafe_acceptance_id_never_executes(self):
        for value in ("../current", "a/b", ".hidden"):
            with self.subTest(value=value):
                self.log.unlink(missing_ok=True)
                self.env["BUNKER_ACCEPTANCE_ID"] = value
                result = self.run_install("--prepare")
                self.assertEqual(result.returncode, 2)
                self.assertIn("Invalid BUNKER_ACCEPTANCE_ID", result.stderr)
                self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
