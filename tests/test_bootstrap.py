import hashlib
import importlib.util
import io
import json
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "product-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("product_bootstrap", SCRIPT)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.published = self.root / "published"
        self.published.mkdir()
        self.archive = self.published / "ops.tar.gz"
        with tarfile.open(self.archive, "w:gz") as package:
            payload = b"0.2.25\n"
            member = tarfile.TarInfo("bunker-ops-0.2.25/VERSION")
            member.size = len(payload)
            package.addfile(member, io.BytesIO(payload))

        self.manifest = self.published / "release-1.0.0.json"
        self.manifest.write_text(json.dumps({
            "schema_version": "bunker.appliance-release/v1",
            "status": "production",
            "platform_release": {"version": "1.0.0"},
            "distribution": {"ops_source": {
                "version": "0.2.25",
                "source_commit": "a" * 40,
                "path": "ops/bunker-ops_0.2.25_source.tar.gz",
                "artifact": "https://example.invalid/ops.tar.gz",
                "size_bytes": self.archive.stat().st_size,
                "sha256": bootstrap.sha256(self.archive),
            }},
        }), encoding="utf-8")
        self.private = self.published / "private.pem"
        self.public = self.published / "public.pem"
        self.signature = self.published / "release-1.0.0.sig"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(self.private)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout",
                        "-out", str(self.public)], check=True, capture_output=True)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.private),
                        "-out", str(self.signature), str(self.manifest)],
                       check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(self.public),
                              "-outform", "DER"], check=True, capture_output=True).stdout
        self.fingerprint = hashlib.sha256(der).hexdigest()
        self.urls = {
            "https://example.invalid/release-1.0.0.json": self.manifest,
            "https://example.invalid/release-1.0.0.sig": self.signature,
            "https://example.invalid/public.pem": self.public,
            "https://example.invalid/ops.tar.gz": self.archive,
        }
        self.arguments = (
            "https://example.invalid/release-1.0.0.json",
            "https://example.invalid/release-1.0.0.sig",
            "https://example.invalid/public.pem",
            self.root / "cache", self.root / "releases",
        )

    def download(self, url, destination, *, resume):
        shutil.copyfile(self.urls[url], destination)

    def test_acceptance_paths_allow_service_traversal_without_listing(self):
        base = self.root / "acceptance"
        base.mkdir(mode=0o700)
        target = base / "rc5"
        bootstrap.prepare_acceptance_service_paths(target)
        for path in (base, target, target / "opt", target / "opt/bunker",
                     target / "opt/bunker/platform", target / "opt/bunker/platform/bin",
                     target / "var", target / "var/lib"):
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertTrue(mode & stat.S_IXOTH, path)
            self.assertFalse(mode & stat.S_IROTH, path)
        bootstrap.prepare_acceptance_service_paths(target)

    def test_acceptance_path_symlink_is_rejected(self):
        base = self.root / "acceptance"
        base.mkdir(mode=0o700)
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (base / "rc5").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "symbolic link"):
            bootstrap.prepare_acceptance_service_paths(base / "rc5")
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)

    def test_signed_bootstrap_reuses_exact_source_and_rejects_local_drift(self):
        with patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint), \
                patch.object(bootstrap, "curl", side_effect=self.download):
            target = bootstrap.bootstrap(*self.arguments)
            self.assertEqual((target / "VERSION").read_text(), "0.2.25\n")
            self.assertEqual(bootstrap.bootstrap(*self.arguments), target)
            (target / "VERSION").write_text("modified\n")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "installed Ops source differs"):
                bootstrap.bootstrap(*self.arguments)

    def test_configure_uses_signed_11_manifest_and_stages_only_chooser(self):
        script = b"""import argparse, json
from pathlib import Path
cli = argparse.ArgumentParser()
for name in ("manifest", "signature", "public-key", "profile", "choices-json"):
    cli.add_argument("--" + name, type=Path)
cli.add_argument("--non-interactive", action="store_true")
args = cli.parse_args()
assert args.non_interactive and args.signature.is_file() and args.public_key.is_file()
assert json.loads(args.manifest.read_bytes())["platform_release"]["version"] == "1.1.0"
args.profile.write_text(args.choices_json.read_text())
"""
        with tarfile.open(self.archive, "w:gz") as package:
            for name, payload in (("VERSION", b"0.2.25\n"), ("scripts/install/product-setup.py", script)):
                entry = tarfile.TarInfo("bunker-ops-0.2.25/" + name)
                entry.size = len(payload)
                package.addfile(entry, io.BytesIO(payload))
        document = json.loads(self.manifest.read_bytes())
        document.update(schema_version="bunker.appliance-release/v2", platform_release={"version": "1.1.0"},
                        installation_catalog={"schema_version": "bunker.install-catalog/v2"})
        document["distribution"]["ops_source"].update(size_bytes=self.archive.stat().st_size,
                                                      sha256=bootstrap.sha256(self.archive))
        self.manifest.write_text(json.dumps(document))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.private),
                        "-out", str(self.signature), str(self.manifest)], check=True, capture_output=True)
        choices = self.root / "selected models.json"
        choices.write_text('{"models":["alpha","beta"]}')
        profile = self.root / "profile.json"
        with patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint), \
                patch.object(bootstrap, "curl", side_effect=self.download):
            target = bootstrap.configure_product(*self.arguments, profile, non_interactive=True,
                                                 choices=choices, probe_download=False)
            self.assertTrue((target / "scripts/install/product-setup.py").is_file())
            self.assertEqual(profile.read_text(), choices.read_text())
            self.assertFalse((self.root / "cache/trust").exists())
            self.assertFalse((target / "scripts/install/__pycache__").exists())
            profile.unlink()
            self.manifest.write_text("{}")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "signature verification failed"):
                bootstrap.configure_product(*self.arguments, profile, non_interactive=True,
                                            choices=choices, probe_download=False)
            self.assertFalse(profile.exists())

    def test_configure_refuses_even_a_validly_signed_10_release(self):
        profile = self.root / "profile.json"
        with patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint), \
                patch.object(bootstrap, "curl", side_effect=self.download) as fetch:
            with self.assertRaisesRegex(bootstrap.BootstrapError, "not a production Bunker AI 1.1.0"):
                bootstrap.configure_product(*self.arguments, profile, non_interactive=False,
                                            choices=None, probe_download=False)
            self.assertEqual(fetch.call_count, 3)
            self.assertFalse(profile.exists())

    def test_bad_key_or_signature_stops_before_ops_download(self):
        fetched = []

        def download(url, destination, *, resume):
            fetched.append(url)
            self.download(url, destination, resume=resume)

        with patch.object(bootstrap, "curl", side_effect=download):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "fingerprint mismatch"):
                bootstrap.bootstrap(*self.arguments)
            self.assertNotIn("https://example.invalid/ops.tar.gz", fetched)

            self.manifest.write_text("{}", encoding="utf-8")
            with patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "signature verification failed"):
                    bootstrap.bootstrap(*self.arguments)
            self.assertNotIn("https://example.invalid/ops.tar.gz", fetched)
        self.assertFalse((self.root / "releases").exists())

    def test_corrupted_partial_retries_from_zero_without_replacing_cache(self):
        item = json.loads(self.manifest.read_text())["distribution"]["ops_source"]
        target = self.root / "cache" / item["path"]
        target.parent.mkdir(parents=True)
        target.write_bytes(b"previous")
        partial = target.with_name(target.name + ".part")
        partial.write_bytes(b"stale")
        attempts = []

        def download(url, destination, *, resume):
            attempts.append(destination.exists())
            if len(attempts) == 1:
                destination.write_bytes(b"corrupt")
            else:
                shutil.copyfile(self.archive, destination)

        with patch.object(bootstrap, "curl", side_effect=download):
            self.assertEqual(bootstrap.fetch_ops(item, self.root / "cache"), target)
        self.assertEqual(attempts, [True, False])
        self.assertEqual(target.read_bytes(), self.archive.read_bytes())

    def test_trust_download_failure_preserves_previous_file(self):
        destination = self.root / "cache" / "release-1.0.0.json"
        destination.parent.mkdir()
        destination.write_bytes(b"previous")
        with patch.object(bootstrap, "curl", side_effect=subprocess.CalledProcessError(22, ["curl"])):
            with self.assertRaises(subprocess.CalledProcessError):
                bootstrap.fetch_trust_file(self.arguments[0], destination)
        self.assertEqual(destination.read_bytes(), b"previous")
        self.assertFalse(destination.with_name(destination.name + ".part").exists())


if __name__ == "__main__":
    unittest.main()
