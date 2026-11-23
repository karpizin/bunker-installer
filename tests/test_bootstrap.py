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
from contextlib import redirect_stdout
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
        self.root = Path(self.temporary.name).resolve()
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

    def local_geo_fixture(self, script_name="product-geo-service.py", script=None, extra_scripts=()):
        if script is None:
            script = b"""import json, sys
from pathlib import Path
action = sys.argv[1]
opts = dict(zip(sys.argv[2::2], sys.argv[3::2]))
assert Path(opts["--signature"]).is_file()
assert Path(opts["--public-key"]).is_file()
manifest = json.loads(Path(opts["--manifest"]).read_bytes())
assert manifest["platform_release"]["version"] == "1.1.0"
Path(opts["--profile"]).write_text(action)
"""
        with tarfile.open(self.archive, "w:gz") as package:
            for name, payload in (("VERSION", b"0.2.25\n"), ("scripts/install/" + script_name, script), *extra_scripts):
                entry = tarfile.TarInfo("bunker-ops-0.2.25/" + name)
                entry.size = len(payload)
                package.addfile(entry, io.BytesIO(payload))
        document = json.loads(self.manifest.read_bytes())
        document.update(schema_version="bunker.appliance-release/v2", platform_release={"version": "1.1.0"},
                        installation_catalog={"schema_version": "bunker.install-catalog/v2"},
                        target_host={"disk_policy": "platform_plus_selected_catalog", "platform_disk_budget": {}})
        item = document["distribution"]["ops_source"]
        item.update(size_bytes=self.archive.stat().st_size, sha256=bootstrap.sha256(self.archive))
        trust = self.root / "local trust"
        trust.mkdir()
        manifest = trust / "release-1.1.0.json"
        manifest.write_text(json.dumps(document))
        signature = trust / "release-1.1.0.sig"
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.private),
                        "-out", str(signature), str(manifest)], check=True, capture_output=True)
        shutil.copyfile(self.public, trust / "bunker-product-release-2026.pem")
        archive = self.arguments[3] / item["path"]
        archive.parent.mkdir(parents=True)
        shutil.copyfile(self.archive, archive)
        return trust, archive

    def test_prepare_profile_bootstraps_only_the_verified_11_preparer(self):
        trust, _ = self.local_geo_fixture("product-11-prepare.py", b"""import json, sys
from pathlib import Path
opts = dict(zip(sys.argv[1::2], sys.argv[2::2]))
assert Path(opts["--signature"]).is_file()
assert Path(opts["--public-key"]).is_file()
assert json.loads(Path(opts["--manifest"]).read_bytes())["platform_release"]["version"] == "1.1.0"
assert json.loads(Path(opts["--profile"]).read_bytes())["selection"] == {"name": "saved"}
assert Path(opts["--source-root"]) == Path(__file__).parents[2]
assert int(opts["--min-free-after-bytes"]) == 80 * 1024**3
print(json.dumps({"ok": True, "activated": False, "options": opts, "platform_inputs": {"transport_only": True}}))
""")
        self.urls[self.arguments[0]] = trust / "release-1.1.0.json"
        self.urls[self.arguments[1]] = trust / "release-1.1.0.sig"
        acceptance = self.root / "release-110-test"
        cache = acceptance / "var/cache/bunker-ai/1.1.0"
        ops = acceptance / "opt/bunker/selection-releases"
        profile = acceptance / "var/lib/bunker-installer/1.1.0/selection.json"
        profile.parent.mkdir(parents=True)
        original = json.dumps({"release_manifest_sha256": bootstrap.sha256(trust / "release-1.1.0.json"),
                               "selection": {"name": "saved"}})
        profile.write_text(original)
        with patch.object(bootstrap, "ACCEPTANCE_HOME", self.root), \
                patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint), \
                patch.object(bootstrap, "curl", side_effect=self.download) as download:
            output = io.StringIO()
            with redirect_stdout(output):
                bootstrap.prepare_profile(*self.arguments[:3], cache, ops, acceptance.name)
                bootstrap.prepare_profile(*self.arguments[:3], cache, ops, acceptance.name)
            result, retry = (json.loads(line) for line in output.getvalue().splitlines())
            self.assertEqual(result["prepared_profile_id"], retry["prepared_profile_id"])
            opts = result["options"]
            self.assertEqual(Path(opts["--cache-root"]), acceptance / "var/cache/bunker-selected")
            self.assertEqual(Path(opts["--geo-content-root"]), acceptance / "var/lib/bunker-platform/modules/geo/content")
            self.assertEqual(Path(opts["--model-root"]), acceptance / "var/lib/bunker-profile/models")
            self.assertEqual(Path(opts["--runtime-staging-root"]), acceptance / "var/lib/bunker-profile/runtime")
            self.assertEqual(Path(opts["--distribution-root"]), cache)
            self.assertFalse(Path(opts["--manifest"]).exists())
            self.assertEqual(profile.read_text(), original)
            bundle = bootstrap.prepared_profile_files(acceptance, result["prepared_profile_id"])
            self.assertEqual((bundle / "selection.json").read_text(), original)
            self.assertEqual(stat.S_IMODE((bundle / "selection.json").stat().st_mode), 0o400)
            download.reset_mock()
            (trust / "release-1.1.0.json").write_bytes(b"tampered")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "signature verification failed"):
                bootstrap.prepare_profile(*self.arguments[:3], cache, ops, acceptance.name)
            self.assertEqual(download.call_count, 3)
            self.assertEqual(len(tuple(bundle.parent.iterdir())), 1)

    def test_prepared_geo_uses_saved_profiles_for_activation_and_offline_recovery(self):
        handler = b"""import json, sys
from pathlib import Path
options = dict(zip(sys.argv[2::2], sys.argv[3::2]))
Path(options['--env-file']).write_text(json.dumps({
    'action': sys.argv[1],
    'selected': json.loads(Path(options['--profile']).read_bytes())['selection']['name'],
    'rollback': json.loads(Path(options['--rollback-profile']).read_bytes())['selection']['name'],
    'root': options['--content-root'],
}))
"""
        trust, _ = self.local_geo_fixture(
            "product-11-prepare.py", b'print(\'{"ok": true, "activated": false, "platform_inputs": {"transport_only": true}}\')\n',
            extra_scripts=[("scripts/install/product-geo-service.py", handler)])
        self.urls[self.arguments[0]] = trust / "release-1.1.0.json"
        self.urls[self.arguments[1]] = trust / "release-1.1.0.sig"
        acceptance = self.root / "release-110-geo"
        cache = acceptance / "var/cache/bunker-ai/1.1.0"
        ops = acceptance / "opt/bunker/selection-releases"
        profile = acceptance / "var/lib/bunker-installer/1.1.0/selection.json"
        profile.parent.mkdir(parents=True)
        ids = {}
        with patch.object(bootstrap, "ACCEPTANCE_HOME", self.root), \
                patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint), \
                patch.object(bootstrap, "curl", side_effect=self.download) as network:
            for name in ("previous", "candidate"):
                profile.write_text(json.dumps({"release_manifest_sha256": bootstrap.sha256(trust / "release-1.1.0.json"),
                                               "selection": {"name": name}}))
                output = io.StringIO()
                with redirect_stdout(output):
                    bootstrap.prepare_profile(*self.arguments[:3], cache, ops, acceptance.name)
                ids[name] = json.loads(output.getvalue())["prepared_profile_id"]
            profile.unlink()
            network.reset_mock()
            marker = acceptance / "observed.json"
            for action in ("activate", "recover"):
                bootstrap.run_prepared_geo(action, ids["candidate"], cache, ops, acceptance.name,
                                           [f'--rollback-prepared={ids["previous"]}', "--env-file", str(marker)])
                self.assertEqual(json.loads(marker.read_bytes()), {
                    "action": action, "selected": "candidate", "rollback": "previous",
                    "root": str(acceptance / "var/lib/bunker-platform/modules/geo/content"),
                })
            with self.assertRaisesRegex(bootstrap.BootstrapError, "cannot be overridden"):
                bootstrap.run_prepared_geo("activate", ids["candidate"], cache, ops, acceptance.name,
                                           ["--profile=/wrong"])
            with self.assertRaisesRegex(bootstrap.BootstrapError, "different profile"):
                bootstrap.run_prepared_geo("recover", ids["candidate"], cache, ops, acceptance.name,
                                           [f'--rollback-prepared={ids["candidate"]}'])
            bundle = bootstrap.prepared_profile_files(acceptance, ids["candidate"])
            snapshot = bundle / "selection.json"
            snapshot.chmod(0o600)
            snapshot.write_text("tampered")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "snapshot is missing or changed"):
                bootstrap.run_prepared_geo("recover", ids["candidate"], cache, ops, acceptance.name, [])
            network.assert_not_called()

    def test_prepare_profile_refuses_missing_linked_or_legacy_paths_before_download(self):
        acceptance = self.root / "release-110-test"
        cache = acceptance / "var/cache/bunker-ai/1.1.0"
        ops = acceptance / "opt/bunker/selection-releases"
        with patch.object(bootstrap, "ACCEPTANCE_HOME", self.root), patch.object(bootstrap, "bootstrap") as start:
            for identifier, target_cache, reason in (
                ("release-100-rc22", cache, "separate"),
                (acceptance.name, self.root / "other-cache", "acceptance root"),
                (acceptance.name, cache, "no saved profile"),
            ):
                with self.subTest(identifier=identifier, reason=reason), self.assertRaisesRegex(
                        bootstrap.BootstrapError, reason):
                    bootstrap.prepare_profile(*self.arguments[:3], target_cache, ops, identifier)
            acceptance.mkdir(mode=0o700)
            acceptance.chmod(0o777)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "owned and protected"):
                bootstrap.prepare_profile(*self.arguments[:3], cache, ops, acceptance.name)
            acceptance.rmdir()
            acceptance.symlink_to(self.published, target_is_directory=True)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "symbolic links"):
                bootstrap.prepare_profile(*self.arguments[:3], cache, ops, acceptance.name)
            start.assert_not_called()

    def test_wikipedia_bootstrap_verifies_local_ops_and_prepared_profiles_without_network(self):
        trust, _ = self.local_geo_fixture(
            "product-11-prepare.py", b'print(\'{"ok": true, "activated": false, "platform_inputs": {"transport_only": true}}\')\n',
            extra_scripts=[("scripts/install/product-11-wikipedia.py",
                            b'import sys; assert sys.argv[1] in ("activate", "recover", "setup-index", "start-voice")\n')])
        self.urls[self.arguments[0]] = trust / "release-1.1.0.json"
        self.urls[self.arguments[1]] = trust / "release-1.1.0.sig"
        acceptance = self.root / "release-110-rc1"
        cache = acceptance / "var/cache/bunker-ai/1.1.0"
        ops = acceptance / "opt/bunker/selection-releases"
        profile = acceptance / "var/lib/bunker-installer/1.1.0/selection.json"
        profile.parent.mkdir(parents=True)
        ids = []
        with patch.object(bootstrap, "ACCEPTANCE_HOME", self.root), \
                patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint), \
                patch.object(bootstrap, "curl", side_effect=self.download) as network:
            for name in ("previous", "candidate"):
                profile.write_text(json.dumps({"release_manifest_sha256": bootstrap.sha256(trust / "release-1.1.0.json"),
                                               "selection": {"name": name}}))
                output = io.StringIO()
                with redirect_stdout(output):
                    bootstrap.prepare_profile(*self.arguments[:3], cache, ops, acceptance.name)
                ids.append(json.loads(output.getvalue())["prepared_profile_id"])
            network.reset_mock()
            bootstrap.run_prepared_wikipedia("activate", ids[0], None, cache, ops, acceptance.name)
            bootstrap.run_prepared_wikipedia("setup-index", ids[0], None, cache, ops, acceptance.name)
            bootstrap.run_prepared_wikipedia("start-voice", ids[0], None, cache, ops, acceptance.name)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "does not accept a rollback"):
                bootstrap.run_prepared_wikipedia("setup-index", ids[0], ids[1], cache, ops, acceptance.name)
            bootstrap.run_prepared_wikipedia("recover", ids[1], ids[0], cache, ops, acceptance.name)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "different prepared"):
                bootstrap.run_prepared_wikipedia("recover", ids[1], ids[1], cache, ops, acceptance.name)
            saved = bootstrap.prepared_profile_files(acceptance, ids[0]) / "selection.json"
            saved.chmod(0o600)
            saved.write_text("tampered")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "missing or changed"):
                bootstrap.run_prepared_wikipedia("recover", ids[1], ids[0], cache, ops, acceptance.name)
            network.assert_not_called()

    def test_managed_geo_dispatches_each_step_offline_from_signed_source(self):
        trust, _archive = self.local_geo_fixture()
        profile = self.root / "selected profile.json"
        cache, releases = self.arguments[3:]
        with patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint), \
                patch.object(bootstrap, "curl", side_effect=AssertionError("used network")) as network:
            for action in ("activate", "recover", "restart"):
                with self.subTest(action=action):
                    self.assertEqual(bootstrap.geo_entry([
                        action, "--trust-dir", str(trust), "--ops-cache", str(cache), "--ops-root", str(releases),
                        "--", "--profile", str(profile),
                    ]), 0)
                    self.assertEqual(profile.read_text(), action)
            network.assert_not_called()
        self.assertFalse((releases / "bunker-ops-0.2.25/scripts/install/__pycache__").exists())

    def test_managed_geo_rejects_trust_overrides_even_before_verification(self):
        for option in ("--manifest", "--signature=/other.sig", "--public-k", "--"):
            with self.subTest(option=option):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "only from the local trust"):
                    bootstrap.run_local_geo("recover", self.published, *self.arguments[3:], [option])

    def test_managed_geo_refuses_missing_or_tampered_ops_archive_without_network(self):
        trust, archive = self.local_geo_fixture()
        with patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint), \
                patch.object(bootstrap, "curl", side_effect=AssertionError("used network")):
            archive.write_bytes(b"tampered")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "archive checksum mismatch"):
                bootstrap.run_local_geo("recover", trust, *self.arguments[3:], [])
            archive.unlink()
            with self.assertRaisesRegex(bootstrap.BootstrapError, "must already be in the local cache"):
                bootstrap.run_local_geo("recover", trust, *self.arguments[3:], [])
        self.assertFalse(self.arguments[4].exists())

    def test_managed_geo_refuses_linked_trust_and_changed_staged_ops(self):
        trust, _archive = self.local_geo_fixture()
        aliased_trust = self.root / "alias"
        aliased_trust.symlink_to(trust, target_is_directory=True)
        with patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "canonical absolute"):
                bootstrap.run_local_geo("recover", aliased_trust, *self.arguments[3:], [])
            profile = self.root / "marker"
            opts = ["--profile", str(profile)]
            bootstrap.run_local_geo("recover", trust, *self.arguments[3:], opts)
            profile.unlink()
            (self.arguments[4] / "bunker-ops-0.2.25/scripts/install/product-geo-service.py").write_text("# changed\n")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "installed Ops source differs"):
                bootstrap.run_local_geo("recover", trust, *self.arguments[3:], opts)
            self.assertFalse(profile.exists())

    def test_managed_geo_rejects_tampered_or_wrong_version_manifest(self):
        trust, _archive = self.local_geo_fixture()
        with patch.object(bootstrap, "PRODUCT_KEY_FINGERPRINT", self.fingerprint):
            manifest = trust / "release-1.1.0.json"
            shutil.copyfile(self.manifest, manifest)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "signature verification failed"):
                bootstrap.run_local_geo("activate", trust, *self.arguments[3:], [])
            shutil.copyfile(self.signature, trust / "release-1.1.0.sig")
            with self.assertRaisesRegex(bootstrap.BootstrapError, "not a production Bunker AI 1.1.0"):
                bootstrap.run_local_geo("activate", trust, *self.arguments[3:], [])
        self.assertFalse(self.arguments[4].exists())

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
for name in ("manifest", "signature", "public-key", "profile", "choices-json", "space-root"):
    cli.add_argument("--" + name, type=Path)
cli.add_argument("--min-free-after-bytes", type=int)
cli.add_argument("--non-interactive", action="store_true")
args = cli.parse_args()
assert args.non_interactive and args.signature.is_file() and args.public_key.is_file() and args.space_root.name == "target volume"
assert args.min_free_after_bytes == 80 * (1 << 30)
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
                        installation_catalog={"schema_version": "bunker.install-catalog/v2"},
                        target_host={"disk_policy": "platform_plus_selected_catalog", "platform_disk_budget": {
                            "asset_bytes": 120, "image_download_bytes": 400, "install_overhead_bytes": 50,
                            "required_bytes": 570}})
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
                                                 choices=choices, probe_download=False,
                                                 space_root=self.root / "target volume", min_free_after_bytes=80 << 30)
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
