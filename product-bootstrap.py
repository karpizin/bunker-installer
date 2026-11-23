#!/usr/bin/env python3
"""Establish product trust and stage the signed Ops source before running it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


PRODUCT_KEY_FINGERPRINT = "1e7ad26b66b4f5eab9e60f9ae630b3f57f59fd19fe8c33dfadf3282b4127ae5b"
MAX_OPS_BYTES = 1024 * 1024 * 1024
RELEASE_SCHEMAS = {"1.0.0": "bunker.appliance-release/v1", "1.1.0": "bunker.appliance-release/v2"}
CONFIGURE_CANCELLED = 3


class BootstrapError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def https_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BootstrapError("release downloads require an HTTPS URL without credentials")
    return url


def curl(url: str, target: Path, *, resume: bool) -> None:
    command = ["curl", "--fail", "--location", "--retry", "5", "--retry-all-errors",
               "--proto", "=https", "--proto-redir", "=https", "--silent", "--show-error"]
    if resume:
        command += ["--continue-at", "-"]
    subprocess.run(command + ["--output", str(target), https_url(url)],
                   check=True, capture_output=True)


def fetch_trust_file(url: str, destination: Path) -> None:
    if destination.is_symlink():
        raise BootstrapError("trust cache contains a symbolic link")
    temporary = destination.with_name(destination.name + ".part")
    if temporary.is_symlink():
        raise BootstrapError("trust cache partial file is a symbolic link")
    try:
        temporary.unlink(missing_ok=True)
        curl(url, temporary, resume=False)
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise BootstrapError("empty trust download")
        os.replace(temporary, destination)
    except (BootstrapError, OSError, subprocess.CalledProcessError):
        temporary.unlink(missing_ok=True)
        raise


def verify_signature(manifest: Path, signature: Path, public_key: Path) -> None:
    if not all(path.is_file() and not path.is_symlink() for path in (manifest, signature, public_key)):
        raise BootstrapError("manifest, signature and product key are required")
    try:
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(public_key),
                              "-outform", "DER"], check=True, capture_output=True).stdout
        if hashlib.sha256(der).hexdigest() != PRODUCT_KEY_FINGERPRINT:
            raise BootstrapError("product public key fingerprint mismatch")
        subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key),
                        "-signature", str(signature), str(manifest)], check=True, capture_output=True)
    except subprocess.CalledProcessError as error:
        raise BootstrapError("product manifest signature verification failed") from error


def ops_pin(manifest: Path, release_version: str = "1.0.0") -> dict[str, object]:
    value = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BootstrapError("signed file is not a product manifest")
    platform_release = value.get("platform_release")
    distribution = value.get("distribution")
    if (release_version not in RELEASE_SCHEMAS
            or value.get("schema_version") != RELEASE_SCHEMAS[release_version]
            or value.get("status") != "production"
            or not isinstance(platform_release, dict)
            or platform_release.get("version") != release_version):
        raise BootstrapError(f"signed file is not a production Bunker AI {release_version} manifest")
    if release_version == "1.1.0":
        catalog = value.get("installation_catalog")
        if not isinstance(catalog, dict) or catalog.get("schema_version") != "bunker.install-catalog/v2":
            raise BootstrapError("signed 1.1.0 manifest lacks a world-bundle installation catalog")
        host = value.get("target_host")
        if (not isinstance(host, dict) or host.get("disk_policy") != "platform_plus_selected_catalog"
                or not isinstance(host.get("platform_disk_budget"), dict)):
            raise BootstrapError("signed 1.1.0 manifest lacks the platform disk budget")
    item = distribution.get("ops_source") if isinstance(distribution, dict) else None
    if not isinstance(item, dict):
        raise BootstrapError("signed manifest lacks the Ops source")
    version = item.get("version")
    if (not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
            or item.get("path") != f"ops/bunker-ops_{version}_source.tar.gz"
            or re.fullmatch(r"[0-9a-f]{40}", str(item.get("source_commit", ""))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is None
            or type(item.get("size_bytes")) is not int or item["size_bytes"] <= 0):
        raise BootstrapError("signed Ops source metadata is incomplete")
    https_url(str(item.get("artifact", "")))
    return item


def fetch_ops(item: dict[str, object], cache: Path) -> Path:
    destination = cache / str(item["path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or destination.parent.is_symlink():
        raise BootstrapError("Ops archive cache contains a symbolic link")
    if destination.is_file() and destination.stat().st_size == item["size_bytes"] and sha256(destination) == item["sha256"]:
        return destination
    partial = destination.with_name(destination.name + ".part")
    if partial.is_symlink():
        raise BootstrapError("Ops archive partial file is a symbolic link")
    for attempt in range(2):
        if attempt:
            partial.unlink(missing_ok=True)
        curl(str(item["artifact"]), partial, resume=True)
        if partial.is_file() and partial.stat().st_size == item["size_bytes"] and sha256(partial) == item["sha256"]:
            os.replace(partial, destination)
            return destination
    raise BootstrapError("Ops source download failed size or SHA-256 verification")


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise BootstrapError("unexpected Ops source entry")
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(b"d" if path.is_dir() else b"f")
        if path.is_file():
            digest.update(b"x" if path.stat().st_mode & 0o111 else b"-")
            digest.update(bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def stage_ops(archive: Path, item: dict[str, object], ops_root: Path) -> Path:
    if (not archive.is_file() or archive.is_symlink()
            or archive.stat().st_size != item["size_bytes"] or sha256(archive) != item["sha256"]):
        raise BootstrapError("Ops source archive checksum mismatch before staging")
    ops_root.mkdir(parents=True, exist_ok=True)
    if ops_root.is_symlink():
        raise BootstrapError("Ops release root must not be a symbolic link")
    name = f"bunker-ops-{item['version']}"
    target = ops_root / name
    if target.is_symlink():
        raise BootstrapError("Ops release target is a symbolic link")
    with tempfile.TemporaryDirectory(prefix=".ops-bootstrap-", dir=ops_root) as temporary:
        staged = Path(temporary) / name
        staged.mkdir()
        seen: set[str] = set()
        expanded = 0
        with tarfile.open(archive, "r:gz") as package:
            for member in package:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                        or not path.parts or path.parts[0] != name
                        or not (member.isdir() or member.isfile())):
                    raise BootstrapError("unsafe Ops source archive entry")
                relative = PurePosixPath(*path.parts[1:])
                if not relative.parts:
                    if not member.isdir():
                        raise BootstrapError("unsafe Ops source archive root")
                    continue
                normalized = relative.as_posix()
                if normalized in seen or normalized == ".bunker-source-commit":
                    raise BootstrapError("duplicate or reserved Ops source archive entry")
                seen.add(normalized)
                destination = staged.joinpath(*relative.parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    destination.chmod(0o755)
                else:
                    expanded += member.size
                    if expanded > MAX_OPS_BYTES or len(seen) > 100000:
                        raise BootstrapError("Ops source archive exceeds safety limits")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source = package.extractfile(member)
                    if source is None:
                        raise BootstrapError("unreadable Ops source archive entry")
                    with source, destination.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    destination.chmod(0o755 if member.mode & 0o111 else 0o644)
        version_file = staged / "VERSION"
        if not version_file.is_file() or version_file.read_text(encoding="utf-8").strip() != item["version"]:
            raise BootstrapError("Ops source VERSION differs from signed manifest")
        (staged / ".bunker-source-commit").write_text(str(item["source_commit"]) + "\n", encoding="utf-8")
        if target.exists():
            if tree_digest(target) != tree_digest(staged):
                raise BootstrapError("installed Ops source differs from signed archive")
        else:
            os.replace(staged, target)
    return target


def bootstrap(manifest_url: str, signature_url: str, public_key_url: str,
              cache: Path, ops_root: Path, *, release_version: str = "1.0.0", private_trust: Path | None = None) -> Path:
    if release_version not in RELEASE_SCHEMAS:
        raise BootstrapError("unsupported bootstrap release")
    cache.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink():
        raise BootstrapError("bootstrap cache must not be a symbolic link")
    trust = private_trust if private_trust is not None else cache / "trust"
    trust.mkdir(exist_ok=True)
    if trust.is_symlink():
        raise BootstrapError("bootstrap trust cache must not be a symbolic link")
    manifest, signature, key = (trust / f"release-{release_version}.json", trust / f"release-{release_version}.sig",
                                trust / "bunker-product-release-2026.pem")
    fetch_trust_file(manifest_url, manifest)
    fetch_trust_file(signature_url, signature)
    fetch_trust_file(public_key_url, key)
    verify_signature(manifest, signature, key)
    item = ops_pin(manifest, release_version)
    return stage_ops(fetch_ops(item, cache), item, ops_root)


def configure_product(manifest_url: str, signature_url: str, public_key_url: str, cache: Path, ops_root: Path,
                      profile: Path, *, non_interactive: bool, choices: Path | None, probe_download: bool,
                      space_root: Path | None = None, min_free_after_bytes: int = 0,
                      disk_layout: Path | None = None, locale: str | None = None) -> Path | None:
    if choices is not None and not non_interactive:
        raise BootstrapError("choices file requires non-interactive configuration")
    if type(min_free_after_bytes) is not int or min_free_after_bytes < 0:
        raise BootstrapError("post-install free-space floor must be a nonnegative integer")
    if space_root is not None and disk_layout is not None:
        raise BootstrapError("space root and disk layout cannot be combined")
    if locale is not None and locale not in ("en", "ru", "zh-Hans"):
        raise BootstrapError("unsupported installer locale")
    # Keep this run's signature and catalog together even when another selection runs concurrently.
    with tempfile.TemporaryDirectory(prefix="bunker-selection-trust-") as directory:
        trust = Path(directory)
        target = bootstrap(manifest_url, signature_url, public_key_url, cache, ops_root,
                           release_version="1.1.0", private_trust=trust)
        script = target / "scripts/install/product-setup.py"
        if not script.is_file() or script.is_symlink():
            raise BootstrapError("verified Ops source lacks the 1.1 selection tool")
        command = [sys.executable, "-B", str(script), "--manifest", str(trust / "release-1.1.0.json"),
                   "--signature", str(trust / "release-1.1.0.sig"), "--public-key",
                   str(trust / "bunker-product-release-2026.pem"), "--profile", str(profile)]
        if non_interactive:
            command.append("--non-interactive")
        if locale is not None:
            command += ["--locale", locale]
        if choices is not None:
            command += ["--choices-json", str(choices)]
        if probe_download:
            command.append("--probe-download")
        if space_root is not None:
            command += ["--space-root", str(space_root)]
        if disk_layout is not None:
            command += ["--disk-layout-json", str(disk_layout)]
        if min_free_after_bytes:
            command += ["--min-free-after-bytes", str(min_free_after_bytes)]
        result = subprocess.run(command, check=False)
        if result.returncode == CONFIGURE_CANCELLED and not non_interactive:
            return None
        result.check_returncode()
    return target


def prepare_product(target: Path, cache: Path, ops_root: Path,
                    source_root: Path, install_root: Path) -> None:
    script = target / "scripts/install/product-stage.py"
    if not script.is_file() or script.is_symlink():
        raise BootstrapError("verified Ops source lacks the product staging script")
    trust = cache / "trust"
    subprocess.run([
        sys.executable, str(script),
        "--manifest", str(trust / "release-1.0.0.json"),
        "--signature", str(trust / "release-1.0.0.sig"),
        "--public-key", str(trust / "bunker-product-release-2026.pem"),
        "--distribution-root", str(cache),
        "--source-root", str(source_root),
        "--ops-root", str(ops_root),
        "--install-root", str(install_root),
    ], check=True)


def run_product_step(target: Path, cache: Path, ops_root: Path, source_root: Path,
                     install_root: Path, state_root: Path, step: str) -> None:
    if step not in {"install-platform", "initialize-n8n", "activate-modules"}:
        raise BootstrapError("unsupported product activation step")
    trust = cache / "trust"
    shared = ["--manifest", str(trust / "release-1.0.0.json"),
              "--signature", str(trust / "release-1.0.0.sig"),
              "--public-key", str(trust / "bunker-product-release-2026.pem"),
              "--distribution-root", str(cache), "--source-root", str(source_root),
              "--state-root", str(state_root)]
    if step == "install-platform":
        script = target / "scripts/install/product-platform.py"
        command = [sys.executable, str(script), *shared, "--ops-root", str(ops_root),
                   "--install-root", str(install_root), "--activate"]
    else:
        script = target / "scripts/install/product-modules.py"
        command = [sys.executable, str(script), *shared, "--prepare" if step == "initialize-n8n" else "--activate"]
    if not script.is_file() or script.is_symlink():
        raise BootstrapError(f"verified Ops source lacks {script.name}")
    subprocess.run(command, check=True)
    if step == "initialize-n8n":
        driver = target / "scripts/install/bunker-appliance-modules.py"
        if not driver.is_file() or driver.is_symlink():
            raise BootstrapError("verified Ops source lacks the module installer")
        subprocess.run([sys.executable, str(driver), "initialize-n8n", "--manifest",
                        str(trust / "release-1.0.0.json"), "--module-source-root",
                        str(source_root), "--state-root", str(state_root)], check=True)


def prepare_acceptance_service_paths(root: Path) -> None:
    # Service users need traversal, not listing access, through the isolated root.
    for path in (root.parent, root, root / "opt", root / "opt/bunker",
                 root / "opt/bunker/platform", root / "opt/bunker/platform/bin",
                 root / "var", root / "var/lib"):
        if path.is_symlink():
            raise BootstrapError(f"acceptance path is a symbolic link: {path}")
        path.mkdir(mode=0o700, exist_ok=True)
        if not path.is_dir() or path.is_symlink():
            raise BootstrapError(f"acceptance path is not a safe directory: {path}")
        path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IXOTH)


def run_local_geo(action: str, trust: Path, cache: Path, ops_root: Path, options: list[str]) -> None:
    if action not in {"activate", "recover", "restart"}:
        raise BootstrapError("unsupported managed Geo action")
    pinned_options = ("--manifest", "--signature", "--public-key")
    if any(option == "--" or (option.startswith("--") and any(
            flag.startswith(option.split("=", 1)[0]) for flag in pinned_options)) for option in options):
        raise BootstrapError("Geo manifest, signature and key come only from the local trust directory")
    if any(not path.is_absolute() or path == Path("/") or path.resolve() != path
           for path in (trust, cache, ops_root)):
        raise BootstrapError("Geo trust, cache and Ops roots must be canonical absolute directories")
    names = ("release-1.1.0.json", "release-1.1.0.sig", "bunker-product-release-2026.pem")
    with tempfile.TemporaryDirectory(prefix="bunker-geo-trust-") as directory:
        snapshot = Path(directory)
        for name in names:
            source = trust / name
            if source.is_symlink() or not source.is_file():
                raise BootstrapError("local signed 1.1 Geo release files are required")
            shutil.copyfile(source, snapshot / name)
        manifest, signature, key = (snapshot / name for name in names)
        verify_signature(manifest, signature, key)
        item = ops_pin(manifest, "1.1.0")
        archive = cache / str(item["path"])
        if archive.resolve() != archive or not archive.is_file():
            raise BootstrapError("the pinned Ops archive must already be in the local cache")
        target = stage_ops(archive, item, ops_root)
        script = target / "scripts/install/product-geo-service.py"
        if not script.is_file() or script.is_symlink():
            raise BootstrapError("verified Ops source lacks the managed Geo command")
        subprocess.run([
            sys.executable, "-B", str(script), action,
            "--manifest", str(manifest), "--signature", str(signature), "--public-key", str(key), *options,
        ], check=True)


def geo_entry(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="product-bootstrap.py --geo", allow_abbrev=False)
    parser.add_argument("action", choices=("activate", "recover", "restart"))
    parser.add_argument("--trust-dir", type=Path, required=True)
    parser.add_argument("--ops-cache", type=Path, required=True)
    parser.add_argument("--ops-root", type=Path, required=True)
    if "--" not in argv:
        parser.error("separate the managed Geo options with --")
    split = argv.index("--")
    args = parser.parse_args(argv[:split])
    try:
        run_local_geo(args.action, args.trust_dir, args.ops_cache, args.ops_root, argv[split + 1:])
    except (BootstrapError, OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"Bunker AI Geo bootstrap: {error}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    if sys.argv[1:2] == ["--geo"]:
        return geo_entry(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-url", required=True)
    parser.add_argument("--signature-url", required=True)
    parser.add_argument("--public-key-url", required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--ops-root", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--prepare", action="store_true",
                        help="run preflight, distribution download and unpack; do not activate services")
    action.add_argument("--install-platform", action="store_true")
    action.add_argument("--initialize-n8n", action="store_true")
    action.add_argument("--activate-modules", action="store_true")
    action.add_argument("--configure", action="store_true", help="save the choices from the signed 1.1 catalog; do not install")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--locale", choices=("en", "ru", "zh-Hans"),
                        help="setup language only (default: en)")
    parser.add_argument("--choices-json", type=Path)
    parser.add_argument("--probe-download", action="store_true")
    parser.add_argument("--space-root", type=Path)
    parser.add_argument("--disk-layout-json", type=Path)
    parser.add_argument("--min-free-after-bytes", type=int)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--install-root", type=Path)
    parser.add_argument("--state-root", type=Path)
    args = parser.parse_args()
    if args.configure:
        if args.profile is None or (args.choices_json is not None and not args.non_interactive):
            parser.error("--configure requires --profile; --choices-json requires --non-interactive")
        try:
            target = configure_product(args.manifest_url, args.signature_url, args.public_key_url, args.cache,
                                       args.ops_root, args.profile, non_interactive=args.non_interactive,
                                       choices=args.choices_json, probe_download=args.probe_download,
                                       space_root=args.space_root,
                                       disk_layout=args.disk_layout_json, locale=args.locale,
                                       min_free_after_bytes=0 if args.min_free_after_bytes is None else args.min_free_after_bytes)
        except (BootstrapError, OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
            print(f"Bunker AI bootstrap: {error}", file=sys.stderr)
            return 1
        result = {"ok": True, "step": "configure", "saved": target is not None}
        if target is not None:
            result["ops_source"] = str(target)
        print(json.dumps(result))
        return 0
    if (args.profile or args.non_interactive or args.choices_json or args.probe_download or args.space_root or args.locale
            or args.min_free_after_bytes is not None or args.disk_layout_json is not None):
        parser.error("selection options require --configure")
    if args.source_root is None or args.install_root is None:
        parser.error("product operation requires --source-root and --install-root")
    if not args.prepare and args.state_root is None:
        parser.error("activation requires --state-root")
    try:
        acceptance_root = args.install_root.parent.parent
        if acceptance_root.parent == Path("/var/lib/bunker-acceptance"):
            prepare_acceptance_service_paths(acceptance_root)
        target = bootstrap(args.manifest_url, args.signature_url, args.public_key_url,
                           args.cache, args.ops_root)
        if args.prepare:
            prepare_product(target, args.cache, args.ops_root,
                            args.source_root, args.install_root)
        else:
            step = "install-platform" if args.install_platform else (
                "initialize-n8n" if args.initialize_n8n else "activate-modules")
            run_product_step(target, args.cache, args.ops_root, args.source_root,
                             args.install_root, args.state_root, step)
    except (BootstrapError, OSError, ValueError, subprocess.CalledProcessError,
            tarfile.TarError) as error:
        print(f"Bunker AI bootstrap: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "ops_source": str(target), "step": (
        "prepare" if args.prepare else step)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
