# Bunker AI installer

**Bunker AI 1.0.0 is released.** Use the signed assets and known-limitations
notes in the [v1.0.0 release](https://github.com/karpizin/bunker-installer/releases/tag/v1.0.0).
The GA assets are byte-identical to the accepted RC22 candidate; the signed
manifest still references pinned files on earlier RC tags. Those releases
must remain publicly available. A source branch or component tag alone is
not a product release.

The installer targets AMD Ryzen AI Max+ 395, verifies the signed disk budget,
Vulkan, and Ubuntu 20.04, 22.04, 24.04, or 26.04. Full hardware acceptance was
performed on the AMD target, not on every listed Ubuntu version. It provides separate
stages for signed preparation, base-platform activation, initial n8n owner
setup, and physical module activation. Customer keys, Coder workspace ACL,
and real hardware sources remain explicit readiness gates.

Download `install.sh` and `product-bootstrap.py` from the same v1.0.0 release
into one directory. The bundled helper has SHA-256
`dfd1b974a809cd2489af417c5056379e9e3c19d0d764eafb9d856b69c59e5267`.
The shell script copies the helper into a private root-owned temporary directory,
checks the copy's digest, executes that copy, and removes it afterward; changing
the bundle after the copy cannot change the executed bytes. The shell entry
point itself does not execute downloaded code before the trust check. The
helper pins the product signing key, verifies the signed
manifest, downloads the Ops source by its signed size and SHA-256, and only
then runs the staged Ops installer. A missing or invalid signature fails closed.

Run these stages in order on the target Ubuntu host:

```sh
sudo sh install.sh --prepare
sudo sh install.sh --install-platform
sudo sh install.sh --initialize-n8n
sudo sh install.sh --activate-modules
```

Each command revalidates trust. Preparation does not activate services;
subsequent stages are separate so owner credentials, Coder ACL and physical
sources can be supplied and checked before module activation. Do not pipe
`install.sh` alone into a shell: its bundled helper is required. On an already
installed appliance with a completed Wikipedia index, a same-release
`--install-platform` rerun can fail; see the [known limitation](https://github.com/karpizin/bunker-ops/issues/178)
before using it as a repair step. Clean-host installation from removable media
is not part of this release's validated scope.

For an explicitly selected 1.0.0 prerelease acceptance run, an operator may
set `BUNKER_RELEASE_TAG` to a `v1.0.0-rcN` tag (for example,
`sudo env BUNKER_RELEASE_TAG=v1.0.0-rc2 sh install.sh --prepare`). This changes
only the fixed GitHub Release path; signature and pinned bootstrap checks are
unchanged. Without this variable the installer always targets `v1.0.0`.
Prerelease installation must be isolated from an existing appliance and must
not be represented as a completed public release.

For that acceptance run, set `BUNKER_ACCEPTANCE_ID` to a short safe name such
as `release-100-rc3`. The installer places its cache, staged sources, program
files and platform state under `/var/lib/bunker-acceptance/<id>/` instead of
the normal paths. This separates files, **not host-level services, Docker or
GPU ownership**. Do not activate the candidate concurrently with a working
installation: first preserve its recovery evidence, stop it in a controlled
maintenance window, and verify rollback. A successful `--prepare` alone is
not acceptance of activation.

## Candidate profile preparation (1.1 development only)

After a signed 1.1 candidate is staged, use the same `BUNKER_RELEASE_TAG` and
`BUNKER_ACCEPTANCE_ID=release-110-rcN` for `--configure` and `--prepare-profile`.
The latter verifies the signed release again and passes the saved profile and
private staging directories to the Ops preparer. It preserves an 80 GiB
free-space floor and does not start the platform, index Wikipedia, or activate
models or maps. Use the preparer's `activated: false` report as staging evidence
only. It also returns `prepared_profile_id`: the SHA-256 of the saved selection,
retained with the verified release trust files under the same acceptance root.
A different candidate requires its own manifest-bound selection.

## Managed geography (1.1 development only)

The development bundle accepts `--geo activate|recover|restart TRUST_DIR -- [Geo options]`.
`TRUST_DIR` must contain the local signed 1.1 manifest (`release-1.1.0.json`),
its detached signature (`release-1.1.0.sig`) and the pinned product public key
(`bunker-product-release-2026.pem`). The corresponding Ops archive must already
be in the 1.1 cache at the manifest's pinned path. This command does not fetch
trust files, Ops or content. It runs only the managed Geo command from the
verified Ops archive.

With the same `release-110-*` acceptance ID you can use
`--geo activate prepared:PROFILE_SHA256 -- [managed project options]` instead of
assembling a trust directory manually. The profile, selected cache and Geo
content directory come from preparation, not caller overrides. Supply the
trusted Compose definition, module environment, dedicated project and loopback
port explicitly. An update or its recovery can name the original profile with
`--rollback-prepared=PREVIOUS_PROFILE_SHA256` after the separator. This reuses
the saved profile even if `--configure` has changed the current choice. The
original signed artifacts must remain in the caches. `restart` cannot switch
profiles or recover an incomplete transaction.

Prepare a signed selection and staged Geo generation first. Supply only the
trusted Compose definition, private module environment and dedicated Geo
project. An update and its recovery require the original rollback manifest,
signature, profile and cache. Use `restart` for the already-selected profile;
it refuses a pending switch rather than changing the selector. Do not use
this command on a 1.0 acceptance root or on an unmanaged service. This is
not a clean offline installer and is not shipped as part of 1.0.0.
