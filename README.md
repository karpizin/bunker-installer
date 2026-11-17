# Bunker AI installer

**Release preparation in progress.** This repository may host publicly
downloadable *candidate* assets so their final URLs can be independently
checked. A candidate asset or prerelease is not an accepted appliance. Bunker
AI 1.0.0 is not released until the product manifest is signed, the published
installation is accepted on AMD, and the final release is explicitly published.
Do not treat a source branch or an individual component tag as a release.

The installer targets AMD Ryzen AI Max+ 395, verifies the signed disk budget,
Vulkan, and Ubuntu 20.04, 22.04, 24.04, or 26.04. It will provide separate
stages for signed preparation, base-platform activation, initial n8n owner
setup, and physical module activation. Customer keys, Coder workspace ACL,
and real hardware sources remain explicit readiness gates.

The four-stage entry point is now staged here as `install.sh` together with
`product-bootstrap.py`. The helper is an unchanged copy of the Ops bootstrap
with SHA-256 `939a33520f9b92e2a3f58fb4d3e687eb3cc5504e2ad049fa1222a2fbb6bfbcad`.
The shell script copies the helper into a private root-owned temporary directory,
checks the copy's digest, executes that copy, and removes it afterward; changing
the bundle after the copy cannot change the executed bytes. It never downloads
executable code. The helper pins the product signing key, verifies the signed
manifest, downloads the Ops source by its signed size and SHA-256, and only
then runs the staged Ops installer. A missing or invalid signature fails closed.

Once the complete signed release bundle is published, use these stages in
order on the supported Ubuntu target:

```sh
sudo sh install.sh --prepare
sudo sh install.sh --install-platform
sudo sh install.sh --initialize-n8n
sudo sh install.sh --activate-modules
```

Each command revalidates trust. Preparation does not activate services;
subsequent stages are separate so owner credentials, Coder ACL and physical
sources can be supplied and checked before module activation. Do not pipe
`install.sh` alone into a shell: its bundled helper is required. The release
assets and acceptance are not yet complete, so these commands are documentation
of the intended flow, not a published installation instruction.

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
