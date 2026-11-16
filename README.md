# Bunker AI installer

**Release preparation in progress.** This repository is private until the
signed 1.0.0 manifest, all published image and file digests, and the AMD
installation acceptance are complete. Do not treat a source branch or an
individual component tag as a released appliance.

The installer targets AMD Ryzen AI Max+ 395, verifies the signed disk budget,
Vulkan, and Ubuntu 20.04, 22.04, 24.04, or 26.04. It will provide separate
stages for signed preparation, base-platform activation, initial n8n owner
setup, and physical module activation. Customer keys, Coder workspace ACL,
and real hardware sources remain explicit readiness gates.

The canonical installer implementation currently lives in Bunker Ops. This
repository will carry the verified `install.sh`, pinned bootstrap helper,
signed manifest, checksums, Geo pack, and acceptance notes only after the
published bytes have been measured and checked. No installation command is
published yet.
