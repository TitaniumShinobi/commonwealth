# ARM64 8 GiB cloud co-host qualification

This branch-only workflow uses a native Ubuntu 24.04 ARM64 GitHub Actions VM. Smoke verifies the kernel and userspace architecture, cgroup v2, and an isolated network namespace. The official Ubiquiti downloads page lists UniFi OS Server Linux ARM64 5.1.42. The workflow pins the publisher CDN URL and SHA-256 `8e29bd50cde8f781ace4b85599256ef62c02723bdc751044d4db90a087fb5207`, computed from the vendor bytes on the initial ARM64 provenance run. This is a fixture integrity pin.

The workflow verifies actual cgroup membership before measuring. If the rootless container resides in a separate cgroup, bound the service and wired slice to 2 GiB and the complete container subtree to 6 GiB. Both enforced limits disallow cgroup swap. If the container resides under the workload slice, use a single 8 GiB cap. The controller is installed only after a network namespace and its systemd overrides are present. Its management segment has no physical interface or external route. The test checks local health and listener containment before invoking the existing wired guest fixture. It samples aggregate memory and controller health during the wired run, verifies a controlled restart, and requires the wired receipt for exact rollback with withdrawal still enforced. Readiness failures retain evidence and leave co-hosting unverified. The disposable runner is not a Raspberry Pi and provides no radio, physical thermal, PSU, storage endurance or deployed-site evidence.

Sources
- [Ubiquiti downloads](https://www.ui.com/download/software/unifi-os-server)
- [Ubiquiti self-hosting requirements](https://help.ui.com/hc/en-us/articles/34210126298775-Self-Hosting-UniFi)
