# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

We only support the latest release. Please upgrade before reporting issues.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities by emailing **security@natron.io** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within **3 business days** and aim to provide a fix or mitigation plan within **14 days**, depending on severity.

## Scope

cainjekt runs as a privileged DaemonSet with access to the container runtime. Security-relevant areas include:

- **CA file injection**: symlink protection, atomic writes, file permission handling
- **OCI hook execution**: runs inside the container's mount namespace with access to the rootfs
- **NRI plugin**: communicates with containerd over a Unix socket
- **Wrapper binary**: prepended to container entrypoints, must fail-open safely

## Disclosure

We follow coordinated disclosure. Once a fix is released, we will:

1. Publish a GitHub Security Advisory
2. Credit the reporter (unless they prefer anonymity)
3. Tag a new release with the fix

Thank you for helping keep cainjekt and its users safe.
