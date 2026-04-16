# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

We only support the latest release. Please upgrade before reporting issues.

## Reporting a Vulnerability

To report a security vulnerability, please [open a GitHub issue](https://github.com/natrontech/cainjekt/issues/new) with the label `security`. Include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

> **Note:** This is an open-source project maintained on a best-effort basis. There is no guaranteed response time or acknowledgment for security reports. We will address issues as capacity allows.

## Direct Support

If you are a direct customer of [**Natron Tech AG**](https://natron.io), you can submit service requests through your existing support channels for guaranteed response times.

## Scope

cainjekt runs as a privileged DaemonSet with access to the container runtime. Security-relevant areas include:

- **CA file injection**: symlink protection, atomic writes, file permission handling
- **OCI hook execution**: runs inside the container's mount namespace with access to the rootfs
- **NRI plugin**: communicates with containerd over a Unix socket
- **Wrapper binary**: prepended to container entrypoints, must fail-open safely

## Disclosure

Once a fix is released, we will:

1. Publish a GitHub Security Advisory
2. Credit the reporter (unless they prefer anonymity)
3. Tag a new release with the fix
