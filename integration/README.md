# Integration tests

These tests use a real kind Kubernetes cluster and require Docker.

Run:

```bash
make integration-test
```

Optional env vars:

- `CAINJEKT_CLUSTER_NAME` (default: `cainjekt-test-cluster`)
- `CAINJEKT_PLUGIN_IDX` (default: dynamic)
