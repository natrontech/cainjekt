# Documentation Conventions

## Documentation Structure

| File | Audience | Purpose |
|------|----------|---------|
| `README.md` | Users | Quick start, features, install commands |
| `CLAUDE.md` | Developers (AI) | Architecture, commands, config for Claude Code |
| `docs/architecture.md` | Engineers | Deep-dive: injection pipeline, processor system, security model |
| `docs/usage.md` | Operators | Full usage guide: install, configure, verify, troubleshoot |
| `docs/why-we-forked.md` | Decision-makers | Fork rationale, what changed vs upstream |
| `deploy/kubernetes/README.md` | Ops | Step-by-step kustomize deployment + troubleshooting |
| `charts/cainjekt/values.yaml` | Ops | Helm values with `@param` comments |
| `charts/cainjekt/templates/NOTES.txt` | Ops | Post-install quick reference |

## When to Update Docs

Documentation must be updated in the same commit as code changes when:

- A new processor is added → update README.md, CLAUDE.md, docs/architecture.md (processor tables), docs/usage.md (available processors + limitations table), deploy/kubernetes/README.md
- A new configuration option is added → update README.md (config table), CLAUDE.md, docs/usage.md, deploy/kubernetes/README.md, values.yaml
- Annotations change → update README.md, CLAUDE.md, docs/usage.md, deploy/kubernetes/README.md, NOTES.txt
- Architecture changes (new phase, new component) → update docs/architecture.md, CLAUDE.md
- Observability changes (new metric, new alert) → update docs/architecture.md (metrics table), docs/usage.md
- Helm chart values change → update values.yaml comments, NOTES.txt, docs/usage.md
- Build/test commands change → update CLAUDE.md, Makefile

## Files to Keep in Sync

| Change | Files to update |
|--------|----------------|
| New processor | README.md, CLAUDE.md, docs/architecture.md, docs/usage.md, deploy/kubernetes/README.md |
| New env var | README.md, CLAUDE.md, docs/usage.md, deploy/kubernetes/README.md, values.yaml, daemonset.yaml |
| New annotation | README.md, CLAUDE.md, docs/usage.md, deploy/kubernetes/README.md, .claude/rules/general.md, NOTES.txt |
| New metric | docs/architecture.md (metrics table), docs/usage.md |
| New Helm resource | values.yaml, docs/usage.md |
| New make target | CLAUDE.md, Makefile |
| New CI job | .claude/rules/cicd.md |
| Architecture change | CLAUDE.md, README.md, docs/architecture.md |
| Security change | docs/architecture.md (security model section) |

## Style

- **README.md**: concise, shows install commands first, links to docs/ for details
- **CLAUDE.md**: developer reference, all commands, config table, architecture summary
- **docs/architecture.md**: technical deep-dive, diagrams, design decisions, "why" not just "what"
- **docs/usage.md**: step-by-step with examples, verification commands, troubleshooting
- **docs/why-we-forked.md**: before/after comparisons, rationale

## Release Notes

No manual CHANGELOG — GitHub auto-generates release notes from PR titles and commit messages via `generate_release_notes: true` in the release workflow. Use clear conventional commit messages so release notes are useful.
