# Documentation Conventions

## When to Update Docs

Documentation must be updated in the same commit as code changes when:

- A new processor is added → update README.md (features, known limitations), CLAUDE.md (architecture section), deploy/kubernetes/README.md (processor selection)
- A new configuration option is added → update README.md (configuration table), deploy/kubernetes/README.md (environment variables), charts/cainjekt/values.yaml (with `@param` comments), CLAUDE.md (configuration section)
- Annotations change → update README.md, deploy/kubernetes/README.md, deploy/kubernetes/examples/, charts/cainjekt/templates/NOTES.txt
- Helm chart values change → update charts/cainjekt/values.yaml comments and NOTES.txt
- Build/test commands change → update CLAUDE.md (common commands), Makefile

## Files to Keep in Sync

| Change | Files to update |
|--------|----------------|
| New processor | README.md, CLAUDE.md, deploy/kubernetes/README.md |
| New env var | README.md, CLAUDE.md, deploy/kubernetes/README.md, values.yaml, daemonset.yaml |
| New annotation | README.md, CLAUDE.md, deploy/kubernetes/README.md, .claude/rules/general.md, NOTES.txt |
| New make target | CLAUDE.md, Makefile |
| New CI job | .claude/rules/cicd.md |
| Architecture change | CLAUDE.md, README.md |

## Style

- README.md: user-facing, concise, shows install commands first
- CLAUDE.md: developer-facing, architecture details, all commands
- deploy/kubernetes/README.md: ops-facing, step-by-step with troubleshooting
- Helm NOTES.txt: post-install quick reference

## Release Notes

No manual CHANGELOG — GitHub auto-generates release notes from PR titles and commit messages via `generate_release_notes: true` in the release workflow. Use clear conventional commit messages so release notes are useful.
