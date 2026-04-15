# Git Conventions

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Concise, imperative mood. Focus on "why" not "what".

Format: `<type>[optional scope]: <description>`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

```
feat(processor): add Java JKS keystore injection
fix(hook): handle read-only root filesystem gracefully
docs: update limitation notes in CLAUDE.md
ci: add golangci-lint to CI pipeline
refactor(osstore): extract symlink resolution into helper
chore: update Go dependencies
test(python): add wrapper env var override test
```

## Branch Strategy

Work on `main` for now. Feature branches for larger changes.

## Worktree Merge

When finishing work in an isolated worktree, merge cleanly back to main: no merge commits, no worktree branch names in history.

1. Squash all worktree commits into one clean commit (if multiple exist)
2. From the main repo, fast-forward merge: `git merge <worktree-branch> --ff-only`
3. If main has advanced, rebase the worktree branch first
4. Delete the worktree branch after merge
