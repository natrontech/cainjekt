# Go Conventions

## Philosophy

Write idiomatic Go. Follow [Effective Go](https://go.dev/doc/effective_go) and [The Zen of Go](https://the-zen-of-go.netlify.app/). Key principles:

- Each package fulfils a single purpose
- Handle errors explicitly
- Return early rather than nesting deeply
- Write for clarity, not cleverness
- A little copying is better than a little dependency
- Simplicity is not a goal, it is the prerequisite

## Imports

Three groups separated by blank lines: stdlib, external, internal.

```go
import (
    "fmt"
    "log/slog"
    "os"

    "github.com/containerd/nri/pkg/api"

    "github.com/tsuzu/cainjekt/internal/config"
)
```

## Naming

- **Exported**: PascalCase (`NewDebian`, `MergePEM`, `AtomicWrite`)
- **Unexported**: camelCase (`parseOSRelease`, `resolveContainerSymlinks`)
- **Constructors**: `New<Type>(...) (*Type, error)` or `New<Type>() *Type`
- **Method receivers**: short names (`p *processor`, `s *State`, `c *Context`)
- **Interfaces**: semantic names (`Processor`, `WrapperProcessor`, `FactStore`)
- **Packages**: single lowercase word (`config`, `hook`, `wrapper`, `certs`, `fsx`)

## Error Handling

```go
if err != nil {
    return fmt.Errorf("failed to <action>: %w", err)
}
```

Always wrap with context using `%w`. Use `slog.Error()` before `os.Exit(1)` in main.

## Logging

`log/slog` with structured key-value pairs:

```go
slog.Info("processor result", "name", r.Name, "applied", r.Applied)
slog.Error("hook failed", "error", err)
```

## File Organization

- Feature-based naming (`plugin.go`, `dynamic_ca.go`, `registry.go`)
- Tests alongside source: `_test.go` suffix, standard `testing` package
- Structure within file: package decl, imports, types/interfaces, constructors, methods, helpers

## Dependencies

Run `go mod tidy` after adding or removing dependencies. Keep dependency count low. Prefer stdlib. No CGO.

## Patterns

- **Context**: pass `*hookapi.Context` through processor pipeline, not `context.Context` (this is OCI hook level, not HTTP)
- **Processor interface**: `Detect(*Context) DetectResult` + `Apply(*Context) error`
- **Registry pattern**: global init-time registration, runtime lookup by name
- **Atomic file writes**: always use `fsx.AtomicWrite` with symlink protection for CA files
- **Fail-open by default**: hook failures must not block container startup
