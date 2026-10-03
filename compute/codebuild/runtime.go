// Package codebuild defines the native build-container boundary. AWS admission,
// authorization, service time, Logs and S3 publication belong to the service.
package codebuild

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("CodeBuild execution does not exist")

// Executor retains isolated native containers across controller shutdown.
// Prepare is idempotent by ARN and must never restart an existing execution.
type Executor interface {
	Prepare(context.Context, Specification) (Execution, error)
	Open(context.Context, string) (Execution, error)
	Remove(context.Context, string) error
}

type RegistryAuth struct{ Username, Password, ServerAddress string }
type GitSource struct {
	URL, Version, Username, Password string
	Depth                            int
	FetchSubmodules                  bool
}

// Source is a named secondary workspace supplied by the source owner.
// Exactly one of ZIP, Files or Git supplies its contents.
type Source struct {
	Identifier string
	ZIP        []byte
	Files      []File
	Git        *GitSource
}
type Specification struct {
	ARN, Image, Buildspec, FleetARN string
	RegistryAuth                    *RegistryAuth
	Environment                     []string
	// SensitiveEnvironment names variables whose exact values must be masked in
	// output. Only names are stored separately; values remain in native Env.
	SensitiveEnvironment  []string
	SourceZIP             []byte
	SourceFiles           []File
	SecondarySources      []Source
	Git                   *GitSource
	CacheZIP              []byte
	MemoryBytes, CPUQuota int64
	// ResolveSecret resolves a buildspec Secrets Manager reference as the build
	// role. It is called only during preparation and never retained by the runtime.
	ResolveSecret func(context.Context, string) (string, error)
	// ResolveParameters retrieves buildspec Parameter Store references as the
	// current build role; returned values never enter retained build metadata.
	ResolveParameters func(context.Context, []string) (map[string]string, error)
}

// Execution.Close detaches; only Stop or Remove may terminate customer code.
// Files returns files selected by buildspec artifacts/cache globs, not invented
// output. Logs uses byte offsets in the retained native stdout stream.
type Execution interface {
	Start(context.Context) error
	Inspect(context.Context) (Status, error)
	Stop(context.Context) error
	Logs(context.Context, int64) ([]byte, int64, error)
	Files(context.Context, string) ([]File, error)
	Close() error
}
type File struct {
	Path string
	Body []byte
	Mode uint32
}
type Phase struct {
	Name, Status, Message string
	Started, Ended        time.Time
}
type Status struct {
	State             string // created, running, exited
	ExitCode          int
	Error             string
	Phases            []Phase
	ExportedVariables map[string]string
	// ArtifactNames holds shell-expanded primary/secondary buildspec names,
	// keyed by the corresponding Files selector.
	ArtifactNames map[string]string
}
