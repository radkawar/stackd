package codebuild

import (
	"context"
	runtime "stackd/compute/codebuild"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"time"
)

type BuildRoles interface {
	Validate(context.Context, string, string) error
	Assume(context.Context, string, string, string) (identity.Credential, *awswire.Error)
	Context(context.Context, identity.Credential, string) (context.Context, error)
}
type Objects interface {
	Read(context.Context, string, string, string) ([]byte, error)
	ReadFolder(context.Context, string, string) ([]runtime.File, error)
	ReadBuildspec(context.Context, string, string) ([]byte, error)
	Write(context.Context, string, string, []byte, string) error
}

// PipelineArtifacts resolves the admitted action's artifact bindings in the
// shared transaction. It must verify the project, primary source and output
// locations against the current pipeline action, not infer metadata from S3
// headers or caller-supplied environment variables. Reads of artifact bytes and
// all other external effects belong to subsequent build-role execution.
type PipelineArtifacts interface {
	ResolveBuild(ctx context.Context, actionExecutionID, projectARN, sourceARN, outputARN string) (PipelineBuild, error)
}

type PipelineBuild struct {
	PipelineName string
	// Inputs begins with the primary source containing the buildspec.
	Inputs  []PipelineInput
	Outputs []PipelineOutput
}

// PipelineInput retains optional copied-object metadata separately from its
// original source revision. Only RevisionID is CodeBuild's resolvedSourceVersion.
// The admitted artifact ARN remains the public source object locator.
type PipelineInput struct {
	Name, Location, VersionID, RevisionID string
}

// PipelineOutput binds a pipeline artifact name to its exact output object.
// EncryptionKey is the artifact store's KMS key, not an S3 object metadata field.
type PipelineOutput struct {
	Name, Location, EncryptionKey string
}
type Secrets interface {
	Read(context.Context, string) (string, error)
}

// Parameters resolves references under the current build role. Values are used
// only for native environment preparation, never written into build state.
type Parameters interface {
	Read(context.Context, []string) (map[string]string, error)
}
type CredentialCipher interface {
	Seal(context.Context, string, string, string) ([]byte, error)
	Open(context.Context, string, []byte) (string, string, error)
}
type BuildLogs interface {
	Write(context.Context, string, string, []byte, time.Time) error
}
type Registry interface {
	Authorization(context.Context, string) (*runtime.RegistryAuth, error)
}
type BuildEvent struct {
	Key    BuildKey
	ID     string
	At     time.Time
	Detail []byte
}
type EventPublisher interface {
	PublishBuildEvent(context.Context, BuildEvent) error
}
