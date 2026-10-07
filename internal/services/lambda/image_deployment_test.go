package lambda

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	runtime "stackd/compute/lambda"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const deploymentImageFirstID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const deploymentImageSecondID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

var errImageDeploymentBackend = errors.New("recording execution backend deliberately unavailable")

// This boundary records admission/preparation but never returns a successful
// environment or pretends to execute a handler. Native Docker request generation
// is covered independently in compute/lambda/docker_image_test.go.
type imageDeploymentBoundary struct {
	mu           sync.Mutex
	image        runtime.Image
	resolveError error
	resolutions  []string
	prepared     chan runtime.Specification
	release      <-chan struct{}
}

func (b *imageDeploymentBoundary) ResolveImage(_ context.Context, uri, architecture string) (runtime.Image, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resolutions = append(b.resolutions, uri+"/"+architecture)
	image := *runtime.CloneImage(&b.image)
	image.URI = uri
	return image, b.resolveError
}

func (b *imageDeploymentBoundary) Prepare(ctx context.Context, spec runtime.Specification) (runtime.Environment, error) {
	b.prepared <- spec
	if b.release != nil {
		select {
		case <-b.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errImageDeploymentBackend
}

type imageDeploymentRoles struct{}

func (imageDeploymentRoles) Validate(context.Context, string, string) *awswire.Error { return nil }
func (imageDeploymentRoles) Assume(context.Context, string, string, string) (runtime.Credentials, *awswire.Error) {
	return runtime.Credentials{AccessKeyID: "local-role", SecretAccessKey: "local-secret", SessionToken: "local-session", Expiration: time.Now().Add(time.Hour)}, nil
}

func imageDeploymentFixture(t *testing.T) (*Service, *imageDeploymentBoundary, context.Context, FunctionKey) {
	t.Helper()
	key := FunctionKey{Scope: Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "local-image"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.Account, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: key.Account})
	backend := &imageDeploymentBoundary{image: runtime.Image{ID: deploymentImageFirstID, ResolvedURI: deploymentImageFirstID, Size: 4096, EntryPoint: []string{"/image/bootstrap"}, Command: []string{"image.handler"}, WorkingDirectory: "/image/work", Environment: []string{"IMAGE_DEFAULT=present"}}, prepared: make(chan runtime.Specification, 8)}
	service := New(Config{Executor: backend, Roles: imageDeploymentRoles{}})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return service, backend, ctx, key
}

func imageDeploymentCreateInput(key FunctionKey) *api.CreateFunctionInput {
	return &api.CreateFunctionInput{FunctionName: new(api.FunctionName(key.Name)), Role: new(api.RoleArn("arn:aws:iam::111111111111:role/execution")), PackageType: new(api.PackageType("Image")), Code: &api.FunctionCode{ImageUri: new(api.String("local-unified:latest"))}, Publish: new(api.Boolean(true))}
}

func imageDeploymentRecord(t *testing.T, s *Service, ctx context.Context, key FunctionKey, version uint64) FunctionRecord {
	t.Helper()
	var record FunctionRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		if version == 0 {
			record, err = r.Function(key)
		} else {
			record, err = r.FunctionVersion(FunctionVersionKey{FunctionKey: key, Version: version})
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return record
}

func imageDeploymentPrepared(t *testing.T, backend *imageDeploymentBoundary) runtime.Specification {
	t.Helper()
	select {
	case spec := <-backend.prepared:
		return spec
	case <-time.After(10 * time.Second):
		t.Fatal("image deployment never reached execution preparation")
	}
	return runtime.Specification{}
}

func TestImageDeploymentAdmissionPinsTagAndPublishedSnapshot(t *testing.T) {
	service, backend, ctx, key := imageDeploymentFixture(t)
	release := make(chan struct{})
	backend.release = release
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	input := imageDeploymentCreateInput(key)
	input.ImageConfig = &api.ImageConfig{EntryPoint: api.StringList{"/override/bootstrap"}, Command: api.StringList{"override.handler"}, WorkingDirectory: new(api.WorkingDirectory("/override/work"))}
	created, wire := service.createFunction(ctx, input)
	if wire != nil {
		t.Fatal(wire)
	}
	if value(created.PackageType) != "Image" || created.Runtime != nil || created.Handler != nil || value(created.Version) != "1" {
		t.Fatalf("image CreateFunction projection = %+v", created)
	}
	spec := imageDeploymentPrepared(t, backend)
	backend.mu.Lock()
	backend.image.ID, backend.image.ResolvedURI = deploymentImageSecondID, deploymentImageSecondID
	backend.image.Command[0] = "retagged.handler"
	backend.mu.Unlock()
	input.ImageConfig.Command[0] = "mutated.request"
	if spec.Image == nil || spec.Image.ID != deploymentImageFirstID || spec.Image.Command[0] != "image.handler" || spec.ImageConfig == nil || !reflect.DeepEqual(spec.ImageConfig.Command, []string{"override.handler"}) || spec.ImageConfig.WorkingDirectory != "/override/work" {
		t.Fatalf("retag/request mutation changed prepared image deployment: %+v config=%+v", spec.Image, spec.ImageConfig)
	}
	if len(spec.Code) != 0 || len(spec.Layers) != 0 || spec.Runtime != "" || spec.Handler != "" {
		t.Fatalf("image routed through ZIP deployment: %+v", spec)
	}
	published := imageDeploymentRecord(t, service, ctx, key, 1)
	if published.Image == nil || published.Image.ID != deploymentImageFirstID || published.ImageConfig == nil || string(published.ImageConfig.Command[0]) != "override.handler" {
		t.Fatalf("published image mutated: %+v", published)
	}
	// Reads must not hand callers mutable repository-owned image/config slices.
	published.Image.Command[0] = "mutated.read"
	published.ImageConfig.Command[0] = "mutated.read"
	published = imageDeploymentRecord(t, service, ctx, key, 1)
	if published.Image.Command[0] != "image.handler" || string(published.ImageConfig.Command[0]) != "override.handler" {
		t.Fatalf("repository returned shared image snapshot: %+v", published)
	}
	close(release)
	service.work.Wait()
	latest := imageDeploymentRecord(t, service, ctx, key, 0)
	if latest.State != "Failed" || !strings.Contains(latest.StateReason, errImageDeploymentBackend.Error()) {
		t.Fatalf("backend failure advertised a running function: %+v", latest)
	}
	out, wire := service.getFunction(ctx, &api.GetFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("1"))})
	if wire != nil {
		t.Fatal(wire)
	}
	if out.Code == nil || value(out.Code.ImageUri) != "local-unified:latest" || value(out.Code.ResolvedImageUri) != deploymentImageFirstID || out.Code.Location != nil {
		t.Fatalf("image GetFunction fabricated a ZIP download: %+v", out.Code)
	}
}

func TestImageUpdateFunctionCodeSelectsNewExecutionImageAndPreservesPublication(t *testing.T) {
	service, backend, ctx, key := imageDeploymentFixture(t)
	if _, wire := service.createFunction(ctx, imageDeploymentCreateInput(key)); wire != nil {
		t.Fatal(wire)
	}
	first := imageDeploymentPrepared(t, backend)
	service.work.Wait()
	backend.mu.Lock()
	backend.image.ID, backend.image.ResolvedURI = deploymentImageSecondID, deploymentImageSecondID
	backend.image.Command = []string{"new.handler"}
	backend.mu.Unlock()
	updated, wire := service.updateCode(ctx, &api.UpdateFunctionCodeInput{FunctionName: new(api.FunctionName(key.Name)), ImageUri: new(api.String("local-unified:latest")), Publish: new(api.Boolean(true))})
	if wire != nil {
		t.Fatal(wire)
	}
	if value(updated.PackageType) != "Image" || value(updated.Version) != "2" {
		t.Fatalf("image UpdateFunctionCode projection = %+v", updated)
	}
	second := imageDeploymentPrepared(t, backend)
	service.work.Wait()
	if first.Image == nil || second.Image == nil || first.Image.ID != deploymentImageFirstID || second.Image.ID != deploymentImageSecondID || second.Image.Command[0] != "new.handler" {
		t.Fatalf("UpdateFunctionCode did not change execution image: first=%+v second=%+v", first.Image, second.Image)
	}
	if len(second.Code) != 0 {
		t.Fatal("image update loaded a ZIP code archive")
	}
	publishedFirst := imageDeploymentRecord(t, service, ctx, key, 1)
	publishedSecond := imageDeploymentRecord(t, service, ctx, key, 2)
	if publishedFirst.Image.ID != deploymentImageFirstID || publishedSecond.Image.ID != deploymentImageSecondID || publishedFirst.DeploymentRevision == publishedSecond.DeploymentRevision {
		t.Fatalf("image code update rewrote immutable version: first=%+v second=%+v", publishedFirst, publishedSecond)
	}
	latest := imageDeploymentRecord(t, service, ctx, key, 0)
	if latest.Image.ID != deploymentImageFirstID || latest.UpdateStatus != "Failed" || !strings.Contains(latest.UpdateReason, errImageDeploymentBackend.Error()) || publishedSecond.State != "Failed" {
		t.Fatalf("failed replacement silently became executable: latest=%+v published=%+v", latest, publishedSecond)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if !reflect.DeepEqual(backend.resolutions, []string{"local-unified:latest/x86_64", "local-unified:latest/x86_64"}) {
		t.Fatalf("image tag resolved outside code admission: %q", backend.resolutions)
	}
}

func TestImageAdmissionFailureDoesNotCommitFunction(t *testing.T) {
	service, backend, ctx, key := imageDeploymentFixture(t)
	backend.resolveError = errors.New("lambda image platform linux/arm64 does not match linux/amd64")
	if _, wire := service.createFunction(ctx, imageDeploymentCreateInput(key)); wire == nil || !strings.Contains(wire.Message, "does not match") {
		t.Fatalf("platform mismatch admitted: %v", wire)
	}
	if err := service.repository.View(ctx, func(r Reader) error {
		if _, err := r.Function(key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed admission committed function: %v", err)
		}
		versions, err := r.FunctionVersions(key)
		if err != nil {
			return err
		}
		if len(versions) != 0 {
			t.Fatalf("failed admission committed versions: %+v", versions)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case spec := <-backend.prepared:
		t.Fatalf("platform mismatch reached execution: %+v", spec)
	default:
	}
}

func TestImageConfigurationUpdatePreservesImageIdentityAndOverrides(t *testing.T) {
	service, backend, ctx, key := imageDeploymentFixture(t)
	if _, wire := service.createFunction(ctx, imageDeploymentCreateInput(key)); wire != nil {
		t.Fatal(wire)
	}
	imageDeploymentPrepared(t, backend)
	service.work.Wait()
	config := &api.ImageConfig{Command: api.StringList{"configured.handler", "argument with spaces"}, WorkingDirectory: new(api.WorkingDirectory("/configured/work"))}
	if _, wire := service.updateConfiguration(ctx, &api.UpdateFunctionConfigurationInput{FunctionName: new(api.FunctionName(key.Name)), ImageConfig: config}); wire != nil {
		t.Fatal(wire)
	}
	spec := imageDeploymentPrepared(t, backend)
	service.work.Wait()
	if spec.Image == nil || spec.Image.ID != deploymentImageFirstID || spec.ImageConfig == nil || spec.ImageConfig.EntryPoint != nil || !reflect.DeepEqual(spec.ImageConfig.Command, []string{"configured.handler", "argument with spaces"}) || spec.ImageConfig.WorkingDirectory != "/configured/work" {
		t.Fatalf("ImageConfig update lost defaults/overrides: image=%+v config=%+v", spec.Image, spec.ImageConfig)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.resolutions) != 1 {
		t.Fatalf("configuration update re-resolved mutable tag: %q", backend.resolutions)
	}
}

func TestImageCodeUpdateAdmissionFailurePreservesExistingDeployment(t *testing.T) {
	service, backend, ctx, key := imageDeploymentFixture(t)
	if _, wire := service.createFunction(ctx, imageDeploymentCreateInput(key)); wire != nil {
		t.Fatal(wire)
	}
	imageDeploymentPrepared(t, backend)
	service.work.Wait()
	before := imageDeploymentRecord(t, service, ctx, key, 0)
	backend.mu.Lock()
	backend.resolveError = errors.New("lambda image platform linux/arm64 does not match linux/amd64")
	backend.mu.Unlock()
	if _, wire := service.updateCode(ctx, &api.UpdateFunctionCodeInput{FunctionName: new(api.FunctionName(key.Name)), ImageUri: new(api.String("wrong-platform:latest")), Publish: new(api.Boolean(true))}); wire == nil || !strings.Contains(wire.Message, "does not match") {
		t.Fatalf("platform mismatch admitted during code update: %v", wire)
	}
	after := imageDeploymentRecord(t, service, ctx, key, 0)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed image admission mutated deployment: before=%+v after=%+v", before, after)
	}
	if err := service.repository.View(ctx, func(r Reader) error {
		if _, err := r.PendingFunction(key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed admission left pending image: %v", err)
		}
		versions, err := r.FunctionVersions(key)
		if err != nil {
			return err
		}
		if len(versions) != 1 {
			t.Fatalf("failed image admission published a version: %+v", versions)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case spec := <-backend.prepared:
		t.Fatalf("rejected image reached execution: %+v", spec)
	default:
	}
}

func TestImageConfigurationEmptyDeadLetterAndLoggingReplacePriorControls(t *testing.T) {
	service, backend, ctx, key := imageDeploymentFixture(t)
	release := make(chan struct{})
	backend.release = release
	defer close(release)
	original := FunctionRecord{Key: key, Role: "arn:aws:iam::111111111111:role/execution", Architecture: "x86_64", Image: runtime.CloneImage(&backend.image), CodeSHA256: "admitted-image", State: "Active", Revision: "original", DeploymentRevision: "original", Timeout: 3, MemoryMB: 128, EphemeralMB: 512, DeadLetterARN: "arn:aws:sqs:us-east-1:111111111111:old-dlq", LogGroup: "custom/old", Logging: runtime.LoggingConfig{Format: "JSON", ApplicationLevel: "ERROR", SystemLevel: "WARN"}}
	if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutFunction(original) }); err != nil {
		t.Fatal(err)
	}
	_, wire := service.updateConfiguration(ctx, &api.UpdateFunctionConfigurationInput{FunctionName: new(api.FunctionName(key.Name)), DeadLetterConfig: &api.DeadLetterConfig{}, LoggingConfig: &api.LoggingConfig{}})
	if wire != nil {
		t.Fatal(wire)
	}
	spec := imageDeploymentPrepared(t, backend)
	if spec.LogGroup != "/aws/lambda/"+key.Name || spec.Logging.Format != "Text" || spec.Logging.ApplicationLevel != "" || spec.Logging.SystemLevel != "" {
		t.Fatalf("empty logging configuration retained prior controls: %+v", spec)
	}
	if err := service.repository.View(ctx, func(r Reader) error {
		pending, err := r.PendingFunction(key)
		if err == nil && pending.DeadLetterARN != "" {
			t.Fatalf("empty DeadLetterConfig retained prior target: %+v", pending)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
