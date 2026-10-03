package lambda_test

import (
	"context"
	"reflect"
	"testing"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	service "stackd/internal/services/lambda"
	"stackd/storage/lambda"
)

type layerPermissionFenceContextKey struct{}

type layerPermissionFenceRepository struct {
	lambda.Repository
	entered chan struct{}
	release chan struct{}
}

func (r layerPermissionFenceRepository) Update(ctx context.Context, fn func(lambda.Transaction) error) error {
	if gated, _ := ctx.Value(layerPermissionFenceContextKey{}).(bool); gated {
		close(r.entered)
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return r.Repository.Update(ctx, fn)
}

func TestLayerPermissionRevisionFencesConcurrentNativeReplacement(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		key := permissionOwnerKey()
		seedPermissionLayer(t, repo, key.LayerVersionKey)
		ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
		native := service.New(service.Config{Repository: repo})
		t.Cleanup(func() { _ = native.Close() })
		in, deletion := permissionOwnerInput(key), permissionOwnerDelete(key)
		first := permissionOwnerAdd(t, native, ctx, in)
		deletion.RevisionId = first.RevisionId
		fence := layerPermissionFenceRepository{Repository: repo, entered: make(chan struct{}), release: make(chan struct{})}
		stale := service.New(service.Config{Repository: fence})
		t.Cleanup(func() { _ = stale.Close() })
		result := make(chan *awswire.Error, 1)
		go func() {
			_, wire := storedAliasCommand(t, stale, context.WithValue(ctx, layerPermissionFenceContextKey{}, true), "RemoveLayerVersionPermission", deletion)
			result <- wire
		}()
		<-fence.entered
		// The stale operation has reached its mutation boundary. A native writer
		// replaces exactly that Sid before the stale transaction can begin.
		if _, wire := storedAliasCommand(t, native, ctx, "RemoveLayerVersionPermission", deletion); wire != nil {
			close(fence.release)
			t.Fatal(wire)
		}
		in.OrganizationId = new(api.OrganizationId("o-1234567890"))
		replacement, wire := storedAliasCommand(t, native, ctx, "AddLayerVersionPermission", in)
		close(fence.release)
		staleWire := <-result
		if wire != nil {
			t.Fatal(wire)
		}
		requirePermissionCode(t, staleWire, "PreconditionFailedException")
		out, wire := storedAliasCommand(t, native, ctx, "GetLayerVersionPolicy", &api.GetLayerVersionPolicyInput{LayerName: in.LayerName, VersionNumber: in.VersionNumber})
		if wire != nil {
			t.Fatal(wire)
		}
		if !reflect.DeepEqual(out.(*api.GetLayerVersionPolicyOutput).RevisionId, replacement.(*api.AddLayerVersionPermissionOutput).RevisionId) {
			t.Fatal("stale revision deletion changed native replacement")
		}
	})
}
