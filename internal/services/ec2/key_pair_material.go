package ec2

import (
	"context"

	api "stackd/internal/awsapi/ec2"
)

type keyPairMaterialSinkKey struct{}

// WithKeyPairMaterialSink supplies a trusted in-process consumer of newly
// generated key material. The callback joins the key owner's transaction and
// must persist the material through an owner sharing that transaction before
// returning. A failure rejects key creation; private material is never retained
// in the EC2 resource record or passed to the audit projection.
func WithKeyPairMaterialSink(ctx context.Context, sink func(context.Context, *api.KeyPair) error) context.Context {
	return context.WithValue(ctx, keyPairMaterialSinkKey{}, sink)
}

func retainKeyPairMaterial(ctx context.Context, pair *api.KeyPair) error {
	sink, _ := ctx.Value(keyPairMaterialSinkKey{}).(func(context.Context, *api.KeyPair) error)
	if sink == nil {
		return nil
	}
	return sink(ctx, pair)
}

type keyPairDeletionSinkKey struct{}

// WithKeyPairDeletionSink supplies a trusted material cleanup joining the exact
// key deletion transaction. The native owner first authorizes and fences the
// actual key; sink failure rolls back deletion and any joined cleanup.
func WithKeyPairDeletionSink(ctx context.Context, sink func(context.Context, string) error) context.Context {
	return context.WithValue(ctx, keyPairDeletionSinkKey{}, sink)
}

func deleteKeyPairMaterial(ctx context.Context, id string) error {
	sink, _ := ctx.Value(keyPairDeletionSinkKey{}).(func(context.Context, string) error)
	if sink == nil {
		return nil
	}
	return sink(ctx, id)
}
