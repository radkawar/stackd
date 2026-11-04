package gateway

import (
	"context"
	"slices"

	"stackd/internal/awsctx"
)

// ActivityRecorder enqueues an authenticated API attempt independently of its
// authorization outcome, without waiting for storage. The context contains
// verified credential metadata; serviceNamespace and operationName come from
// the registered service contract. Reporting errors never prevent dispatch.
type ActivityRecorder interface {
	RecordActivity(ctx context.Context, serviceNamespace, operationName string) error
}

func (g *Gateway) recordActivity(ctx context.Context, service *Service, action string) {
	if g.config.Activity == nil {
		return
	}
	var known bool
	if service.Model != nil {
		_, known = service.Model.Operation(action)
	} else {
		known = slices.Contains(service.Provider.Operations(), action)
	}
	if known {
		g.recordKnownActivity(ctx, service, action)
	}
}

// recordKnownActivity accepts an operation selected by a public model or a
// private native provider. Both use the same authenticated usage owner.
func (g *Gateway) recordKnownActivity(ctx context.Context, service *Service, action string) {
	if g.config.Activity == nil || awsctx.FromContext(ctx).AccessKeyID == "" {
		// Unsigned federation and anonymous S3 have no verified AWS access key
		// whose authenticated usage can be recorded.
		return
	}
	// Activity is asynchronous reporting, not admission for the service effect.
	// Its owner exposes persistence failures at an explicit drain or shutdown.
	_ = g.config.Activity.RecordActivity(ctx, service.Name, action)
}
