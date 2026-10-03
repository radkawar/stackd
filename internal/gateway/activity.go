package gateway

import (
	"context"
	"slices"

	"stackd/internal/awsctx"
)

// ActivityRecorder persists an authenticated API attempt independently of its
// authorization outcome. The context contains verified credential metadata;
// serviceNamespace and operationName come from the registered service contract.
// A failure prevents dispatch, so an operation cannot silently lose its activity.
type ActivityRecorder interface {
	RecordActivity(ctx context.Context, serviceNamespace, operationName string) error
}

func (g *Gateway) recordActivity(ctx context.Context, service *Service, action string) error {
	if g.config.Activity != nil {
		var known bool
		if service.Model != nil {
			_, known = service.Model.Operation(action)
		} else {
			known = slices.Contains(service.Provider.Operations(), action)
		}
		if !known {
			return nil
		}
	}
	return g.recordKnownActivity(ctx, service, action)
}

// recordKnownActivity accepts an operation selected by a public model or a
// private native provider. Both use the same authenticated usage owner.
func (g *Gateway) recordKnownActivity(ctx context.Context, service *Service, action string) error {
	m := awsctx.FromContext(ctx)
	if m.AccessKeyID == "" {
		// Unsigned federation and anonymous S3 have no verified AWS access key
		// whose authenticated usage can be recorded.
		return nil
	}
	if g.config.Activity != nil {
		return g.config.Activity.RecordActivity(ctx, service.Name, action)
	}
	// Standalone gateways can retain credential-only usage without an IAM
	// activity repository. Integrated instances use only the recorder above.
	if recorder, ok := g.config.Credentials.(usageRecorder); ok {
		return recorder.RecordUsage(ctx, m.AccessKeyID, service.SigningName, m.Region)
	}
	return nil
}
