package wafv2

import "context"

// ResourceOwner is the private native claim on one web ACL or IP set creation.
// It is never populated from customer tags or exposed in AWS response models.
type ResourceOwner struct{ StackID, LogicalID, Token string }

type resourceOwnerContextKey struct{}

// WithResourceOwner constrains trusted in-process creation, observations and
// mutations to this exact incarnation. Native requests remain IAM-authorized
// direct operations; this context does not grant any IAM permission.
func WithResourceOwner(ctx context.Context, owner ResourceOwner) context.Context {
	return context.WithValue(ctx, resourceOwnerContextKey{}, owner)
}

func resourceOwnerFor(ctx context.Context) (ResourceOwner, error) {
	owner, present := ctx.Value(resourceOwnerContextKey{}).(ResourceOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return ResourceOwner{}, failure("AccessDeniedException", "The WAF resource owner identity is incomplete", 403)
	}
	return owner, nil
}

func checkResourceOwner(ctx context.Context, actual ResourceOwner) error {
	owner, err := resourceOwnerFor(ctx)
	if err != nil {
		return err
	}
	if owner != (ResourceOwner{}) && owner != actual {
		return failure("AccessDeniedException", "The WAF resource belongs to a different resource incarnation", 403)
	}
	return nil
}
