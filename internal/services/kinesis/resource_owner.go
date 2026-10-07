package kinesis

import (
	"context"
	"errors"
	"strings"
)

// ResourceOwner is private native authority, independent of mutable customer tags.
type ResourceOwner struct{ StackID, LogicalID, Token string }
type resourceOwnerKey struct{}
type resourceOwnerConstraint struct {
	Owner  ResourceOwner
	Kind   string
	Create bool
}

func WithResourceOwner(ctx context.Context, owner ResourceOwner, kind string, create bool) context.Context {
	return context.WithValue(ctx, resourceOwnerKey{}, resourceOwnerConstraint{owner, kind, create})
}

func resourceOwnerFor(ctx context.Context) (resourceOwnerConstraint, error) {
	c, present := ctx.Value(resourceOwnerKey{}).(resourceOwnerConstraint)
	if present && (c.Owner.StackID == "" || c.Owner.LogicalID == "" || c.Owner.Token == "" || (c.Kind != "stream" && c.Kind != "consumer" && c.Kind != "policy")) {
		return c, failure("AccessDeniedException", "Incomplete Kinesis resource owner")
	}
	return c, nil
}

func checkResourceOwner(ctx context.Context, r Reader, key ResourceKey, action string) error {
	c, err := resourceOwnerFor(ctx)
	if err != nil || c.Owner == (ResourceOwner{}) {
		return err
	}
	var actual ResourceOwner
	switch c.Kind {
	case "policy":
		if action != "GetResourcePolicy" && action != "PutResourcePolicy" && action != "DeleteResourcePolicy" {
			return nil
		}
		record, lookup := r.Policy(key)
		if errors.Is(lookup, ErrNotFound) || lookup == nil && record.Policy.Document == "" {
			if c.Create {
				return nil
			}
			return failure("ResourceNotFoundException", "No resource policy found for resource ARN "+key.ARN+".")
		}
		if lookup != nil {
			return lookup
		}
		actual = record.Owner
	case "consumer":
		if !strings.Contains(key.ARN, "/consumer/") {
			return nil
		}
		k, parse := consumerKey(ctx, key.ARN)
		if parse != nil {
			return parse
		}
		record, lookup := r.Consumer(k)
		if errors.Is(lookup, ErrNotFound) {
			return nil
		}
		if lookup != nil {
			return lookup
		}
		actual = record.Owner
	case "stream":
		arn, _, _ := strings.Cut(key.ARN, "/consumer/")
		k, parse := streamKey(ctx, "", arn)
		if parse != nil {
			return parse
		}
		record, lookup := r.Stream(k)
		if errors.Is(lookup, ErrNotFound) {
			return nil
		}
		if lookup != nil {
			return lookup
		}
		actual = record.Owner
	}
	if actual != c.Owner || key.Scope != scopeFor(ctx) {
		if c.Kind == "policy" && actual == (ResourceOwner{}) && !c.Create {
			return failure("ResourceNotFoundException", "The policy is not owned by this resource incarnation")
		}
		if c.Create {
			return failure("AlreadyExistsException", "The Kinesis resource belongs to a different resource incarnation")
		}
		return failure("AccessDeniedException", "The Kinesis resource belongs to a different resource incarnation")
	}
	return nil
}
