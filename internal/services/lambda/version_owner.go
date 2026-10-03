package lambda

import (
	"context"
	"errors"
	"strconv"

	"stackd/internal/awswire"
)

type versionOwnerContextKey struct{}

// WithVersionOwner constrains trusted publication and version-control commands
// to one deployment identity. It never authorizes the caller or changes public
// Lambda request fields. Incomplete identities fail closed.
func WithVersionOwner(ctx context.Context, owner VersionOwner) context.Context {
	return context.WithValue(ctx, versionOwnerContextKey{}, owner)
}

func versionOwnerFor(ctx context.Context) (VersionOwner, *awswire.Error) {
	owner, present := ctx.Value(versionOwnerContextKey{}).(VersionOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return VersionOwner{}, failure("AccessDeniedException", "The version owner identity is incomplete.", 403)
	}
	return owner, nil
}

// Call inside the current-IAM transaction that reads or changes version state.
// Alias resolution must not let an owner mutate a different requested identity.
func requireVersionOwner(r Reader, ref FunctionReference) error {
	owner, wire := versionOwnerFor(r.Context())
	if wire != nil {
		return wire
	}
	if owner == (VersionOwner{}) {
		return nil
	}
	version, err := strconv.ParseUint(ref.Qualifier, 10, 64)
	if err != nil || version == 0 || version >= LatestPublishedVersion {
		return failure("AccessDeniedException", "The version owner requires a numbered publication.", 403)
	}
	key := FunctionVersionKey{FunctionKey: ref.FunctionKey, Version: version}
	existing, err := r.FunctionVersionOwner(key)
	if errors.Is(err, ErrNotFound) {
		// Preserve absence for idempotent controller deletion after a lost
		// response, while refusing to adopt an extant unowned publication.
		if _, missing := r.FunctionVersion(key); missing != nil {
			return missing
		}
	}
	if errors.Is(err, ErrNotFound) || (err == nil && existing != owner) {
		return failure("AccessDeniedException", "The publication does not belong to the requested owner.", 403)
	}
	return err
}
