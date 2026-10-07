package lambda

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// AdditionalOwner is the retained incarnation claim for non-function Lambda
// configuration resources. It never substitutes for current IAM authorization.
type AdditionalOwner struct {
	StackID, LogicalID, Token string
}

type additionalOwnerContextKey struct{}
type additionalOwnerCommand struct {
	Owner  AdditionalOwner
	Create bool
}

// WithAdditionalOwner is a trusted in-process boundary, not a native API field.
func WithAdditionalOwner(ctx context.Context, owner AdditionalOwner, create bool) context.Context {
	return context.WithValue(ctx, additionalOwnerContextKey{}, additionalOwnerCommand{Owner: owner, Create: create})
}

func additionalOwnerFor(ctx context.Context) (AdditionalOwner, bool, error) {
	command, present := ctx.Value(additionalOwnerContextKey{}).(additionalOwnerCommand)
	if present && (command.Owner.StackID == "" || command.Owner.LogicalID == "" || command.Owner.Token == "") {
		return AdditionalOwner{}, false, failure("AccessDeniedException", "The Lambda configuration owner identity is incomplete.", 403)
	}
	return command.Owner, command.Create, nil
}

func requireAdditionalOwner(ctx context.Context, current AdditionalOwner) error {
	owner, _, err := additionalOwnerFor(ctx)
	if err != nil {
		return err
	}
	if owner != (AdditionalOwner{}) && owner != current {
		return failure("AccessDeniedException", "The Lambda configuration belongs to a different resource incarnation.", 403)
	}
	return nil
}

func additionalSigningID(owner AdditionalOwner) string {
	sum := sha256.Sum256([]byte(owner.StackID + "/" + owner.LogicalID + "/" + owner.Token))
	return "csc-" + hex.EncodeToString(sum[:])[:17]
}
