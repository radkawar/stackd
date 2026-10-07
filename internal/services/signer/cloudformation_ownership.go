package signer

import "context"

type cfnOwnershipKey struct{}
type cfnOwnership struct {
	claim   string
	enforce bool
	rows    map[string]string
}

// WithCloudFormationOwnership binds authorized native commands to a private
// incarnation. Observations are emitted only after current IAM authorizes reads.
func WithCloudFormationOwnership(ctx context.Context, claim string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, &cfnOwnership{claim, enforce, rows})
}
func cloudFormationOwner(ctx context.Context) string {
	if b, _ := ctx.Value(cfnOwnershipKey{}).(*cfnOwnership); b != nil {
		return b.claim
	}
	return ""
}
func observeCloudFormationOwner(ctx context.Context, v Profile) error {
	b, _ := ctx.Value(cfnOwnershipKey{}).(*cfnOwnership)
	if b == nil {
		return nil
	}
	if b.enforce && (b.claim == "" || v.Owner != b.claim) {
		return failure("ConflictException", "Signing profile belongs to another CloudFormation incarnation", 409)
	}
	if b.rows != nil {
		b.rows[v.ARN] = v.Owner
	}
	return nil
}
