package acm

import "context"

type cfnOwnershipKey struct{}
type cfnOwnership struct {
	claim   string
	enforce bool
	rows    map[string]string
}

// WithCloudFormationOwnership binds native certificate admission and authorized
// observations/mutations to a private incarnation, never to public tags.
func WithCloudFormationOwnership(ctx context.Context, claim string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, &cfnOwnership{claim, enforce, rows})
}
func cloudFormationOwner(ctx context.Context) string {
	if b, _ := ctx.Value(cfnOwnershipKey{}).(*cfnOwnership); b != nil {
		return b.claim
	}
	return ""
}
func observeCloudFormationOwner(ctx context.Context, c CertificateRecord) error {
	b, _ := ctx.Value(cfnOwnershipKey{}).(*cfnOwnership)
	if b == nil {
		return nil
	}
	if b.enforce && (b.claim == "" || c.Owner != b.claim) {
		return failure("ConflictException", "Certificate belongs to another CloudFormation incarnation.")
	}
	if b.rows != nil {
		b.rows[c.ARN] = c.Owner
	}
	return nil
}
