package integrations

import (
	"context"
	"stackd/internal/services/lambda"
	"stackd/internal/services/signer"
)

// LambdaSignerAuthority joins the cryptographic envelope to current retained
// owner authority. It never contacts AWS or trusts envelope-supplied roots.
type LambdaSignerAuthority struct{ Signer *signer.Service }

func (a LambdaSignerAuthority) CodeSigningRoots(ctx context.Context) ([][]byte, error) {
	return a.Signer.CodeSigningRoots(ctx)
}
func (a LambdaSignerAuthority) Revoked(ctx context.Context, v lambda.CodeSignature) (bool, error) {
	return a.Signer.Revoked(ctx, signer.Signature{ProfileVersionARN: v.SigningProfileVersionARN, JobARN: v.SigningJobARN, SigningTime: v.SigningTime, CertificateHashes: v.CertificateHashes})
}

var _ lambda.CodeSigningAuthority = LambdaSignerAuthority{}
