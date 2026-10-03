package lambda

import (
	"context"
	"time"

	"stackd/compute/lambda/signature"
)

// CodeSignature carries authenticated claims to Lambda's deployment policy and
// its consumer-defined current Signer authority. Integrity alone is not admission.
type CodeSignature signature.Claims

var (
	ErrCodeSignatureMissing   = signature.ErrMissing
	ErrCodeSignatureIntegrity = signature.ErrIntegrity
)

func verifyCodeSignature(ctx context.Context, code []byte, now time.Time, trustedRoots [][]byte) (CodeSignature, error) {
	claims, err := signature.Verify(ctx, code, now, trustedRoots)
	return CodeSignature(claims), err
}
