package lambda

import (
	"context"
	"encoding/json"

	"stackd/journal"
)

type codeSigningAuditKey struct{}
type codeSigningAudit struct {
	Profile string `json:"signingProfileVersionArn,omitempty"`
	Job     string `json:"signingJobArn,omitempty"`
	Status  string `json:"signatureStatus,omitempty"`
}

// withCodeSigningAudit reserves the request-local result before dispatch, so
// both accepted and rejected admissions reach the ordinary API event recorder.
func withCodeSigningAudit(ctx context.Context) context.Context {
	return context.WithValue(ctx, codeSigningAuditKey{}, &codeSigningAudit{})
}

func setCodeSigningAudit(ctx context.Context, signature CodeSignature, status string) {
	if result, ok := ctx.Value(codeSigningAuditKey{}).(*codeSigningAudit); ok {
		// A later valid layer must not replace an earlier warning.
		if result.Status != "" && result.Status != "VALID" {
			return
		}
		*result = codeSigningAudit{Profile: signature.SigningProfileVersionARN, Job: signature.SigningJobARN, Status: status}
	}
}

func applyCodeSigningAudit(ctx context.Context, call *journal.APICallCompleted) {
	// Native rejected deployments record the modeled error but no signature
	// AdditionalEventData. Only accepted valid/Warn outcomes include it.
	if call.ErrorCode != "" {
		return
	}
	if result, ok := ctx.Value(codeSigningAuditKey{}).(*codeSigningAudit); ok && result.Status != "" {
		// Strings only: marshaling cannot fail.
		call.AdditionalEventData, _ = json.Marshal(result)
	}
}
