package lambda

import (
	"context"
	"errors"
	"slices"

	"stackd/internal/awswire"
)

// CodeSigningAuthority owns trusted certificate roots and current revocations,
// never assertions supplied by a deployment ZIP. Calls run outside the Lambda
// repository transaction; unavailable authority does not imply non-revoked.
type CodeSigningAuthority interface {
	CodeSigningRoots(context.Context) ([][]byte, error)
	Revoked(context.Context, CodeSignature) (bool, error)
}

func (s *Service) verifyDeploymentSignature(ctx context.Context, code []byte) (CodeSignature, error) {
	var roots [][]byte
	if s.codeSigningAuthority != nil {
		var err error
		roots, err = s.codeSigningAuthority.CodeSigningRoots(ctx)
		if err != nil {
			return CodeSignature{}, err
		}
	}
	return verifyCodeSignature(ctx, code, s.clock.Now(), roots)
}

type codeSigningAdmission struct {
	service         *Service
	function        FunctionKey
	config          *CodeSigningConfigRecord
	explicit        bool
	signature       CodeSignature
	codePresent     bool
	warnings        int64
	validSignatures []CodeSignature
}

// prepareCodeSigning verifies actual deployment bytes, including retained layer
// archives rather than deletable catalog entries. Nil code means a layer-only
// configuration update; attaching a CSC alone intentionally does not call this.
func (s *Service) prepareCodeSigning(ctx context.Context, function FunctionKey, arn string, code []byte, layers []LayerAttachment) (*codeSigningAdmission, *awswire.Error) {
	a := &codeSigningAdmission{service: s, function: function, explicit: arn != "", codePresent: code != nil}
	var layerCode [][]byte
	err := s.repository.View(ctx, func(r Reader) error {
		var key CodeSigningConfigKey
		var err error
		if arn != "" {
			var wire *awswire.Error
			key, wire = parseCodeSigningConfigARN(ctx, arn)
			if wire != nil {
				return wire
			}
		} else {
			key, err = r.FunctionCodeSigningConfig(function)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
		}
		if key.Scope != function.Scope {
			return failure("CodeSigningConfigNotFoundException", "Code signing configuration not found.", 404)
		}
		v, err := r.CodeSigningConfig(key)
		if errors.Is(err, ErrNotFound) {
			return failure("CodeSigningConfigNotFoundException", "Code signing configuration not found.", 404)
		}
		if err != nil {
			return err
		}
		a.config = &v
		for _, layer := range layers {
			archive, err := r.CodeArchive(CodeArchiveKey{Scope: layer.Key.Scope, SHA256: layer.CodeSHA256})
			if err != nil {
				return err
			}
			layerCode = append(layerCode, archive.Code)
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	if code != nil {
		signature, err := s.verifyDeploymentSignature(ctx, code)
		if err == nil {
			a.signature = signature
		}
		if a.config != nil {
			if wire := a.check(ctx, signature, err); wire != nil {
				return nil, wire
			}
		}
	}
	for _, bytes := range layerCode {
		signature, err := s.verifyDeploymentSignature(ctx, bytes)
		if wire := a.check(ctx, signature, err); wire != nil {
			return nil, wire
		}
	}
	return a, nil
}

func (a *codeSigningAdmission) check(ctx context.Context, signature CodeSignature, verification error) *awswire.Error {
	status := "VALID"
	if errors.Is(verification, ErrCodeSignatureMissing) {
		status = "MISMATCH"
	} else if verification != nil {
		if !errors.Is(verification, ErrCodeSignatureIntegrity) {
			return failure("ServiceException", "Cannot verify the code signing certificate authority: "+verification.Error(), 503)
		}
		status = "INVALID"
	} else {
		if a.service.codeSigningAuthority == nil {
			return failure("ServiceException", "The AWS Signer revocation authority is not configured; signed deployment cannot be verified.", 503)
		}
		revoked, err := a.service.codeSigningAuthority.Revoked(ctx, signature)
		if err != nil {
			return failure("ServiceException", "Cannot verify the current AWS Signer revocation status: "+err.Error(), 503)
		}
		switch {
		case !a.service.clock.Now().Before(signature.Expires):
			status = "EXPIRED"
		case !slices.Contains(a.config.Publishers, signature.SigningProfileVersionARN):
			status = "MISMATCH"
		case revoked:
			status = "REVOKED"
		}
	}
	setCodeSigningAudit(ctx, signature, status)
	if status == "VALID" {
		a.validSignatures = append(a.validSignatures, signature)
		return nil
	}
	a.warnings++
	if a.config.Policy == "Warn" && status != "INVALID" {
		return nil
	}
	// A rejected deployment leaves code untouched but still emits the native
	// validation metric; this is an outcome, not a successful deployment write.
	if err := a.service.repository.Update(ctx, func(tx Transaction) error {
		return a.service.stageMetric(tx, FunctionReference{FunctionKey: a.function}, a.service.clock.Now(), "SignatureValidationErrors", 1)
	}); err != nil {
		return wireError(err)
	}
	a.service.jobs.Wake()
	return failure("CodeVerificationFailedException", "Lambda cannot deploy the function. The function or layer signature failed the code signing configuration validation ("+status+").", 400)
}

func (a *codeSigningAdmission) commit(tx Transaction, creating bool) error {
	if a == nil {
		return nil
	}
	// Fence a concurrent attach/detach/policy update between cryptographic I/O
	// and code admission. A stale verification must never weaken new policy.
	if !creating {
		key, err := tx.FunctionCodeSigningConfig(a.function)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if (a.config == nil) != errors.Is(err, ErrNotFound) || (a.config != nil && key != a.config.Key) {
			return failure("ResourceConflictException", "Code signing configuration changed during deployment.", 409)
		}
	}
	if a.config == nil {
		return nil
	}
	current, err := tx.CodeSigningConfig(a.config.Key)
	if err != nil {
		return err
	}
	if current.Policy != a.config.Policy || !slices.Equal(current.Publishers, a.config.Publishers) {
		return failure("ResourceConflictException", "Code signing policy changed during deployment.", 409)
	}
	warnings := a.warnings
	for _, signature := range a.validSignatures {
		if !a.service.clock.Now().Before(signature.Expires) {
			setCodeSigningAudit(tx.Context(), signature, "EXPIRED")
			if current.Policy == "Enforce" {
				return failure("CodeVerificationFailedException", "The code signature expired before deployment admission committed.", 400)
			}
			warnings++
		}
	}
	if creating && a.explicit {
		if err := tx.PutFunctionCodeSigningConfig(a.function, a.config.Key); err != nil {
			return err
		}
	}
	if warnings > 0 {
		return a.service.stageMetric(tx, FunctionReference{FunctionKey: a.function}, a.service.clock.Now(), "SignatureValidationErrors", warnings)
	}
	return nil
}

func (a *codeSigningAdmission) applyFunction(v *FunctionRecord) {
	if a == nil || !a.codePresent {
		return
	}
	v.SigningProfileVersionARN = a.signature.SigningProfileVersionARN
	v.SigningJobARN = a.signature.SigningJobARN
}
