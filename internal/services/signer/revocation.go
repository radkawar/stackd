package signer

import (
	"context"
	"errors"
	"slices"
	api "stackd/internal/awsapi/signer"
	"stackd/internal/awsctx"
	"strings"
	"time"
)

func registerRevocation(s *Service) {
	register(s, "RevokeSignature", s.revokeSignature)
	register(s, "RevokeSigningProfile", s.revokeProfile)
	register(s, "GetRevocationStatus", s.getRevocationStatus)
}
func (s *Service) revokeSignature(ctx context.Context, t Transaction, in *api.RevokeSignatureInput) (*api.RevokeSignatureOutput, error) {
	if value(in.JobOwner) != "" && value(in.JobOwner) != scopeFor(ctx).AccountID {
		return nil, invalid("Cross-account job revocation is not implemented")
	}
	if strings.TrimSpace(value(in.Reason)) == "" {
		return nil, invalid("A revocation reason is required")
	}
	v, e := s.loadJob(ctx, t, value(in.JobId), "RevokeSignature")
	if e != nil {
		return nil, e
	}
	if v.Status != "Succeeded" {
		return nil, invalid("Only a successful signing job can be revoked")
	}
	if v.RevokedAt.IsZero() {
		v.RevokedAt = s.clock.Now().UTC().Truncate(time.Second)
		v.RevocationReason = value(in.Reason)
		v.RevokedBy = awsctx.FromContext(ctx).PrincipalARN
	}
	return &api.RevokeSignatureOutput{}, t.PutJob(v)
}
func (s *Service) revokeProfile(ctx context.Context, t Transaction, in *api.RevokeSigningProfileInput) (*api.RevokeSigningProfileOutput, error) {
	if in.EffectiveTime == nil || in.EffectiveTime.After(s.clock.Now()) {
		return nil, invalid("Revocation effectiveTime must be in the past")
	}
	if strings.TrimSpace(value(in.Reason)) == "" {
		return nil, invalid("A revocation reason is required")
	}
	v, e := s.loadProfile(ctx, t, value(in.ProfileName), value(in.ProfileVersion), "", "RevokeSigningProfile")
	if e != nil {
		return nil, e
	}
	if !v.RevokedAt.IsZero() && in.EffectiveTime.After(v.EffectiveTime) {
		return nil, invalid("The revocation effective time cannot move later")
	}
	v.Status = "Revoked"
	v.RevokedAt = s.clock.Now().UTC().Truncate(time.Second)
	v.EffectiveTime = in.EffectiveTime.UTC()
	v.RevocationReason = value(in.Reason)
	v.RevokedBy = awsctx.FromContext(ctx).PrincipalARN
	return &api.RevokeSigningProfileOutput{}, t.PutProfile(v)
}
func (s *Service) getRevocationStatus(ctx context.Context, _ Transaction, in *api.GetRevocationStatusInput) (*api.GetRevocationStatusOutput, error) {
	if e := s.authorize(ctx, "GetRevocationStatus", "", nil, nil); e != nil {
		return nil, e
	}
	if value(in.PlatformId) == LambdaPlatform {
		return nil, invalid("Invalid platformId: " + LambdaPlatform)
	}
	return nil, invalid("Container signing revocation platforms are not implemented")
}

// Signature identifies a cryptographically verified native envelope. It is not
// an API request and cannot authorize an unrecognized job or certificate chain.
type Signature struct {
	ProfileVersionARN, JobARN string
	SigningTime               time.Time
	CertificateHashes         []string
}

// Revoked resolves current retained state for the exact verified signing claims.
// Lambda's service-to-service check does not borrow deployment-caller Signer
// permissions. Mutations of that state remain subject to current Signer IAM.
func (s *Service) Revoked(ctx context.Context, sig Signature) (bool, error) {
	sc, id, e := parseResourceARN(sig.JobARN, "signing-jobs")
	if e != nil {
		return false, e
	}
	psc, profileID, e := parseResourceARN(sig.ProfileVersionARN, "signing-profiles")
	if e != nil {
		return false, e
	}
	parts := strings.Split(profileID, "/")
	if len(parts) != 2 || psc != sc {
		return false, invalid("Signing profile and job scopes do not match")
	}
	request := scopeFor(ctx)
	if request.Partition != "" && request.Partition != sc.Partition {
		return false, invalid("Signing partition does not match deployment")
	}
	revoked := false
	e = s.repository.View(ctx, func(r Reader) error {
		job, e := r.Job(sc, id)
		if e != nil {
			return e
		}
		profile, e := r.Profile(sc, parts[0], parts[1])
		if e != nil {
			return e
		}
		if job.Status != "Succeeded" || job.ProfileVersionARN != sig.ProfileVersionARN || !job.Created.Equal(sig.SigningTime) || len(sig.CertificateHashes) == 0 || !slices.Equal(job.CertificateHashes, sig.CertificateHashes) {
			return errors.New("signature is not an authoritative completed signing job")
		}
		revoked = !job.RevokedAt.IsZero() || !profile.RevokedAt.IsZero() && sig.SigningTime.After(profile.EffectiveTime)
		return nil
	})
	return revoked, e
}
