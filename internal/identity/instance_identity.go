package identity

import (
	"context"
	"strings"
	"time"

	"stackd/journal"
)

// EC2InstanceIdentitySpec identifies an instance whose private metadata owner
// requests intrinsic credentials. It is not an IAM role or trust-policy input.
type EC2InstanceIdentitySpec struct {
	InstanceARN string
	// RoleDelivery is the trusted metadata owner's IMDS version: "1.0" or "2.0".
	RoleDelivery         string
	Duration             time.Duration
	RequestParentEventID string
}

// IssueEC2InstanceIdentity issues an instance's restricted service identity.
// The caller must bind the store to its IAM authority transaction. No IAM role,
// AssumeRole operation or parent access key is created for this identity.
func (s *Store) IssueEC2InstanceIdentity(ctx context.Context, spec EC2InstanceIdentitySpec) (Credential, error) {
	parts := strings.SplitN(spec.InstanceARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "ec2" || parts[3] == "" || !accountPattern.MatchString(parts[4]) || !strings.HasPrefix(parts[5], "instance/i-") || strings.Contains(parts[5][len("instance/"):], "/") || len(parts[5]) <= len("instance/i-") {
		return Credential{}, ErrInvalidPrincipal
	}
	if spec.Duration <= 0 {
		return Credential{}, ErrInvalidDuration
	}
	instanceID := parts[5][len("instance/"):]
	principal := Principal{
		AccountID: parts[4],
		ARN:       "arn:" + parts[1] + ":sts::" + parts[4] + ":assumed-role/aws:ec2-instance/" + instanceID,
		ID:        parts[4] + ":aws:ec2-instance:" + instanceID,
	}
	var credential Credential
	err := s.repository.Update(ctx, func(tx Transaction) error {
		instant := s.now()
		var err error
		credential, err = newCredential(principal, "ASIA", instant)
		if err != nil {
			return err
		}
		credential.SessionType = SessionTypeEC2InstanceIdentity
		credential.IssuerARN = "arn:" + parts[1] + ":iam::" + parts[4] + ":role/aws:ec2-instance"
		credential.IssuerID = parts[4] + ":aws:ec2-instance"
		credential.InScopeOf = journal.APIIdentityScope{IssuerType: "AWS::EC2::Instance", CredentialsIssuedTo: spec.InstanceARN}
		credential.SessionContext = map[string][]string{"ec2:roledelivery": {spec.RoleDelivery}}
		credential.Expiration = instant.Add(spec.Duration).UTC()
		credential.RequestParentEventID = spec.RequestParentEventID
		return putSession(tx, &credential)
	})
	if err != nil {
		return Credential{}, err
	}
	return credential, nil
}
