package iam

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"stackd/internal/awsctx"
)

// RoleSnapshot contains the trust and session-issuance properties consumed by
// STS and service execution-role assumptions. Maps never expose live IAM state.
type RoleSnapshot struct {
	// EvaluationTime is populated by the atomic federation authority callback.
	EvaluationTime     time.Time
	ARN                string
	ID                 string
	Name               string
	TrustPolicy        string
	TrustPrincipalIDs  map[string]string
	MaxSessionDuration time.Duration
	Tags               map[string]string
	ServiceLinkedRole  bool
}

// RoleForAssumption resolves a role in the request partition, including roles
// in another account. The consumer must evaluate the trust relationship and
// any required caller permissions before issuing credentials for this snapshot.
func (s *Service) RoleForAssumption(ctx context.Context, roleARN string) (RoleSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return RoleSnapshot{}, err
	}
	m := awsctx.FromContext(ctx)
	parts := strings.SplitN(roleARN, ":", 6)
	if len(parts) != 6 || parts[1] != m.Partition || parts[2] != "iam" || parts[3] != "" || !strings.HasPrefix(parts[5], "role/") {
		return RoleSnapshot{}, fmt.Errorf("invalid role ARN")
	}
	var result RoleSnapshot
	err := s.view(ctx, func(tx ReadTx) error {
		roles, err := tx.Roles(Scope{Partition: m.Partition, AccountID: parts[4]})
		if err != nil {
			return err
		}
		for _, r := range roles {
			if r.Arn != roleARN {
				continue
			}
			tags := make(map[string]string, len(r.Tags))
			for _, tag := range r.Tags {
				tags[tag.Key] = tag.Value
			}
			result = RoleSnapshot{ARN: r.Arn, ID: r.RoleId, Name: r.RoleName, TrustPolicy: r.AssumeRolePolicyDocument, TrustPrincipalIDs: maps.Clone(r.TrustPrincipalIDs), MaxSessionDuration: time.Duration(r.MaxSessionDuration) * time.Second, Tags: tags, ServiceLinkedRole: r.ServiceLinkedService != ""}
			return nil
		}
		return fmt.Errorf("role does not exist")
	})
	return result, err
}

// ResolveManagedPolicyDocuments snapshots the default versions of session
// managed policies from the request account and partition.
func (s *Service) ResolveManagedPolicyDocuments(ctx context.Context, arns []string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := awsctx.FromContext(ctx)
	result := make([]string, 0, len(arns))
	err := s.view(ctx, func(tx ReadTx) error {
		for _, arn := range arns {
			p, ok := lookupAWSManagedPolicy(m.Partition, arn)
			if !ok {
				var err error
				p, err = tx.ManagedPolicy(Scope{Partition: m.Partition, AccountID: m.AccountID}, arn)
				if err != nil {
					return err
				}
			}
			v := p.Versions[p.DefaultVersionId]
			if v == nil {
				return fmt.Errorf("session managed policy default version does not exist")
			}
			result = append(result, v.Document)
		}
		return nil
	})
	return result, err
}
