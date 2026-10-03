package iam

import (
	"context"
	"fmt"
	"strings"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
)

// InstanceProfileSnapshot gives compute providers a consistent profile/role
// association without exposing IAM storage or mutable policy records. Empty role
// fields mean the profile exists but has no assigned role.
type InstanceProfileSnapshot struct {
	ARN, ID, Name, Path string
	RoleARN, RoleID     string
	Profile             iamapi.InstanceProfile
}

// InstanceProfileForUse resolves a name or exact ARN within the authenticated
// account and partition. The consuming service authorizes its own operation and
// iam:PassRole; reading this snapshot does not grant permission to use the role.
func (s *Service) InstanceProfileForUse(ctx context.Context, reference string) (InstanceProfileSnapshot, error) {
	m := awsctx.FromContext(ctx)
	name := reference
	if strings.HasPrefix(reference, "arn:") {
		prefix := "arn:" + m.Partition + ":iam::" + m.AccountID + ":instance-profile/"
		if !strings.HasPrefix(reference, prefix) {
			return InstanceProfileSnapshot{}, fmt.Errorf("instance profile must belong to the caller's account and partition")
		}
		name = reference[strings.LastIndexByte(reference, '/')+1:]
	}
	if !namePattern.MatchString(name) || len(name) > 128 {
		return InstanceProfileSnapshot{}, fmt.Errorf("invalid instance profile reference")
	}
	var result InstanceProfileSnapshot
	err := s.viewAt(ctx, func(tx ReadTx, now time.Time) error {
		ctx := context.WithValue(ctx, transactionKey{}, serviceTransaction{service: s, tx: tx, currentTime: now})
		scope := Scope{Partition: m.Partition, AccountID: m.AccountID}
		profile, err := tx.InstanceProfile(scope, name)
		if err != nil {
			return err
		}
		if strings.HasPrefix(reference, "arn:") && reference != profile.Arn {
			return ErrRecordNotFound
		}
		result = InstanceProfileSnapshot{ARN: profile.Arn, ID: profile.InstanceProfileId, Name: profile.InstanceProfileName, Path: profile.Path}
		a := &account{roles: make(map[string]*Role, 1)}
		if profile.RoleId != "" {
			roles, err := tx.Roles(scope)
			if err != nil {
				return err
			}
			for _, role := range roles {
				if role.RoleId == profile.RoleId {
					result.RoleARN, result.RoleID = role.Arn, role.RoleId
					a.roles[role.RoleName] = &role
					break
				}
			}
		}
		projected, rejected := s.wireInstanceProfile(ctx, a, m, &profile, true)
		if rejected != nil {
			return rejected
		}
		result.Profile = *projected
		return nil
	})
	return result, err
}
