package account

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func (s *Service) authorize(ctx context.Context, action, target string, conditions map[string][]string, instant time.Time) (string, error) {
	m := awsctx.FromContext(ctx)
	permission := authorization.Request{Action: "account:" + action, ResourceARN: "arn:" + m.Partition + ":account::" + m.AccountID + ":account"}
	if target != "" {
		if s.organizations == nil {
			return "", failure("AccessDeniedException", "Organizations account access is unavailable.", 403)
		}
		var err error
		permission, err = s.organizations.AccountManagementPermission(ctx, target, permission.Action)
		if err != nil {
			return "", err
		}
	} else {
		target = m.AccountID
	}
	permission.EvaluationTime = &instant
	if len(conditions) != 0 {
		if permission.Context == nil {
			permission.Context = make(map[string][]string)
		}
		maps.Copy(permission.Context, conditions)
	}
	if err := s.authorizer.Authorize(ctx, permission); err != nil {
		return "", failure("AccessDeniedException", err.Message, 403)
	}
	for _, region := range conditions["account:TargetRegion"] {
		if strings.ToLower(region) != region {
			return "", failure("AccessDeniedException", fmt.Sprintf("User: %s is not authorized to perform: %s (You specified an invalid target region.)", m.PrincipalARN, permission.Action), 403)
		}
	}
	for _, kind := range conditions["account:AlternateContactTypes"] {
		if !slices.Contains(enumValues("AlternateContactType"), kind) {
			return "", failure("AccessDeniedException", fmt.Sprintf("User: %s is not authorized to perform: %s (You specified an invalid Alternate Contact type.)", m.PrincipalARN, permission.Action), 403)
		}
	}
	return target, nil
}
