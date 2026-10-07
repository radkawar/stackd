package configservice

import (
	"context"
	"fmt"
	"strings"
)

// CloudFormationOwnership is private native incarnation authority, never wire input.
type CloudFormationOwnership struct{ Owner, Token string }
type cloudFormationOwnershipKey struct{}

func WithCloudFormationOwnership(ctx context.Context, v CloudFormationOwnership) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, v)
}

type recorderStartKey struct{}

func WithRecorderStartOnCreate(ctx context.Context, start bool) context.Context {
	return context.WithValue(ctx, recorderStartKey{}, start)
}
func creationOwnership(ctx context.Context) CloudFormationOwnership {
	v, _ := ctx.Value(cloudFormationOwnershipKey{}).(CloudFormationOwnership)
	return v
}
func channelOwnershipARN(scope Scope, name string) string {
	return fmt.Sprintf("arn:%s:config:%s:%s:delivery-channel/%s", scope.Partition, scope.Region, scope.AccountID, name)
}
func checkCloudFormationClaim(ctx context.Context, actual CloudFormationOwnership) error {
	expected, ok := ctx.Value(cloudFormationOwnershipKey{}).(CloudFormationOwnership)
	if !ok {
		return nil
	}
	if expected.Owner == "" || expected.Token == "" || actual != expected {
		return failure("ResourceAlreadyExistsException", "The control belongs to another resource incarnation.")
	}
	return nil
}

// The two ARN-addressed controls do not have a wire ownership field.
func checkCloudFormationOwnership(r Reader, arn string, exists bool) error {
	if _, ok := r.Context().Value(cloudFormationOwnershipKey{}).(CloudFormationOwnership); !ok || !exists {
		return nil
	}
	scope := scopeFor(r.Context())
	if strings.Contains(arn, ":delivery-channel/") {
		row, found, err := r.Channel(scope)
		if err != nil {
			return err
		}
		if found && channelOwnershipARN(scope, row.Name) == arn {
			return checkCloudFormationClaim(r.Context(), row.CFNOwnership)
		}
	} else {
		rows, err := r.AggregationAuthorizations(scope)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.ARN == arn {
				return checkCloudFormationClaim(r.Context(), row.CFNOwnership)
			}
		}
	}
	return checkCloudFormationClaim(r.Context(), CloudFormationOwnership{})
}

// CloudFormationRecorderStartedOnCreate observes immutable admitted creation
// configuration, not mutable recording status or customer tags. Unknown historical
// and ordinary native settings stay absent. Current native read IAM and an optional
// exact private claim are checked before returning metadata.
func (s *Service) CloudFormationRecorderStartedOnCreate(ctx context.Context, name string) (started, known bool, err error) {
	err = s.repository.View(ctx, func(reader Reader) error {
		row, found, err := reader.Recorder(scopeFor(reader.Context()))
		if err != nil {
			return err
		}
		resource := "*"
		if found && row.Name == name {
			resource = row.ARN
		}
		if err := s.authorizeResource(reader.Context(), "DescribeConfigurationRecorders", resource); err != nil {
			return err
		}
		if !found || row.Name != name {
			return failure("NoSuchConfigurationRecorderException", "The specified configuration recorder does not exist.")
		}
		if err := checkCloudFormationClaim(reader.Context(), row.CFNOwnership); err != nil {
			return err
		}
		started, known = row.StartedOnCreate, row.StartedOnCreateKnown
		return nil
	})
	return started, known, err
}
