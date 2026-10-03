package firehose

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/firehose"
)

func (s *Service) authorize(ctx context.Context, r Reader, key StreamKey, action string, conditions map[string][]string) error {
	if conditions == nil {
		conditions = make(map[string][]string)
	}
	stream, err := r.Stream(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	for key, val := range stream.Tags {
		conditions["aws:ResourceTag/"+key] = []string{val}
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{
		Action: "firehose:" + action, ResourceARN: key.ARN(), Context: conditions,
		ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now,
	}); rejected != nil {
		return rejected
	}
	return nil
}

func (s *Service) loadStream(ctx context.Context, r Reader, name, action string) (StreamRecord, error) {
	key := StreamKey{Scope: scopeFor(ctx), Name: name}
	if err := s.authorize(ctx, r, key, action, nil); err != nil {
		return StreamRecord{}, err
	}
	return findStream(r, key)
}

func findStream(r Reader, key StreamKey) (StreamRecord, error) {
	stream, err := r.Stream(key)
	if errors.Is(err, ErrNotFound) {
		return StreamRecord{}, failure("ResourceNotFoundException", fmt.Sprintf("Firehose under account %s not found.", key.AccountID))
	}
	return stream, err
}

func (s *Service) passRole(ctx context.Context, key StreamKey, roles ...string) error {
	now := s.clock.Now()
	for i, role := range roles {
		if slices.Contains(roles[:i], role) {
			continue
		}
		if rejected := s.authorizer.Authorize(ctx, authorization.Request{
			Action: "iam:PassRole", ResourceARN: role, EvaluationTime: &now,
			Context: map[string][]string{"iam:PassedToService": {"firehose.amazonaws.com"}, "iam:AssociatedResourceArn": {key.ARN()}},
		}); rejected != nil {
			return rejected
		}
	}
	return nil
}

func (s *Service) validateDestinations(ctx context.Context, key StreamKey, destination api.ExtendedS3DestinationDescription) error {
	if s.destination == nil {
		return unsupported("No S3 destination adapter is configured.")
	}
	if rejected := s.destination.Validate(ctx, key, destination); rejected != nil {
		return rejected
	}
	if destination.S3BackupDescription != nil {
		if rejected := s.destination.Validate(ctx, key, extendedBackup(*destination.S3BackupDescription)); rejected != nil {
			return rejected
		}
	}
	return nil
}
