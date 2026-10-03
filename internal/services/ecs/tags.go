package ecs

import (
	"context"
	"errors"
	"maps"
	"slices"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
	"strings"
	"unicode"
	"unicode/utf8"
)

func tagMap(tags api.Tags) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[value(t.Key)] = value(t.Value)
	}
	return m
}
func equalTags(a, b api.Tags) bool { return maps.Equal(tagMap(a), tagMap(b)) }
func validTagText(text string) bool {
	for _, r := range text {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) && !strings.ContainsRune("_ .:/=+-@", r) {
			return false
		}
	}
	return utf8.ValidString(text)
}
func admitTags(tags api.Tags, code string) (api.Tags, map[string][]string, *awswire.Error) {
	out := api.Tags{}
	conditions := map[string][]string{}
	seen := map[string]bool{}
	for _, tag := range tags {
		key, v := value(tag.Key), value(tag.Value)
		if tag.Key == nil {
			return nil, nil, failure(code, "Tag key can not be null.")
		}
		if tag.Value == nil {
			return nil, nil, failure(code, "Tag value can not be null.")
		}
		if utf8.RuneCountInString(key) < 1 || utf8.RuneCountInString(key) > 128 || utf8.RuneCountInString(v) > 256 || !validTagText(key) || !validTagText(v) || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, nil, failure(code, "Invalid tag key or value.")
		}
		if seen[key] {
			return nil, nil, failure(code, "Duplicate tag keys are not allowed.")
		}
		seen[key] = true
		out = append(out, api.CloneTag(tag))
		conditions["aws:RequestTag/"+key] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
	}
	if len(out) > 50 {
		return nil, nil, failure(code, "The maximum number of tags per resource is 50.")
	}
	return out, conditions, nil
}
func (s *Service) tagTarget(ctx context.Context, tx Transaction, arn string) (TagRecord, string, error) {
	if !strings.HasPrefix(arn, "arn:") {
		return TagRecord{}, "", failure("InvalidParameterException", "Invalid resource ARN.")
	}
	var scope Scope
	code := "InvalidParameterException"
	switch {
	case strings.Contains(arn, ":cluster/"):
		key, rejected := clusterKey(ctx, arn)
		if rejected != nil {
			return TagRecord{}, code, rejected
		}
		scope = key.Scope
		arn = key.ARN()
		record, err := tx.Cluster(key)
		if errors.Is(err, ErrNotFound) {
			return TagRecord{}, code, failure(code, "The specified cluster does not exist.")
		}
		if err != nil {
			return TagRecord{}, code, err
		}
		if value(record.Data.Status) != "ACTIVE" {
			return TagRecord{}, code, failure(code, "The specified cluster is inactive. Specify an active cluster and try again.")
		}
	case strings.Contains(arn, ":service/"):
		serviceScope, resource, rejected := resourceID(ctx, arn, "service")
		if rejected != nil {
			return TagRecord{}, code, rejected
		}
		cluster, _, qualified := strings.Cut(resource, "/")
		if !qualified || !resourceName.MatchString(cluster) {
			return TagRecord{}, code, failure(code, "Invalid resource ARN.")
		}
		key, rejected := serviceKey(ctx, ClusterKey{Scope: serviceScope, Name: cluster}, arn)
		if rejected != nil {
			return TagRecord{}, code, rejected
		}
		record, err := tx.Service(key)
		if errors.Is(err, ErrNotFound) {
			return TagRecord{}, code, failure(code, "The specified service does not exist.")
		}
		if err != nil {
			return TagRecord{}, code, err
		}
		if value(record.Data.Status) == "INACTIVE" {
			return TagRecord{}, code, failure(code, "The specified service is inactive. Specify an active service and try again.")
		}
		scope = key.Scope
		arn = key.ARN()
	case strings.Contains(arn, ":task/"):
		taskScope, resource, rejected := resourceID(ctx, arn, "task")
		if rejected != nil {
			return TagRecord{}, code, rejected
		}
		cluster, _, qualified := strings.Cut(resource, "/")
		if !qualified || !resourceName.MatchString(cluster) {
			return TagRecord{}, code, failure(code, "Invalid resource ARN.")
		}
		key, rejected := taskKey(ctx, ClusterKey{Scope: taskScope, Name: cluster}, arn)
		if rejected != nil {
			return TagRecord{}, code, rejected
		}
		task, err := tx.Task(key)
		if errors.Is(err, ErrNotFound) {
			return TagRecord{}, code, failure(code, "The specified task does not exist.")
		}
		if err != nil {
			return TagRecord{}, code, err
		}
		if value(task.Data.LastStatus) == "STOPPED" {
			return TagRecord{}, code, failure(code, "The specified task is stopped. Specify a running task and try again.")
		}
		scope = key.Scope
		arn = key.ARN()
	case strings.Contains(arn, ":task-definition/"):
		code = "ClientException"
		key, rejected := definitionKey(ctx, arn, true)
		if rejected != nil {
			return TagRecord{}, code, rejected
		}
		scope = key.Scope
		arn = key.ARN()
		if err := s.reapTaskDefinitions(tx, scope); err != nil {
			return TagRecord{}, code, err
		}
		if _, err := tx.TaskDefinition(key); err != nil {
			if errors.Is(err, ErrNotFound) {
				return TagRecord{}, code, failure(code, "Unable to describe task definition.")
			}
			return TagRecord{}, code, err
		}
	default:
		return TagRecord{}, code, unsupported("Tags for this ECS resource type require its real resource implementation.")
	}
	tags, err := tagsFor(tx, scope, arn)
	return TagRecord{TagKey{scope, arn}, tags}, code, err
}
func (s *Service) tagResource(ctx context.Context, tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	record, code, err := s.tagTarget(ctx, tx, value(in.ResourceArn))
	if err != nil {
		return nil, err
	}
	incoming, conditions, rejected := admitTags(in.Tags, code)
	if rejected != nil {
		return nil, rejected
	}
	if err := s.authorize(ctx, "TagResource", record.Key.ResourceARN, record.Tags, conditions); err != nil {
		return nil, err
	}
	for _, tag := range incoming {
		at := slices.IndexFunc(record.Tags, func(old api.Tag) bool { return value(old.Key) == value(tag.Key) })
		if at >= 0 {
			record.Tags[at] = tag
		} else {
			record.Tags = append(record.Tags, tag)
		}
	}
	count := 0
	for _, tag := range record.Tags {
		if !strings.HasPrefix(strings.ToLower(value(tag.Key)), "aws:") {
			count++
		}
	}
	if count > 50 {
		return nil, failure(code, "The maximum number of tags per resource is 50.")
	}
	if err := tx.PutTags(record); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}
func (s *Service) untagResource(ctx context.Context, tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	record, _, err := s.tagTarget(ctx, tx, value(in.ResourceArn))
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{}
	for _, key := range in.TagKeys {
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(key))
	}
	if err := s.authorize(ctx, "UntagResource", record.Key.ResourceARN, record.Tags, conditions); err != nil {
		return nil, err
	}
	record.Tags = slices.DeleteFunc(record.Tags, func(tag api.Tag) bool {
		if strings.HasPrefix(strings.ToLower(value(tag.Key)), "aws:") {
			return false
		}
		for _, key := range in.TagKeys {
			if string(key) == value(tag.Key) {
				return true
			}
		}
		return false
	})
	if err := tx.PutTags(record); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}
func (s *Service) listTagsForResource(ctx context.Context, tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	record, _, err := s.tagTarget(ctx, tx, value(in.ResourceArn))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "ListTagsForResource", record.Key.ResourceARN, record.Tags, nil); err != nil {
		return nil, err
	}
	return &api.ListTagsForResourceOutput{Tags: record.Tags}, nil
}
