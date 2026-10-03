package dynamodb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
)

func tagConditions(tags api.TagList) (map[string][]string, error) {
	conditions := map[string][]string{}
	seen := map[string]bool{}
	for _, tag := range tags {
		key := value(tag.Key)
		if err := validateTagKey(key); err != nil {
			return nil, err
		}
		if tag.Value == nil || len(value(tag.Value)) > 256 {
			return nil, failure("ValidationException", "Tag value must be specified and must not exceed 256 bytes")
		}
		if seen[key] {
			return nil, failure("ValidationException", "Duplicate Tag Keys provided as input: Duplicate Tag Key found "+key)
		}
		seen[key] = true
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
		conditions["aws:RequestTag/"+key] = []string{value(tag.Value)}
	}
	if len(tags) > 50 {
		return nil, failure("LimitExceededException", "Subscriber limit exceeded: Only 50 tags are allowed per resource")
	}
	return conditions, nil
}

func (s *Service) tagTable(ctx context.Context, tx Transaction, resource, action string, conditions map[string][]string) (TableRecord, error) {
	if !strings.HasPrefix(resource, "arn:") {
		return TableRecord{}, failure("ValidationException", "ResourceArn must be a valid DynamoDB table ARN")
	}
	return s.controlTable(ctx, tx, resource, action, conditions)
}

func readTags(r Reader, key TableKey) (TagRecord, error) {
	tags, err := r.Tags(key)
	if errors.Is(err, ErrNotFound) {
		return TagRecord{Key: key, Tags: api.TagList{}}, nil
	}
	return tags, err
}

func (s *Service) tagResource(ctx context.Context, tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	conditions, err := tagConditions(in.Tags)
	if err != nil {
		return nil, err
	}
	if len(in.Tags) == 0 {
		return nil, failure("ValidationException", "Tags must not be empty")
	}
	table, err := s.tagTable(ctx, tx, value(in.ResourceArn), "TagResource", conditions)
	if err != nil {
		return nil, err
	}
	if value(table.Data.TableStatus) == "DELETING" {
		return nil, failure("ResourceInUseException", "Table is being deleted: "+table.Key.Name)
	}
	tags, err := readTags(tx, table.Key)
	if err != nil {
		return nil, err
	}
	for _, tag := range in.Tags {
		index := slices.IndexFunc(tags.Tags, func(current api.Tag) bool { return value(current.Key) == value(tag.Key) })
		if index < 0 {
			tags.Tags = append(tags.Tags, api.CloneTag(tag))
		} else {
			tags.Tags[index] = api.CloneTag(tag)
		}
	}
	if len(tags.Tags) > 50 {
		return nil, failure("LimitExceededException", "Subscriber limit exceeded: Only 50 tags are allowed per resource")
	}
	if err = tx.PutTags(tags); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untagResource(ctx context.Context, tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	if len(in.TagKeys) == 0 {
		return nil, failure("ValidationException", "TagKeys must not be empty")
	}
	conditions := map[string][]string{"aws:TagKeys": {}}
	remove := map[string]bool{}
	for _, key := range in.TagKeys {
		if err := validateTagKey(string(key)); err != nil {
			return nil, err
		}
		remove[string(key)] = true
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(key))
	}
	table, err := s.tagTable(ctx, tx, value(in.ResourceArn), "UntagResource", conditions)
	if err != nil {
		return nil, err
	}
	if value(table.Data.TableStatus) == "DELETING" {
		return nil, failure("ResourceInUseException", "Table is being deleted: "+table.Key.Name)
	}
	tags, err := readTags(tx, table.Key)
	if err != nil {
		return nil, err
	}
	tags.Tags = slices.DeleteFunc(tags.Tags, func(tag api.Tag) bool { return remove[value(tag.Key)] })
	if err = tx.PutTags(tags); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}

type tagCursor struct{ Resource, After string }

func (s *Service) listTagsOfResource(ctx context.Context, tx Transaction, in *api.ListTagsOfResourceInput) (*api.ListTagsOfResourceOutput, error) {
	table, err := s.tagTable(ctx, tx, value(in.ResourceArn), "ListTagsOfResource", nil)
	if err != nil {
		return nil, err
	}
	collection := table.Key.ARN() + "/" + value(table.Data.TableId)
	after := ""
	if in.NextToken != nil {
		data, decodeErr := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		var cursor tagCursor
		if decodeErr != nil || json.Unmarshal(data, &cursor) != nil || cursor.Resource != collection || cursor.After == "" {
			return nil, failure("ValidationException", "Invalid NextToken")
		}
		after = cursor.After
	}
	tags, err := readTags(tx, table.Key)
	if err != nil {
		return nil, err
	}
	ordered := api.CloneTagList(tags.Tags)
	slices.SortFunc(ordered, func(a, b api.Tag) int { return strings.Compare(value(a.Key), value(b.Key)) })
	out := &api.ListTagsOfResourceOutput{Tags: api.TagList{}}
	for _, tag := range ordered {
		if value(tag.Key) <= after {
			continue
		}
		if len(out.Tags) == 100 {
			data, _ := json.Marshal(tagCursor{Resource: collection, After: value(out.Tags[len(out.Tags)-1].Key)})
			out.NextToken = new(api.NextTokenString(base64.RawURLEncoding.EncodeToString(data)))
			break
		}
		out.Tags = append(out.Tags, tag)
	}
	return out, nil
}
