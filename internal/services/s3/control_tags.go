package s3

import (
	"context"
	"slices"
	"strings"

	api "stackd/internal/awsapi/s3control"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func controlTags(input api.TagList) ([]Tag, error) {
	seen := make(map[string]bool, len(input))
	tags := make([]Tag, 0, len(input))
	for _, item := range input {
		key, val := value(item.Key), value(item.Value)
		if seen[key] {
			return nil, failure("InvalidTag", "There are duplicate tag keys in your request. Remove the duplicate tag keys and try again.", 400)
		}
		if len(key) >= 4 && strings.EqualFold(key[:4], "aws:") {
			return nil, failure("InvalidTag", "User-defined tag keys can't start with \"aws:\". This prefix is reserved for system tags. Remove \"aws:\" from your tag keys and try again.", 400)
		}
		seen[key] = true
		tags = append(tags, Tag{Key: key, Value: val})
	}
	return tags, nil
}

func (p *Control) taggedAccessPoint(reader Reader, account, arn string) (AccessPointRecord, error) {
	key, wire := parseAccessPointARN(arn)
	if wire != nil {
		return AccessPointRecord{}, wire
	}
	m := awsctx.FromContext(reader.Context())
	if key.Partition != m.Partition || key.Region != m.Region || key.AccountID != account {
		return AccessPointRecord{}, failure("InvalidRequest", "The resource ARN does not match the request account and region.", 400)
	}
	return p.controlAccessPoint(reader, account, key.Name, false)
}

func (p *Control) tagResource(ctx context.Context, in *api.TagResourceInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "TagResource")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		target, err := p.taggedResource(tx, c, value(in.AccountId), value(in.ResourceArn))
		if err != nil {
			return err
		}
		if len(in.Tags) == 0 {
			if target.bucket != nil {
				return failure("InvalidTag", "At least one tag is required.", 400)
			}
			return failure("InvalidRequest", "At least one 1 tag must be supplied", 400)
		}
		requested, err := controlTags(in.Tags)
		if err != nil {
			return err
		}
		if err := p.authorizeTags(tx, c, target, "TagResource", requested, nil); err != nil {
			return err
		}
		tags, err := target.tags(tx, c)
		if err != nil {
			return err
		}
		for _, tag := range requested {
			index := slices.IndexFunc(tags, func(existing Tag) bool { return existing.Key == tag.Key })
			if index < 0 {
				tags = append(tags, tag)
			} else {
				tags[index] = tag
			}
		}
		if len(tags) > 50 {
			return failure("TooManyTags", "The maximum number of tags allowed on a resource is 50.", 400)
		}
		if err := target.replaceTags(tx, tags); err != nil {
			return err
		}
		if target.bucket != nil {
			response.statusCode = 204
		}
		return response.prepare(c, &api.TagResourceOutput{})
	})
	return response, wire
}

func (p *Control) untagResource(ctx context.Context, in *api.UntagResourceInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "UntagResource")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		target, err := p.taggedResource(tx, c, value(in.AccountId), value(in.ResourceArn))
		if err != nil {
			return err
		}
		if len(in.TagKeys) == 0 {
			if target.bucket != nil {
				return failure("InvalidTag", "At least one tag is required.", 400)
			}
			return failure("InvalidRequest", "Invalid Request Parameter Sepcified", 400)
		}
		keys := make([]string, 0, len(in.TagKeys))
		removed := make(map[string]struct{}, len(in.TagKeys))
		for _, key := range in.TagKeys {
			if _, duplicate := removed[string(key)]; duplicate {
				if target.bucket != nil {
					return failure("InternalError", "We encountered an internal error. Please try again.", 500)
				}
				return failure("InvalidTag", "There are duplicate tag keys in your request. Remove the duplicate tag keys and try again.", 400)
			}
			if len(key) >= 4 && strings.EqualFold(string(key[:4]), "aws:") {
				return failure("InvalidTag", "The tag key you have provided is invalid.", 400)
			}
			keys = append(keys, string(key))
			removed[string(key)] = struct{}{}
		}
		if err := p.authorizeTags(tx, c, target, "UntagResource", nil, keys); err != nil {
			return err
		}
		tags, err := target.tags(tx, c)
		if err != nil {
			return err
		}
		tags = slices.DeleteFunc(tags, func(tag Tag) bool {
			_, remove := removed[tag.Key]
			return remove
		})
		if err := target.replaceTags(tx, tags); err != nil {
			return err
		}
		return response.prepare(c, &api.UntagResourceOutput{})
	})
	return response, wire
}

func (p *Control) listTagsForResource(ctx context.Context, in *api.ListTagsForResourceInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "ListTagsForResource")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		target, err := p.taggedResource(tx, c, value(in.AccountId), value(in.ResourceArn))
		if err != nil {
			return err
		}
		if err := p.authorizeTags(tx, c, target, "ListTagsForResource", nil, nil); err != nil {
			return err
		}
		tags, err := target.tags(tx, c)
		if err != nil {
			return err
		}
		out := &api.ListTagsForResourceOutput{Tags: make(api.TagList, 0, len(tags))}
		for _, tag := range tags {
			out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKeyString(tag.Key)), Value: new(api.TagValueString(tag.Value))})
		}
		return response.prepare(c, out)
	})
	return response, wire
}
