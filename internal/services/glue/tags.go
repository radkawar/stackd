package glue

import (
	"context"
	"encoding/json"
	"maps"
	api "stackd/internal/awsapi/glue"
	"strings"
	"unicode/utf8"
)

func registerTags(s *Service) {
	registerControl(s, "GetTags", s.getTags)
	registerControl(s, "TagResource", s.tagResource)
	registerControl(s, "UntagResource", s.untagResource)
}
func workflowInputTags(input api.TagsMap) (map[string]string, error) {
	tags := make(map[string]string, len(input))
	for k, v := range input {
		key, val := string(k), string(v)
		if key == "" || utf8.RuneCountInString(key) > 128 || utf8.RuneCountInString(val) > 256 || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, failure("InvalidInputException", "Invalid tag key or value.")
		}
		tags[key] = val
	}
	if len(tags) > 50 {
		return nil, failure("ResourceNumberLimitExceededException", "A resource supports at most 50 tags.")
	}
	return tags, nil
}
func jsonTriggerTags(tags api.TagsMap) (string, error) {
	b, err := json.Marshal(tags)
	return string(b), err
}
func glueTagResource(scope Scope, arn string) (string, string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "glue" || parts[3] != scope.Region || parts[4] != scope.AccountID {
		return "", "", failure("InvalidInputException", "Resource ARN must identify a Glue resource in the current account and Region.")
	}
	kind, name, ok := strings.Cut(parts[5], "/")
	if !ok || name == "" {
		return "", "", failure("InvalidInputException", "Invalid Glue resource ARN.")
	}
	switch kind {
	case "job", "crawler", "trigger", "workflow", "connection", "registry", "schema":
	case "catalog":
		if catalogTagKey(scope, name).ARN() != arn {
			return "", "", failure("InvalidInputException", "Invalid named catalog ARN.")
		}
	case "database":
		if databaseTagKey(scope, name).ARN() != arn {
			return "", "", failure("InvalidInputException", "Invalid database ARN.")
		}
	default:
		return "", "", failure("InvalidInputException", "This resource type does not support tagging.")
	}
	return kind, name, nil
}
func databaseTagKey(scope Scope, name string) DatabaseKey {
	parts := strings.Split(name, "/")
	catalog := scope.AccountID
	if len(parts) > 1 {
		catalog += ":" + strings.Join(parts[:len(parts)-1], ":")
	}
	return DatabaseKey{CatalogKey{scope, catalog}, parts[len(parts)-1]}
}
func catalogTagKey(scope Scope, name string) CatalogKey {
	return CatalogKey{Scope: scope, CatalogID: scope.AccountID + ":" + strings.ReplaceAll(name, "/", ":")}
}
func (s *Service) resourceTags(ctx context.Context, tx Reader, scope Scope, arn, kind, name string) (map[string]string, error) {
	key := ResourceKey{scope, name}
	switch kind {
	case "workflow":
		v, err := tx.Workflow(key)
		return v.Tags, err
	case "trigger":
		v, err := tx.Trigger(key)
		return v.Tags, err
	case "job":
		return jobResourceTags(tx, scope, arn)
	case "crawler":
		return crawlerResourceTags(tx, scope, arn)
	case "connection":
		tags, err := connectionResourceTags(tx, scope, arn)
		if err != nil {
			return nil, err
		}
		if err = s.authorize(ctx, tx, "GetConnection", scope, arn, tags); err != nil {
			return nil, err
		}
		return tags, nil
	case "registry", "schema":
		return registryResourceTags(tx, scope, arn)
	case "catalog":
		v, err := tx.Catalog(catalogTagKey(scope, name))
		return v.Tags, err
	case "database":
		key := databaseTagKey(scope, name)
		v, err := tx.Database(key)
		if err != nil {
			return nil, err
		}
		if err = s.authorizeDatabase(ctx, tx, "GetDatabase", key); err != nil {
			return nil, err
		}
		return v.Tags, nil
	}
	return nil, ErrNotFound
}
func setResourceTags(tx Transaction, scope Scope, arn, kind, name string, tags map[string]string) error {
	key := ResourceKey{scope, name}
	switch kind {
	case "workflow":
		v, err := tx.Workflow(key)
		if err != nil {
			return err
		}
		v.Tags = tags
		return tx.PutWorkflow(v)
	case "trigger":
		v, err := tx.Trigger(key)
		if err != nil {
			return err
		}
		v.Tags = tags
		return tx.PutTrigger(v)
	case "job":
		return tagJobResource(tx, scope, arn, tags)
	case "crawler":
		return tagCrawlerResource(tx, scope, arn, tags)
	case "connection":
		return tagConnectionResource(tx, scope, arn, tags)
	case "registry", "schema":
		return tagRegistryResource(tx, scope, arn, tags)
	case "catalog":
		v, err := tx.Catalog(catalogTagKey(scope, name))
		if err != nil {
			return err
		}
		v.Tags = tags
		return tx.PutCatalog(v)
	case "database":
		v, err := tx.Database(databaseTagKey(scope, name))
		if err != nil {
			return err
		}
		v.Tags = tags
		return tx.PutDatabase(v)
	}
	return ErrNotFound
}
func (s *Service) getTags(ctx context.Context, tx Transaction, in *api.GetTagsInput) (*api.GetTagsOutput, error) {
	scope := scopeFor(ctx)
	arn := value(in.ResourceArn)
	identity := scope
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[3] != "" {
		identity.Region = parts[3]
	}
	kind, name, err := glueTagResource(identity, arn)
	if err != nil {
		return nil, err
	}
	out := &api.GetTagsOutput{Tags: api.TagsMap{}}
	// AWS GetTags returns an empty map for a well-formed ARN outside the
	// receiving regional endpoint. It must not alias a local same-name resource.
	// Mutation commands still require an exact local ARN.
	if identity.Region != scope.Region {
		if err = s.authorize(ctx, tx, "GetTags", scope, arn, nil); err != nil {
			return nil, err
		}
		return out, nil
	}
	tags, err := s.resourceTags(ctx, tx, scope, arn, kind, name)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, tx, "GetTags", scope, arn, tags); err != nil {
		return nil, err
	}
	for k, v := range tags {
		out.Tags[api.TagKey(k)] = api.TagValue(v)
	}
	return out, nil
}
func (s *Service) tagResource(ctx context.Context, tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	scope := scopeFor(ctx)
	arn := value(in.ResourceArn)
	kind, name, err := glueTagResource(scope, arn)
	if err != nil {
		return nil, err
	}
	added, err := workflowInputTags(in.TagsToAdd)
	if err != nil {
		return nil, err
	}
	tags, err := s.resourceTags(ctx, tx, scope, arn, kind, name)
	if err != nil {
		return nil, err
	}
	if err = s.authorizeWithConditions(ctx, tx, "TagResource", scope, arn, tags, requestTagConditions(added)); err != nil {
		return nil, err
	}
	merged := maps.Clone(tags)
	if merged == nil {
		merged = map[string]string{}
	}
	maps.Copy(merged, added)
	if len(merged) > 50 {
		return nil, failure("ResourceNumberLimitExceededException", "A resource supports at most 50 tags.")
	}
	if err = setResourceTags(tx, scope, arn, kind, name, merged); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}
func (s *Service) untagResource(ctx context.Context, tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	scope := scopeFor(ctx)
	arn := value(in.ResourceArn)
	kind, name, err := glueTagResource(scope, arn)
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{}
	for _, k := range in.TagsToRemove {
		key := string(k)
		if key == "" || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, failure("InvalidInputException", "Invalid tag key.")
		}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
	}
	tags, err := s.resourceTags(ctx, tx, scope, arn, kind, name)
	if err != nil {
		return nil, err
	}
	if err = s.authorizeWithConditions(ctx, tx, "UntagResource", scope, arn, tags, conditions); err != nil {
		return nil, err
	}
	for _, key := range in.TagsToRemove {
		delete(tags, string(key))
	}
	if err = setResourceTags(tx, scope, arn, kind, name, tags); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}
