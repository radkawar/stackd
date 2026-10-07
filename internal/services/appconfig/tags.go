package appconfig

import (
	"context"
	"maps"
	"strconv"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/appconfig"
)

func (s *Service) authorizeTagsOnCreate(ctx context.Context, resource string, tags map[string]string) error {
	if len(tags) == 0 {
		return nil
	}
	return s.authorize(ctx, "TagResource", resource, nil)
}

func registerTags(s *Service) {
	register(s, "ListTagsForResource", func(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
		sc := scopeFor(tx.Context())
		resource := value(in.ResourceArn)
		if err := resourceExists(tx, sc, resource); err != nil {
			return nil, err
		}
		tags, err := tx.Tags(sc, resource)
		if err != nil {
			return nil, err
		}
		if err = s.authorizeClaimed(tx, "ListTagsForResource", resource, tags); err != nil {
			return nil, err
		}
		out := &api.ResourceTags{Tags: api.TagMap{}}
		for k, v := range tags {
			out.Tags[api.TagKey(k)] = api.TagValue(v)
		}
		return out, nil
	})
	register(s, "TagResource", func(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
		sc := scopeFor(tx.Context())
		resource := value(in.ResourceArn)
		if err := resourceExists(tx, sc, resource); err != nil {
			return nil, err
		}
		tags, err := tx.Tags(sc, resource)
		if err != nil {
			return nil, err
		}
		if err = s.authorizeClaimed(tx, "TagResource", resource, tags); err != nil {
			return nil, err
		}
		tags = maps.Clone(tags)
		if tags == nil {
			tags = map[string]string{}
		}
		for k, v := range in.Tags {
			if strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
				return nil, failure("BadRequestException", "Tag keys cannot begin with aws:.")
			}
			tags[string(k)] = string(v)
		}
		if len(tags) > 50 {
			return nil, failure("BadRequestException", "A resource may have at most 50 tags.")
		}
		if err := tx.PutTags(sc, resource, tags); err != nil {
			return nil, err
		}
		return &api.Unit{}, nil
	})
	register(s, "UntagResource", func(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
		sc := scopeFor(tx.Context())
		resource := value(in.ResourceArn)
		if err := resourceExists(tx, sc, resource); err != nil {
			return nil, err
		}
		tags, err := tx.Tags(sc, resource)
		if err != nil {
			return nil, err
		}
		if err = s.authorizeClaimed(tx, "UntagResource", resource, tags); err != nil {
			return nil, err
		}
		tags = maps.Clone(tags)
		for _, k := range in.TagKeys {
			delete(tags, string(k))
		}
		if err := tx.PutTags(sc, resource, tags); err != nil {
			return nil, err
		}
		return &api.Unit{}, nil
	})
}
func resourceExists(r Reader, sc Scope, resource string) error {
	relative, ok := strings.CutPrefix(resource, arn(sc, ""))
	if !ok {
		return failure("ResourceNotFoundException", "Resource not found.")
	}
	parts := strings.Split(relative, "/")
	missing := failure("ResourceNotFoundException", "Resource not found: "+resource)
	if len(parts) < 2 {
		return missing
	}
	switch parts[0] {
	case "application":
		a, err := findApplication(r, sc, parts[1])
		if err != nil {
			return err
		}
		if a.ID != parts[1] {
			return missing
		}
		if len(parts) == 2 {
			return nil
		}
		if len(parts) == 4 {
			switch parts[2] {
			case "environment":
				v, e := findEnvironment(r, sc, a.ID, parts[3])
				if e == nil && v.ID != parts[3] {
					return missing
				}
				return e
			case "configurationprofile":
				v, e := findProfile(r, sc, a.ID, parts[3])
				if e == nil && v.ID != parts[3] {
					return missing
				}
				return e
			}
		}
		if len(parts) == 6 && parts[2] == "environment" && parts[4] == "deployment" {
			n, err := strconv.ParseInt(parts[5], 10, 32)
			if err != nil {
				return missing
			}
			rows, err := r.Deployments(sc, a.ID, parts[3])
			if err != nil {
				return err
			}
			for _, v := range rows {
				if v.Number == int32(n) {
					return nil
				}
			}
		}
		if len(parts) == 4 && parts[2] == "experimentdefinition" {
			rows, err := r.ExperimentDefinitions(sc, a.ID)
			if err != nil {
				return err
			}
			for _, v := range rows {
				if v.ID == parts[3] {
					return nil
				}
			}
		}
		if len(parts) == 6 && parts[2] == "experimentdefinition" && parts[4] == "experimentrun" {
			n, err := strconv.ParseInt(parts[5], 10, 32)
			if err != nil {
				return missing
			}
			rows, err := r.ExperimentRuns(sc, a.ID, parts[3])
			if err != nil {
				return err
			}
			for _, v := range rows {
				if v.Number == int32(n) {
					return nil
				}
			}
		}
	case "deploymentstrategy":
		if len(parts) != 2 {
			return missing
		}
		v, e := findStrategy(r, sc, parts[1])
		if e != nil {
			return e
		}
		if strings.HasPrefix(v.ID, "AppConfig.") {
			return failure("BadRequestException", "AWS managed deployment strategies cannot be tagged.")
		}
		return nil
	case "extension":
		if len(parts) != 3 {
			return missing
		}
		rows, err := r.Extensions(sc)
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.ARN == resource {
				return nil
			}
		}
	case "extensionassociation":
		if len(parts) != 2 {
			return missing
		}
		rows, err := r.Associations(sc)
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.ID == parts[1] {
				return nil
			}
		}
	}
	return missing
}
func requestTagContext(ctx context.Context) map[string][]string {
	d, ok := awsapi.FromContext(ctx)
	if !ok {
		return map[string][]string{}
	}
	var tags api.TagMap
	var keys api.TagKeyList
	switch in := d.Input.(type) {
	case *api.CreateApplicationInput:
		tags = in.Tags
	case *api.CreateConfigurationProfileInput:
		tags = in.Tags
	case *api.CreateEnvironmentInput:
		tags = in.Tags
	case *api.CreateDeploymentStrategyInput:
		tags = in.Tags
	case *api.CreateExtensionInput:
		tags = in.Tags
	case *api.CreateExtensionAssociationInput:
		tags = in.Tags
	case *api.CreateExperimentDefinitionInput:
		tags = in.Tags
	case *api.StartExperimentRunInput:
		tags = in.Tags
	case *api.StartDeploymentInput:
		tags = in.Tags
	case *api.TagResourceInput:
		tags = in.Tags
	case *api.UntagResourceInput:
		keys = in.TagKeys
	}
	values := map[string][]string{}
	for k, v := range tags {
		values["aws:RequestTag/"+string(k)] = []string{string(v)}
		values["aws:TagKeys"] = append(values["aws:TagKeys"], string(k))
	}
	for _, k := range keys {
		values["aws:TagKeys"] = append(values["aws:TagKeys"], string(k))
	}
	return values
}
