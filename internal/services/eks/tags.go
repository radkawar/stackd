package eks

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/eks"
)

// visitResourceTags keeps the resource owner's typed row authoritative. The
// callback returns whether its detached tags changed; reads never rewrite state.
func (s *Service) visitResourceTags(ctx context.Context, tx Transaction, arn string, visit func(map[string]string) (map[string]string, bool, error)) (err error) {
	defer func() {
		if errors.Is(err, ErrNotFound) {
			err = failure("NotFoundException", "The requested EKS resource does not exist.", 404)
		}
	}()
	sc := scopeFor(ctx)
	prefix := "arn:" + sc.Partition + ":eks:" + sc.Region + ":" + sc.AccountID + ":"
	if !strings.HasPrefix(arn, prefix) {
		return ErrNotFound
	}
	parts := strings.Split(strings.TrimPrefix(arn, prefix), "/")
	if len(parts) < 2 || !clusterName.MatchString(parts[1]) {
		return ErrNotFound
	}
	key := Key{sc, parts[1]}
	switch parts[0] {
	case "cluster":
		if len(parts) != 2 {
			return ErrNotFound
		}
		row, err := tx.Cluster(key)
		if err != nil {
			return err
		}
		tags, changed, err := visit(row.Tags)
		if err != nil || !changed {
			return err
		}
		row.Tags = tags
		return tx.PutCluster(row)
	case "access-entry":
		rows, err := tx.AccessEntries(key)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if accessARN(row) == arn {
				tags, changed, err := visit(row.Tags)
				if err != nil || !changed {
					return err
				}
				row.Tags = tags
				return tx.PutAccessEntry(row)
			}
		}
	case "nodegroup":
		if len(parts) != 4 {
			return ErrNotFound
		}
		row, err := tx.Nodegroup(NodegroupKey{Cluster: key, Name: parts[2]})
		if err != nil {
			return err
		}
		if row.Key.ARN(row.ID) != arn {
			return ErrNotFound
		}
		tags, changed, err := visit(row.Tags)
		if err != nil || !changed {
			return err
		}
		row.Tags = tags
		return tx.PutNodegroup(row)
	case "addon":
		if len(parts) != 4 {
			return ErrNotFound
		}
		row, err := tx.Addon(key, parts[2])
		if err != nil {
			return err
		}
		if row.ARN() != arn {
			return ErrNotFound
		}
		tags, changed, err := visit(row.Tags)
		if err != nil || !changed {
			return err
		}
		row.Tags = tags
		return tx.PutAddon(row)
	case "fargateprofile":
		if len(parts) != 4 {
			return ErrNotFound
		}
		row, err := tx.FargateProfile(key, parts[2])
		if err != nil {
			return err
		}
		if row.ARN() != arn {
			return ErrNotFound
		}
		tags, changed, err := visit(row.Tags)
		if err != nil || !changed {
			return err
		}
		row.Tags = tags
		return tx.PutFargateProfile(row)
	case "podidentityassociation":
		if len(parts) != 3 {
			return ErrNotFound
		}
		row, err := tx.PodIdentityAssociation(key, parts[2])
		if err != nil {
			return err
		}
		if row.ARN() != arn {
			return ErrNotFound
		}
		tags, changed, err := visit(row.Tags)
		if err != nil || !changed {
			return err
		}
		row.Tags = tags
		return tx.PutPodIdentityAssociation(row)
	}
	return ErrNotFound
}

func (s *Service) tagResource(ctx context.Context, tx Transaction, in *api.TagResourceRequest) (*api.TagResourceResponse, error) {
	arn := value(in.ResourceArn)
	additions := tagsFromAPI(in.Tags)
	err := s.visitResourceTags(ctx, tx, arn, func(current map[string]string) (map[string]string, bool, error) {
		if err := s.authorizeResource(ctx, arn, current, "TagResource", tagConditions(additions)); err != nil {
			return nil, false, err
		}
		if current == nil {
			current = map[string]string{}
		}
		for k, v := range additions {
			current[k] = v
		}
		if err := validateTags(current); err != nil {
			return nil, false, err
		}
		return current, true, nil
	})
	if err != nil {
		return nil, err
	}
	return &api.TagResourceResponse{}, nil
}
func (s *Service) untagResource(ctx context.Context, tx Transaction, in *api.UntagResourceRequest) (*api.UntagResourceResponse, error) {
	arn := value(in.ResourceArn)
	keys := make([]string, len(in.TagKeys))
	for i, k := range in.TagKeys {
		keys[i] = string(k)
	}
	err := s.visitResourceTags(ctx, tx, arn, func(current map[string]string) (map[string]string, bool, error) {
		if err := s.authorizeResource(ctx, arn, current, "UntagResource", map[string][]string{"aws:TagKeys": keys}); err != nil {
			return nil, false, err
		}
		for _, k := range keys {
			delete(current, k)
		}
		return current, true, nil
	})
	if err != nil {
		return nil, err
	}
	return &api.UntagResourceResponse{}, nil
}
func (s *Service) listTags(ctx context.Context, tx Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResponse, error) {
	arn := value(in.ResourceArn)
	var tags map[string]string
	err := s.visitResourceTags(ctx, tx, arn, func(current map[string]string) (map[string]string, bool, error) {
		if err := s.authorizeResource(ctx, arn, current, "ListTagsForResource", nil); err != nil {
			return nil, false, err
		}
		tags = current
		return current, false, nil
	})
	if err != nil {
		return nil, err
	}
	return &api.ListTagsForResourceResponse{Tags: tagsToAPI(tags)}, nil
}
