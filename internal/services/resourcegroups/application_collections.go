package resourcegroups

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/resourcegroups"
)

// AssociateApplicationTagValue retains a real resource-query group. Its members
// are always selected from current resource owners, not association-time ARNs.
func (s *Service) AssociateApplicationTagValue(ctx context.Context, applicationARN, parentARN, key, value string) (string, error) {
	digest := sha256.Sum256([]byte(applicationARN + "\x00" + key + "\x00" + value))
	name := "AWS_AppRegistry_ResourceGroup-" + hex.EncodeToString(digest[:16])
	arn := groupARN(scopeFor(ctx), name)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, exists, err := tx.Group(scopeFor(ctx), arn); err != nil {
			return err
		} else if exists {
			return failure("BadRequestException", "The tag value is already associated.")
		}
		body, err := json.Marshal(resourceQuery{ResourceTypeFilters: []string{"AWS::S3::Bucket", "AWS::SQS::Queue", "AWS::SSM::Parameter", "AWS::CloudFormation::Stack"}, TagFilters: []tagFilter{{Key: key, Values: []string{value}}}})
		if err != nil {
			return err
		}
		g := Group{Scope: scopeFor(ctx), ARN: arn, Name: name, Created: s.clock.Now(), ApplicationARN: applicationARN, SourceName: value, SourceARN: arn, ParentARN: parentARN, Tags: map[string]string{"EnableAWSServiceCatalogAppRegistry": "true"}, Query: &api.ResourceQuery{Type: new(api.QueryTypeTAG_FILTERS_1_0), Query: new(api.Query(body))}}
		if err := s.authorize(tx.Context(), "CreateGroup", nil, g.Tags, []string{"EnableAWSServiceCatalogAppRegistry"}); err != nil {
			return err
		}
		return tx.PutGroup(g)
	})
	return arn, err
}
func (s *Service) ApplicationTagValueResources(ctx context.Context, arn string) ([]ApplicationResource, error) {
	var selected []ApplicationResource
	err := s.repository.View(ctx, func(r Reader) error {
		g, ok, err := r.Group(scopeFor(ctx), arn)
		if err != nil {
			return err
		}
		if !ok || g.ApplicationARN == "" || g.ParentARN == "" || g.Query == nil {
			return failure("NotFoundException", "The application resource collection does not exist.")
		}
		if denied := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "tag:GetResources", ResourceARN: "*"}); denied != nil {
			return denied
		}
		q, err := parseQuery(g.Query)
		if err != nil {
			return err
		}
		if s.applicationResources == nil {
			return failure("NotImplementedException", "Current application resource owners are unavailable.")
		}
		rows, err := s.applicationResources.List(r.Context())
		if err != nil {
			return err
		}
		for _, row := range rows {
			match := true
			for _, f := range q.TagFilters {
				v, ok := row.Tags[f.Key]
				if !ok || len(f.Values) > 0 && !slices.Contains(f.Values, v) {
					match = false
					break
				}
			}
			if match {
				selected = append(selected, row)
			}
		}
		return nil
	})
	return selected, err
}
