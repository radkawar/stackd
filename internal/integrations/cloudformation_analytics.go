package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	athenaapi "stackd/internal/awsapi/athena"
	glueapi "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
	athenaowner "stackd/internal/services/athena"
	"stackd/internal/services/cloudformation"
	glueowner "stackd/internal/services/glue"
	"strings"
)

// Resource contracts are pinned from the official regional registry schemas.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/resource-type-schemas.html
func CloudFormationAnalyticsHandlers(c StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::Glue::DataCatalogEncryptionSettings": cfnGlueDataCatalogEncryptionSettings{c},
		"AWS::Glue::Catalog":                       cfnGlueCatalog{c}, "AWS::Glue::Database": cfnGlueDatabase{c}, "AWS::Glue::Table": cfnGlueTable{c}, "AWS::Glue::Partition": cfnGluePartition{c},
		"AWS::Glue::Connection": cfnGlueConnection{c}, "AWS::Glue::Crawler": cfnGlueCrawler{c}, "AWS::Glue::Classifier": cfnGlueClassifier{c}, "AWS::Glue::Job": cfnGlueJob{c}, "AWS::Glue::Trigger": cfnGlueTrigger{c}, "AWS::Glue::Workflow": cfnGlueWorkflow{c}, "AWS::Glue::SecurityConfiguration": cfnGlueSecurityConfiguration{c}, "AWS::Glue::Registry": cfnGlueRegistry{c}, "AWS::Glue::Schema": cfnGlueSchema{c}, "AWS::Glue::SchemaVersion": cfnGlueSchemaVersion{c}, "AWS::Glue::SchemaVersionMetadata": cfnGlueSchemaVersionMetadata{c},
		"AWS::Athena::WorkGroup": cfnAthenaWorkGroup{c}, "AWS::Athena::DataCatalog": cfnAthenaDataCatalog{c}, "AWS::Athena::NamedQuery": cfnAthenaNamedQuery{c}, "AWS::Athena::PreparedStatement": cfnAthenaPreparedStatement{c},
	}
}
func cfnAnalyticsMissing(err error) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && (cfnComputeMissing(err) || wire.Code == "EntityNotFoundException" || wire.Code == "InvalidRequestException" && (wire.Message == "Requested resource does not exist." || wire.Message == "Prepared statement does not exist in the requested workgroup."))
}
func cfnAnalyticsAbsent(err error) error {
	if cfnAnalyticsMissing(err) {
		return nil
	}
	return err
}

// Ownership is the native row's private claim, scoped by kind or exact ARN.
// CloudControl reads and mutations remain current-IAM operations; Create always claims.
func cfnAnalyticsContext(ctx context.Context, r cloudformation.ResourceRequest, service, kind string) context.Context {
	if r.CloudControl {
		return ctx
	}
	incarnation := r.StackID + "/" + r.LogicalID + "/" + r.Token
	if service == "glue" {
		return glueowner.WithCloudFormationOwner(ctx, kind, incarnation)
	}
	return athenaowner.WithCloudFormationOwner(ctx, kind, incarnation)
}
func cfnGlueScope(r cloudformation.ResourceRequest) glueowner.Scope {
	return glueowner.Scope{Partition: r.Scope.Partition, AccountID: r.Scope.Account, Region: r.Scope.Region}
}
func cfnGlueClaim(ctx context.Context, r cloudformation.ResourceRequest, kind, name string) context.Context {
	return cfnAnalyticsContext(ctx, r, "glue", glueowner.CloudFormationResourceClaim(cfnGlueScope(r), kind, name))
}
func cfnGlueCatalogClaim(ctx context.Context, r cloudformation.ResourceRequest, catalog string) context.Context {
	return cfnAnalyticsContext(ctx, r, "glue", glueowner.CloudFormationCatalogClaim(cfnGlueScope(r), catalog))
}
func cfnGlueDatabaseClaim(ctx context.Context, r cloudformation.ResourceRequest, catalog, name string) context.Context {
	return cfnAnalyticsContext(ctx, r, "glue", glueowner.CloudFormationDatabaseClaim(cfnGlueScope(r), catalog, name))
}

// A same-name row claimed by another incarnation proves this incarnation's row is gone.
func cfnAnalyticsGone(err error) bool {
	var wire *awswire.Error
	return cfnAnalyticsMissing(err) || errors.As(err, &wire) && wire.Code == "AlreadyExistsException" && wire.Message == "Resource is not owned by this CloudFormation incarnation."
}
func cfnAthenaKey(r cloudformation.ResourceRequest, name string) athenaowner.ResourceKey {
	return athenaowner.ResourceKey{Scope: athenaowner.Scope{Partition: r.Scope.Partition, AccountID: r.Scope.Account, Region: r.Scope.Region}, Name: name}
}
func cfnAthenaWorkGroupClaim(ctx context.Context, r cloudformation.ResourceRequest, name string) context.Context {
	return cfnAnalyticsContext(ctx, r, "athena", athenaowner.CloudFormationWorkGroupClaim(cfnAthenaKey(r, name)))
}
func cfnAthenaDataCatalogClaim(ctx context.Context, r cloudformation.ResourceRequest, name string) context.Context {
	return cfnAnalyticsContext(ctx, r, "athena", athenaowner.CloudFormationDataCatalogClaim(cfnAthenaKey(r, name)))
}

type cfnAnalyticsRecoveryKey struct{}

// RecoverCreation observes only the exact claimed incarnation and never admits a new resource.
func cfnAnalyticsRecovery(ctx context.Context) context.Context {
	return context.WithValue(ctx, cfnAnalyticsRecoveryKey{}, true)
}
func cfnAnalyticsNotAdmitted(ctx context.Context) error {
	if recovering, _ := ctx.Value(cfnAnalyticsRecoveryKey{}).(bool); recovering {
		return &awswire.Error{Code: "ResourceNotFoundException", Message: "This resource incarnation has no admitted native resource.", StatusCode: 404}
	}
	return nil
}
func cfnAnalyticsMap(value any) (cloudformation.Properties, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var p cloudformation.Properties
	err = json.Unmarshal(body, &p)
	return p, err
}
func cfnAnalyticsProject(value any, keys ...string) (cloudformation.Properties, error) {
	p, err := cfnAnalyticsMap(value)
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties(cfnComputeCopy(p, keys...)), nil
}
func cfnAnalyticsResult(id, ref string, attrs map[string]any) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: ref, Attributes: attrs}
}
func cfnAnalyticsSort(rows []cloudformation.ResourceDescription) []cloudformation.ResourceDescription {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Identifier < rows[j].Identifier })
	return rows
}
func cfnAnalyticsTags(p map[string]any) (map[string]string, error) {
	if v, ok := p["Tags"].(map[string]any); ok {
		tags := map[string]string{}
		for k, val := range v {
			s, ok := val.(string)
			if !ok || k == "" || strings.HasPrefix(strings.ToLower(k), "aws:") {
				return nil, fmt.Errorf("invalid or reserved tag %s", k)
			}
			tags[k] = s
		}
		return tags, nil
	}
	return cfnComputeTags(p)
}

// Tags are customer configuration only; they never establish or prove ownership.
func cfnAnalyticsCustomerTags(r cloudformation.ResourceRequest) map[string]string {
	tags := map[string]string{}
	for k, v := range r.Tags {
		tags[k] = v
	}
	user, _ := cfnAnalyticsTags(r.Properties)
	for k, v := range user {
		tags[k] = v
	}
	return tags
}
func cfnGlueARN(r cloudformation.ResourceRequest, kind, name string) string {
	return "arn:" + r.Scope.Partition + ":glue:" + r.Scope.Region + ":" + r.Scope.Account + ":" + kind + "/" + name
}
func cfnGlueTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[glueapi.GetTagsOutput](ctx, c, "glue", "GetTags", map[string]any{"ResourceArn": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for k, v := range out.Tags {
		tags[string(k)] = string(v)
	}
	return tags, nil
}
func cfnGlueUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	current, err := cfnGlueTags(ctx, c, arn)
	if err != nil {
		return err
	}
	desired := cfnAnalyticsCustomerTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err = cfnComputeRun(ctx, c, "glue", "UntagResource", map[string]any{"ResourceArn": arn, "TagsToRemove": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "glue", "TagResource", map[string]any{"ResourceArn": arn, "TagsToAdd": desired})
}
func cfnAthenaARN(r cloudformation.ResourceRequest, kind, name string) string {
	return "arn:" + r.Scope.Partition + ":athena:" + r.Scope.Region + ":" + r.Scope.Account + ":" + kind + "/" + name
}
func cfnAthenaTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	tags := map[string]string{}
	input := map[string]any{"ResourceARN": arn}
	for {
		out, err := cfnComputeCall[athenaapi.ListTagsForResourceOutput](ctx, c, "athena", "ListTagsForResource", input)
		if err != nil {
			return nil, err
		}
		for _, tag := range out.Tags {
			tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
		}
		if cfnComputeValue(out.NextToken) == "" {
			return tags, nil
		}
		input["NextToken"] = out.NextToken
	}
}
func cfnAthenaUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	current, err := cfnAthenaTags(ctx, c, arn)
	if err != nil {
		return err
	}
	desired := cfnAnalyticsCustomerTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err = cfnComputeRun(ctx, c, "athena", "UntagResource", map[string]any{"ResourceARN": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "athena", "TagResource", map[string]any{"ResourceARN": arn, "Tags": cfnComputeTagList(desired)})
}
func cfnAnalyticsRequireIdentity(h cloudformation.ResourceHandler, r cloudformation.ResourceRequest) error {
	replace, err := cloudformation.RequiresReplacement(h, r.Scope, r.Previous, r.Properties)
	if err != nil {
		return err
	}
	if replace {
		return fmt.Errorf("resource identity is immutable and requires replacement")
	}
	return nil
}
func cfnAnalyticsReadError(err error) error {
	if cfnAnalyticsMissing(err) {
		return &awswire.Error{Code: "ResourceNotFoundException", Message: err.Error(), StatusCode: 400}
	}
	return err
}

// Tagged analytics owners recover only this incarnation's private native claim;
// recovery reports a modeled absence instead of admitting a new resource.
func (h cfnGlueCatalog) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnGlueDatabase) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnGlueConnection) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnGlueJob) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnGlueCrawler) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnGlueRegistry) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnGlueSchema) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnGlueTrigger) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnGlueWorkflow) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnAthenaDataCatalog) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
