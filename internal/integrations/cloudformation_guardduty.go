package integrations

import (
	"context"
	"errors"
	"fmt"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	gd "stackd/internal/services/guardduty"
	"strings"
)

func cfnGuardContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return gd.WithCloudFormationOwnership(ctx, gd.CloudFormationOwnership{Owner: cfnMessagingOwner(r), Token: cfnMessagingHash(r.Token)})
}
func cfnGuardCreateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	r.CloudControl = false
	return cfnGuardContext(ctx, r)
}
func cfnGuardKey(r cloudformation.ResourceRequest) (string, string) {
	if r.PhysicalID != "" {
		a, b, ok := strings.Cut(r.PhysicalID, "|")
		if ok {
			return a, b
		}
	}
	return cfnComputeString(r.Properties, "DetectorId"), r.PhysicalID
}
func cfnGuardARN(r cloudformation.ResourceRequest, detector, kind, id string) string {
	a := fmt.Sprintf("arn:%s:guardduty:%s:%s:detector/%s", r.Scope.Partition, r.Scope.Region, r.Scope.Account, detector)
	if kind != "" {
		a += "/" + kind + "/" + id
	}
	return a
}
func cfnGuardMissing(err error) bool {
	if cfnSecurityMissing(err) {
		return true
	}
	var w *awswire.Error
	if !errors.As(err, &w) || w.Code != "BadRequestException" {
		return false
	}
	switch w.Message {
	case "The requested filter does not exist", "The request is rejected since no such resource found.", "The requested resource does not exist", "The request is rejected because the input detectorId is not owned by the current account.", "The request is rejected because the one or more input parameters have invalid values.":
		return true
	}
	return false
}
func cfnGuardAbsent(err error) error {
	if cfnGuardMissing(err) {
		return nil
	}
	return err
}
func cfnGuardUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, old api.TagMap) error {
	ctx = cfnGuardContext(ctx, r)
	next, e := cfnSecurityTags(r)
	if e != nil {
		return e
	}
	remove := []string{}
	for k := range old {
		if _, ok := next[string(k)]; !ok {
			remove = append(remove, string(k))
		}
	}
	if len(remove) > 0 {
		if e := cfnComputeRun(ctx, c, "guardduty", "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": remove}); e != nil {
			return e
		}
	}
	if len(next) > 0 {
		return cfnComputeRun(ctx, c, "guardduty", "TagResource", map[string]any{"ResourceArn": arn, "Tags": next})
	}
	return nil
}
func cfnGuardDetectors(ctx context.Context, c StepFunctionsCommands) ([]string, error) {
	o, e := cfnComputeCall[api.ListDetectorsOutput](ctx, c, "guardduty", "ListDetectors", map[string]any{})
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, id := range o.DetectorIds {
		out = append(out, string(id))
	}
	return out, nil
}

type cfnGuardDutyDetector struct{ c StepFunctionsCommands }

func (h cfnGuardDutyDetector) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "Enable", "FindingPublishingFrequency", "DataSources", "Features", "Tags"); e != nil {
		return e
	}
	return cfnComputeRequired(p, "Enable")
}
func (h cfnGuardDutyDetector) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, nil
}
func (h cfnGuardDutyDetector) load(ctx context.Context, r cloudformation.ResourceRequest) (*api.GetDetectorOutput, error) {
	return cfnComputeCall[api.GetDetectorOutput](cfnGuardContext(ctx, r), h.c, "guardduty", "GetDetector", map[string]any{"DetectorId": r.PhysicalID})
}
func (h cfnGuardDutyDetector) result(id string) cloudformation.ResourceResult {
	return cfnSecurityResult(id, id, map[string]any{"Id": id})
}
func (h cfnGuardDutyDetector) create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p := cfnComputeCopy(r.Properties, "Enable", "FindingPublishingFrequency", "DataSources", "Features")
	t, e := cfnSecurityTags(r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p["Tags"] = t
	p["ClientToken"] = cfnMessagingHash(r.Token)
	o, e := cfnComputeCall[api.CreateDetectorOutput](ctx, h.c, "guardduty", "CreateDetector", p)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	r.PhysicalID = cfnComputeValue(o.DetectorId)
	_, e = h.load(ctx, r)
	return h.result(r.PhysicalID), e
}
func (h cfnGuardDutyDetector) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p := cfnComputeCopy(r.Properties, "Enable", "FindingPublishingFrequency", "DataSources", "Features")
	if p["FindingPublishingFrequency"] == nil {
		p["FindingPublishingFrequency"] = "SIX_HOURS"
	}
	p["DetectorId"] = r.PhysicalID
	if e = cfnComputeRun(cfnGuardContext(ctx, r), h.c, "guardduty", "UpdateDetector", p); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	e = cfnGuardUpdateTags(ctx, h.c, r, cfnGuardARN(r, r.PhysicalID, "", ""), v.Tags)
	return h.result(r.PhysicalID), e
}
func (h cfnGuardDutyDetector) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if _, e := h.load(ctx, r); e != nil {
		return cfnGuardAbsent(e)
	}
	return cfnGuardAbsent(cfnComputeRun(cfnGuardContext(ctx, r), h.c, "guardduty", "DeleteDetector", map[string]any{"DetectorId": r.PhysicalID}))
}
func (h cfnGuardDutyDetector) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.load(ctx, r)
	if e != nil {
		return nil, e
	}
	features := []any{}
	for _, f := range v.Features {
		p := cfnSecuritySelect(f, "Name", "Status")
		additional := []any{}
		for _, a := range f.AdditionalConfiguration {
			additional = append(additional, cfnSecuritySelect(a, "Name", "Status"))
		}
		if len(additional) > 0 {
			p["AdditionalConfiguration"] = additional
		}
		features = append(features, p)
	}
	return cloudformation.Properties{"Id": r.PhysicalID, "Enable": cfnComputeValue(v.Status) == "ENABLED", "FindingPublishingFrequency": cfnComputeValue(v.FindingPublishingFrequency), "Features": features, "Tags": cfnSecurityUserTags(v.Tags)}, nil
}
func (h cfnGuardDutyDetector) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	ids, e := cfnGuardDetectors(ctx, h.c)
	if e != nil {
		return nil, e
	}
	out := []cloudformation.ResourceDescription{}
	for _, id := range ids {
		r.PhysicalID = id
		p, e := h.Read(ctx, r)
		if e != nil {
			return nil, e
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: p})
	}
	return out, nil
}
