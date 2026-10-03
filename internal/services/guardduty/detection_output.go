package guardduty

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	api "stackd/internal/awsapi/guardduty"
)

// observedFindingOutput projects only retained API evidence. It deliberately
// does not load sample templates or synthesize network/geographic enrichment.
func observedFindingOutput(v Finding) api.Finding {
	evidence := v.Observation
	accessKey := &api.AccessKeyDetails{}
	if evidence.AccessKeyID != "" {
		text(&accessKey.AccessKeyId, evidence.AccessKeyID)
	}
	if evidence.PrincipalID != "" {
		text(&accessKey.PrincipalId, evidence.PrincipalID)
	}
	if evidence.UserName != "" {
		text(&accessKey.UserName, evidence.UserName)
	}
	text(&accessKey.UserType, evidence.UserType)
	action := &api.AwsApiCallAction{}
	text(&action.Api, evidence.API)
	text(&action.ServiceName, evidence.ServiceName)
	if evidence.ErrorCode != "" {
		text(&action.ErrorCode, evidence.ErrorCode)
	}
	if evidence.ResourceType != "" && evidence.ResourceName != "" {
		action.AffectedResources = api.AffectedResources{api.String(evidence.ResourceType): api.String(evidence.ResourceName)}
	}
	if address, err := netip.ParseAddr(evidence.SourceIP); err == nil {
		action.RemoteIpDetails = &api.RemoteIpDetails{}
		if address.Is4() {
			text(&action.RemoteIpDetails.IpAddressV4, address.String())
		} else {
			text(&action.RemoteIpDetails.IpAddressV6, address.String())
		}
		text(&action.CallerType, "Remote IP")
	}
	service := &api.Service{Action: &api.Action{AwsApiCallAction: action}}
	text(&service.Action.ActionType, "AWS_API_CALL")
	text(&service.DetectorId, v.DetectorID)
	text(&service.ServiceName, "guardduty")
	text(&service.ResourceRole, "ACTOR")
	text(&service.FeatureName, evidence.FeatureName)
	text(&service.EventFirstSeen, v.Created.UTC().Format(time.RFC3339Nano))
	text(&service.EventLastSeen, v.Updated.UTC().Format(time.RFC3339Nano))
	service.Count = new(api.Integer(v.Count))
	boolean(&service.Archived, v.Archived)
	service.Evidence = threatListEvidence(evidence.ThreatListNames)
	if v.Feedback != "" {
		text(&service.UserFeedback, v.Feedback)
	}
	if evidence.EventID != "" {
		// A string-only document cannot fail JSON encoding. This ties the latest
		// aggregated evidence to its real API outcome, without sample markers.
		data, _ := json.Marshal(struct {
			EventID string `json:"eventId"`
		}{evidence.EventID})
		service.AdditionalInfo = &api.ServiceAdditionalInfo{}
		text(&service.AdditionalInfo.Type, "default")
		text(&service.AdditionalInfo.Value, string(data))
	}
	out := api.Finding{
		Resource: &api.Resource{AccessKeyDetails: accessKey}, Service: service,
		Severity: new(api.Double(evidence.Severity)),
	}
	text(&out.Resource.ResourceType, "AccessKey")
	// AWS uses S3Bucket for S3 data findings, but AccessKey for management
	// findings even when their affected resource is an S3 bucket.
	if strings.Contains(evidence.Type, ":S3/") && evidence.FeatureName == "S3DataEvent" && evidence.ResourceType == "AWS::S3::Bucket" {
		text(&out.Resource.ResourceType, "S3Bucket")
		bucket := api.S3BucketDetail{}
		text(&bucket.Name, evidence.ResourceName)
		text(&bucket.Arn, evidence.ResourceARN)
		out.Resource.S3BucketDetails = api.S3BucketDetails{bucket}
		text(&service.ResourceRole, "TARGET")
	}
	text(&out.AccountId, v.AccountID)
	text(&out.Arn, detectorARN(v.Scope, v.DetectorID)+"/finding/"+v.ID)
	text(&out.Id, v.ID)
	text(&out.Partition, v.Partition)
	text(&out.Region, v.Region)
	text(&out.SchemaVersion, "2.0")
	text(&out.CreatedAt, v.Created.UTC().Format(time.RFC3339Nano))
	text(&out.UpdatedAt, v.Updated.UTC().Format(time.RFC3339Nano))
	text(&out.Type, evidence.Type)
	text(&out.Title, evidence.Title)
	text(&out.Description, evidence.Description)
	return out
}

func threatListEvidence(names []string) *api.Evidence {
	if len(names) == 0 {
		return nil
	}
	details := make(api.ThreatIntelligenceDetails, len(names))
	for i, name := range names {
		text(&details[i].ThreatListName, name)
	}
	return &api.Evidence{ThreatIntelligenceDetails: details}
}
