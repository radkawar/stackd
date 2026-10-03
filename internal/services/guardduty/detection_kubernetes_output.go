package guardduty

import (
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	api "stackd/internal/awsapi/guardduty"
)

// kubernetesFindingOutput projects retained audit metadata, never sample fields
// or inferred pod configuration, geography, network ownership, or credentials.
func kubernetesFindingOutput(v Finding) (*api.Finding, error) {
	evidence := v.Observation
	event := evidence.Kubernetes
	if event == nil {
		return nil, errors.New("kubernetes finding has no audit evidence")
	}
	action := &api.KubernetesApiCallAction{
		StatusCode: new(api.Integer(event.ResponseCode)),
	}
	text(&action.Verb, event.Verb)
	text(&action.RequestUri, event.RequestURI)
	if event.Resource != "" {
		text(&action.Resource, event.Resource)
	}
	if event.Subresource != "" {
		text(&action.Subresource, event.Subresource)
	}
	if event.Namespace != "" {
		text(&action.Namespace, event.Namespace)
	}
	if event.Name != "" {
		text(&action.ResourceName, event.Name)
	}
	if event.UserAgent != "" {
		text(&action.UserAgent, event.UserAgent)
	}
	if event.SourceIP != "" {
		action.SourceIps = api.SourceIps{api.String(event.SourceIP)}
		if address, err := netip.ParseAddr(event.SourceIP); err == nil {
			action.RemoteIpDetails = &api.RemoteIpDetails{}
			if address.Is4() {
				text(&action.RemoteIpDetails.IpAddressV4, address.String())
			} else {
				text(&action.RemoteIpDetails.IpAddressV6, address.String())
			}
		}
	}
	user := &api.KubernetesUserDetails{}
	groups := make(api.Groups, len(event.Groups))
	for i, group := range event.Groups {
		groups[i] = api.String(group)
	}
	if event.ActorUserName != "" && event.ActorUserName != event.UserName {
		text(&user.Username, event.ActorUserName)
		user.ImpersonatedUser = &api.ImpersonatedUser{Groups: groups}
		text(&user.ImpersonatedUser.Username, event.UserName)
		// The retained UID belongs to the effective user, not the actor. The
		// AWS impersonated-user shape has no UID; retain it in AdditionalInfo.
	} else {
		text(&user.Username, event.UserName)
		if event.UserUID != "" {
			text(&user.Uid, event.UserUID)
		}
		user.Groups = groups
	}
	cluster := &api.EksClusterDetails{}
	text(&cluster.Arn, event.ClusterARN)
	text(&cluster.Name, event.ClusterName)
	resource := &api.Resource{
		EksClusterDetails: cluster,
		KubernetesDetails: &api.KubernetesDetails{KubernetesUserDetails: user},
	}
	text(&resource.ResourceType, "EKSCluster")
	service := &api.Service{Action: &api.Action{KubernetesApiCallAction: action}}
	text(&service.Action.ActionType, "KUBERNETES_API_CALL")
	text(&service.DetectorId, v.DetectorID)
	text(&service.ServiceName, "guardduty")
	text(&service.ResourceRole, "TARGET")
	text(&service.FeatureName, evidence.FeatureName)
	text(&service.EventFirstSeen, v.Created.UTC().Format(time.RFC3339Nano))
	text(&service.EventLastSeen, v.Updated.UTC().Format(time.RFC3339Nano))
	service.Count = new(api.Integer(v.Count))
	boolean(&service.Archived, v.Archived)
	service.Evidence = threatListEvidence(evidence.ThreatListNames)
	if v.Feedback != "" {
		text(&service.UserFeedback, v.Feedback)
	}
	type roleReference struct {
		APIGroup string `json:"apiGroup"`
		Kind     string `json:"kind"`
		Name     string `json:"name"`
	}
	type subject struct {
		APIGroup  string `json:"apiGroup"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace,omitempty"`
	}
	type deleteOptions struct {
		Observed bool `json:"observed"`
		DryRun   bool `json:"dryRun"`
	}
	var roleRef *roleReference
	if event.RoleRefName != "" {
		roleRef = &roleReference{event.RoleRefAPIGroup, event.RoleRefKind, event.RoleRefName}
	}
	var subjects []subject
	if len(event.Subjects) != 0 {
		subjects = make([]subject, len(event.Subjects))
		for i, retained := range event.Subjects {
			subjects[i] = subject{retained.APIGroup, retained.Kind, retained.Name, retained.Namespace}
		}
	}
	additional, err := json.Marshal(struct {
		AuditID          string         `json:"auditId"`
		Stage            string         `json:"stage"`
		ClusterID        string         `json:"clusterId,omitempty"`
		APIVersion       string         `json:"apiVersion,omitempty"`
		EffectiveUserUID string         `json:"effectiveUserUid,omitempty"`
		NativeAt         time.Time      `json:"nativeAt"`
		RoleRef          *roleReference `json:"roleRef,omitempty"`
		Subjects         []subject      `json:"subjects,omitempty"`
		DeleteOptions    deleteOptions  `json:"deleteOptions,omitzero"`
	}{event.AuditID, event.Stage, event.ClusterID, event.APIVersion, event.UserUID, event.NativeAt, roleRef, subjects, deleteOptions{event.DeleteOptionsObserved, event.DryRun}})
	if err != nil {
		return nil, err
	}
	service.AdditionalInfo = &api.ServiceAdditionalInfo{}
	text(&service.AdditionalInfo.Type, "default")
	text(&service.AdditionalInfo.Value, string(additional))
	out := &api.Finding{Resource: resource, Service: service, Severity: new(api.Double(evidence.Severity))}
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
	return out, nil
}
