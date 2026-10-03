package authorization_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

const fullRCP = `{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`

type resourceControls struct {
	controlSource
	levels    []iampolicy.PolicyLevel
	err       error
	owner     string
	partition string
	orgID     string
	orgPath   string
}

func (s *resourceControls) ResourceControlPolicies(ctx context.Context, owner string) (authorization.ResourceControlSet, error) {
	s.owner, s.partition = owner, awsctx.FromContext(ctx).Partition
	return authorization.ResourceControlSet{Levels: s.levels, OrganizationID: s.orgID, OrganizationPath: s.orgPath}, s.err
}

func TestResourceControlContextRejectsServiceOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
	}{
		{"organization ID", "AWS:ResourceOrgID", "o-invented"},
		{"organization path", "aws:ResourceOrgPaths", "o-real/r-root/ou-other/"},
		{"AWS service identity", "aws:PrincipalIsAWSService", "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &resourceControls{orgID: "o-real", orgPath: "o-real/r-root/"}
			e := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}}}, source)
			err := e.Authorize(awsctx.WithMetadata(t.Context(), metadata(false)), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, Context: map[string][]string{tc.key: {tc.value}}})
			if err == nil {
				t.Fatal("service supplied authoritative organization or principal context")
			}
		})
	}
}

func TestResourceControlsIntersectAllGrantsAndFailOnUnavailableSource(t *testing.T) {
	for _, tc := range []struct {
		name      string
		set       authorization.PolicySet
		resource  string
		sourceErr error
	}{
		{"identity grant", authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}}, "", nil},
		{"direct resource grant", authorization.PolicySet{}, direct, nil},
		{"boundary bypass cannot bypass RCP", authorization.PolicySet{HasBoundary: true}, direct, nil},
		{"unavailable control source", authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}}, "", errors.New("unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &resourceControls{levels: []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: fullRCP}, {Document: resourceDeny}}}}, err: tc.sourceErr}
			e := authorization.New(identitySource{set: tc.set}, source)
			if err := e.Authorize(awsctx.WithMetadata(t.Context(), metadata(false)), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, ResourcePolicies: []authorization.BoundPolicy{{Document: tc.resource}}}); err == nil {
				t.Fatal("RCP restriction bypassed")
			}
			if source.owner != account || source.partition != "aws" {
				t.Fatalf("resource scope = %s/%s", source.partition, source.owner)
			}
		})
	}
	// The AWS-managed full-access RCP is a maximum, never a permission grant.
	e := authorization.New(identitySource{}, &resourceControls{levels: []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: fullRCP}}}}})
	if err := e.Authorize(awsctx.WithMetadata(t.Context(), metadata(false)), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN}); err == nil {
		t.Fatal("RCP granted identity permissions")
	}
}

func TestResourceControlExemptionsRetainOtherPolicyLayers(t *testing.T) {
	m := metadata(false)
	m.PrincipalARN = "arn:aws:sts::123456789012:assumed-role/linked/session"
	m.PrincipalID = "AROAEXAMPLE:session"
	m.IssuerARN = "arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/linked"
	m.IssuerID = "AROAEXAMPLE"
	for _, tc := range []struct {
		name                                  string
		linked, exempt, identityDeny, scpDeny bool
		allowed                               bool
	}{
		{"ordinary role denied", false, false, false, false, false},
		{"service-linked role", true, false, false, true, true},
		{"service-linked identity deny", true, false, true, false, false},
		{"resource exemption", false, true, false, false, true},
		{"resource exemption preserves SCP", false, true, false, true, false},
		{"resource exemption preserves identity deny", false, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}, ServiceLinkedRole: tc.linked}
			if tc.identityDeny {
				set.Identity = append(set.Identity, iampolicy.Policy{Document: deny})
			}
			source := &resourceControls{levels: []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: fullRCP}, {Document: resourceDeny}}}}}
			if tc.scpDeny {
				source.controlSource = controlSource{{Documents: []iampolicy.Policy{{Document: deny}}}}
			}
			err := authorization.New(identitySource{set: set}, source).Authorize(awsctx.WithMetadata(t.Context(), m), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, ResourceControlExempt: tc.exempt})
			if (err == nil) != tc.allowed {
				t.Fatalf("permission = %v, want allowed %v", err, tc.allowed)
			}
		})
	}
}

func TestResourceControlCurrentPrimaryActionBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/iam/resource_control_current.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name      string `json:"name"`
			Action    string `json:"action"`
			ARNFormat string `json:"arn_format"`
			Applies   bool   `json:"applies"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	variable := regexp.MustCompile(`\$\{([^}]+)\}`)
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			resource := "*"
			if tc.ARNFormat != "" {
				resource = variable.ReplaceAllStringFunc(tc.ARNFormat, func(token string) string {
					switch token {
					case "${Partition}":
						return "aws"
					case "${Account}":
						return account
					case "${Region}":
						return "us-east-1"
					default:
						return "example"
					}
				})
			}
			document := `{"Statement":{"Effect":"Deny","Principal":"*","Action":"` + tc.Action + `","Resource":"*","Condition":{"StringEquals":{"aws:ResourceOrgID":"o-owner","aws:ResourceAccount":"` + account + `"}}}}`
			source := &resourceControls{orgID: "o-owner", orgPath: "o-owner/r-root/ou-restricted/", levels: []iampolicy.PolicyLevel{{TargetID: "ou-restricted", Documents: []iampolicy.Policy{{Document: fullRCP}, {Document: document}}}}}
			e := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}}}}, source)
			request := authorization.Request{Action: tc.Action, ResourceARN: resource, ResourceAccountID: account}
			rejected := e.Authorize(awsctx.WithMetadata(t.Context(), metadata(false)), request)
			if tc.Applies {
				if rejected == nil || !strings.Contains(rejected.Message, "resource control policy") {
					t.Fatalf("resource-owner denial not applied: %v", rejected)
				}
			} else if rejected != nil {
				t.Fatalf("RCP restricted an action without an authorized resource type: %v", rejected)
			}
		})
	}
}
