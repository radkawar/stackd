package stackd_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestCognitoNativeGroupWorkflows(t *testing.T) {
	cognitoNativeRun(t, "group_workflows", "")
}

func TestCognitoNativeGroupAuthority(t *testing.T) {
	cognitoNativeRun(t, "group_authority_workflows", "")
}

type cognitoAuthority struct {
	Policy          json.RawMessage
	DurationSeconds int32                  `json:"duration_seconds"`
	FederatedUser   ststypes.FederatedUser `json:"federated_user"`
}

func (r *cognitoReplay) federationCredentials(t *testing.T, clients cloudClients, fixture cognitoLoginFixture, principal string, issuer aws.CredentialsProvider) aws.Credentials {
	t.Helper()
	authority := fixture.Authorities[principal]
	var policy any
	awsDecodeJSON(t, authority.Policy, &policy)
	r.bindInput(policy, "")
	document, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	client := sts.New(sts.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: issuer, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	arn := aws.ToString(authority.FederatedUser.Arn)
	out, err := client.GetFederationToken(t.Context(), &sts.GetFederationTokenInput{
		Name: aws.String(arn[strings.LastIndex(arn, "/")+1:]), Policy: aws.String(string(document)), DurationSeconds: aws.Int32(authority.DurationSeconds),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.bindings[cognitoBinding(arn)] = aws.ToString(out.FederatedUser.Arn)
	r.bindings[cognitoBinding(aws.ToString(authority.FederatedUser.FederatedUserId))] = aws.ToString(out.FederatedUser.FederatedUserId)
	return aws.Credentials{
		AccessKeyID: aws.ToString(out.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey), SessionToken: aws.ToString(out.Credentials.SessionToken),
	}
}

type cognitoReplayPage struct {
	native, local []any
}

// Group listings have no documented ordering contract. Preserve page lengths,
// cursor transitions and complete collection contents without copying AWS's
// private ordering into the deterministic local repositories.
func (r *cognitoReplay) compareResponse(t *testing.T, row cognitoObservation, expected, actual any) {
	t.Helper()
	field := ""
	switch row.Operation {
	case "ListGroups", "AdminListGroupsForUser":
		field = "Groups"
	case "ListUsersInGroup":
		field = "Users"
	}
	var input struct {
		Limit     *int32
		NextToken string
	}
	if field != "" {
		awsDecodeJSON(t, row.Input, &input)
	}
	if input.Limit == nil {
		r.compare(t, "", expected, actual)
		return
	}
	want, got := expected.(map[string]any), actual.(map[string]any)
	native, nativeOK := want[field].([]any)
	local, localOK := got[field].([]any)
	if !nativeOK || !localOK || len(native) != len(local) {
		t.Fatalf("%s: page contents differ: native=%v local=%v", field, want[field], got[field])
	}
	page := r.pages[input.NextToken]
	if page == nil {
		page = &cognitoReplayPage{}
	}
	delete(r.pages, input.NextToken)
	page.native = append(page.native, native...)
	page.local = append(page.local, local...)
	want[field], got[field] = nil, nil
	r.compare(t, "", want, got)
	want[field], got[field] = native, local
	if next, ok := want["NextToken"].(string); ok && next != "" {
		if r.pages == nil {
			r.pages = map[string]*cognitoReplayPage{}
		}
		r.pages[next] = page
		return
	}
	r.compare(t, "."+field, page.native, page.local)
}
