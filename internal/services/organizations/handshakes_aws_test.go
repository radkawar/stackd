package organizations_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestOrganizationsHandshakesReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/iam/organizations_handshakes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Action, Code string
			Status             int
			Input              map[string]any
			Output             map[string]json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	_, client := setup(t)
	sender := client(managementID, "us-east-1")
	createOrg(t, sender)
	memberID := createAccount(t, sender, "Member")
	recipient := client(memberID, "us-west-2")
	organization, err := sender.DescribeOrganization(t.Context(), &sdk.DescribeOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	replace := strings.NewReplacer("222222222222", memberID, "member@example.test", "Member@example.com", "management@example.test", managementID+"@localhost.local", "o-exampleorgid", *organization.Organization.Id, "exampleorgid", strings.TrimPrefix(*organization.Organization.Id, "o-"))
	ids := map[string]string{}
	for n, row := range fixture.Observations {
		// Real session-policy evaluation is exercised by the root integration test.
		if row.Case == "management-owner" || row.Case == "member-owner" || row.Case == "owner-absent" {
			continue
		}
		t.Run(fmt.Sprintf("%02d/%s", n, row.Case), func(t *testing.T) {
			body, _ := json.Marshal(row.Input)
			text := replace.Replace(string(body))
			for original, id := range ids {
				text = strings.ReplaceAll(text, original, id)
			}
			var input map[string]any
			if err := json.Unmarshal([]byte(text), &input); err != nil {
				t.Fatal(err)
			}
			actor := sender
			switch row.Case {
			case "recipient-description", "recipient-list", "recipient-cancel", "recipient-already-member", "decline-accepted", "accept-accepted", "decline", "decline-again", "accept-declined", "accept-canceled", "decline-canceled":
				actor = recipient
			}
			option := func(o *sdk.Options) { o.APIOptions = append(o.APIOptions, organizationsJSONInput(t, input)) }
			got, callErr := callHandshakeSDK(t, actor, row.Action, option)
			if row.Code != "Success" {
				requireCode(t, callErr, row.Code)
				var httpErr *smithyhttp.ResponseError
				if !errors.As(callErr, &httpErr) || httpErr.HTTPStatusCode() != row.Status {
					t.Fatalf("status: %v", callErr)
				}
				var expectedReason string
				_ = json.Unmarshal(row.Output["Reason"], &expectedReason)
				if expectedReason != "" {
					var invalid *types.InvalidInputException
					var constraint *types.HandshakeConstraintViolationException
					reason := ""
					if errors.As(callErr, &invalid) {
						reason = string(invalid.Reason)
					}
					if errors.As(callErr, &constraint) {
						reason = string(constraint.Reason)
					}
					if reason != expectedReason {
						t.Errorf("reason %q, want %q", reason, expectedReason)
					}
				}
				return
			}
			if callErr != nil {
				t.Fatal(callErr)
			}
			var expected []map[string]json.RawMessage
			if h, ok := row.Output["Handshake"]; ok {
				var one map[string]json.RawMessage
				_ = json.Unmarshal(h, &one)
				expected = append(expected, one)
			} else if h, ok := row.Output["Handshakes"]; ok {
				_ = json.Unmarshal(h, &expected)
			}
			if len(got) != len(expected) {
				t.Fatalf("handshakes=%d, want %d", len(got), len(expected))
			}
			if row.Action == "InviteAccountToOrganization" {
				var original string
				_ = json.Unmarshal(expected[0]["Id"], &original)
				ids[original] = *got[0].Id
			}
			for _, h := range expected {
				var original string
				_ = json.Unmarshal(h["Id"], &original)
				index := slices.IndexFunc(got, func(i types.Handshake) bool { return aws.ToString(i.Id) == ids[original] })
				if index < 0 {
					t.Fatal("missing handshake", original)
				}
				actual := got[index]
				var requested, expiration float64
				_ = json.Unmarshal(h["RequestedTimestamp"], &requested)
				_ = json.Unmarshal(h["ExpirationTimestamp"], &expiration)
				if actual.RequestedTimestamp == nil || actual.ExpirationTimestamp == nil || actual.ExpirationTimestamp.Sub(*actual.RequestedTimestamp) != time.Duration(expiration-requested)*time.Second {
					t.Fatal("invitation lifetime", actual)
				}
				delete(h, "RequestedTimestamp")
				delete(h, "ExpirationTimestamp")
				actual.RequestedTimestamp, actual.ExpirationTimestamp = nil, nil
				raw, _ := json.Marshal(h)
				text := replace.Replace(string(raw))
				for original, id := range ids {
					text = strings.ReplaceAll(text, original, id)
				}
				var want types.Handshake
				if err := json.Unmarshal([]byte(text), &want); err != nil {
					t.Fatal(err)
				}
				partyLess := func(a, b types.HandshakeParty) int {
					return strings.Compare(string(a.Type)+aws.ToString(a.Id), string(b.Type)+aws.ToString(b.Id))
				}
				slices.SortFunc(actual.Parties, partyLess)
				slices.SortFunc(want.Parties, partyLess)
				if !reflect.DeepEqual(actual, want) {
					t.Fatalf("handshake:\ngot %+v\nwant %+v", actual, want)
				}
			}
		})
	}
}

func callHandshakeSDK(t *testing.T, c *sdk.Client, action string, option func(*sdk.Options)) ([]types.Handshake, error) {
	t.Helper()
	id := aws.String("h-00000000")
	var h *types.Handshake
	var err error
	switch action {
	case "InviteAccountToOrganization":
		out, e := c.InviteAccountToOrganization(t.Context(), &sdk.InviteAccountToOrganizationInput{Target: &types.HandshakeParty{Id: aws.String("222222222222"), Type: types.HandshakePartyTypeAccount}}, option)
		err = e
		if out != nil {
			h = out.Handshake
		}
	case "DescribeHandshake":
		out, e := c.DescribeHandshake(t.Context(), &sdk.DescribeHandshakeInput{HandshakeId: id}, option)
		err = e
		if out != nil {
			h = out.Handshake
		}
	case "AcceptHandshake":
		out, e := c.AcceptHandshake(t.Context(), &sdk.AcceptHandshakeInput{HandshakeId: id}, option)
		err = e
		if out != nil {
			h = out.Handshake
		}
	case "DeclineHandshake":
		out, e := c.DeclineHandshake(t.Context(), &sdk.DeclineHandshakeInput{HandshakeId: id}, option)
		err = e
		if out != nil {
			h = out.Handshake
		}
	case "CancelHandshake":
		out, e := c.CancelHandshake(t.Context(), &sdk.CancelHandshakeInput{HandshakeId: id}, option)
		err = e
		if out != nil {
			h = out.Handshake
		}
	case "ListHandshakesForAccount":
		out, e := c.ListHandshakesForAccount(t.Context(), &sdk.ListHandshakesForAccountInput{}, option)
		if out != nil {
			return out.Handshakes, e
		}
		return nil, e
	case "ListHandshakesForOrganization":
		out, e := c.ListHandshakesForOrganization(t.Context(), &sdk.ListHandshakesForOrganizationInput{}, option)
		if out != nil {
			return out.Handshakes, e
		}
		return nil, e
	default:
		t.Fatal("unknown captured action", action)
	}
	if h != nil {
		return []types.Handshake{*h}, err
	}
	return nil, err
}
