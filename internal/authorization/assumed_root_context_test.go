package authorization

import (
	"testing"
	"time"

	"stackd/internal/awsctx"
)

func TestAssumedRootContextRequiresVerifiedSession(t *testing.T) {
	root := awsctx.Metadata{AccountID: "123456789012", Partition: "aws", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}
	request := Request{Action: "iam:GetAccountSummary", ResourceARN: "*"}
	for _, sessionType := range []string{"", "GetSessionToken", "AssumeRole", "GetFederationToken", "AssumeRoot"} {
		t.Run(sessionType, func(t *testing.T) {
			m := root
			m.SessionType = sessionType
			kind := "Account"
			switch sessionType {
			case "AssumeRole":
				kind = "AssumedRole"
				m.PrincipalARN, m.PrincipalID = "arn:aws:sts::123456789012:assumed-role/worker/session", "AROATEST:session"
				m.IssuerARN, m.IssuerID = "arn:aws:iam::123456789012:role/worker", "AROATEST"
			case "GetFederationToken":
				kind = "FederatedUser"
				m.PrincipalARN, m.PrincipalID = "arn:aws:sts::123456789012:federated-user/session", "123456789012:session"
				m.IssuerARN, m.IssuerID = "arn:aws:iam::123456789012:user/alice", "AIDATEST"
			}
			values, _, err := evaluationContext(m, kind, nil, request, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			value, present := values["aws:assumedroot"]
			if present != (sessionType == "AssumeRoot") || present && (len(value) != 1 || value[0] != "true") {
				t.Fatalf("AssumedRoot=%v present=%v for %q", value, present, sessionType)
			}
			for _, supplied := range []string{"true", "false"} {
				withContext := request
				withContext.Context = map[string][]string{"AWS:AssumedRoot": {supplied}}
				_, _, err := evaluationContext(m, kind, nil, withContext, time.Time{})
				if (err == nil) != (sessionType == "AssumeRoot" && supplied == "true") {
					t.Fatalf("spoofed/matching attribute %q error=%v", supplied, err)
				}
			}
			m.SessionContext = map[string][]string{"aws:AssumedRoot": {"true"}}
			if _, _, err := evaluationContext(m, kind, nil, request, time.Time{}); err == nil {
				t.Fatal("federation context supplied an AWS-owned session attribute")
			}
		})
	}
}
