package authorization_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func TestEventBridgeServicePrincipalAWS(t *testing.T) {
	const source = "arn:aws:events:us-east-1:111111111111:rule/stackd-event-delivery-owned/stackd-event-delivery-owned"
	const target = "arn:aws:sqs:us-east-1:111111111111:stackd-event-delivery-owned-target"
	m := awsctx.Metadata{AccountID: "111111111111", Partition: "aws", Region: "us-east-1",
		PrincipalARN: "arn:aws:iam::111111111111:user/publisher", HasSessionPolicy: true,
		SessionPolicies: []string{deny}}
	ctx := awsctx.WithServicePrincipal(awsctx.WithMetadata(t.Context(), m), awsctx.ServicePrincipal{
		Name: "events.amazonaws.com", SourceARN: source, Type: "User"})
	// Neither the publisher's current identity nor its SCP is the delivery actor.
	e := authorization.New(identitySource{err: errors.New("IAM source must not be consulted")},
		controlSource{{Documents: []policy.Policy{{Document: deny}}}})
	for _, name := range []string{"delivery", "principal_types"} {
		data, err := os.ReadFile("../../testdata/aws/eventbridge/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var capture struct {
			Observations []struct {
				Case, Delivery string
				Condition      map[string]any
			}
		}
		if err := json.Unmarshal(data, &capture); err != nil {
			t.Fatal(err)
		}
		for _, observation := range capture.Observations {
			t.Run(observation.Case, func(t *testing.T) {
				statement := map[string]any{"Effect": "Allow", "Principal": map[string]string{"Service": "events.amazonaws.com"},
					"Action": "sqs:SendMessage", "Resource": target}
				if len(observation.Condition) != 0 {
					statement["Condition"] = observation.Condition
				}
				document, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{statement}})
				if err != nil {
					t.Fatal(err)
				}
				authErr := e.Authorize(ctx, authorization.Request{Action: "sqs:SendMessage", ResourceARN: target, ResourcePolicies: []authorization.BoundPolicy{{Document: string(document)}}})
				if allowed := authErr == nil; allowed != (observation.Delivery == "target") {
					t.Fatalf("authorization = %v, native delivery = %s", authErr, observation.Delivery)
				}
			})
		}
	}
}

func TestServicePrincipalResourceControls(t *testing.T) {
	ctx := awsctx.WithServicePrincipal(awsctx.WithMetadata(t.Context(), metadata(false)), awsctx.ServicePrincipal{
		Name: "events.amazonaws.com", SourceARN: "arn:aws:events:us-east-1:" + account + ":rule/source", Type: "User"})
	const target = "arn:aws:sqs:us-east-1:222222222222:target"
	const grant = `{"Statement":{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"*"}}`
	for _, tc := range []struct {
		name     string
		resource string
		controls []policy.PolicyLevel
		allowed  bool
	}{
		{"resource grant", grant, nil, true},
		{"no resource grant", "", nil, false},
		{"resource deny", resourceDeny, nil, false},
		{"RCP deny", grant, []policy.PolicyLevel{{Documents: []policy.Policy{{Document: fullRCP}, {Document: resourceDeny}}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &resourceControls{levels: tc.controls}
			e := authorization.New(nil, source)
			err := e.Authorize(ctx, authorization.Request{Action: "sqs:SendMessage", ResourceARN: target, ResourcePolicies: []authorization.BoundPolicy{{Document: tc.resource}}})
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%t: %v", tc.allowed, err)
			}
			if source.owner != "222222222222" {
				t.Fatalf("resource controls used account %q", source.owner)
			}
		})
	}
}

func TestServiceAliasConditionsUseVerifiedIdentity(t *testing.T) {
	const canonical = "logs.amazonaws.com"
	const regional = "logs.us-east-1.amazonaws.com"
	const source = "arn:aws:logs:us-east-1:" + account + ":log-group:source:*"
	const target = "arn:aws:lambda:us-east-1:" + account + ":function:target"
	const grant = `{"Statement":{"Effect":"Allow","Principal":{"Service":"` + regional + `"},"Action":"lambda:InvokeFunction","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalServiceName":"` + canonical + `","aws:SourceAccount":"` + account + `"},"ArnEquals":{"aws:SourceArn":"` + source + `"},"ForAnyValue:StringEquals":{"aws:PrincipalServiceNamesList":"` + regional + `"}}}}`
	aliases := []string{regional}
	ctx := awsctx.WithServicePrincipal(awsctx.WithMetadata(t.Context(), metadata(false)), awsctx.ServicePrincipal{
		Name: canonical, Aliases: aliases, SourceARN: source, Type: "AWSService"})
	// Callers cannot mutate a previously authenticated identity through either
	// the supplied slice or a retrieved metadata snapshot.
	aliases[0] = "logs.us-west-2.amazonaws.com"
	awsctx.FromContext(ctx).ServicePrincipal.Aliases[0] = aliases[0]
	e := authorization.New(nil, nil)
	request := authorization.Request{Action: "lambda:InvokeFunction", ResourceARN: target, ResourcePolicies: []authorization.BoundPolicy{{Document: grant}}}
	if err := e.Authorize(ctx, request); err != nil {
		t.Fatalf("verified regional identity with canonical scalar condition denied: %v", err)
	}
	request.Context = map[string][]string{"aws:PrincipalServiceNamesList": {canonical, aliases[0]}}
	if err := e.Authorize(ctx, request); err == nil {
		t.Fatal("service consumer overrode verified service identities")
	}
	request.Context = nil
	request.ResourcePolicies = append(request.ResourcePolicies, authorization.BoundPolicy{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:PrincipalServiceNamesList":"` + canonical + `"}}}}`})
	if err := e.Authorize(ctx, request); err == nil {
		t.Fatal("canonical service-name condition denial was bypassed by regional grant")
	}
	request.ResourcePolicies = []authorization.BoundPolicy{{Document: `{"Statement":{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction","Resource":"*"}}`}}
	request.Context = map[string][]string{"aws:PrincipalServiceNamesList": {canonical, regional}}
	if err := e.Authorize(awsctx.WithMetadata(t.Context(), metadata(true)), request); err == nil {
		t.Fatal("IAM principal manufactured service identities")
	}
}
