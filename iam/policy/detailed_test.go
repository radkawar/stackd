package policy_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"

	"stackd/iam/policy"
)

func TestDetailedEvaluationKeepsEveryMatch(t *testing.T) {
	document := mustParse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"},{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*"}]}`)
	result, err := policy.EvaluateDetailed([]*policy.Document{document, document}, policy.Request{Action: "s3:GetObject", Resource: "*"})
	if err != nil || result.Decision != policy.ExplicitDeny || len(result.MatchedStatements) != 8 {
		t.Fatalf("detailed evaluation = %+v, %v", result, err)
	}
	for i, match := range result.MatchedStatements {
		if match.DocumentIndex != i/4 || match.StatementIndex != i%4 || match.Start.Line != 1 || match.End.Column <= match.Start.Column {
			t.Errorf("match[%d] = %+v", i, match)
		}
	}
}

func TestDetailedEvaluationAgreement(t *testing.T) {
	allow := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	deny := mustParse(t, `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`)
	wrongKind, err := policy.ParseResource([]byte(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{
		`{"StringEquals":{"test:key":"yes"}}`,
		`{"StringNotEquals":{"test:key":"yes"}}`,
		`{"StringLikeIfExists":{"test:key":"y*"}}`,
		`{"StringNotLikeIfExists":{"test:key":"y*"}}`,
		`{"Null":{"test:key":"false"}}`,
		`{"Null":{"test:key":"true"}}`,
		`{"ForAllValues:StringEquals":{"test:key":["yes","2"]}}`,
		`{"ForAnyValue:StringNotEquals":{"test:key":["yes","2"]}}`,
		`{"ForAnyValue:StringEqualsIfExists":{"test:key":"yes"}}`,
		`{"NumericGreaterThan":{"test:key":"1"}}`,
		`{"DateLessThan":{"test:key":"2035-01-01T00:00:00Z"}}`,
		`{"Bool":{"test:key":"true"}}`,
		`{"BinaryEquals":{"test:key":"eWVz"}}`,
		`{"IpAddress":{"test:key":"192.0.2.0/24"}}`,
		`{"ArnLike":{"test:key":"arn:aws:iam::*:user/*"}}`,
		`{"StringEquals":{"test:key":"${test:variable}"}}`,
		`{"StringEquals":{"test:key":"${test:variable, 'yes'}"}}`,
		`{"StringEquals":{"a:shortcircuit":"no"},"NumericEquals":{"test:key":"1"}}`,
	} {
		document := mustParse(t, fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":%s}}`, condition))
		for _, values := range [][]string{nil, {}, {""}, {"yes"}, {"true"}, {"2"}, {"192.0.2.1"}, {"2030-01-01T00:00:00Z"}, {"yes", "2"}} {
			request := policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"TEST:KEY": values}}
			for _, documents := range [][]*policy.Document{{document}, {allow, document}, {document, allow}, {deny, document}, {document, deny}, {nil}, {wrongKind}, {{}}, {deny, nil, document}, {document, nil, deny}} {
				assertDetailedAgreement(t, documents, request)
			}
		}
	}
	for _, request := range []policy.Request{{}, {Action: "s3:*", Resource: "*"}, {Action: "s3:GetObject", Resource: "broken"}, {Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"Test:Key": {"yes"}, "test:key": {"no"}}}} {
		assertDetailedAgreement(t, []*policy.Document{allow}, request)
	}
}

func assertDetailedAgreement(t *testing.T, documents []*policy.Document, request policy.Request) {
	t.Helper()
	want, wantErr := policy.Evaluate(documents, request)
	got, err := policy.EvaluateDetailed(documents, request)
	if got.Decision != want || (err == nil) != (wantErr == nil) {
		t.Fatalf("detailed = %+v, %v; ordinary = %s, %v; request = %+v", got, err, want, wantErr, request)
	}
	for _, sentinel := range []error{policy.ErrInvalidPolicy, policy.ErrInvalidRequest, policy.ErrUnsupported} {
		if errors.Is(err, sentinel) != errors.Is(wantErr, sentinel) {
			t.Fatalf("detailed error %v differs from ordinary error %v", err, wantErr)
		}
	}
}

func TestDetailedResourcePrincipalDecisions(t *testing.T) {
	principal := policy.Principal{ARN: "arn:aws:sts::123456789012:assumed-role/worker/run", AccountID: "123456789012", Partition: "aws", IssuerARN: "arn:aws:iam::123456789012:role/worker"}
	for _, raw := range []string{
		`{"Statement":{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/worker"},"Action":"*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:sts::123456789012:assumed-role/worker/run"},"Action":"*","Resource":"*"}}`,
		`{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::123456789012:role/worker"},"Action":"*","Resource":"*"},{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"},{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":{"NumericEquals":{"test:key":"1"}}}]}`,
	} {
		document, err := policy.ParseResource([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		for _, boundary := range []bool{false, true} {
			principal.HasBoundary = boundary
			request := policy.Request{Action: "s3:GetObject", Resource: "*", Context: map[string][]string{"test:key": {"bad-number"}}}
			want, wantErr := policy.EvaluateResource(document, request, principal)
			got, err := policy.EvaluateResourceDetailed(document, request, principal)
			if got.ResourceDecision != want || (err == nil) != (wantErr == nil) {
				t.Fatalf("resource detailed = %+v, %v; ordinary = %+v, %v", got, err, want, wantErr)
			}
		}
	}
}

func TestDetailedPolicyAndResultsAreDetached(t *testing.T) {
	data := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/${test:resource}","Condition":{"StringEquals":{"test:condition":"${test:value}"}}}]}`)
	document, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	request := policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::example/file"}
	first, err := policy.EvaluateDetailed([]*policy.Document{document}, request)
	if err != nil || !slices.Equal(first.MissingContextValues, []string{"test:condition", "test:resource", "test:value"}) {
		t.Fatalf("missing = %+v, %v", first, err)
	}
	first.MissingContextValues[0] = "mutated"
	request.Context = map[string][]string{"test:resource": {"file"}, "test:condition": {"yes"}, "test:value": {"yes"}}
	want, err := policy.EvaluateDetailed([]*policy.Document{document}, request)
	if err != nil || want.Decision != policy.Allow || len(want.MatchedStatements) != 1 {
		t.Fatalf("matching = %+v, %v", want, err)
	}
	firstMatch := want.MatchedStatements[0]
	want.MatchedStatements[0].Start.Line = 99
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			for range 20 {
				got, err := policy.EvaluateDetailed([]*policy.Document{document}, request)
				if err != nil || len(got.MatchedStatements) != 1 || got.MatchedStatements[0] != firstMatch || len(got.MissingContextValues) != 0 {
					t.Errorf("concurrent evaluation = %+v, %v", got, err)
					return
				}
			}
		})
	}
	group.Wait()
}

func TestDetailedMissingContextDistinguishesEmptyStringAndDefaults(t *testing.T) {
	document := mustParse(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/${test:resource, 'default'}","Condition":{"StringEquals":{"test:key":"${test:value, 'fallback'}"}}}}`)
	for _, values := range [][]string{nil, {""}} {
		request := policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::other/file", Context: map[string][]string{"TEST:KEY": values}}
		got, err := policy.EvaluateDetailed([]*policy.Document{document}, request)
		want := []string{"test:resource", "test:value"}
		if len(values) == 0 {
			want = []string{"test:key", "test:resource", "test:value"}
		}
		if err != nil || got.Decision != policy.ImplicitDeny || !slices.Equal(got.MissingContextValues, want) {
			t.Fatalf("values %q: %+v, %v; want missing %q", values, got, err, want)
		}
	}
}

func TestSimulationActionValidationDoesNotWeakenAuthorization(t *testing.T) {
	allow := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	concrete := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	for _, action := range []string{"s3:*", "s3:", "s3:Get Object"} {
		request := policy.Request{Action: action, Resource: "*"}
		for _, document := range []*policy.Document{allow, concrete} {
			if got, err := policy.EvaluateDetailed([]*policy.Document{document}, request); !errors.Is(err, policy.ErrInvalidRequest) || got.Decision != policy.ImplicitDeny {
				t.Fatalf("authorization accepted %q: %+v, %v", action, got, err)
			}
			got, err := policy.EvaluateSimulationDetailed([]*policy.Document{document}, request)
			want := policy.ImplicitDeny
			if document == allow {
				want = policy.Allow
			}
			if err != nil || got.Decision != want {
				t.Fatalf("simulation %q = %+v, %v; want %s", action, got, err, want)
			}
		}
	}
}

func FuzzDetailedEvaluationAgreement(f *testing.F) {
	f.Add(`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`, "")
	f.Add(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::example/${test:key}"}}`, "file")
	f.Add(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericEquals":{"test:key":"1"}}}}`, "not-a-number")
	f.Fuzz(func(t *testing.T, input, value string) {
		document, err := policy.Parse([]byte(input))
		if err != nil {
			return
		}
		request := policy.Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::example/file", Context: map[string][]string{"test:key": {value}}}
		assertDetailedAgreement(t, []*policy.Document{document}, request)
		before, _ := json.Marshal(request)
		_, _ = policy.EvaluateDetailed([]*policy.Document{document}, request)
		after, _ := json.Marshal(request)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("evaluation mutated request")
		}
	})
}
