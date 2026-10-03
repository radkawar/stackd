package stackd_test

import (
	"cmp"
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	xraytypes "github.com/aws/aws-sdk-go-v2/service/xray/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

// These captures include account-wide discovery, asynchronous projections and
// one-off AWS backend failures. Only owned resources are replayed; allocation
// values and publication latency are not deterministic AWS contracts.
func TestXRayNativeSamplingControl(t *testing.T) {
	var fixture xrayNativeStream
	awsReadFixture(t, "xray/sampling.json", &fixture)
	rows := append(slices.Clone(fixture.Observations), fixture.Cleanup...)
	slices.SortStableFunc(rows, func(a, b xrayNativeObservation) int { return cmp.Compare(a.Started, b.Started) })
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			first := fixture.Observations[0]
			source := clock.NewManual(time.UnixMilli(first.Started).UTC())
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: first.Account, Clock: source})
			_, user, _ := strings.Cut(first.ActorARN, ":user/")
			arn, key, secret := clients.user(t, first.Account, user)
			putUserPolicy(t, clients.iam(first.Account, "test", ""), user, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
			identities := map[string]aws.Credentials{arn: {AccessKeyID: key, SecretAccessKey: secret}}
			for _, row := range rows {
				if row.Service != "xray" && row.Service != "iam" && row.Service != "sts" || row.Operation == "get-caller-identity" {
					continue // Audit resources belong to the separate audit replay.
				}
				switch row.Label {
				case "assume-owned-role-0", "assume-owned-role-1":
					continue // Same trust policy succeeds at assume-owned-role-2.
				case "rule-update-refresh-poll-0", "rule-update-refresh-poll-1", "targets-after-delete-immediate":
					continue // Captured targets still contain the prior rule version.
				}
				if strings.HasPrefix(row.Label, "targets-after-cleanup-") {
					continue // Even the final native poll returns deleted, cached rules.
				}
				if !t.Run(row.Label, func(t *testing.T) {
					when := time.UnixMilli(row.Started).UTC()
					if when.After(source.Now()) {
						advanceClock(t, source, when.Sub(source.Now()))
					}
					// Retain rules/tags and IAM sessions across the authorization and
					// delete/recreate phases, not merely a final list operation.
					if row.Label == "iam-resource-tag-allowed" || row.Label == "recreate-a-same-name" {
						clients = reopen()
					}
					identity, ok := identities[row.ActorARN]
					if !ok {
						t.Fatalf("unreplayed actor %s", row.ActorARN)
					}
					if row.Service == "xray" {
						_, got := xraySamplingCall(t, clients.xrayRegion(fixture.Region, identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken), row.awsNativeObservation)
						if row.Result.Code != "Success" {
							return
						}
						want := row.Result.Output
						if row.RawResponse != "" {
							want = json.RawMessage(row.RawResponse)
						}
						actual := xraySamplingReply(t, got, fixture.Prefix)
						expected := xraySamplingReply(t, want, fixture.Prefix)
						if !reflect.DeepEqual(actual, expected) {
							t.Fatalf("native sampling response differs\nnative: %v\nlocal: %v", expected, actual)
						}
						return
					}
					var client any = clients.iam(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
					if row.Service == "sts" {
						client = clients.sts(identity.AccessKeyID, identity.SecretAccessKey, identity.SessionToken)
					}
					out, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
					awsNativeResult(t, row.awsNativeObservation, err)
					if session, ok := out.(*sts.AssumeRoleOutput); ok && err == nil {
						identities[aws.ToString(session.AssumedRoleUser.Arn)] = aws.Credentials{AccessKeyID: aws.ToString(session.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(session.Credentials.SecretAccessKey), SessionToken: aws.ToString(session.Credentials.SessionToken)}
					}
				}) {
					return
				}
			}
		})
	}
}

// Keep the SDK consumer and HTTP deserializer while sending native invalid or
// omitted required fields that the SDK would otherwise reject before transport.
func xraySamplingCall(t *testing.T, client *xray.Client, row awsNativeObservation) (any, []byte) {
	t.Helper()
	options := client.Options()
	wire := &awstest.WireClient{Client: options.HTTPClient}
	options.HTTPClient = wire
	options.APIOptions = append(options.APIOptions, awstest.JSONBody(row.Input))
	input := json.RawMessage(`{"SamplingRule":{"Priority":1,"FixedRate":0,"ReservoirSize":0,"Host":"*","HTTPMethod":"*","ResourceARN":"*","ServiceName":"*","ServiceType":"*","URLPath":"*","Version":1},"SamplingRuleUpdate":{},"SamplingStatisticsDocuments":[],"ResourceARN":"request","Tags":[],"TagKeys":[]}`)
	out, err := awstest.CallSDK(t.Context(), xray.New(options), row.Operation, input)
	awsNativeResult(t, row, err)
	if err == nil && wire.Status != row.Result.HTTPStatus {
		t.Fatalf("HTTP status: got %d, native %d", wire.Status, row.Result.HTTPStatus)
	}
	return out, wire.Body
}

func xraySamplingReply(t *testing.T, raw []byte, prefix string) map[string]any {
	t.Helper()
	out := xrayNativeReply(t, raw, prefix)
	normalizeRecord := func(raw any) {
		record := raw.(map[string]any)
		delete(record, "CreatedAt")
		delete(record, "ModifiedAt")
	}
	if record, ok := out["SamplingRuleRecord"].(map[string]any); ok {
		normalizeRecord(record)
	}
	if records, ok := out["SamplingRuleRecords"].([]any); ok {
		records = slices.DeleteFunc(records, func(raw any) bool {
			name := raw.(map[string]any)["SamplingRule"].(map[string]any)["RuleName"].(string)
			return name != "Default" && !strings.HasPrefix(name, prefix)
		})
		for _, record := range records {
			normalizeRecord(record)
		}
		slices.SortFunc(records, func(a, b any) int {
			return strings.Compare(a.(map[string]any)["SamplingRule"].(map[string]any)["RuleName"].(string), b.(map[string]any)["SamplingRule"].(map[string]any)["RuleName"].(string))
		})
		out["SamplingRuleRecords"] = records
	}
	if tags, ok := out["Tags"].([]any); ok {
		xraySortReply(tags, "Key")
	}
	delete(out, "LastRuleModification") // Native target caches lag management reads.
	if targets, ok := out["SamplingTargetDocuments"].([]any); ok {
		for _, raw := range targets {
			target := raw.(map[string]any)
			// The retained-state tests below assert legal allocation and lease
			// transitions; AWS's stochastic quota and adaptive rate are not copied.
			delete(target, "Interval")
			delete(target, "ReservoirQuota")
			delete(target, "ReservoirQuotaTTL")
			delete(target, "SamplingBoost")
		}
		xraySortReply(targets, "RuleName")
	}
	if summaries, ok := out["SamplingStatisticSummaries"].([]any); ok {
		summaries = slices.DeleteFunc(summaries, func(raw any) bool { return !strings.HasPrefix(raw.(map[string]any)["RuleName"].(string), prefix) })
		for _, raw := range summaries {
			value := raw.(map[string]any)
			// Native polls cross asynchronous windows. Counts are proved from
			// the captured report at controlled boundaries below, not erased there.
			delete(value, "Timestamp")
			delete(value, "RequestCount")
			delete(value, "SampledCount")
			delete(value, "BorrowCount")
		}
		xraySortReply(summaries, "RuleName")
		out["SamplingStatisticSummaries"] = summaries
	}
	return out
}

type xraySamplingEdge struct {
	Label, Path, Code string
	Input, Output     json.RawMessage
	Started           float64
	Status            int
}

func (r xraySamplingEdge) native() awsNativeObservation {
	row := awsNativeObservation{Label: r.Label, Service: "xray", Operation: r.Path, Input: r.Input, Started: int64(r.Started * 1000)}
	if row.Operation == "SamplingTargets" {
		row.Operation = "GetSamplingTargets"
	}
	row.Result.Code, row.Result.HTTPStatus, row.Result.Output = r.Code, r.Status, r.Output
	return row
}

type xraySamplingEdges struct {
	Prefix, Region        string
	Identity              struct{ Account string }
	Observations, Cleanup []xraySamplingEdge
	Additional            struct {
		Prefix                string
		Observations, Cleanup []xraySamplingEdge
	} `json:"additional_capture"`
	Metrics []struct {
		Operation     string
		Input, Output json.RawMessage
	} `json:"cloudwatch_observations"`
}

func TestXRayNativeAdaptiveSampling(t *testing.T) {
	var fixture xraySamplingEdges
	awsReadFixture(t, "xray/sampling_edges.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.UnixMilli(int64(fixture.Observations[0].Started * 1000)).UTC())
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Identity.Account, Clock: source})
			rows := append(slices.Clone(fixture.Observations), fixture.Cleanup...)
			rows = append(rows, fixture.Additional.Observations...)
			rows = append(rows, fixture.Additional.Cleanup...)
			var effective []float64
			for _, edge := range rows {
				if edge.Code == "InternalFailure" {
					continue
				} // Observed zero/empty-cooldown backend discrepancy, not an API contract.
				if !t.Run(edge.Label, func(t *testing.T) {
					when := time.UnixMilli(int64(edge.Started * 1000)).UTC().Add(time.Millisecond)
					if when.After(source.Now()) {
						advanceClock(t, source, when.Sub(source.Now()))
					}
					if edge.Label == "boost-report-3" {
						clients = reopen()
					}
					out, raw := xraySamplingCall(t, clients.xrayRegion(fixture.Region, fixture.Identity.Account, "test", ""), edge.native())
					got, want := xraySamplingReply(t, raw, fixture.Prefix), xraySamplingReply(t, edge.Output, fixture.Prefix)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("native edge differs\nnative: %v\nlocal: %v", want, got)
					}
					if targets, ok := out.(*xray.GetSamplingTargetsOutput); ok {
						for _, target := range targets.SamplingTargetDocuments {
							rate := target.FixedRate
							if target.SamplingBoost != nil {
								rate = target.SamplingBoost.BoostRate
							}
							if rate < target.FixedRate || rate > .5 {
								t.Fatalf("adaptive rate outside configured bounds: %+v", target)
							}
							effective = append(effective, rate)
						}
					}
				}) {
					return
				}
			}
			clients = reopen()
			options := metricsClient(clients, fixture.Identity.Account).Options()
			options.Region = fixture.Region
			metrics := cloudwatch.New(options)
			for _, row := range fixture.Metrics {
				out, err := awstest.CallSDK(t.Context(), metrics, row.Operation, row.Input)
				if err != nil {
					t.Fatal(err)
				}
				switch got := out.(type) {
				case *cloudwatch.ListMetricsOutput:
					var want cloudwatch.ListMetricsOutput
					awsDecodeJSON(t, row.Output, &want)
					if len(got.Metrics) != len(want.Metrics) || len(want.Metrics) != 0 && !reflect.DeepEqual(got.Metrics, want.Metrics) {
						t.Fatalf("SamplingRate namespace/dimensions: got %v, native %v", got.Metrics, want.Metrics)
					}
				case *cloudwatch.GetMetricStatisticsOutput:
					var want cloudwatch.GetMetricStatisticsOutput
					awsDecodeJSON(t, row.Output, &want)
					if len(want.Datapoints) == 0 {
						if len(got.Datapoints) != 0 {
							t.Fatalf("configuration-only rule emitted SamplingRate: %v", got.Datapoints)
						}
						continue
					}
					native, nativeUnit := ebMetricStatistics(t, want.Datapoints)
					actual, unit := ebMetricStatistics(t, got.Datapoints)
					var sum float64
					for _, rate := range effective {
						sum += rate
					}
					if unit != nativeUnit || unit != cwtypes.StandardUnitNone || actual[1] != native[1] || actual[1] != float64(len(effective)) || math.Abs(actual[0]-sum) > 1e-9 || actual[2] != slices.Min(effective) || actual[3] != slices.Max(effective) || math.Abs(actual[4]-sum/float64(len(effective))) > 1e-9 {
						t.Fatalf("SamplingRate must contain one effective-rate sample per successful target: statistics=%v unit=%s targets=%v native=%v", actual, unit, effective, native)
					}
					if actual[3] <= actual[2] {
						t.Fatal("native anomaly flow never raised effective sampling above baseline")
					}
				}
			}
		})
	}
}

func TestXRaySamplingRetainedConsumerTransitions(t *testing.T) {
	var fixture xrayNativeStream
	awsReadFixture(t, "xray/sampling.json", &fixture)
	native := make(map[string]xrayNativeObservation)
	for _, row := range fixture.Observations {
		native[row.Label] = row
	}
	var plan struct {
		Create, Report string
		Replacement    string `json:"replacement_report"`
		Cases          []struct {
			Name  string
			Steps []struct {
				At                                       int
				Restart, Initial, Replacement, Duplicate bool
				Clients                                  []string
				Timestamp                                *int
				QuotaTotal                               *int32 `json:"quota_total"`
				Summary                                  []int32
			}
		}
	}
	awsReadFixture(t, "xray/sampling_transitions.json", &plan)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range plan.Cases {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				epoch := time.UnixMilli(native[plan.Create].Started).UTC().Truncate(10 * time.Second)
				source := clock.NewManual(epoch)
				account := fixture.Observations[0].Account
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: source})
				client := clients.xrayRegion(fixture.Region, account, "test", "")
				var create xray.CreateSamplingRuleInput
				if err := awstest.DecodeSDK(native[plan.Create].Input, &create); err != nil {
					t.Fatal(err)
				}
				created, err := client.CreateSamplingRule(t.Context(), &create)
				if err != nil {
					t.Fatal(err)
				}
				rule := created.SamplingRuleRecord.SamplingRule
				// An SDK consumer must discover the matching rule before reporting;
				// the fixture's matching attributes, not a synthetic rule, are used.
				discovered, err := client.GetSamplingRules(t.Context(), &xray.GetSamplingRulesInput{NextToken: aws.String("ignored-native-token")})
				if err != nil || len(discovered.SamplingRuleRecords) != 2 || discovered.NextToken != nil {
					t.Fatalf("consumer discovery: %v %v", discovered, err)
				}
				report := xraySamplingReportTemplate(t, native[plan.Report].Input)
				replacement := xraySamplingReportTemplate(t, native[plan.Replacement].Input)
				leases := make(map[string]xraytypes.SamplingTargetDocument)
				for _, step := range scenario.Steps {
					advanceClock(t, source, epoch.Add(time.Duration(step.At)*time.Second).Sub(source.Now()))
					if step.Restart {
						clients = reopen()
						client = clients.xrayRegion(fixture.Region, account, "test", "")
					}
					if step.Summary != nil {
						out, err := client.GetSamplingStatisticSummaries(t.Context(), &xray.GetSamplingStatisticSummariesInput{})
						if err != nil {
							t.Fatal(err)
						}
						if len(out.SamplingStatisticSummaries) != 1 {
							t.Fatalf("owned summary at %d: %v", step.At, out.SamplingStatisticSummaries)
						}
						summary := out.SamplingStatisticSummaries[0]
						got := []int32{summary.RequestCount, summary.SampledCount, summary.BorrowCount}
						if !slices.Equal(got, step.Summary) || aws.ToString(summary.RuleName) != aws.ToString(rule.RuleName) || summary.Timestamp == nil || !summary.Timestamp.Equal(source.Now().Truncate(10*time.Second).Add(-10*time.Second)) {
							t.Fatalf("closed-window summary at %d: got %+v, counts %v; want %v", step.At, summary, got, step.Summary)
						}
						continue
					}
					input := &xray.GetSamplingTargetsInput{SamplingStatisticsDocuments: []xraytypes.SamplingStatisticsDocument{}}
					for _, id := range step.Clients {
						document := report.SamplingStatisticsDocuments[0]
						if step.Replacement {
							document = replacement.SamplingStatisticsDocuments[0]
						}
						document.RuleName = rule.RuleName
						document.ClientID = aws.String(strings.Repeat(id, 24))
						document.Timestamp = aws.Time(source.Now())
						if step.Timestamp != nil {
							document.Timestamp = aws.Time(epoch.Add(time.Duration(*step.Timestamp) * time.Second))
						}
						input.SamplingStatisticsDocuments = append(input.SamplingStatisticsDocuments, document)
					}
					out, err := client.GetSamplingTargets(t.Context(), input)
					if err != nil || len(out.UnprocessedStatistics) != 0 || len(out.SamplingTargetDocuments) != len(step.Clients) {
						t.Fatalf("report at %d: %+v %v", step.At, out, err)
					}
					var granted int32
					for i, target := range out.SamplingTargetDocuments {
						if aws.ToString(target.RuleName) != aws.ToString(rule.RuleName) || target.FixedRate != rule.FixedRate {
							t.Fatalf("wrong rule target: %+v", target)
						}
						if step.Initial && (target.ReservoirQuota != nil || target.ReservoirQuotaTTL != nil || target.Interval != nil) {
							t.Fatalf("initial borrowing window has a quota: %+v", target)
						}
						if target.ReservoirQuota != nil {
							if *target.ReservoirQuota < 0 || *target.ReservoirQuota > rule.ReservoirSize || aws.ToInt32(target.Interval) != 10 || target.ReservoirQuotaTTL == nil || !target.ReservoirQuotaTTL.Equal(source.Now().Add(5*time.Minute)) {
								t.Fatalf("illegal lease at %d: %+v", step.At, target)
							}
							granted += *target.ReservoirQuota
						}
						leases[step.Clients[i]] = target
					}
					if step.Duplicate && !reflect.DeepEqual(out.SamplingTargetDocuments[0], out.SamplingTargetDocuments[1]) {
						t.Fatal("duplicate client received conflicting replacement leases")
					}
					if step.QuotaTotal != nil && granted != *step.QuotaTotal {
						t.Fatalf("report allocation at %d: got %d, want %d", step.At, granted, *step.QuotaTotal)
					}
					var outstanding int32
					for _, lease := range leases {
						if lease.ReservoirQuotaTTL != nil && lease.ReservoirQuotaTTL.After(source.Now()) {
							outstanding += aws.ToInt32(lease.ReservoirQuota)
						}
					}
					if outstanding > rule.ReservoirSize {
						t.Fatalf("new/replacement client overspent live reservoir at %d: %d > %d", step.At, outstanding, rule.ReservoirSize)
					}
				}
				// A deterministic ARN may be reused, but no old report or client
				// lease may cross the deletion/recreation boundary, even on disk.
				if _, err := client.DeleteSamplingRule(t.Context(), &xray.DeleteSamplingRuleInput{RuleARN: rule.RuleARN}); err != nil {
					t.Fatal(err)
				}
				clients = reopen()
				client = clients.xrayRegion(fixture.Region, account, "test", "")
				var recreate xray.CreateSamplingRuleInput
				if err := awstest.DecodeSDK(native["recreate-a-same-name"].Input, &recreate); err != nil {
					t.Fatal(err)
				}
				fresh, err := client.CreateSamplingRule(t.Context(), &recreate)
				if err != nil || aws.ToString(fresh.SamplingRuleRecord.SamplingRule.RuleARN) != aws.ToString(rule.RuleARN) {
					t.Fatalf("recreate ARN: %v %v", fresh, err)
				}
				tags, err := client.ListTagsForResource(t.Context(), &xray.ListTagsForResourceInput{ResourceARN: rule.RuleARN})
				if err != nil || len(tags.Tags) != 0 {
					t.Fatalf("recreated tags: %v %v", tags, err)
				}
				document := report.SamplingStatisticsDocuments[0]
				document.RuleName, document.ClientID, document.Timestamp = rule.RuleName, aws.String(strings.Repeat("a", 24)), aws.Time(source.Now())
				target, err := client.GetSamplingTargets(t.Context(), &xray.GetSamplingTargetsInput{SamplingStatisticsDocuments: []xraytypes.SamplingStatisticsDocument{document}})
				if err != nil || len(target.SamplingTargetDocuments) != 1 || target.SamplingTargetDocuments[0].ReservoirQuota != nil || target.SamplingTargetDocuments[0].FixedRate != recreate.SamplingRule.FixedRate {
					t.Fatalf("old lease survived recreation: %v %v", target, err)
				}
				summary, err := client.GetSamplingStatisticSummaries(t.Context(), &xray.GetSamplingStatisticSummariesInput{})
				if err != nil || len(summary.SamplingStatisticSummaries) != 1 || summary.SamplingStatisticSummaries[0].RequestCount != 0 {
					t.Fatalf("old reports survived recreation: %v %v", summary, err)
				}
			})
		}
	}
}

func TestXRaySamplingScopeAndDefault(t *testing.T) {
	var fixture xrayNativeStream
	awsReadFixture(t, "xray/sampling.json", &fixture)
	var create xray.CreateSamplingRuleInput
	for _, row := range fixture.Observations {
		if row.Label == "create-a-attributes-absent" {
			if err := awstest.DecodeSDK(row.Input, &create); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			account := fixture.Observations[0].Account
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			owner := clients.xrayRegion(fixture.Region, account, "test", "")
			created, err := owner.CreateSamplingRule(t.Context(), &create)
			if err != nil {
				t.Fatal(err)
			}
			arn := created.SamplingRuleRecord.SamplingRule.RuleARN
			for _, foreign := range []*xray.Client{clients.xrayRegion("us-east-1", account, "test", ""), clients.xrayRegion(fixture.Region, "111122223333", "test", "")} {
				out, err := foreign.GetSamplingRules(t.Context(), &xray.GetSamplingRulesInput{})
				if err != nil || len(out.SamplingRuleRecords) != 1 || aws.ToString(out.SamplingRuleRecords[0].SamplingRule.RuleName) != "Default" {
					t.Fatalf("foreign discovery leaked rules: %v %v", out, err)
				}
				_, err = foreign.UpdateSamplingRule(t.Context(), &xray.UpdateSamplingRuleInput{SamplingRuleUpdate: &xraytypes.SamplingRuleUpdate{RuleARN: arn, FixedRate: aws.Float64(.9)}})
				assertAPIError(t, err, "InvalidRequestException")
				_, err = foreign.DeleteSamplingRule(t.Context(), &xray.DeleteSamplingRuleInput{RuleARN: arn})
				assertAPIError(t, err, "InvalidRequestException")
				_, err = foreign.CreateSamplingRule(t.Context(), &create)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Default is virtual per scope, mutable only in rate/reservoir.
			_, err = owner.DeleteSamplingRule(t.Context(), &xray.DeleteSamplingRuleInput{RuleName: aws.String("Default")})
			assertAPIError(t, err, "InvalidRequestException")
			_, err = owner.UpdateSamplingRule(t.Context(), &xray.UpdateSamplingRuleInput{SamplingRuleUpdate: &xraytypes.SamplingRuleUpdate{RuleName: aws.String("Default"), FixedRate: aws.Float64(.75), Host: aws.String("invalid")}})
			assertAPIError(t, err, "InvalidRequestException")
			before, err := owner.GetSamplingRules(t.Context(), &xray.GetSamplingRulesInput{})
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range before.SamplingRuleRecords {
				if aws.ToString(record.SamplingRule.RuleName) == "Default" && record.SamplingRule.FixedRate != .05 {
					t.Fatal("invalid default update committed its rate")
				}
			}
			_, err = owner.UpdateSamplingRule(t.Context(), &xray.UpdateSamplingRuleInput{SamplingRuleUpdate: &xraytypes.SamplingRuleUpdate{RuleName: aws.String("Default"), FixedRate: aws.Float64(.75), ReservoirSize: aws.Int32(2)}})
			if err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			owner = clients.xrayRegion(fixture.Region, account, "test", "")
			after, err := owner.GetSamplingRules(t.Context(), &xray.GetSamplingRulesInput{})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, record := range after.SamplingRuleRecords {
				if aws.ToString(record.SamplingRule.RuleName) == "Default" {
					found = true
					if record.SamplingRule.FixedRate != .75 || record.SamplingRule.ReservoirSize != 2 {
						t.Fatalf("default mutation lost on reopen: %+v", record.SamplingRule)
					}
				} else if record.SamplingRule.FixedRate != create.SamplingRule.FixedRate {
					t.Fatal("foreign ARN mutation changed owner rule")
				}
			}
			if !found {
				t.Fatal("mutable Default disappeared after reopen")
			}
		})
	}
}

func TestXRaySamplingBoostCooldownAcrossReopen(t *testing.T) {
	var fixture xraySamplingEdges
	awsReadFixture(t, "xray/sampling_edges.json", &fixture)
	var create xray.CreateSamplingRuleInput
	var anomaly xray.GetSamplingTargetsInput
	for _, row := range fixture.Observations {
		if row.Label == "create-boost" {
			if err := awstest.DecodeSDK(row.Input, &create); err != nil {
				t.Fatal(err)
			}
		}
		if row.Label == "boost-report-1" {
			anomaly = xraySamplingReportTemplate(t, row.Input)
		}
	}
	// A longer configured cooldown separates boost expiry from eligibility for a
	// new activation. This is a local durability boundary, not an AWS timing claim.
	create.SamplingRule.SamplingRateBoost.CooldownWindowMinutes = 2
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			epoch := time.UnixMilli(int64(fixture.Observations[0].Started * 1000)).UTC().Truncate(10 * time.Second)
			source := clock.NewManual(epoch)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Identity.Account, Clock: source})
			client := clients.xrayRegion(fixture.Region, fixture.Identity.Account, "test", "")
			if _, err := client.CreateSamplingRule(t.Context(), &create); err != nil {
				t.Fatal(err)
			}
			for _, step := range []struct {
				at         int
				restart    bool
				boostUntil int
			}{
				{0, false, 0}, {10, false, 70}, {20, true, 70},
				{69, false, 70}, {70, true, 0}, {80, true, 0},
				{120, false, 0}, {130, true, 190},
			} {
				advanceClock(t, source, epoch.Add(time.Duration(step.at)*time.Second).Sub(source.Now()))
				if step.restart {
					clients = reopen()
					client = clients.xrayRegion(fixture.Region, fixture.Identity.Account, "test", "")
				}
				input := anomaly
				input.SamplingStatisticsDocuments = slices.Clone(anomaly.SamplingStatisticsDocuments)
				input.SamplingBoostStatisticsDocuments = slices.Clone(anomaly.SamplingBoostStatisticsDocuments)
				input.SamplingStatisticsDocuments[0].Timestamp = aws.Time(source.Now())
				input.SamplingBoostStatisticsDocuments[0].Timestamp = aws.Time(source.Now())
				out, err := client.GetSamplingTargets(t.Context(), &input)
				if err != nil || len(out.SamplingTargetDocuments) != 1 {
					t.Fatalf("anomaly report at %d: %v %v", step.at, out, err)
				}
				target := out.SamplingTargetDocuments[0]
				if step.boostUntil == 0 {
					if target.SamplingBoost != nil {
						t.Fatalf("boost activated during initial window/cooldown at %d: %+v", step.at, target.SamplingBoost)
					}
					continue
				}
				boost := target.SamplingBoost
				if boost == nil || boost.BoostRate <= target.FixedRate || boost.BoostRate > create.SamplingRule.SamplingRateBoost.MaxRate || boost.BoostRateTTL == nil || !boost.BoostRateTTL.Equal(epoch.Add(time.Duration(step.boostUntil)*time.Second)) {
					t.Fatalf("boost lost bounds or changed activation expiry at %d: %+v", step.at, boost)
				}
			}
		})
	}
}

// Local transition cases replace native Unix timestamps with service-clock
// instants. Strip only those fields before decoding into the SDK's time.Time.
func xraySamplingReportTemplate(t *testing.T, raw json.RawMessage) xray.GetSamplingTargetsInput {
	t.Helper()
	var input map[string]any
	awsDecodeJSON(t, raw, &input)
	for _, name := range []string{"SamplingStatisticsDocuments", "SamplingBoostStatisticsDocuments"} {
		if documents, ok := input[name].([]any); ok {
			for _, document := range documents {
				delete(document.(map[string]any), "Timestamp")
			}
		}
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var out xray.GetSamplingTargetsInput
	awsDecodeJSON(t, encoded, &out)
	return out
}
