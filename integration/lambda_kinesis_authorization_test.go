package stackd_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go"
)

// AWS checks a different source permission set for stream and consumer ARNs.
// Replay each captured policy mutation before its two admission observations;
// an accepted unused-action denial is as important as a rejected required one.
func TestLambdaKinesisDockerNativeAuthorization(t *testing.T) {
	lambdaURLDocker(t)
	fixture := lambdaFixture[lambdaKinesisFixture](t, "kinesis_source")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.StartedAt)
			clients, _ := lambdaKinesisCloud(t, backend, source)
			replace, _ := lambdaKinesisNativeSetup(t, fixture, clients, source)
			observed := 0
			for _, row := range fixture.Observations {
				if row.Label == "policy_owned-source" {
					lambdaKinesisCall(t, clients, row, replace)
				}
				if row.Operation != "create-event-source-mapping" || !strings.HasPrefix(row.Label, "deny_") {
					continue
				}
				observed++
				if !t.Run(row.Label, func(t *testing.T) {
					input := lambdaStreamingInput[awslambda.CreateEventSourceMappingInput](t, row.Input, replace)
					out, err := lambdaDynamoDBClient(clients).CreateEventSourceMapping(t.Context(), &input)
					if row.Result.Code != "Success" {
						assertAPIError(t, err, row.Result.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					id := aws.ToString(out.UUID)
					lambdaKinesisMappingState(t, clients, source, id, "Disabled")
					lambdaKinesisDeleteMapping(t, clients, source, id)
				}) {
					return
				}
			}
			if observed == 0 {
				t.Fatal("native capture has no permission-denial matrix")
			}
		})
	}
}

// Admission is not an enduring authorization grant. A role denied after an
// enabled poller exists must retain its unread record, including across reopen,
// and deliver it through the ordinary runtime once the deny is removed.
func TestLambdaKinesisDockerRuntimeAuthorizationRecovery(t *testing.T) {
	lambdaURLDocker(t)
	fixture := lambdaFixture[lambdaKinesisFixture](t, "kinesis_source")
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"stream", "consumer"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				source := clock.NewManual(fixture.StartedAt)
				clients, reopen := lambdaKinesisCloud(t, backend, source)
				replace, _ := lambdaKinesisNativeSetup(t, fixture, clients, source)
				label, action := "partial_off", "kinesis:GetRecords"
				if kind == "consumer" {
					label, action = "consumer_partial", "kinesis:SubscribeToShard"
				}
				lambdaKinesisCall(t, clients, fixture.row(t, label+"_alias"), replace)
				input := lambdaStreamingInput[awslambda.CreateEventSourceMappingInput](t, fixture.row(t, label+"_create").Input, replace)
				input.Enabled, input.BatchSize, input.MaximumBatchingWindowInSeconds = aws.Bool(true), aws.Int32(1), aws.Int32(0)
				mapping, err := lambdaDynamoDBClient(clients).CreateEventSourceMapping(t.Context(), &input)
				if err != nil {
					t.Fatal(err)
				}
				id := aws.ToString(mapping.UUID)
				lambdaKinesisMappingState(t, clients, source, id, "Enabled")
				role := lambdaStreamingInput[iam.CreateRoleInput](t, fixture.row(t, "create_role").Input, replace)
				policyName := "deny-live-source"
				if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.RoleName, PolicyName: &policyName, PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":%q,"Resource":"*"}}`, action))}); err != nil {
					t.Fatal(err)
				}
				record := lambdaStreamingInput[kinesis.PutRecordInput](t, fixture.row(t, label+"_put_1").Input, replace)
				accepted, err := clients.kinesis("test", "test", "").PutRecord(t.Context(), &record)
				if err != nil {
					t.Fatal(err)
				}
				lambdaKinesisAwaitDenied(t, clients, source, id, action)
				clients = reopen()
				lambdaKinesisAwaitDenied(t, clients, source, id, action)
				if invocations := lambdaDynamoDBLogInvocations(t, clients, fixture.Prefix, "KINESIS_PROBE "); len(invocations) != 0 {
					t.Fatalf("runtime executed a source record while its role was denied: %+v", invocations)
				}
				if _, err := clients.iam("test", "test", "").DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: role.RoleName, PolicyName: &policyName}); err != nil {
					t.Fatal(err)
				}
				invocations := lambdaKinesisInvocations(t, clients, source, fixture.Prefix, "KINESIS_PROBE ", 1)
				if len(invocations) != 1 || len(invocations[0].Event["Records"].([]any)) != 1 {
					t.Fatalf("restored poller lost or repeated its retained record: %+v", invocations)
				}
				delivered := invocations[0].Event["Records"].([]any)[0].(map[string]any)
				if delivered["eventSourceARN"] != aws.ToString(input.EventSourceArn) || delivered["eventID"] != aws.ToString(accepted.ShardId)+":"+aws.ToString(accepted.SequenceNumber) || delivered["kinesis"].(map[string]any)["sequenceNumber"] != aws.ToString(accepted.SequenceNumber) {
					t.Fatalf("restored poller delivered a different record: %+v", delivered)
				}
			})
		}
	}
}

func lambdaKinesisAwaitDenied(t *testing.T, clients cloudClients, source *clock.Manual, id, action string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		advanceClock(t, source, 250*time.Millisecond)
		out, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
		if err != nil {
			t.Fatal(err)
		}
		status = aws.ToString(out.LastProcessingResult)
		if strings.HasPrefix(status, "PROBLEM:") && strings.Contains(status, action) {
			if aws.ToString(out.State) != "Enabled" {
				t.Fatalf("runtime denial disabled the mapping instead of retaining its work: %+v", out)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("poller did not report rejected %s: %s", action, status)
}

func lambdaKinesisDeleteMapping(t *testing.T, clients cloudClients, source *clock.Manual, id string) {
	t.Helper()
	if _, err := lambdaDynamoDBClient(clients).DeleteEventSourceMapping(t.Context(), &awslambda.DeleteEventSourceMappingInput{UUID: &id}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		advanceClock(t, source, 250*time.Millisecond)
		_, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
		var api smithy.APIError
		if errors.As(err, &api) && api.ErrorCode() == "ResourceNotFoundException" {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("deleted mapping retained its source identity")
}
