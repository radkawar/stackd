package stackd_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd"
	"stackd/clock"
	"stackd/journal"
)

func TestCloudFormationAuditPrivacyAndAncestry(t *testing.T) {
	var fixture struct {
		Account, Region, Prefix string
		ExportUpdateComplete    bool `json:"export_update_complete"`
		Cleanup                 struct{ Complete bool }
		Calls                   []struct {
			Label     string
			RequestID string `json:"request_id"`
			Input     json.RawMessage
		}
		CloudTrail struct {
			Events []struct {
				Label string `json:"call_label"`
				Event json.RawMessage
			}
		}
		ResourceCloudTrail struct {
			Events []struct{ Event json.RawMessage }
		} `json:"resource_cloudtrail"`
	}
	awsReadFixture(t, "cloudformation/lifecycle.json", &fixture)
	if !fixture.ExportUpdateComplete || !fixture.Cleanup.Complete {
		t.Fatal("native audit fixture requires completed NoEcho capture and exact cleanup")
	}
	inputs := map[string]json.RawMessage{}
	requestIDs := map[string]map[string]bool{}
	for _, row := range fixture.Calls {
		inputs[row.Label] = row.Input
		if requestIDs[row.Label] == nil {
			requestIDs[row.Label] = map[string]bool{}
		}
		requestIDs[row.Label][row.RequestID] = true
	}
	native := map[string]json.RawMessage{}
	for _, row := range fixture.CloudTrail.Events {
		if row.Label == "" {
			continue
		}
		var event map[string]any
		awsDecodeJSON(t, row.Event, &event)
		id, _ := event["requestID"].(string)
		if !requestIDs[row.Label][id] {
			t.Fatal("native audit event is not correlated to its recorded request", row.Label)
		}
		native[row.Label] = row.Event
	}
	var nativeChild map[string]any
	for _, row := range fixture.ResourceCloudTrail.Events {
		var event map[string]any
		awsDecodeJSON(t, row.Event, &event)
		if event["eventSource"] == "sqs.amazonaws.com" && event["eventName"] == "CreateQueue" &&
			awsFixtureField(event, "requestParameters.queueName") == fixture.Prefix+"-q1" {
			nativeChild = event
			break
		}
	}
	if nativeChild == nil {
		t.Fatal("native capture lacks the caller-attributed CloudFormation child CreateQueue")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			var events journal.Storage
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				events = config.Storage.Journal
				return startPublicCloud(t, config)
			})
			actor, access, secret := c.user(t, fixture.Account, "Delegated")
			putUserPolicy(t, c.iam(fixture.Account, "test", ""), "Delegated", allow(`"*"`, "*"))
			user, err := c.iam(fixture.Account, "test", "").GetUser(ctx, &iam.GetUserInput{UserName: aws.String("Delegated")})
			if err != nil {
				t.Fatal(err)
			}
			client := cloudFormationClient(c, fixture.Region, access, secret)
			trails := organizationTrailClient(c, fixture.Account, fixture.Region)
			const secretValue = "private-noecho-value-cfn-audit"
			const plainValue = "private-plain-value-cfn-audit"
			const changedPlain = "private-updated-value-cfn-audit"
			const templateMarker = "private-template-content-cfn-audit"
			const queueName = "cfn-audit-queue"
			const stackName = "cfn-audit"
			template := func(visibility int) string {
				var body map[string]any
				awsDecodeJSON(t, []byte(cloudFormationQueueTemplate(t, queueName, visibility, 0)), &body)
				body["Description"] = templateMarker
				body["Parameters"] = map[string]any{
					"Secret": map[string]any{"Type": "String", "NoEcho": true},
					"Plain":  map[string]any{"Type": "String"},
				}
				encoded, marshalErr := json.Marshal(body)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				return string(encoded)
			}
			request := func(label string) map[string]any {
				var event map[string]any
				awsDecodeJSON(t, native[label], &event)
				value, ok := event["requestParameters"].(map[string]any)
				if !ok {
					t.Fatal("native accepted request lacks projection", label)
				}
				return value
			}
			// Native explicit NoEcho input calibrates the keys-only projection. The
			// ordinary parameter additionally protects the documented privacy
			// boundary: CloudTrail omits parameter values regardless of NoEcho.
			keys := []any{map[string]any{"parameterKey": "Secret"}, map[string]any{"parameterKey": "Plain"}}
			check := func(label string, output any, callErr error, parameters, response any) map[string]any {
				id := nativeAuditRequestID(t, output, callErr)
				var want map[string]any
				awsDecodeJSON(t, native[label], &want)
				want["requestParameters"], want["responseElements"] = parameters, response
				got := auditLookupRecord(t, trails, id, want["eventName"].(string))
				for _, field := range []string{"eventSource", "eventName", "awsRegion", "readOnly", "eventCategory", "managementEvent", "eventType", "recipientAccountId", "resources", "requestParameters", "responseElements", "errorCode"} {
					actual, present := got[field]
					expected, nativePresent := want[field]
					if present != nativePresent || !reflect.DeepEqual(actual, expected) {
						t.Fatalf("%s audit %s differs from native\nwant %#v present %t\ngot %#v present %t", label, field, expected, nativePresent, actual, present)
					}
				}
				for _, field := range []string{"type", "arn", "accountId", "userName"} {
					if awsFixtureField(got, "userIdentity."+field) != awsFixtureField(want, "userIdentity."+field) {
						t.Fatalf("%s changed authenticated audit caller %s", label, field)
					}
				}
				if awsFixtureField(got, "userIdentity.accessKeyId") != access || awsFixtureField(got, "userIdentity.principalId") != aws.ToString(user.User.UserId) {
					t.Fatal("audit did not retain the actual signing key and IAM principal")
				}
				encoded, marshalErr := json.Marshal(got)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				for _, private := range []string{secretValue, plainValue, changedPlain, templateMarker} {
					if strings.Contains(string(encoded), private) {
						t.Fatalf("%s CloudTrail event exposed a template or parameter value", label)
					}
				}
				return got
			}
			var create cloudformation.CreateStackInput
			awsDecodeJSON(t, inputs["create-export-update-producer"], &create)
			create.StackName, create.TemplateBody, create.ClientRequestToken = aws.String(stackName), aws.String(template(10)), aws.String("audit-create")
			create.Parameters = []cfntypes.Parameter{{ParameterKey: aws.String("Secret"), ParameterValue: aws.String(secretValue)}, {ParameterKey: aws.String("Plain"), ParameterValue: aws.String(plainValue)}}
			created, err := client.CreateStack(ctx, &create)
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, client, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			queue := cloudFormationQueueURL(t, stack)
			createRequest := request("create-export-update-producer")
			createRequest["stackName"], createRequest["parameters"] = stackName, keys
			parent := check("create-export-update-producer", created, nil, createRequest, map[string]any{"stackId": aws.ToString(created.StackId)})
			parentRequest := nativeAuditRequestID(t, created, nil)
			childRows, err := events.LookupAPICalls(ctx, journal.APICallQuery{Partition: "aws", AccountID: fixture.Account,
				Region: fixture.Region, End: source.Now(), AttributeKey: "EventName", AttributeValue: "CreateQueue", Limit: 1000})
			if err != nil {
				t.Fatal(err)
			}
			var child *journal.Event
			for _, row := range childRows.Events {
				if row.APICallCompleted == nil {
					continue
				}
				var parameters map[string]any
				awsDecodeJSON(t, row.APICallCompleted.RequestParameters, &parameters)
				if parameters["queueName"] != queueName {
					continue
				}
				if child != nil {
					t.Fatal("deployment produced duplicate CreateQueue audit outcomes")
				}
				copy := row
				child = &copy
			}
			if child == nil {
				t.Fatal("actual deployed SQS queue lacks child audit outcome")
			}
			// AWS exposes the original caller and service origin, not a parent
			// request field. ParentEventID is our shared journal ancestry contract.
			if child.ParentEventID != parent["eventID"] || child.RequestID == parentRequest || child.ActorARN != actor ||
				child.ActorService != "cloudformation.amazonaws.com" || child.APICallCompleted.Identity.AccessKeyID != access ||
				child.APICallCompleted.Identity.PrincipalID != aws.ToString(user.User.UserId) {
				t.Fatalf("child audit lost its initiating event or actual caller: %+v", child)
			}
			childAudit := auditLookupRecord(t, trails, child.RequestID, "CreateQueue")
			for _, field := range []string{"eventSource", "eventName", "readOnly", "eventCategory", "managementEvent", "eventType", "sourceIPAddress", "userAgent"} {
				if !reflect.DeepEqual(childAudit[field], nativeChild[field]) {
					t.Fatalf("child audit %s differs from native", field)
				}
			}
			for _, field := range []string{"type", "accountId", "arn", "userName", "invokedBy"} {
				if awsFixtureField(childAudit, "userIdentity."+field) != awsFixtureField(nativeChild, "userIdentity."+field) {
					t.Fatalf("child caller %s differs from native", field)
				}
			}
			if childAudit["eventID"] != child.APICallCompleted.EventID ||
				awsFixtureField(childAudit, "userIdentity.accessKeyId") != access ||
				awsFixtureField(childAudit, "userIdentity.principalId") != aws.ToString(user.User.UserId) ||
				cloudFormationQueueIdentity(awsFixtureField(childAudit, "responseElements.queueUrl").(string)) != cloudFormationQueueIdentity(queue) {
				t.Fatal("CloudTrail child did not expose the actual committed SQS outcome")
			}
			var update cloudformation.UpdateStackInput
			awsDecodeJSON(t, inputs["update-export-in-use"], &update)
			update.StackName, update.TemplateBody, update.ClientRequestToken = created.StackId, aws.String(template(20)), aws.String("audit-update")
			update.Parameters = []cfntypes.Parameter{{ParameterKey: aws.String("Secret"), UsePreviousValue: aws.Bool(true)}, {ParameterKey: aws.String("Plain"), ParameterValue: aws.String(changedPlain)}}
			updated, err := client.UpdateStack(ctx, &update)
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, client, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			cloudFormationQueueVisibility(t, c.sqs(access, secret, ""), queue, "20")
			updateRequest := request("update-export-in-use")
			updateRequest["stackName"], updateRequest["parameters"] = aws.ToString(created.StackId), keys
			check("update-export-in-use", updated, nil, updateRequest, map[string]any{"stackId": aws.ToString(created.StackId)})
			read, err := client.GetTemplate(ctx, &cloudformation.GetTemplateInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationTemplateEqual(t, template(20), aws.ToString(read.TemplateBody))
			check("get-template", read, nil, map[string]any{"stackName": aws.ToString(created.StackId)}, nil)
			described, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: created.StackId})
			if err != nil {
				t.Fatal(err)
			}
			parameters := map[string]string{}
			for _, value := range described.Stacks[0].Parameters {
				parameters[aws.ToString(value.ParameterKey)] = aws.ToString(value.ParameterValue)
			}
			if !reflect.DeepEqual(parameters, map[string]string{"Secret": "****", "Plain": changedPlain}) {
				t.Fatalf("public NoEcho boundary changed: %v", parameters)
			}
			check("create-describe", described, nil, map[string]any{"stackName": aws.ToString(created.StackId)}, nil)
			unchanged := update
			unchanged.ClientRequestToken = aws.String("audit-no-change")
			failedUpdate, callErr := client.UpdateStack(ctx, &unchanged)
			assertAPIError(t, callErr, "ValidationError")
			check("update-stack-no-change", failedUpdate, callErr, nil, nil)
			var change cloudformation.CreateChangeSetInput
			awsDecodeJSON(t, inputs["no-change-create-changeset"], &change)
			change.StackName, change.ChangeSetName, change.TemplateBody, change.ClientToken = created.StackId, aws.String("audit-no-change"), update.TemplateBody, aws.String("audit-no-change-set")
			change.Parameters = update.Parameters
			planned, err := client.CreateChangeSet(ctx, &change)
			if err != nil {
				t.Fatal(err)
			}
			changeRequest := request("no-change-create-changeset")
			changeRequest["stackName"], changeRequest["changeSetName"], changeRequest["clientToken"], changeRequest["parameters"] = aws.ToString(created.StackId), "audit-no-change", "audit-no-change-set", keys
			check("no-change-create-changeset", planned, nil, changeRequest, map[string]any{"id": aws.ToString(planned.Id)})
			for {
				state, err := client.DescribeChangeSet(ctx, &cloudformation.DescribeChangeSetInput{ChangeSetName: planned.Id})
				if err != nil {
					t.Fatal(err)
				}
				if state.Status == cfntypes.ChangeSetStatusFailed {
					break
				}
				if state.Status != cfntypes.ChangeSetStatusCreatePending && state.Status != cfntypes.ChangeSetStatusCreateInProgress {
					t.Fatal("unchanged plan became executable", state.Status)
				}
				advanceClock(t, source, time.Second)
				if _, err := c.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
					t.Fatal(err)
				}
			}
			rejected, callErr := client.ExecuteChangeSet(ctx, &cloudformation.ExecuteChangeSetInput{ChangeSetName: planned.Id})
			assertAPIError(t, callErr, "InvalidChangeSetStatus")
			check("no-change-execute-rejected", rejected, callErr, nil, nil)
			c = reopen()
			client = cloudFormationClient(c, fixture.Region, access, secret)
			trails = organizationTrailClient(c, fixture.Account, fixture.Region)
			for _, before := range []map[string]any{parent, childAudit} {
				retained := auditLookupRecord(t, trails, before["requestID"].(string), before["eventName"].(string))
				for _, field := range []string{"eventID", "requestID", "userIdentity", "requestParameters", "responseElements"} {
					if !reflect.DeepEqual(retained[field], before[field]) {
						t.Fatal("restart changed retained caller/audit secrecy contract", field)
					}
				}
			}
			retainedChildren, err := events.ReadAPICalls(ctx, []string{child.APICallCompleted.EventID})
			if err != nil {
				t.Fatal(err)
			}
			if len(retainedChildren) != 1 || retainedChildren[0].ParentEventID != parent["eventID"] ||
				retainedChildren[0].RequestID != child.RequestID || retainedChildren[0].ActorARN != actor {
				t.Fatal("restart lost the committed parent-child caller ancestry")
			}
			cloudFormationDeleteQueueStack(t, c, source, client, c.sqs(access, secret, ""), aws.ToString(created.StackId), queue)
		})
	}
}
