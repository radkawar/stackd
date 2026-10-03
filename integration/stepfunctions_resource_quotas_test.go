package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/smithy-go/middleware"

	"stackd"
	"stackd/clock"
	sfnstore "stackd/storage/stepfunctions"
)

type stepFunctionsOccupiedCounts struct{ machines, activities, executions int64 }

// This decorator adds a fixed already-occupied population to REAL scoped counts
// in the same repository transaction that admits each SDK request. It never
// supplies a canned count or changes resource reads, writes, IAM or scheduling.
// Every scope has the same fixed baseline, so accidentally counting another
// account/Region's real rows prevents its first admission and fails these tests.
// This proves small-store boundary semantics, not native AWS quota exhaustion,
// exact native error wording, or performance with a million persisted rows.
type stepFunctionsOccupiedRepository struct {
	sfnstore.Repository
	occupied stepFunctionsOccupiedCounts
}

type stepFunctionsOccupiedReader struct {
	sfnstore.Reader
	occupied stepFunctionsOccupiedCounts
}

type stepFunctionsOccupiedTransaction struct {
	sfnstore.Transaction
	occupied stepFunctionsOccupiedCounts
}

func (r *stepFunctionsOccupiedRepository) View(ctx context.Context, fn func(sfnstore.Reader) error) error {
	return r.Repository.View(ctx, func(reader sfnstore.Reader) error {
		return fn(stepFunctionsOccupiedReader{Reader: reader, occupied: r.occupied})
	})
}

func (r *stepFunctionsOccupiedRepository) Update(ctx context.Context, fn func(sfnstore.Transaction) error) error {
	return r.Repository.Update(ctx, func(tx sfnstore.Transaction) error {
		return fn(stepFunctionsOccupiedTransaction{Transaction: tx, occupied: r.occupied})
	})
}

func (r *stepFunctionsOccupiedRepository) Attempt(ctx context.Context, fn func(sfnstore.Transaction) error) error {
	return r.Repository.Attempt(ctx, func(tx sfnstore.Transaction) error {
		return fn(stepFunctionsOccupiedTransaction{Transaction: tx, occupied: r.occupied})
	})
}

func (r stepFunctionsOccupiedReader) MachineCount(scope sfnstore.Scope) (int64, error) {
	count, err := r.Reader.MachineCount(scope)
	return count + r.occupied.machines, err
}

func (r stepFunctionsOccupiedReader) ActivityCount(scope sfnstore.Scope) (int64, error) {
	count, err := r.Reader.ActivityCount(scope)
	return count + r.occupied.activities, err
}

func (r stepFunctionsOccupiedReader) OpenExecutionCount(scope sfnstore.Scope) (int64, error) {
	count, err := r.Reader.OpenExecutionCount(scope)
	return count + r.occupied.executions, err
}

func (tx stepFunctionsOccupiedTransaction) MachineCount(scope sfnstore.Scope) (int64, error) {
	return (stepFunctionsOccupiedReader{Reader: tx.Transaction, occupied: tx.occupied}).MachineCount(scope)
}

func (tx stepFunctionsOccupiedTransaction) ActivityCount(scope sfnstore.Scope) (int64, error) {
	return (stepFunctionsOccupiedReader{Reader: tx.Transaction, occupied: tx.occupied}).ActivityCount(scope)
}

func (tx stepFunctionsOccupiedTransaction) OpenExecutionCount(scope sfnstore.Scope) (int64, error) {
	return (stepFunctionsOccupiedReader{Reader: tx.Transaction, occupied: tx.occupied}).OpenExecutionCount(scope)
}

func TestStepFunctionsResourceQuotaBoundariesSDK(t *testing.T) {
	var fixture struct {
		Evidence struct {
			QuotaCatalogue string `json:"quota_catalogue"`
		}
		Started        time.Time `json:"started_at"`
		Scopes         []struct{ Account, Region string }
		WaitDefinition json.RawMessage `json:"wait_definition"`
		MapDefinition  json.RawMessage `json:"map_definition"`
		DeniedError    string          `json:"denied_error"`
		Scenarios      []struct {
			Resource       string
			QuotaName      string `json:"quota_name"`
			OccupiedCount  int64  `json:"occupied_count"`
			AvailableSlots int64  `json:"available_slots"`
			LimitError     string `json:"limit_error"`
			HTTPStatus     int    `json:"http_status"`
		}
	}
	data, err := os.ReadFile("../testdata/integration/stepfunctions_resource_quotas.json")
	if err != nil {
		t.Fatal(err)
	}
	awsDecodeJSON(t, data, &fixture)
	var catalogue struct{ Observations []awsNativeObservation }
	awsReadFixture(t, fixture.Evidence.QuotaCatalogue, &catalogue)
	defaults := map[string]int64{}
	for _, observation := range catalogue.Observations {
		if observation.Service != "service-quotas" || stepFunctionsOperation(observation.Operation) != "listawsdefaultservicequotas" {
			continue
		}
		var output struct {
			Quotas []struct {
				QuotaName string
				Value     float64
			}
		}
		awsDecodeJSON(t, observation.Result.Output, &output)
		for _, quota := range output.Quotas {
			defaults[quota.QuotaName] = int64(quota.Value)
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Resource, func(t *testing.T) {
				if scenario.OccupiedCount+scenario.AvailableSlots != defaults[scenario.QuotaName] {
					t.Fatalf("fixture must leave %d slots beneath captured %s ceiling %d", scenario.AvailableSlots, scenario.QuotaName, defaults[scenario.QuotaName])
				}
				occupied := stepFunctionsOccupiedCounts{}
				switch scenario.Resource {
				case "machines":
					occupied.machines = scenario.OccupiedCount
				case "activities":
					occupied.activities = scenario.OccupiedCount
				case "executions", "map-backlog":
					occupied.executions = scenario.OccupiedCount
				default:
					t.Fatalf("unknown quota boundary %q", scenario.Resource)
				}
				source := &stepFunctionsReplayClock{Manual: clock.NewManual(fixture.Started), timers: make(chan time.Time, 256)}
				var repository sfnstore.Repository
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Scopes[0].Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					repository = config.Storage.StepFunctions
					if previous, ok := repository.(*stepFunctionsOccupiedRepository); ok {
						repository = previous.Repository
					}
					config.Storage.StepFunctions = &stepFunctionsOccupiedRepository{Repository: repository, occupied: occupied}
					repository = config.Storage.StepFunctions
					return startPublicCloud(t, config)
				})
				replay := &stepFunctionsNativeReplay{clients: clients, clock: source}
				client := func(scope int, key, secret string) *sfn.Client {
					if key == "" {
						key, secret = fixture.Scopes[scope].Account, "test"
					}
					return sfn.New(sfn.Options{Region: fixture.Scopes[scope].Region, BaseEndpoint: aws.String(clients.server.URL),
						Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				}
				roles := map[string]*string{}
				for _, scope := range fixture.Scopes {
					if roles[scope.Account] != nil {
						continue
					}
					role, err := clients.iam(scope.Account, "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("quota-worker"),
						AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
					if err != nil {
						t.Fatal(err)
					}
					roles[scope.Account] = role.Role.Arn
				}
				_, deniedKey, deniedSecret := clients.user(t, fixture.Scopes[0].Account, "quota-observer")
				putUserPolicy(t, clients.iam(fixture.Scopes[0].Account, "test", ""), "quota-observer", allow(`["states:Describe*","states:List*"]`, "*"))
				api, denied := client(0, "", ""), client(0, deniedKey, deniedSecret)
				limitError := func(err error) {
					t.Helper()
					assertAPIError(t, err, scenario.LimitError)
					var response interface{ HTTPStatusCode() int }
					if !errors.As(err, &response) || response.HTTPStatusCode() != scenario.HTTPStatus {
						t.Fatalf("expected quota HTTP %d, got %v", scenario.HTTPStatus, err)
					}
					// Require the actual SDK modeled shape, not merely a generic
					// error whose code happens to echo the fixture's expectation.
					var machine *sfntypes.StateMachineLimitExceeded
					var activity *sfntypes.ActivityLimitExceeded
					var execution *sfntypes.ExecutionLimitExceeded
					if !errors.As(err, &machine) && !errors.As(err, &activity) && !errors.As(err, &execution) {
						t.Fatalf("quota error is not modeled by the SDK: %T: %v", err, err)
					}
				}
				createMachine := func(scope int, name string, typ sfntypes.StateMachineType) (*sfn.CreateStateMachineOutput, error) {
					return client(scope, "", "").CreateStateMachine(t.Context(), &sfn.CreateStateMachineInput{Name: aws.String(name),
						RoleArn: roles[fixture.Scopes[scope].Account], Type: typ, Definition: aws.String(string(fixture.WaitDefinition))})
				}
				start := func(api *sfn.Client, machine *string, name string) (*sfn.StartExecutionOutput, error) {
					return api.StartExecution(t.Context(), &sfn.StartExecutionInput{StateMachineArn: machine, Name: aws.String(name), Input: aws.String(`{"retained":true}`)})
				}
				stop := func(execution *string) {
					t.Helper()
					if _, err := api.StopExecution(t.Context(), &sfn.StopExecutionInput{ExecutionArn: execution, Error: aws.String("QuotaSlotReleased"), Cause: aws.String("Release the real occupied slot")}); err != nil {
						t.Fatal(err)
					}
					replay.drain(t)
				}

				switch scenario.Resource {
				case "machines":
					first, err := createMachine(0, "retained-machine", sfntypes.StateMachineTypeStandard)
					if err != nil {
						t.Fatal(err)
					}
					repeated, err := createMachine(0, "retained-machine", sfntypes.StateMachineTypeStandard)
					if err != nil {
						t.Fatalf("idempotent machine at capacity: %v", err)
					}
					if aws.ToString(first.StateMachineArn) != aws.ToString(repeated.StateMachineArn) || !aws.ToTime(first.CreationDate).Equal(aws.ToTime(repeated.CreationDate)) {
						t.Fatal("idempotent machine changed its retained identity")
					}
					_, err = denied.CreateStateMachine(t.Context(), &sfn.CreateStateMachineInput{Name: aws.String("blocked-machine"), RoleArn: roles[fixture.Scopes[0].Account], Definition: aws.String(string(fixture.WaitDefinition))})
					assertAPIError(t, err, fixture.DeniedError)
					_, err = createMachine(0, "blocked-machine", sfntypes.StateMachineTypeStandard)
					limitError(err)
					for scope := 1; scope < len(fixture.Scopes); scope++ {
						if _, err := createMachine(scope, "retained-machine", sfntypes.StateMachineTypeStandard); err != nil {
							t.Fatalf("machine count leaked into scope %d: %v", scope, err)
						}
					}
					machines, err := api.ListStateMachines(t.Context(), &sfn.ListStateMachinesInput{})
					if err != nil || len(machines.StateMachines) != 1 || machines.NextToken != nil || aws.ToString(machines.StateMachines[0].StateMachineArn) != aws.ToString(first.StateMachineArn) {
						t.Fatalf("rejected creation or another scope changed the machine list: %+v, %v", machines, err)
					}
					execution, err := start(api, first.StateMachineArn, "retain-deleting-slot")
					if err != nil {
						t.Fatal(err)
					}
					replay.drain(t)
					if _, err := api.DeleteStateMachine(t.Context(), &sfn.DeleteStateMachineInput{StateMachineArn: first.StateMachineArn}); err != nil {
						t.Fatal(err)
					}
					replay.drain(t)
					deleting, err := api.DescribeStateMachine(t.Context(), &sfn.DescribeStateMachineInput{StateMachineArn: first.StateMachineArn})
					if err != nil || deleting.Status != sfntypes.StateMachineStatusDeleting {
						t.Fatalf("active machine was removed instead of retaining DELETING: %+v, %v", deleting, err)
					}
					_, err = createMachine(0, "blocked-machine", sfntypes.StateMachineTypeStandard)
					limitError(err)
					stop(execution.ExecutionArn)
					if _, err := createMachine(0, "blocked-machine", sfntypes.StateMachineTypeStandard); err != nil {
						t.Fatalf("removed machine did not release its slot: %v", err)
					}
					machines, err = api.ListStateMachines(t.Context(), &sfn.ListStateMachinesInput{})
					if err != nil || len(machines.StateMachines) != 1 || aws.ToString(machines.StateMachines[0].Name) != "blocked-machine" {
						t.Fatalf("machine slot reuse retained the wrong resources: %+v, %v", machines, err)
					}

				case "activities":
					input := &sfn.CreateActivityInput{Name: aws.String("retained-activity")}
					first, err := api.CreateActivity(t.Context(), input)
					if err != nil {
						t.Fatal(err)
					}
					repeated, err := api.CreateActivity(t.Context(), input)
					if err != nil {
						t.Fatalf("idempotent activity at capacity: %v", err)
					}
					if aws.ToString(first.ActivityArn) != aws.ToString(repeated.ActivityArn) || !aws.ToTime(first.CreationDate).Equal(aws.ToTime(repeated.CreationDate)) {
						t.Fatal("idempotent activity changed its retained identity")
					}
					blocked := &sfn.CreateActivityInput{Name: aws.String("blocked-activity")}
					_, err = denied.CreateActivity(t.Context(), blocked)
					assertAPIError(t, err, fixture.DeniedError)
					_, err = api.CreateActivity(t.Context(), blocked)
					limitError(err)
					for scope := 1; scope < len(fixture.Scopes); scope++ {
						if _, err := client(scope, "", "").CreateActivity(t.Context(), input); err != nil {
							t.Fatalf("activity count leaked into scope %d: %v", scope, err)
						}
					}
					activities, err := api.ListActivities(t.Context(), &sfn.ListActivitiesInput{})
					if err != nil || len(activities.Activities) != 1 || activities.NextToken != nil || aws.ToString(activities.Activities[0].ActivityArn) != aws.ToString(first.ActivityArn) {
						t.Fatalf("rejected creation or another scope changed the activity list: %+v, %v", activities, err)
					}
					if _, err := api.DeleteActivity(t.Context(), &sfn.DeleteActivityInput{ActivityArn: first.ActivityArn}); err != nil {
						t.Fatal(err)
					}
					if _, err := api.CreateActivity(t.Context(), blocked); err != nil {
						t.Fatalf("deleted activity did not release its slot: %v", err)
					}
					activities, err = api.ListActivities(t.Context(), &sfn.ListActivitiesInput{})
					if err != nil || len(activities.Activities) != 1 || aws.ToString(activities.Activities[0].Name) != "blocked-activity" {
						t.Fatalf("activity slot reuse retained the wrong resources: %+v, %v", activities, err)
					}

				case "map-backlog":
					putRolePolicy(t, clients.iam(fixture.Scopes[0].Account, "test", ""), "quota-worker",
						allow(`["states:StartExecution","states:DescribeExecution","states:StopExecution"]`, "*"))
					ordinary, err := createMachine(0, "ordinary", sfntypes.StateMachineTypeStandard)
					if err != nil {
						t.Fatal(err)
					}
					blocker, err := start(api, ordinary.StateMachineArn, "unrelated-open-execution")
					if err != nil {
						t.Fatal(err)
					}
					machine, err := api.CreateStateMachine(t.Context(), &sfn.CreateStateMachineInput{Name: aws.String("map-parent"),
						RoleArn: roles[fixture.Scopes[0].Account], Type: sfntypes.StateMachineTypeStandard, Definition: aws.String(string(fixture.MapDefinition))})
					if err != nil {
						t.Fatal(err)
					}
					parent, err := api.StartExecution(t.Context(), &sfn.StartExecutionInput{StateMachineArn: machine.StateMachineArn,
						Name: aws.String("backlogged-parent"), Input: aws.String(`{"items":["first","second"]}`)})
					if err != nil {
						t.Fatal(err)
					}
					replay.drainEffects(t, repository)
					maps, err := api.ListMapRuns(t.Context(), &sfn.ListMapRunsInput{ExecutionArn: parent.ExecutionArn})
					if err != nil || len(maps.MapRuns) != 1 {
						t.Fatalf("distributed Map was not admitted: %+v, %v", maps, err)
					}
					mapARN := maps.MapRuns[0].MapRunArn
					backlogged, err := api.DescribeMapRun(t.Context(), &sfn.DescribeMapRunInput{MapRunArn: mapARN})
					if err != nil || backlogged.ExecutionCounts == nil || backlogged.ExecutionCounts.Pending != 2 || backlogged.ExecutionCounts.Running != 0 {
						t.Fatalf("full account admitted Map children instead of retaining backlog: %+v, %v", backlogged, err)
					}
					_, err = start(api, ordinary.StateMachineArn, "blocked-by-parent")
					limitError(err)
					// Recovery retains pending children and the shared account
					// ceiling, rather than reserving or losing capacity on reopen.
					clients = reopen()
					replay.clients = clients
					api = client(0, "", "")
					stop(blocker.ExecutionArn)
					// Wake local retained work, not a claimed native AWS poll
					// interval. The child Wait lasts longer than this advance.
					replay.advance(t, source.Now().Add(5*time.Second))
					replay.drainEffects(t, repository)
					resumed, err := api.DescribeMapRun(t.Context(), &sfn.DescribeMapRunInput{MapRunArn: mapARN})
					if err != nil || resumed.ExecutionCounts == nil || resumed.ExecutionCounts.Pending != 1 || resumed.ExecutionCounts.Running != 1 {
						t.Fatalf("released slot did not admit exactly one pending child: %+v, %v", resumed, err)
					}
					children, err := api.ListExecutions(t.Context(), &sfn.ListExecutionsInput{MapRunArn: mapARN, StatusFilter: sfntypes.ExecutionStatusRunning})
					if err != nil || len(children.Executions) != 1 || children.NextToken != nil {
						t.Fatalf("Map running-child count disagrees with real executions: %+v, %v", children, err)
					}
					child, err := api.DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: children.Executions[0].ExecutionArn})
					if err != nil || child.Status != sfntypes.ExecutionStatusRunning || aws.ToString(child.MapRunArn) != aws.ToString(mapARN) {
						t.Fatalf("admitted child is not a running member of the retained Map: %+v, %v", child, err)
					}
					_, err = start(api, ordinary.StateMachineArn, "blocked-by-child")
					limitError(err)

				case "executions":
					standard, err := createMachine(0, "standard", sfntypes.StateMachineTypeStandard)
					if err != nil {
						t.Fatal(err)
					}
					express, err := createMachine(0, "express", sfntypes.StateMachineTypeExpress)
					if err != nil {
						t.Fatal(err)
					}
					// Express is already RUNNING when Standard claims its last
					// slot; admission alone at capacity would not test the filter.
					if _, err := start(api, express.StateMachineArn, "express-before-standard"); err != nil {
						t.Fatal(err)
					}
					first, err := start(api, standard.StateMachineArn, "retained-execution")
					if err != nil {
						t.Fatalf("Express consumed the Standard slot: %v", err)
					}
					replay.drain(t)
					before, history := stepFunctionsQuotaExecutionSnapshot(t, api, first.ExecutionArn)
					repeated, err := start(api, standard.StateMachineArn, "retained-execution")
					if err != nil {
						t.Fatalf("idempotent start at capacity: %v", err)
					}
					if aws.ToString(first.ExecutionArn) != aws.ToString(repeated.ExecutionArn) || !aws.ToTime(first.StartDate).Equal(aws.ToTime(repeated.StartDate)) {
						t.Fatal("idempotent start changed the retained execution")
					}
					_, err = start(denied, standard.StateMachineArn, "blocked-execution")
					assertAPIError(t, err, fixture.DeniedError)
					_, err = start(api, standard.StateMachineArn, "blocked-execution")
					limitError(err)
					if _, err := start(api, express.StateMachineArn, "express-at-capacity"); err != nil {
						t.Fatalf("full Standard capacity rejected Express: %v", err)
					}
					for scope := 1; scope < len(fixture.Scopes); scope++ {
						machine, err := createMachine(scope, "standard", sfntypes.StateMachineTypeStandard)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := start(client(scope, "", ""), machine.StateMachineArn, "retained-execution"); err != nil {
							t.Fatalf("open execution count leaked into scope %d: %v", scope, err)
						}
					}
					executions, err := api.ListExecutions(t.Context(), &sfn.ListExecutionsInput{StateMachineArn: standard.StateMachineArn})
					if err != nil || len(executions.Executions) != 1 || executions.NextToken != nil || aws.ToString(executions.Executions[0].ExecutionArn) != aws.ToString(first.ExecutionArn) {
						t.Fatalf("rejected/idempotent starts changed retained executions: %+v, %v", executions, err)
					}
					after, afterHistory := stepFunctionsQuotaExecutionSnapshot(t, api, first.ExecutionArn)
					if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(history, afterHistory) {
						t.Fatal("idempotent/rejected starts mutated the running execution or history")
					}
					stop(first.ExecutionArn)
					before, history = stepFunctionsQuotaExecutionSnapshot(t, api, first.ExecutionArn)
					if before.Status != sfntypes.ExecutionStatusAborted || before.RedriveStatus != sfntypes.ExecutionRedriveStatusRedrivable {
						t.Fatalf("closed execution is not a retained redrive candidate: %+v", before)
					}
					blocker, err := start(api, standard.StateMachineArn, "blocked-execution")
					if err != nil {
						t.Fatalf("closed execution or Express leaked an open slot: %v", err)
					}
					replay.drain(t)
					redrive := &sfn.RedriveExecutionInput{ExecutionArn: first.ExecutionArn, ClientToken: aws.String("rejected-then-admitted")}
					_, err = denied.RedriveExecution(t.Context(), redrive)
					assertAPIError(t, err, fixture.DeniedError)
					_, err = api.RedriveExecution(t.Context(), redrive)
					limitError(err)
					// Reconstruct services/storage before retrying the rejected
					// token. Neither a leaked write nor an in-process cache may
					// turn the rejection into an idempotent success.
					clients = reopen()
					replay.clients = clients
					api = client(0, "", "")
					retained, err := start(api, standard.StateMachineArn, "blocked-execution")
					if err != nil || aws.ToString(retained.ExecutionArn) != aws.ToString(blocker.ExecutionArn) || !aws.ToTime(retained.StartDate).Equal(aws.ToTime(blocker.StartDate)) {
						t.Fatalf("retained StartExecution lost idempotency at capacity after reopen: %+v, %v", retained, err)
					}
					_, err = api.RedriveExecution(t.Context(), redrive)
					limitError(err)
					after, afterHistory = stepFunctionsQuotaExecutionSnapshot(t, api, first.ExecutionArn)
					if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(history, afterHistory) {
						t.Fatal("rejected redrive mutated the retained execution or causal history")
					}
					stop(blocker.ExecutionArn)
					admitted, err := api.RedriveExecution(t.Context(), redrive)
					if err != nil {
						t.Fatalf("rejected token could not claim the genuinely released slot: %v", err)
					}
					replay.drain(t)
					before, history = stepFunctionsQuotaExecutionSnapshot(t, api, first.ExecutionArn)
					if before.Status != sfntypes.ExecutionStatusRunning || aws.ToInt32(before.RedriveCount) != 1 {
						t.Fatalf("redrive did not resume exactly once: %+v", before)
					}
					clients = reopen()
					replay.clients = clients
					api = client(0, "", "")
					replayed, err := api.RedriveExecution(t.Context(), redrive)
					if err != nil || !aws.ToTime(admitted.RedriveDate).Equal(aws.ToTime(replayed.RedriveDate)) {
						t.Fatalf("retained redrive token failed idempotency at capacity: %+v, %v", replayed, err)
					}
					_, err = start(api, standard.StateMachineArn, "after-redrive")
					limitError(err)
					after, afterHistory = stepFunctionsQuotaExecutionSnapshot(t, api, first.ExecutionArn)
					if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(history, afterHistory) {
						t.Fatal("idempotent redrive appended history or restarted the execution")
					}
					stop(first.ExecutionArn)
					// Exercise atomic last-slot admission over real HTTP and the
					// real backend transaction, not a count-only mock callback.
					type result struct {
						output *sfn.StartExecutionOutput
						err    error
					}
					results := make(chan result, 2)
					ready := make(chan struct{})
					for _, name := range []string{"concurrent-one", "concurrent-two"} {
						go func() {
							<-ready
							output, err := start(api, standard.StateMachineArn, name)
							results <- result{output: output, err: err}
						}()
					}
					close(ready)
					var winner *string
					for range 2 {
						result := <-results
						if result.err != nil {
							limitError(result.err)
							continue
						}
						if winner != nil {
							t.Fatal("concurrent starts both claimed the last open slot")
						}
						winner = result.output.ExecutionArn
					}
					if winner == nil {
						t.Fatal("no concurrent start could reuse the released slot")
					}
					executions, err = api.ListExecutions(t.Context(), &sfn.ListExecutionsInput{StateMachineArn: standard.StateMachineArn, StatusFilter: sfntypes.ExecutionStatusRunning})
					if err != nil || len(executions.Executions) != 1 || aws.ToString(executions.Executions[0].ExecutionArn) != aws.ToString(winner) {
						t.Fatalf("last-slot race retained the wrong open executions: %+v, %v", executions, err)
					}
				}
			})
		}
	}
}

func stepFunctionsQuotaExecutionSnapshot(t *testing.T, api *sfn.Client, arn *string) (*sfn.DescribeExecutionOutput, []sfntypes.HistoryEvent) {
	t.Helper()
	description, err := api.DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: arn})
	if err != nil {
		t.Fatal(err)
	}
	// HTTP request metadata is not retained workflow state. All execution
	// fields and complete event payloads, IDs and timestamps remain compared.
	description.ResultMetadata = middleware.Metadata{}
	history, err := api.GetExecutionHistory(t.Context(), &sfn.GetExecutionHistoryInput{ExecutionArn: arn, MaxResults: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if history.NextToken != nil {
		t.Fatal("quota boundary workflow unexpectedly exceeded one history page")
	}
	return description, history.Events
}
