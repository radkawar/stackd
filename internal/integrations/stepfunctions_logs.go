package integrations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/logs"
	sfnapi "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/logs"
	"stackd/internal/services/stepfunctions"
)

// StepFunctionsLogsAPI is implemented by the real Logs service. Admission uses
// the execution role; ingestion uses the resource-policy-authorized delivery
// principal, as observed in testdata/aws/stepfunctions/observability.json.
type StepFunctionsLogsAPI interface {
	ConfigureServiceDelivery(context.Context, string) *awswire.Error
	EnsureLogStream(context.Context, string, string) *awswire.Error
	PutLogEvents(context.Context, *api.PutLogEventsRequest) (*api.PutLogEventsResponse, *awswire.Error)
}

type StepFunctionsLogs struct {
	Logs     StepFunctionsLogsAPI
	Roles    ServiceRoles
	KMS      StepFunctionsKMSOperations
	Activity IAMActivity
}

var _ stepfunctions.HistoryPublisher = (*StepFunctionsLogs)(nil)

// ConfigureLogging admits role and Logs resource-policy state in the caller's
// shared transaction. It performs no external IO and never caches credentials
// whose publication could still roll back. Actual delivery runs after commit.
func (a *StepFunctionsLogs) ConfigureLogging(ctx context.Context, revision stepfunctions.RevisionRecord) error {
	if revision.LogLevel == "" || revision.LogLevel == "OFF" {
		return nil
	}
	if a.Logs == nil {
		return errors.New("step functions CloudWatch Logs dependency is not configured")
	}
	origin := awsctx.FromContext(ctx)
	parent := apievents.EventID(ctx)
	if parent == "" {
		parent = origin.ParentEventID
	}
	key := revision.Machine
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ParentEventID: parent})
	credential, wire := a.Roles.assume(ctx,
		awsctx.ServicePrincipal{Name: "states.amazonaws.com", SourceARN: key.ARN(), Type: "AWSService"},
		revision.RoleARN, identity.RoleSessionSpec{SessionName: "StepFunctions_LogsDelivery"}, "")
	if wire != nil {
		return stepFunctionsLogAdmissionError(wire)
	}
	role, wire := serviceRoleRequestContext(ctx, credential, key.Region, "states.amazonaws.com")
	if wire != nil {
		return stepFunctionsLogAdmissionError(wire)
	}
	if wire := a.Logs.ConfigureServiceDelivery(role, revision.LogGroupARN); wire != nil {
		return stepFunctionsLogAdmissionError(wire)
	}
	return nil
}

func stepFunctionsLogAdmissionError(err error) error {
	var wire *awswire.Error
	if errors.As(err, &wire) && wire.StatusCode >= 500 {
		return wire
	}
	return &awswire.Error{Code: "AccessDeniedException", Message: "The state machine IAM Role is not authorized to access the Log Destination.", StatusCode: 400, Cause: err}
}

// PublishHistory consumes a committed history event outside the source
// transaction. Delivery is best effort and must never change execution status.
func (a *StepFunctionsLogs) PublishHistory(ctx context.Context, history stepfunctions.HistoryRecord, execution stepfunctions.ExecutionRecord, revision stepfunctions.RevisionRecord) error {
	if !stepFunctionsLogLevel(revision.LogLevel, history.Event.Type) {
		return nil
	}
	if err := a.publishHistory(ctx, history, execution, revision); err != nil {
		slog.Warn("Step Functions log delivery failed", "execution_arn", execution.Key.ARN, "log_group", revision.LogGroupARN, "error", err)
	}
	return nil
}

func (a *StepFunctionsLogs) publishHistory(ctx context.Context, history stepfunctions.HistoryRecord, execution stepfunctions.ExecutionRecord, revision stepfunctions.RevisionRecord) error {
	if a.Logs == nil {
		return errors.New("CloudWatch Logs dependency is not configured")
	}
	event := history.Event
	if event.Id == nil || event.Type == nil || event.Timestamp == nil {
		return errors.New("incomplete Step Functions history event")
	}
	message, err := stepFunctionsLogMessage(event, execution.Key.ARN, revision.IncludeExecutionData)
	if err != nil {
		return err
	}
	if len(message)+logs.EventOverheadBytes > logs.MaxBatchBytes {
		return errors.New("step functions log event exceeds the CloudWatch Logs size limit")
	}
	at := time.Time(*event.Timestamp).UTC()
	bucket := "2006-01-02-15"
	if execution.Type == "EXPRESS" {
		bucket = "2006-01-02-15-04"
	}
	// A single delivery shard; the timestamp granularity differs natively for
	// Standard and Express. No execution name or token becomes a stream name.
	stream := "states/" + execution.Machine.Name + "/" + at.Format(bucket) + "/00000000"
	_, group, ok := strings.Cut(revision.LogGroupARN, ":log-group:")
	if !ok {
		return errors.New("invalid Step Functions log group ARN")
	}
	group = strings.TrimSuffix(group, ":*")
	origin := awsctx.FromContext(ctx)
	parent := apievents.EventID(ctx)
	if parent == "" {
		parent = origin.ParentEventID
	}
	if parent == "" {
		parent = execution.ParentEventID
	}
	key := execution.Key
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ParentEventID: parent,
		SourceIP: "delivery.logs.amazonaws.com", UserAgent: "delivery.logs.amazonaws.com",
		ServicePrincipal: awsctx.ServicePrincipal{Name: "delivery.logs.amazonaws.com", SourceARN: strings.TrimSuffix(revision.LogGroupARN, ":*"), Type: "AWSService"},
	})
	command := func() context.Context {
		metadata := awsctx.FromContext(ctx)
		metadata.RequestID = uuid.NewString()
		return awsctx.WithMetadata(ctx, metadata)
	}
	if revision.EncryptionType == "CUSTOMER_MANAGED_KMS_KEY" {
		message, err = a.workflowLogMessage(command(), revision, message)
		if err != nil {
			return err
		}
	}
	if wire := a.Logs.EnsureLogStream(command(), group, stream); wire != nil {
		return wire
	}
	out, wire := a.Logs.PutLogEvents(command(), &api.PutLogEventsRequest{
		LogGroupName: new(api.LogGroupName(group)), LogStreamName: new(api.LogStreamName(stream)),
		LogEvents: api.InputLogEvents{{Timestamp: new(api.Timestamp(at.UnixMilli())), Message: new(api.EventMessage(message))}},
	})
	if wire != nil {
		return wire
	}
	if out.RejectedLogEventsInfo != nil {
		return errors.New("CloudWatch Logs rejected the Step Functions history timestamp")
	}
	return nil
}

// workflowLogMessage crosses the workflow-CMK delivery boundary before Logs
// receives plaintext. The workflow role encrypts; the Logs delivery principal
// must independently unwrap the key. Log-group-at-rest encryption is separate.
func (a *StepFunctionsLogs) workflowLogMessage(ctx context.Context, revision stepfunctions.RevisionRecord, message string) (string, error) {
	if a.KMS == nil || a.Activity == nil {
		return "", errors.New("step functions log encryption dependencies are not configured")
	}
	credential, wire := a.Roles.assume(ctx,
		awsctx.ServicePrincipal{Name: "states.amazonaws.com", SourceARN: revision.Machine.ARN(), Type: "AWSService"},
		revision.RoleARN, identity.RoleSessionSpec{SessionName: "StepFunctions_LogsDelivery"}, "")
	if wire != nil {
		return "", fmt.Errorf("assuming workflow log encryption role: %w", wire)
	}
	role, wire := serviceRoleRequestContext(ctx, credential, revision.Machine.Region, "states.amazonaws.com")
	if wire != nil {
		return "", fmt.Errorf("opening workflow log encryption role: %w", wire)
	}
	if wire := recordKMSActivity(role, a.Activity, "GenerateDataKey"); wire != nil {
		return "", fmt.Errorf("recording workflow log encryption activity: %w", wire)
	}
	scope := revision.Machine
	encryption := map[string]string{
		"SourceArn":     "arn:" + scope.Partition + ":logs:" + scope.Region + ":" + scope.AccountID + ":*",
		"SourceAccount": scope.AccountID,
	}
	plain, wrapped, _, wire := a.KMS.GenerateDataKey(role, revision.KMSKeyARN, encryption)
	if wire != nil {
		clear(plain)
		return "", fmt.Errorf("generating workflow log data key: %w", wire)
	}
	sealer, err := stepFunctionsLogCipher(plain)
	clear(plain)
	if err != nil {
		return "", fmt.Errorf("initializing workflow log encryption: %w", err)
	}
	// Match retained workflow payloads' nonce-prefixed AES-GCM envelope. This
	// envelope is transient: no plaintext key or delivery record is retained.
	nonce := make([]byte, sealer.NonceSize(), sealer.NonceSize()+len(message)+sealer.Overhead())
	_, _ = rand.Read(nonce)
	content := sealer.Seal(nonce, nonce, []byte(message), nil)

	// ctx contains only delivery.logs.amazonaws.com, never the execution role
	// or API caller. The returned key, not the generating key, opens the data.
	plain, _, wire = a.KMS.Decrypt(ctx, wrapped, encryption)
	if wire != nil {
		clear(plain)
		return "", fmt.Errorf("unwrapping workflow log data key for delivery: %w", wire)
	}
	opener, err := stepFunctionsLogCipher(plain)
	clear(plain)
	if err != nil {
		return "", fmt.Errorf("initializing workflow log decryption: %w", err)
	}
	n := opener.NonceSize()
	if len(content) < n {
		return "", errors.New("invalid encrypted workflow log payload")
	}
	recovered, err := opener.Open(nil, content[:n], content[n:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypting workflow log payload for delivery: %w", err)
	}
	return string(recovered), nil
}

func stepFunctionsLogCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ERROR/FATAL use the documented event table, not substring guesses (for
// example FailStateEntered is ERROR whereas ExecutionFailed is also FATAL).
func stepFunctionsLogLevel(level string, event *sfnapi.HistoryEventType) bool {
	if event == nil {
		return false
	}
	if level == "ALL" {
		return true
	}
	if level != "ERROR" && level != "FATAL" {
		return false
	}
	switch string(*event) {
	case "ExecutionAborted", "ExecutionFailed", "ExecutionTimedOut":
		return true
	}
	if level == "FATAL" {
		return false
	}
	switch string(*event) {
	case "FailStateEntered", "LambdaFunctionFailed", "LambdaFunctionScheduleFailed", "LambdaFunctionStartFailed", "LambdaFunctionTimedOut", "MapIterationAborted", "MapIterationFailed", "MapRunAborted", "MapRunFailed", "MapStateAborted", "MapStateFailed", "ParallelStateAborted", "ParallelStateFailed", "TaskFailed", "TaskStartFailed", "TaskStateAborted", "TaskSubmitFailed", "TaskTimedOut", "WaitStateAborted", "ActivityFailed", "ActivityScheduleFailed", "ActivityTimedOut", "EvaluationFailed":
		return true
	}
	return false
}

func stepFunctionsLogMessage(event sfnapi.HistoryEvent, executionARN string, includeData bool) (string, error) {
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return "", err
	}
	kind := string(*event.Type)
	detailsName := strings.ToLower(kind[:1]) + kind[1:] + "EventDetails"
	if strings.HasSuffix(kind, "StateEntered") {
		detailsName = "stateEnteredEventDetails"
	}
	if strings.HasSuffix(kind, "StateExited") {
		detailsName = "stateExitedEventDetails"
	}
	details := map[string]json.RawMessage{}
	if raw := envelope[detailsName]; len(raw) != 0 {
		if err := json.Unmarshal(raw, &details); err != nil {
			return "", err
		}
	}
	if !includeData {
		for _, name := range []string{"input", "inputDetails", "output", "outputDetails", "parameters", "assignedVariables", "assignedVariablesDetails"} {
			delete(details, name)
		}
	} else {
		// Step Functions reserves event-envelope space within the 256-KiB
		// delivery payload. Truncate only execution data, never error/cause or
		// the event identity; flags distinguish truncation from absent data.
		remaining := 248 * 1024
		for _, name := range []string{"input", "output", "assignedVariables"} {
			raw, present := details[name]
			if !present {
				continue
			}
			if len(raw) <= remaining {
				remaining -= len(raw)
				continue
			}
			if name == "assignedVariables" {
				delete(details, name)
			} else {
				var text string
				if err := json.Unmarshal(raw, &text); err != nil {
					return "", err
				}
				text = stepFunctionsLogPrefix(text, max(remaining-2, 0))
				details[name], err = json.Marshal(text)
				if err != nil {
					return "", err
				}
			}
			details[name+"Details"] = json.RawMessage(`{"truncated":true}`)
			remaining = 0
		}
	}
	previous := int64(0)
	if event.PreviousEventId != nil {
		previous = int64(*event.PreviousEventId)
	}
	record := struct {
		Details         map[string]json.RawMessage `json:"details"`
		RedriveCount    string                     `json:"redrive_count"`
		ID              string                     `json:"id"`
		Type            string                     `json:"type"`
		PreviousEventID string                     `json:"previous_event_id"`
		EventTimestamp  string                     `json:"event_timestamp"`
		ExecutionARN    string                     `json:"execution_arn"`
	}{details, "0", strconv.FormatInt(int64(*event.Id), 10), kind, strconv.FormatInt(previous, 10), strconv.FormatInt(time.Time(*event.Timestamp).UnixMilli(), 10), executionARN}
	encoded, err = json.Marshal(record)
	return string(encoded), err
}

func stepFunctionsLogPrefix(text string, limit int) string {
	used := 0
	for offset, r := range text {
		size := utf8.RuneLen(r)
		switch {
		case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
			size = 2
		case r < 0x20 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029':
			size = 6
		}
		if used+size > limit {
			return text[:offset]
		}
		used += size
	}
	return text
}
