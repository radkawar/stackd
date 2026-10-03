package integrations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	sqsapi "stackd/internal/awsapi/sqs"
	xrayapi "stackd/internal/awsapi/xray"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/stepfunctions"
)

// StepFunctionsTracing is an X-Ray client, not a second sampling control plane.
// Rules, quotas and their authorization belong to the ordinary X-Ray commands.
// The transient counters are client-side reservoir consumption and reports;
// execution admission retains the resulting public header and private segment ID.
// Clock must be the owning instance's service clock.
type StepFunctionsTracing struct {
	Roles    ServiceRoles
	Commands StepFunctionsCommands
	Clock    clock.Clock

	mu      sync.Mutex
	clients map[string]*stepFunctionsSamplingClient
}

type stepFunctionsSamplingClient struct {
	id                          string
	second, window              time.Time
	used                        int64
	requests, sampled, borrowed int32
	quota                       int64
	quotaExpires                time.Time
}

var stepFunctionsTraceRoot = regexp.MustCompile(`^1-[0-9a-fA-F]{8}-[0-9a-fA-F]{24}$`)
var stepFunctionsTraceParent = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

func stepFunctionsTraceHeader(header string) (root, parent, sampled string, valid bool) {
	for field := range strings.SplitSeq(header, ";") {
		name, value, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found {
			continue
		}
		switch name {
		case "Root":
			root = value
		case "Parent":
			parent = value
		case "Sampled":
			sampled = value
		}
	}
	valid = stepFunctionsTraceRoot.MatchString(root) && (parent == "" || stepFunctionsTraceParent.MatchString(parent)) && (sampled == "0" || sampled == "1")
	return
}

func stepFunctionsSegmentID() string {
	var random [8]byte
	_, _ = rand.Read(random[:])
	return hex.EncodeToString(random[:])
}

func (t *StepFunctionsTracing) BeginTracing(ctx context.Context, execution stepfunctions.ExecutionRecord, revision stepfunctions.RevisionRecord, provided bool) (stepfunctions.TraceContext, error) {
	trace := stepfunctions.TraceContext{Header: execution.TraceHeader}
	root, parent, sampled, valid := stepFunctionsTraceHeader(trace.Header)
	if valid {
		if sampled == "1" {
			trace.SegmentID = stepFunctionsSegmentID()
		}
		return trace, nil
	}
	if !provided && trace.Header == "" && !revision.TracingEnabled {
		return trace, nil
	}
	if !stepFunctionsTraceRoot.MatchString(root) {
		root = awsctx.NewTraceID(t.Clock.Now())
	}
	trace.Header = "Root=" + root
	if parent != "" && stepFunctionsTraceParent.MatchString(parent) {
		trace.Header += ";Parent=" + parent
	}
	if sampled == "0" || sampled == "1" {
		trace.Header += ";Sampled=" + sampled
		if sampled == "1" {
			trace.SegmentID = stepFunctionsSegmentID()
		}
		return trace, nil
	}
	canonical := trace.Header
	trace.Header = canonical + ";Sampled=0"
	role, err := t.roleContext(ctx, revision)
	if err != nil {
		return trace, err
	}
	selected, err := t.sample(role, execution, revision)
	if err != nil {
		return trace, err
	}
	if selected {
		trace.Header = canonical + ";Sampled=1"
		trace.SegmentID = stepFunctionsSegmentID()
	}
	return trace, nil
}

func (t *StepFunctionsTracing) roleContext(ctx context.Context, revision stepfunctions.RevisionRecord) (context.Context, error) {
	ctx = context.WithValue(ctx, stepFunctionsTraceObserverKey{}, (*stepFunctionsTraceObserver)(nil))
	origin := awsctx.FromContext(ctx)
	key := revision.Machine
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ParentEventID: origin.ParentEventID})
	credential, wire := t.Roles.assume(ctx,
		awsctx.ServicePrincipal{Name: "states.amazonaws.com", SourceARN: key.ARN(), Type: "AWSService"},
		revision.RoleARN, identity.RoleSessionSpec{SessionName: "StepFunctions_XRay"}, "")
	if wire != nil {
		return nil, wire
	}
	role, wire := serviceRoleRequestContext(ctx, credential, key.Region, "states.amazonaws.com")
	if wire != nil {
		return nil, wire
	}
	return role, nil
}

func (t *StepFunctionsTracing) PublishTrace(ctx context.Context, revision stepfunctions.RevisionRecord, documents []stepfunctions.TraceDocument) error {
	if len(documents) == 0 {
		return nil
	}
	role, err := t.roleContext(ctx, revision)
	if err != nil {
		return err
	}
	input := &xrayapi.PutTraceSegmentsRequest{TraceSegmentDocuments: make(xrayapi.TraceSegmentDocumentList, 0, len(documents))}
	for _, document := range documents {
		encoded, err := json.Marshal(document)
		if err != nil {
			return err
		}
		input.TraceSegmentDocuments = append(input.TraceSegmentDocuments, xrayapi.TraceSegmentDocument(encoded))
	}
	result, wire := t.Commands.CallTyped(role, "xray", "PutTraceSegments", input)
	if wire != nil {
		return wire
	}
	output, ok := result.Output.(*xrayapi.PutTraceSegmentsResult)
	if !ok || output == nil {
		return errors.New("X-Ray PutTraceSegments returned no result")
	}
	if len(output.UnprocessedTraceSegments) != 0 {
		return fmt.Errorf("X-Ray rejected %d trace documents", len(output.UnprocessedTraceSegments))
	}
	return nil
}

// Rules match the documented service name/type/resource ARN. Workflow admission
// is not an HTTP server request: host, method and URL have no invented values,
// and rules requiring attributes unavailable at admission cannot match.
// https://docs.aws.amazon.com/xray/latest/devguide/xray-console-sampling.html
func stepFunctionsSamplingRuleMatches(rule *xrayapi.SamplingRule, machine stepfunctions.MachineKey) bool {
	// TODO: Comeback verify Step Functions rule-field matching and quota timing; native scoped-rule captures did not establish selection.
	return rule != nil && rule.RuleName != nil && rule.Priority != nil && rule.FixedRate != nil && rule.ReservoirSize != nil &&
		len(rule.Attributes) == 0 && stepFunctionsTraceMatch(rule.ServiceName, machine.Name) &&
		stepFunctionsTraceMatch(rule.ServiceType, "AWS::StepFunctions::StateMachine") &&
		stepFunctionsTraceMatch(rule.ResourceARN, machine.ARN()) &&
		stepFunctionsTraceMatch(rule.Host, "") && stepFunctionsTraceMatch(rule.HTTPMethod, "") && stepFunctionsTraceMatch(rule.URLPath, "")
}

// X-Ray wildcards match across ARN separators; path.Match would not.
func stepFunctionsTraceMatch[T ~string](pattern *T, value string) bool {
	if pattern == nil {
		return false
	}
	p, v, star, retry := 0, 0, -1, 0
	text := string(*pattern)
	for v < len(value) {
		switch {
		case p < len(text) && (text[p] == '?' || text[p] == value[v]):
			p++
			v++
		case p < len(text) && text[p] == '*':
			star, retry = p, v
			p++
		case star >= 0:
			retry++
			p, v = star+1, retry
		default:
			return false
		}
	}
	for p < len(text) && text[p] == '*' {
		p++
	}
	return p == len(text)
}

func (t *StepFunctionsTracing) sample(ctx context.Context, execution stepfunctions.ExecutionRecord, revision stepfunctions.RevisionRecord) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var rule *xrayapi.SamplingRule
	request := &xrayapi.GetSamplingRulesRequest{}
	for {
		result, wire := t.Commands.CallTyped(ctx, "xray", "GetSamplingRules", request)
		if wire != nil {
			return false, wire
		}
		output, ok := result.Output.(*xrayapi.GetSamplingRulesResult)
		if !ok || output == nil {
			return false, errors.New("X-Ray GetSamplingRules returned no result")
		}
		for _, record := range output.SamplingRuleRecords {
			candidate := record.SamplingRule
			if stepFunctionsSamplingRuleMatches(candidate, revision.Machine) && (rule == nil || *candidate.Priority < *rule.Priority || *candidate.Priority == *rule.Priority && *candidate.RuleName < *rule.RuleName) {
				rule = candidate
			}
		}
		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		request.NextToken = output.NextToken
	}
	if rule == nil {
		return false, errors.New("X-Ray returned no matching sampling rule")
	}
	now := t.Clock.Now().UTC()
	key := revision.Machine.ARN() + ":" + string(*rule.RuleName)
	client := t.clients[key]
	if client == nil {
		if t.clients == nil {
			t.clients = make(map[string]*stepFunctionsSamplingClient)
		}
		client = &stepFunctionsSamplingClient{id: stepFunctionsSegmentID() + stepFunctionsSegmentID()[:8]}
		t.clients[key] = client
	}
	second, window := now.Truncate(time.Second), now.Truncate(10*time.Second)
	if !client.second.Equal(second) {
		client.second, client.used = second, 0
	}
	if !client.window.Equal(window) {
		client.window = window
		client.requests, client.sampled, client.borrowed = 0, 0, 0
	}
	// Borrow one request per second only until X-Ray grants an unexpired quota.
	// The client's lease and counters are disposable, like the X-Ray SDK; X-Ray
	// retains authoritative fleet allocation. No regional fleet timing is claimed.
	quota, borrowing := min(client.quota, int64(*rule.ReservoirSize)), !now.Before(client.quotaExpires)
	if borrowing {
		quota = 0
		if *rule.ReservoirSize > 0 {
			quota = 1
		}
	}
	digest := sha256.Sum256([]byte(execution.Key.ARN + ":" + execution.Started.UTC().Format(time.RFC3339Nano)))
	selected := float64(binary.BigEndian.Uint64(digest[:8])>>11)/(1<<53) < float64(*rule.FixedRate)
	if client.used < quota {
		client.used++
		selected = true
		if borrowing {
			client.borrowed++
		}
	}
	client.requests++
	if selected {
		client.sampled++
	}
	result, wire := t.Commands.CallTyped(ctx, "xray", "GetSamplingTargets", &xrayapi.GetSamplingTargetsRequest{SamplingStatisticsDocuments: xrayapi.SamplingStatisticsDocumentList{{
		RuleName: rule.RuleName, ClientID: new(xrayapi.ClientID(client.id)), Timestamp: &now,
		RequestCount: new(xrayapi.RequestCount(client.requests)), SampledCount: new(xrayapi.SampledCount(client.sampled)), BorrowCount: new(xrayapi.BorrowCount(client.borrowed)),
	}}})
	if wire != nil {
		return false, wire
	}
	output, ok := result.Output.(*xrayapi.GetSamplingTargetsResult)
	if !ok || output == nil {
		return false, errors.New("X-Ray GetSamplingTargets returned no result")
	}
	if len(output.UnprocessedStatistics) != 0 {
		return false, errors.New("X-Ray rejected sampling statistics")
	}
	for _, target := range output.SamplingTargetDocuments {
		if target.RuleName != nil && string(*target.RuleName) == string(*rule.RuleName) && target.ReservoirQuota != nil && target.ReservoirQuotaTTL != nil {
			client.quota, client.quotaExpires = int64(*target.ReservoirQuota), *target.ReservoirQuotaTTL
		}
	}
	return selected, nil
}

type stepFunctionsTraceObserverKey struct{}

type stepFunctionsTraceObserver struct {
	publisher *StepFunctionsTracing
	revision  stepfunctions.RevisionRecord
	trace     stepfunctions.TaskTrace
	optimized bool
	calls     atomic.Uint64
}

func (t *StepFunctionsTracing) taskContext(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord) context.Context {
	trace, ok := stepfunctions.TracingTask(ctx)
	if !ok {
		return ctx
	}
	observer := &stepFunctionsTraceObserver{publisher: t, revision: revision, trace: trace, optimized: !strings.Contains(task.Resource, ":aws-sdk:")}
	return context.WithValue(ctx, stepFunctionsTraceObserverKey{}, observer)
}

func (o *stepFunctionsTraceObserver) begin(ctx context.Context) (context.Context, string, time.Time) {
	started := o.publisher.Clock.Now()
	call := o.calls.Add(1)
	span := o.trace.CallSpanID
	if call > 1 {
		span = stepfunctions.TraceSpanID(span, "command", strconv.FormatUint(call, 10))
	}
	root, _, sampled, valid := stepFunctionsTraceHeader(o.trace.Header)
	if !valid {
		// Untraced task edges still carry independent unsampled correlation. This
		// is request metadata, never an invented public execution traceHeader.
		root, sampled = awsctx.NewTraceID(started), "0"
	}
	metadata := awsctx.FromContext(ctx)
	metadata.TraceHeader = "Root=" + root + ";Parent=" + span + ";Sampled=" + sampled
	ctx = awsctx.WithMetadata(ctx, metadata)
	// Nested commands and this observer's own X-Ray effects cannot reuse it.
	ctx = context.WithValue(ctx, stepFunctionsTraceObserverKey{}, (*stepFunctionsTraceObserver)(nil))
	return ctx, span, started
}

func (o *stepFunctionsTraceObserver) finish(ctx context.Context, span string, started time.Time, result StepFunctionsCommandResult, input any, wire *awswire.Error) {
	if o.trace.RedriveCount != 0 {
		return
	}
	metadata := awsctx.FromContext(ctx)
	root, _, sampled, _ := stepFunctionsTraceHeader(metadata.TraceHeader)
	// A configured SDK edge can exist without a supported workflow root
	// (Distributed Map). Retain its actual API span, not a fabricated root;
	// X-Ray then exposes the observed empty envelope for an orphaned trace.
	recording := sampled == "1" || o.trace.Header == "" && o.revision.TracingEnabled
	if !recording {
		return
	}
	ended := o.publisher.Clock.Now()
	end := stepfunctions.TraceTimestamp(ended)
	document := stepfunctions.TraceDocument{
		ID: span, Name: result.Service.SDKID, TraceID: root, ParentID: o.trace.StateSpanID, Type: "subsegment", Namespace: "aws",
		StartTime: stepfunctions.TraceTimestamp(started), EndTime: &end,
		AWS: map[string]any{"retries": 0, "region": metadata.Region, "operation": string(result.Operation.Name), "request_id": metadata.RequestID},
	}
	if o.optimized && result.Service.Name == "sqs" {
		if send, ok := input.(*sqsapi.SendMessageInput); ok && send.QueueUrl != nil {
			queue := string(*send.QueueUrl)
			document.AWS = map[string]any{"queue_url": queue, "operation": string(result.Operation.Name), "request_id": metadata.RequestID, "resource_names": []string{queue}}
			if output, ok := result.Output.(*sqsapi.SendMessageResult); ok && output != nil && output.MessageId != nil {
				document.AWS["message_id"] = string(*output.MessageId)
			}
		}
	}
	if wire == nil {
		response := result.Response
		var err error
		if response.StatusCode == 0 {
			response, err = awsapi.EncodeHTTPResponse(result.Service, result.Operation, result.Output)
		}
		if err == nil && response.Stream == nil {
			document.HTTP = &stepfunctions.TraceHTTP{Response: stepfunctions.TraceHTTPResponse{Status: response.StatusCode, ContentLength: int64(len(response.Body))}}
		}
	} else {
		document.HTTP = stepFunctionsTraceErrorResponse(ctx, result, wire)
		document.Fault = wire.StatusCode >= 500
		document.Error = !document.Fault
		document.Throttle = wire.StatusCode == http.StatusTooManyRequests || strings.Contains(strings.ToLower(wire.Code), "throttl")
		document.Cause = stepfunctions.TraceCause{Message: wire.Message, Exceptions: []stepfunctions.TraceException{{Message: wire.Message, Type: wire.Code, Remote: true}}}
	}
	// Observability cannot change the command's result or replay its side effects.
	if err := o.publisher.PublishTrace(ctx, o.revision, []stepfunctions.TraceDocument{document}); err != nil {
		slog.WarnContext(ctx, "Step Functions command trace delivery failed", "state_machine", o.revision.Machine.ARN(), "error", err)
	}
}

// Count the existing error encoder's actual bytes without retaining another
// response body or introducing an HTTP request to the destination service.
type stepFunctionsTraceResponse struct {
	header http.Header
	status int
	length int64
}

func (w *stepFunctionsTraceResponse) Header() http.Header    { return w.header }
func (w *stepFunctionsTraceResponse) WriteHeader(status int) { w.status = status }
func (w *stepFunctionsTraceResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.length += int64(len(body))
	return len(body), nil
}

func stepFunctionsTraceErrorResponse(ctx context.Context, result StepFunctionsCommandResult, wire *awswire.Error) *stepfunctions.TraceHTTP {
	writer := &stepFunctionsTraceResponse{header: make(http.Header)}
	request := (&http.Request{Method: result.Operation.HTTPMethod, Header: make(http.Header)}).WithContext(ctx)
	request.Header.Set("X-Amz-Target", result.Service.TargetPrefix+"."+string(result.Operation.Name))
	switch result.Service.Protocol {
	case awscatalog.RestJSON:
		awswire.RESTJSONError(writer, request, &result.Service, wire)
	case awscatalog.RestXML:
		awswire.RESTXMLError(writer, request, &result.Service, wire)
	case awscatalog.AWSQuery:
		awswire.QueryError(writer, request, result.Service.XMLNamespace, wire)
	case awscatalog.EC2Query:
		awswire.EC2QueryError(writer, request, wire)
	case awscatalog.RPCV2CBOR:
		awswire.RPCV2Error(writer, request, &result.Service, wire)
	default:
		awswire.JSONError(writer, request, wire)
	}
	return &stepfunctions.TraceHTTP{Response: stepfunctions.TraceHTTPResponse{Status: writer.status, ContentLength: writer.length}}
}

var _ stepfunctions.TracePublisher = (*StepFunctionsTracing)(nil)
