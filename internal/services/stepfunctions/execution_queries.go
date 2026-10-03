package stepfunctions

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
)

func (s *Service) registerQueryOperations() {
	register(s, "DescribeExecution", s.describeExecution)
	register(s, "DescribeStateMachineForExecution", s.describeStateMachineForExecution)
	register(s, "GetExecutionHistory", s.getExecutionHistory)
	register(s, "ListExecutions", s.listExecutions)
	register(s, "DescribeMapRun", s.describeMapRun)
	register(s, "ListMapRuns", s.listMapRuns)
}

func executionMissing(raw string) error {
	return failure("ExecutionDoesNotExist", "Execution Does Not Exist: '"+raw+"'", 400)
}

// executionKeyFor validates identity and endpoint scope, without authorizing or
// requiring a retained execution. Internal sync consumers may use Express ARNs.
func executionKeyFor(r Reader, raw string) (ExecutionKey, error) {
	parts := strings.SplitN(raw, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "states" || parts[3] == "" || !accountPattern.MatchString(parts[4]) {
		return ExecutionKey{}, failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
	}
	resource := strings.Split(parts[5], ":")
	if len(resource) < 3 || resource[0] != "execution" && resource[0] != "express" {
		return ExecutionKey{}, failure("InvalidArn", "Invalid Arn: 'Resource type not valid in this context: "+resource[0]+"'", 400)
	}
	machine := strings.Split(resource[1], "/")
	if len(machine) > 2 || !validResourceName(machine[0]) || len(machine) == 2 && !validResourceName(machine[1]) || !validResourceName(resource[2]) || resource[0] == "execution" && len(resource) != 3 || resource[0] == "express" && (len(resource) != 4 || !validResourceName(resource[3])) {
		return ExecutionKey{}, failure("InvalidArn", "Invalid Arn: '"+raw+"'", 400)
	}
	key := ExecutionKey{Scope: Scope{Partition: parts[1], Region: parts[3], AccountID: parts[4]}, ARN: raw}
	if key.Scope != scopeFor(r.Context()) {
		return key, executionMissing(raw)
	}
	return key, nil
}

// retainedExecution is the common lifetime gate, also used after authorizing a
// Map Run. A deleting machine retains its executions until physical cleanup;
// a recreated ARN never exposes the old incarnation's executions.
func (s *Service) retainedExecution(r Reader, key ExecutionKey) (ExecutionRecord, MachineRecord, error) {
	execution, err := r.Execution(key)
	if errors.Is(err, ErrNotFound) {
		return ExecutionRecord{}, MachineRecord{}, executionMissing(key.ARN)
	}
	if err != nil {
		return ExecutionRecord{}, MachineRecord{}, err
	}
	machine, err := r.Machine(execution.Machine)
	now := s.clock.Now()
	if errors.Is(err, ErrNotFound) || err == nil && (machine.ID != execution.MachineID || execution.Expires != nil && !now.Before(*execution.Expires)) {
		return ExecutionRecord{}, MachineRecord{}, executionMissing(key.ARN)
	}
	return execution, machine, err
}

// executionFor is the single execution IAM/lifetime authority for public queries
// and Stop/callback/sync consumers. It does not impose public Express API limits.
func (s *Service) executionFor(r Reader, raw, action string) (ExecutionRecord, error) {
	key, keyErr := executionKeyFor(r, raw)
	if key.ARN == "" {
		return ExecutionRecord{}, keyErr
	}
	var execution ExecutionRecord
	var machine MachineRecord
	err := keyErr
	if err == nil {
		execution, machine, err = s.retainedExecution(r, key)
	}
	if denied := s.authorize(r, action, raw, machine.Tags, nil); denied != nil {
		return ExecutionRecord{}, denied
	}
	return execution, err
}

func (s *Service) publicExecutionFor(r Reader, raw, action string) (ExecutionRecord, error) {
	parts := strings.SplitN(raw, ":", 7)
	inspectMapChild := len(parts) == 7 && strings.Contains(parts[6], "/") && (action == "DescribeExecution" || action == "DescribeStateMachineForExecution")
	if len(parts) == 7 && parts[5] == "express" && !inspectMapChild {
		return ExecutionRecord{}, failure("InvalidArn", "Invalid Arn: 'Resource type not valid in this context: express'", 400)
	}
	execution, err := s.executionFor(r, raw, action)
	if err != nil {
		return ExecutionRecord{}, err
	}
	if execution.Type == "EXPRESS" && !inspectMapChild {
		return ExecutionRecord{}, unsupportedExecutionType()
	}
	return execution, nil
}

func unsupportedExecutionType() error {
	return failure("StateMachineTypeNotSupported", "This operation is not supported by this type of state machine", 400)
}

func includedExecutionData(in *api.IncludedData) error {
	if in != nil && value(in) != "ALL_DATA" && value(in) != "METADATA_ONLY" {
		return invalid("includedData must be ALL_DATA or METADATA_ONLY.")
	}
	return nil
}

func executionMachineARN(execution ExecutionRecord) string {
	if execution.MapRunARN != "" {
		return mapRunMachineARN(execution.MapRunARN)
	}
	return execution.Machine.ARN()
}

func executionQueryName(execution ExecutionRecord) string {
	if execution.Type == "EXPRESS" && execution.MapRunARN != "" {
		return execution.Name + execution.Key.ARN[strings.LastIndexByte(execution.Key.ARN, ':'):]
	}
	return execution.Name
}

func (s *Service) describeExecution(tx Transaction, in *api.DescribeExecutionInput) (*api.DescribeExecutionOutput, error) {
	execution, err := s.publicExecutionFor(tx, value(in.ExecutionArn), "DescribeExecution")
	if err != nil {
		return nil, err
	}
	if err := includedExecutionData(in.IncludedData); err != nil {
		return nil, err
	}
	if execution.Encrypted != nil {
		if value(in.IncludedData) == "METADATA_ONLY" {
			out := s.executionDescription(execution)
			out.Input, out.Output, out.Error, out.Cause = nil, nil, nil, nil
			out.InputDetails, out.OutputDetails = nil, nil
			return out, nil
		}
		revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
		if err != nil {
			return nil, err
		}
		execution, err = s.workflowReader(tx, revision, "").execution(execution)
		if err != nil {
			return nil, err
		}
	}
	return s.executionDescription(execution), nil
}

// executionDescription projects an already authorized, scoped retained record.
// Trusted execution waiters share this projection without invoking a public API.
func (s *Service) executionDescription(execution ExecutionRecord) *api.DescribeExecutionOutput {
	redriveStatus, reason := executionRedrive(execution, s.clock.Now())
	out := &api.DescribeExecutionOutput{
		ExecutionArn: new(api.Arn(execution.Key.ARN)), StateMachineArn: new(api.Arn(executionMachineARN(execution))),
		Name: new(api.Name(executionQueryName(execution))), Status: new(api.ExecutionStatus(execution.Status)), StartDate: controlTimestamp(execution.Started),
		Input: new(api.SensitiveData(execution.Input)), InputDetails: &api.CloudWatchEventsExecutionDataDetails{Included: new(api.IncludedDetails(true))},
		RedriveStatus: new(api.ExecutionRedriveStatus(redriveStatus)),
	}
	if execution.MapRunARN == "" || execution.Stopped != nil {
		out.RedriveCount = new(api.RedriveCount(execution.RedriveCount))
	}
	if execution.Stopped != nil {
		out.StopDate = controlTimestamp(*execution.Stopped)
	}
	if execution.Type == "STANDARD" && execution.Redriven != nil {
		out.RedriveDate = controlTimestamp(*execution.Redriven)
	}
	if execution.Status == "SUCCEEDED" {
		out.Output = new(api.SensitiveData(execution.Output))
		out.OutputDetails = &api.CloudWatchEventsExecutionDataDetails{Included: new(api.IncludedDetails(true))}
	}
	if execution.Error != "" {
		out.Error = new(api.SensitiveError(execution.Error))
	}
	if execution.Cause != "" {
		out.Cause = new(api.SensitiveCause(execution.Cause))
	}
	if execution.TraceHeader != "" {
		out.TraceHeader = new(api.TraceHeader(execution.TraceHeader))
	}
	if execution.VersionARN != "" {
		out.StateMachineVersionArn = new(api.Arn(execution.VersionARN))
	}
	if execution.AliasARN != "" {
		out.StateMachineAliasArn = new(api.Arn(execution.AliasARN))
	}
	if execution.MapRunARN != "" {
		out.MapRunArn = new(api.LongArn(execution.MapRunARN))
	}
	if reason != "" {
		out.RedriveStatusReason = new(api.SensitiveData(reason))
	}
	return out
}

// Eligibility is shared by admission and retained execution/Map Run queries.
func executionRedrive(execution ExecutionRecord, now time.Time) (string, string) {
	reason := ""
	switch {
	case execution.Status == "RUNNING" || execution.Status == "SUCCEEDED" || execution.Status == "PENDING":
		reason = "Execution is " + execution.Status + " and cannot be redriven"
	case execution.Started.Before(time.Date(2023, 11, 15, 0, 0, 0, 0, time.UTC)):
		reason = "Execution was started before the launch of RedriveExecution"
	case execution.NextHistoryID >= 24999:
		reason = "Execution history event limit exceeded"
	case !now.Before(execution.Started.Add(365 * 24 * time.Hour)):
		reason = "Execution has exceeded the max execution time"
	case execution.Stopped != nil && !now.Before(execution.Stopped.Add(14*24*time.Hour)):
		reason = "Execution redrivable period exceeded"
	}
	if reason != "" {
		return "NOT_REDRIVABLE", reason
	}
	if execution.MapRunARN != "" {
		return "REDRIVABLE_BY_MAP_RUN", ""
	}
	return "REDRIVABLE", ""
}

func (s *Service) describeStateMachineForExecution(tx Transaction, in *api.DescribeStateMachineForExecutionInput) (*api.DescribeStateMachineForExecutionOutput, error) {
	execution, err := s.publicExecutionFor(tx, value(in.ExecutionArn), "DescribeStateMachineForExecution")
	if err != nil {
		return nil, err
	}
	if err := includedExecutionData(in.IncludedData); err != nil {
		return nil, err
	}
	revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
	if err != nil {
		return nil, err
	}
	if revision.Encrypted != nil && value(in.IncludedData) == "METADATA_ONLY" {
		revision.Definition = "{}"
	} else {
		revision, err = s.openRevision(tx, revision, "")
		if err != nil {
			return nil, err
		}
	}
	out := &api.DescribeStateMachineForExecutionOutput{
		Definition: new(api.Definition(revision.Definition)), RoleArn: new(api.Arn(revision.RoleARN)), Name: new(api.Name(execution.Machine.Name)),
		StateMachineArn: new(api.Arn(executionMachineARN(execution))), UpdateDate: controlTimestamp(revision.Created), RevisionId: publicRevisionID(revision),
		EncryptionConfiguration: encryptionOutput(revision.EncryptionConfig), LoggingConfiguration: loggingOutput(revision), TracingConfiguration: &api.TracingConfiguration{Enabled: new(api.Enabled(revision.TracingEnabled))},
	}
	if execution.MapRunARN != "" {
		run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: execution.MapRunARN})
		if err != nil {
			return nil, err
		}
		out.MapRunArn, out.Label = new(api.LongArn(run.Key.ARN)), new(api.MapRunLabel(run.Label))
	}
	return out, nil
}

func (s *Service) getExecutionHistory(tx Transaction, in *api.GetExecutionHistoryInput) (*api.GetExecutionHistoryOutput, error) {
	execution, err := s.publicExecutionFor(tx, value(in.ExecutionArn), "GetExecutionHistory")
	if err != nil {
		return nil, err
	}
	reverse := in.ReverseOrder != nil && bool(*in.ReverseOrder)
	include := in.IncludeExecutionData == nil || bool(*in.IncludeExecutionData)
	filters, _ := json.Marshal([]any{execution.Key.ARN, reverse, include, in.MaxResults})
	collection := controlCollection(tx, "GetExecutionHistory", string(filters), executionIncarnation(execution))
	now := s.clock.Now()
	limit, after, err := controlPage(in.NextToken, in.MaxResults, collection, now)
	if err != nil {
		return nil, err
	}
	var afterID int64
	if after != "" {
		afterID, err = strconv.ParseInt(after, 10, 64)
		if err != nil || afterID <= 0 {
			return nil, failure("InvalidToken", "Invalid Token: 'Invalid token'", 400)
		}
	}
	rows, err := tx.History(execution.Key)
	if err != nil {
		return nil, err
	}
	// The projection flag does not bypass caller authorization to decrypt.
	var reader *workflowReader
	for i := range rows {
		if rows[i].Encrypted == nil {
			continue
		}
		if reader == nil {
			revision, err := tx.Revision(RevisionKey{Scope: execution.Key.Scope, ID: execution.RevisionID})
			if err != nil {
				return nil, err
			}
			reader = s.workflowReader(tx, revision, "")
		}
		rows[i], err = reader.history(rows[i])
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(rows, func(a, b HistoryRecord) int { return cmp.Compare(*a.Event.Id, *b.Event.Id) })
	if reverse {
		slices.Reverse(rows)
	}
	out := &api.GetExecutionHistoryOutput{Events: api.HistoryEventList{}}
	for _, row := range rows {
		id := int64(*row.Event.Id)
		if afterID != 0 && (!reverse && id <= afterID || reverse && id >= afterID) {
			continue
		}
		if len(out.Events) == limit {
			out.NextToken = controlNext(collection, after, now)
			break
		}
		event := api.CloneHistoryEvent(row.Event)
		if !include {
			omitHistoryData(&event)
		}
		out.Events = append(out.Events, event)
		after = strconv.FormatInt(id, 10)
	}
	return out, nil
}

// Omit only execution payloads. In particular, error/cause and the engine's
// actual causal previousEventId remain intact even when they contain user data.
func omitHistoryData(event *api.HistoryEvent) {
	if d := event.ActivityScheduledEventDetails; d != nil {
		d.Input, d.InputDetails = nil, nil
	}
	if d := event.ActivitySucceededEventDetails; d != nil {
		d.Output, d.OutputDetails = nil, nil
	}
	if d := event.ExecutionStartedEventDetails; d != nil {
		d.Input, d.InputDetails = nil, nil
	}
	if d := event.ExecutionSucceededEventDetails; d != nil {
		d.Output, d.OutputDetails = nil, nil
	}
	if d := event.LambdaFunctionScheduledEventDetails; d != nil {
		d.Input, d.InputDetails = nil, nil
	}
	if d := event.LambdaFunctionSucceededEventDetails; d != nil {
		d.Output, d.OutputDetails = nil, nil
	}
	if d := event.StateEnteredEventDetails; d != nil {
		d.Input, d.InputDetails = nil, nil
	}
	if d := event.StateExitedEventDetails; d != nil {
		d.Output, d.OutputDetails, d.AssignedVariables, d.AssignedVariablesDetails = nil, nil, nil, nil
	}
	if d := event.TaskScheduledEventDetails; d != nil {
		d.Parameters = nil
	}
	if d := event.TaskSubmittedEventDetails; d != nil {
		d.Output, d.OutputDetails = nil, nil
	}
	if d := event.TaskSucceededEventDetails; d != nil {
		d.Output, d.OutputDetails = nil, nil
	}
}

func executionIncarnation(execution ExecutionRecord) string {
	return execution.MachineID + "/" + execution.Started.UTC().Format(time.RFC3339Nano)
}

// A keyset cursor includes the timestamp and ARN tie-breaker, so expiry/deletion
// of the cursor's row cannot shift the next page or make the token unusable.
func queryPosition(at time.Time, arn string) string {
	return fmt.Sprintf("%020d/%s", math.MaxInt64-at.UnixNano(), arn)
}

func executionSortTime(execution ExecutionRecord) time.Time {
	if execution.Stopped != nil {
		return *execution.Stopped
	}
	return execution.Started
}

func (s *Service) listExecutions(tx Transaction, in *api.ListExecutionsInput) (*api.ListExecutionsOutput, error) {
	if (in.StateMachineArn == nil) == (in.MapRunArn == nil) {
		return nil, invalid("Specify exactly one of stateMachineArn or mapRunArn.")
	}
	status, redrive := value(in.StatusFilter), value(in.RedriveFilter)
	if in.StatusFilter != nil && !slices.Contains([]string{"RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED", "PENDING_REDRIVE"}, status) {
		return nil, invalid("Invalid statusFilter.")
	}
	if status == "PENDING_REDRIVE" && in.MapRunArn == nil {
		return nil, invalid("PENDING_REDRIVE requires mapRunArn.")
	}
	if in.RedriveFilter != nil && redrive != "REDRIVEN" && redrive != "NOT_REDRIVEN" {
		return nil, invalid("redriveFilter must be REDRIVEN or NOT_REDRIVEN.")
	}
	if in.RedriveFilter != nil && in.MapRunArn == nil {
		return nil, invalid("redriveFilter requires mapRunArn.")
	}
	selection := ExecutionSelection{Scope: scopeFor(tx.Context()), Status: status}
	var incarnation string
	if in.MapRunArn != nil {
		run, parent, err := s.mapRunFor(tx, value(in.MapRunArn), "ListExecutions")
		if err != nil {
			return nil, err
		}
		selection.MapRunARN, incarnation = run.Key.ARN, executionIncarnation(parent)
	} else {
		machine, qualifier, err := s.controlMachine(tx, value(in.StateMachineArn), "ListExecutions", false, false)
		if err != nil {
			return nil, err
		}
		if machine.Type == "EXPRESS" {
			return nil, unsupportedExecutionType()
		}
		selection.MachineID, incarnation = machine.ID, machine.ID
		// Qualification selects pinned admission identities, even after the
		// corresponding version or alias has been deleted.
		if qualifier != "" {
			if _, version := versionNumber(qualifier); version {
				selection.VersionARN = value(in.StateMachineArn)
			} else {
				selection.AliasARN = value(in.StateMachineArn)
			}
		}
	}
	filters, _ := json.Marshal([]any{in.StateMachineArn, in.MapRunArn, in.StatusFilter, in.RedriveFilter, in.MaxResults})
	collection := controlCollection(tx, "ListExecutions", string(filters), incarnation)
	var token *api.PageToken
	if in.NextToken != nil {
		token = new(api.PageToken(*in.NextToken))
	}
	now := s.clock.Now()
	limit, after, err := controlPage(token, in.MaxResults, collection, now)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Executions(selection)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rows, func(a, b ExecutionRecord) int {
		if order := executionSortTime(b).Compare(executionSortTime(a)); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.ARN, b.Key.ARN)
	})
	out := &api.ListExecutionsOutput{Executions: api.ExecutionList{}}
	for _, execution := range rows {
		if redrive == "REDRIVEN" && execution.RedriveCount == 0 || redrive == "NOT_REDRIVEN" && execution.RedriveCount != 0 {
			continue
		}
		if execution.Status == "PENDING" || in.MapRunArn == nil && execution.MapRunARN != "" {
			continue
		}
		if execution.Expires != nil && !now.Before(*execution.Expires) {
			continue
		}
		position := queryPosition(executionSortTime(execution), execution.Key.ARN)
		if position <= after {
			continue
		}
		if len(out.Executions) == limit {
			out.NextToken = new(api.ListExecutionsPageToken(*controlNext(collection, after, now)))
			break
		}
		item := api.ExecutionListItem{ExecutionArn: new(api.Arn(execution.Key.ARN)), StateMachineArn: new(api.Arn(executionMachineARN(execution))), Name: new(api.Name(executionQueryName(execution))), Status: new(api.ExecutionStatus(execution.Status)), StartDate: controlTimestamp(execution.Started), RedriveCount: new(api.RedriveCount(execution.RedriveCount))}
		if execution.Type == "STANDARD" && execution.Redriven != nil {
			item.RedriveDate = controlTimestamp(*execution.Redriven)
		}
		if execution.Stopped != nil {
			item.StopDate = controlTimestamp(*execution.Stopped)
		}
		if execution.VersionARN != "" {
			item.StateMachineVersionArn = new(api.Arn(execution.VersionARN))
		}
		if execution.AliasARN != "" {
			item.StateMachineAliasArn = new(api.Arn(execution.AliasARN))
		}
		if in.MapRunArn != nil {
			item.MapRunArn = new(api.LongArn(execution.MapRunARN))
			item.ItemCount = new(api.UnsignedInteger(execution.MapItemCount))
		}
		out.Executions = append(out.Executions, item)
		after = position
	}
	return out, nil
}
