package ssmcommands

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awswire"
	"stackd/internal/services/ssmdocuments"
)

func (s *Service) sendCommand(tx Transaction, in *api.SendCommandRequest) (*api.SendCommandResult, error) {
	ctx := tx.Context()
	if s.documents == nil || s.instances == nil {
		return nil, failure("InternalServerError", "Managed execution dependencies are not configured.")
	}
	admission, monitored := ctx.Value(alarmAdmissionKey{}).(alarmAdmission)
	doc, err := s.documents.Resolve(ctx, value(in.DocumentName), value(in.DocumentVersion))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "ssm:SendCommand", doc.ARN, doc.Tags, doc.Shared); err != nil {
		return nil, err
	}
	if hash := value(in.DocumentHash); hash != "" && (value(in.DocumentHashType) != "Sha256" || hash != doc.Hash) {
		return nil, failure("InvalidDocument", "The selected document hash does not match.")
	}
	params := make(map[string][]string, len(in.Parameters))
	for k, values := range in.Parameters {
		v := make([]string, len(values))
		for i, p := range values {
			v[i] = string(p)
		}
		params[string(k)] = v
	}
	_, err = ssmdocuments.ValidateParameters(doc, params)
	if err != nil {
		return nil, err
	}
	executionTimeout, err := ssmdocuments.ExecutionTimeout(doc, params)
	if err != nil {
		return nil, err
	}
	content, err := ssmdocuments.JSONContent(doc)
	if err != nil {
		return nil, err
	}
	if len(in.InstanceIds) > 0 && len(in.Targets) > 0 {
		return nil, failure("InvalidParameters", "Specify either InstanceIds or Targets, not both.")
	}
	if len(in.InstanceIds) == 0 && len(in.Targets) == 0 {
		return nil, failure("InvalidParameters", "A command must specify InstanceIds or Targets.")
	}
	ids := make([]string, 0, len(in.InstanceIds))
	for _, id := range in.InstanceIds {
		ids = append(ids, string(id))
	}
	targets, groupName, groupEC2, err := commandTargets(in.Targets)
	if err != nil {
		return nil, err
	}
	var groupIDs []string
	groupDenied := false
	if groupName != "" {
		if s.resourceGroups == nil {
			return nil, failure("InternalServerError", "Resource Groups is not configured.")
		}
		groupIDs, err = s.resourceGroups.Instances(ctx, groupName)
		if err != nil {
			var wire *awswire.Error
			if !errors.As(err, &wire) || (wire.Code != "AccessDenied" && wire.Code != "AccessDeniedException" && wire.Code != "ForbiddenException") {
				return nil, err
			}
			groupDenied = true
		}
	}
	if len(targets) > 0 {
		nodes, err := tx.Nodes(scopeFor(ctx))
		if err != nil {
			return nil, err
		}
		for _, node := range nodes {
			if groupName != "" && (groupDenied || !groupEC2 || !slices.Contains(groupIDs, node.Key.ID)) {
				continue
			}
			instance, err := s.instances.Instance(ctx, node.Key.ID)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if instance.State != "running" {
				continue
			}
			matched := true
			for _, target := range targets {
				if strings.HasPrefix(target.Key, "resource-groups:") {
					continue
				}
				v := instance.ID
				if strings.HasPrefix(target.Key, "tag:") {
					var present bool
					v, present = instance.Tags[strings.TrimPrefix(target.Key, "tag:")]
					if !present {
						matched = false
						break
					}
				}
				if !slices.Contains(target.Values, v) && !((target.Key == "InstanceIds" || target.Key == "instanceids") && slices.Contains(target.Values, "*")) {
					matched = false
					break
				}
			}
			if matched {
				ids = append(ids, node.Key.ID)
			}
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	concurrency := value(in.MaxConcurrency)
	if concurrency == "" {
		concurrency = "50"
	}
	maxErrors := value(in.MaxErrors)
	if maxErrors == "" {
		maxErrors = "0"
	}
	limit, err := budget(concurrency, len(ids), false)
	if err != nil {
		return nil, err
	}
	errorsAllowed, err := budget(maxErrors, len(ids), true)
	if err != nil {
		return nil, err
	}
	timeout := int32(3600)
	if in.TimeoutSeconds != nil {
		timeout = int32(*in.TimeoutSeconds)
	}
	if timeout < 30 || timeout > 2592000 {
		return nil, failure("ValidationException", "TimeoutSeconds must be between 30 and 2592000.")
	}
	now := s.clock.Now().UTC()
	selector := value(in.DocumentVersion)
	if selector == "" {
		selector = "$DEFAULT"
	}
	commandKey := admission.command.Key
	if !monitored {
		commandKey = keyFor(ctx, uuid.NewString())
	}
	cmd := Command{Key: commandKey, DocumentName: doc.Name, DocumentVersion: selector, DocumentHash: doc.Hash, Content: string(content), Comment: value(in.Comment), Parameters: params, InstanceIDs: []string{}, Targets: targets, RequestedAt: now, DeliveryDeadline: now.Add(time.Duration(timeout)*time.Second + executionTimeout), TimeoutSeconds: timeout, MaxConcurrency: concurrency, MaxErrors: maxErrors, Concurrency: limit, ErrorBudget: errorsAllowed, OutputBucket: value(in.OutputS3BucketName), OutputPrefix: value(in.OutputS3KeyPrefix), OutputRegion: scopeFor(ctx).Region, Status: "Pending", StatusDetails: "Pending", ParentEventID: apievents.EventID(ctx)}
	if monitored {
		cmd.Alarm, cmd.AlarmPoll = admission.command.Alarm, admission.command.AlarmPoll
		roleID, err := s.alarms.Prepare(ctx, cmd)
		if err != nil {
			return nil, err
		}
		if roleID != cmd.AlarmPoll.RoleID {
			return nil, failure("ValidationException", "The alarm monitoring role changed while the command was being admitted.")
		}
	}
	for _, id := range in.InstanceIds {
		cmd.InstanceIDs = append(cmd.InstanceIDs, string(id))
	}
	if in.CloudWatchOutputConfig != nil {
		cmd.CloudWatchEnabled = boolValue(in.CloudWatchOutputConfig.CloudWatchOutputEnabled)
		cmd.LogGroup = value(in.CloudWatchOutputConfig.CloudWatchLogGroupName)
	}
	if cmd.CloudWatchEnabled && cmd.LogGroup == "" {
		cmd.LogGroup = "/aws/ssm/" + doc.Name
	}
	if err := s.configureNotifications(ctx, &cmd, in); err != nil {
		return nil, err
	}
	if err := validateCommandSize(cmd); err != nil {
		return nil, err
	}
	if !groupDenied && len(ids) == 0 {
		cmd.EmptyTargetReadyAt = now
	}
	if err = s.putCommand(tx, cmd); err != nil {
		return nil, err
	}
	if groupDenied {
		cmd.Status, cmd.StatusDetails = "Failed", "AccessDenied"
		if err = s.putCommand(tx, cmd); err != nil {
			return nil, err
		}
	}
	for _, id := range ids {
		node, err := tx.Node(keyFor(ctx, id))
		if errors.Is(err, ErrNotFound) {
			return nil, failure("InvalidInstanceId", "The instance is not a managed node in this account and region.")
		}
		if err != nil {
			return nil, err
		}
		instance, err := s.instances.Instance(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return nil, failure("InvalidInstanceId", "The managed instance no longer exists.")
		}
		if err != nil {
			return nil, err
		}
		if instance.State != "running" {
			return nil, failure("InvalidInstanceId", "The managed EC2 instance is not running.")
		}
		if err = s.authorize(ctx, "ssm:SendCommand", instanceARN(node.Key), instance.Tags); err != nil {
			return nil, err
		}
		inv := Invocation{Key: InvocationKey{cmd.Key, id}, InstanceName: instance.Tags["Name"], Status: "Pending", StatusDetails: "Pending", DeliveryID: uuid.NewString()}
		for _, step := range doc.MainSteps {
			inv.Plugins = append(inv.Plugins, Plugin{Name: step.Name, Action: step.Action, Status: "Pending", StatusDetails: "Pending", Code: -1})
		}
		if err = s.putInvocation(tx, inv); err != nil {
			return nil, err
		}
	}
	invocations, err := tx.Invocations(cmd.Key)
	if err != nil {
		return nil, err
	}
	return &api.SendCommandResult{Command: commandOutput(cmd, invocations)}, nil
}
func budget(input string, total int, allowZero bool) (int, error) {
	percentage := strings.HasSuffix(input, "%")
	text := strings.TrimSuffix(input, "%")
	if text == "" || strings.HasPrefix(text, "+") || strings.HasPrefix(text, "-") {
		return 0, failure("ValidationException", "Invalid command concurrency/error budget.")
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 0 || (!allowZero && n == 0) || (percentage && n > 100) {
		return 0, failure("ValidationException", "Invalid command concurrency/error budget.")
	}
	if percentage {
		n = (n*total + 99) / 100
	}
	if !allowZero && n == 0 {
		n = 1
	}
	return n, nil
}
func (s *Service) cancelCommand(tx Transaction, in *api.CancelCommandRequest) (*api.CancelCommandResult, error) {
	if err := s.authorize(tx.Context(), "ssm:CancelCommand", "*", nil); err != nil {
		return nil, err
	}
	cmd, err := tx.Command(keyFor(tx.Context(), value(in.CommandId)))
	if errors.Is(err, ErrNotFound) {
		return nil, failure("InvalidCommandId", "Command does not exist.")
	}
	if err != nil {
		return nil, err
	}
	invs, err := tx.Invocations(cmd.Key)
	if err != nil {
		return nil, err
	}
	for _, id := range in.InstanceIds {
		if !slices.ContainsFunc(invs, func(v Invocation) bool { return v.Key.NodeID == string(id) }) {
			return nil, failure("InvalidInstanceId", "The instance is not targeted by this command.")
		}
	}
	if len(invs) == 0 && !cmd.EmptyTargetReadyAt.IsZero() && !terminal(cmd.Status) {
		cmd.Status, cmd.StatusDetails = "Cancelled", "Cancelled"
		cmd.EmptyTargetReadyAt = time.Time{}
	}
	for i := range invs {
		inv := &invs[i]
		if len(in.InstanceIds) > 0 && !slices.ContainsFunc(in.InstanceIds, func(v api.InstanceId) bool { return string(v) == inv.Key.NodeID }) {
			continue
		}
		if terminal(inv.Status) {
			continue
		}
		if inv.DeliveredAt.IsZero() {
			setInvocationTerminal(inv, "Cancelled", "Cancelled", s.clock.Now())
		} else {
			inv.Status = "Cancelling"
			inv.StatusDetails = "Cancelling"
			if inv.CancelID == "" {
				inv.CancelID = uuid.NewString()
				inv.CancelJobID = uuid.NewString()
				inv.CancelAcknowledged = false
				inv.RetryAt = time.Time{}
			}
		}
		if err = s.putInvocation(tx, *inv); err != nil {
			return nil, err
		}
	}
	aggregate(&cmd, invs)
	if err = s.putCommand(tx, cmd); err != nil {
		return nil, err
	}
	return &api.CancelCommandResult{}, nil
}
func jobID(command, node string) string { return fmt.Sprintf("aws.ssm.%s.%s", command, node) }
