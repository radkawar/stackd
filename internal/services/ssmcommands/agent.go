package ssmcommands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"stackd/internal/awsctx"
	"stackd/internal/services/ssmmessages"
)

// AuthorizeAgent binds transport to EC2-issued credentials, not a caller-supplied
// instance ID, source IP, role-session name or unsigned identity document.
func (s *Service) AuthorizeAgent(ctx context.Context, nodeID, action string) error {
	m := awsctx.FromContext(ctx)
	if s.credentials == nil || m.AccessKeyID == "" {
		return failure("AccessDeniedException", "An EC2 instance-profile credential is required.")
	}
	if _, err := s.credentials.Resolve(ctx, m.AccessKeyID); err != nil {
		return failure("AccessDeniedException", "The agent credential is no longer valid.")
	}
	if m.InScopeOf.IssuerType != "AWS::EC2::Instance" || m.InScopeOf.CredentialsIssuedTo != instanceARN(keyFor(ctx, nodeID)) {
		return failure("AccessDeniedException", "The signed credential was not issued to this managed instance.")
	}
	if s.instances == nil {
		return failure("InternalServerError", "EC2 identity authority is unavailable.")
	}
	instance, err := s.instances.Instance(ctx, nodeID)
	if errors.Is(err, ErrNotFound) {
		return failure("InvalidInstanceId", "The EC2 instance no longer exists.")
	}
	if err != nil {
		return err
	}
	if instance.State != "running" {
		return failure("InvalidInstanceId", "The EC2 instance is not running.")
	}
	return s.authorize(ctx, action, "*", nil)
}

type agentJob struct {
	Content, JobId, Topic string
	SchemaVersion         int
}
type sendPayload struct {
	Parameters                                                               map[string]any
	DocumentContent                                                          json.RawMessage
	CommandId, DocumentName, CloudWatchLogGroupName, CloudWatchOutputEnabled string
	OutputS3KeyPrefix                                                        string `json:",omitempty"`
	OutputS3BucketName                                                       string `json:",omitempty"`
}

func commandPayload(cmd Command) (sendPayload, error) {
	var doc struct {
		Parameters map[string]struct {
			Type string `json:"type"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal([]byte(cmd.Content), &doc); err != nil {
		return sendPayload{}, err
	}
	parameters := make(map[string]any, len(cmd.Parameters))
	for name, values := range cmd.Parameters {
		if doc.Parameters[name].Type == "String" {
			if len(values) != 1 {
				return sendPayload{}, fmt.Errorf("invalid retained String parameter %q", name)
			}
			parameters[name] = values[0]
		} else {
			parameters[name] = values
		}
	}
	return sendPayload{Parameters: parameters, DocumentContent: json.RawMessage(cmd.Content), CommandId: cmd.Key.ID, DocumentName: cmd.DocumentName, OutputS3KeyPrefix: cmd.OutputPrefix, OutputS3BucketName: cmd.OutputBucket, CloudWatchLogGroupName: cmd.LogGroup, CloudWatchOutputEnabled: fmt.Sprint(cmd.CloudWatchEnabled)}, nil
}

func encodeCommandPayload(payload sendPayload) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

// validateCommandSize measures the same payload sent to the official agent.
// Native admission bounds both the escaped parameter document and the complete
// execution payload at 100000 bytes ("97KB"). See managed_execution_admission*:
// strings become scalars, absent S3 destinations omit their members, HTML escapes
// apply to parameter admission but not the payload, and non-ASCII uses \u escapes.
// This one boundary also bounds the twice-encoded MGS job below its 1 MiB frame.
func validateCommandSize(cmd Command) error {
	payload, err := commandPayload(cmd)
	if err != nil {
		return err
	}
	encoded, err := encodeCommandPayload(payload)
	if err != nil {
		return err
	}
	parameters, err := json.Marshal(payload.Parameters)
	if err != nil {
		return err
	}
	if max(asciiJSONSize(encoded), asciiJSONSize(parameters)) > 100000 {
		return failure("MaxDocumentSizeExceeded", "The total size of your parameter(s) and document exceeds the 97KB limit.")
	}
	return nil
}

func asciiJSONSize(encoded []byte) int {
	size := len(encoded)
	for len(encoded) != 0 {
		r, width := utf8.DecodeRune(encoded)
		if r > 0x7f {
			escaped := 6
			if r > 0xffff {
				escaped = 12
			}
			size += escaped - width
		}
		encoded = encoded[width:]
	}
	return size
}

func sendMessage(cmd Command, inv Invocation) (ssmmessages.Message, error) {
	content, err := commandPayload(cmd)
	if err != nil {
		return ssmmessages.Message{}, err
	}
	payload, err := encodeCommandPayload(content)
	if err != nil {
		return ssmmessages.Message{}, err
	}
	return jobMessage(inv.DeliveryID, jobID(cmd.Key.ID, inv.Key.NodeID), "aws.ssm.sendCommand", payload, cmd.RequestedAt)
}
func jobMessage(id, job, topic string, content []byte, at time.Time) (ssmmessages.Message, error) {
	payload, err := json.Marshal(agentJob{Content: string(content), JobId: job, Topic: topic, SchemaVersion: 1})
	if err != nil {
		return ssmmessages.Message{}, err
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return ssmmessages.Message{}, err
	}
	return ssmmessages.Message{ID: parsed, Type: "agent_job", CreatedAt: at, Payload: payload}, nil
}

// PendingMessages commits delivery intent before bytes leave the controller.
// Reconnect retries carry the SAME message/job IDs. Agent disk state owns actual
// plugin execution and duplicate suppression; completed side effects are not rerun.
func (s *Service) PendingMessages(ctx context.Context, nodeID string) ([]ssmmessages.Message, error) {
	var messages []ssmmessages.Message
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.AuthorizeAgent(tx.Context(), nodeID, "ssmmessages:OpenControlChannel"); err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		node, err := tx.Node(keyFor(ctx, nodeID))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		// The real channel proves liveness, independently of the periodic agent API ping.
		if now.Sub(node.LastPing) >= time.Minute {
			node.LastPing = now
			if err = tx.PutNode(node); err != nil {
				return err
			}
		}
		invs, err := tx.NodeInvocations(node.Key)
		if err != nil {
			return err
		}
		for _, inv := range invs {
			if terminal(inv.Status) || inv.RetryAt.After(now) {
				continue
			}
			cmd, err := tx.Command(inv.Key.Command)
			if err != nil {
				return err
			}
			if !cmd.DeliveryDeadline.After(now) {
				continue
			}
			var msg ssmmessages.Message
			if inv.CancelID != "" && !inv.CancelAcknowledged {
				content, err := json.Marshal(struct {
					CancelMessageID string `json:"CancelMessageId"`
				}{jobID(cmd.Key.ID, nodeID)})
				if err != nil {
					return err
				}
				msg, err = jobMessage(inv.CancelID, jobID(inv.CancelJobID, nodeID), "aws.ssm.cancelCommand", content, now)
				if err != nil {
					return err
				}
			} else {
				if cmd.Alarm != nil && inv.DeliveredAt.IsZero() && (!cmd.AlarmPoll.Checked || !cmd.AlarmPoll.Due.After(now)) {
					// A due observation must settle before additional work is sent.
					continue
				}
				if inv.DeliveryAcknowledged || inv.CancelID != "" {
					continue
				}
				all, err := tx.Invocations(cmd.Key)
				if err != nil {
					return err
				}
				active, failed := 0, 0
				for _, other := range all {
					if !terminal(other.Status) && !other.DeliveredAt.IsZero() {
						active++
					}
					if other.Status == "Failed" || other.StatusDetails == "ExecutionTimedOut" {
						failed++
					}
				}
				if inv.DeliveredAt.IsZero() {
					if failed > cmd.ErrorBudget {
						setInvocationTerminal(&inv, "Cancelled", "Terminated", now)
						if err = s.putInvocation(tx, inv); err != nil {
							return err
						}
						continue
					}
					if active >= cmd.Concurrency {
						continue
					}
					inv.DeliveredAt = now
					inv.Status = "InProgress"
					inv.StatusDetails = "InProgress"
					cmd.Status = "InProgress"
					cmd.StatusDetails = "InProgress"
					if err = s.putCommand(tx, cmd); err != nil {
						return err
					}
				}
				msg, err = sendMessage(cmd, inv)
				if err != nil {
					return err
				}
			}
			inv.RetryAt = now.Add(10 * time.Second)
			if err = s.putInvocation(tx, inv); err != nil {
				return err
			}
			messages = append(messages, msg)
		}
		return nil
	})
	if err == nil {
		s.jobs.Wake()
	}
	return messages, err
}

type agentAck struct {
	JobID        string `json:"jobId"`
	MessageID    string `json:"acknowledgedMessageId"`
	StatusCode   string `json:"statusCode"`
	ErrorMessage string `json:"errorMessage"`
}
type agentReply struct {
	JobID         string `json:"jobId"`
	Content       string `json:"content"`
	Topic         string `json:"topic"`
	SchemaVersion int    `json:"schemaVersion"`
}
type agentResult struct {
	DocumentStatus      string                 `json:"documentStatus"`
	DocumentTraceOutput string                 `json:"documentTraceOutput"`
	RuntimeStatus       map[string]agentPlugin `json:"runtimeStatus"`
}
type agentPlugin struct {
	Status             string `json:"status"`
	Code               int32  `json:"code"`
	Name               string `json:"name"`
	StepName           string `json:"stepName"`
	Output             string `json:"output"`
	StandardOutput     string `json:"standardOutput"`
	StandardError      string `json:"standardError"`
	StartDateTime      string `json:"startDateTime"`
	EndDateTime        string `json:"endDateTime"`
	OutputS3BucketName string `json:"outputS3BucketName"`
	OutputS3KeyPrefix  string `json:"outputS3KeyPrefix"`
}

func commandFromJob(job, nodeID string) (string, error) {
	suffix := "." + nodeID
	if !strings.HasPrefix(job, "aws.ssm.") || !strings.HasSuffix(job, suffix) {
		return "", failure("InvalidParameters", "Invalid agent job identity.")
	}
	id := strings.TrimSuffix(strings.TrimPrefix(job, "aws.ssm."), suffix)
	if _, err := uuid.Parse(id); err != nil {
		return "", failure("InvalidParameters", "Invalid agent command identity.")
	}
	return id, nil
}
func (s *Service) ReceiveMessage(ctx context.Context, nodeID string, message ssmmessages.Message) error {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.AuthorizeAgent(tx.Context(), nodeID, "ssmmessages:OpenControlChannel"); err != nil {
			return err
		}
		var ack agentAck
		var reply agentReply
		var result agentResult
		var job string
		switch message.Type {
		case "agent_job_ack":
			if err := json.Unmarshal(message.Payload, &ack); err != nil {
				return err
			}
			job = ack.JobID
		case "agent_job_reply":
			if err := json.Unmarshal(message.Payload, &reply); err != nil {
				return err
			}
			if err := json.Unmarshal([]byte(reply.Content), &result); err != nil {
				return err
			}
			job = reply.JobID
		default:
			return failure("InvalidParameters", "Unsupported agent message type.")
		}
		commandID, err := commandFromJob(job, nodeID)
		if err != nil {
			return err
		}
		inv, err := tx.Invocation(InvocationKey{keyFor(ctx, commandID), nodeID})
		if errors.Is(err, ErrNotFound) {
			// Cancellation has its own job ID; it cannot address arbitrary node commands.
			invs, e := tx.NodeInvocations(keyFor(ctx, nodeID))
			if e != nil {
				return e
			}
			found := false
			for _, candidate := range invs {
				if candidate.CancelJobID == commandID {
					inv = candidate
					found = true
					break
				}
			}
			if !found {
				return failure("InvalidCommandId", "Agent job was not delivered to this node.")
			}
		} else if err != nil {
			return err
		}
		if slices.Contains(inv.ReplyIDs, message.ID.String()) {
			return nil
		}
		cancelJob := inv.CancelJobID == commandID
		now := s.clock.Now().UTC()
		if message.Type == "agent_job_ack" {
			expected := inv.DeliveryID
			if cancelJob {
				expected = inv.CancelID
			}
			if ack.MessageID != expected {
				return failure("InvalidParameters", "Acknowledgment does not match the delivered message.")
			}
			switch ack.StatusCode {
			case "200", "51405":
				if cancelJob {
					inv.CancelAcknowledged = true
				} else {
					inv.DeliveryAcknowledged = true
				}
			case "51401", "51402":
				inv.Trace = ack.ErrorMessage // agent queue/backpressure: same durable message remains eligible.
			default:
				if !terminal(inv.Status) {
					inv.Trace = ack.ErrorMessage
					setInvocationTerminal(&inv, "Failed", "Failed", now)
				}
			}
		} else if !cancelJob && inv.StatusDetails != "DeliveryTimedOut" && inv.StatusDetails != "Terminated" && !inv.DeliveredAt.IsZero() {
			inv.DeliveryAcknowledged = true
			if !terminal(inv.Status) {
				inv.Trace = result.DocumentTraceOutput
			}
			for name, reported := range result.RuntimeStatus {
				index := slices.IndexFunc(inv.Plugins, func(p Plugin) bool { return p.Name == name || p.Name == reported.StepName })
				if index < 0 {
					return failure("InvalidParameters", "Agent reported a plugin outside the admitted document.")
				}
				p := &inv.Plugins[index]
				if terminal(p.Status) {
					continue
				}
				status, details, err := agentStatus(reported.Status)
				if err != nil {
					return err
				}
				p.Status, p.StatusDetails, p.Code = status, details, reported.Code
				p.Output, p.StandardOutput, p.StandardError = reported.Output, reported.StandardOutput, reported.StandardError
				p.StartedAt, err = parseAgentTime(reported.StartDateTime)
				if err != nil {
					return err
				}
				p.FinishedAt, err = parseAgentTime(reported.EndDateTime)
				if err != nil {
					return err
				}
				p.OutputBucket, p.OutputPrefix = reported.OutputS3BucketName, reported.OutputS3KeyPrefix
				if !p.StartedAt.IsZero() && (inv.StartedAt.IsZero() || p.StartedAt.Before(inv.StartedAt)) {
					inv.StartedAt = p.StartedAt
				}
			}
			status, details, err := agentStatus(result.DocumentStatus)
			if err != nil {
				return err
			}
			// The official agent sends document completion and plugin results on
			// independent reply goroutines. Late plugin results must fill their
			// retained slots without reopening an already terminal invocation.
			if !terminal(inv.Status) {
				if inv.Status != "Cancelling" || terminal(status) {
					inv.Status, inv.StatusDetails = status, details
				}
				if terminal(inv.Status) {
					inv.FinishedAt = now
				}
			}
		}
		inv.ReplyIDs = append(inv.ReplyIDs, message.ID.String())
		if err = s.putInvocation(tx, inv); err != nil {
			return err
		}
		cmd, err := tx.Command(inv.Key.Command)
		if err != nil {
			return err
		}
		invs, err := tx.Invocations(cmd.Key)
		if err != nil {
			return err
		}
		failures := 0
		for _, v := range invs {
			if v.Status == "Failed" || v.StatusDetails == "ExecutionTimedOut" {
				failures++
			}
		}
		if failures > cmd.ErrorBudget {
			for i := range invs {
				v := &invs[i]
				if !terminal(v.Status) && v.DeliveredAt.IsZero() {
					setInvocationTerminal(v, "Cancelled", "Terminated", now)
					if err = s.putInvocation(tx, *v); err != nil {
						return err
					}
				}
			}
		}
		aggregate(&cmd, invs)
		return s.putCommand(tx, cmd)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}
func agentStatus(status string) (string, string, error) {
	switch status {
	case "NotStarted", "Pending":
		return "Pending", "Pending", nil
	case "InProgress":
		return "InProgress", "InProgress", nil
	case "SuccessAndReboot", "PassedAndReboot":
		return "InProgress", "InProgress", nil
	case "Success":
		return "Success", "Success", nil
	case "Failed":
		return "Failed", "Failed", nil
	case "Cancelled":
		return "Cancelled", "Cancelled", nil
	case "TimedOut":
		return "TimedOut", "ExecutionTimedOut", nil
	case "Skipped":
		return "Success", "Success", nil
	default:
		return "", "", failure("InvalidParameters", "Unknown agent document/plugin status: "+status)
	}
}
func parseAgentTime(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05.000000Z"} {
		if t, err := time.Parse(layout, text); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid agent result timestamp %q", text)
}
