package ssmcommands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// AlarmConfiguration retains the single named CloudWatch alarm admitted by SSM.
// Neither CloudWatch state nor IAM policy/credentials are configuration snapshots.
type AlarmConfiguration struct {
	Name              string
	IgnorePollFailure bool
}

// AlarmPoll is the durable, revision-fenced position of the shared scheduler.
// RoleID binds monitoring to the service-linked role incarnation admitted by IAM.
type AlarmPoll struct {
	RoleID         string
	Due            time.Time
	Revision       uint64
	Checked        bool
	TriggeredState string
	LastError      string
}

// Alarms prepares the current service-linked-role relationship at admission and
// reads current CloudWatch state outside the SSM write transaction on each poll.
type Alarms interface {
	Prepare(context.Context, Command) (string, error)
	State(context.Context, Command) (string, error)
}

// This is a deterministic local scheduling choice, not a measured AWS cadence.
const alarmPollInterval = 5 * time.Second

type alarmAdmissionKey struct{}
type alarmAdmission struct {
	command Command
}

func (s *Service) prepareAlarmRequest(ctx context.Context, input any) (context.Context, error) {
	in, ok := input.(*api.SendCommandRequest)
	if !ok || in.AlarmConfiguration == nil {
		return ctx, nil
	}
	config := in.AlarmConfiguration
	if len(config.Alarms) != 1 {
		return ctx, failure("ValidationException", "AlarmConfiguration requires exactly one alarm.")
	}
	name := value(config.Alarms[0].Name)
	if strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 255 {
		return ctx, failure("ValidationException", "Alarm names must contain 1 to 255 characters and cannot be blank.")
	}
	if s.alarms == nil || s.documents == nil {
		return ctx, failure("InternalServerError", "Run Command alarm monitoring is not configured.")
	}
	doc, err := s.documents.Resolve(ctx, value(in.DocumentName), value(in.DocumentVersion))
	if err != nil {
		return ctx, err
	}
	if err = s.authorize(ctx, "ssm:SendCommand", doc.ARN, doc.Tags, doc.Shared); err != nil {
		return ctx, err
	}
	cmd := Command{Key: keyFor(ctx, uuid.NewString()), Alarm: &AlarmConfiguration{Name: name, IgnorePollFailure: boolValue(config.IgnorePollAlarmFailure)}}
	cmd.AlarmPoll.RoleID, err = s.alarms.Prepare(ctx, cmd)
	if err != nil {
		return ctx, err
	}
	state, pollErr := s.alarms.State(ctx, cmd)
	state = alarmState(state, pollErr)
	if state == "ALARM" || state == "UNKNOWN" && !cmd.Alarm.IgnorePollFailure {
		return ctx, failure("ValidationException", fmt.Sprintf("The following Cloudwatch alarm(s) were not in a compliant state: %s in state: %s", name, state))
	}
	cmd.AlarmPoll.Checked = true
	cmd.AlarmPoll.Revision = 1
	cmd.AlarmPoll.Due = s.clock.Now().UTC().Add(alarmPollInterval)
	if pollErr != nil {
		cmd.AlarmPoll.LastError = pollErr.Error()
	}
	return context.WithValue(ctx, alarmAdmissionKey{}, alarmAdmission{command: cmd}), nil
}

func alarmState(state string, err error) string {
	if err == nil {
		switch state {
		case "OK", "INSUFFICIENT_DATA", "ALARM":
			return state
		}
	}
	return "UNKNOWN"
}

func alarmFailureDetails(state string) string {
	if state == "UNKNOWN" {
		return "FailedDueToUnknownAlarmState"
	}
	return "FailedDueToAlarm"
}

type alarmJobs struct{ s *Service }

func (j alarmJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var cmd Command
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		cmd, err = r.NextAlarmPoll()
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	key, err := json.Marshal(cmd.Key)
	return scheduler.Job{Key: string(key), Version: cmd.AlarmPoll.Revision, Due: cmd.AlarmPoll.Due}, err == nil, err
}

func (j alarmJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key Key
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	eligible := func(cmd Command) bool {
		return cmd.Alarm != nil && !terminal(cmd.Status) && cmd.Status != "Cancelling" && cmd.AlarmPoll.Revision == job.Version && cmd.AlarmPoll.Due.Equal(job.Due) && !job.Due.After(j.s.clock.Now())
	}
	var cmd Command
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		cmd, err = r.Command(key)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil || !eligible(cmd) {
		return err
	}
	metadata := awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ParentEventID: cmd.ParentEventID}
	var state string
	if j.s.alarms == nil {
		err = errors.New("Run Command alarm monitoring is not configured")
	} else {
		// IAM assumption and CloudWatch observation must never run under the SSM
		// write transaction. Revalidate the selected revision before committing.
		state, err = j.s.alarms.State(awsctx.WithMetadata(ctx, metadata), cmd)
	}
	state = alarmState(state, err)
	pollErr := err
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Command(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || !eligible(current) {
			return err
		}
		current.AlarmPoll.Checked = true
		current.AlarmPoll.Revision++
		current.AlarmPoll.LastError = ""
		if pollErr != nil {
			current.AlarmPoll.LastError = pollErr.Error()
		}
		current.AlarmPoll.Due = j.s.clock.Now().UTC().Add(alarmPollInterval)
		if state == "ALARM" || state == "UNKNOWN" && !current.Alarm.IgnorePollFailure {
			current.AlarmPoll.TriggeredState = state
			current.AlarmPoll.Due = time.Time{}
			invs, err := tx.Invocations(key)
			if err != nil {
				return err
			}
			for i := range invs {
				inv := &invs[i]
				if terminal(inv.Status) {
					continue
				}
				inv.Status, inv.StatusDetails, inv.FinishedAt = "Failed", "Terminated", j.s.clock.Now().UTC()
				for n := range inv.Plugins {
					p := &inv.Plugins[n]
					if !terminal(p.Status) {
						*p = Plugin{Name: p.Name, Action: p.Action, Status: "Failed", StatusDetails: "Terminated", Code: -1}
					}
				}
				if err = j.s.putInvocation(tx, *inv); err != nil {
					return err
				}
			}
			current.Status, current.StatusDetails = "Failed", alarmFailureDetails(state)
		}
		return j.s.putCommand(tx, current)
	})
}

// WithAlarmRoleUsage holds the shared transaction through IAM's deletion decision.
func (s *Service) WithAlarmRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		regions, err := tx.AlarmRegions(partition, account)
		if err != nil {
			return err
		}
		return fn(tx.Context(), regions)
	})
}
