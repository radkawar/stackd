package scheduler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/scheduler"
	"stackd/internal/awsschedule"
)

func (s *Service) registerSchedules() {
	register(s, "CreateSchedule", s.createSchedule)
	register(s, "UpdateSchedule", s.updateSchedule)
	register(s, "GetSchedule", s.getSchedule)
	register(s, "ListSchedules", s.listSchedules)
	register(s, "DeleteSchedule", s.deleteSchedule)
}

func (s *Service) prepareSchedule(tx Transaction, in *api.CreateScheduleInput, update bool) (ScheduleRecord, error) {
	k := ScheduleKey{
		Group: GroupKey{
			scopeFor(tx.Context()),
			groupName(value(in.GroupName)),
		},
		Name: value(in.Name),
	}
	v := ScheduleRecord{
		Key:                   k,
		Expression:            value(in.ScheduleExpression),
		Timezone:              value(in.ScheduleExpressionTimezone),
		State:                 value(in.State),
		Description:           value(in.Description),
		HasDescription:        in.Description != nil,
		ActionAfterCompletion: value(in.ActionAfterCompletion),
		Start:                 in.StartDate,
		End:                   in.EndDate,
		KmsKeyARN:             value(in.KmsKeyArn),
	}
	if !validName(k.Name) || !validName(k.Group.Name) {
		return v, failure("ValidationException", "Invalid schedule or group name.")
	}
	g, err := s.group(tx, k.Group)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	action := "CreateSchedule"
	if update {
		action = "UpdateSchedule"
	}
	if rejected := s.authorize(tx, action, k.ARN(), g.Tags, map[string][]string{"scheduler:GroupName": {k.Group.Name}}); rejected != nil {
		return v, rejected
	}
	if err != nil {
		return v, err
	}
	v.ParentID = g.ID
	old, err := tx.Schedule(k)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if update && errors.Is(err, ErrNotFound) {
		return v, err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return v, err
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	token := value(in.ClientToken)
	if !errors.Is(err, ErrNotFound) && old.Revision != 0 {
		if err := cloudFormationScheduleCheck(tx.Context(), old.CFNOwner); err != nil {
			return v, err
		}
		if old.ParentID != g.ID {
			return v, failure("ConflictException", "Schedule parent incarnation changed.", 409)
		}
		if !update && token != "" && old.CreateToken == token && old.CreateHash == hash {
			return old, nil
		}
		if update && token != "" && old.UpdateToken == token && old.UpdateHash == hash {
			return old, nil
		}
		if !update {
			return v, failure("ConflictException", "A schedule with this name already exists.", 409)
		}
	}
	if v.Timezone == "" {
		if in.ScheduleExpressionTimezone != nil {
			return v, failure("ValidationException", "Invalid timezone.")
		}
		v.Timezone = "UTC"
	}
	calendar, err := awsschedule.ParseScheduler(v.Expression, v.Timezone)
	if err != nil {
		return v, failure("ValidationException", "Invalid schedule expression or timezone.")
	}
	if v.State == "" {
		v.State = "ENABLED"
	}
	if v.State != "ENABLED" && v.State != "DISABLED" {
		return v, failure("ValidationException", "Invalid state.")
	}
	if v.ActionAfterCompletion == "" {
		v.ActionAfterCompletion = "NONE"
	}
	if v.ActionAfterCompletion != "NONE" && v.ActionAfterCompletion != "DELETE" {
		return v, failure("ValidationException", "Invalid action after completion.")
	}
	if in.FlexibleTimeWindow == nil {
		return v, failure("ValidationException", "FlexibleTimeWindow is required.")
	}
	v.WindowMode = value(in.FlexibleTimeWindow.Mode)
	v.HasWindowMinutes = in.FlexibleTimeWindow.MaximumWindowInMinutes != nil
	if v.HasWindowMinutes {
		v.WindowMinutes = int(*in.FlexibleTimeWindow.MaximumWindowInMinutes)
	}
	if v.WindowMode != "OFF" && v.WindowMode != "FLEXIBLE" || v.WindowMode == "FLEXIBLE" && !v.HasWindowMinutes || v.HasWindowMinutes && (v.WindowMinutes < 1 || v.WindowMinutes > 1440) {
		return v, failure("ValidationException", "Invalid flexible time window.")
	}
	once := strings.HasPrefix(v.Expression, "at(")
	if !once && v.Start != nil && v.End != nil && !v.End.After(*v.Start) {
		return v, failure("ValidationException", "EndDate must be after StartDate.")
	}
	now := s.clock.Now()
	v.Created = now
	v.Modified = now
	v.Revision = 1
	v.CreateToken = token
	v.CreateHash = hash
	v.CFNOwner = cloudFormationScheduleClaim(tx.Context())
	if update {
		v.CFNOwner = old.CFNOwner
		v.ParentID = old.ParentID
		v.Created = old.Created
		v.Revision = old.Revision + 1
		v.CreateToken = old.CreateToken
		v.CreateHash = old.CreateHash
		v.UpdateToken = token
		v.UpdateHash = hash
	}
	if v.State == "ENABLED" {
		anchor := now
		if !once && v.Start != nil {
			anchor = *v.Start
		}
		var next time.Time
		var ok bool
		if strings.HasPrefix(v.Expression, "rate(") {
			next, ok = calendar.First(anchor)
			if v.Start != nil && next.Before(now) {
				next, ok = calendar.NextAfter(next, now.Add(-time.Nanosecond))
			}
		} else {
			if anchor.Before(now) {
				anchor = now
			}
			next, ok = calendar.Next(anchor.Add(-time.Nanosecond))
		}
		if ok && (once || v.End == nil || !next.After(*v.End)) {
			v.Next = &next
		}
	}
	v.Target, err = targetInput(in.Target)
	if err != nil {
		return v, err
	}
	if s.delivery == nil {
		return v, unsupported("Scheduler target delivery is not configured.")
	}
	if rejected := s.delivery.ValidateTarget(tx.Context(), k, v.Target); rejected != nil {
		return v, rejected
	}
	role := strings.SplitN(v.Target.RoleARN, ":", 6)
	if len(role) != 6 || role[1] != k.Group.Partition || role[2] != "iam" || role[3] != "" || role[4] != k.Group.Account || !strings.HasPrefix(role[5], "role/") {
		return v, failure("ValidationException", "Execution role must be an IAM role in this account.")
	}
	if rejected := s.authorizer.Authorize(tx.Context(), authorization.Request{
		Action:         "iam:PassRole",
		ResourceARN:    v.Target.RoleARN,
		EvaluationTime: &now,
		Context: map[string][]string{
			"iam:PassedToService":       {"scheduler.amazonaws.com"},
			"iam:AssociatedResourceArn": {k.ARN()},
		},
	}); rejected != nil {
		return v, rejected
	}
	if s.roles == nil {
		return v, unsupported("Scheduler execution-role authority is not configured.")
	}
	if rejected := s.roles.ValidateRole(tx.Context(), k, v.Target.RoleARN); rejected != nil {
		return v, rejected
	}
	if v.KmsKeyARN != "" {
		if s.keys == nil {
			return v, unsupported("Scheduler customer-managed encryption is not configured.")
		}
		ciphertext, dataKey, keyARN, rejected := s.keys.Seal(tx.Context(), v.Key, v.KmsKeyARN, []byte(v.Target.Input))
		if rejected != nil {
			return v, rejected
		}
		v.Ciphertext, v.DataKey, v.KmsKeyARN = ciphertext, dataKey, keyARN
		v.Target.Input = ""
	}
	return v, nil
}

func (s *Service) createSchedule(tx Transaction, in *api.CreateScheduleInput) (*api.CreateScheduleOutput, error) {
	v, err := s.prepareSchedule(tx, in, false)
	if err != nil {
		return nil, err
	}
	if err = tx.PutSchedule(v); err != nil {
		return nil, err
	}
	return &api.CreateScheduleOutput{ScheduleArn: new(api.ScheduleArn(v.Key.ARN()))}, nil
}

func (s *Service) updateSchedule(tx Transaction, in *api.UpdateScheduleInput) (*api.UpdateScheduleOutput, error) {
	converted := api.CreateScheduleInput(*in)
	v, err := s.prepareSchedule(tx, &converted, true)
	if err != nil {
		return nil, err
	}
	if err = tx.PutSchedule(v); err != nil {
		return nil, err
	}
	return &api.UpdateScheduleOutput{ScheduleArn: new(api.ScheduleArn(v.Key.ARN()))}, nil
}

func (s *Service) schedule(tx Transaction, k ScheduleKey, action string) (ScheduleRecord, error) {
	g, err := s.group(tx, k.Group)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return ScheduleRecord{}, err
	}
	if rejected := s.authorize(tx, action, k.ARN(), g.Tags, map[string][]string{"scheduler:GroupName": {k.Group.Name}}); rejected != nil {
		return ScheduleRecord{}, rejected
	}
	if err != nil {
		return ScheduleRecord{}, err
	}
	row, err := tx.Schedule(k)
	if err == nil {
		err = cloudFormationScheduleCheck(tx.Context(), row.CFNOwner)
		if err == nil && row.ParentID != g.ID {
			err = failure("ConflictException", "Schedule parent incarnation changed.", 409)
		}
	}
	return row, err
}

func (s *Service) getSchedule(tx Transaction, in *api.GetScheduleInput) (*api.GetScheduleOutput, error) {
	k := ScheduleKey{
		Group: GroupKey{
			scopeFor(tx.Context()),
			groupName(value(in.GroupName)),
		},
		Name: value(in.Name),
	}
	v, err := s.schedule(tx, k, "GetSchedule")
	if err != nil {
		return nil, err
	}
	if v.KmsKeyARN != "" {
		if s.keys == nil {
			return nil, unsupported("Scheduler encryption is not configured.")
		}
		plain, rejected := s.keys.Open(tx.Context(), k, "", v.Ciphertext, v.DataKey)
		if rejected != nil {
			return nil, rejected
		}
		v.Target.Input = string(plain)
		clear(plain)
	}
	window := &api.FlexibleTimeWindow{Mode: new(api.FlexibleTimeWindowMode(v.WindowMode))}
	if v.HasWindowMinutes {
		window.MaximumWindowInMinutes = new(api.MaximumWindowInMinutes(v.WindowMinutes))
	}
	return &api.GetScheduleOutput{
		Arn:                        new(api.ScheduleArn(k.ARN())),
		Name:                       new(api.Name(k.Name)),
		GroupName:                  new(api.ScheduleGroupName(k.Group.Name)),
		CreationDate:               &v.Created,
		LastModificationDate:       &v.Modified,
		ScheduleExpression:         new(api.ScheduleExpression(v.Expression)),
		ScheduleExpressionTimezone: new(api.ScheduleExpressionTimezone(v.Timezone)),
		State:                      new(api.ScheduleState(v.State)),
		ActionAfterCompletion:      new(api.ActionAfterCompletion(v.ActionAfterCompletion)),
		Description:                optional[api.Description](v.Description, v.HasDescription),
		StartDate:                  v.Start,
		EndDate:                    v.End,
		FlexibleTimeWindow:         window,
		KmsKeyArn:                  optional[api.KmsKeyArn](v.KmsKeyARN, v.KmsKeyARN != ""),
		Target:                     targetOutput(v.Target),
	}, nil
}

func (s *Service) deleteSchedule(tx Transaction, in *api.DeleteScheduleInput) (*api.DeleteScheduleOutput, error) {
	k := ScheduleKey{
		Group: GroupKey{
			scopeFor(tx.Context()),
			groupName(value(in.GroupName)),
		},
		Name: value(in.Name),
	}
	if _, err := s.schedule(tx, k, "DeleteSchedule"); err != nil {
		return nil, err
	}
	if err := tx.DeleteScheduleDeliveries(k); err != nil {
		return nil, err
	}
	if err := tx.DeleteSchedule(k); err != nil {
		return nil, err
	}
	return &api.DeleteScheduleOutput{}, nil
}

func (s *Service) listSchedules(tx Transaction, in *api.ListSchedulesInput) (*api.ListSchedulesOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "ListSchedules", "*", nil, nil); err != nil {
		return nil, err
	}
	binding := "schedules:" + scopeBinding(scope) + ":" + value(in.GroupName) + ":" + value(in.NamePrefix) + ":" + value(in.State)
	last, n, err := pagination(value(in.NextToken), binding, in.MaxResults)
	if err != nil {
		return nil, err
	}
	lastGroup, lastName, _ := strings.Cut(last, "/")
	rows, err := tx.Schedules(scope)
	if err != nil {
		return nil, err
	}
	out := &api.ListSchedulesOutput{Schedules: api.ScheduleList{}}
	previous := ""
	for _, v := range rows {
		beforeCursor := v.Key.Group.Name < lastGroup || v.Key.Group.Name == lastGroup && v.Key.Name <= lastName
		if beforeCursor || in.GroupName != nil && value(in.GroupName) != v.Key.Group.Name || in.State != nil && value(in.State) != v.State || !strings.HasPrefix(v.Key.Name, value(in.NamePrefix)) {
			continue
		}
		if len(out.Schedules) == n {
			out.NextToken = nextToken(binding, previous)
			break
		}
		out.Schedules = append(out.Schedules, api.ScheduleSummary{
			Arn:                  new(api.ScheduleArn(v.Key.ARN())),
			Name:                 new(api.Name(v.Key.Name)),
			GroupName:            new(api.ScheduleGroupName(v.Key.Group.Name)),
			State:                new(api.ScheduleState(v.State)),
			CreationDate:         &v.Created,
			LastModificationDate: &v.Modified,
			Target:               &api.TargetSummary{Arn: new(api.TargetArn(v.Target.ARN))},
		})
		previous = v.Key.Group.Name + "/" + v.Key.Name
	}
	return out, nil
}
