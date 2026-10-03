package appconfig

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// appconfigJobs leases a retained generation before invoking customer code.
// Completion never publishes bytes after a concurrent stop or replacement.
type appconfigJobs struct{ s *Service }

func deploymentEnvironmentState(state string) string {
	switch state {
	case "ROLLING_BACK":
		return "RollingBack"
	case "ROLLED_BACK":
		return "RolledBack"
	case "REVERTED":
		return "Reverted"
	case "COMPLETE":
		return "ReadyForDeployment"
	default:
		return "Deploying"
	}
}
func deploymentJob(d Deployment) scheduler.Job {
	return scheduler.Job{Key: deploymentARN(d.Scope, d.ApplicationID, d.EnvironmentID, d.Number), Version: uint64(d.Generation), Due: d.Due}
}
func nextAppConfigDeployment(r Reader) (Deployment, bool, error) {
	rows, err := r.PendingDeployments()
	if err != nil {
		return Deployment{}, false, err
	}
	var selected Deployment
	found := false
	for _, d := range rows {
		if d.Due.IsZero() {
			continue
		}
		if !found || scheduler.Compare(deploymentJob(d), deploymentJob(selected)) < 0 {
			selected = d
			found = true
		}
	}
	return selected, found, nil
}
func (j appconfigJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var d Deployment
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error { var e error; d, found, e = nextAppConfigDeployment(r); return e })
	return deploymentJob(d), found, err
}
func deploymentSteps(d Deployment) int {
	if d.GrowthFactor <= 0 || d.GrowthFactor >= 100 {
		return 1
	}
	if d.GrowthType == "EXPONENTIAL" {
		return int(math.Ceil(math.Log2(100/d.GrowthFactor))) + 1
	}
	return int(math.Ceil(100 / d.GrowthFactor))
}
func deploymentProgress(d Deployment, now time.Time) float64 {
	if d.DurationMinutes == 0 {
		return 100
	}
	duration := time.Duration(d.DurationMinutes) * time.Minute
	elapsed := now.Sub(d.StartedAt)
	if elapsed >= duration {
		return 100
	}
	if elapsed <= 0 {
		return 0
	}
	step := int(float64(elapsed) / float64(duration) * float64(deploymentSteps(d)))
	if step == 0 {
		return 0
	}
	if d.GrowthType == "EXPONENTIAL" {
		return math.Min(100, d.GrowthFactor*math.Exp2(float64(step-1)))
	}
	return math.Min(100, d.GrowthFactor*float64(step))
}
func nextDeploymentDue(d Deployment, now time.Time) time.Time {
	if d.State == "VALIDATING" || d.State == "ROLLING_BACK" {
		return now
	}
	end := d.StartedAt.Add(time.Duration(d.DurationMinutes) * time.Minute)
	if d.State == "BAKING" {
		end = end.Add(time.Duration(d.FinalBakeMinutes) * time.Minute)
	} else if d.DurationMinutes > 0 {
		duration := time.Duration(d.DurationMinutes) * time.Minute
		steps := deploymentSteps(d)
		step := int(float64(now.Sub(d.StartedAt))/float64(duration)*float64(steps)) + 1
		if step < 1 {
			step = 1
		}
		end = d.StartedAt.Add(time.Duration(float64(duration) * float64(step) / float64(steps)))
	}
	if end.Before(now) {
		return now
	}
	if alarmTick := now.Add(time.Minute); alarmTick.Before(end) {
		return alarmTick
	}
	return end
}
func (j appconfigJobs) Run(ctx context.Context, selected scheduler.Job) error {
	var claim *Deployment
	var app Application
	var env Environment
	var profile Profile
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		d, found, e := nextAppConfigDeployment(tx)
		if e != nil || !found || deploymentJob(d) != selected {
			return e
		}
		now := j.s.clock.Now().UTC()
		if d.Due.After(now) {
			return nil
		}
		app, e = findApplication(tx, d.Scope, d.ApplicationID)
		if e != nil {
			return e
		}
		env, e = findEnvironment(tx, d.Scope, d.ApplicationID, d.EnvironmentID)
		if e != nil {
			return e
		}
		profile, e = findProfile(tx, d.Scope, d.ApplicationID, d.ProfileID)
		if e != nil {
			return e
		}
		d.Generation++
		d.Due = now.Add(30 * time.Second)
		if e = tx.PutDeployment(d); e != nil {
			return e
		}
		claim = &d
		return nil
	})
	if err != nil || claim == nil {
		return err
	}
	d := *claim
	effectCtx := scopedContext(ctx, d.Scope)
	principal := "appconfig.amazonaws.com"
	if d.Partition == "aws-cn" {
		principal = "appconfig.amazonaws.com.cn"
	}
	effectCtx = awsctx.WithServicePrincipal(effectCtx, awsctx.ServicePrincipal{Name: principal, SourceARN: envARN(d.Scope, d.ApplicationID, d.EnvironmentID), Type: "AWSService"})
	content := ConfigurationContent{Content: d.Content, ContentType: d.ContentType, Version: d.ConfigurationVersion, VersionLabel: d.VersionLabel, KMSKeyARN: d.KMSKeyARN}
	var invocations []ActionInvocation
	var rejected error
	if d.KMSKeyARN != "" && len(d.Extensions) > 0 {
		if j.s.effects == nil {
			rejected = failure("BadRequestException", "KMS decryption is not configured")
		} else {
			content.Content, rejected = j.s.effects.Unprotect(effectCtx, d.Scope, d.KMSKeyARN, deploymentARN(d.Scope, d.ApplicationID, d.EnvironmentID, d.Number), d.Content)
		}
	}
	invoke := func(point string) {
		if rejected != nil {
			return
		}
		_, _, actions, e := j.s.runExtensions(effectCtx, point, app, &env, &profile, content, &d)
		invocations = append(invocations, actions...)
		rejected = e
	}
	now := j.s.clock.Now().UTC()
	next := d
	kind := ""
	description := ""
	by := "APPCONFIG"
	if d.State == "ROLLING_BACK" {
		invoke("ON_DEPLOYMENT_ROLLED_BACK")
		next.State = "ROLLED_BACK"
		kind = "ROLLBACK_COMPLETED"
		description = "Deployment rolled back"
		if !d.CompletedAt.IsZero() {
			next.State = "REVERTED"
			kind = "REVERT_COMPLETED"
			description = "Deployment reverted"
		} else {
			next.CompletedAt = now
		}
		for _, event := range d.Events {
			if event.Type == "ROLLBACK_STARTED" {
				by = event.TriggeredBy
				break
			}
		}
		next.Due = time.Time{}
	} else {
		for _, monitor := range env.Monitors {
			if rejected != nil {
				break
			}
			if j.s.effects == nil {
				rejected = failure("BadRequestException", "CloudWatch alarm monitoring is not configured")
				by = "INTERNAL_ERROR"
				break
			}
			state, e := j.s.effects.Alarm(effectCtx, d.Scope, monitor)
			if e != nil {
				rejected = e
				by = "INTERNAL_ERROR"
			} else if state == "ALARM" || state == "INSUFFICIENT_DATA" {
				rejected = fmt.Errorf("CloudWatch alarm %s is %s", monitor.AlarmARN, state)
				by = "CLOUDWATCH_ALARM"
			}
		}
		invoke("AT_DEPLOYMENT_TICK")
		switch d.State {
		case "VALIDATING":
			invoke("ON_DEPLOYMENT_START")
			next.State = "DEPLOYING"
		case "DEPLOYING":
			next.Percentage = deploymentProgress(d, now)
			if next.Percentage > d.Percentage {
				invoke("ON_DEPLOYMENT_STEP")
				kind = "PERCENTAGE_UPDATED"
				description = fmt.Sprintf("Deployment reached %g percent", next.Percentage)
			}
			if next.Percentage >= 100 {
				invoke("ON_DEPLOYMENT_BAKING")
				next.State = "BAKING"
				kind = "BAKE_TIME_STARTED"
				description = "Deployment bake time started"
			}
		case "BAKING":
			if !now.Before(d.StartedAt.Add(time.Duration(d.DurationMinutes+d.FinalBakeMinutes) * time.Minute)) {
				invoke("ON_DEPLOYMENT_COMPLETE")
				next.State = "COMPLETE"
				next.CompletedAt = now
				kind = "DEPLOYMENT_COMPLETED"
				description = "Deployment completed"
			}
		}
		if rejected != nil {
			next.State = "ROLLING_BACK"
			next.CompletedAt = time.Time{}
			kind = "ROLLBACK_STARTED"
			description = rejected.Error()
		}
		if next.State == "COMPLETE" {
			next.Due = time.Time{}
		} else {
			next.Due = nextDeploymentDue(next, now)
		}
	}
	if kind != "" {
		addDeploymentEvent(&next, kind, by, description, now, invocations)
	} else if len(invocations) > 0 {
		addDeploymentEvent(&next, "PERCENTAGE_UPDATED", by, "Deployment extension actions invoked", now, invocations)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, e := findDeployment(tx, d.Scope, d.ApplicationID, d.EnvironmentID, d.Number)
		if e != nil {
			return e
		}
		if current.Generation != d.Generation || current.State != d.State || current.Due != d.Due {
			return nil
		}
		currentEnv, e := findEnvironment(tx, d.Scope, d.ApplicationID, d.EnvironmentID)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(currentEnv.Monitors, env.Monitors) {
			return nil
		}
		next.Generation++
		if e = tx.PutDeployment(next); e != nil {
			return e
		}
		currentEnv.State = deploymentEnvironmentState(next.State)
		return tx.PutEnvironment(currentEnv)
	})
}
