package autoscaling

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awswire"
)

// The template dependency supplies an already-resolved immutable configuration;
// these tests exercise admission races, not guest execution or EC2 resolution.
type admissionTemplateInstances struct{ Instances }

func (admissionTemplateInstances) Template(context.Context, api.LaunchTemplateSpecification) (api.LaunchTemplateSpecification, error) {
	return api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-admission")), Version: new(api.XmlStringMaxLen255("1"))}, nil
}

func TestPreparedGroupAdmissionDistinguishesConfigurationFromBookkeeping(t *testing.T) {
	for _, operation := range []string{"update", "refresh"} {
		for _, mutation := range []string{"bookkeeping", "membership", "role", "template", "incarnation", "deletion", "origin", "cause", "pending-warmup"} {
			t.Run(operation+"/"+mutation, func(t *testing.T) {
				s, ctx, group, source, _ := ownedControlService(t)
				s.instances = admissionTemplateInstances{}
				group.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-admission")), Version: new(api.XmlStringMaxLen255("1"))}
				text(&group.Data.HealthCheckType, "EC2")
				text(&group.Data.ServiceLinkedRoleARN, "arn:aws:iam::000000000000:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling")
				group.OriginEventID = "previous-request"
				group.ReconcileCause = "Previous capacity request."
				group.PendingInstanceWarmup = new(int32(180))
				if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutGroup(group) }); err != nil {
					t.Fatal(err)
				}
				requestCtx, err := apievents.Reserve(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var commit func(Transaction) error
				if operation == "update" {
					update, err := s.prepareUpdateAutoScalingGroup(requestCtx, &api.UpdateAutoScalingGroupInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, DefaultCooldown: new(api.Cooldown(49))})
					if err != nil {
						t.Fatal(err)
					}
					commit = func(tx Transaction) error { _, err := update(tx); return err }
				} else {
					refresh, err := s.prepareStartInstanceRefresh(requestCtx, &api.StartInstanceRefreshInput{AutoScalingGroupName: group.Data.AutoScalingGroupName})
					if err != nil {
						t.Fatal(err)
					}
					commit = func(tx Transaction) error { _, err := refresh(tx); return err }
				}

				// This is the actual scheduler completion that previously rejected
				// otherwise legal API requests during outside-transaction preparation.
				if err := s.finishGroupPass(ctx, group.Key, group.ID, group.Version, false, nil); err != nil {
					t.Fatal(err)
				}
				metricDeadline := source.Now().Add(time.Minute)
				var before GroupRecord
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					current, err := tx.Group(group.Key)
					if err != nil {
						return err
					}
					current.MetricAt = metricDeadline
					switch mutation {
					case "membership":
						member := transitionMember(current, "i-new-member", "InService", source.Now())
						if err := tx.PutInstance(member); err != nil {
							return err
						}
					case "role":
						text(&current.Data.ServiceLinkedRoleARN, "arn:aws:iam::000000000000:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling_new")
					case "template":
						text(&current.Data.LaunchTemplate.Version, "2")
					case "incarnation":
						current.ID = "replacement-group"
						text(&current.Data.AutoScalingGroupARN, current.Key.ARN(current.ID))
					case "deletion":
						current.Deleting = true
					case "origin":
						current.OriginEventID = "intervening-request"
					case "cause":
						current.ReconcileCause = "Intervening scaling cause."
					case "pending-warmup":
						current.PendingInstanceWarmup = new(int32(240))
					}
					before = cloneGroup(current)
					return tx.PutGroup(current)
				}); err != nil {
					t.Fatal(err)
				}
				err = s.repository.Update(requestCtx, commit)
				allowed := mutation == "bookkeeping" || mutation == "membership"
				if allowed {
					if err != nil {
						t.Fatalf("bookkeeping or independent membership prevented admission: %v", err)
					}
				} else {
					var rejected *awswire.Error
					if !errors.As(err, &rejected) || rejected.Code != "ResourceContention" {
						t.Fatalf("stale configuration admitted: %v", err)
					}
				}
				if err := s.repository.View(ctx, func(tx Reader) error {
					current, err := tx.Group(group.Key)
					if err != nil {
						return err
					}
					if !current.MetricAt.Equal(metricDeadline) {
						t.Fatal("prepared API overwrote the metric publication deadline")
					}
					if allowed {
						if current.Version != before.Version+1 || !current.ReconcileAt.Equal(source.Now()) {
							t.Fatal("admission did not advance the current scheduler generation and wakeup")
						}
						if operation == "update" && intValue(current.Data.DefaultCooldown) != 49 {
							t.Fatal("admission lost the requested configuration")
						}
						if mutation == "membership" {
							if _, err := tx.Instance(group.Key.Scope, "i-new-member"); err != nil {
								return err
							}
						}
					} else if !sameGroupConfiguration(current, before) || current.Version != before.Version || !current.ReconcileAt.Equal(before.ReconcileAt) {
						t.Fatal("rejected admission changed the current group")
					}
					refreshes, err := tx.Refreshes(group.Key)
					if err != nil {
						return err
					}
					if operation == "refresh" && allowed {
						if len(refreshes) != 1 || refreshes[0].GroupID != current.ID {
							t.Fatal("admission lost the refresh intent")
						}
						if mutation == "membership" && (len(refreshes[0].Members) != 1 || refreshes[0].Members[0].InstanceID != "i-new-member") {
							t.Fatal("refresh did not capture the current membership cohort")
						}
					} else if len(refreshes) != 0 {
						t.Fatal("rejected refresh admission left a refresh intent")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
