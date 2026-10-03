package autoscaling

import (
	"context"
	"errors"
	"fmt"
	"testing"

	api "stackd/internal/awsapi/autoscaling"
)

type refreshReplacementInstances struct {
	transitionInstances
	templateError error
}

func (i refreshReplacementInstances) Template(context.Context, api.LaunchTemplateSpecification) (api.LaunchTemplateSpecification, error) {
	return api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), Version: new(api.XmlStringMaxLen255("2"))}, i.templateError
}

func TestRefreshRoundedBoundsChooseReplacementOrder(t *testing.T) {
	for _, test := range []struct {
		name           string
		desired        int64
		minimum        int64
		maximum        *api.IntPercent100To200
		warmup         int64
		launches       int
		retirements    int
		templateDenied bool
	}{
		{name: "one-ninety-omitted", desired: 1, minimum: 90, launches: 1, retirements: 1},
		{name: "one-ninety-explicit", desired: 1, minimum: 90, maximum: new(api.IntPercent100To200(100)), launches: 1},
		{name: "one-hundred-omitted", desired: 1, minimum: 100, launches: 1, retirements: 1},
		{name: "one-hundred-explicit", desired: 1, minimum: 100, maximum: new(api.IntPercent100To200(100)), launches: 1},
		{name: "two-rounded-explicit", desired: 2, minimum: 90, maximum: new(api.IntPercent100To200(120)), launches: 1},
		{name: "two-rounded-omitted", desired: 2, minimum: 90, launches: 1, retirements: 1},
		{name: "two-room-to-retire", desired: 2, minimum: 50, maximum: new(api.IntPercent100To200(100)), retirements: 1},
		{name: "two-room-to-launch", desired: 2, minimum: 100, maximum: new(api.IntPercent100To200(150)), launches: 1},
		{name: "warmup-over-two-days", desired: 1, minimum: 90, maximum: new(api.IntPercent100To200(100)), warmup: 172801, launches: 1},
		{name: "concurrent-launch-denied", desired: 1, minimum: 100, templateDenied: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			instances := refreshReplacementInstances{}
			if test.templateDenied {
				instances.templateError = errors.New("launch template access denied")
			}
			s.instances = instances
			g.Data.SuspendedProcesses = nil
			number(&g.Data.DesiredCapacity, test.desired)
			g.Data.LaunchTemplate = &api.LaunchTemplateSpecification{LaunchTemplateId: new(api.XmlStringMaxLen255("lt-refresh")), Version: new(api.XmlStringMaxLen255("1"))}
			members := make([]InstanceRecord, test.desired)
			for i := range members {
				members[i] = transitionMember(g, fmt.Sprintf("i-original-%d", i), "InService", source.Now())
				members[i].Data.LaunchTemplate = new(api.CloneLaunchTemplateSpecification(*g.Data.LaunchTemplate))
			}
			r := refreshFixture(g, source.Now(), members...)
			preferences, err := refreshPreferences(g, &api.RefreshPreferences{MinHealthyPercentage: new(api.IntPercent(test.minimum)), MaxHealthyPercentage: test.maximum, InstanceWarmup: new(api.RefreshInstanceWarmup(test.warmup))})
			if err != nil {
				t.Fatal(err)
			}
			r.Data.Preferences = &preferences
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutGroup(g); err != nil {
					return err
				}
				for _, member := range members {
					if err := tx.PutInstance(member); err != nil {
						return err
					}
				}
				return tx.PutRefresh(r)
			}); err != nil {
				t.Fatal(err)
			}
			refreshPasses(t, s, ctx, g, 4)
			if err := s.repository.View(ctx, func(tx Reader) error {
				current, err := tx.Instances(g.Key)
				if err != nil {
					return err
				}
				retirements := 0
				for _, member := range current {
					if member.TerminationRequested {
						retirements++
					}
				}
				activities, err := tx.Activities(g.Key.Scope, g.Key.Name, false)
				if err != nil {
					return err
				}
				launches, terminationActivities := 0, 0
				for _, activity := range activities {
					switch activity.Kind {
					case "launch":
						launches++
						if activity.InstanceWarmup == nil || int64(*activity.InstanceWarmup) != test.warmup || value(activity.LaunchTemplate.Version) != "2" {
							t.Fatalf("replacement lost requested target or warmup: %+v", activity)
						}
					case "terminate":
						terminationActivities++
					}
				}
				if launches != test.launches || retirements != test.retirements || terminationActivities != test.retirements {
					t.Fatalf("replacement ordering: launches=%d retiring=%d termination activities=%d; want launches=%d retiring=%d", launches, retirements, terminationActivities, test.launches, test.retirements)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
