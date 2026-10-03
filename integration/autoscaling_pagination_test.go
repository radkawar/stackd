package stackd_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"

	"stackd/clock"
)

// The retained native controls contain only one group. This test expands that
// exact zero-capacity configuration under three distinct names to verify local
// pagination, tenancy and current IAM invariants; it does not claim native page
// ordering, cursor encoding, or a captured multi-group AWS population.
func TestAutoScalingFixturePopulationPaginationAndCurrentIAM(t *testing.T) {
	fixture := asgFixture(t, "controls")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt.Add(-time.Minute))
			bindings := map[string]string{}
			clients, reopen := asgRetainedCloud(t, backend, fixture, source, bindings, nil)
			asgControlNetwork(t, clients, fixture, bindings)
			asgPrerequisite(t, clients, fixture.Region, fixture.row(t, "create-template"), bindings, nil)
			var names []string
			for i := range 3 {
				row := fixture.row(t, "create-group")
				input := ecsControlBody(t, row.Input)
				name := fmt.Sprintf("%s-page-%d", input["AutoScalingGroupName"], i)
				names = append(names, name)
				input["AutoScalingGroupName"] = name
				var err error
				row.Input, err = json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				asgReplay(t, clients, fixture.Region, row, bindings, asgRoot())
			}
			clients = reopen()
			_, key, secret := clients.user(t, "test", "asg-page-reader")
			identity := aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			putUserPolicy(t, clients.iam("test", "test", ""), "asg-page-reader", allow(`["autoscaling:DescribeAutoScalingGroups","autoscaling:DescribeTags"]`, "*"))
			client := asgClient(clients, fixture.Region, identity, clients.server.Client())
			request := &autoscaling.DescribeAutoScalingGroupsInput{MaxRecords: aws.Int32(1)}
			first, err := client.DescribeAutoScalingGroups(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if len(first.AutoScalingGroups) != 1 || aws.ToString(first.NextToken) == "" {
				t.Fatalf("first page did not partition three groups: %+v", first)
			}
			request.NextToken = first.NextToken
			t.Run("current-iam-on-retained-token", func(t *testing.T) {
				putUserPolicy(t, clients.iam("test", "test", ""), "asg-page-reader", `{"Statement":{"Effect":"Deny","Action":"autoscaling:DescribeAutoScalingGroups","Resource":"*"}}`)
				clients = reopen()
				client = asgClient(clients, fixture.Region, identity, clients.server.Client())
				_, err := client.DescribeAutoScalingGroups(t.Context(), request)
				assertAPIError(t, err, "AccessDenied")
				putUserPolicy(t, clients.iam("test", "test", ""), "asg-page-reader", allow(`["autoscaling:DescribeAutoScalingGroups","autoscaling:DescribeTags"]`, "*"))
			})
			t.Run("cross-region-and-account-isolation", func(t *testing.T) {
				for _, scope := range []struct{ region, key string }{{"eu-west-1", "test"}, {fixture.Region, "111122223333"}} {
					foreign := asgClient(clients, scope.region, aws.Credentials{AccessKeyID: scope.key, SecretAccessKey: "test"}, clients.server.Client())
					_, err := foreign.DescribeAutoScalingGroups(t.Context(), request)
					assertAPIError(t, err, "InvalidNextToken")
					groups, err := foreign.DescribeAutoScalingGroups(t.Context(), &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: names})
					if err != nil || len(groups.AutoScalingGroups) != 0 {
						t.Fatalf("foreign scope exposed groups: %+v, %v", groups, err)
					}
					_, err = foreign.SetDesiredCapacity(t.Context(), &autoscaling.SetDesiredCapacityInput{AutoScalingGroupName: &names[0], DesiredCapacity: aws.Int32(0)})
					assertAPIError(t, err, "ValidationError")
				}
			})
			t.Run("reopen-continuation-is-complete-and-unique", func(t *testing.T) {
				seen := []string{aws.ToString(first.AutoScalingGroups[0].AutoScalingGroupName)}
				for request.NextToken != nil {
					if len(seen) >= len(names) {
						t.Fatal("continuation did not terminate at the fixture population boundary")
					}
					clients = reopen()
					client = asgClient(clients, fixture.Region, identity, clients.server.Client())
					page, err := client.DescribeAutoScalingGroups(t.Context(), request)
					if err != nil {
						t.Fatal(err)
					}
					if len(page.AutoScalingGroups) != 1 {
						t.Fatalf("MaxRecords=1 returned %+v", page.AutoScalingGroups)
					}
					group := page.AutoScalingGroups[0]
					if aws.ToInt32(group.DesiredCapacity) != 0 || len(group.Instances) != 0 {
						t.Fatalf("zero-capacity fixture unexpectedly launched: %+v", group)
					}
					seen = append(seen, aws.ToString(group.AutoScalingGroupName))
					request.NextToken = page.NextToken
				}
				slices.Sort(seen)
				if !slices.Equal(names, seen) {
					t.Fatalf("pagination lost or duplicated fixture groups: got %v, want %v", seen, names)
				}
			})
			t.Run("tags-filtered-pages-preserve-propagation", func(t *testing.T) {
				client = asgClient(clients, fixture.Region, identity, clients.server.Client())
				input := &autoscaling.DescribeTagsInput{MaxRecords: aws.Int32(1), Filters: []asgtypes.Filter{{Name: aws.String("auto-scaling-group"), Values: names}, {Name: aws.String("key"), Values: []string{"inherited"}}}}
				var seen []string
				for {
					page, err := client.DescribeTags(t.Context(), input)
					if err != nil {
						t.Fatal(err)
					}
					if len(page.Tags) != 1 || len(seen) >= len(names) {
						t.Fatalf("filtered page outside three inherited tags: %+v", page)
					}
					tag := page.Tags[0]
					if aws.ToString(tag.Key) != "inherited" || aws.ToString(tag.Value) != "group" || !aws.ToBool(tag.PropagateAtLaunch) || aws.ToString(tag.ResourceType) != "auto-scaling-group" {
						t.Fatalf("tag page changed native configuration: %+v", tag)
					}
					seen = append(seen, aws.ToString(tag.ResourceId))
					if page.NextToken == nil {
						break
					}
					input.NextToken = page.NextToken
					clients = reopen()
					client = asgClient(clients, fixture.Region, identity, clients.server.Client())
				}
				slices.Sort(seen)
				if !slices.Equal(names, seen) {
					t.Fatalf("tag pages lost or duplicated groups: got %v, want %v", seen, names)
				}
			})
		})
	}
}
