// Command guardduty_smoke exercises a local executable; it never contacts AWS.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	it "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func check(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func code(err error, want string) {
	var e smithy.APIError
	if !errors.As(err, &e) || e.ErrorCode() != want {
		panic(fmt.Sprintf("want %s, got %v", want, err))
	}
}
func config(account, region string) aws.Config {
	return aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), RetryMaxAttempts: 1}
}
func client(endpoint, account, region string) *gd.Client {
	return gd.NewFromConfig(config(account, region), func(o *gd.Options) { o.BaseEndpoint = &endpoint })
}
func wait(ctx context.Context, f func() bool) {
	for !f() {
		select {
		case <-ctx.Done():
			panic(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func main() {
	if len(os.Args) != 2 {
		panic("usage: guardduty_smoke /absolute/path/to/stackd")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "stackd-guardduty-")
	must(err)
	fmt.Println("Evidence directory:", dir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	address := listener.Addr().String()
	must(listener.Close())
	endpoint := "http://" + address
	clockStart := time.Now().UTC().Format(time.RFC3339Nano)
	var cmd *exec.Cmd
	var log *os.File
	stop := func() {
		if cmd != nil {
			must(cmd.Process.Signal(os.Interrupt))
			must(cmd.Wait())
			must(log.Close())
			cmd = nil
		}
	}
	defer stop()
	start := func() {
		log, err = os.OpenFile(filepath.Join(dir, "controller.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		must(err)
		cmd = exec.Command(os.Args[1], "-listen", address, "-database", filepath.Join(dir, "state.db"), "-clock-start", clockStart)
		cmd.Stdout, cmd.Stderr = log, log
		must(cmd.Start())
		wait(ctx, func() bool {
			r, e := http.Get(endpoint + "/_stackd/health")
			if e != nil {
				return false
			}
			r.Body.Close()
			return r.StatusCode == 200
		})
	}
	start()
	const account = "123456789012"
	const region = "us-east-1"
	c := client(endpoint, account, region)
	roles := iam.NewFromConfig(config(account, region), func(o *iam.Options) { o.BaseEndpoint = &endpoint })
	features := []gt.DetectorFeatureConfiguration{}
	for _, name := range []string{"S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "RUNTIME_MONITORING", "AI_PROTECTION", "AI_ANALYST"} {
		features = append(features, gt.DetectorFeatureConfiguration{Name: gt.DetectorFeature(name), Status: gt.FeatureStatusDisabled})
	}
	authority(ctx, endpoint, roles, features)
	created, err := c.CreateDetector(ctx, &gd.CreateDetectorInput{Enable: aws.Bool(false), Features: features, ClientToken: aws.String("guardduty-smoke-token"), Tags: map[string]string{"owner": "smoke"}})
	must(err)
	id := created.DetectorId
	replay, err := c.CreateDetector(ctx, &gd.CreateDetectorInput{Enable: aws.Bool(true), ClientToken: aws.String("guardduty-smoke-token"), Tags: map[string]string{"owner": "changed"}})
	must(err)
	check(aws.ToString(replay.DetectorId) == aws.ToString(id), "detector replay changed identity")
	detector, err := c.GetDetector(ctx, &gd.GetDetectorInput{DetectorId: id})
	must(err)
	check(detector.Status == gt.DetectorStatusDisabled && detector.Tags["owner"] == "smoke", "replay changed detector")
	role, err := roles.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String("AWSServiceRoleForAmazonGuardDuty")})
	must(err)
	check(aws.ToString(role.Role.Arn) == aws.ToString(detector.ServiceRole), "wrong linked role")
	_, err = c.CreateDetector(ctx, &gd.CreateDetectorInput{Enable: aws.Bool(false), Features: features})
	code(err, "BadRequestException")
	_, err = client(endpoint, "222222222222", region).GetDetector(ctx, &gd.GetDetectorInput{DetectorId: id})
	code(err, "BadRequestException")
	_, err = client(endpoint, account, "us-west-2").GetDetector(ctx, &gd.GetDetectorInput{DetectorId: id})
	code(err, "BadRequestException")
	verifyEvents, cleanEvents := findingEvents(ctx, endpoint, "Backdoor:EC2/DenialOfService.Tcp", "")
	defer cleanEvents()
	_, err = c.CreateSampleFindings(ctx, &gd.CreateSampleFindingsInput{DetectorId: id})
	must(err)
	verifyEvents()
	ids := []string{}
	var token *string
	for {
		page, e := c.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: id, MaxResults: aws.Int32(37), NextToken: token, SortCriteria: &gt.SortCriteria{AttributeName: aws.String("type"), OrderBy: gt.OrderByAsc}})
		must(e)
		ids = append(ids, page.FindingIds...)
		token = page.NextToken
		if token == nil {
			break
		}
	}
	check(len(ids) == 444, fmt.Sprintf("sample inventory: %d, want native 444", len(ids)))
	seen := map[string]bool{}
	for _, id := range ids {
		check(!seen[id], "pagination duplicated finding")
		seen[id] = true
	}
	first, err := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: id, FindingIds: ids[:1]})
	must(err)
	finding := first.Findings[0]
	check(aws.ToString(finding.AccountId) == account && aws.ToString(finding.Region) == region, "sample scope not rebound")
	originalID := aws.ToString(finding.Id)
	sampleType := aws.ToString(finding.Type)
	_, err = c.CreateSampleFindings(ctx, &gd.CreateSampleFindingsInput{DetectorId: id, FindingTypes: []string{sampleType}})
	must(err)
	repeated, err := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: id, FindingIds: []string{originalID}})
	must(err)
	check(aws.ToInt32(repeated.Findings[0].Service.Count) == 2, "repeat did not increment original finding")
	_, err = c.UpdateFindingsFeedback(ctx, &gd.UpdateFindingsFeedbackInput{DetectorId: id, FindingIds: []string{originalID}, Feedback: gt.FeedbackUseful})
	must(err)
	_, err = c.ArchiveFindings(ctx, &gd.ArchiveFindingsInput{DetectorId: id, FindingIds: []string{originalID}})
	must(err)
	archived, err := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: id, FindingIds: []string{originalID}})
	must(err)
	check(aws.ToBool(archived.Findings[0].Service.Archived), "archive not retained")
	criterion := &gt.FindingCriteria{Criterion: map[string]gt.Condition{"type": {Equals: []string{sampleType}}}}
	_, err = c.CreateFilter(ctx, &gd.CreateFilterInput{DetectorId: id, Name: aws.String("suppression"), Action: gt.FilterActionArchive, FindingCriteria: criterion, Rank: aws.Int32(1), Tags: map[string]string{"owner": "smoke"}})
	must(err)
	_, err = c.CreateSampleFindings(ctx, &gd.CreateSampleFindingsInput{DetectorId: id, FindingTypes: []string{sampleType}})
	must(err)
	stats, err := c.GetFindingsStatistics(ctx, &gd.GetFindingsStatisticsInput{DetectorId: id, GroupBy: gt.GroupByTypeAccount})
	must(err)
	check(len(stats.FindingStatistics.GroupedByAccount) == 1, "missing account statistics")
	check(aws.ToInt32(stats.FindingStatistics.GroupedByAccount[0].TotalFindings) == 445, "statistics did not retain archived/new occurrence")
	job, err := roles.DeleteServiceLinkedRole(ctx, &iam.DeleteServiceLinkedRoleInput{RoleName: aws.String("AWSServiceRoleForAmazonGuardDuty")})
	must(err)
	wait(ctx, func() bool {
		v, e := roles.GetServiceLinkedRoleDeletionStatus(ctx, &iam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: job.DeletionTaskId})
		must(e)
		if v.Status == it.DeletionTaskStatusTypeFailed {
			check(len(v.Reason.RoleUsageList) == 1, "linked role missing detector dependency")
			return true
		}
		return false
	})
	verifyDestinationsRestart := publishingDestinations(ctx, endpoint, features)
	verifyIPListsRestart := ipLists(ctx, endpoint, id)
	verifyDetectionRestart := detections(ctx, endpoint, c, roles, id)
	stop()
	start()
	verifyDestinationsRestart()
	verifyDetectionRestart()
	verifyIPListsRestart()
	retained, err := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: id, FindingIds: []string{originalID}})
	must(err)
	check(aws.ToBool(retained.Findings[0].Service.Archived) && aws.ToString(retained.Findings[0].Service.UserFeedback) == "USEFUL", "restart lost finding mutations")
	filter, err := c.GetFilter(ctx, &gd.GetFilterInput{DetectorId: id, FilterName: aws.String("suppression")})
	must(err)
	check(filter.Action == gt.FilterActionArchive && filter.Tags["owner"] == "smoke", "restart lost filter")
	_, err = c.DeleteFilter(ctx, &gd.DeleteFilterInput{DetectorId: id, FilterName: aws.String("suppression")})
	must(err)
	_, err = c.DeleteDetector(ctx, &gd.DeleteDetectorInput{DetectorId: id})
	must(err)
	job, err = roles.DeleteServiceLinkedRole(ctx, &iam.DeleteServiceLinkedRoleInput{RoleName: aws.String("AWSServiceRoleForAmazonGuardDuty")})
	must(err)
	// Actual list ingestion issues role sessions. Deleting the detector removes
	// resource dependencies, but must not bypass IAM's active-session check.
	wait(ctx, func() bool {
		v, e := roles.GetServiceLinkedRoleDeletionStatus(ctx, &iam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: job.DeletionTaskId})
		must(e)
		check(v.Status != it.DeletionTaskStatusTypeSucceeded, "linked role deleted with live ingestion sessions")
		if v.Status != it.DeletionTaskStatusTypeFailed {
			return false
		}
		check(v.Reason != nil && strings.Contains(aws.ToString(v.Reason.Reason), "active sessions"), "unexpected linked-role deletion blocker")
		return true
	})
	advance, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/_stackd/clock", strings.NewReader(`{"advance":"1h"}`))
	must(err)
	advance.Header.Set("Content-Type", "application/json")
	advanced, err := http.DefaultClient.Do(advance)
	must(err)
	must(advanced.Body.Close())
	check(advanced.StatusCode == http.StatusOK, "could not expire ingestion role sessions")
	job, err = roles.DeleteServiceLinkedRole(ctx, &iam.DeleteServiceLinkedRoleInput{RoleName: aws.String("AWSServiceRoleForAmazonGuardDuty")})
	must(err)
	wait(ctx, func() bool {
		v, e := roles.GetServiceLinkedRoleDeletionStatus(ctx, &iam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: job.DeletionTaskId})
		must(e)
		check(v.Status != it.DeletionTaskStatusTypeFailed, "linked role still in use after detector deletion")
		return v.Status == it.DeletionTaskStatusTypeSucceeded
	})
	left, err := c.ListDetectors(ctx, &gd.ListDetectorsInput{})
	must(err)
	check(len(left.DetectorIds) == 0, "detector cleanup failed")
	payload, err := json.MarshalIndent(map[string]any{"sdk": "guardduty v1.96.0", "native_sample_count": 444, "restart": true, "linked_role_dependency_and_cleanup": true, "scope_isolation": true}, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(dir, "evidence.json"), payload, 0600))
	retention(dir)
	fmt.Println("GuardDuty signed SDK samples, criteria, statistics, scope isolation, linked role dependency, SQLite restart and cleanup: PASS")
}
