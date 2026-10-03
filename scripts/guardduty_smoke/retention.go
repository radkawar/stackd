package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// retention owns a separate clock and database so advances cannot stall the
// wall-clock detection and linked-role workflows in main.
func retention(evidenceDir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := filepath.Join(evidenceDir, "retention")
	must(os.Mkdir(dir, 0700))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	address := listener.Addr().String()
	must(listener.Close())
	endpoint := "http://" + address
	httpClient := &http.Client{Timeout: 10 * time.Second}
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
	start := func(initial bool) {
		log, err = os.OpenFile(filepath.Join(dir, "controller.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		must(err)
		args := []string{"-listen", address, "-database", filepath.Join(dir, "state.db")}
		if initial {
			args = append(args, "-clock-start", "2031-02-03T04:05:00Z")
		}
		cmd = exec.Command(os.Args[1], args...)
		cmd.Stdout, cmd.Stderr = log, log
		must(cmd.Start())
		wait(ctx, func() bool {
			r, e := httpClient.Get(endpoint + "/_stackd/health")
			if e != nil {
				return false
			}
			r.Body.Close()
			return r.StatusCode == http.StatusOK
		})
	}
	clock := func(advance time.Duration) time.Time {
		method := http.MethodGet
		var body []byte
		if advance > 0 {
			method = http.MethodPost
			body, err = json.Marshal(map[string]string{"advance": advance.String()})
			must(err)
		}
		req, e := http.NewRequestWithContext(ctx, method, endpoint+"/_stackd/clock", bytes.NewReader(body))
		must(e)
		req.Header.Set("Content-Type", "application/json")
		r, e := httpClient.Do(req)
		must(e)
		defer r.Body.Close()
		check(r.StatusCode == http.StatusOK, "retention clock request failed")
		var result struct {
			Time time.Time `json:"time"`
		}
		must(json.NewDecoder(r.Body).Decode(&result))
		return result.Time
	}
	drain := func() {
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/_stackd/jobs/drain?limit=1024", nil)
		must(e)
		r, e := httpClient.Do(req)
		must(e)
		defer r.Body.Close()
		check(r.StatusCode == http.StatusOK, "retention job drain failed")
	}
	start(true)
	epoch := clock(0)
	check(epoch.Equal(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)), "retention initial clock differs")
	const account = "123456789012"
	const sampleType = "Backdoor:EC2/DenialOfService.Tcp"
	east := client(endpoint, account, "us-east-1")
	west := client(endpoint, account, "us-west-2")
	features := []gt.DetectorFeatureConfiguration{
		{Name: "EKS_AUDIT_LOGS", Status: gt.FeatureStatusDisabled},
		{Name: "EBS_MALWARE_PROTECTION", Status: gt.FeatureStatusDisabled},
		{Name: "RDS_LOGIN_EVENTS", Status: gt.FeatureStatusDisabled},
		{Name: "LAMBDA_NETWORK_LOGS", Status: gt.FeatureStatusDisabled},
	}
	createDetector := func(c *gd.Client) *string {
		v, e := c.CreateDetector(ctx, &gd.CreateDetectorInput{Enable: aws.Bool(false), Features: features})
		must(e)
		return v.DetectorId
	}
	eastID := createDetector(east)
	westID := createDetector(west)
	defer func() {
		for _, scope := range []struct {
			client *gd.Client
			id     *string
		}{{east, eastID}, {west, westID}} {
			_, e := scope.client.DeleteDetector(ctx, &gd.DeleteDetectorInput{DetectorId: scope.id})
			must(e)
			v, e := scope.client.ListDetectors(ctx, &gd.ListDetectorsInput{})
			must(e)
			check(len(v.DetectorIds) == 0, "retention detector cleanup failed")
		}
	}()
	sample := func(c *gd.Client, id *string) string {
		_, e := c.CreateSampleFindings(ctx, &gd.CreateSampleFindingsInput{DetectorId: id, FindingTypes: []string{sampleType}})
		must(e)
		v, e := c.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: id})
		must(e)
		check(len(v.FindingIds) == 1, "retention sample must have exactly one live finding")
		return v.FindingIds[0]
	}
	get := func(c *gd.Client, id *string, findingID string) gt.Finding {
		v, e := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: id, FindingIds: []string{findingID}})
		must(e)
		check(len(v.Findings) == 1, "retention live finding missing")
		check(aws.ToString(v.Findings[0].Id) == findingID, "retention finding identity changed")
		return v.Findings[0]
	}
	visible := func(c *gd.Client, id *string, findingID string, want bool) {
		v, e := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: id, FindingIds: []string{findingID}})
		must(e)
		count := 0
		if want {
			count = 1
		}
		check(len(v.Findings) == count, "retention GetFindings boundary mismatch")
		listed, e := c.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: id})
		must(e)
		check(len(listed.FindingIds) == count, "retention ListFindings boundary mismatch")
		if want {
			check(listed.FindingIds[0] == findingID, "retention ListFindings identity mismatch")
		}
		stats, e := c.GetFindingsStatistics(ctx, &gd.GetFindingsStatisticsInput{DetectorId: id, GroupBy: gt.GroupByTypeAccount})
		must(e)
		check(stats.FindingStatistics != nil, "retention statistics missing")
		var total int32
		for _, group := range stats.FindingStatistics.GroupedByAccount {
			total += aws.ToInt32(group.TotalFindings)
		}
		check(total == int32(count), "retention statistics boundary mismatch")
	}

	original := sample(east, eastID)
	first := get(east, eastID, original)
	createdAt, err := time.Parse(time.RFC3339Nano, aws.ToString(first.CreatedAt))
	must(err)
	check(createdAt.Equal(epoch) && aws.ToInt32(first.Service.Count) == 1, "retention sample creation timestamp/count differs")
	refreshedAt := clock(89 * 24 * time.Hour)
	check(sample(east, eastID) == original, "retention repeat replaced unexpired sample")
	refreshed := get(east, eastID, original)
	updatedAt, err := time.Parse(time.RFC3339Nano, aws.ToString(refreshed.UpdatedAt))
	must(err)
	check(aws.ToInt32(refreshed.Service.Count) == 2 && aws.ToString(refreshed.CreatedAt) == aws.ToString(first.CreatedAt) && updatedAt.Equal(refreshedAt), "retention repeat did not preserve creation/update occurrence")
	_, err = east.UpdateFindingsFeedback(ctx, &gd.UpdateFindingsFeedbackInput{DetectorId: eastID, FindingIds: []string{original}, Feedback: gt.FeedbackUseful})
	must(err)
	_, err = east.ArchiveFindings(ctx, &gd.ArchiveFindingsInput{DetectorId: eastID, FindingIds: []string{original}})
	must(err)
	younger := sample(west, westID)
	stop()
	start(false)
	check(clock(0).Equal(refreshedAt), "retention restart did not restore manual clock")
	mutated := get(east, eastID, original)
	check(aws.ToBool(mutated.Service.Archived) && aws.ToString(mutated.Service.UserFeedback) == "USEFUL", "retention restart lost archive/feedback")
	deadline := epoch.Add(90 * 24 * time.Hour)
	check(clock(24*time.Hour-time.Second).Equal(deadline.Add(-time.Second)), "retention pre-expiry clock differs")
	visible(east, eastID, original, true)
	visible(west, westID, younger, true)
	check(clock(time.Second).Equal(deadline), "retention exact-expiry clock differs")
	visible(east, eastID, original, false)
	visible(west, westID, younger, true)
	_, err = east.ArchiveFindings(ctx, &gd.ArchiveFindingsInput{DetectorId: eastID, FindingIds: []string{original}})
	code(err, "BadRequestException")
	_, err = east.UpdateFindingsFeedback(ctx, &gd.UpdateFindingsFeedbackInput{DetectorId: eastID, FindingIds: []string{original}, Feedback: gt.FeedbackNotUseful})
	must(err)
	drain()
	stop()
	start(false)
	check(clock(0).Equal(deadline), "retention expiry restart reset saved time")
	visible(east, eastID, original, false)
	visible(west, westID, younger, true)
	freshID := sample(east, eastID)
	check(freshID != original, "retention fresh sample reused expired identity")
	fresh := get(east, eastID, freshID)
	freshCreated, err := time.Parse(time.RFC3339Nano, aws.ToString(fresh.CreatedAt))
	must(err)
	check(freshCreated.Equal(deadline) && aws.ToInt32(fresh.Service.Count) == 1 && !aws.ToBool(fresh.Service.Archived) && aws.ToString(fresh.Service.UserFeedback) == "", "retention fresh sample inherited expired state")
	visible(east, eastID, freshID, true)
	fmt.Println("GuardDuty signed SDK 90-day creation cap, refreshed/archive/feedback expiry, exact Get/List/statistics boundary, regional isolation, saved-clock/job restart and fresh sample: PASS")
}
