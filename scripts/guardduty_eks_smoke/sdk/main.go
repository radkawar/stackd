// Command sdk verifies real EKS audit findings through the AWS SDK for Go v2.
// The owning Python workflow supplies native audit expectations on stdin.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

const anonymousGrantType = "Policy:Kubernetes/AnonymousAccessGranted"

type bindingRoleRef struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}

type bindingSubject struct {
	APIGroup  string `json:"apiGroup"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type deleteOptions struct {
	Observed bool `json:"observed"`
	DryRun   bool `json:"dryRun"`
}

type expectation struct {
	ID            string
	Type          string
	Count         int32
	Username      string
	Groups        []string
	URI           string
	Verb          string
	Status        int32
	Namespace     string
	Resource      string
	Name          string
	Subresource   string
	SourceIPs     []string
	UserAgent     string
	RoleRef       *bindingRoleRef
	Subjects      []bindingSubject
	DeleteOptions *deleteOptions
	ThreatLists   []string
}

func require(ok bool, detail string) {
	if !ok {
		panic(detail)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func verify(f gt.Finding, want expectation, account, region, detector, clusterARN, clusterName string) {
	require(aws.ToString(f.Id) == want.ID && aws.ToString(f.Type) == want.Type, "finding identity differs from native workflow")
	require(aws.ToString(f.AccountId) == account && aws.ToString(f.Region) == region, "finding account/region mismatch")
	r := f.Resource
	require(r != nil && aws.ToString(r.ResourceType) == "EKSCluster" && r.EksClusterDetails != nil, "missing EKSCluster resource")
	require(aws.ToString(r.EksClusterDetails.Arn) == clusterARN && aws.ToString(r.EksClusterDetails.Name) == clusterName, "wrong owned cluster")
	require(r.InstanceDetails == nil && r.ContainerDetails == nil && r.AccessKeyDetails == nil && len(r.S3BucketDetails) == 0, "unobserved resource fields")
	require(r.KubernetesDetails != nil && r.KubernetesDetails.KubernetesUserDetails != nil, "missing Kubernetes user")
	user := r.KubernetesDetails.KubernetesUserDetails
	username, groups := aws.ToString(user.Username), user.Groups
	if user.ImpersonatedUser != nil {
		username, groups = aws.ToString(user.ImpersonatedUser.Username), user.ImpersonatedUser.Groups
	}
	require(username == want.Username, "effective Kubernetes username mismatch")
	slices.Sort(groups)
	slices.Sort(want.Groups)
	require(slices.Equal(groups, want.Groups), "effective Kubernetes groups mismatch")
	s := f.Service
	require(s != nil && aws.ToString(s.DetectorId) == detector, "wrong finding detector")
	require(want.Count > 0 && aws.ToInt32(s.Count) == want.Count, "finding count differs from native workflow")
	require(s.RuntimeDetails == nil && s.Detection == nil, "unobserved runtime/anomaly evidence")
	var threatLists []string
	if s.Evidence != nil {
		for _, detail := range s.Evidence.ThreatIntelligenceDetails {
			threatLists = append(threatLists, aws.ToString(detail.ThreatListName))
		}
	}
	require(slices.Equal(threatLists, want.ThreatLists), "active custom threat list evidence mismatch")
	a := s.Action
	require(a != nil && aws.ToString(a.ActionType) == "KUBERNETES_API_CALL" && a.KubernetesApiCallAction != nil, "missing native Kubernetes action")
	require(a.AwsApiCallAction == nil && a.DnsRequestAction == nil && a.NetworkConnectionAction == nil && a.PortProbeAction == nil, "unobserved AWS/network action")
	k := a.KubernetesApiCallAction
	require(aws.ToString(k.RequestUri) == want.URI && aws.ToString(k.Verb) == want.Verb && aws.ToInt32(k.StatusCode) == want.Status, "native Kubernetes API result mismatch")
	require(aws.ToString(k.Namespace) == want.Namespace && aws.ToString(k.Resource) == want.Resource && aws.ToString(k.ResourceName) == want.Name && aws.ToString(k.Subresource) == want.Subresource, "native Kubernetes object mismatch")
	require(slices.Equal(k.SourceIps, want.SourceIPs) && aws.ToString(k.UserAgent) == want.UserAgent, "native Kubernetes caller metadata mismatch")
	require(s.AdditionalInfo != nil, "native audit evidence missing")
	var additional struct {
		DeleteOptions *deleteOptions `json:"deleteOptions"`
	}
	must(json.Unmarshal([]byte(aws.ToString(s.AdditionalInfo.Value)), &additional))
	if want.DeleteOptions == nil {
		require(additional.DeleteOptions == nil, "unobserved deletion options were invented")
	} else {
		require(additional.DeleteOptions != nil && *additional.DeleteOptions == *want.DeleteOptions,
			"effective native deletion options mismatch")
	}
	if want.Type == anonymousGrantType {
		require(want.RoleRef != nil && len(want.Subjects) > 0, "native binding expectations missing")
		require(s.AdditionalInfo != nil, "native binding evidence missing")
		var binding struct {
			RoleRef  bindingRoleRef   `json:"roleRef"`
			Subjects []bindingSubject `json:"subjects"`
		}
		must(json.Unmarshal([]byte(aws.ToString(s.AdditionalInfo.Value)), &binding))
		require(binding.RoleRef == *want.RoleRef, "native binding roleRef mismatch")
		require(slices.Equal(binding.Subjects, want.Subjects), "native ordered binding subjects mismatch")
	}
}

func main() {
	endpoint := flag.String("endpoint", "", "owned local stackd endpoint")
	account := flag.String("account", "", "owned stackd account")
	region := flag.String("region", "us-east-1", "owned detector region")
	detector := flag.String("detector", "", "owned detector ID")
	clusterARN := flag.String("cluster-arn", "", "owned EKS cluster ARN")
	clusterName := flag.String("cluster-name", "", "owned EKS cluster name")
	custom := flag.Bool("custom-threats", false, "verify the custom threat-list workflow instead of anonymous/exec findings")
	flag.Parse()
	u, err := url.Parse(*endpoint)
	must(err)
	require(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback(), "only an explicit loopback stackd endpoint is permitted")
	require(*account != "" && *region != "" && *detector != "" && *clusterARN != "" && *clusterName != "", "all scope flags are required")
	var expected []expectation
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	must(decoder.Decode(&expected))
	required := map[string]bool{
		"Execution:Kubernetes/ExecInKubeSystemPod":              false,
		"CredentialAccess:Kubernetes/SuccessfulAnonymousAccess": false,
		"Discovery:Kubernetes/SuccessfulAnonymousAccess":        false,
		"Impact:Kubernetes/SuccessfulAnonymousAccess":           false,
		anonymousGrantType: false,
	}
	if *custom {
		required = map[string]bool{
			"CredentialAccess:Kubernetes/MaliciousIPCaller.Custom": false,
			"Discovery:Kubernetes/MaliciousIPCaller.Custom":        false,
			"Impact:Kubernetes/MaliciousIPCaller.Custom":           false,
		}
	}
	require(len(expected) >= len(required), "expected every workflow finding type")
	byID := make(map[string]expectation, len(expected))
	for _, want := range expected {
		_, ok := required[want.Type]
		require(ok && want.ID != "", "unexpected finding expectation")
		required[want.Type] = true
		if !*custom && want.Type != "Execution:Kubernetes/ExecInKubeSystemPod" && want.Type != anonymousGrantType {
			require(want.Username == "system:anonymous", "anonymous operation has non-anonymous expectation")
		}
		_, duplicate := byID[want.ID]
		require(!duplicate, "duplicate finding ID")
		byID[want.ID] = want
	}
	for kind, seen := range required {
		require(seen, "missing native finding type: "+kind)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config := aws.Config{Region: *region, Credentials: credentials.NewStaticCredentialsProvider(*account, "test", ""), RetryMaxAttempts: 1}
	client := gd.NewFromConfig(config, func(options *gd.Options) { options.BaseEndpoint = endpoint })
	criteria := &gt.FindingCriteria{Criterion: map[string]gt.Condition{
		"resource.resourceType": {Equals: []string{"EKSCluster"}},
	}}
	var token *string
	listed := make(map[string]bool)
	for {
		page, err := client.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector, FindingCriteria: criteria, MaxResults: aws.Int32(50), NextToken: token})
		must(err)
		for _, id := range page.FindingIds {
			require(!listed[id], "ListFindings pagination repeated an ID")
			listed[id] = true
		}
		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		token = page.NextToken
	}
	require(len(listed) == len(expected), "unexpected EKS findings outside the native positive operations")
	ids := make([]string, 0, len(expected))
	for _, want := range expected {
		require(listed[want.ID], "native Kubernetes finding missing from ListFindings")
		ids = append(ids, want.ID)
	}
	result, err := client.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: ids})
	must(err)
	require(len(result.Findings) == len(expected), "GetFindings omitted a native Kubernetes finding")
	observed := make([]map[string]any, 0, len(expected))
	for _, finding := range result.Findings {
		id := aws.ToString(finding.Id)
		want, ok := byID[id]
		require(ok, "GetFindings returned an unexpected or duplicate finding")
		verify(finding, want, *account, *region, *detector, *clusterARN, *clusterName)
		observed = append(observed, map[string]any{"id": id, "type": want.Type, "count": aws.ToInt32(finding.Service.Count), "username": want.Username, "requestURI": want.URI})
		delete(byID, id)
	}
	require(len(byID) == 0, "GetFindings did not verify every native finding")
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "sdk": "AWS SDK for Go v2", "signed": true, "clusterARN": *clusterARN, "findings": observed}))
	fmt.Fprintln(os.Stderr, "GuardDuty EKS signed Go SDK ListFindings/GetFindings: PASS")
}
