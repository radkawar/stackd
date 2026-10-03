// awspolicies captures AWS managed IAM policies using only read-only IAM APIs.
// Completed immutable version reads are cached so interrupted captures resume.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go/middleware"
	"stackd/internal/iam/managed"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

type capture struct {
	client   *iam.Client
	cache    string
	ticks    <-chan time.Time
	versions atomic.Int64
}

func run() error {
	partition := flag.String("partition", "aws", "partition to capture (never translates policy ARNs)")
	region := flag.String("region", "us-east-1", "IAM signing region for the selected partition")
	endpoint := flag.String("endpoint", "https://iam.amazonaws.com", "authoritative IAM endpoint")
	output := flag.String("output", "internal/iam/managed/data/aws.json.gz", "deterministic compressed snapshot")
	cache := flag.String("cache-dir", ".stackd/cache/aws-managed-policies", "resumable read cache; stores public policies only")
	workers := flag.Int("workers", 8, "concurrent policy readers")
	rate := flag.Int("requests-per-second", 10, "maximum initial request rate; SDK separately retries throttling")
	check := flag.Bool("check", false, "verify embedded catalogues offline")
	flag.Parse()
	if *check {
		return managed.Check()
	}
	if *workers < 1 || *rate < 1 {
		return fmt.Errorf("workers and requests-per-second must be positive")
	}
	validEndpoint := map[string]string{"aws": "https://iam.amazonaws.com", "aws-us-gov": "https://iam.us-gov.amazonaws.com", "aws-cn": "https://iam.cn-north-1.amazonaws.com.cn"}
	if validEndpoint[*partition] != *endpoint {
		return fmt.Errorf("endpoint must be the authoritative IAM endpoint for partition %s", *partition)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(*region))
	if err != nil {
		return err
	}
	client := iam.NewFromConfig(cfg, func(o *iam.Options) { o.BaseEndpoint = endpoint; o.RetryMaxAttempts = 12 })
	ticker := time.NewTicker(time.Second / time.Duration(*rate))
	defer ticker.Stop()
	c := capture{client: client, cache: filepath.Join(*cache, *partition), ticks: ticker.C}
	if err = os.MkdirAll(c.cache, 0755); err != nil {
		return err
	}
	s := managed.Snapshot{Schema: 1, Partition: *partition, Endpoint: *endpoint, Region: *region, Source: "AWS IAM ListPolicies(Scope=AWS), GetPolicy, ListPolicyVersions and GetPolicyVersion", SDK: sdkVersion(), Started: time.Now().UTC()}
	var policies []types.Policy
	pager := iam.NewListPoliciesPaginator(client, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeAws, MaxItems: aws.Int32(1000)})
	for pager.HasMorePages() {
		if err = c.wait(ctx); err != nil {
			return err
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		s.ListRequestIDs = append(s.ListRequestIDs, requestID(page.ResultMetadata))
		policies = append(policies, page.Policies...)
	}
	log.Printf("capturing %d policies in %s", len(policies), *partition)
	s.Policies = make([]managed.Policy, len(policies))
	jobs := make(chan int)
	errs := make(chan error, 1)
	var wg sync.WaitGroup
	var done atomic.Int64
	for range *workers {
		wg.Go(func() {
			for i := range jobs {
				p, err := c.policy(ctx, aws.ToString(policies[i].Arn))
				if err != nil {
					select {
					case errs <- err:
						cancel()
					default:
					}
					return
				}
				s.Policies[i] = p
				n := done.Add(1)
				if n%25 == 0 || int(n) == len(policies) {
					log.Printf("captured %d/%d policies, %d version documents read", n, len(policies), c.versions.Load())
				}
			}
		})
	}
enqueue:
	for i := range policies {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break enqueue
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err = <-errs:
		return err
	default:
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	s.Completed = time.Now().UTC()
	encoded, err := managed.Encode(s)
	if err != nil {
		return err
	}
	if err = atomicWrite(*output, encoded); err != nil {
		return err
	}
	log.Printf("wrote %s: %d policies, %d versions, sha256 %s", *output, len(s.Policies), c.versions.Load(), managed.Digest(encoded))
	return nil
}

func (c *capture) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ticks:
		return nil
	}
}

func (c *capture) policy(ctx context.Context, arn string) (managed.Policy, error) {
	if err := c.wait(ctx); err != nil {
		return managed.Policy{}, err
	}
	meta, err := c.client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return managed.Policy{}, err
	}
	if meta.Policy == nil {
		return managed.Policy{}, fmt.Errorf("%s: AWS returned no policy metadata", arn)
	}
	m := meta.Policy
	p := managed.Policy{ARN: arn, Name: aws.ToString(m.PolicyName), ID: aws.ToString(m.PolicyId), Path: aws.ToString(m.Path), DefaultVersion: aws.ToString(m.DefaultVersionId), Attachable: m.IsAttachable, Description: aws.ToString(m.Description), Created: aws.ToTime(m.CreateDate), Updated: aws.ToTime(m.UpdateDate), MetadataRequestID: requestID(meta.ResultMetadata), Retrieved: time.Now().UTC()}
	pager := iam.NewListPolicyVersionsPaginator(c.client, &iam.ListPolicyVersionsInput{PolicyArn: aws.String(arn), MaxItems: aws.Int32(1000)})
	for pager.HasMorePages() {
		if err = c.wait(ctx); err != nil {
			return p, err
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			return p, err
		}
		p.VersionsRequestIDs = append(p.VersionsRequestIDs, requestID(page.ResultMetadata))
		for _, v := range page.Versions {
			version, err := c.version(ctx, arn, aws.ToString(v.VersionId))
			if err != nil {
				return p, err
			}
			version.Default = v.IsDefaultVersion
			p.Versions = append(p.Versions, version)
		}
	}
	return p, nil
}

func (c *capture) version(ctx context.Context, arn, id string) (managed.Version, error) {
	file := filepath.Join(c.cache, managed.Digest([]byte(arn)), id+".json")
	if raw, err := os.ReadFile(file); err == nil {
		var v managed.Version
		if json.Unmarshal(raw, &v) == nil && v.ID == id && v.SHA256 == managed.Digest([]byte(v.Document)) && json.Valid([]byte(v.Document)) && v.RequestID != "" {
			c.versions.Add(1)
			return v, nil
		}
	}
	if err := c.wait(ctx); err != nil {
		return managed.Version{}, err
	}
	response, err := c.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String(id)})
	if err != nil {
		return managed.Version{}, fmt.Errorf("%s %s: %w", arn, id, err)
	}
	if response.PolicyVersion == nil {
		return managed.Version{}, fmt.Errorf("%s %s: AWS returned no policy version", arn, id)
	}
	document, err := url.QueryUnescape(aws.ToString(response.PolicyVersion.Document))
	if err != nil {
		return managed.Version{}, err
	}
	if !json.Valid([]byte(document)) {
		return managed.Version{}, fmt.Errorf("%s %s: invalid JSON document", arn, id)
	}
	v := managed.Version{ID: id, Default: response.PolicyVersion.IsDefaultVersion, Created: aws.ToTime(response.PolicyVersion.CreateDate), Document: document, SHA256: managed.Digest([]byte(document)), RequestID: requestID(response.ResultMetadata), Retrieved: time.Now().UTC()}
	raw, err := json.Marshal(v)
	if err != nil {
		return v, err
	}
	if err = atomicWrite(file, raw); err != nil {
		return v, err
	}
	c.versions.Add(1)
	return v, nil
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".awspolicies-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func requestID(metadata middleware.Metadata) string {
	id, _ := awsmiddleware.GetRequestIDMetadata(metadata)
	return id
}

func sdkVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if strings.HasPrefix(dep.Path, "github.com/aws/aws-sdk-go-v2/service/iam") {
				return dep.Path + "@" + dep.Version
			}
		}
	}
	return "github.com/aws/aws-sdk-go-v2/service/iam"
}
