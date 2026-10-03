// Command opensearch_smoke exercises the actual stackd executable and native
// OpenSearch with official AWS SDK v2 and the ordinary signed OpenSearch client.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	legacy "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	ostypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/smithy-go"
	search "github.com/opensearch-project/opensearch-go/v4"
	signer "github.com/opensearch-project/opensearch-go/v4/signer/awsv2"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./scripts/opensearch_smoke /absolute/path/to/stackd")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type controller struct {
	binary, dir, endpoint, listen string
	cmd                           *exec.Cmd
	log                           *os.File
}

func (c *controller) start() error {
	var err error
	c.log, err = os.OpenFile(filepath.Join(c.dir, "controller.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	c.cmd = exec.Command(c.binary, "-listen", c.listen, "-database", filepath.Join(c.dir, "state.db"), "-docker-host", "unix:///var/run/docker.sock", "-compute-endpoint", c.endpoint, "-opensearch-runtime")
	c.cmd.Stdout, c.cmd.Stderr = c.log, c.log
	if err = c.cmd.Start(); err != nil {
		return err
	}
	err = wait(30*time.Second, func() (bool, error) {
		r, e := http.Get(c.endpoint + "/_stackd/health")
		if e != nil {
			return false, nil
		}
		defer r.Body.Close()
		return r.StatusCode == 200, nil
	})
	if err != nil {
		_ = c.stop()
		raw, _ := os.ReadFile(filepath.Join(c.dir, "controller.log"))
		return fmt.Errorf("controller startup: %w\n%s", err, raw)
	}
	return nil
}
func (c *controller) stop() error {
	if c.cmd == nil {
		return nil
	}
	_ = c.cmd.Process.Signal(os.Interrupt)
	err := c.cmd.Wait()
	c.cmd = nil
	_ = c.log.Close()
	return err
}
func config(region, key, secret string) aws.Config {
	return aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), RetryMaxAttempts: 1}
}
func control(cfg aws.Config, endpoint string) *opensearch.Client {
	return opensearch.NewFromConfig(cfg, func(o *opensearch.Options) { o.BaseEndpoint = &endpoint })
}
func data(cfg aws.Config, endpoint string) (*search.Client, error) {
	signed, err := signer.NewSigner(cfg)
	if err != nil {
		return nil, err
	}
	return search.NewClient(search.Config{Addresses: []string{"http://" + endpoint}, Signer: signed, DisableRetry: true, DiscoverNodesOnStart: aws.Bool(false)})
}
func request(client *search.Client, method, path, body string, want int) (map[string]any, error) {
	r, err := http.NewRequest(method, path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	if strings.Contains(path, "_bulk") {
		r.Header.Set("Content-Type", "application/x-ndjson")
	}
	response, err := client.Stream(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != want {
		return nil, fmt.Errorf("%s %s status=%d want=%d body=%s", method, path, response.StatusCode, want, raw)
	}
	out := map[string]any{}
	if len(raw) != 0 {
		if err = json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

//go:embed testdata/path_authorization.json
var pathAuthorizationFixture []byte

func provePathAuthorization(ctx context.Context, api *opensearch.Client, identity *iam.Client, root, consumer *search.Client, name, arn, userName, policyName string) error {
	var fixture struct {
		Documents []struct{ Path, ID, Title string }
		Requests  []struct {
			Path, ID, Title string
			Status          int
		}
	}
	if err := json.Unmarshal(pathAuthorizationFixture, &fixture); err != nil {
		return err
	}
	for _, document := range fixture.Documents {
		body, err := json.Marshal(map[string]any{"category": "boundary", "price": 1, "title": document.Title})
		if err != nil {
			return err
		}
		out, err := request(root, "PUT", document.Path, string(body), 201)
		if err != nil {
			return err
		}
		if out["_id"] != document.ID {
			return fmt.Errorf("created boundary document: %v want ID=%s", out, document.ID)
		}
	}
	if _, err := request(root, "POST", "/catalog/_refresh", "", 200); err != nil {
		return err
	}
	allow := fmt.Sprintf(`{"Effect":"Allow","Action":"es:ESHttpGet","Resource":[%q,%q,%q]}`, arn+"/catalog/_doc/*", arn+"/catalog/_search*", arn+"/")
	for _, layer := range []string{"identity", "resource"} {
		deny := fmt.Sprintf(`{"Effect":"Deny","Action":"es:ESHttpGet","Resource":[%q,%q]}`, arn+"/catalog/_doc/secret", arn+"/catalog/_search")
		policy := `{"Statement":[` + allow + `]}`
		resource := ""
		if layer == "identity" {
			policy = `{"Statement":[` + allow + `,` + deny + `]}`
		} else {
			resource = fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"es:ESHttpGet","Resource":[%q,%q]}}`, arn+"/catalog/_doc/secret", arn+"/catalog/_search")
		}
		if _, err := identity.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: &userName, PolicyName: &policyName, PolicyDocument: &policy}); err != nil {
			return err
		}
		if _, err := api.UpdateDomainConfig(ctx, &opensearch.UpdateDomainConfigInput{DomainName: &name, AccessPolicies: &resource}); err != nil {
			return err
		}
		for _, row := range fixture.Requests {
			out, err := request(consumer, "GET", row.Path, "", row.Status)
			if err != nil {
				return fmt.Errorf("%s path authorization: %w", layer, err)
			}
			if row.Status == 400 && out["__type"] != "ValidationException" || row.Status == 403 && out["__type"] != "AccessDeniedException" {
				return fmt.Errorf("%s path %s returned unexpected error: %v", layer, row.Path, out)
			}
			if row.ID != "" && (out["_id"] != row.ID || out["_source"].(map[string]any)["title"] != row.Title) {
				return fmt.Errorf("%s document %s changed: %v", layer, row.Path, out)
			}
			if row.Path == "/" && out["version"].(map[string]any)["number"] != "2.19.4" {
				return fmt.Errorf("%s native root changed: %v", layer, out)
			}
			fmt.Printf("path_authorization layer=%s path=%s status=%d id=%v\n", layer, row.Path, row.Status, out["_id"])
		}
	}
	empty := ""
	_, err := api.UpdateDomainConfig(ctx, &opensearch.UpdateDomainConfigInput{DomainName: &name, AccessPolicies: &empty})
	return err
}
func wait(timeout time.Duration, fn func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		ok, err := fn()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for actual engine state")
		}
		time.Sleep(300 * time.Millisecond)
	}
}
func modeled(err error, code string) error {
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() == code {
		return nil
	}
	return fmt.Errorf("modeled error=%v want=%s", err, code)
}
func ready(ctx context.Context, client *opensearch.Client, name string) (*ostypes.DomainStatus, error) {
	var status *ostypes.DomainStatus
	err := wait(3*time.Minute, func() (bool, error) {
		out, e := client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: &name})
		if e != nil {
			return false, e
		}
		status = out.DomainStatus
		return !aws.ToBool(status.Processing) && aws.ToString(status.Endpoint) != "", nil
	})
	return status, err
}

type ownedDomain struct {
	client         *opensearch.Client
	name, endpoint string
}

func run(binary string) (result error) {
	ctx := context.Background()
	directory, err := os.MkdirTemp("", "stackd-opensearch-sdk-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	listener.Close()
	c := &controller{binary: binary, dir: directory, listen: address, endpoint: "http://" + address}
	if err = c.start(); err != nil {
		return err
	}
	defer func() {
		if e := c.stop(); e != nil {
			result = errors.Join(result, e)
		}
	}()
	var owned []ownedDomain
	defer func() {
		if c.cmd == nil {
			if e := c.start(); e != nil {
				result = errors.Join(result, e)
				return
			}
		}
		for _, v := range owned {
			_, e := v.client.DeleteDomain(ctx, &opensearch.DeleteDomainInput{DomainName: &v.name})
			if e != nil {
				var a smithy.APIError
				if !errors.As(e, &a) || a.ErrorCode() != "ResourceNotFoundException" {
					result = errors.Join(result, e)
					continue
				}
			}
			e = wait(time.Minute, func() (bool, error) {
				_, e := v.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: &v.name})
				var a smithy.APIError
				return errors.As(e, &a) && a.ErrorCode() == "ResourceNotFoundException", nil
			})
			result = errors.Join(result, e)
		}
		if result != nil {
			raw, _ := os.ReadFile(filepath.Join(directory, "controller.log"))
			fmt.Fprintln(os.Stderr, string(raw))
		}
	}()
	root := config("us-east-1", "test", "test")
	api := control(root, c.endpoint)
	iamClient := iam.NewFromConfig(root, func(o *iam.Options) { o.BaseEndpoint = &c.endpoint })
	name := "engine-proof"
	_, err = api.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: aws.String("missing-domain")})
	if err = modeled(err, "ResourceNotFoundException"); err != nil {
		return err
	}
	_, err = api.CreateDomain(ctx, &opensearch.CreateDomainInput{DomainName: &name, EngineVersion: aws.String("Elasticsearch_7.10")})
	if err = modeled(err, "ValidationException"); err != nil {
		return err
	}
	_, err = api.CreateDomain(ctx, &opensearch.CreateDomainInput{DomainName: &name, AdvancedSecurityOptions: &ostypes.AdvancedSecurityOptionsInput{Enabled: aws.Bool(true)}})
	if err = modeled(err, "ValidationException"); err != nil {
		return err
	}
	created, err := api.CreateDomain(ctx, &opensearch.CreateDomainInput{DomainName: &name, EngineVersion: aws.String("OpenSearch_2.19"), TagList: []ostypes.Tag{{Key: aws.String("team"), Value: aws.String("blue")}}})
	if err != nil {
		return err
	}
	owned = append(owned, ownedDomain{client: api, name: name})
	arn := aws.ToString(created.DomainStatus.ARN)
	status, err := ready(ctx, api, name)
	if err != nil {
		return err
	}
	owned[0].endpoint = aws.ToString(status.Endpoint)
	endpoint := owned[0].endpoint
	client, err := data(root, endpoint)
	if err != nil {
		return err
	}
	info, err := request(client, "GET", "/", "", 200)
	if err != nil {
		return err
	}
	version := info["version"].(map[string]any)
	if version["distribution"] != "opensearch" || version["number"] != "2.19.4" {
		return fmt.Errorf("unexpected real engine: %v", version)
	}
	if _, err = request(client, "PUT", "/catalog", `{"settings":{"number_of_shards":1,"number_of_replicas":0},"mappings":{"dynamic":"strict","properties":{"category":{"type":"keyword"},"price":{"type":"long"},"title":{"type":"text"}}}}`, 200); err != nil {
		return err
	}
	bulk := `{"index":{"_index":"catalog","_id":"a"}}
{"category":"books","price":15,"title":"Go concurrency"}
{"index":{"_index":"catalog","_id":"b"}}
{"category":"books","price":30,"title":"Advanced search"}
{"index":{"_index":"catalog","_id":"c"}}
{"category":"games","price":50,"title":"Distributed worlds"}
{"index":{"_index":"catalog","_id":"bad"}}
{"category":"books","price":"not-a-number","title":"Rejected"}
`
	bulkResult, err := request(client, "POST", "/_bulk", bulk, 200)
	if err != nil {
		return err
	}
	if bulkResult["errors"] != true {
		return fmt.Errorf("native bulk did not reject invalid mapping: %v", bulkResult)
	}
	bad := bulkResult["items"].([]any)[3].(map[string]any)["index"].(map[string]any)
	if bad["status"] != float64(400) || bad["error"].(map[string]any)["type"] != "mapper_parsing_exception" {
		return fmt.Errorf("wrong native bulk error: %v", bad)
	}
	if _, err = request(client, "PUT", "/catalog/_doc/space%20%2B%20id", `{"category":"tools","price":7,"title":"Escaped id"}`, 201); err != nil {
		return err
	}
	escaped, err := request(client, "GET", "/catalog/_doc/space%20%2B%20id", "", 200)
	if err != nil {
		return err
	}
	if escaped["_id"] != "space + id" {
		return fmt.Errorf("escaped ID changed: %v", escaped)
	}
	if _, err = request(client, "POST", "/catalog/_refresh", "", 200); err != nil {
		return err
	}
	query := `{"query":{"bool":{"filter":[{"term":{"category":"books"}},{"range":{"price":{"gte":20}}}]}},"aggs":{"total_price":{"sum":{"field":"price"}}},"sort":[{"price":"desc"}]}`
	prove := func() error {
		out, e := request(client, "POST", "/catalog/_search", query, 200)
		if e != nil {
			return e
		}
		hits := out["hits"].(map[string]any)
		if hits["total"].(map[string]any)["value"] != float64(1) || hits["hits"].([]any)[0].(map[string]any)["_id"] != "b" || out["aggregations"].(map[string]any)["total_price"].(map[string]any)["value"] != float64(30) {
			return fmt.Errorf("native query result mismatch: %v", out)
		}
		return nil
	}
	if err = prove(); err != nil {
		return err
	}
	mapping, err := request(client, "PUT", "/catalog/_mapping", `{"properties":{"price":{"type":"keyword"}}}`, 400)
	if err != nil {
		return err
	}
	if mapping["error"].(map[string]any)["type"] != "illegal_argument_exception" {
		return fmt.Errorf("wrong mapping error: %v", mapping)
	}
	if _, err = request(client, "PUT", "/_cluster/settings", `{"persistent":{"rest.action.multi.allow_explicit_index":false}}`, 400); err != nil {
		return err
	}
	fmt.Printf("native version=%s filtered_id=b sum=30 bulk_error=mapper_parsing_exception escaped_id=space+id mapping_error=illegal_argument_exception\n", version["number"])
	// Current identity tags, policy denial and domain policy denial/recovery.
	userName := "search-consumer"
	user, err := iamClient.CreateUser(ctx, &iam.CreateUserInput{UserName: &userName})
	if err != nil {
		return err
	}
	key, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: &userName})
	if err != nil {
		return err
	}
	userConfig := config("us-east-1", aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey))
	consumer, err := data(userConfig, endpoint)
	if err != nil {
		return err
	}
	policyName := "search-access"
	if err = provePathAuthorization(ctx, api, iamClient, client, consumer, name, arn, userName, policyName); err != nil {
		return err
	}
	allow := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"es:ESHttp*","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"red"}}}}`, arn+"/*")
	if _, err = iamClient.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: &userName, PolicyName: &policyName, PolicyDocument: &allow}); err != nil {
		return err
	}
	if _, err = request(consumer, "GET", "/catalog/_search", "", 403); err != nil {
		return err
	}
	if _, err = api.AddTags(ctx, &opensearch.AddTagsInput{ARN: &arn, TagList: []ostypes.Tag{{Key: aws.String("team"), Value: aws.String("red")}}}); err != nil {
		return err
	}
	if _, err = request(consumer, "GET", "/catalog/_search", "", 200); err != nil {
		return err
	}
	deny := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"es:ESHttp*","Resource":%q},{"Effect":"Deny","Action":"es:ESHttpGet","Resource":%q}]}`, arn+"/*", arn+"/*")
	if _, err = iamClient.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: &userName, PolicyName: &policyName, PolicyDocument: &deny}); err != nil {
		return err
	}
	if _, err = request(consumer, "GET", "/catalog/_search", "", 403); err != nil {
		return err
	}
	if _, err = iamClient.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: &userName, PolicyName: &policyName, PolicyDocument: &allow}); err != nil {
		return err
	}
	resourceDeny := fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"es:ESHttpGet","Resource":%q}}`, arn+"/catalog/_search")
	if _, err = api.UpdateDomainConfig(ctx, &opensearch.UpdateDomainConfigInput{DomainName: &name, AccessPolicies: &resourceDeny}); err != nil {
		return err
	}
	if _, err = request(consumer, "GET", "/catalog/_search", "", 403); err != nil {
		return err
	}
	resourceAllow := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"es:ESHttp*","Resource":%q}}`, aws.ToString(user.User.Arn), arn+"/*")
	if _, err = api.UpdateDomainConfig(ctx, &opensearch.UpdateDomainConfigInput{DomainName: &name, AccessPolicies: &resourceAllow}); err != nil {
		return err
	}
	if _, err = ready(ctx, api, name); err != nil {
		return err
	}
	if _, err = request(consumer, "GET", "/catalog/_search", "", 200); err != nil {
		return err
	}
	// Resource policy alone grants the bound user; deleting/recreating it cannot
	// inherit that grant despite an identical ARN.
	if _, err = iamClient.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: &userName, PolicyName: &policyName}); err != nil {
		return err
	}
	if _, err = request(consumer, "GET", "/catalog/_search", "", 200); err != nil {
		return err
	}
	if _, err = iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: &userName, AccessKeyId: key.AccessKey.AccessKeyId}); err != nil {
		return err
	}
	if _, err = iamClient.DeleteUser(ctx, &iam.DeleteUserInput{UserName: &userName}); err != nil {
		return err
	}
	if _, err = iamClient.CreateUser(ctx, &iam.CreateUserInput{UserName: &userName}); err != nil {
		return err
	}
	replacementKey, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: &userName})
	if err != nil {
		return err
	}
	replacement, err := data(config("us-east-1", aws.ToString(replacementKey.AccessKey.AccessKeyId), aws.ToString(replacementKey.AccessKey.SecretAccessKey)), endpoint)
	if err != nil {
		return err
	}
	if _, err = request(replacement, "GET", "/catalog/_search", "", 403); err != nil {
		return err
	}
	if _, err = api.UpdateDomainConfig(ctx, &opensearch.UpdateDomainConfigInput{DomainName: &name, AccessPolicies: &resourceAllow}); err != nil {
		return err
	}
	if _, err = request(replacement, "GET", "/catalog/_search", "", 200); err != nil {
		return err
	}
	fmt.Println("current IAM/tag/resource-policy denies recover; recreated principal does not inherit bound grant")
	anonymous := func(want int) error {
		r, e := http.NewRequest(http.MethodGet, "http://"+endpoint+"/catalog/_search", nil)
		if e != nil {
			return e
		}
		r.Header.Set("X-Forwarded-For", "192.0.2.1")
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			return fmt.Errorf("anonymous/IP policy status=%d want=%d", response.StatusCode, want)
		}
		return nil
	}
	if err = anonymous(403); err != nil {
		return err
	}
	for _, rule := range []struct {
		cidr   string
		status int
	}{{"127.0.0.1/32", 200}, {"192.0.2.1/32", 403}} {
		policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"es:ESHttpGet","Resource":%q,"Condition":{"IpAddress":{"aws:SourceIp":%q}}}}`, arn+"/catalog/_search", rule.cidr)
		if _, err = api.UpdateDomainConfig(ctx, &opensearch.UpdateDomainConfigInput{DomainName: &name, AccessPolicies: &policy}); err != nil {
			return err
		}
		if err = anonymous(rule.status); err != nil {
			return err
		}
	}
	fmt.Println("unsigned data requests require current public/IP grants; forwarded IP cannot spoof authority")
	// Legacy API shares the exact modern owner and can update its policy.
	old := legacy.NewFromConfig(root, func(o *legacy.Options) { o.BaseEndpoint = &c.endpoint })
	oldVersions, err := old.ListElasticsearchVersions(ctx, &legacy.ListElasticsearchVersionsInput{MaxResults: 100})
	if err != nil {
		return err
	}
	if len(oldVersions.ElasticsearchVersions) != 1 || oldVersions.ElasticsearchVersions[0] != "OpenSearch_2.19" {
		return fmt.Errorf("legacy supported-version metadata: %+v", oldVersions)
	}
	oldDomain, err := old.DescribeElasticsearchDomain(ctx, &legacy.DescribeElasticsearchDomainInput{DomainName: &name})
	if err != nil {
		return err
	}
	if aws.ToString(oldDomain.DomainStatus.ARN) != arn || aws.ToString(oldDomain.DomainStatus.Endpoint) != endpoint {
		return fmt.Errorf("legacy owner diverged: %+v", oldDomain.DomainStatus)
	}
	if _, err = old.UpdateElasticsearchDomainConfig(ctx, &legacy.UpdateElasticsearchDomainConfigInput{DomainName: &name, AccessPolicies: aws.String("")}); err != nil {
		return err
	}
	// Real config updates change native bulk admission then recover.
	if _, err = api.UpdateDomainConfig(ctx, &opensearch.UpdateDomainConfigInput{DomainName: &name, AdvancedOptions: map[string]string{"rest.action.multi.allow_explicit_index": "false"}}); err != nil {
		return err
	}
	if _, err = ready(ctx, api, name); err != nil {
		return err
	}
	if _, err = request(client, "POST", "/_bulk", bulk, 400); err != nil {
		return err
	}
	if _, err = api.UpdateDomainConfig(ctx, &opensearch.UpdateDomainConfigInput{DomainName: &name, AdvancedOptions: map[string]string{"rest.action.multi.allow_explicit_index": "true"}}); err != nil {
		return err
	}
	if _, err = ready(ctx, api, name); err != nil {
		return err
	}
	if err = prove(); err != nil {
		return err
	}
	// Identical resource names never share native data across account/region; a
	// second same-scope domain also gets a distinct native owner.
	for _, scope := range []struct {
		cfg  aws.Config
		name string
	}{{config("us-west-2", "test", "test"), name}, {config("us-east-1", "111111111111", "test"), name}, {root, "other-domain"}} {
		scoped := control(scope.cfg, c.endpoint)
		if _, err = scoped.CreateDomain(ctx, &opensearch.CreateDomainInput{DomainName: &scope.name}); err != nil {
			return err
		}
		owned = append(owned, ownedDomain{client: scoped, name: scope.name})
		d, e := ready(ctx, scoped, scope.name)
		if e != nil {
			return e
		}
		owned[len(owned)-1].endpoint = aws.ToString(d.Endpoint)
		isolated, e := data(scope.cfg, aws.ToString(d.Endpoint))
		if e != nil {
			return e
		}
		if _, e = request(isolated, "GET", "/catalog/_search", "", 404); e != nil {
			return e
		}
	}
	foreign, err := data(config("us-east-1", "111111111111", "test"), endpoint)
	if err != nil {
		return err
	}
	if _, err = request(foreign, "GET", "/catalog/_search", "", 403); err != nil {
		return err
	}
	wrongRegion, err := data(config("us-west-2", "test", "test"), endpoint)
	if err != nil {
		return err
	}
	if _, err = request(wrongRegion, "GET", "/catalog/_search", "", 403); err != nil {
		return err
	}
	fmt.Println("account/region/domain native data isolation and signing scope enforced")
	if err = c.stop(); err != nil {
		return err
	}
	if err = c.start(); err != nil {
		return err
	}
	if _, err = ready(ctx, api, name); err != nil {
		return err
	}
	if err = prove(); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(filepath.Join(directory, "state.db")))
	namespace := fmt.Sprintf("stackd-opensearch-%x", sum[:12])
	id := endpoint[strings.LastIndex(endpoint, "/")+1:]
	hash := sha256.Sum256([]byte(namespace + "\x00" + id))
	container := fmt.Sprintf("stackd-opensearch-node-%x", hash)
	inspected, err := exec.Command("docker", "inspect", container).Output()
	if err != nil {
		return err
	}
	var inspections []struct {
		Config struct{ Labels map[string]string }
	}
	if err = json.Unmarshal(inspected, &inspections); err != nil {
		return err
	}
	if len(inspections) != 1 || inspections[0].Config.Labels["stackd.opensearch.namespace"] != namespace || inspections[0].Config.Labels["stackd.opensearch.id"] != id {
		return errors.New("native restart ownership mismatch")
	}
	if out, e := exec.Command("docker", "restart", container).CombinedOutput(); e != nil {
		return fmt.Errorf("native restart: %w %s", e, out)
	}
	if err = wait(time.Minute, func() (bool, error) { return prove() == nil, nil }); err != nil {
		return err
	}
	fmt.Println("controller and exact-owned native restart retain query id=b sum=30")
	metrics := cloudwatch.NewFromConfig(root, func(o *cloudwatch.Options) { o.BaseEndpoint = &c.endpoint })
	if err = wait(45*time.Second, func() (bool, error) {
		out, e := metrics.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{Namespace: aws.String("AWS/ES"), MetricName: aws.String("SearchableDocuments"), Dimensions: []cwtypes.Dimension{{Name: aws.String("DomainName"), Value: &name}, {Name: aws.String("ClientId"), Value: aws.String("000000000000")}}, StartTime: aws.Time(time.Now().Add(-time.Hour)), EndTime: aws.Time(time.Now().Add(time.Minute)), Period: aws.Int32(60), Statistics: []cwtypes.Statistic{cwtypes.StatisticMaximum}})
		if e != nil {
			return false, e
		}
		for _, p := range out.Datapoints {
			if aws.ToFloat64(p.Maximum) >= 4 {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return err
	}
	trail := cloudtrail.NewFromConfig(root, func(o *cloudtrail.Options) { o.BaseEndpoint = &c.endpoint })
	events, err := trail.LookupEvents(ctx, &cloudtrail.LookupEventsInput{MaxResults: aws.Int32(50), LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("UpdateDomainConfig")}}})
	if err != nil {
		return err
	}
	found := false
	for _, event := range events.Events {
		if aws.ToString(event.EventSource) == "es.amazonaws.com" && aws.ToString(event.EventName) == "UpdateDomainConfig" {
			found = true
		}
	}
	if !found {
		return errors.New("source-owned OpenSearch CloudTrail management event absent")
	}
	fmt.Println("measured CloudWatch documents>=4 and es.amazonaws.com management audit observed")
	// Delete old incarnation, recreate the same domain, then exercise stale URL.
	if _, err = api.DeleteDomain(ctx, &opensearch.DeleteDomainInput{DomainName: &name}); err != nil {
		return err
	}
	if err = wait(time.Minute, func() (bool, error) {
		_, e := api.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: &name})
		return modeled(e, "ResourceNotFoundException") == nil, nil
	}); err != nil {
		return err
	}
	if _, err = request(client, "GET", "/catalog/_search", "", 404); err != nil {
		return err
	}
	if _, err = api.CreateDomain(ctx, &opensearch.CreateDomainInput{DomainName: &name}); err != nil {
		return err
	}
	fresh, err := ready(ctx, api, name)
	if err != nil {
		return err
	}
	if aws.ToString(fresh.Endpoint) == endpoint {
		return errors.New("recreated domain retained stale incarnation endpoint")
	}
	owned[0].endpoint = aws.ToString(fresh.Endpoint)
	if _, err = request(client, "GET", "/catalog/_search", "", 404); err != nil {
		return err
	}
	freshClient, err := data(root, aws.ToString(fresh.Endpoint))
	if err != nil {
		return err
	}
	if _, err = request(freshClient, "GET", "/catalog/_search", "", 404); err != nil {
		return err
	}
	for _, v := range owned {
		if _, err = v.client.DeleteDomain(ctx, &opensearch.DeleteDomainInput{DomainName: &v.name}); err != nil {
			return err
		}
		if err = wait(time.Minute, func() (bool, error) {
			_, e := v.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: &v.name})
			return modeled(e, "ResourceNotFoundException") == nil, nil
		}); err != nil {
			return err
		}
	}
	for _, kind := range []string{"container", "volume", "network"} {
		out, e := exec.Command("docker", kind, "ls", "--filter", "label=stackd.opensearch.namespace="+namespace, "--format", "{{.ID}}").CombinedOutput()
		if e != nil {
			return fmt.Errorf("inspect cleanup %s: %w %s", kind, e, out)
		}
		if len(bytes.TrimSpace(out)) != 0 {
			return fmt.Errorf("owned %s remains after cleanup: %s", kind, out)
		}
	}
	fmt.Println("stale incarnation remains absent after recreation; all exact-namespace containers/volumes/networks absent")
	owned = nil
	return nil
}
