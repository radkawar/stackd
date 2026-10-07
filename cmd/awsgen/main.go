// Command awsgen derives frontend contracts and DTOs from a local AWS SDK for
// Go v2 Smithy checkout. It never downloads source or contacts AWS.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"stackd/internal/awsschema"
)

type options struct {
	SDK, Services, CatalogOut, APIOut string
	Check                             bool
}

func main() {
	var o options
	flag.StringVar(&o.SDK, "sdk", "clones/aws-sdk-go-v2", "local AWS SDK for Go v2 checkout")
	flag.StringVar(&o.Services, "services", "account,apigateway=api-gateway,apigatewaymanagementapi,apigatewayv2,appconfig,appconfigdata,applicationautoscaling=application-auto-scaling,athena,autoscaling=auto-scaling,cloudformation,cloudtrail,cloudwatch,codebuild,codepipeline,cognitoidp=cognito-identity-provider,dynamodb,dynamodbstreams=dynamodb-streams,ebs,ec2,ecr,ecs,eks,eksauth=eks-auth,elasticache,elbv2=elastic-load-balancing-v2,es=elasticsearch-service,eventbridge,firehose,glue,guardduty,iam,kafka,kinesis,kms,lambda,logs=cloudwatch-logs,memorydb,opensearch,organizations,pipes,ram,rds,rdsdata=rds-data,resourcegroups=resource-groups,resourcegroupstaggingapi=resource-groups-tagging-api,s3,s3control=s3-control,scheduler,secretsmanager=secrets-manager,servicecatalogappregistry=service-catalog-appregistry,ses,sesv2,sns,sqs,ssm,stepfunctions=sfn,sts,wafv2,xray"+",mq,signer,docdb,cloudcontrol,configservice=config-service,route53=route-53,acm,cognitoidentity=cognito-identity,identitystore,ssoadmin=sso-admin,ssooidc=sso-oidc,sso,appsync", "comma-separated service names, optionally service=model")
	flag.StringVar(&o.CatalogOut, "out", "internal/awscatalog", "catalog output directory")
	flag.StringVar(&o.APIOut, "api-out", "internal/awsapi", "typed frontend output directory")
	flag.BoolVar(&o.Check, "check", false, "check generated output without writing files")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "awsgen: unexpected positional arguments")
		os.Exit(2)
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "awsgen:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	output, err := exec.Command("git", "-C", o.SDK, "rev-parse", "HEAD").Output()
	if err != nil {
		return fmt.Errorf("read SDK checkout revision: %w", err)
	}
	revision := strings.TrimSpace(string(output))
	if !regexp.MustCompile(`^[0-9a-f]{40,64}$`).MatchString(revision) {
		return errors.New("SDK checkout has invalid revision")
	}
	models := make(map[string]string)
	serviceName := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	modelName := regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	for _, selection := range strings.Split(o.Services, ",") {
		name, model, explicit := strings.Cut(strings.TrimSpace(selection), "=")
		if !explicit {
			model = name
		}
		if !serviceName.MatchString(name) || !modelName.MatchString(model) {
			return fmt.Errorf("invalid service model selection %q", selection)
		}
		if previous, exists := models[name]; exists && previous != model {
			return fmt.Errorf("service %s selects both %s and %s models", name, previous, model)
		}
		models[name] = model
	}
	var contracts []contract
	for _, name := range sortedKeys(models) {
		path := filepath.ToSlash(filepath.Join("codegen", "sdk-codegen", "aws-models", models[name]+".json"))
		data, err := os.ReadFile(filepath.Join(o.SDK, filepath.FromSlash(path)))
		if err != nil {
			return fmt.Errorf("read %s model: %w", name, err)
		}
		status, err := exec.Command("git", "-C", o.SDK, "status", "--porcelain", "--", path).Output()
		if err != nil {
			return fmt.Errorf("read model status: %w", err)
		}
		c, err := parseModel(name, data, awsschema.Source{Repository: "https://github.com/aws/aws-sdk-go-v2", Revision: revision, Path: path, Modified: len(status) > 0})
		if err != nil {
			return err
		}
		contracts = append(contracts, c)
	}
	files, err := generate(contracts, o.CatalogOut, o.APIOut)
	if err != nil {
		return err
	}
	partitions, err := os.ReadFile(filepath.Join(o.SDK, "internal", "endpoints", "awsrulesfn", "partitions.json"))
	if err != nil {
		return fmt.Errorf("read SDK region descriptions: %w", err)
	}
	regions, err := renderRegionCompatibility(partitions, revision)
	if err != nil {
		return fmt.Errorf("render region catalogue: %w", err)
	}
	files[filepath.Join(o.CatalogOut, "generated_regions.go")] = regions
	if _, selected := models["ec2"]; selected {
		catalog, err := os.ReadFile("testdata/aws/ec2/instance_types.json")
		if err != nil {
			return fmt.Errorf("read native EC2 instance catalog: %w", err)
		}
		credits, err := os.ReadFile("testdata/aws/ec2/instance_credit_defaults.json")
		if err != nil {
			return fmt.Errorf("read EC2 credit rates: %w", err)
		}
		metadata, err := renderInstanceTypeMetadata(catalog, credits)
		if err != nil {
			return fmt.Errorf("render EC2 instance metadata: %w", err)
		}
		files[filepath.Join(filepath.Dir(o.APIOut), "services", "ec2", "instance_types_generated.json")] = metadata
		routes, err := os.ReadFile("testdata/aws/ec2/instances_metadata_depth_handoff.json")
		if err != nil {
			return fmt.Errorf("read native IMDS routes: %w", err)
		}
		routing, err := renderInstanceMetadataRoutes(routes)
		if err != nil {
			return fmt.Errorf("render native IMDS routes: %w", err)
		}
		files[filepath.Join(filepath.Dir(o.APIOut), "services", "ec2", "instance_metadata_generated.go")] = routing
	}
	return writeGenerated(files, o.Check)
}

func generate(contracts []contract, catalogOut, apiOut string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	index, err := renderIndex(contracts)
	if err != nil {
		return nil, err
	}
	files[filepath.Join(catalogOut, "generated.go")] = index
	inputs, err := renderCommandInputs(contracts)
	if err != nil {
		return nil, err
	}
	files[filepath.Join(filepath.Dir(apiOut), "awscommands", "inputs_generated.go")] = inputs
	for _, c := range contracts {
		catalog, err := renderCatalog(c)
		if err != nil {
			return nil, fmt.Errorf("render %s catalog: %w", c.Info.Name, err)
		}
		files[filepath.Join(catalogOut, "generated_"+c.Info.Name+".go")] = catalog
		metadata, err := renderServiceMetadata(c)
		if err != nil {
			return nil, fmt.Errorf("render %s metadata: %w", c.Info.Name, err)
		}
		files[filepath.Join(catalogOut, "models", c.Info.Name, "generated.go")] = metadata
		types, err := renderTypes(c)
		if err != nil {
			return nil, fmt.Errorf("render %s types: %w", c.Info.Name, err)
		}
		files[filepath.Join(apiOut, c.Info.Name, "types_generated.go")] = types
		clones, err := renderClones(c)
		if err != nil {
			return nil, fmt.Errorf("render %s clones: %w", c.Info.Name, err)
		}
		if clones != nil {
			files[filepath.Join(apiOut, c.Info.Name, "clone_generated.go")] = clones
		}
		if c.Info.Name == "ec2" {
			conversions, err := renderLaunchTemplateConversions(c)
			if err != nil {
				return nil, fmt.Errorf("render launch-template conversions: %w", err)
			}
			files[filepath.Join(apiOut, c.Info.Name, "launch_template_generated.go")] = conversions
		}
		checksums, err := renderChecksums(c)
		if err != nil {
			return nil, fmt.Errorf("render %s checksums: %w", c.Info.Name, err)
		}
		if checksums != nil {
			files[filepath.Join(apiOut, c.Info.Name, "checksum_generated.go")] = checksums
		}
		decoder, err := renderDecoder(c)
		if err != nil {
			return nil, fmt.Errorf("render %s decoder: %w", c.Info.Name, err)
		}
		files[filepath.Join(apiOut, c.Info.Name, "decode_generated.go")] = decoder
		if c.Info.Name == "iam" || c.Info.Name == "organizations" || c.Info.Name == "sns" {
			authorization, err := renderAuthorization(c)
			if err != nil {
				return nil, fmt.Errorf("render %s authorization: %w", c.Info.Name, err)
			}
			files[filepath.Join(apiOut, c.Info.Name, "authorization_generated.go")] = authorization
		}
		if c.Info.Name == "iam" || c.Info.Name == "organizations" {
			pagination, err := renderPagination(c)
			if err != nil {
				return nil, fmt.Errorf("render %s pagination: %w", c.Info.Name, err)
			}
			files[filepath.Join(apiOut, c.Info.Name, "pagination_generated.go")] = pagination
		}
		if c.Info.Protocol == awsschema.AWSJSON10 || c.Info.Protocol == awsschema.AWSJSON11 || c.Info.Protocol == awsschema.AWSQuery || c.Info.Protocol == awsschema.EC2Query || c.Info.Protocol == awsschema.RestJSON || c.Info.Protocol == awsschema.RestXML || c.Info.Protocol == awsschema.RPCV2CBOR {
			encoder, err := renderEncoder(c)
			if err != nil {
				return nil, fmt.Errorf("render %s encoder: %w", c.Info.Name, err)
			}
			files[filepath.Join(apiOut, c.Info.Name, "encode_generated.go")] = encoder
		}
	}
	return files, nil
}

func writeGenerated(files map[string][]byte, check bool) error {
	var drift []string
	for _, path := range sortedKeys(files) {
		current, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if bytes.Equal(current, files[path]) {
			continue
		}
		if check {
			drift = append(drift, path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(path), ".awsgen-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		if _, err = tmp.Write(files[path]); err == nil {
			err = tmp.Chmod(0o644)
		}
		closeErr := tmp.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(tmpName, path)
		}
		if err != nil {
			_ = os.Remove(tmpName)
			return err
		}
	}
	if len(drift) > 0 {
		return fmt.Errorf("generated output is stale: %s", strings.Join(drift, ", "))
	}
	return nil
}
