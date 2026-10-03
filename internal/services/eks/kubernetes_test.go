package eks

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"stackd/internal/awsctx"
	"stackd/internal/gateway"
)

func TestTokenEndpointScopeAndClusterBinding(t *testing.T) {
	verifier, err := gateway.New(&gateway.Registry{}, gateway.Config{AccountID: "111111111111"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, host, region, partition, expires string
		valid                                  bool
	}{
		{"global", "sts.amazonaws.com", "us-east-1", "aws", "60", true},
		{"other regional", "sts.us-west-2.amazonaws.com", "us-west-2", "aws", "60", true},
		{"FIPS", "sts-fips.us-east-1.amazonaws.com", "us-east-1", "aws", "60", true},
		{"dual stack", "sts.us-east-1.api.aws", "us-east-1", "aws", "60", true},
		{"FIPS dual stack", "sts-fips.us-east-1.api.aws", "us-east-1", "aws", "60", true},
		{"zero presign parameter", "sts.us-east-1.amazonaws.com", "us-east-1", "aws", "0", true},
		{"wrong signing region", "sts.us-east-1.amazonaws.com", "us-west-2", "aws", "60", false},
		{"wrong global signing region", "sts.amazonaws.com", "us-west-2", "aws", "60", false},
		{"wrong partition", "sts.cn-north-1.amazonaws.com.cn", "cn-north-1", "aws", "60", false},
		{"forged host suffix", "sts.us-east-1.amazonaws.com.invalid", "us-east-1", "aws", "60", false},
		{"excessive presign parameter", "sts.us-east-1.amazonaws.com", "us-east-1", "aws", "901", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+tc.host+"/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Expires="+tc.expires, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("x-k8s-aws-id", "workloads")
			empty := sha256.Sum256(nil)
			uri, _, err := v4.NewSigner().PresignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, hex.EncodeToString(empty[:]), "sts", tc.region, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			token := "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(uri))
			key := Key{Scope: Scope{Partition: tc.partition, Region: "eu-west-1"}, Name: "workloads"}
			parsed, err := tokenRequest(t.Context(), token, key)
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid endpoint scope admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			authenticated, rejected := verifier.AuthenticateEKS(parsed.Request, parsed.Region)
			if rejected != nil {
				t.Fatal(rejected)
			}
			if awsctx.FromContext(authenticated.Context()).PrincipalARN != "arn:aws:iam::111111111111:root" {
				t.Fatal("signed identity changed")
			}
			key.Name = "other-cluster"
			rebound, err := tokenRequest(t.Context(), token, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, rejected = verifier.AuthenticateEKS(rebound.Request, rebound.Region); rejected == nil {
				t.Fatal("signed cluster rebinding admitted")
			}
		})
	}
}

func TestPrincipalIdentityDoesNotElevateFederationIssuer(t *testing.T) {
	issuer := "arn:aws:iam::111111111111:user/admin"
	federated := awsctx.Metadata{SessionType: "GetFederationToken", PrincipalARN: "arn:aws:sts::111111111111:federated-user/restricted", PrincipalID: "111111111111:restricted", IssuerARN: issuer, IssuerID: "AIDAadmin"}
	arn, id := principalIdentity(federated)
	if arn != federated.PrincipalARN || id != federated.PrincipalID {
		t.Fatalf("federated identity elevated to issuer: %s %s", arn, id)
	}
	role := awsctx.Metadata{SessionType: "AssumeRole", PrincipalARN: "arn:aws:sts::111111111111:assumed-role/developer/session", PrincipalID: "AROAdeveloper:session", IssuerARN: "arn:aws:iam::111111111111:role/path/developer", IssuerID: "AROAdeveloper"}
	arn, id = principalIdentity(role)
	if arn != role.IssuerARN || id != role.IssuerID {
		t.Fatalf("role session lost immutable role identity: %s %s", arn, id)
	}
}
