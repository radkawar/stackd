package stackd_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"stackd"
)

func TestOutboundIdentityAWSInputErrors(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/outbound_identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Service, Operation, Code, Region, Endpoint string
			Input                                            map[string]any
			Status                                           int `json:"http_status"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	c, _ := outboundCloud(t, stackd.Config{})
	for _, row := range fixture.Observations {
		if !strings.HasPrefix(row.Case, "original_") {
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			values := url.Values{"Action": {row.Operation}, "Version": {"2011-06-15"}}
			var encode func(string, any)
			encode = func(name string, value any) {
				switch v := value.(type) {
				case map[string]any:
					for key, item := range v {
						encode(name+"."+key, item)
					}
				case []any:
					for i, item := range v {
						encode(fmt.Sprintf("%s.member.%d", name, i+1), item)
					}
				default:
					values.Set(name, fmt.Sprint(v))
				}
			}
			for key, value := range row.Input {
				encode(key, value)
			}
			body := values.Encode()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.server.URL, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if row.Endpoint == "https://sts.amazonaws.com" {
				request.Host = "sts.amazonaws.com"
			}
			digest := sha256.Sum256([]byte(body))
			if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, hex.EncodeToString(digest[:]), row.Service, row.Region, time.Now()); err != nil {
				t.Fatal(err)
			}
			response, err := c.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var output struct {
				Error struct{ Code, Message string }
			}
			if err := xml.NewDecoder(response.Body).Decode(&output); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != row.Status || output.Error.Code != row.Code {
				t.Fatalf("got %d %s (%s), AWS %d %s", response.StatusCode, output.Error.Code, output.Error.Message, row.Status, row.Code)
			}
		})
	}
}

func TestOutboundIdentityAWSPayloadByteBoundary(t *testing.T) {
	c, source := outboundCloud(t, stackd.Config{})
	ctx := t.Context()
	root := c.iam("test", "test", "")
	if _, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{}); err != nil {
		t.Fatal(err)
	}
	_, key, secret := c.user(t, "test", "payload")
	putUserPolicy(t, root, "payload", allow(`["sts:GetWebIdentityToken","sts:TagGetWebIdentityToken"]`, "*"))
	advanceClock(t, source, 10*time.Second)
	caller := c.sts(key, secret, "")
	padded := func(size int, algorithm string) *sts.GetWebIdentityTokenInput {
		in := &sts.GetWebIdentityTokenInput{SigningAlgorithm: &algorithm, DurationSeconds: aws.Int32(60)}
		for range 10 {
			n := min(size, 999)
			in.Audience = append(in.Audience, strings.Repeat("a", n+1))
			size -= n
		}
		for i := range 50 {
			n := min(size, 256)
			in.Tags = append(in.Tags, ststypes.Tag{Key: aws.String(fmt.Sprint(i)), Value: aws.String(strings.Repeat("v", n))})
			size -= n
		}
		return in
	}
	initial, err := caller.GetWebIdentityToken(ctx, padded(0, "RS256"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.Split(aws.ToString(initial.WebIdentityToken), ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	// AWS capture reached the same decoded 14,984-byte boundary with a user
	// and a role, both algorithms, ASCII, escaped quotes and UTF-8 text.
	padding := 14984 - len(body)
	for _, algorithm := range []string{"RS256", "ES384"} {
		out, err := caller.GetWebIdentityToken(ctx, padded(padding, algorithm))
		if err != nil || out.WebIdentityToken == nil {
			t.Fatalf("exact boundary %s: %v", algorithm, err)
		}
		_, err = caller.GetWebIdentityToken(ctx, padded(padding+1, algorithm))
		assertAPIError(t, err, "JWTPayloadSizeExceededException")
	}
	for _, value := range []string{"é", `"`} {
		in := padded(padding, "RS256")
		in.Audience[0] = value + in.Audience[0][1:]
		_, err := caller.GetWebIdentityToken(ctx, in)
		assertAPIError(t, err, "JWTPayloadSizeExceededException")
	}
}
