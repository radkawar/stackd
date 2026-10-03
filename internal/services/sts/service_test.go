package sts_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/sts"
)

// These provider tests inject resolved identity metadata. End-to-end gateway
// tests separately verify SigV4 and session-token authentication.
func clientFor(t *testing.T, s *sts.Service, c identity.Credential, region string) *sdksts.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := awsctx.Metadata{AccountID: c.AccountID, Region: region, Partition: "aws", AccessKeyID: c.AccessKeyID, PrincipalARN: c.PrincipalARN, PrincipalID: c.PrincipalID, UserName: c.UserName, RequestID: "sts-sdk-test"}
		s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)))
	}))
	t.Cleanup(server.Close)
	return sdksts.New(sdksts.Options{Region: region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken), Retryer: aws.NopRetryer{}})
}

func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != want {
		t.Fatalf("error = %v; want AWS %s", err, want)
	}
}

func TestGetSessionTokenIdentityAndDurations(t *testing.T) {
	store := identity.NewStore("123456789012")
	s := sts.NewWithIdentity(store)
	ctx := context.Background()
	root, err := store.Resolve(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateAccessKey(identity.Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/app/Alice", ID: "AIDATESTPRINCIPAL", UserName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		parent   identity.Credential
		duration *int32
		want     time.Duration
	}{
		{"root default", root, nil, time.Hour},
		{"root capped", root, aws.Int32(129600), time.Hour},
		{"root minimum", root, aws.Int32(900), 15 * time.Minute},
		{"user default", user, nil, 12 * time.Hour},
		{"user maximum", user, aws.Int32(129600), 36 * time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := clientFor(t, s, test.parent, "us-east-1")
			before := time.Now()
			out, err := client.GetSessionToken(ctx, &sdksts.GetSessionTokenInput{DurationSeconds: test.duration})
			if err != nil {
				t.Fatal(err)
			}
			if out.Credentials == nil || out.Credentials.Expiration == nil {
				t.Fatal("missing session credentials")
			}
			duration := out.Credentials.Expiration.Sub(before)
			if duration < test.want-time.Second || duration > test.want+time.Second {
				t.Fatalf("session duration = %v; want %v", duration, test.want)
			}
			session, err := store.Resolve(ctx, aws.ToString(out.Credentials.AccessKeyId))
			if err != nil {
				t.Fatal(err)
			}
			if session.SecretAccessKey != aws.ToString(out.Credentials.SecretAccessKey) || session.SessionToken != aws.ToString(out.Credentials.SessionToken) || session.SessionType != identity.SessionTypeGetSessionToken {
				t.Fatal("session response differs from stored credential")
			}
			otherRegion := clientFor(t, s, session, "eu-west-1")
			who, err := otherRegion.GetCallerIdentity(ctx, &sdksts.GetCallerIdentityInput{})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(who.Account) != test.parent.AccountID || aws.ToString(who.Arn) != test.parent.PrincipalARN || aws.ToString(who.UserId) != test.parent.PrincipalID {
				t.Fatalf("session principal: %+v", who)
			}
			_, err = otherRegion.GetSessionToken(ctx, &sdksts.GetSessionTokenInput{})
			requireCode(t, err, "AccessDenied")
		})
	}
}

func TestSessionValidationAndCallerAccountIsolation(t *testing.T) {
	store := identity.NewStore("123456789012")
	s := sts.NewWithIdentity(store)
	ctx := context.Background()
	root, err := store.Resolve(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	c := clientFor(t, s, root, "us-east-1")
	for _, seconds := range []int32{0, 899, 129601} {
		_, err := c.GetSessionToken(ctx, &sdksts.GetSessionTokenInput{DurationSeconds: aws.Int32(seconds)})
		requireCode(t, err, "ValidationError")
	}
	_, err = c.GetSessionToken(ctx, &sdksts.GetSessionTokenInput{SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/test")})
	requireCode(t, err, "ValidationError")
	_, err = c.GetSessionToken(ctx, &sdksts.GetSessionTokenInput{SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/test"), TokenCode: aws.String("123456")})
	requireCode(t, err, "NotImplemented")
	otherRoot, err := store.Resolve(ctx, "999999999999")
	if err != nil {
		t.Fatal(err)
	}
	other := clientFor(t, s, otherRoot, "us-west-2")
	out, err := other.GetSessionToken(ctx, &sdksts.GetSessionTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Resolve(ctx, aws.ToString(out.Credentials.AccessKeyId))
	if err != nil || session.AccountID != "999999999999" || session.PrincipalID != "999999999999" {
		t.Fatalf("other-account session: %v, %v", session, err)
	}
	for _, parent := range []identity.Credential{root, otherRoot, session} {
		who, err := clientFor(t, s, parent, "eu-west-1").GetCallerIdentity(ctx, &sdksts.GetCallerIdentityInput{})
		if err != nil || aws.ToString(who.Account) != parent.AccountID || aws.ToString(who.Arn) != parent.PrincipalARN {
			t.Fatalf("caller identity: %+v, %v", who, err)
		}
	}
}
