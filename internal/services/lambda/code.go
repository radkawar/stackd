package lambda

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

const codeDownloadPrefix = "/_stackd/lambda/code/"
const codeDownloadLifetime = 10 * time.Minute

var codeDigestPath = strings.NewReplacer("+", "-", "/", "_")

func deploymentArchive(scope Scope, code []byte, at time.Time) CodeArchive {
	digest := sha256.Sum256(code)
	return CodeArchive{Key: CodeArchiveKey{Scope: scope, SHA256: base64.StdEncoding.EncodeToString(digest[:])}, Code: code, CreatedAt: at}
}

func (s *Service) getFunction(ctx context.Context, in *api.GetFunctionInput) (*api.GetFunctionOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	key, arn := ref.FunctionKey, ref.ARN()
	out := &api.GetFunctionOutput{}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		record, err := loadFunction(tx, ref)
		if errors.Is(err, ErrNotFound) {
			if wire := s.authorize(tx.Context(), "GetFunction", arn, nil, nil, nil); wire != nil {
				return wire
			}
		}
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "GetFunction", ref, record, nil); wire != nil {
			return wire
		}
		if record.Version == 0 {
			if pending, err := tx.PendingFunction(key); err == nil {
				record = pending
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		out.Configuration = configuration(record)
		out.Configuration.FunctionArn = new(api.NameSpacedFunctionArn(arn))
		if arn == key.ARN() {
			// Native same-account GetFunction returns tags under its own permission,
			// including when a separate ListTags request is explicitly denied.
			if len(record.Tags) != 0 {
				out.Tags = make(api.Tags, len(record.Tags))
				for k, v := range record.Tags {
					out.Tags[api.TagKey(k)] = api.TagValue(v)
				}
			}
			reserved, present, err := tx.FunctionConcurrency(key)
			if err != nil {
				return err
			}
			if present {
				out.Concurrency = &api.Concurrency{ReservedConcurrentExecutions: new(api.ReservedConcurrentExecutions(reserved))}
			}
		}
		out.Code = &api.FunctionCodeLocation{RepositoryType: new(api.String("S3")), ResolvedS3Object: resolvedS3Object(record.Reference)}
		if record.Reference == nil {
			location, err := s.issueCodeURL(tx, CodeArchiveKey{Scope: key.Scope, SHA256: record.CodeSHA256})
			if err != nil {
				return err
			}
			out.Code.Location = new(api.SensitiveStringOnServerOnly(location))
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) issueCodeURL(tx Transaction, key CodeArchiveKey) (string, error) {
	if s.publicEndpoint == "" {
		return "", unsupported("Code downloads require a configured PublicEndpoint.")
	}
	signing, err := tx.CodeSigningKey(key.Scope)
	if errors.Is(err, ErrNotFound) {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return "", err
		}
		signing = CodeSigningKey{Scope: key.Scope, AccessKeyID: "STACKDLAMBDA" + rand.Text(), SecretAccessKey: base64.StdEncoding.EncodeToString(secret[:])}
		if err := tx.PutCodeSigningKey(signing); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	issued := s.clock.Now().UTC().Truncate(time.Second)
	if err := tx.RetainCodeArchive(key, issued.Add(codeDownloadLifetime)); err != nil {
		return "", err
	}
	// The opaque archive identifier cannot be redirected by resource mutation.
	digest := strings.TrimRight(codeDigestPath.Replace(key.SHA256), "=")
	location := s.publicEndpoint + codeDownloadPrefix + key.Partition + "/" + key.Account + "/" + key.Region + "/" + digest
	request, err := http.NewRequestWithContext(tx.Context(), http.MethodGet, location+"?X-Amz-Expires="+strconv.FormatInt(int64(codeDownloadLifetime/time.Second), 10), nil)
	if err != nil {
		return "", err
	}
	location, _, err = v4.NewSigner().PresignHTTP(tx.Context(), aws.Credentials{AccessKeyID: signing.AccessKeyID, SecretAccessKey: signing.SecretAccessKey}, request, "UNSIGNED-PAYLOAD", "s3", key.Region, issued, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	return location, err
}

type codeArchiveJobs struct{ s *Service }

func (j codeArchiveJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var due time.Time
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		due, found, err = r.NextCodeArchiveDeadline()
		return err
	})
	return scheduler.Job{Key: "expired-code", Due: due}, found, err
}

func (j codeArchiveJobs) Run(ctx context.Context, _ scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		_, err := tx.DeleteExpiredCodeArchives(j.s.clock.Now())
		return err
	})
}
