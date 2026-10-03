package ssm

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"stackd/clock"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func parameterReadHarness(t *testing.T) (*Service, context.Context) {
	t.Helper()
	s := New(Config{Clock: clock.Real{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	return s, ctx
}

func readTestPut(t *testing.T, s *Service, ctx context.Context, name, text string) int64 {
	t.Helper()
	out, err := runCommand(s, ctx, "PutParameter", &api.PutParameterRequest{Name: new(api.PSParameterName(name)), Value: new(api.PSParameterValue(text)), Type: new(api.ParameterType("String")), Overwrite: new(api.Boolean(true))}, s.putParameter)
	if err != nil {
		t.Fatal(err)
	}
	return int64(*out.Version)
}

func readTestError(t *testing.T, err *awswire.Error, code string) {
	t.Helper()
	if err == nil || err.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func TestParameterSelectorsLabelsAndHistory(t *testing.T) {
	s, ctx := parameterReadHarness(t)
	readTestPut(t, s, ctx, "/app/value", "old")
	readTestPut(t, s, ctx, "/app/value", "new")
	label, err := runCommand(s, ctx, "LabelParameterVersion", &api.LabelParameterVersionRequest{Name: new(api.PSParameterName("/app/value")), ParameterVersion: new(api.PSParameterVersion(1)), Labels: api.ParameterLabelList{"stable", "123bad", "awsBad", "ssmBad", "bad label", "123bad"}}, s.labelParameterVersion)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(label.InvalidLabels)
	if !slices.Equal(label.InvalidLabels, api.ParameterLabelList{"123bad", "awsBad", "bad label", "ssmBad"}) {
		t.Fatalf("invalid labels = %v", label.InvalidLabels)
	}
	for _, tc := range []struct {
		name, want string
		version    int64
	}{{"/app/value", "new", 2}, {"/app/value:1", "old", 1}, {"/app/value:01", "old", 1}, {"/app/value:stable", "old", 1}, {"arn:aws:ssm:us-east-1:123456789012:parameter/app/value:stable", "old", 1}} {
		out, err := runCommand(s, ctx, "GetParameter", &api.GetParameterRequest{Name: new(api.PSParameterName(tc.name))}, s.getParameter)
		if err != nil {
			t.Fatal(err)
		}
		if value(out.Parameter.Value) != tc.want || int64(*out.Parameter.Version) != tc.version {
			t.Fatalf("%s = %+v", tc.name, out.Parameter)
		}
	}
	for _, suffix := range []string{":missing", ":0", ":-1", ":99", ":9223372036854775808"} {
		_, err := runCommand(s, ctx, "GetParameter", &api.GetParameterRequest{Name: new(api.PSParameterName("/app/value" + suffix))}, s.getParameter)
		readTestError(t, err, "ParameterVersionNotFound")
	}
	for _, suffix := range []string{":", ":1:2"} {
		_, err = runCommand(s, ctx, "GetParameter", &api.GetParameterRequest{Name: new(api.PSParameterName("/app/value" + suffix))}, s.getParameter)
		readTestError(t, err, "ValidationException")
	}
	oldPath, err := runCommand(s, ctx, "GetParametersByPath", &api.GetParametersByPathRequest{Path: new(api.PSParameterName("/app")), ParameterFilters: api.ParameterStringFilterList{{Key: new(api.ParameterStringFilterKey("Label")), Values: api.ParameterStringFilterValueList{"stable"}}}}, s.getParametersByPath)
	if err != nil || len(oldPath.Parameters) != 1 || *oldPath.Parameters[0].Version != 1 || value(oldPath.Parameters[0].Value) != "old" || oldPath.Parameters[0].Selector != nil {
		t.Fatalf("historical label path = %+v %v", oldPath, err)
	}
	_, err = runCommand(s, ctx, "LabelParameterVersion", &api.LabelParameterVersionRequest{Name: new(api.PSParameterName("/app/value")), Labels: api.ParameterLabelList{"stable"}}, s.labelParameterVersion)
	if err != nil {
		t.Fatal(err)
	}
	history, err := runCommand(s, ctx, "GetParameterHistory", &api.GetParameterHistoryRequest{Name: new(api.PSParameterName("/app/value"))}, s.getParameterHistory)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Parameters) != 2 || value(history.Parameters[0].Value) != "old" || value(history.Parameters[1].Value) != "new" || len(history.Parameters[0].Labels) != 0 || !slices.Equal(history.Parameters[1].Labels, api.ParameterLabelList{"stable"}) {
		t.Fatalf("history = %+v", history.Parameters)
	}
	removed, err := runCommand(s, ctx, "UnlabelParameterVersion", &api.UnlabelParameterVersionRequest{Name: new(api.PSParameterName("/app/value")), ParameterVersion: new(api.PSParameterVersion(2)), Labels: api.ParameterLabelList{"absent", "stable", "stable"}}, s.unlabelParameterVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(removed.InvalidLabels, api.ParameterLabelList{"absent"}) || !slices.Equal(removed.RemovedLabels, api.ParameterLabelList{"stable"}) {
		t.Fatalf("unlabel = %+v", removed)
	}
}

func TestParameterBatchOrderAndPendingVisibility(t *testing.T) {
	s, ctx := parameterReadHarness(t)
	readTestPut(t, s, ctx, "/batch/z", "first")
	readTestPut(t, s, ctx, "/batch/z", "second")
	readTestPut(t, s, ctx, "/batch/a", "alpha")
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		p, err := tx.Parameter(ParameterKey{Scope: scopeFor(ctx), Name: "/batch/z"})
		if err != nil {
			return err
		}
		v := VersionRecord{Key: VersionKey{Parameter: p.Key, Version: 3}, Type: "String", Value: []byte("pending"), Labels: []string{"pending"}}
		if err := tx.PutVersion(v); err != nil {
			return err
		}
		p.Key.Name = "/batch/unpublished"
		p.ARN = parameterARN(p.Key)
		p.CurrentVersion = 0
		return tx.PutParameter(p)
	}); err != nil {
		t.Fatal(err)
	}
	out, err := s.GetParameters(ctx, &api.GetParametersRequest{Names: api.ParameterNameList{"/batch/z:1", "/batch/z", "/batch/a", "/batch/a", "/batch/z:3", "/batch/unpublished"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Parameters) != 3 || value(out.Parameters[0].Name) != "/batch/a" || !slices.Equal(out.InvalidParameters, api.ParameterNameList{"/batch/unpublished", "/batch/z:3"}) {
		t.Fatalf("batch = %+v", out)
	}
	versions := []api.PSParameterVersion{*out.Parameters[1].Version, *out.Parameters[2].Version}
	slices.Sort(versions)
	if !slices.Equal(versions, []api.PSParameterVersion{1, 2}) {
		t.Fatalf("selected versions = %v", versions)
	}
	history, err := runCommand(s, ctx, "GetParameterHistory", &api.GetParameterHistoryRequest{Name: new(api.PSParameterName("/batch/z"))}, s.getParameterHistory)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Parameters) != 2 || *history.Parameters[1].Version != 2 {
		t.Fatalf("pending history = %+v", history)
	}
}

func TestParameterTopLevelReadAliases(t *testing.T) {
	s, ctx := parameterReadHarness(t)
	readTestPut(t, s, ctx, "bare", "value")
	for _, name := range []string{"bare", "/bare"} {
		out, err := runCommand(s, ctx, "GetParameter", &api.GetParameterRequest{Name: new(api.PSParameterName(name))}, s.getParameter)
		if err != nil || value(out.Parameter.Name) != name || value(out.Parameter.Value) != "value" {
			t.Fatalf("alias %s = %+v %v", name, out, err)
		}
	}
	out, err := s.GetParameters(ctx, &api.GetParametersRequest{Names: api.ParameterNameList{"bare", "/bare", "bare"}})
	if err != nil || len(out.Parameters) != 2 || value(out.Parameters[0].Name) != "/bare" || value(out.Parameters[1].Name) != "bare" {
		t.Fatalf("batch aliases = %+v %v", out, err)
	}
	metadata, err := runCommand(s, ctx, "DescribeParameters", &api.DescribeParametersRequest{}, s.describeParameters)
	if err != nil || len(metadata.Parameters) != 1 || value(metadata.Parameters[0].Name) != "bare" {
		t.Fatalf("stored spelling = %+v %v", metadata, err)
	}
}

func TestParameterLabelsProtectVersionCapAtomically(t *testing.T) {
	s, ctx := parameterReadHarness(t)
	key := ParameterKey{Scope: scopeFor(ctx), Name: "/versions"}
	modified := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		p := ParameterRecord{Key: key, ARN: parameterARN(key), Type: "String", Tier: "Standard", DataType: "text", CurrentVersion: 100}
		if err := tx.PutParameter(p); err != nil {
			return err
		}
		for number := int64(1); number <= 100; number++ {
			v := VersionRecord{Key: VersionKey{Parameter: key, Version: number}, Type: "String", Tier: "Standard", DataType: "text", Value: []byte(fmt.Sprint(number)), Modified: modified}
			if number == 1 {
				v.Labels = []string{"pinned"}
			}
			if number == 2 {
				for i := range 10 {
					v.Labels = append(v.Labels, fmt.Sprintf("label%d", i))
				}
			}
			if err := tx.PutVersion(v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	input := &api.PutParameterRequest{Name: new(api.PSParameterName(key.Name)), Value: new(api.PSParameterValue("next")), Overwrite: new(api.Boolean(true))}
	_, err := runCommand(s, ctx, "PutParameter", input, s.putParameter)
	readTestError(t, err, "ParameterMaxVersionLimitExceeded")
	_, err = runCommand(s, ctx, "LabelParameterVersion", &api.LabelParameterVersionRequest{Name: input.Name, ParameterVersion: new(api.PSParameterVersion(2)), Labels: api.ParameterLabelList{"pinned"}}, s.labelParameterVersion)
	readTestError(t, err, "ParameterVersionLabelLimitExceeded")
	pinned, err := runCommand(s, ctx, "GetParameter", &api.GetParameterRequest{Name: new(api.PSParameterName("/versions:pinned"))}, s.getParameter)
	if err != nil || *pinned.Parameter.Version != 1 {
		t.Fatalf("failed move lost pin: %+v %v", pinned, err)
	}
	_, err = runCommand(s, ctx, "UnlabelParameterVersion", &api.UnlabelParameterVersionRequest{Name: input.Name, ParameterVersion: new(api.PSParameterVersion(2)), Labels: api.ParameterLabelList{"label0"}}, s.unlabelParameterVersion)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runCommand(s, ctx, "LabelParameterVersion", &api.LabelParameterVersionRequest{Name: input.Name, ParameterVersion: new(api.PSParameterVersion(2)), Labels: api.ParameterLabelList{"pinned", "pinned"}}, s.labelParameterVersion)
	if err != nil {
		t.Fatal(err)
	}
	next, err := runCommand(s, ctx, "PutParameter", input, s.putParameter)
	if err != nil || *next.Version != 101 {
		t.Fatalf("released cap = %+v %v", next, err)
	}
	_, err = runCommand(s, ctx, "GetParameter", &api.GetParameterRequest{Name: new(api.PSParameterName("/versions:1"))}, s.getParameter)
	readTestError(t, err, "ParameterVersionNotFound")
	history, err := runCommand(s, ctx, "GetParameterHistory", &api.GetParameterHistoryRequest{Name: input.Name, MaxResults: new(api.MaxResults(1))}, s.getParameterHistory)
	if err != nil {
		t.Fatal(err)
	}
	first := history.Parameters[0]
	if *first.Version != 2 || value(first.Value) != "2" || !first.LastModifiedDate.Equal(modified) || len(first.Labels) != 10 {
		t.Fatalf("label move mutated version: %+v", first)
	}
}

type readPolicySource struct{ documents []policy.Policy }

func (p readPolicySource) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: p.documents}, nil
}

func TestParameterPathAndHistoryIndependentAuthority(t *testing.T) {
	s, root := parameterReadHarness(t)
	readTestPut(t, s, root, "/authority/denied", "secret")
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParametersByPath","Resource":"arn:aws:ssm:us-east-1:123456789012:parameter/authority","Condition":{"Bool":{"ssm:Recursive":"true"}}},{"Effect":"Deny","Action":["ssm:GetParameter","ssm:GetParametersByPath"],"Resource":"arn:aws:ssm:us-east-1:123456789012:parameter/authority/denied"},{"Effect":"Allow","Action":"ssm:GetParameterHistory","Resource":"arn:aws:ssm:us-east-1:123456789012:parameter/authority/denied"},{"Effect":"Allow","Action":"ssm:DescribeParameters","Resource":"*"}]}`
	s.authorizer = authorization.New(readPolicySource{[]policy.Policy{{Document: document}}}, nil)
	metadata := awsctx.FromContext(root)
	metadata.PrincipalARN = "arn:aws:iam::123456789012:user/reader"
	metadata.PrincipalID = "AIDAREADER"
	ctx := awsctx.WithMetadata(root, metadata)
	path, err := runCommand(s, ctx, "GetParametersByPath", &api.GetParametersByPathRequest{Path: new(api.PSParameterName("/authority")), Recursive: new(api.Boolean(true))}, s.getParametersByPath)
	if err != nil || len(path.Parameters) != 1 || value(path.Parameters[0].Value) != "secret" {
		t.Fatalf("recursive inherited authority = %+v %v", path, err)
	}
	_, err = runCommand(s, ctx, "GetParametersByPath", &api.GetParametersByPathRequest{Path: new(api.PSParameterName("/authority"))}, s.getParametersByPath)
	readTestError(t, err, "AccessDeniedException")
	_, err = runCommand(s, ctx, "GetParameter", &api.GetParameterRequest{Name: new(api.PSParameterName("/authority/denied"))}, s.getParameter)
	readTestError(t, err, "AccessDeniedException")
	history, err := runCommand(s, ctx, "GetParameterHistory", &api.GetParameterHistoryRequest{Name: new(api.PSParameterName("/authority/denied"))}, s.getParameterHistory)
	if err != nil || len(history.Parameters) != 1 || value(history.Parameters[0].Value) != "secret" {
		t.Fatalf("independent history authority = %+v %v", history, err)
	}
	described, err := runCommand(s, ctx, "DescribeParameters", &api.DescribeParametersRequest{}, s.describeParameters)
	if err != nil || len(described.Parameters) != 1 || value(described.Parameters[0].Name) != "/authority/denied" {
		t.Fatalf("describe wildcard authority = %+v %v", described, err)
	}
}
