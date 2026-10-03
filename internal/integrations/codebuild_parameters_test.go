package integrations

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ssm"
)

func TestCodeBuildParametersBatchSelectorsAndMissingReference(t *testing.T) {
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "111122223333", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: "111122223333"})
	repository := ssm.NewMemoryRepository(nil)
	references := make([]string, 0, 13)
	expected := make(map[string]string)
	if err := repository.Update(ctx, func(tx ssm.Transaction) error {
		for i := range 12 {
			name := fmt.Sprintf("/build/parameter-%02d", i)
			key := ssm.ParameterKey{Scope: ssm.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}, Name: name}
			resource := "arn:aws:ssm:us-east-1:111122223333:parameter" + name
			if err := tx.PutParameter(ssm.ParameterRecord{Key: key, ARN: resource, Type: "String", Tier: "Standard", DataType: "text", CurrentVersion: 1}); err != nil {
				return err
			}
			content := fmt.Sprintf("value-%02d", i)
			if err := tx.PutVersion(ssm.VersionRecord{Key: ssm.VersionKey{Parameter: key, Version: 1}, Type: "String", Tier: "Standard", DataType: "text", Value: []byte(content), Modified: time.Unix(1, 0), Labels: []string{"selected"}}); err != nil {
				return err
			}
			reference := name
			if i%2 == 0 {
				reference = resource + ":selected"
			}
			references = append(references, reference)
			expected[reference] = content
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	service := ssm.New(ssm.Config{Repository: repository})
	t.Cleanup(func() { service.Close() })
	adapter := CodeBuildParameters{Parameters: service}
	values, err := adapter.Read(ctx, references)
	if err != nil {
		t.Fatal(err)
	}
	for reference, want := range expected {
		if got, exists := values[reference]; !exists || got != want {
			t.Fatalf("batch or ARN selector lost %q", reference)
		}
	}
	values, err = adapter.Read(ctx, append(references, "/build/missing"))
	if err == nil || values != nil {
		t.Fatal("missing parameter produced a partial executable environment")
	}
	metadata := awsctx.FromContext(ctx)
	metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::111122223333:user/unprivileged", "AIDAUNPRIVILEGED"
	values, err = adapter.Read(awsctx.WithMetadata(ctx, metadata), references)
	var denied *awswire.Error
	if values != nil || !errors.As(err, &denied) || denied.Code != "AccessDeniedException" {
		t.Fatalf("CodeBuild service attribution bypassed caller authority: %v", err)
	}
}
