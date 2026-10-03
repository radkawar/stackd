package ecs

import (
	"reflect"
	"slices"
	"testing"

	api "stackd/internal/awsapi/ecs"
)

func TestTaskParameterEnvironmentPrecedenceDoesNotMutateDefinition(t *testing.T) {
	container := api.ContainerDefinition{
		Environment: api.EnvironmentVariables{{Name: new(api.String("TOKEN")), Value: new(api.String("plaintext"))}},
		Secrets: api.SecretList{
			{Name: new(api.String("TOKEN")), ValueFrom: new(api.String("/token"))},
			{Name: new(api.String("AWS_REGION")), ValueFrom: new(api.String("/region"))},
		},
	}
	environment := taskEnvironment(container, []string{"AWS_REGION=us-east-1"}, map[string]string{"/token": "resolved-sensitive", "/region": "not-the-runtime-region"}, nil)
	if !slices.Contains(environment, "TOKEN=resolved-sensitive") || !slices.Contains(environment, "AWS_REGION=us-east-1") || slices.Contains(environment, "TOKEN=plaintext") {
		t.Fatal("task secret or runtime environment precedence is incorrect")
	}
	if value(container.Environment[0].Value) != "plaintext" || value(container.Secrets[0].ValueFrom) != "/token" {
		t.Fatal("native secret injection changed the persisted definition")
	}
}

func TestTaskSecretReferenceAdmission(t *testing.T) {
	for _, scenario := range []struct {
		reference string
		allowed   bool
	}{
		{"/parameter", true},
		{"arn:aws:ssm:us-east-1:111122223333:parameter/token", true},
		{"arn:aws:secretsmanager:us-east-1:111122223333:secret:token:key::", true},
		{"arn:aws:secretsmanager:us-east-1:111122223333:secret:token:key:AWSPREVIOUS:", true},
		{"arn:aws:secretsmanager:us-east-1:111122223333:secret:token:key::version", true},
		{"arn:aws:secretsmanager:us-east-1:111122223333:secret:token:key:AWSCURRENT:version", false},
		{"arn:aws:s3:::bucket/token", false},
	} {
		definition := api.TaskDefinition{ContainerDefinitions: api.ContainerDefinitions{{Secrets: api.SecretList{{Name: new(api.String("TOKEN")), ValueFrom: new(api.String(scenario.reference))}}}}}
		if rejected := executableTaskDefinition(definition, api.TaskOverride{}); (rejected == nil) != scenario.allowed {
			t.Fatalf("reference %s: %v", scenario.reference, rejected)
		}
	}
}

func TestTaskEnvironmentFileLiteralParsingAndPrecedence(t *testing.T) {
	files := map[string]string{}
	if err := parseTaskEnvironmentFile([]byte("\ufeff# comment\r\nDUP=first\nDUP=ignored\nBLANK=\nLITERAL= \"quoted\" $HOME\\n \nUTF8=é\nTOKEN=file\n"), files); err != nil {
		t.Fatal(err)
	}
	if err := parseTaskEnvironmentFile([]byte("DUP=second\nSECOND=two\nTOKEN=other\n"), files); err != nil {
		t.Fatal(err)
	}
	container := api.ContainerDefinition{Environment: api.EnvironmentVariables{{Name: new(api.String("TOKEN")), Value: new(api.String("explicit"))}}}
	got := taskEnvironment(container, nil, nil, files)
	want := []string{"DUP=first", "LITERAL= \"quoted\" $HOME\\n ", "SECOND=two", "TOKEN=explicit", "UTF8=é"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment = %#v; want %#v", got, want)
	}
	for _, body := range [][]byte{[]byte("TOKEN=secret\ninvalid"), []byte("=value"), []byte("X=\x00"), {0xff}} {
		if err := parseTaskEnvironmentFile(body, map[string]string{}); err == nil {
			t.Fatalf("invalid environment file accepted: %q", body)
		}
	}
}

func TestTaskEnvironmentFileOverrideReplacesDefinition(t *testing.T) {
	file := func(reference string) api.EnvironmentFile {
		return api.EnvironmentFile{Type: new(api.EnvironmentFileType("s3")), Value: new(api.String(reference))}
	}
	record := TaskRecord{Definition: api.TaskDefinition{ContainerDefinitions: api.ContainerDefinitions{{Name: new(api.String("app")), EnvironmentFiles: api.EnvironmentFiles{file("arn:aws:s3:::bucket/definition.env")}}}}, Data: api.Task{Overrides: &api.TaskOverride{ContainerOverrides: api.ContainerOverrides{{Name: new(api.String("app")), EnvironmentFiles: api.EnvironmentFiles{file("arn:aws:s3:::bucket/override.env")}}}}}}
	got := effectiveTaskContainers(record)
	if len(got[0].EnvironmentFiles) != 1 || value(got[0].EnvironmentFiles[0].Value) != "arn:aws:s3:::bucket/override.env" || value(record.Definition.ContainerDefinitions[0].EnvironmentFiles[0].Value) != "arn:aws:s3:::bucket/definition.env" {
		t.Fatal("override did not replace files without mutating definition")
	}
	for _, files := range []api.EnvironmentFiles{
		{file("arn:aws:s3:::bucket/not-env.txt")},
		{file("arn:aws:s3:us-east-1::bucket/file.env")},
		{file("arn:aws:s3:::file.env")},
		slices.Repeat(api.EnvironmentFiles{file("arn:aws:s3:::bucket/file.env")}, 11),
	} {
		if validateTaskEnvironmentFiles(files) == nil {
			t.Fatal("invalid environment files admitted")
		}
	}
}
