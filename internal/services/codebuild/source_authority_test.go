package codebuild

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awswire"
)

func TestNativeSourceAuthorityAdmission(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/codebuild/stackd-source-authority-4cc3e6fa3b3d.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case       string `json:"case"`
			Operation  string `json:"operation"`
			Parameters struct {
				Source *api.ProjectSource `json:"source"`
			} `json:"parameters"`
			Code string `json:"code"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	for _, observation := range capture.Observations {
		if observation.Operation != "UpdateProject" || observation.Parameters.Source == nil || value(observation.Parameters.Source.Type) == "NO_SOURCE" {
			continue
		}
		t.Run(observation.Case, func(t *testing.T) {
			err := validateGitSource(observation.Parameters.Source)
			if observation.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var rejected *awswire.Error
			if !errors.As(err, &rejected) || rejected.Code != observation.Code {
				t.Fatalf("admission = %v; native = %s", err, observation.Code)
			}
		})
	}
}

func TestRetainedForeignSourceRejectedBeforeCredentials(t *testing.T) {
	for _, auth := range []*api.SourceAuth{nil, {Type: new(api.SourceAuthType("SECRETS_MANAGER")), Resource: new(api.String("owned-secret"))}} {
		s := New(Config{})
		t.Cleanup(func() { s.Close() })
		r := BuildRecord{Data: api.Build{Source: &api.ProjectSource{Type: new(api.SourceType("GITHUB")), Location: new(api.String("https://foreign.example.invalid/repository.git")), Auth: auth}}}
		_, _, err := s.gitCredentials(context.Background(), r, r.Data.Source)
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.Code != "InvalidInputException" {
			t.Fatalf("retained source reached credential resolution: %v", err)
		}
	}
}

func TestNativeGitSecondaryAdmission(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/codebuild/stackd-cb-git-secondary-4c4fb322e510.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Operation string                 `json:"operation"`
			Input     json.RawMessage        `json:"input"`
			Error     *struct{ Code string } `json:"error"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	for _, row := range capture.Observations {
		if row.Operation != "update_project" {
			continue
		}
		var input api.UpdateProjectInput
		if err := json.Unmarshal(row.Input, &input); err != nil {
			t.Fatal(err)
		}
		project := api.Project{Source: &api.ProjectSource{}, Artifacts: &api.ProjectArtifacts{}, SecondarySources: input.SecondarySources, SecondarySourceVersions: input.SecondarySourceVersions}
		err := validateSecondaries(&project)
		if row.Error == nil {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.Code != row.Error.Code {
			t.Fatalf("secondary admission = %v; native = %s", err, row.Error.Code)
		}
	}
}
