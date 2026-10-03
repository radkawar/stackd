package glue_test

import (
	"encoding/json"
	"strings"
	"testing"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
	"stackd/journal"
	"stackd/storage/memory"
)

func TestConnectionJournalOmitsCredentialEndpoints(t *testing.T) {
	cases := []struct {
		name, kind, endpoint, secret string
		property                     api.ConnectionPropertyKey
		retained                     bool
	}{
		{name: "mongodb-userinfo", kind: "MONGODB", property: "CONNECTION_URL", endpoint: "mongodb://reader:uri-secret-mongodb@db.internal/analytics", secret: "uri-secret-mongodb"},
		{name: "jdbc-userinfo", kind: "JDBC", property: "JDBC_CONNECTION_URL", endpoint: "jdbc:postgresql://reader:uri-secret-jdbc@db.internal:5432/analytics", secret: "uri-secret-jdbc"},
		{name: "query-credential", kind: "JDBC", property: "JDBC_CONNECTION_URL", endpoint: "jdbc:postgresql://db.internal/analytics?password=uri-secret-query", secret: "uri-secret-query"},
		{name: "opaque-vendor-dsn", kind: "JDBC", property: "JDBC_CONNECTION_URL", endpoint: "jdbc:oracle:thin:reader/uri-secret-opaque@db.internal:1521:analytics", secret: "uri-secret-opaque"},
		{name: "vendor-path-parameters", kind: "JDBC", property: "JDBC_CONNECTION_URL", endpoint: "jdbc:postgresql://db.internal/analytics;password=uri-secret-path", secret: "uri-secret-path"},
		{name: "nested-escaped-parameters", kind: "JDBC", property: "JDBC_CONNECTION_URL", endpoint: "jdbc:postgresql://db.internal/analytics%253bpassword%253duri-secret-escape", secret: "uri-secret-escape"},
		{name: "plain-endpoint", kind: "JDBC", property: "JDBC_CONNECTION_URL", endpoint: "jdbc:postgresql://db.internal:5432/analytics", retained: true},
		{name: "plain-driver-uri", kind: "JDBC", property: "JDBC_DRIVER_JAR_URI", endpoint: "s3://public-drivers/postgres.jar", retained: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := catalogTestContext("123456789012", "us-east-1")
			domain := memory.NewDomain()
			history := journal.NewMemory(domain)
			s := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), Recorder: apievents.New(history)})
			defer s.Close()
			name := api.NameString("audit-" + test.name)
			properties := api.ConnectionProperties{"JDBC_CONNECTION_URL": "jdbc:postgresql://public-endpoint/analytics", "USERNAME": "public-reader", "PASSWORD": "property-secret-sentinel"}
			properties[test.property] = api.ValueString(test.endpoint)
			input := &api.ConnectionInput{Name: &name, ConnectionType: new(api.ConnectionType(test.kind)), Description: new(api.DescriptionString("public-description")), ConnectionProperties: properties}
			catalogTestCall[api.CreateConnectionOutput](t, s, ctx, "CreateConnection", &api.CreateConnectionInput{ConnectionInput: input})
			updated := *input
			updated.Description = new(api.DescriptionString("public-updated-description"))
			catalogTestCall[api.UpdateConnectionOutput](t, s, ctx, "UpdateConnection", &api.UpdateConnectionInput{Name: &name, ConnectionInput: &updated})
			got := catalogTestCall[api.GetConnectionOutput](t, s, ctx, "GetConnection", &api.GetConnectionInput{Name: &name})
			if got.Connection == nil || string(got.Connection.ConnectionProperties[test.property]) != test.endpoint {
				t.Fatal("audit projection changed the retained connection endpoint")
			}
			events, err := history.Read(ctx, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 3 {
				t.Fatalf("journal outcomes=%d, want create, update and read", len(events))
			}
			for i, action := range []string{"CreateConnection", "UpdateConnection"} {
				call := events[i].APICallCompleted
				if call == nil || call.EventName != action || call.ErrorCode != "" {
					t.Fatalf("unexpected %s journal outcome", action)
				}
				encoded, err := json.Marshal(events[i])
				if err != nil {
					t.Fatal(err)
				}
				text := string(encoded)
				if strings.Contains(text, "property-secret-sentinel") || test.secret != "" && strings.Contains(text, test.secret) {
					t.Fatalf("%s retained connection credentials in the shared journal", action)
				}
				description := "public-description"
				if action == "UpdateConnection" {
					description = "public-updated-description"
				}
				if !strings.Contains(text, string(name)) || !strings.Contains(text, test.kind) || !strings.Contains(text, description) || !strings.Contains(text, "public-reader") {
					t.Fatalf("%s lost nonsecret connection audit fields", action)
				}
				if test.retained && !strings.Contains(text, test.endpoint) {
					t.Fatalf("%s lost a plain endpoint URL", action)
				}
			}
		})
	}
}

func TestRejectedConnectionJournalOmitsMalformedEndpoints(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	domain := memory.NewDomain()
	history := journal.NewMemory(domain)
	s := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), Recorder: apievents.New(history)})
	defer s.Close()
	name := api.NameString("rejected-audit")
	// Missing type rejects creation; the missing resource rejects update before
	// either command interprets the malformed URI.
	input := &api.ConnectionInput{Name: &name, Description: new(api.DescriptionString("public-rejection-description")), ConnectionProperties: api.ConnectionProperties{"JDBC_CONNECTION_URL": "jdbc:postgresql://reader:rejected-uri-secret%ZZ@db.internal/analytics", "PASSWORD": "rejected-property-secret", "USERNAME": "public-rejected-reader"}}
	catalogTestError(t, s, ctx, "CreateConnection", &api.CreateConnectionInput{ConnectionInput: input}, "InvalidInputException")
	catalogTestError(t, s, ctx, "UpdateConnection", &api.UpdateConnectionInput{Name: &name, ConnectionInput: input}, "EntityNotFoundException")
	events, err := history.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("rejected journal outcomes=%d, want create and update", len(events))
	}
	for i, action := range []string{"CreateConnection", "UpdateConnection"} {
		call := events[i].APICallCompleted
		code := "InvalidInputException"
		if action == "UpdateConnection" {
			code = "EntityNotFoundException"
		}
		if call == nil || call.EventName != action || call.ErrorCode != code {
			t.Fatalf("unexpected rejected %s journal outcome", action)
		}
		encoded, err := json.Marshal(events[i])
		if err != nil {
			t.Fatal(err)
		}
		text := string(encoded)
		if strings.Contains(text, "rejected-uri-secret") || strings.Contains(text, "rejected-property-secret") {
			t.Fatalf("rejected %s retained credentials in the shared journal", action)
		}
		if !strings.Contains(text, string(name)) || !strings.Contains(text, "public-rejection-description") || !strings.Contains(text, "public-rejected-reader") {
			t.Fatalf("rejected %s lost nonsecret audit fields", action)
		}
	}
}

func TestRejectedConnectionJournalOmitsComputeCredentials(t *testing.T) {
	for _, environment := range []string{"Athena", "Spark", "Python"} {
		t.Run(environment, func(t *testing.T) {
			ctx := catalogTestContext("123456789012", "us-east-1")
			domain := memory.NewDomain()
			history := journal.NewMemory(domain)
			s := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), Recorder: apievents.New(history)})
			defer s.Close()
			name := new(api.NameString("rejected-overrides"))
			input := &api.ConnectionInput{Name: name, ConnectionType: new(api.ConnectionTypeJDBC), Description: new(api.DescriptionString("public-rejection-description")), ConnectionProperties: api.ConnectionProperties{"JDBC_CONNECTION_URL": "jdbc:postgresql://db.internal/catalog", "USERNAME": "public-reader", "PASSWORD": "synthetic-password"}}
			catalogTestCall[api.CreateConnectionOutput](t, s, ctx, "CreateConnection", &api.CreateConnectionInput{ConnectionInput: input})
			properties := api.PropertyMap{"apiToken": "synthetic-token", "DbPassword": "synthetic-override-password", "TOKEN_URL": "https://public.example/synthetic-token-url", "queryTimeout": "public-timeout"}
			switch environment {
			case "Athena":
				input.AthenaProperties = properties
			case "Spark":
				input.SparkProperties = properties
			case "Python":
				input.PythonProperties = properties
			}
			catalogTestError(t, s, ctx, "CreateConnection", &api.CreateConnectionInput{ConnectionInput: input}, "InvalidInputException")
			catalogTestError(t, s, ctx, "UpdateConnection", &api.UpdateConnectionInput{Name: name, ConnectionInput: input}, "InvalidInputException")
			events, err := history.Read(ctx, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 3 {
				t.Fatalf("journal outcomes=%d, want setup and two rejections", len(events))
			}
			for i, action := range []string{"CreateConnection", "UpdateConnection"} {
				event := events[i+1]
				call := event.APICallCompleted
				if call == nil || call.EventName != action || call.ErrorCode != "InvalidInputException" {
					t.Fatalf("unexpected rejected %s journal outcome", action)
				}
				encoded, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				text := string(encoded)
				for _, sentinel := range []string{"synthetic-password", "synthetic-token", "synthetic-override-password"} {
					if strings.Contains(text, sentinel) {
						t.Fatalf("%s retained synthetic credential in shared journal", action)
					}
				}
				for _, diagnostic := range []string{"public-timeout", "public-rejection-description", "public-reader"} {
					if !strings.Contains(text, diagnostic) {
						t.Fatalf("%s lost nonsecret diagnostic %q", action, diagnostic)
					}
				}
			}
			got := catalogTestCall[api.GetConnectionOutput](t, s, ctx, "GetConnection", &api.GetConnectionInput{Name: name})
			if got.Connection.ConnectionProperties["PASSWORD"] != "synthetic-password" || len(got.Connection.AthenaProperties)+len(got.Connection.SparkProperties)+len(got.Connection.PythonProperties) != 0 {
				t.Fatal("rejected update changed retained connection")
			}
		})
	}
}
