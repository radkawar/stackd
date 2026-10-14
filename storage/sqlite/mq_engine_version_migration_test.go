package sqlite_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"stackd/internal/awstest"
	domain "stackd/storage/mq"
	"stackd/storage/sqlite"
	sqlmq "stackd/storage/sqlite/mq"
)

func TestMQActiveMQAPIVersionUpgradeRetainsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mq.sqlite")
	files, err := filepath.Glob("schema/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	// schema.Apply counts ordered files, not their numeric filename prefixes.
	version := slices.Index(files, filepath.Join("schema", "295_mq_activemq_api_version.sql"))
	if version < 0 {
		t.Fatal("MQ API version migration not found")
	}
	db := awstest.HistoricalSQLite(t, path, "schema", version, "", nil)
	t.Cleanup(func() { _ = db.Close() })
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	var brokers []domain.BrokerRecord
	var configurations []domain.ConfigurationRecord
	created := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, fixture := range []struct {
		partition, account, region, engine, version string
	}{
		{"aws", "111111111111", "us-east-1", "ACTIVEMQ", "5.18.7"},
		{"aws-cn", "222222222222", "cn-north-1", "ACTIVEMQ", "5.18.7"},
		{"aws", "111111111111", "us-east-1", "ACTIVEMQ", "5.18"},
		{"aws", "111111111111", "us-east-1", "ACTIVEMQ", "5.18.99"},
		{"aws", "111111111111", "us-east-1", "ACTIVEMQ", "5.17.6"},
		{"aws", "111111111111", "us-east-1", "RABBITMQ", "5.18.7"},
		{"aws", "111111111111", "us-east-1", "RABBITMQ", "3.13"},
	} {
		id := fmt.Sprintf("retained-%d", i)
		brokerARN := fmt.Sprintf("arn:%s:mq:%s:%s:broker:%s:%s", fixture.partition, fixture.region, fixture.account, id, id)
		configARN := fmt.Sprintf("arn:%s:mq:%s:%s:configuration:%s:%s", fixture.partition, fixture.region, fixture.account, id, id)
		exec(`INSERT INTO mq_brokers
			(partition,account_id,region,id,arn,name,engine,engine_version,instance_type,state,creator_request_id,username,password,operation,failure,version,created,due,endpoint_address,endpoint_console_url,endpoint_native_id,endpoint_ca_pem,
			maintenance_day,maintenance_time,maintenance_zone,maintenance_due,maintenance_adjustments,
			log_general,log_audit,log_pending_general,log_pending_audit,log_general_file_id,log_general_offset,log_audit_file_id,log_audit_offset,log_delivery_error,log_due)
			VALUES(?,?,?,?,?,?,?,?,'mq.m5.large','REBOOT_IN_PROGRESS','request','initial','initial-password','reboot','retained failure',19,'2031-01-01T00:00:00Z','2031-01-02T00:00:00Z','ssl://localhost:61617','https://localhost:8162','native-container',X'010203',
			'MONDAY','03:00','UTC','2031-01-03T00:00:00Z',2,
			1,0,0,1,'general-file',123,'audit-file',456,'delivery failure','2031-01-04T00:00:00Z')`,
			fixture.partition, fixture.account, fixture.region, id, brokerARN, id, fixture.engine, fixture.version)
		exec(`INSERT INTO mq_broker_tags VALUES(?,'owner','retained')`, brokerARN)
		exec(`INSERT INTO mq_broker_users VALUES(?,'initial','native-password',1,'UPDATE','pending-password',0)`, brokerARN)
		exec(`INSERT INTO mq_broker_user_groups VALUES(?,'initial',0,'effective-group'),(?,'initial',1,'pending-group')`, brokerARN, brokerARN)
		exec(`INSERT INTO mq_configurations VALUES(?,?,?,?,?,?,'retained description',?,?,'simple','2031-01-01T00:00:00Z')`,
			fixture.partition, fixture.account, fixture.region, id, configARN, id, fixture.engine, fixture.version)
		exec(`INSERT INTO mq_configuration_tags VALUES(?,'owner','configuration')`, configARN)
		exec(`INSERT INTO mq_configuration_revisions VALUES(?,1,'effective','<broker name="effective"/>','2031-01-01T00:00:00Z'),(?,2,'pending','<broker name="pending"/>','2031-01-02T00:00:00Z')`, configARN, configARN)
		exec(`INSERT INTO mq_broker_configurations VALUES(?,'current',0,?,1,'<broker name="effective"/>'),(?,'pending',0,?,2,'<broker name="pending"/>'),(?,'history',0,?,1,'<broker name="historical"/>'),(?,'history',1,?,1,'<broker name="historical"/>')`, brokerARN, id, brokerARN, id, brokerARN, id, brokerARN, id)
		engineVersion := fixture.version
		if fixture.engine == "ACTIVEMQ" && engineVersion == "5.18.7" {
			engineVersion = "5.18"
		}
		scope := domain.Scope{Partition: fixture.partition, AccountID: fixture.account, Region: fixture.region}
		brokers = append(brokers, domain.BrokerRecord{
			Scope: scope, ID: id, ARN: brokerARN, Name: id,
			Engine: fixture.engine, EngineVersion: engineVersion, InstanceType: "mq.m5.large",
			State: "REBOOT_IN_PROGRESS", CreatorRequestID: "request", Operation: "reboot",
			Failure: "retained failure", Version: 19, Created: created, Due: created.Add(24 * time.Hour),
			Username: "initial", Password: "initial-password",
			Endpoint: domain.Endpoint{
				Address: "ssl://localhost:61617", ConsoleURL: "https://localhost:8162",
				NativeID: "native-container", CAPEM: []byte{1, 2, 3},
			},
			Tags: map[string]string{"owner": "retained"},
			Users: []domain.UserRecord{{
				Username: "initial", Password: "native-password", ConsoleAccess: true,
				Groups: []string{"effective-group"}, PendingChange: "UPDATE",
				PendingPassword: "pending-password", PendingGroups: []string{"pending-group"},
			}},
			Configuration:        domain.ConfigurationReference{ID: id, Revision: 1, Data: `<broker name="effective"/>`},
			PendingConfiguration: domain.ConfigurationReference{ID: id, Revision: 2, Data: `<broker name="pending"/>`},
			ConfigurationHistory: []domain.ConfigurationReference{
				{ID: id, Revision: 1, Data: `<broker name="historical"/>`},
				{ID: id, Revision: 1, Data: `<broker name="historical"/>`},
			},
			MaintenanceDay: "MONDAY", MaintenanceTime: "03:00", MaintenanceZone: "UTC",
			MaintenanceDue: created.Add(48 * time.Hour), MaintenanceAdjustments: 2,
			Logs: domain.LogSettings{General: true}, PendingLogs: &domain.LogSettings{Audit: true},
			GeneralLogCursor: domain.LogCursor{FileID: "general-file", Offset: 123},
			AuditLogCursor:   domain.LogCursor{FileID: "audit-file", Offset: 456},
			LogDeliveryError: "delivery failure", LogDue: created.Add(72 * time.Hour),
		})
		configurations = append(configurations, domain.ConfigurationRecord{
			Scope: scope, ID: id, ARN: configARN, Name: id,
			Description: "retained description", Engine: fixture.engine, EngineVersion: engineVersion,
			AuthenticationStrategy: "simple", Created: created,
			Tags: map[string]string{"owner": "configuration"},
			Revisions: []domain.ConfigurationRevisionRecord{
				{Revision: 1, Description: "effective", Data: `<broker name="effective"/>`, Created: created},
				{Revision: 2, Description: "pending", Data: `<broker name="pending"/>`, Created: created.Add(24 * time.Hour)},
			},
		})
	}
	for reopen := range 2 {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlmq.New(db).View(t.Context(), func(r domain.Reader) error {
			for i, want := range brokers {
				got, err := r.Broker(want.Scope, want.ID)
				if err != nil {
					return err
				}
				if got.Scope != want.Scope || got.ID != want.ID || got.ARN != want.ARN || got.Name != want.Name ||
					got.Engine != want.Engine || got.EngineVersion != want.EngineVersion || got.InstanceType != want.InstanceType ||
					got.CreatorRequestID != want.CreatorRequestID || !reflect.DeepEqual(got.Tags, want.Tags) {
					t.Fatalf("reopen %d changed broker identity or engine: got %#v, want %#v", reopen, got, want)
				}
				if !reflect.DeepEqual(got.Endpoint, want.Endpoint) {
					t.Fatalf("reopen %d changed native endpoint: got %#v, want %#v", reopen, got.Endpoint, want.Endpoint)
				}
				if got.Username != want.Username || got.Password != want.Password || !reflect.DeepEqual(got.Users, want.Users) {
					t.Fatalf("reopen %d changed effective or pending credentials: got %#v, want %#v", reopen, got, want)
				}
				if got.State != want.State || got.Operation != want.Operation || got.Failure != want.Failure ||
					got.Version != want.Version || !got.Created.Equal(want.Created) || !got.Due.Equal(want.Due) {
					t.Fatalf("reopen %d changed retained lifecycle work: got %#v, want %#v", reopen, got, want)
				}
				if got.Configuration != want.Configuration || got.PendingConfiguration != want.PendingConfiguration ||
					!reflect.DeepEqual(got.ConfigurationHistory, want.ConfigurationHistory) {
					t.Fatalf("reopen %d changed admitted configuration or history: got %#v, want %#v", reopen, got, want)
				}
				if got.MaintenanceDay != want.MaintenanceDay || got.MaintenanceTime != want.MaintenanceTime ||
					got.MaintenanceZone != want.MaintenanceZone || !got.MaintenanceDue.Equal(want.MaintenanceDue) ||
					got.MaintenanceAdjustments != want.MaintenanceAdjustments {
					t.Fatalf("reopen %d changed retained maintenance work: got %#v, want %#v", reopen, got, want)
				}
				if got.Logs != want.Logs || !reflect.DeepEqual(got.PendingLogs, want.PendingLogs) ||
					got.GeneralLogCursor != want.GeneralLogCursor || got.AuditLogCursor != want.AuditLogCursor ||
					got.LogDeliveryError != want.LogDeliveryError || !got.LogDue.Equal(want.LogDue) {
					t.Fatalf("reopen %d changed pending logs or native log offsets: got %#v, want %#v", reopen, got, want)
				}
				wantConfiguration := configurations[i]
				configuration, err := r.Configuration(wantConfiguration.Scope, wantConfiguration.ID)
				if err != nil {
					return err
				}
				if configuration.Scope != wantConfiguration.Scope || configuration.ID != wantConfiguration.ID ||
					configuration.ARN != wantConfiguration.ARN || configuration.Name != wantConfiguration.Name ||
					configuration.Engine != wantConfiguration.Engine || configuration.EngineVersion != wantConfiguration.EngineVersion ||
					configuration.Description != wantConfiguration.Description ||
					configuration.AuthenticationStrategy != wantConfiguration.AuthenticationStrategy ||
					!configuration.Created.Equal(wantConfiguration.Created) {
					t.Fatalf("reopen %d changed configuration identity or engine: got %#v, want %#v", reopen, configuration, wantConfiguration)
				}
				if !reflect.DeepEqual(configuration.Tags, wantConfiguration.Tags) ||
					!reflect.DeepEqual(configuration.Revisions, wantConfiguration.Revisions) {
					t.Fatalf("reopen %d changed configuration tags or revision payloads: got %#v, want %#v", reopen, configuration, wantConfiguration)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		rows, err := db.QueryContext(t.Context(), "PRAGMA foreign_key_check")
		if err != nil {
			t.Fatal(err)
		}
		if rows.Next() {
			rows.Close()
			t.Fatal("upgraded MQ storage has broken foreign keys")
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
