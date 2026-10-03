package mq_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	service "stackd/internal/services/mq"
	"stackd/storage/memory"
	domain "stackd/storage/mq"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/mq"
)

func controlRecords() (domain.BrokerRecord, domain.ConfigurationRecord) {
	scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	now := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	current := domain.ConfigurationReference{ID: "c-settings", Revision: 2, Data: "<broker persistent=\"true\"/>"}
	pending := domain.ConfigurationReference{ID: "c-settings", Revision: 3, Data: "<broker persistent=\"false\"/>"}
	broker := domain.BrokerRecord{
		Scope: scope, ID: "b-source", ARN: "arn:aws:mq:us-east-1:111111111111:broker:source:b-source", Name: "source",
		Engine: "ACTIVEMQ", EngineVersion: "5.18", InstanceType: "mq.m5.large", State: "RUNNING",
		CreatorRequestID: "request", Username: "legacy", Password: "", Operation: "reboot", Failure: "retained failure",
		Version: 9, Created: now, Due: time.Unix(0, 0).UTC(),
		Endpoint: domain.Endpoint{Address: "ssl://localhost:61617", ConsoleURL: "https://localhost:8162", NativeID: "owned-container", CAPEM: []byte("ca")},
		Tags:     map[string]string{"owner": "first"},
		Users: []domain.UserRecord{
			{Username: "z-new", PendingChange: "CREATE", PendingPassword: "new-secret", PendingGroups: []string{"writers", "readers"}, PendingConsoleAccess: true},
			{Username: "a-owner", Password: "effective-secret", Groups: []string{"writers", "admins"}, ConsoleAccess: true, PendingChange: "UPDATE", PendingPassword: "pending-secret", PendingGroups: []string{"readers"}},
		},
		Configuration: current, PendingConfiguration: pending,
		ConfigurationHistory: []domain.ConfigurationReference{{ID: "c-prior", Revision: 7, Data: "prior"}, {ID: "c-settings", Revision: 1, Data: "initial"}, {ID: "c-prior", Revision: 7, Data: "prior"}},
		MaintenanceDay:       "MONDAY", MaintenanceTime: "23:15", MaintenanceZone: "America/New_York", MaintenanceDue: now.Add(24 * time.Hour),
		MaintenanceAdjustments: 4,
		Logs:                   domain.LogSettings{General: true},
		PendingLogs:            &domain.LogSettings{Audit: true},
		GeneralLogCursor:       domain.LogCursor{FileID: "native-general", Offset: 1024},
		AuditLogCursor:         domain.LogCursor{FileID: "native-audit", Offset: 512},
		LogDeliveryError:       "resource policy denied delivery", LogDue: now.Add(time.Second),
	}
	configuration := domain.ConfigurationRecord{
		Scope: scope, ID: "c-settings", ARN: "arn:aws:mq:us-east-1:111111111111:configuration:settings:c-settings", Name: "settings",
		Description: "retained configuration", Engine: "ACTIVEMQ", EngineVersion: "5.18", AuthenticationStrategy: "simple",
		Created: now, Tags: map[string]string{"owner": "config"},
		Revisions: []domain.ConfigurationRevisionRecord{
			{Revision: 3, Description: "pending", Data: pending.Data, Created: now.Add(time.Hour)},
			{Revision: 2, Description: "current", Data: current.Data, Created: now},
		},
	}
	return broker, configuration
}

func TestControlIntentAtomicityIsolationAndReplacement(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var repo domain.Repository
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "mq.sqlite")
			if kind == "memory" {
				repo = domain.NewMemory(memory.NewDomain())
			} else {
				var err error
				db, err = sqlite.Open(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = backend.New(db)
			}
			broker, configuration := controlRecords()
			otherBroker, otherConfiguration := controlRecords()
			otherBroker.AccountID = "999999999999"
			otherBroker.ARN = "arn:aws:mq:us-east-1:999999999999:broker:source:b-source"
			otherConfiguration.AccountID = otherBroker.AccountID
			otherConfiguration.ARN = "arn:aws:mq:us-east-1:999999999999:configuration:settings:c-settings"
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutConfiguration(otherConfiguration); err != nil {
					return err
				}
				if err := tx.PutBroker(otherBroker); err != nil {
					return err
				}
				if err := tx.PutConfiguration(configuration); err != nil {
					return err
				}
				return tx.PutBroker(broker)
			}); err != nil {
				t.Fatal(err)
			}
			// Query order is independent of admission order, but history is ordered
			// by application and must retain repeated references.
			slices.Reverse(broker.Users)
			broker.Users[0].Groups = []string{"admins", "writers"}
			broker.Users[1].PendingGroups = []string{"readers", "writers"}
			slices.Reverse(configuration.Revisions)
			failure := errors.New("audit rejected transition")
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				v, err := tx.Broker(broker.Scope, broker.ID)
				if err != nil {
					return err
				}
				v.Users[0].Password = v.Users[0].PendingPassword
				v.Users[0].PendingPassword = ""
				v.Users[0].Groups[0] = "unauthorized"
				v.Configuration = v.PendingConfiguration
				v.PendingConfiguration = domain.ConfigurationReference{}
				v.ConfigurationHistory[0].Data = "changed"
				v.MaintenanceDue = v.MaintenanceDue.Add(7 * 24 * time.Hour)
				v.MaintenanceAdjustments = 0
				v.Logs = *v.PendingLogs
				v.PendingLogs.General = true
				v.GeneralLogCursor.Offset += 100
				v.AuditLogCursor.FileID = "replaced"
				v.LogDeliveryError = ""
				v.LogDue = v.LogDue.Add(time.Second)
				v.Endpoint.CAPEM[0] = 'X'
				v.Tags["owner"] = "changed"
				if err := tx.PutBroker(v); err != nil {
					return err
				}
				c, err := tx.Configuration(configuration.Scope, configuration.ID)
				if err != nil {
					return err
				}
				c.Revisions[0].Data = "changed"
				c.Tags["owner"] = "changed"
				if err := tx.PutConfiguration(c); err != nil {
					return err
				}
				return failure
			}); !errors.Is(err, failure) {
				t.Fatalf("transition failure: %v", err)
			}
			if kind == "sqlite" {
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				var err error
				db, err = sqlite.Open(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				repo = backend.New(db)
			}
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				got, err := r.Broker(broker.Scope, broker.ID)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got, broker) {
					t.Fatalf("broker intent escaped rollback or restart: got %#v, want %#v", got, broker)
				}
				config, err := r.Configuration(configuration.Scope, configuration.ID)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(config, configuration) {
					t.Fatalf("configuration escaped rollback or restart: got %#v, want %#v", config, configuration)
				}
				for _, scope := range []domain.Scope{
					{Partition: "aws-cn", AccountID: broker.AccountID, Region: broker.Region},
					{Partition: broker.Partition, AccountID: "222222222222", Region: broker.Region},
					{Partition: broker.Partition, AccountID: broker.AccountID, Region: "us-west-2"},
				} {
					if _, err := r.Broker(scope, broker.ID); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("broker crossed scope %#v: %v", scope, err)
					}
					if _, err := r.Configuration(scope, configuration.ID); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("configuration crossed scope %#v: %v", scope, err)
					}
				}
				brokers, err := r.AllBrokers()
				if err != nil {
					return err
				}
				if len(brokers) != 2 || brokers[0].ARN != broker.ARN || brokers[1].ARN != otherBroker.ARN {
					t.Fatalf("broker list lost scope or stable order: %#v", brokers)
				}
				configurations, err := r.AllConfigurations()
				if err != nil {
					return err
				}
				if len(configurations) != 2 || configurations[0].ARN != configuration.ARN || configurations[1].ARN != otherConfiguration.ARN {
					t.Fatalf("configuration list lost scope or stable order: %#v", configurations)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.DeleteBroker(broker.Scope, broker.ID); err != nil {
					return err
				}
				if err := tx.DeleteConfiguration(configuration.Scope, configuration.ID); err != nil {
					return err
				}
				// An explicitly empty user set must not resurrect the legacy user.
				if err := tx.PutBroker(domain.BrokerRecord{Scope: broker.Scope, ID: broker.ID, ARN: broker.ARN, Name: broker.Name, Username: "legacy", Users: []domain.UserRecord{}}); err != nil {
					return err
				}
				return tx.PutConfiguration(domain.ConfigurationRecord{Scope: configuration.Scope, ID: configuration.ID, ARN: configuration.ARN, Name: configuration.Name})
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				got, err := r.Broker(broker.Scope, broker.ID)
				if err != nil {
					return err
				}
				if got.Users == nil || len(got.Users) != 0 || len(got.Tags) != 0 || len(got.ConfigurationHistory) != 0 || got.Configuration.ID != "" || got.PendingConfiguration.ID != "" {
					t.Fatalf("broker replacement inherited retired authority: %#v", got)
				}
				config, err := r.Configuration(configuration.Scope, configuration.ID)
				if err != nil {
					return err
				}
				if len(config.Revisions) != 0 || len(config.Tags) != 0 {
					t.Fatalf("configuration replacement inherited retired revisions: %#v", config)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMemoryControlAttemptKeepsOuterIntent(t *testing.T) {
	repo := domain.NewMemory(memory.NewDomain())
	broker, configuration := controlRecords()
	rejected := errors.New("rejected native change")
	if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutBroker(broker); err != nil {
			return err
		}
		if err := tx.PutConfiguration(configuration); err != nil {
			return err
		}
		err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
			v, err := child.Broker(broker.Scope, broker.ID)
			if err != nil {
				return err
			}
			v.Users[0].PendingGroups[0] = "forbidden"
			v.ConfigurationHistory[0].Data = "forbidden"
			if err := child.PutBroker(v); err != nil {
				return err
			}
			return rejected
		})
		if !errors.Is(err, rejected) {
			t.Fatalf("attempt rejection: %v", err)
		}
		v, err := tx.Broker(broker.Scope, broker.ID)
		if err != nil {
			return err
		}
		if !slices.Equal(v.Users[0].PendingGroups, []string{"readers"}) || v.ConfigurationHistory[0].Data != "prior" {
			t.Fatalf("rejected attempt changed enclosing intent: %#v", v)
		}
		if err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
			c, err := child.Configuration(configuration.Scope, configuration.ID)
			if err != nil {
				return err
			}
			c.Description = "accepted"
			return child.PutConfiguration(c)
		}); err != nil {
			return err
		}
		c, err := tx.Configuration(configuration.Scope, configuration.ID)
		if err != nil {
			return err
		}
		if c.Description != "accepted" {
			t.Fatalf("enclosing transaction missed accepted child: %#v", c)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyBrokerUserMigrationRetainsNativeIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), "PRAGMA foreign_keys=ON"); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.ReadFile("../schema/266_mq.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), string(legacy)); err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"", "not-yet-applied"} {
		id := "broker-" + password
		if _, err := db.ExecContext(t.Context(), `INSERT INTO mq_brokers
			(partition,account_id,region,id,arn,name,engine,engine_version,instance_type,state,creator_request_id,username,password,operation,failure,version,created,due,endpoint_address,endpoint_console_url,endpoint_native_id,endpoint_ca_pem)
			VALUES('aws','111111111111','us-east-1',?,?,?,'RABBITMQ','3.13','mq.m5.large','RUNNING','','initial',?,'','',7,'2031-01-01T00:00:00Z','0001-01-01T00:00:00Z','amqps://localhost:5671','','retained-container',X'010203')`, id, "arn:"+id, id, password); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"../schema/283_mq_control.sql", "../schema/284_mq_maintenance.sql", "../schema/285_mq_logs.sql"} {
		migration, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(t.Context(), string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	repo := backend.New(db)
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		for _, password := range []string{"", "not-yet-applied"} {
			v, err := r.Broker(domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, "broker-"+password)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(v.Users, []domain.UserRecord{{Username: "initial", Password: password}}) {
				t.Fatalf("migration lost initial user or fabricated a password: %#v", v.Users)
			}
			if v.MaintenanceAdjustments != 0 {
				t.Fatal("legacy migration invented a consumed maintenance budget")
			}
			if v.Logs.General || v.Logs.Audit || v.PendingLogs != nil || !v.LogDue.IsZero() {
				t.Fatal("legacy migration enabled logging or invented pending delivery")
			}
			if v.Endpoint.NativeID != "retained-container" || v.Endpoint.Address != "amqps://localhost:5671" || !slices.Equal(v.Endpoint.CAPEM, []byte{1, 2, 3}) || v.Version != 7 || !v.MaintenanceDue.IsZero() {
				t.Fatalf("migration replaced native identity or maintenance intent: %#v", v)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRoleUsageDecisionSharesWritableTransaction(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var repo domain.Repository
			if kind == "memory" {
				repo = domain.NewMemory(memory.NewDomain())
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "roles.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = backend.New(db)
			}
			broker, _ := controlRecords()
			broker.Engine = "RABBITMQ"
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutBroker(broker) }); err != nil {
				t.Fatal(err)
			}
			owner := service.New(service.Config{Repository: repo})
			t.Cleanup(func() { _ = owner.Close() })
			aborted := errors.New("reject usage decision")
			decide := func(reject bool) error {
				return owner.WithMQRoleUsage(t.Context(), broker.Partition, broker.AccountID, func(ctx context.Context, resources []string) error {
					if !slices.Equal(resources, []string{broker.ARN}) {
						t.Fatalf("missing role dependency: %v", resources)
					}
					if err := repo.Update(ctx, func(tx domain.Transaction) error { return tx.DeleteBroker(broker.Scope, broker.ID) }); err != nil {
						return err
					}
					if reject {
						return aborted
					}
					return nil
				})
			}
			if err := decide(true); !errors.Is(err, aborted) {
				t.Fatalf("decision rollback: %v", err)
			}
			if err := decide(false); err != nil {
				t.Fatal(err)
			}
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				_, err := r.Broker(broker.Scope, broker.ID)
				if !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("decision did not commit: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
