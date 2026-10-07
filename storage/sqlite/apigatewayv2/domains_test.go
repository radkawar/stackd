package apigatewayv2_test

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	domain "stackd/internal/services/apigatewayv2"
	backend "stackd/storage/sqlite/apigatewayv2"
	"testing"
)

func TestDomainsMappingsPersistAndCascade(t *testing.T) {
	schema, err := os.ReadFile("../schema/318_apigateway_domains.sql")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "domains.sqlite")
	open := func() *sql.DB {
		db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		return db
	}
	db := open()
	if _, err = db.ExecContext(t.Context(), string(schema)); err != nil {
		t.Fatal(err)
	}
	sc := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	key := domain.DomainKey{Scope: sc, Name: "api.example.test"}
	owner := domain.ResourceOwner{StackID: "stack", LogicalID: "domain", Token: "generation"}
	record := domain.DomainRecord{Key: key, Owner: owner, CertificateARN: "certificate", CertificateID: "identity", CertificateName: "label", OwnershipCertificateARN: "proof", OwnershipCertificateID: "proof-id", SecurityPolicy: "TLS_1_2", IPAddressType: "ipv4", TruststoreURI: "s3://trust/pem", TruststoreVersion: "version", TruststorePEM: []byte("retained PEM"), Tags: map[string]string{"purpose": "test"}}
	mapping := domain.MappingRecord{Key: domain.MappingKey{DomainKey: key, ID: "mapping"}, Owner: owner, APIID: "api", Stage: "live", Path: "orders/v1"}
	if err = backend.New(db).Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutDomain(record); err != nil {
			return err
		}
		return tx.PutMapping(mapping)
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = open()
	defer db.Close()
	repo := backend.New(db)
	if err = repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.DomainByHost(key.Name)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, record) {
			t.Fatalf("domain after reopen: %#v", got)
		}
		rows, err := r.Mappings(key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(rows, []domain.MappingRecord{mapping}) {
			t.Fatalf("mappings after reopen: %#v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteDomain(key) }); err != nil {
		t.Fatal(err)
	}
	if err = repo.View(t.Context(), func(r domain.Reader) error {
		_, err := r.Mapping(mapping.Key)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("mapping survived domain deletion: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
