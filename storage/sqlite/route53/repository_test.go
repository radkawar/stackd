package route53_test

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"path/filepath"
	"stackd/clock"
	"stackd/compute/dns"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/route53"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	service "stackd/internal/services/route53"
	domain "stackd/storage/route53"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/route53"
	"testing"
	"time"
)

func owner() context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", Region: "us-east-1", AccountID: "111111111111", PrincipalID: "111111111111", PrincipalARN: "arn:aws:iam::111111111111:root"})
}
func command[O any](t *testing.T, s *service.Service, ctx context.Context, name string, in any) *O {
	t.Helper()
	m, _ := awscatalog.LookupService("route53")
	op, _ := m.Operation(name)
	out, e := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: in})
	if e != nil {
		t.Fatalf("%s: %v", name, e)
	}
	return out.(*O)
}
func requestDNS(t *testing.T, address, network string, kind dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	name, _ := dnsmessage.NewName("app.restart.test.")
	packet, e := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}).Pack()
	if e != nil {
		t.Fatal(e)
	}
	c, e := net.DialTimeout(network, address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if network == "tcp" {
		packet = append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
	}
	if _, e = c.Write(packet); e != nil {
		t.Fatal(e)
	}
	buffer := make([]byte, 65535)
	var n int
	if network == "tcp" {
		var size [2]byte
		if _, e = io.ReadFull(c, size[:]); e != nil {
			t.Fatal(e)
		}
		n = int(binary.BigEndian.Uint16(size[:]))
		_, e = io.ReadFull(c, buffer[:n])
	} else {
		n, e = c.Read(buffer)
	}
	if e != nil {
		t.Fatal(e)
	}
	var result dnsmessage.Message
	if e = result.Unpack(buffer[:n]); e != nil {
		t.Fatal(e)
	}
	return result
}
func TestRetainedAuthorityAcrossSQLiteRestartAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route53.sqlite")
	var db *sql.DB
	var repo *backend.Repository
	var s *service.Service
	var server *dns.Server
	at := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
	open := func() {
		t.Helper()
		var e error
		db, e = sqlite.Open(t.Context(), path)
		if e != nil {
			t.Fatal(e)
		}
		repo = backend.New(db)
		server, e = dns.Listen(dns.Config{Address: "127.0.0.1:0"})
		if e != nil {
			t.Fatal(e)
		}
		s, e = service.New(service.Config{Repository: repo, Clock: at, DNSAuthority: server})
		if e != nil {
			t.Fatal(e)
		}
	}
	close := func() {
		t.Helper()
		if e := s.Close(); e != nil {
			t.Fatal(e)
		}
		if e := server.Close(); e != nil {
			t.Fatal(e)
		}
		if e := db.Close(); e != nil {
			t.Fatal(e)
		}
	}
	open()
	t.Cleanup(close)
	zone := command[api.CreateHostedZoneResponse](t, s, owner(), "CreateHostedZone", &api.CreateHostedZoneRequest{Name: new(api.DNSName("restart.test")), CallerReference: new(api.Nonce("retained"))})
	record := &api.ResourceRecordSet{Name: new(api.DNSName("app.restart.test")), Type: new(api.RRTypeA), TTL: new(api.TTL(60)), ResourceRecords: api.ResourceRecords{{Value: new(api.RData("192.0.2.42"))}}}
	add := command[api.ChangeResourceRecordSetsResponse](t, s, owner(), "ChangeResourceRecordSets", &api.ChangeResourceRecordSetsRequest{HostedZoneId: zone.HostedZone.Id, ChangeBatch: &api.ChangeBatch{Changes: api.Changes{{Action: new(api.ChangeActionCREATE), ResourceRecordSet: record}}}})
	rollback := errors.New("abort enclosing transaction")
	if e := repo.Update(owner(), func(tx domain.Transaction) error {
		command[api.ChangeResourceRecordSetsResponse](t, s, tx.Context(), "ChangeResourceRecordSets", &api.ChangeResourceRecordSetsRequest{HostedZoneId: zone.HostedZone.Id, ChangeBatch: &api.ChangeBatch{Changes: api.Changes{{Action: new(api.ChangeActionDELETE), ResourceRecordSet: record}}}})
		return rollback
	}); !errors.Is(e, rollback) {
		t.Fatal(e)
	}
	close()
	open()
	if e := at.Advance(time.Second); e != nil {
		t.Fatal(e)
	}
	status := command[api.GetChangeResponse](t, s, owner(), "GetChange", &api.GetChangeRequest{Id: new(api.ChangeId(*add.ChangeInfo.Id))})
	if *status.ChangeInfo.Status != api.ChangeStatusINSYNC {
		t.Fatal(status)
	}
	for _, network := range []string{"udp", "tcp"} {
		got := requestDNS(t, server.Address(), network, dnsmessage.TypeA)
		if got.RCode != dnsmessage.RCodeSuccess || !got.Authoritative || len(got.Answers) != 1 {
			t.Fatalf("%s DNS response=%#v", network, got)
		}
		a, ok := got.Answers[0].Body.(*dnsmessage.AResource)
		if !ok || a.A != [4]byte{192, 0, 2, 42} {
			t.Fatalf("%s wrong retained address: %#v", network, got.Answers)
		}
	}
	noData := requestDNS(t, server.Address(), "udp", dnsmessage.TypeAAAA)
	if noData.RCode != dnsmessage.RCodeSuccess || len(noData.Answers) != 0 || len(noData.Authorities) != 1 || noData.Authorities[0].Header.Type != dnsmessage.TypeSOA {
		t.Fatalf("invalid NODATA response: %#v", noData)
	}
	command[api.ChangeResourceRecordSetsResponse](t, s, owner(), "ChangeResourceRecordSets", &api.ChangeResourceRecordSetsRequest{HostedZoneId: zone.HostedZone.Id, ChangeBatch: &api.ChangeBatch{Changes: api.Changes{{Action: new(api.ChangeActionDELETE), ResourceRecordSet: record}}}})
	close()
	open()
	deleted := requestDNS(t, server.Address(), "udp", dnsmessage.TypeA)
	if deleted.RCode != dnsmessage.RCodeNameError || len(deleted.Answers) != 0 {
		t.Fatalf("deleted record revived: %#v", deleted)
	}
	command[api.DeleteHostedZoneResponse](t, s, owner(), "DeleteHostedZone", &api.DeleteHostedZoneRequest{Id: zone.HostedZone.Id})
	absent := requestDNS(t, server.Address(), "udp", dnsmessage.TypeA)
	if absent.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("deleted zone still authoritative: %#v", absent)
	}
}
