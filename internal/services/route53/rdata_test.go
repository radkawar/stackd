package route53

import (
	"encoding/json"
	"golang.org/x/net/dns/dnsmessage"
	"os"
	"reflect"
	"testing"
)

func TestRDataFixtureRoundTripsWire(t *testing.T) {
	data, e := os.ReadFile("testdata/rdata.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Cases []struct {
			Type, Value, Canonical string
			Invalid                bool
		}
	}
	if e = json.Unmarshal(data, &fixture); e != nil {
		t.Fatal(e)
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Type+"/"+tc.Value, func(t *testing.T) {
			body, canonical, e := parseRData(tc.Type, tc.Value)
			if tc.Invalid {
				if e == nil {
					t.Fatalf("accepted invalid %s %s", tc.Type, tc.Value)
				}
				return
			}
			if e != nil || canonical != tc.Canonical {
				t.Fatalf("canonical=%q err=%v want=%q", canonical, e, tc.Canonical)
			}
			name, _ := dnsmessage.NewName("record.example.test.")
			message := dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: recordTypes[tc.Type], Class: dnsmessage.ClassINET, TTL: 60}, Body: body}}}
			packet, e := message.Pack()
			if e != nil {
				t.Fatal(e)
			}
			var decoded dnsmessage.Message
			if e = decoded.Unpack(packet); e != nil {
				t.Fatal(e)
			}
			if len(decoded.Answers) != 1 || !reflect.DeepEqual(decoded.Answers[0].Body, body) {
				t.Fatalf("wire value changed: %#v", decoded.Answers)
			}
			if tc.Type == "CAA" {
				caa := decoded.Answers[0].Body.(*dnsmessage.UnknownResource)
				if string(caa.Data[2:7]) != "issue" || string(caa.Data[7:]) != "example-ca.test" || caa.Data[0] != 0 || caa.Data[1] != 5 {
					t.Fatalf("invalid CAA wire encoding: %v", caa.Data)
				}
			}
		})
	}
}
