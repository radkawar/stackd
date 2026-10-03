package guardduty

import (
	"reflect"
	"testing"

	"stackd/journal"
)

func TestIPListsDetectionPrecedenceAndLatestEvidence(t *testing.T) {
	s, ctx, detector, _ := filterFixture(t)
	detector.Status = "ENABLED"
	detector.ARN = detectorARN(detector.Scope, detector.ID)
	detector.Features = []Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}}
	address, _ := listSourceIPv4("8.8.8.8")
	trusted := IPList{Scope: detector.Scope, DetectorID: detector.ID, Kind: TrustedIPList, ID: "trusted", Name: "trusted", Status: "INACTIVE"}
	threat := IPList{Scope: detector.Scope, DetectorID: detector.ID, Kind: ThreatIPList, ID: "threat", Name: "malicious-source", Status: "ACTIVE"}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutDetector(detector); err != nil {
			return err
		}
		for _, list := range []IPList{trusted, threat} {
			if err := tx.PutIPList(list); err != nil {
				return err
			}
			if err := tx.ReplaceIPRanges(list.Scope, list.DetectorID, list.Kind, list.ID, []IPRange{{First: address, Last: address}}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	call := journal.APICallCompleted{EventID: "first", EventSource: "iam.amazonaws.com", EventName: "ListUsers", Category: journal.CategoryManagement, SourceIPAddress: "8.8.8.8", Identity: journal.APIIdentity{Type: "Root", PrincipalID: detector.AccountID, AccessKeyID: "actual-key"}}
	envelope := journal.Envelope{At: s.clock.Now(), Partition: detector.Partition, AccountID: detector.AccountID, Region: detector.Region}
	observe := func() {
		t.Helper()
		if err := s.ObserveAPICall(ctx, envelope, call, nil); err != nil {
			t.Fatal(err)
		}
	}
	findings := func() map[string]Finding {
		t.Helper()
		out := map[string]Finding{}
		if err := s.repository.View(ctx, func(r Reader) error {
			rows, err := r.Findings(detector.Scope, detector.ID)
			for _, row := range rows {
				out[row.Observation.Type] = row
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	const custom = "Recon:IAMUser/MaliciousIPCaller.Custom"
	const root = "Policy:IAMUser/RootCredentialUsage"
	observe()
	first := findings()
	if len(first) != 2 || first[custom].Count != 1 || first[root].Count != 1 || !reflect.DeepEqual(first[custom].Observation.ThreatListNames, []string{"malicious-source"}) {
		t.Fatalf("missing actual threat/root evidence: %+v", first)
	}
	// Matching trust suppresses both the new custom rule and preexisting rules,
	// but cannot erase already-retained occurrences or alter their counts.
	trusted.Status = "ACTIVE"
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutIPList(trusted) }); err != nil {
		t.Fatal(err)
	}
	call.EventID = "trusted"
	observe()
	if got := findings(); !reflect.DeepEqual(got, first) {
		t.Fatalf("trusted activity changed retained findings: %+v", got)
	}
	trusted.Status = "INACTIVE"
	threat.Name = "renamed-source"
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutIPList(trusted); err != nil {
			return err
		}
		return tx.PutIPList(threat)
	}); err != nil {
		t.Fatal(err)
	}
	call.EventID, call.ErrorCode = "denied", "AccessDenied"
	observe()
	second := findings()
	if second[custom].ID != first[custom].ID || second[custom].Count != 2 || second[root].Count != 2 || second[custom].Observation.ErrorCode != "AccessDenied" || !reflect.DeepEqual(second[custom].Observation.ThreatListNames, []string{"renamed-source"}) {
		t.Fatalf("reactivated detection lost identity/count/latest evidence: %+v", second)
	}
	out := observedFindingOutput(second[custom])
	if out.Service.Evidence == nil || len(out.Service.Evidence.ThreatIntelligenceDetails) != 1 || value(out.Service.Evidence.ThreatIntelligenceDetails[0].ThreatListName) != "renamed-source" {
		t.Fatalf("missing threat list in public finding: %+v", out.Service.Evidence)
	}
	// Same event replay is idempotent, and another regional producer cannot use
	// this detector's lists or mutate its observations.
	observe()
	envelope.Region = "us-west-2"
	call.EventID = "other-region"
	observe()
	if got := findings(); !reflect.DeepEqual(got, second) {
		t.Fatalf("replay/other region changed findings: %+v", got)
	}
	threat.Status = "DELETED"
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutIPList(threat) }); err != nil {
		t.Fatal(err)
	}
	envelope.Region = detector.Region
	call.EventID = "after-delete"
	observe()
	last := findings()
	if last[custom].Count != 2 || last[root].Count != 3 {
		t.Fatalf("deleted threat list still detected: %+v", last)
	}
}

func TestIPListsExcludeNonPublicAndUnauthenticatedSources(t *testing.T) {
	for _, source := range []string{"", "guardduty.amazonaws.com", "127.0.0.1", "10.1.2.3", "172.16.1.2", "192.168.1.2", "169.254.1.2", "100.64.1.2", "0.1.2.3", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.19.1.1", "192.0.0.8", "192.88.99.2", "224.0.0.1", "240.1.1.1", "::1", "::ffff:8.8.8.8", "2001:4860:4860::8888"} {
		if _, ok := listSourceIPv4(source); ok {
			t.Errorf("non-public source admitted: %s", source)
		}
	}
	s, ctx, d, _ := filterFixture(t)
	d.Status, d.Features = "ENABLED", []Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}}
	list := IPList{Scope: d.Scope, DetectorID: d.ID, Kind: ThreatIPList, ID: "threat", Name: "all-public", Status: "ACTIVE"}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutIPList(list); err != nil {
			return err
		}
		return tx.ReplaceIPRanges(d.Scope, d.ID, list.Kind, list.ID, []IPRange{{First: 0, Last: ^uint32(0)}})
	}); err != nil {
		t.Fatal(err)
	}
	base := journal.APICallCompleted{EventSource: "iam.amazonaws.com", EventName: "ListUsers", SourceIPAddress: "8.8.8.8", Category: journal.CategoryManagement, Identity: journal.APIIdentity{Type: "IAMUser", AccessKeyID: "actual-key"}}
	for _, mutate := range []func(*journal.APICallCompleted){
		func(c *journal.APICallCompleted) { c.Identity.AccessKeyID = "" },
		func(c *journal.APICallCompleted) { c.ServiceEvent = true },
		func(c *journal.APICallCompleted) { c.Identity.Type = "AWSService" },
		func(c *journal.APICallCompleted) { c.SourceIPAddress = "guardduty.amazonaws.com" },
		func(c *journal.APICallCompleted) { c.Category = journal.CategoryData },
	} {
		call := base
		mutate(&call)
		if err := s.repository.View(ctx, func(r Reader) error {
			got, err := detectAPICallWithLists(r, d, call, nil)
			if len(got) != 0 {
				t.Fatalf("ineligible source produced %+v", got)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIPListsCustomFindingOperationBoundaries(t *testing.T) {
	s, ctx, d, _ := filterFixture(t)
	d.Status = "ENABLED"
	d.Features = []Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}, {Name: "S3_DATA_EVENTS", Status: "ENABLED"}}
	address, _ := listSourceIPv4("8.8.8.8")
	list := IPList{Scope: d.Scope, DetectorID: d.ID, Kind: ThreatIPList, ID: "threat", Name: "ingested-threat", Status: "ACTIVE"}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutIPList(list); err != nil {
			return err
		}
		return tx.ReplaceIPRanges(d.Scope, d.ID, list.Kind, list.ID, []IPRange{{First: address, Last: address}})
	}); err != nil {
		t.Fatal(err)
	}
	const recon = "Recon:IAMUser/MaliciousIPCaller.Custom"
	const iamAccess = "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"
	const discovery = "Discovery:S3/MaliciousIPCaller.Custom"
	const s3Access = "UnauthorizedAccess:S3/MaliciousIPCaller.Custom"
	bucketARN := "arn:" + d.Partition + ":s3:::actual-bucket"
	for _, tc := range []struct {
		name, source, action string
		category             journal.APICallCategory
		errorCode, want      string
	}{
		{"list management", "iam.amazonaws.com", "ListUsers", journal.CategoryManagement, "", recon},
		{"describe denied", "ec2.amazonaws.com", "DescribeInstances", journal.CategoryManagement, "UnauthorizedOperation", recon},
		{"create management", "iam.amazonaws.com", "CreateUser", journal.CategoryManagement, "", iamAccess},
		{"launch denied", "ec2.amazonaws.com", "RunInstances", journal.CategoryManagement, "UnauthorizedOperation", iamAccess},
		{"permission denied", "iam.amazonaws.com", "PutUserPolicy", journal.CategoryManagement, "AccessDenied", iamAccess},
		{"s3 management stays IAM", "s3.amazonaws.com", "PutBucketPolicy", journal.CategoryManagement, "AccessDenied", iamAccess},
		{"s3 list", "s3.amazonaws.com", "ListObjects", journal.CategoryData, "", discovery},
		{"s3 list v2 denied", "s3.amazonaws.com", "ListObjectsV2", journal.CategoryData, "AccessDenied", discovery},
		{"s3 object acl denied", "s3.amazonaws.com", "GetObjectAcl", journal.CategoryData, "NoSuchKey", discovery},
		{"s3 write", "s3.amazonaws.com", "PutObject", journal.CategoryData, "", s3Access},
		{"s3 write denied", "s3.amazonaws.com", "PutObject", journal.CategoryData, "AccessDenied", s3Access},
		{"s3 acl write", "s3.amazonaws.com", "PutObjectAcl", journal.CategoryData, "", s3Access},
		{"s3 acl write denied", "s3.amazonaws.com", "PutObjectAcl", journal.CategoryData, "AccessDenied", s3Access},
		{"unclassified category", "iam.amazonaws.com", "CreateUser", "", "", ""},
		{"wrong data source", "lambda.amazonaws.com", "PutObject", journal.CategoryData, "", ""},
		{"IAM data is not management", "iam.amazonaws.com", "ListUsers", journal.CategoryData, "", ""},
		{"get is not discovery prefix", "s3.amazonaws.com", "GetObject", journal.CategoryData, "", ""},
		{"unknown put is not write evidence", "s3.amazonaws.com", "PutUnrecognizedObject", journal.CategoryData, "", ""},
		{"bucket management is not data discovery", "s3.amazonaws.com", "ListBuckets", journal.CategoryData, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := journal.APICallCompleted{
				EventID: tc.name, EventSource: tc.source, EventName: tc.action, Category: tc.category,
				ErrorCode: tc.errorCode, SourceIPAddress: "8.8.8.8",
				Identity:          journal.APIIdentity{Type: "IAMUser", AccessKeyID: "actual-key", PrincipalID: "actual-principal"},
				RequestParameters: []byte(`{"bucketName":"actual-bucket","key":"actual-key"}`),
				EventResources:    []journal.APIEventResource{{Type: "AWS::S3::Bucket", ARN: bucketARN}},
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				got, err := detectAPICallWithLists(r, d, call, nil)
				if err != nil {
					return err
				}
				if tc.want == "" {
					if len(got) != 0 {
						t.Fatalf("unsupported category/operation generated %+v", got)
					}
					return nil
				}
				if len(got) != 1 || got[0].Type != tc.want || got[0].ErrorCode != tc.errorCode ||
					!reflect.DeepEqual(got[0].ThreatListNames, []string{"ingested-threat"}) {
					t.Fatalf("wrong custom threat evidence: %+v", got)
				}
				if tc.want == discovery || tc.want == s3Access {
					if got[0].ResourceType != "AWS::S3::Bucket" || got[0].ResourceName != "actual-bucket" ||
						got[0].ResourceARN != bucketARN || got[0].FeatureName != "S3DataEvent" || got[0].Severity != 8 {
						t.Fatalf("lost actual bucket identity or S3 classification: %+v", got[0])
					}
				} else if got[0].FeatureName != "CloudTrailManagementEvent" || got[0].ResourceARN != "" || got[0].Severity != 5 {
					t.Fatalf("management event classified as S3 data: %+v", got[0])
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIPListsCustomFindingGatesAndRetainedEvidence(t *testing.T) {
	for _, action := range []string{"ListUsers", "CreateUser", "ListObjects", "PutObject"} {
		t.Run(action, func(t *testing.T) {
			s, ctx, d, _ := filterFixture(t)
			d.Status, d.ARN = "ENABLED", detectorARN(d.Scope, d.ID)
			d.Features = []Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}, {Name: "S3_DATA_EVENTS", Status: "ENABLED"}}
			address, _ := listSourceIPv4("8.8.8.8")
			list := IPList{Scope: d.Scope, DetectorID: d.ID, Kind: ThreatIPList, ID: "threat", Name: "original-list", Status: "ACTIVE"}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutDetector(d); err != nil {
					return err
				}
				if err := tx.PutIPList(list); err != nil {
					return err
				}
				return tx.ReplaceIPRanges(d.Scope, d.ID, list.Kind, list.ID, []IPRange{{First: address, Last: address}})
			}); err != nil {
				t.Fatal(err)
			}
			call := journal.APICallCompleted{
				EventID: "actual-event", EventSource: "iam.amazonaws.com", EventName: action,
				Category: journal.CategoryManagement, SourceIPAddress: "8.8.8.8",
				Identity: journal.APIIdentity{Type: "IAMUser", AccessKeyID: "actual-key", PrincipalID: "actual-principal"},
			}
			isS3 := action == "ListObjects" || action == "PutObject"
			if isS3 {
				call.EventSource, call.Category = "s3.amazonaws.com", journal.CategoryData
				call.RequestParameters = []byte(`{"bucketName":"actual-bucket","key":"actual-key"}`)
				call.EventResources = []journal.APIEventResource{{Type: "AWS::S3::Bucket", ARN: "arn:" + d.Partition + ":s3:::actual-bucket"}}
			}
			assertSuppressed := func(detector Detector, candidate journal.APICallCompleted) {
				t.Helper()
				if err := s.repository.View(ctx, func(r Reader) error {
					got, err := detectAPICallWithLists(r, detector, candidate, []DetectionTarget{{ResourceType: "AWS::S3::Bucket", ResourceName: "actual-bucket"}})
					if len(got) != 0 {
						t.Fatalf("ineligible event generated %+v", got)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			disabled := d
			disabled.Status = "DISABLED"
			assertSuppressed(disabled, call)
			disabled = d
			disabled.Features = []Feature{{Name: "CLOUD_TRAIL", Status: "DISABLED"}, {Name: "S3_DATA_EVENTS", Status: "ENABLED"}}
			assertSuppressed(disabled, call)
			for _, mutate := range []func(*journal.APICallCompleted){
				func(c *journal.APICallCompleted) { c.Identity.AccessKeyID = "" },
				func(c *journal.APICallCompleted) { c.ServiceEvent = true },
				func(c *journal.APICallCompleted) { c.Identity.Type = "AWSService" },
				func(c *journal.APICallCompleted) { c.SourceIPAddress = "8.8.4.4" },
				func(c *journal.APICallCompleted) { c.SourceIPAddress = "10.0.0.1" },
				func(c *journal.APICallCompleted) { c.SourceIPAddress = "threat-list:8.8.8.8" },
			} {
				candidate := call
				mutate(&candidate)
				assertSuppressed(d, candidate)
			}
			if isS3 {
				disabled.Features = []Feature{{Name: "CLOUD_TRAIL", Status: "ENABLED"}, {Name: "S3_DATA_EVENTS", Status: "DISABLED"}}
				assertSuppressed(disabled, call)
				for _, mutate := range []func(*journal.APICallCompleted){
					func(c *journal.APICallCompleted) { c.RequestParameters = nil },
					func(c *journal.APICallCompleted) { c.RequestParameters = []byte(`{"bucketName":"different-bucket"}`) },
					func(c *journal.APICallCompleted) {
						c.EventResources = nil
						c.Resources = []journal.APIResource{{Type: "AWS::S3::Bucket", Name: "actual-bucket"}}
					},
					func(c *journal.APICallCompleted) {
						c.EventResources = []journal.APIEventResource{{Type: "AWS::S3::Object", ARN: "arn:" + d.Partition + ":s3:::actual-bucket/key"}}
					},
					func(c *journal.APICallCompleted) {
						c.EventResources = []journal.APIEventResource{{Type: "AWS::S3::Bucket", ARN: "arn:other:s3:::actual-bucket"}}
					},
				} {
					candidate := call
					mutate(&candidate)
					assertSuppressed(d, candidate)
				}
			}
			envelope := journal.Envelope{At: s.clock.Now(), Partition: d.Partition, AccountID: d.AccountID, Region: d.Region}
			if err := s.ObserveAPICall(ctx, envelope, call, nil); err != nil {
				t.Fatal(err)
			}
			var original []Finding
			if err := s.repository.View(ctx, func(r Reader) error {
				var err error
				original, err = r.Findings(d.Scope, d.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if len(original) != 1 || original[0].Count != 1 || !reflect.DeepEqual(original[0].Observation.ThreatListNames, []string{"original-list"}) {
				t.Fatalf("actual matching activity not retained: %+v", original)
			}
			call.EventID = "other-scope"
			for _, other := range []journal.Envelope{
				{At: envelope.At, Partition: d.Partition, AccountID: "other-account", Region: d.Region},
				{At: envelope.At, Partition: d.Partition, AccountID: d.AccountID, Region: "other-region"},
				{At: envelope.At, Partition: "other-partition", AccountID: d.AccountID, Region: d.Region},
			} {
				if err := s.ObserveAPICall(ctx, other, call, nil); err != nil {
					t.Fatal(err)
				}
			}
			// Activating trust and renaming the matched threat list must neither
			// create another occurrence nor rewrite already retained evidence.
			list.Name = "renamed-list"
			trusted := IPList{Scope: d.Scope, DetectorID: d.ID, Kind: TrustedIPList, ID: "trusted", Name: "trusted", Status: "ACTIVE"}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutIPList(list); err != nil {
					return err
				}
				if err := tx.PutIPList(trusted); err != nil {
					return err
				}
				return tx.ReplaceIPRanges(d.Scope, d.ID, trusted.Kind, trusted.ID, []IPRange{{First: address, Last: address}})
			}); err != nil {
				t.Fatal(err)
			}
			assertSuppressed(d, call)
			call.EventID = "trusted-event"
			if err := s.ObserveAPICall(ctx, envelope, call, nil); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				got, err := r.Findings(d.Scope, d.ID)
				if !reflect.DeepEqual(got, original) {
					t.Fatalf("trusted/other-scope activity or list rename altered retained findings: %+v", got)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
