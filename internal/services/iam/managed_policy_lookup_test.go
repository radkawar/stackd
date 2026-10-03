package iam

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func TestAWSManagedLookupSkipsNonAWSReferences(t *testing.T) {
	const child = "STACKD_TEST_COLD_MANAGED_LOOKUP"
	if os.Getenv(child) != "1" {
		// Other IAM tests legitimately initialize the lazy catalogue. A fresh
		// test process makes a cold customer lookup independent of test order.
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAWSManagedLookupSkipsNonAWSReferences$")
		command.Env = append(os.Environ(), child+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cold policy lookup: %v\n%s", err, output)
		}
		return
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, reference := range []struct{ partition, arn string }{
		{"aws", "arn:aws:iam::123456789012:policy/deleted-session"},
		{"aws", "arn:aws:iam::123456789012:policy/AdministratorAccess"},
		{"aws-cn", "arn:aws-cn:iam::123456789012:policy/local"},
		{"aws-us-gov", "arn:aws-us-gov:iam::123456789012:policy/local"},
		{"aws", "arn:aws-cn:iam::aws:policy/AdministratorAccess"},
		{"aws-cn", "arn:aws:iam::aws:policy/AdministratorAccess"},
		{"aws", "arn:aws:sqs::aws:policy/AdministratorAccess"},
		{"aws", "arn:aws:iam:us-east-1:aws:policy/AdministratorAccess"},
		{"aws", "arn:aws:iam::aws:user/AdministratorAccess"},
		{"aws", "arn:aws:iam::AWS:policy/AdministratorAccess"},
		{"aws", "arn:aws:iam::aws:policy/"},
		{"aws", ""},
		{"", "arn::iam::aws:policy/AdministratorAccess"},
	} {
		if _, ok := lookupAWSManagedPolicy(reference.partition, reference.arn); ok {
			t.Fatalf("non-AWS reference resolved: %q %q", reference.partition, reference.arn)
		}
	}
	runtime.ReadMemStats(&after)
	// Rejecting references must not decompress/parse the 72 MB catalogue. This
	// generous allocation budget catches that regression without a wall timer.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Fatalf("non-AWS references allocated %d bytes; immutable catalogue was loaded", allocated)
	}
}

func TestAWSManagedLookupPreservesLiteralNamesAndPartitions(t *testing.T) {
	for _, name := range []string{"AdministratorAccess", "service-role/AWSLambdaBasicExecutionRole", "job-function/ViewOnlyAccess"} {
		arn := "arn:aws:iam::aws:policy/" + name
		policy, ok := lookupAWSManagedPolicy("aws", arn)
		if !ok || policy.Arn != arn || len(policy.Versions) == 0 {
			t.Fatalf("authoritative policy unavailable: %s", arn)
		}
	}
	for _, arn := range []string{
		"arn:aws:iam::aws:policy/administratoraccess",
		"arn:aws:iam::aws:policy/service-role%2FAWSLambdaBasicExecutionRole",
		"arn:aws:iam::aws:policy/AWSLambdaBasicExecutionRole",
	} {
		if _, ok := lookupAWSManagedPolicy("aws", arn); ok {
			t.Fatalf("lookup normalized a nonliteral policy name: %s", arn)
		}
	}
	for _, partition := range []string{"aws-cn", "aws-us-gov"} {
		if _, ok := lookupAWSManagedPolicy(partition, "arn:"+partition+":iam::aws:policy/AdministratorAccess"); ok {
			t.Fatalf("uncaptured partition %s received a rewritten commercial policy", partition)
		}
	}
}
