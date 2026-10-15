package network

import (
	_ "embed"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
)

//go:embed flows_receiver_test.py
var flowReceiverTests string

func TestFlowReceiverDecoderRetentionAndLoss(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python 3 is required for embedded native receiver unit tests")
	}
	command := exec.CommandContext(t.Context(), python, "-c", flowReceiverTests)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "FLOW_TEST_SOURCE="+base64.StdEncoding.EncodeToString([]byte(flowReceiverScript)))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded receiver decoder/retention/loss checks: %v\n%s", err, output)
	}
}

func TestFlowIdentityFullVPCAndSharedOwner(t *testing.T) {
	identity := FlowIdentity{Partition: "aws", AccountID: "222222222222", VPCOwnerAccountID: "111111111111", Region: "us-east-1", VPCID: "vpc-owned", SubnetID: "subnet-shared", InterfaceID: "eni-participant"}
	ownerARN := "arn:aws:ec2:us-east-1:111111111111:vpc/vpc-owned"
	if identity.VPCARN() != ownerARN || identity.Validate(ownerARN) != nil {
		t.Fatalf("shared VPC identity rejected: %+v", identity)
	}
	for _, wrong := range []string{"vpc-owned", strings.Replace(ownerARN, "111111111111", "222222222222", 1), strings.Replace(ownerARN, "us-east-1", "us-west-2", 1)} {
		if identity.Validate(wrong) == nil {
			t.Fatalf("accepted wrong scoped VPC identity %q", wrong)
		}
	}
	identity.VPCOwnerAccountID = ""
	if identity.Validate("arn:aws:ec2:us-east-1:222222222222:vpc/vpc-owned") != nil {
		t.Fatal("same-owner VPC identity rejected")
	}
}
