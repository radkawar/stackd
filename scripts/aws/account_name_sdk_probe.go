//go:build ignore

// Probe the AWS Go SDK error for a blank account name. The companion Python
// probe supplies a temporary member session and captures this output.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func main() {
	selectedAccount := flag.String("account", "", "AWS account authorized for this native probe (required)")
	flag.Parse()
	if len(*selectedAccount) != 12 {
		fmt.Fprintln(os.Stderr, "--account must be a 12-digit AWS account ID")
		os.Exit(2)
	}
	for _, digit := range *selectedAccount {
		if digit < '0' || digit > '9' {
			fmt.Fprintln(os.Stderr, "--account must be a 12-digit AWS account ID")
			os.Exit(2)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	config := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN"))}
	identity, err := sts.NewFromConfig(config).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "STS caller identity failed:", err)
		os.Exit(1)
	}
	if aws.ToString(identity.Account) != *selectedAccount {
		fmt.Fprintln(os.Stderr, "STS caller account does not match --account")
		os.Exit(1)
	}
	client := account.NewFromConfig(config)
	_, err = client.PutAccountName(ctx, &account.PutAccountNameInput{AccountName: aws.String(" ")})
	result := map[string]any{"success": err == nil}
	var api smithy.APIError
	if errors.As(err, &api) {
		result["code"], result["message"] = api.ErrorCode(), api.ErrorMessage()
	}
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) {
		result["status"] = response.HTTPStatusCode()
		result["error_type_header"] = response.Response.Header.Get("X-Amzn-Errortype")
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
