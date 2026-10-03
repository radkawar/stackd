// Command ses_classic_sdk_smoke exercises both generated AWS SDK SES clients
// against an explicitly selected local controller, never a native endpoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	classic "github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	v2 "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/smithy-go"
)

type message struct {
	ID         string   `json:"message_id"`
	Subject    string   `json:"subject"`
	Text       string   `json:"text"`
	BCC        []string `json:"bcc"`
	EnvelopeTo []string `json:"envelope_to,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	endpoint := flag.String("endpoint", "", "explicit local HTTP endpoint")
	sender := flag.String("sender", "", "verified owned identity")
	template := flag.String("template", "", "owned shared template")
	configuration := flag.String("config", "", "owned shared configuration set")
	phase := flag.String("phase", "", "unique process phase")
	flag.Parse()
	u, e := url.Parse(*endpoint)
	if e != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return errors.New("endpoint must explicitly select local loopback HTTP")
	}
	if *sender == "" || *template == "" || *configuration == "" || *phase == "" {
		return errors.New("sender, template, config and phase are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1}
	c := ses.NewFromConfig(cfg, func(o *ses.Options) { o.BaseEndpoint = endpoint })
	c2 := sesv2.NewFromConfig(cfg, func(o *sesv2.Options) { o.BaseEndpoint = endpoint })
	t, e := c2.GetEmailTemplate(ctx, &sesv2.GetEmailTemplateInput{TemplateName: template})
	if e != nil {
		return e
	}
	if t.TemplateContent == nil || aws.ToString(t.TemplateContent.Subject) != "Classic {{name}}" {
		return errors.New("classic template not visible through v2 SDK")
	}
	identity, e := c2.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{EmailIdentity: sender})
	if e != nil {
		return e
	}
	if !identity.VerifiedForSendingStatus {
		return errors.New("classic verification not visible through v2 SDK")
	}
	if _, e = c.DescribeConfigurationSet(ctx, &ses.DescribeConfigurationSetInput{ConfigurationSetName: configuration}); e != nil {
		return e
	}
	const recipient = "success@simulator.amazonses.com"
	const hidden = "complaint@simulator.amazonses.com"
	var messages []message
	subject, text := "SDK simple "+*phase, "Actual generated classic SDK body "+*phase
	single, e := c.SendEmail(ctx, &ses.SendEmailInput{Source: sender, ConfigurationSetName: configuration, Destination: &classic.Destination{ToAddresses: []string{recipient}, BccAddresses: []string{hidden}}, Message: &classic.Message{Subject: &classic.Content{Data: &subject}, Body: &classic.Body{Text: &classic.Content{Data: &text}}}})
	if e != nil {
		return e
	}
	messages = append(messages, message{ID: aws.ToString(single.MessageId), Subject: subject, Text: text, BCC: []string{hidden}})
	subject, text = "SDK raw "+*phase, "Actual raw MIME "+*phase
	raw := []byte("From: " + *sender + "\r\nTo: header-only@example.invalid\r\nBcc: hidden-header@example.invalid\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + text + "\r\n")
	rawOut, e := c.SendRawEmail(ctx, &ses.SendRawEmailInput{Source: sender, ConfigurationSetName: configuration, Destinations: []string{recipient}, RawMessage: &classic.RawMessage{Data: raw}})
	if e != nil {
		return e
	}
	messages = append(messages, message{ID: aws.ToString(rawOut.MessageId), Subject: subject, Text: text, BCC: []string{}, EnvelopeTo: []string{recipient}})
	name, code := "SDK-template-"+*phase, "sdk-"+*phase
	data, _ := json.Marshal(map[string]string{"name": name, "code": code})
	templated, e := c.SendTemplatedEmail(ctx, &ses.SendTemplatedEmailInput{Source: sender, ConfigurationSetName: configuration, Template: template, TemplateData: aws.String(string(data)), Destination: &classic.Destination{ToAddresses: []string{recipient}}})
	if e != nil {
		return e
	}
	messages = append(messages, message{ID: aws.ToString(templated.MessageId), Subject: "Classic " + name, Text: "Hello " + name + ", code " + code, BCC: []string{}})
	name = "SDK-bulk-" + *phase
	data, _ = json.Marshal(map[string]string{"name": name, "code": code})
	bulk, e := c.SendBulkTemplatedEmail(ctx, &ses.SendBulkTemplatedEmailInput{Source: sender, ConfigurationSetName: configuration, Template: template, DefaultTemplateData: aws.String(string(data)), Destinations: []classic.BulkEmailDestination{{Destination: &classic.Destination{ToAddresses: []string{recipient}, BccAddresses: []string{hidden}}}}})
	if e != nil {
		return e
	}
	if len(bulk.Status) != 1 || bulk.Status[0].Status != classic.BulkEmailStatusSuccess {
		return fmt.Errorf("classic bulk rejection: %+v", bulk.Status)
	}
	messages = append(messages, message{ID: aws.ToString(bulk.Status[0].MessageId), Subject: "Classic " + name, Text: "Hello " + name + ", code " + code, BCC: []string{hidden}})
	subject, text = "SDK v2 "+*phase, "Shared v2 data plane "+*phase
	second, e := c2.SendEmail(ctx, &sesv2.SendEmailInput{FromEmailAddress: sender, ConfigurationSetName: configuration, Destination: &v2.Destination{ToAddresses: []string{recipient}}, Content: &v2.EmailContent{Simple: &v2.Message{Subject: &v2.Content{Data: &subject}, Body: &v2.Body{Text: &v2.Content{Data: &text}}}}})
	if e != nil {
		return e
	}
	messages = append(messages, message{ID: aws.ToString(second.MessageId), Subject: subject, Text: text, BCC: []string{}})
	_, e = c.SendEmail(ctx, &ses.SendEmailInput{Source: aws.String("unverified@example.invalid"), Destination: &classic.Destination{ToAddresses: []string{recipient}}, Message: &classic.Message{Subject: &classic.Content{Data: &subject}, Body: &classic.Body{Text: &classic.Content{Data: &text}}}})
	var apiError smithy.APIError
	if !errors.As(e, &apiError) || apiError.ErrorCode() != "MessageRejected" {
		return fmt.Errorf("unverified source boundary: %v", e)
	}
	other := ses.NewFromConfig(cfg, func(o *ses.Options) { o.BaseEndpoint = endpoint; o.Region = "us-west-2" })
	_, e = other.GetTemplate(ctx, &ses.GetTemplateInput{TemplateName: template})
	if !errors.As(e, &apiError) || apiError.ErrorCode() != "TemplateDoesNotExist" {
		return fmt.Errorf("region boundary: %v", e)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Messages []message `json:"messages"`
	}{messages})
}
