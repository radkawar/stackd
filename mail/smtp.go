// Package mail delivers control-plane messages through an explicitly configured
// SMTP relay. A local mail capture server keeps these workflows offline.
package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Message is a service-authored plain-text message. To is a validated mailbox;
// Subject and Text belong to the sending service, not request header fragments.
type Message struct{ To, Subject, Text string }

// SMTP sends through a relay without authentication, suitable for a local mail
// capture server. It negotiates verified STARTTLS when the relay advertises it.
type SMTP struct{ address, host, from string }

// NewSMTP configures an explicit host:port relay and literal sender mailbox.
func NewSMTP(address, from string) (*SMTP, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, fmt.Errorf("SMTP address must include a host and port")
	}
	parsed, err := netmail.ParseAddress(from)
	if err != nil || parsed.Name != "" || parsed.Address != from {
		return nil, fmt.Errorf("SMTP sender must be a mailbox address")
	}
	return &SMTP{address: address, host: host, from: from}, nil
}

// Send honors cancellation during dialing and SMTP commands. Its timeout uses
// real time; advancing emulator service time does not interrupt network I/O.
// A failed QUIT after DATA acceptance does not turn a delivered message into a
// delivery failure. Ambiguous network failures may result in duplicate delivery.
func (s *SMTP) Send(ctx context.Context, message Message) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.address)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return err
	}
	defer client.Close()
	if supported, _ := client.Extension("STARTTLS"); supported {
		if err := client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if err := client.Mail(s.from); err != nil {
		return err
	}
	if err := client.Rcpt(message.To); err != nil {
		return err
	}
	data, err := client.Data()
	if err != nil {
		return err
	}
	text := strings.ReplaceAll(strings.ReplaceAll(message.Text, "\r\n", "\n"), "\n", "\r\n")
	_, writeErr := fmt.Fprintf(data, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", s.from, message.To, mime.QEncoding.Encode("UTF-8", message.Subject), text)
	if writeErr != nil {
		return writeErr
	}
	if err := data.Close(); err != nil {
		return err
	}
	_ = client.Quit()
	return nil
}
