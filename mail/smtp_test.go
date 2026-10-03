package mail_test

import (
	"context"
	"net"
	"testing"
	"time"

	"stackd/mail"
)

func TestSMTPCancellationInterruptsBlockedGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	sender, err := mail.NewSMTP(listener.Addr().String(), "sender@example.test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- sender.Send(ctx, mail.Message{To: "recipient@example.test", Subject: "Cancellation", Text: "Test"})
	}()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled delivery reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SMTP greeting prevented cancellation")
	}
}
