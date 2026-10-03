package ec2

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQEMUStateDirectorySocketBoundary(t *testing.T) {
	config := Config{Networks: &GuestNetworkManager{}}
	for name, destination := range map[string]*string{
		"qemu-system-x86_64": &config.SystemBinary, "qemu-img": &config.ImageBinary,
		"qemu-nbd": &config.NBDBinary, "qemu-io": &config.IOBinary,
	} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("native socket boundary requires %s: %v", name, err)
		}
		*destination = path
	}
	root, err := os.MkdirTemp("", "qmp-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	const arn = "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0"
	padding := 107 - len(filepath.Join(root, "vm-"+identifier(arn), "qmp.sock")) - 1
	if padding < 2 {
		t.Skip("temporary root cannot accommodate the native socket boundary")
	}
	for _, tc := range []struct {
		name   string
		suffix string
		valid  bool
	}{
		{"maximum", strings.Repeat("a", padding), true},
		{"oversized", strings.Repeat("a", padding+1), false},
		{"utf8-byte-boundary", strings.Repeat("a", padding-1) + "é", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.StateDirectory = filepath.Join(root, tc.suffix)
			driver, err := NewQEMU(config)
			if !tc.valid {
				if err == nil {
					t.Fatal("accepted a native socket address that cannot be dialed")
				}
				if _, err := os.Stat(config.StateDirectory); !os.IsNotExist(err) {
					t.Fatalf("rejected configuration created native state: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			directory := driver.directory(arn)
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "qmp.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialTimeout("unix", path, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := server.Write([]byte("native boundary")); err != nil {
				t.Fatal(err)
			}
			var got [15]byte
			if _, err := io.ReadFull(client, got[:]); err != nil || string(got[:]) != "native boundary" {
				t.Fatalf("native socket round trip: %q, %v", got, err)
			}
		})
	}
}
