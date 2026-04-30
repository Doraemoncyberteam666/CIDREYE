package scanner

import (
	"context"
	"net"
	"os"
	"reflect"
	"strings"
	"synapse/internal/output"
	"testing"
	"time"
)

func TestScanner_Run(t *testing.T) {
	// Start a local listener to simulate an open port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	// Accept one connection and send a banner
	go func() {
		conn, err := l.Accept()
		if err == nil {
			conn.Write([]byte("SSH-2.0-TestServer\n"))
			conn.Close()
		}
	}()

	tempOut, err := os.CreateTemp("", "scan-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempOut.Name())

	writer, err := output.NewWriter(tempOut.Name(), false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	cfg := Config{
		Concurrency: 10,
		RateLimit:   100,
		Timeout:     500 * time.Millisecond,
		Banner:      true,
	}

	sc := New(cfg, writer)

	ips := make(chan string, 1)
	ips <- "127.0.0.1"
	close(ips)

	ports := []int{port}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := sc.Run(ctx, ips, ports); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Wait briefly for writer to finish writing
	time.Sleep(100 * time.Millisecond)

	outBytes, err := os.ReadFile(tempOut.Name())
	if err != nil {
		t.Fatal(err)
	}

	outStr := string(outBytes)
	if !strings.Contains(outStr, "OPEN") {
		t.Errorf("Expected OPEN port output, got: %s", outStr)
	}
	if !strings.Contains(outStr, "SSH-2.0-TestServer") {
		t.Errorf("Expected banner output, got: %s", outStr)
	}
}

func TestScanner_Run_InvalidConfig(t *testing.T) {
	writer, err := output.NewWriter("", false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "zero concurrency",
			cfg: Config{
				Concurrency: 0,
				Timeout:     500 * time.Millisecond,
			},
			wantErr: "scanner concurrency must be greater than 0",
		},
		{
			name: "zero timeout",
			cfg: Config{
				Concurrency: 1,
				Timeout:     0,
			},
			wantErr: "scanner timeout must be greater than 0",
		},
		{
			name: "negative retries",
			cfg: Config{
				Concurrency: 1,
				Timeout:     500 * time.Millisecond,
				Retries:     -1,
			},
			wantErr: "scanner retries cannot be negative",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := New(tc.cfg, writer)
			ips := make(chan string)
			close(ips)
			err := sc.Run(context.Background(), ips, nil)
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("Run() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestScanner_OpenTargets_Sorted(t *testing.T) {
	sc := &Scanner{
		openTargets: map[string]struct{}{
			"10.0.0.2:443": {},
			"10.0.0.1:22":  {},
			"10.0.0.1:80":  {},
		},
	}

	got := sc.OpenTargets()
	want := []string{
		"10.0.0.1:22",
		"10.0.0.1:80",
		"10.0.0.2:443",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OpenTargets() = %v, want %v", got, want)
	}
}
