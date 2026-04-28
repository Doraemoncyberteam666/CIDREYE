package targets

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func TestGenerator_Generate(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    []string
		wantErr bool
	}{
		{
			name:    "single IP",
			target:  "192.168.1.1",
			want:    []string{"192.168.1.1"},
			wantErr: false,
		},
		{
			name:    "CIDR /30",
			target:  "192.168.1.0/30",
			want:    []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"},
			wantErr: false,
		},
		{
			name:    "invalid IP",
			target:  "192.168.1.256",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			target:  "192.168.1.0/33",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGenerator(tt.target, "")
			out, errc := g.Generate(context.Background())

			var got []string
			for ip := range out {
				got = append(got, ip)
			}

			// read errors
			var err error
			for e := range errc {
				if e != nil {
					err = e
				}
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Generator.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Generator.Generate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerator_GenerateFromFile(t *testing.T) {
	content := "192.168.1.1\n10.0.0.0/30\n# comment\ninvalid_ip"
	f, err := os.CreateTemp("", "ips-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	g := NewGenerator(f.Name(), "")
	out, errc := g.Generate(context.Background())

	var got []string
	for ip := range out {
		got = append(got, ip)
	}

	var hasErr bool
	for e := range errc {
		if e != nil {
			hasErr = true
		}
	}

	want := []string{"192.168.1.1", "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Generate() from file = %v, want %v", got, want)
	}

	if !hasErr {
		t.Errorf("Generate() from file expected error due to invalid_ip")
	}
}

func TestGenerator_GenerateWithExclude(t *testing.T) {
	content := "192.168.1.2\n192.168.1.5"
	f, err := os.CreateTemp("", "excl-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	g := NewGenerator("192.168.1.0/29", f.Name())
	out, errc := g.Generate(context.Background())

	var got []string
	for ip := range out {
		got = append(got, ip)
	}

	var hasErr bool
	for e := range errc {
		if e != nil {
			hasErr = true
		}
	}

	want := []string{"192.168.1.0", "192.168.1.1", "192.168.1.3", "192.168.1.4", "192.168.1.6", "192.168.1.7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Generate() with exclude = %v, want %v", got, want)
	}

	if hasErr {
		t.Errorf("Generate() with exclude expected no error")
	}
}
