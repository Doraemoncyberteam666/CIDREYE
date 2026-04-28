package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Result represents a scan result for a single port on an IP.
type Result struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	State  string `json:"state"` // typically "OPEN"
	Banner string `json:"banner,omitempty"`
}

// Writer handles thread-safe writing of scan results.
type Writer struct {
	mu    sync.Mutex
	file  *os.File
	json  bool
	quiet bool
	out   *os.File // usually os.Stdout
}

// NewWriter creates a new output Writer.
func NewWriter(filepath string, useJSON bool, quiet bool) (*Writer, error) {
	w := &Writer{
		json:  useJSON,
		quiet: quiet,
		out:   os.Stdout,
	}

	if filepath != "" {
		f, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open output file: %w", err)
		}
		w.file = f
	}

	return w, nil
}

// WriteResult writes a scan result to configured destinations.
func (w *Writer) WriteResult(r Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var output []byte
	var err error

	if w.json {
		output, err = json.Marshal(r)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		output = append(output, '\n')
	} else {
		if r.Banner != "" {
			output = []byte(fmt.Sprintf("%s:%d [%s] [%s]\n", r.IP, r.Port, r.State, r.Banner))
		} else {
			output = []byte(fmt.Sprintf("%s:%d [%s]\n", r.IP, r.Port, r.State))
		}
	}

	if !w.quiet {
		if _, err := w.out.Write(output); err != nil {
			return err
		}
	}

	if w.file != nil {
		if _, err := w.file.Write(output); err != nil {
			return err
		}
	}

	return nil
}

// Close closes any open files.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// Log writes a message to stdout if not quiet.
func (w *Writer) Log(format string, a ...interface{}) {
	if w.quiet {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintf(w.out, format+"\n", a...)
}
