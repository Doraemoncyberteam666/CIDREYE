package targets

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

// Generator yields IP strings sequentially to a channel.
type Generator struct {
	target  string
	exclude string
}

// NewGenerator creates a new IP generator from a target string and an optional exclude string.
func NewGenerator(target string, exclude string) *Generator {
	return &Generator{target: target, exclude: exclude}
}

// Generate streams IP addresses from the target to the returned channel.
// It uses a context for cancellation.
func (g *Generator) Generate(ctx context.Context) (<-chan string, <-chan error) {
	out := make(chan string, 100)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		exclusions := make(map[string]struct{})

		if g.exclude != "" {
			exOut := make(chan string, 100)
			exErrc := make(chan error, 1)

			go func() {
				defer close(exOut)
				defer close(exErrc)
				if g.isFile(g.exclude) {
					g.generateFromFile(ctx, g.exclude, exOut, exErrc)
				} else {
					g.generateFromString(ctx, g.exclude, exOut, exErrc)
				}
			}()

			for ip := range exOut {
				exclusions[ip] = struct{}{}
			}

			// check if there were errors parsing exclusions
			for err := range exErrc {
				if err != nil {
					errc <- fmt.Errorf("exclusion error: %w", err)
					return
				}
			}
		}

		// Channel for the main targets
		mainOut := make(chan string, 100)
		mainErrc := make(chan error, 1)

		go func() {
			defer close(mainOut)
			defer close(mainErrc)
			// Determine target type
			if g.isFile(g.target) {
				g.generateFromFile(ctx, g.target, mainOut, mainErrc)
			} else {
				g.generateFromString(ctx, g.target, mainOut, mainErrc)
			}
		}()

		// Filter IPs through the exclusions map
		for ip := range mainOut {
			if _, excluded := exclusions[ip]; !excluded {
				select {
				case <-ctx.Done():
					return
				case out <- ip:
				}
			}
		}

		// Bubble up main generator errors
		for err := range mainErrc {
			if err != nil {
				errc <- err
			}
		}
	}()

	return out, errc
}

func (g *Generator) isFile(target string) bool {
	info, err := os.Stat(target)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func (g *Generator) generateFromFile(ctx context.Context, filepath string, out chan<- string, errc chan<- error) {
	file, err := os.Open(filepath)
	if err != nil {
		errc <- fmt.Errorf("failed to open file %s: %w", filepath, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Each line could be an IP or a CIDR
		g.generateFromString(ctx, line, out, errc)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}

	if err := scanner.Err(); err != nil {
		errc <- fmt.Errorf("error reading file: %w", err)
	}
}

func (g *Generator) generateFromString(ctx context.Context, target string, out chan<- string, errc chan<- error) {
	if strings.Contains(target, "/") {
		// CIDR
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			errc <- fmt.Errorf("invalid CIDR %s: %w", target, err)
			return
		}

		// IPv4 only for now to keep it simple and efficient, as requested
		if ip.To4() == nil {
			errc <- fmt.Errorf("only IPv4 CIDR is currently supported: %s", target)
			return
		}

		// Calculate start and end IP
		startIP := make(net.IP, len(ipnet.IP))
		copy(startIP, ipnet.IP)

		// End IP is IP | ^Mask
		endIP := make(net.IP, len(startIP))
		for i := 0; i < len(startIP); i++ {
			endIP[i] = startIP[i] | ^ipnet.Mask[i]
		}

		startNum := binary.BigEndian.Uint32(startIP.To4())
		endNum := binary.BigEndian.Uint32(endIP.To4())

		for i := startNum; i <= endNum; i++ {
			select {
			case <-ctx.Done():
				return
			case out <- intToIP(i).String():
			}
		}

	} else {
		// Single IP
		ip := net.ParseIP(target)
		if ip == nil {
			errc <- fmt.Errorf("invalid IP: %s", target)
			return
		}

		if ip.To4() == nil {
			errc <- fmt.Errorf("only IPv4 is currently supported: %s", target)
			return
		}

		select {
		case <-ctx.Done():
			return
		case out <- ip.String():
		}
	}
}

func intToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
