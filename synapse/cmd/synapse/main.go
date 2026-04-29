package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"synapse/internal/output"
	"synapse/internal/ports"
	"synapse/internal/scanner"
	"synapse/internal/targets"
)

type Config struct {
	Target      string       `yaml:"target"`
	Ports       string       `yaml:"ports"`
	Concurrency int          `yaml:"concurrency"`
	RateLimit   int          `yaml:"rate_limit"`
	TimeoutMs   int          `yaml:"timeout_ms"`
	Output      string       `yaml:"output"`
	JSON        bool         `yaml:"json"`
	Quiet       bool         `yaml:"quiet"`
	Banner      bool         `yaml:"banner"`
	Exclude     string       `yaml:"exclude"`
	Retries     int          `yaml:"retries"`
	Progress    bool         `yaml:"progress"`
	Nuclei      NucleiConfig `yaml:"nuclei"`
}

type NucleiConfig struct {
	Enabled     bool           `yaml:"enabled"`
	Tags        string         `yaml:"tags"`
	MinSeverity string         `yaml:"min_severity"`
	OutputFile  string         `yaml:"output_file"`
	Telegram    TelegramConfig `yaml:"telegram"`
}

type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

func main() {
	var (
		configFile        string
		targetFlag        string
		portsFlag         string
		concFlag          int
		rateFlag          int
		timeFlag          int
		outFlag           string
		jsonFlag          bool
		quietFlag         bool
		bannerFlag        bool
		excludeFlag       string
		retriesFlag       int
		progFlag          bool
		nucleiFlag        bool
		nucleiTags        string
		nucleiMinSeverity string
		nucleiOutput      string
		telegramFlag      bool
		telegramToken     string
		telegramChatID    string
	)

	flag.StringVar(&configFile, "config", "", "Path to YAML config file")
	flag.StringVar(&targetFlag, "t", "", "Target IP, CIDR, or file (alias for --target)")
	flag.StringVar(&targetFlag, "target", "", "Target IP, CIDR, or file")
	flag.StringVar(&portsFlag, "p", "", "Ports to scan e.g., 80,443,1-1000 (alias for --ports)")
	flag.StringVar(&portsFlag, "ports", "", "Ports to scan e.g., 80,443,1-1000")
	flag.IntVar(&concFlag, "c", 1000, "Concurrency level (alias for --concurrency)")
	flag.IntVar(&concFlag, "concurrency", 1000, "Concurrency level")
	flag.IntVar(&rateFlag, "r", 0, "Rate limit in connections/sec (0 = unlimited) (alias for --rate)")
	flag.IntVar(&rateFlag, "rate", 0, "Rate limit in connections/sec (0 = unlimited)")
	flag.IntVar(&timeFlag, "timeout", 1000, "Timeout in milliseconds")
	flag.StringVar(&outFlag, "o", "", "Output file (alias for --output)")
	flag.StringVar(&outFlag, "output", "", "Output file")
	flag.BoolVar(&jsonFlag, "json", false, "Output in JSON format")
	flag.BoolVar(&quietFlag, "quiet", false, "Quiet mode (only print results)")
	flag.BoolVar(&bannerFlag, "banner", false, "Enable banner grabbing")
	flag.StringVar(&excludeFlag, "e", "", "IPs, CIDRs, or file containing targets to exclude (alias for --exclude)")
	flag.StringVar(&excludeFlag, "exclude", "", "IPs, CIDRs, or file containing targets to exclude")
	flag.IntVar(&retriesFlag, "retries", 0, "Number of retries for port scan")
	flag.BoolVar(&progFlag, "progress", false, "Print periodic progress updates")
	flag.BoolVar(&nucleiFlag, "nuclei", false, "Enable optional nuclei post-scan pipeline with automatic technology detection")
	flag.StringVar(&nucleiTags, "nuclei-tags", "", "Comma-separated nuclei tags filter")
	flag.StringVar(&nucleiMinSeverity, "nuclei-min-severity", "", "Minimum nuclei severity (info|low|medium|high|critical)")
	flag.StringVar(&nucleiOutput, "nuclei-output", "", "Nuclei output text file")
	flag.BoolVar(&telegramFlag, "telegram", false, "Send nuclei output to Telegram")
	flag.StringVar(&telegramToken, "telegram-token", "", "Telegram bot token")
	flag.StringVar(&telegramChatID, "telegram-chat-id", "", "Telegram chat ID")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SYNapse - High-performance userland TCP scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// Default config
	cfg := Config{
		Concurrency: concFlag,
		RateLimit:   rateFlag,
		TimeoutMs:   timeFlag,
		JSON:        jsonFlag,
		Quiet:       quietFlag,
		Banner:      bannerFlag,
		Retries:     retriesFlag,
		Progress:    progFlag,
	}

	// Load from YAML if provided
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config file: %v\n", err)
			os.Exit(1)
		}
	}

	// Override with CLI flags if provided
	if targetFlag != "" {
		cfg.Target = targetFlag
	}
	if portsFlag != "" {
		cfg.Ports = portsFlag
	}
	if outFlag != "" {
		cfg.Output = outFlag
	}
	if excludeFlag != "" {
		cfg.Exclude = excludeFlag
	}
	// Note: for integers/bools, typical CLI tools assume if flag > 0 or == true, we override config file.
	// We'll keep it simple: CLI defaults apply if config file didn't overwrite.
	if retriesFlag > 0 {
		cfg.Retries = retriesFlag
	}
	if progFlag {
		cfg.Progress = progFlag
	}
	if nucleiFlag {
		cfg.Nuclei.Enabled = nucleiFlag
	}
	if nucleiTags != "" {
		cfg.Nuclei.Tags = nucleiTags
	}
	if nucleiMinSeverity != "" {
		cfg.Nuclei.MinSeverity = nucleiMinSeverity
	}
	if nucleiOutput != "" {
		cfg.Nuclei.OutputFile = nucleiOutput
	}
	if telegramFlag {
		cfg.Nuclei.Telegram.Enabled = telegramFlag
	}
	if telegramToken != "" {
		cfg.Nuclei.Telegram.BotToken = telegramToken
	}
	if telegramChatID != "" {
		cfg.Nuclei.Telegram.ChatID = telegramChatID
	}

	// Check required fields
	if cfg.Target == "" {
		fmt.Fprintln(os.Stderr, "Error: Target is required (-t, --target, or config file)")
		flag.Usage()
		os.Exit(1)
	}

	if cfg.Ports == "" {
		fmt.Fprintln(os.Stderr, "Error: Ports are required (-p, --ports, or config file)")
		flag.Usage()
		os.Exit(1)
	}

	// Setup Output Writer
	writer, err := output.NewWriter(cfg.Output, cfg.JSON, cfg.Quiet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up output: %v\n", err)
		os.Exit(1)
	}
	defer writer.Close()

	if !cfg.Quiet {
		writer.Log("SYNapse Scanner starting...")
		writer.Log("Target: %s", cfg.Target)
		if cfg.Exclude != "" {
			writer.Log("Exclude: %s", cfg.Exclude)
		}
		writer.Log("Ports: %s", cfg.Ports)
		writer.Log("Concurrency: %d", cfg.Concurrency)
		writer.Log("Retries: %d", cfg.Retries)
	}

	// Parse Ports
	parsedPorts, err := ports.Parse(cfg.Ports)
	if err != nil {
		writer.Log("Error parsing ports: %v", err)
		os.Exit(1)
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		writer.Log("\nInterrupt received, shutting down...")
		cancel()
	}()

	// Setup Target Generator
	targetGen := targets.NewGenerator(cfg.Target, cfg.Exclude)
	ipsCh, errCh := targetGen.Generate(ctx)

	go func() {
		for err := range errCh {
			if err != nil {
				writer.Log("Target generation error: %v", err)
			}
		}
	}()

	// Configure and Run Scanner
	scanCfg := scanner.Config{
		Concurrency: cfg.Concurrency,
		RateLimit:   cfg.RateLimit,
		Timeout:     time.Duration(cfg.TimeoutMs) * time.Millisecond,
		Banner:      cfg.Banner,
		Retries:     cfg.Retries,
		Progress:    cfg.Progress,
	}

	sc := scanner.New(scanCfg, writer)

	startTime := time.Now()
	if err := sc.Run(ctx, ipsCh, parsedPorts); err != nil {
		writer.Log("Scanner error: %v", err)
	}

	if !cfg.Quiet {
		writer.Log("Scan completed in %v", time.Since(startTime))
	}

	if cfg.Nuclei.Enabled {
		if err := runNucleiPipeline(writer, sc.OpenTargets(), cfg.Nuclei); err != nil {
			writer.Log("Nuclei pipeline error: %v", err)
			os.Exit(1)
		}
	}
}

func runNucleiPipeline(writer *output.Writer, openTargets []string, cfg NucleiConfig) error {
	if len(openTargets) == 0 {
		writer.Log("Nuclei pipeline enabled, but no open ports found. Skipping.")
		return nil
	}

	minSeverity := normalizeSeverity(cfg.MinSeverity)
	if minSeverity == "" {
		minSeverity = "high"
	}

	targetsFile, err := os.CreateTemp("", "synapse-open-targets-*.txt")
	if err != nil {
		return fmt.Errorf("create nuclei targets file: %w", err)
	}
	defer os.Remove(targetsFile.Name())
	defer targetsFile.Close()

	for _, t := range openTargets {
		if _, err := targetsFile.WriteString(t + "\n"); err != nil {
			return fmt.Errorf("write nuclei targets: %w", err)
		}
	}

	outputFile := cfg.OutputFile
	if outputFile == "" {
		outputFile = "nuclei-results.txt"
	}

	args := []string{"-l", targetsFile.Name(), "-as", "-severity", severityFilter(minSeverity), "-o", outputFile}
	if cfg.Tags != "" {
		args = append(args, "-tags", cfg.Tags)
	}

	writer.Log("Running nuclei with automatic technology detection (-as)...")
	cmd := exec.Command("nuclei", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run nuclei: %w", err)
	}

	if cfg.Telegram.Enabled {
		if err := sendToTelegram(cfg.Telegram.BotToken, cfg.Telegram.ChatID, outputFile); err != nil {
			return fmt.Errorf("telegram send failed: %w", err)
		}
		writer.Log("Nuclei output sent to Telegram chat %s", cfg.Telegram.ChatID)
	}
	return nil
}

func normalizeSeverity(sev string) string {
	s := strings.ToLower(strings.TrimSpace(sev))
	switch s {
	case "info", "low", "medium", "high", "critical":
		return s
	default:
		return ""
	}
}

func severityFilter(minSeverity string) string {
	all := []string{"info", "low", "medium", "high", "critical"}
	idx := slices.Index(all, minSeverity)
	if idx == -1 {
		idx = 3
	}
	return strings.Join(all[idx:], ",")
}

func sendToTelegram(botToken, chatID, filePath string) error {
	if botToken == "" || chatID == "" {
		return fmt.Errorf("telegram enabled but bot token/chat id is missing")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	bodyReader, bodyWriter := io.Pipe()
	mw := multipart.NewWriter(bodyWriter)

	go func() {
		defer bodyWriter.Close()
		defer mw.Close()
		_ = mw.WriteField("chat_id", chatID)
		part, err := mw.CreateFormFile("document", filePath)
		if err != nil {
			_ = bodyWriter.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			_ = bodyWriter.CloseWithError(err)
		}
	}()

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botToken)
	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API returned status %s", resp.Status)
	}
	return nil
}
