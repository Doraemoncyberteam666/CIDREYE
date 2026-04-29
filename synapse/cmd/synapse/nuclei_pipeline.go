package main

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"synapse/internal/output"
)

type NucleiConfig struct {
	Enabled     bool           `yaml:"enabled"`
	Tags        string         `yaml:"tags"`
	MinSeverity string         `yaml:"min_severity"`
	OutputFile  string         `yaml:"output_file"`
	Telegram    TelegramConfig `yaml:"telegram"`
}

type TelegramConfig struct {
	Enabled       bool          `yaml:"enabled"`
	BotToken      string        `yaml:"bot_token"`
	ChatID        string        `yaml:"chat_id"`
	UploadTimeout time.Duration `yaml:"upload_timeout"`
}

func RunNucleiPipeline(writer *output.Writer, openTargets []string, cfg NucleiConfig) error {
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
		if err := sendToTelegram(cfg.Telegram, outputFile); err != nil {
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

func sendToTelegram(cfg TelegramConfig, filePath string) error {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram enabled but bot token/chat id is missing")
	}
	timeout := cfg.UploadTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
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
		_ = mw.WriteField("chat_id", cfg.ChatID)
		part, err := mw.CreateFormFile("document", filePath)
		if err != nil {
			_ = bodyWriter.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			_ = bodyWriter.CloseWithError(err)
		}
	}()

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", cfg.BotToken)
	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API returned status %s", resp.Status)
	}
	return nil
}
