package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	_ "github.com/go-kivik/kivik/v4/couchdb"
	kivik "github.com/go-kivik/kivik/v4"
)

type Config struct {
	InboxDir    string
	ProcessedDir string
	FailedDir   string
	STTURL      string
	OpenWebUIURL string
	OpenWebUIKey string
	SummarizeModel string
	CouchDBURL  string
	CouchDBDB   string
	VaultFolder string
	AudioLang   string
	MaxRetries  int
	RetryDelay  time.Duration
}

func loadConfig() Config {
	return Config{
		InboxDir:       env("INBOX_DIR", "/inbox"),
		ProcessedDir:   env("PROCESSED_DIR", "/processed"),
		FailedDir:      env("FAILED_DIR", "/failed"),
		STTURL:         env("STT_URL", "http://parakeet-stt:8000/v1/audio/transcriptions"),
		OpenWebUIURL:   env("OPENWEBUI_URL", "http://openwebui:8080/api/chat/completions"),
		OpenWebUIKey:   env("OPENWEBUI_API_KEY", "sk-ollama"),
		SummarizeModel: env("SUMMARIZE_MODEL", "llama3.2:3b"),
		CouchDBURL:     env("COUCHDB_URL", "http://admin:password@couchdb:5984/"),
		CouchDBDB:      env("COUCHDB_DB", "obsidian-vault"),
		VaultFolder:    env("VAULT_FOLDER", "AudioNotes"),
		AudioLang:      env("AUDIO_LANG", "ru"),
		MaxRetries:     3,
		RetryDelay:     10 * time.Second,
	}
}

var audioExts = map[string]bool{
	".mp3": true, ".m4a": true, ".wav": true, ".ogg": true,
	".flac": true, ".webm": true, ".aac": true, ".mp4": true,
}

// --- CouchDB LiveSync Writer ---

type LiveSyncWriter struct {
	db *kivik.DB
}

func NewLiveSyncWriter(ctx context.Context, couchURL, dbName string) (*LiveSyncWriter, error) {
	client, err := kivik.New("couch", couchURL)
	if err != nil {
		return nil, fmt.Errorf("kivik connect: %w", err)
	}

	db := client.DB(dbName)
	if err := db.Err(); err != nil {
		return nil, fmt.Errorf("kivik db %s: %w", dbName, err)
	}

	slog.Info("CouchDB connected", "db", dbName)
	return &LiveSyncWriter{db: db}, nil
}

func genChunkID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "h:" + hex.EncodeToString(b), nil
}

func (w *LiveSyncWriter) WriteNote(ctx context.Context, vaultPath, content string) error {
	docID := strings.ToLower(vaultPath)
	nowMs := time.Now().UnixMilli()

	chunkID, err := genChunkID()
	if err != nil {
		return fmt.Errorf("gen chunk id: %w", err)
	}

	// Write chunk (leaf)
	chunkDoc := map[string]interface{}{
		"data": content,
		"type": "leaf",
	}
	if _, err := w.putDoc(ctx, chunkID, chunkDoc); err != nil {
		return fmt.Errorf("put chunk %s: %w", chunkID, err)
	}
	slog.Info("chunk written", "id", chunkID)

	// Write main document
	mainDoc := map[string]interface{}{
		"children": []string{chunkID},
		"path":     vaultPath,
		"ctime":    nowMs,
		"mtime":    nowMs,
		"size":     len([]byte(content)),
		"type":     "plain",
		"eden":     map[string]interface{}{},
	}
	if _, err := w.putDoc(ctx, docID, mainDoc); err != nil {
		return fmt.Errorf("put doc %s: %w", docID, err)
	}
	slog.Info("document written", "id", docID, "path", vaultPath)
	return nil
}

func (w *LiveSyncWriter) putDoc(ctx context.Context, docID string, doc map[string]interface{}) (string, error) {
	// Check for existing _rev (upsert)
	rev, err := w.db.GetRev(ctx, docID)
	if err == nil && rev != "" {
		doc["_rev"] = rev
	}
	return w.db.Put(ctx, docID, doc)
}

// --- STT Client ---

type STTResponse struct {
	Text string `json:"text"`
}

func transcribe(ctx context.Context, cfg Config, filePath string) (string, error) {
	slog.Info("transcribing", "file", filepath.Base(filePath))

	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open audio: %w", err)
	}
	defer f.Close()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	part, err := w.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", fmt.Errorf("create form: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", fmt.Errorf("copy audio: %w", err)
	}
	_ = w.WriteField("language", cfg.AudioLang)
	w.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", cfg.STTURL, &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("stt request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("stt status %d: %s", resp.StatusCode, body)
	}

	var sttResp STTResponse
	if err := json.NewDecoder(resp.Body).Decode(&sttResp); err != nil {
		return "", fmt.Errorf("stt decode: %w", err)
	}
	if sttResp.Text == "" {
		return "", fmt.Errorf("empty transcript for %s", filepath.Base(filePath))
	}

	slog.Info("transcribed", "chars", len(sttResp.Text))
	return sttResp.Text, nil
}

// --- LLM Summarizer ---

type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Choices []struct {
		Message ChatMessage `json:"message"`
	} `json:"choices"`
}

func summarize(ctx context.Context, cfg Config, transcript string) (string, error) {
	slog.Info("summarizing", "chars", len(transcript))

	payload := ChatRequest{
		Model: cfg.SummarizeModel,
		Messages: []ChatMessage{
			{
				Role: "system",
				Content: "You are a note-taking assistant. " +
					"Create a concise bullet-point summary in Russian. " +
					"Extract key points, decisions, and action items. " +
					"Use markdown formatting.",
			},
			{Role: "user", Content: transcript},
		},
		Stream: false,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cfg.OpenWebUIURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.OpenWebUIKey)

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("llm status %d: %s", resp.StatusCode, respBody)
	}

	var chatResp ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("llm decode: %w", err)
	}
	if len(chatResp.Choices) == 0 || chatResp.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("empty summary")
	}

	summary := chatResp.Choices[0].Message.Content
	slog.Info("summarized", "chars", len(summary))
	return summary, nil
}

// --- Note Builder ---

func buildNote(filename, transcript, summary string) string {
	now := time.Now().Format(time.RFC3339)
	return fmt.Sprintf(`---
date: %s
source: %s
tags: [audio-note, transcription]
type: audio-transcript
---

## Summary

%s

---

## Transcript

%s
`, now, filename, summary, transcript)
}

// --- File Helpers ---

func isAudio(path string) bool {
	return audioExts[strings.ToLower(filepath.Ext(path))]
}

func fileStable(path string) bool {
	var prev int64 = -1
	for i := 0; i < 10; i++ {
		info, err := os.Stat(path)
		if err != nil {
			return false
		}
		if info.Size() == prev && prev > 0 {
			return true
		}
		prev = info.Size()
		time.Sleep(time.Second)
	}
	return false
}

func moveFile(src, dstDir string) error {
	dst := filepath.Join(dstDir, filepath.Base(src))
	if err := os.Rename(src, dst); err != nil {
		// Cross-device fallback
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()
		if _, err := io.Copy(out, in); err != nil {
			return err
		}
		return os.Remove(src)
	}
	return nil
}

// --- Pipeline ---

type Pipeline struct {
	cfg    Config
	writer *LiveSyncWriter
}

func (p *Pipeline) Process(ctx context.Context, filePath string) error {
	slog.Info("pipeline start", "file", filepath.Base(filePath))

	transcript, err := transcribe(ctx, p.cfg, filePath)
	if err != nil {
		return fmt.Errorf("transcribe: %w", err)
	}

	summary, err := summarize(ctx, p.cfg, transcript)
	if err != nil {
		return fmt.Errorf("summarize: %w", err)
	}

	ts := time.Now().Format("20060102_150405")
	stem := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	vaultPath := fmt.Sprintf("%s/%s_%s.md", p.cfg.VaultFolder, ts, stem)

	note := buildNote(filepath.Base(filePath), transcript, summary)

	if err := p.writer.WriteNote(ctx, vaultPath, note); err != nil {
		return fmt.Errorf("couchdb write: %w", err)
	}

	if err := moveFile(filePath, p.cfg.ProcessedDir); err != nil {
		slog.Error("move to processed failed", "err", err)
	}

	slog.Info("pipeline complete", "vault_path", vaultPath)
	return nil
}

func (p *Pipeline) ProcessWithRetry(ctx context.Context, filePath string) {
	for attempt := 1; attempt <= p.cfg.MaxRetries; attempt++ {
		err := p.Process(ctx, filePath)
		if err == nil {
			return
		}
		slog.Error("attempt failed",
			"attempt", attempt,
			"max", p.cfg.MaxRetries,
			"file", filepath.Base(filePath),
			"err", err,
		)
		if attempt < p.cfg.MaxRetries {
			delay := p.cfg.RetryDelay * time.Duration(attempt)
			slog.Info("retrying", "delay", delay)
			time.Sleep(delay)
		}
	}

	slog.Error("all retries exhausted", "file", filepath.Base(filePath))
	if err := moveFile(filePath, p.cfg.FailedDir); err != nil {
		slog.Error("move to failed dir failed", "err", err)
	}
}

// --- Main ---

func main() {
	cfg := loadConfig()

	for _, dir := range []string{cfg.InboxDir, cfg.ProcessedDir, cfg.FailedDir} {
		os.MkdirAll(dir, 0o755)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	writer, err := NewLiveSyncWriter(ctx, cfg.CouchDBURL, cfg.CouchDBDB)
	if err != nil {
		slog.Error("couchdb init failed", "err", err)
		os.Exit(1)
	}

	pipe := &Pipeline{cfg: cfg, writer: writer}

	// Process existing files
	entries, _ := os.ReadDir(cfg.InboxDir)
	for _, e := range entries {
		if e.IsDir() || !isAudio(e.Name()) {
			continue
		}
		pipe.ProcessWithRetry(ctx, filepath.Join(cfg.InboxDir, e.Name()))
	}

	// Watch for new files
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("fsnotify init failed", "err", err)
		os.Exit(1)
	}
	defer watcher.Close()

	if err := watcher.Add(cfg.InboxDir); err != nil {
		slog.Error("watch add failed", "err", err)
		os.Exit(1)
	}

	slog.Info("watching for audio files", "dir", cfg.InboxDir)

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !event.Has(fsnotify.Create) {
				continue
			}
			if !isAudio(event.Name) {
				continue
			}
			if !fileStable(event.Name) {
				slog.Warn("file not stable, skipping", "file", event.Name)
				continue
			}
			go pipe.ProcessWithRetry(ctx, event.Name)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Error("watcher error", "err", err)
		}
	}
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

