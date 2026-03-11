package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
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
	"regexp"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"
	"golang.org/x/crypto/hkdf"

	"github.com/fsnotify/fsnotify"
	_ "github.com/go-kivik/kivik/v4/couchdb"
	kivik "github.com/go-kivik/kivik/v4"
	"golang.org/x/crypto/pbkdf2"
)

// --- Config ---

type Config struct {
	InboxDir      string
	ProcessedDir  string
	FailedDir     string
	STTURL        string
	OpenWebUIURL  string
	OpenWebUIKey  string
	SummarizeModel string
	CouchDBURL    string
	CouchDBDB     string
	VaultFolder   string
	AudioLang     string
	MaxRetries    int
	RetryDelay    time.Duration
	MaxSlugLength int
	
	// Encryption
	EncryptionPassphrase string // Empty = no encryption
	
	// Prompts
	SystemPrompt string
	NoteTemplate string
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
		MaxSlugLength:  40,
		
		// Encryption - if empty, writes unencrypted (for non-E2EE setups)
		EncryptionPassphrase: os.Getenv("ENCRYPTION_PASSPHRASE"),
		
		// Prompts
		SystemPrompt: env("SYSTEM_PROMPT", 
			"You are a note-taking assistant. Create a concise bullet-point summary in Russian. "+
			"Extract key points, decisions, and action items. Use markdown formatting."),
		NoteTemplate: env("NOTE_TEMPLATE", "---\ndate: {{.Date}}\nsource: {{.Source}}\ntags: [audio-note, transcription]\ntype: audio-transcript\n---\n\n## Summary\n\n{{.Summary}}\n\n---\n\n## Transcript\n\n{{.Transcript}}\n"),
	}
}

var audioExts = map[string]bool{
	".mp3": true, ".m4a": true, ".wav": true, ".ogg": true,
	".flac": true, ".webm": true, ".aac": true, ".mp4": true,
}

// --- LiveSync Crypto (E2EE) ---

type LiveSyncCrypto struct {
	passphrase string
}

func NewLiveSyncCrypto(passphrase string) *LiveSyncCrypto {
	if passphrase == "" {
		return nil
	}
	return &LiveSyncCrypto{passphrase: passphrase}
}

func (c *LiveSyncCrypto) deriveKey(salt []byte) []byte {
	return pbkdf2.Key([]byte(c.passphrase), salt, 1000, 32, sha512.New)
}

func (c *LiveSyncCrypto) deriveKeyHKDF(salt []byte) []byte {
	hk := hkdf.New(sha256.New, []byte(c.passphrase), salt, nil)
	key := make([]byte, 32)
	io.ReadFull(hk, key)
	return key
}

func (c *LiveSyncCrypto) encryptChunk(data string) (string, string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	
	key := c.deriveKeyHKDF(salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	
	encrypted := gcm.Seal(nonce, nonce, []byte(data), nil)
	combined := append(salt, encrypted...)
	
	hash := sha256.Sum256(combined)
	chunkID := "h:" + hex.EncodeToString(hash[:])
	
	return chunkID, base64.StdEncoding.EncodeToString(combined), nil
}

// --- Title Extraction ---

func extractTitle(summary string, maxLen int) string {
	lines := strings.Split(summary, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Remove bullet markers
		line = strings.TrimPrefix(line, "-")
		line = strings.TrimPrefix(line, "*")
		line = strings.TrimSpace(line)
		// Remove bold markers
		line = strings.TrimPrefix(line, "**")
		line = strings.TrimSuffix(line, "**")
		line = strings.TrimSpace(line)
		
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Slugify
		slug := strings.ToLower(line)
		slug = regexp.MustCompile(`[^a-z0-9\s-]`).ReplaceAllString(slug, "")
		slug = regexp.MustCompile(`\s+`).ReplaceAllString(slug, "-")
		slug = strings.Trim(slug, "-")
		
		if len(slug) > maxLen {
			// Try to cut at word boundary
			if idx := strings.LastIndex(slug[:maxLen], "-"); idx > 10 {
				slug = slug[:idx]
			} else {
				slug = slug[:maxLen]
			}
		}
		
		if slug != "" {
			return slug
		}
	}
	return "untitled"
}

// --- CouchDB Writer ---

type LiveSyncWriter struct {
	db     *kivik.DB
	crypto *LiveSyncCrypto
}

func NewLiveSyncWriter(ctx context.Context, couchURL, dbName, passphrase string) (*LiveSyncWriter, error) {
	client, err := kivik.New("couch", couchURL)
	if err != nil {
		return nil, fmt.Errorf("kivik connect: %w", err)
	}

	db := client.DB(dbName)
	if err := db.Err(); err != nil {
		return nil, fmt.Errorf("kivik db %s: %w", dbName, err)
	}

	slog.Info("CouchDB connected", "db", dbName, "encrypted", passphrase != "")
	return &LiveSyncWriter{
		db:     db,
		crypto: NewLiveSyncCrypto(passphrase),
	}, nil
}

func (w *LiveSyncWriter) WriteNote(ctx context.Context, vaultPath, content string) error {
	nowMs := time.Now().UnixMilli()
	docID := strings.ToLower(vaultPath)	
	var chunkID string
	var chunkData string
	var err error
	
	if w.crypto != nil {
		chunkID, chunkData, err = w.crypto.encryptChunk(content)
		if err != nil {
			return fmt.Errorf("encrypt chunk: %w", err)
		}
	} else {
		// Unencrypted mode (legacy)
		raw := make([]byte, 16)
		rand.Read(raw)
		chunkID = "h:" + hex.EncodeToString(raw)
		chunkData = content
	}
	
	// Write chunk
	chunkDoc := map[string]interface{}{
		"data": chunkData,
		"type": "leaf",
	}
	if _, err := w.putDoc(ctx, chunkID, chunkDoc); err != nil {
		return fmt.Errorf("put chunk %s: %w", chunkID, err)
	}
	slog.Info("chunk written", "id", chunkID[:20]+"...")
	
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
	slog.Info("document written", "id", docID[:30]+"...", "path", vaultPath)
	return nil
}

func (w *LiveSyncWriter) putDoc(ctx context.Context, docID string, doc map[string]interface{}) (string, error) {
	rev, err := w.db.GetRev(ctx, docID)
	if err == nil && rev != "" {
		doc["_rev"] = rev
	}
	return w.db.Put(ctx, docID, doc)
}

// --- HTTP Clients ---

type STTResponse struct {
	Text string `json:"text"`
}

func transcribe(ctx context.Context, cfg Config, filePath string, client *http.Client) (string, error) {
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

func summarize(ctx context.Context, cfg Config, transcript string, client *http.Client) (string, error) {
	slog.Info("summarizing", "chars", len(transcript))

	payload := ChatRequest{
		Model: cfg.SummarizeModel,
		Messages: []ChatMessage{
			{Role: "system", Content: cfg.SystemPrompt},
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

// --- Note Building ---

type NoteData struct {
	Date       string
	Source     string
	Summary    string
	Transcript string
}

func buildNote(cfg Config, filename, transcript, summary string) (string, error) {
	tmpl, err := template.New("note").Parse(cfg.NoteTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, NoteData{
		Date:       time.Now().Format(time.RFC3339),
		Source:     filename,
		Summary:    summary,
		Transcript: transcript,
	})
	if err != nil {
		return "", fmt.Errorf("exec template: %w", err)
	}
	return buf.String(), nil
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
	cfg        Config
	writer     *LiveSyncWriter
	httpClient *http.Client
}

func NewPipeline(cfg Config, writer *LiveSyncWriter) *Pipeline {
	return &Pipeline{
		cfg:    cfg,
		writer: writer,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (p *Pipeline) Process(ctx context.Context, filePath string) error {
	slog.Info("pipeline start", "file", filepath.Base(filePath))

	// Transcribe
	transcript, err := transcribe(ctx, p.cfg, filePath, p.httpClient)
	if err != nil {
		return fmt.Errorf("transcribe: %w", err)
	}

	// Summarize
	summary, err := summarize(ctx, p.cfg, transcript, p.httpClient)
	if err != nil {
		return fmt.Errorf("summarize: %w", err)
	}

	// Extract title from summary
	title := extractTitle(summary, p.cfg.MaxSlugLength)
	if title == "untitled" {
		title = strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	}

	// Build note
	note, err := buildNote(p.cfg, filepath.Base(filePath), transcript, summary)
	if err != nil {
		return fmt.Errorf("build note: %w", err)
	}

	// Generate vault path with title
	ts := time.Now().Format("20060102_150405")
	vaultPath := fmt.Sprintf("%s/%s_%s.md", p.cfg.VaultFolder, ts, title)

	// Write to CouchDB (encrypted if passphrase set)
	if err := p.writer.WriteNote(ctx, vaultPath, note); err != nil {
		return fmt.Errorf("couchdb write: %w", err)
	}

	// Move to processed
	if err := moveFile(filePath, p.cfg.ProcessedDir); err != nil {
		slog.Error("move to processed failed", "err", err)
	}

	slog.Info("pipeline complete", "vault_path", vaultPath, "title", title)
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

var (
	processing sync.Map
	running    bool = true
)

func main() {
	cfg := loadConfig()

	for _, dir := range []string{cfg.InboxDir, cfg.ProcessedDir, cfg.FailedDir} {
		os.MkdirAll(dir, 0o755)
	}

	// Setup logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Connect to CouchDB with optional encryption
	writer, err := NewLiveSyncWriter(ctx, cfg.CouchDBURL, cfg.CouchDBDB, cfg.EncryptionPassphrase)
	if err != nil {
		slog.Error("couchdb init failed", "err", err)
		os.Exit(1)
	}

	pipe := NewPipeline(cfg, writer)

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

	slog.Info("watching for audio files", "dir", cfg.InboxDir, "encrypted", cfg.EncryptionPassphrase != "")

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
			// Deduplication: skip if already processing
			if _, loaded := processing.LoadOrStore(event.Name, true); loaded {
				slog.Warn("already processing, skipping", "file", event.Name)
				continue
			}
			go func(path string) {
				defer processing.Delete(path)
				pipe.ProcessWithRetry(ctx, path)
			}(event.Name)

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

