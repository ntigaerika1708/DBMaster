// VaultDB Agent — binário único (systemd) que dispara backups via Director API.
//
// Sem dependências externas: compila para um binário estático e portátil.
//
//	go build -o vaultdb-agent .
//	CGO_ENABLED=0 go build -ldflags "-s -w" -o vaultdb-agent .   # binário mínimo
//
// Uso típico (daemon):
//
//	vaultdb-agent -director http://director:8000 -user admin -pass *** \
//	  -conn <connection_id> -db meu_banco -interval 24h
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Version é injetável em build: -ldflags "-X main.Version=1.2.3"
var Version = "1.0.0"

type config struct {
	director    string
	user        string
	pass        string
	token       string
	connID      string
	database    string
	backupType  string
	compression string
	tables      string
	interval    time.Duration
	once        bool
	insecure    bool // reservado para futura verificação TLS custom
	timeout     time.Duration
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func parseFlags() (config, error) {
	var c config
	var interval string
	flag.StringVar(&c.director, "director", envOr("VAULTDB_DIRECTOR", "http://localhost:8000"), "URL do Director API")
	flag.StringVar(&c.user, "user", envOr("VAULTDB_USER", ""), "utilizador (login JWT)")
	flag.StringVar(&c.pass, "pass", envOr("VAULTDB_PASS", ""), "palavra-passe")
	flag.StringVar(&c.token, "token", envOr("VAULTDB_TOKEN", ""), "JWT pré-obtido (alternativa a user/pass)")
	flag.StringVar(&c.connID, "conn", envOr("VAULTDB_CONN", ""), "connection_id alvo")
	flag.StringVar(&c.database, "db", envOr("VAULTDB_DB", ""), "base de dados a salvaguardar")
	flag.StringVar(&c.backupType, "type", envOr("VAULTDB_TYPE", "full"), "tipo de backup: full|incremental")
	flag.StringVar(&c.compression, "compression", envOr("VAULTDB_COMPRESSION", "zstd"), "compressão: zstd|gzip|none")
	flag.StringVar(&c.tables, "tables", envOr("VAULTDB_TABLES", ""), "tabelas separadas por vírgula (vazio = todas)")
	flag.StringVar(&interval, "interval", envOr("VAULTDB_INTERVAL", "24h"), "intervalo entre execuções (ex: 6h, 30m)")
	flag.BoolVar(&c.once, "once", false, "executa um único backup e termina")
	flag.DurationVar(&c.timeout, "timeout", 10*time.Minute, "timeout de cada chamada HTTP")
	showVersion := flag.Bool("version", false, "mostra a versão e termina")
	flag.Parse()

	if *showVersion {
		fmt.Printf("vaultdb-agent %s\n", Version)
		os.Exit(0)
	}

	d, err := time.ParseDuration(interval)
	if err != nil {
		return c, fmt.Errorf("interval inválido %q: %w", interval, err)
	}
	c.interval = d
	c.director = strings.TrimRight(c.director, "/")

	if c.connID == "" || c.database == "" {
		return c, errors.New("são obrigatórios -conn e -db")
	}
	if c.token == "" && (c.user == "" || c.pass == "") {
		return c, errors.New("forneça -token OU -user e -pass")
	}
	return c, nil
}

type client struct {
	cfg   config
	http  *http.Client
	token string
}

func newClient(cfg config) *client {
	return &client{cfg: cfg, http: &http.Client{Timeout: cfg.timeout}, token: cfg.token}
}

func (c *client) login(ctx context.Context) error {
	if c.token != "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"username": c.cfg.user, "password": c.cfg.pass})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.director+"/api/auth/token/json", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login falhou (%d): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("login: resposta inválida: %w", err)
	}
	if out.AccessToken == "" {
		return errors.New("login: token vazio na resposta")
	}
	c.token = out.AccessToken
	return nil
}

func (c *client) triggerBackup(ctx context.Context) (string, error) {
	payload := map[string]any{
		"connection_id": c.cfg.connID,
		"database":      c.cfg.database,
		"backup_type":   c.cfg.backupType,
		"compression":   c.cfg.compression,
	}
	if t := strings.TrimSpace(c.cfg.tables); t != "" {
		parts := strings.Split(t, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		payload["tables"] = parts
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.director+"/api/backups/trigger", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return "", errAuth
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("trigger falhou (%d): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return strings.TrimSpace(string(data)), nil
}

var errAuth = errors.New("não autorizado (token expirado?)")

func (c *client) runOnce(ctx context.Context) error {
	out, err := c.triggerBackup(ctx)
	if errors.Is(err, errAuth) {
		c.token = ""
		if lerr := c.login(ctx); lerr != nil {
			return lerr
		}
		out, err = c.triggerBackup(ctx)
	}
	if err != nil {
		return err
	}
	log.Printf("backup ok: %s", out)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("vaultdb-agent %s — director=%s conn=%s db=%s interval=%s", Version, cfg.director, cfg.connID, cfg.database, cfg.interval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := newClient(cfg)
	if err := c.login(ctx); err != nil {
		log.Fatalf("autenticação: %v", err)
	}

	if cfg.once {
		if err := c.runOnce(ctx); err != nil {
			log.Fatalf("backup: %v", err)
		}
		return
	}

	// Primeira execução imediata, depois no intervalo configurado.
	if err := c.runOnce(ctx); err != nil {
		log.Printf("erro no backup inicial: %v", err)
	}
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("encerrando (sinal recebido)")
			return
		case <-ticker.C:
			if err := c.runOnce(ctx); err != nil {
				log.Printf("erro no backup: %v", err)
			}
		}
	}
}
