package notify

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"

	"github.com/darpanzope/compliancekit/internal/core"
)

// EmailConfig configures the SMTP sink. Supports three TLS modes:
//
//   - "starttls" (default for port 587) — connect plain, upgrade
//     via STARTTLS before AUTH.
//   - "tls" (default for port 465) — connect TLS immediately
//     (implicit TLS / "SMTPS").
//   - "none" — plaintext, AUTH optional. Only safe inside trusted
//     networks (Postfix on localhost, milter sidecar).
//
// Env: SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
// SMTP_FROM, SMTP_TO (comma-separated), SMTP_TLS (starttls|tls|none),
// SMTP_THRESHOLD.
type EmailConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	From       string
	To         []string
	TLSMode    string // starttls | tls | none
	SkipVerify bool   // disable cert verification — test/dev only

	SeverityFloor core.Severity

	// sendMail overrides the actual send call. Tests inject a stub
	// so they don't need a live SMTP server.
	sendMail func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
}

// Email implements Notifier for SMTP delivery.
type Email struct{ cfg EmailConfig }

// NewEmail constructs an Email sink.
func NewEmail(cfg EmailConfig) *Email {
	if cfg.TLSMode == "" {
		switch cfg.Port {
		case 465:
			cfg.TLSMode = "tls"
		case 25, 587, 0:
			cfg.TLSMode = "starttls"
		}
	}
	if cfg.sendMail == nil {
		cfg.sendMail = smtp.SendMail
	}
	return &Email{cfg: cfg}
}

// Name implements Notifier.
func (e *Email) Name() string { return "email" }

// Configured returns true when host + from + at least one recipient
// are present. Username/password are optional; some operators run
// authenticated relays, others run unauthenticated relays inside
// trusted networks.
func (e *Email) Configured() bool {
	return e.cfg.Host != "" && e.cfg.From != "" && len(e.cfg.To) > 0
}

// Threshold returns the per-sink severity floor.
func (e *Email) Threshold() core.Severity { return e.cfg.SeverityFloor }

// Send dispatches the notifications. One message per notification —
// keeps subject lines targeted and lets recipients filter per check.
func (e *Email) Send(_ context.Context, notifications []Notification) (Result, error) {
	var res Result
	addr := net.JoinHostPort(e.cfg.Host, strconv.Itoa(e.cfg.portOrDefault()))
	auth := e.cfg.auth()
	for _, n := range notifications {
		msg := e.buildMessage(n)
		if err := e.cfg.sendMail(addr, auth, e.cfg.From, e.cfg.To, msg); err != nil {
			res.Errors++
			res.Messages = append(res.Messages, fmt.Sprintf("email: %s — %v", n.Finding.CheckID, err))
			continue
		}
		res.Sent++
		res.Messages = append(res.Messages, fmt.Sprintf("email: %s — sent", n.Finding.CheckID))
	}
	if res.Sent == 0 && res.Errors > 0 {
		return res, fmt.Errorf("email: all %d sends failed", res.Errors)
	}
	return res, nil
}

// buildMessage assembles the RFC 5322 message. Multipart MIME with a
// text/plain part (the rendered body verbatim) — no HTML in v0.17;
// CommonMark renders cleanly in plain text and HTML email templating
// is a v0.18+ enhancement if anyone asks.
func (e *Email) buildMessage(n Notification) []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, "From: %s\r\n", e.cfg.From)
	fmt.Fprintf(&sb, "To: %s\r\n", strings.Join(e.cfg.To, ", "))
	fmt.Fprintf(&sb, "Subject: %s\r\n", n.Title)
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(n.Body)
	if n.URL != "" {
		fmt.Fprintf(&sb, "\r\nDetails: %s\r\n", n.URL)
	}
	return []byte(sb.String())
}

// auth returns the appropriate SMTP auth based on whether
// Username/Password are set. PLAIN over STARTTLS/TLS is the
// canonical authenticated path; no creds → nil (relay path).
func (e *EmailConfig) auth() smtp.Auth {
	if e.Username == "" || e.Password == "" {
		return nil
	}
	return smtp.PlainAuth("", e.Username, e.Password, e.Host)
}

// portOrDefault picks a sensible default port from the TLS mode
// when none is explicitly configured.
func (e *EmailConfig) portOrDefault() int {
	if e.Port != 0 {
		return e.Port
	}
	switch e.TLSMode {
	case "tls":
		return 465
	case "starttls":
		return 587
	}
	return 25
}

// init registers the sink with env-driven config.
func init() {
	cfg := EmailConfig{
		Host:     os.Getenv("SMTP_HOST"),
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     os.Getenv("SMTP_FROM"),
		TLSMode:  os.Getenv("SMTP_TLS"),
	}
	if p := os.Getenv("SMTP_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			cfg.Port = n
		}
	}
	if to := os.Getenv("SMTP_TO"); to != "" {
		for _, r := range strings.Split(to, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				cfg.To = append(cfg.To, r)
			}
		}
	}
	if t := os.Getenv("SMTP_THRESHOLD"); t != "" {
		if sev, err := core.ParseSeverity(t); err == nil {
			cfg.SeverityFloor = sev
		}
	}
	Register(NewEmail(cfg))
}
