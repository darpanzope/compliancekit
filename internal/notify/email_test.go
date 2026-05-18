package notify

import (
	"context"
	"errors"
	"net/smtp"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func TestEmail_NotConfigured(t *testing.T) {
	cases := []EmailConfig{
		{Host: "", From: "a@b.c", To: []string{"x@y.z"}},
		{Host: "smtp", From: "", To: []string{"x@y.z"}},
		{Host: "smtp", From: "a@b.c"}, // empty To
	}
	for i, c := range cases {
		if NewEmail(c).Configured() {
			t.Errorf("case %d: should not be Configured: %+v", i, c)
		}
	}
	full := EmailConfig{Host: "smtp", From: "a@b.c", To: []string{"x@y.z"}}
	if !NewEmail(full).Configured() {
		t.Errorf("full config should be Configured")
	}
}

func TestEmail_PortDefaults(t *testing.T) {
	cases := []struct {
		mode string
		want int
	}{
		{"tls", 465},
		{"starttls", 587},
		{"none", 25},
	}
	for _, c := range cases {
		got := (&EmailConfig{TLSMode: c.mode}).portOrDefault()
		if got != c.want {
			t.Errorf("portOrDefault(%s) = %d, want %d", c.mode, got, c.want)
		}
	}
	if (&EmailConfig{Port: 1025}).portOrDefault() != 1025 {
		t.Errorf("explicit port should override default")
	}
}

func TestEmail_AuthPicker(t *testing.T) {
	if (&EmailConfig{}).auth() != nil {
		t.Errorf("no creds → nil auth")
	}
	a := (&EmailConfig{Username: "u", Password: "p", Host: "smtp.x"}).auth()
	if a == nil {
		t.Errorf("creds set → non-nil auth")
	}
}

func TestEmail_Send_HappyPath(t *testing.T) {
	var captured struct {
		addr string
		from string
		to   []string
		msg  []byte
	}
	cfg := EmailConfig{
		Host:          "smtp.example.com",
		Port:          587,
		From:          "compliance@acme.com",
		To:            []string{"security@acme.com"},
		SeverityFloor: compliancekit.SeverityInfo,
		sendMail: func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
			captured.addr = addr
			captured.from = from
			captured.to = to
			captured.msg = msg
			return nil
		},
	}
	sink := NewEmail(cfg)
	notifications := BuildNotifications([]compliancekit.Finding{
		sampleFinding("aws-s3-public-access-block", "critical"),
	}, BuildOptions{})

	res, err := sink.Send(context.Background(), notifications)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("Sent = %d", res.Sent)
	}
	if captured.addr != "smtp.example.com:587" {
		t.Errorf("addr = %q", captured.addr)
	}
	if captured.from != "compliance@acme.com" || len(captured.to) != 1 {
		t.Errorf("from/to wrong: %s -> %v", captured.from, captured.to)
	}
	msg := string(captured.msg)
	if !strings.Contains(msg, "Subject:") || !strings.Contains(msg, "aws-s3-public-access-block") {
		t.Errorf("missing Subject or CheckID: %q", msg)
	}
	if !strings.Contains(msg, "From: compliance@acme.com") {
		t.Errorf("missing From header: %q", msg)
	}
}

func TestEmail_PerNotificationFailureCounts(t *testing.T) {
	cfg := EmailConfig{
		Host: "smtp", Port: 587, From: "f@x.c", To: []string{"r@x.c"},
		SeverityFloor: compliancekit.SeverityInfo,
		sendMail: func(_ string, _ smtp.Auth, _ string, _ []string, _ []byte) error {
			return errors.New("connection refused")
		},
	}
	sink := NewEmail(cfg)
	notifications := BuildNotifications([]compliancekit.Finding{sampleFinding("x", "critical")}, BuildOptions{})
	res, err := sink.Send(context.Background(), notifications)
	if err == nil {
		t.Errorf("all-fail should return top-level error")
	}
	if res.Errors != 1 {
		t.Errorf("Errors = %d", res.Errors)
	}
}
