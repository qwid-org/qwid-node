package handlers

import (
	"strings"
	"testing"
)

// The contact form used to post through smtp.gmail.com to a hard-coded
// personal address, and put SMTP_USER into the From: header. That breaks on
// SES, where SMTP_USER is an IAM credential such as AKIAIOSFODNN7EXAMPLE and
// the sender must be an identity SES has verified.

func TestContactMailConfigDefaultsToSES(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_PORT", "")
	t.Setenv("CONTACT_TO", "")
	t.Setenv("CONTACT_FROM", "")

	cfg := contactMailConfig()

	if strings.Contains(cfg.Host, "gmail") {
		t.Fatalf("default host still points at Gmail: %q", cfg.Host)
	}
	// Pinned to the region SES actually runs in for this domain: its MX points
	// at inbound-smtp.us-east-1.amazonaws.com. SES SMTP credentials are
	// region-scoped, so a default pointing anywhere else fails to authenticate.
	if cfg.Host != "email-smtp.us-east-1.amazonaws.com" {
		t.Fatalf("default host = %q, want the us-east-1 SES endpoint", cfg.Host)
	}
	if cfg.Addr() != cfg.Host+":587" {
		t.Fatalf("Addr() = %q, want host:587", cfg.Addr())
	}
	if cfg.To != "support@qwid.org" {
		t.Fatalf("default recipient = %q, want support@qwid.org", cfg.To)
	}
	if cfg.From != "support@qwid.org" {
		t.Fatalf("default sender = %q, want support@qwid.org", cfg.From)
	}
}

func TestContactMailConfigHonoursEnvironment(t *testing.T) {
	t.Setenv("SMTP_HOST", "email-smtp.eu-west-1.amazonaws.com")
	t.Setenv("SMTP_PORT", "2587")
	t.Setenv("CONTACT_TO", "hello@example.org")
	t.Setenv("CONTACT_FROM", "noreply@example.org")

	cfg := contactMailConfig()

	if cfg.Addr() != "email-smtp.eu-west-1.amazonaws.com:2587" {
		t.Fatalf("Addr() = %q", cfg.Addr())
	}
	if cfg.To != "hello@example.org" || cfg.From != "noreply@example.org" {
		t.Fatalf("addresses not taken from environment: to=%q from=%q", cfg.To, cfg.From)
	}
}

// SES rejects a message whose From: is not a verified identity. The visitor's
// own address must therefore travel in Reply-To, never in From.
func TestBuildContactMessageSendsFromVerifiedIdentity(t *testing.T) {
	cfg := mailConfig{
		Host: "email-smtp.eu-central-1.amazonaws.com",
		Port: "587",
		To:   "support@qwid.org",
		From: "support@qwid.org",
	}

	msg := string(buildContactMessage(cfg, "Ada Lovelace", "ada@example.com",
		"Question", "Does the delay rule survive a restart?"))

	header, body, found := strings.Cut(msg, "\r\n\r\n")
	if !found {
		t.Fatal("message has no header/body separator")
	}

	if !strings.Contains(header, "From: support@qwid.org\r\n") {
		t.Errorf("From: is not the verified identity\n%s", header)
	}
	if strings.Contains(header, "From: ada@example.com") {
		t.Errorf("visitor address used as From:, SES would reject this\n%s", header)
	}
	if !strings.Contains(header, "Reply-To: ada@example.com\r\n") {
		t.Errorf("visitor address missing from Reply-To:\n%s", header)
	}
	if !strings.Contains(header, "To: support@qwid.org\r\n") {
		t.Errorf("wrong recipient\n%s", header)
	}
	if strings.Contains(msg, "wonabru@gmail.com") {
		t.Error("message still routed to the hard-coded personal address")
	}
	if !strings.Contains(header, "Subject: [QWID Contact] Question\r\n") {
		t.Errorf("subject not prefixed\n%s", header)
	}
	// The sender's name and address belong in the body so the reader can see
	// who wrote in even if Reply-To is stripped somewhere along the way.
	if !strings.Contains(body, "Ada Lovelace") || !strings.Contains(body, "ada@example.com") {
		t.Errorf("body does not identify the sender\n%s", body)
	}
	if !strings.Contains(body, "Does the delay rule survive a restart?") {
		t.Errorf("body does not carry the message\n%s", body)
	}
}

func TestBuildContactMessageWithoutSubject(t *testing.T) {
	cfg := mailConfig{To: "support@qwid.org", From: "support@qwid.org"}

	msg := string(buildContactMessage(cfg, "Ada", "ada@example.com", "", "hi"))

	if !strings.Contains(msg, "Subject: [QWID Contact] New message\r\n") {
		t.Errorf("empty subject not replaced with a default\n%s", msg)
	}
}
