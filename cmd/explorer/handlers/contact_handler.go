package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strings"
)

// Size limits for the contact form. The rate limit in cmd/explorer/ratelimit.go
// bounds how often a client may submit; these bound how large one submission
// may be.
const (
	maxContactBody    = 64 * 1024
	maxContactName    = 200
	maxContactEmail   = 320 // RFC 5321 maximum path length
	maxContactSubject = 300
	maxContactMessage = 10000
)

// mailConfig is where the contact form posts. Amazon SES rather than Gmail:
// the domain already sends through SES (its SPF record is
// "v=spf1 include:amazonses.com ~all"), and relaying visitor messages through
// Gmail put Google in the path of personal data for no reason the privacy
// notice could justify.
type mailConfig struct {
	Host string
	Port string
	To   string
	From string
}

func (c mailConfig) Addr() string { return c.Host + ":" + c.Port }

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// contactMailConfig resolves the mail settings, defaulting to the SES endpoint
// in the region this node runs in. Override SMTP_HOST when deploying elsewhere
// — an SES SMTP endpoint is region-specific and credentials are not portable
// between regions.
func contactMailConfig() mailConfig {
	return mailConfig{
		Host: envOr("SMTP_HOST", "email-smtp.us-east-1.amazonaws.com"),
		Port: envOr("SMTP_PORT", "587"),
		To:   envOr("CONTACT_TO", "support@qwid.org"),
		From: envOr("CONTACT_FROM", "support@qwid.org"),
	}
}

// buildContactMessage assembles the RFC 5322 message.
//
// From: must be an identity SES has verified, so it is cfg.From and never the
// visitor's address — SES rejects the message otherwise, and sending as an
// arbitrary third party would be spoofing in any case. The visitor's address
// goes in Reply-To, so replying still reaches them, and is repeated in the
// body in case a client drops Reply-To.
//
// Callers must reject CR/LF in name, email and subject before calling this;
// SendContact does that (WH-H7). Otherwise a crafted field would inject extra
// headers here.
func buildContactMessage(cfg mailConfig, name, email, subject, message string) []byte {
	displaySubject := "[QWID Contact] New message"
	if subject != "" {
		displaySubject = "[QWID Contact] " + subject
	}
	body := fmt.Sprintf("From: %s <%s>\r\n\r\n%s", name, email, message)
	return []byte("To: " + cfg.To + "\r\n" +
		"From: " + cfg.From + "\r\n" +
		"Reply-To: " + email + "\r\n" +
		"Subject: " + displaySubject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body)
}

func SendContact(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Cap the request body before decoding it. Without this the decoder will
	// read whatever is sent, so a single POST could allocate arbitrary memory
	// and, if it got past validation, hand SES a message of that size.
	r.Body = http.MaxBytesReader(w, r.Body, maxContactBody)

	var req struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		Subject string `json:"subject"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Subject = strings.TrimSpace(req.Subject)
	req.Message = strings.TrimSpace(req.Message)

	if req.Name == "" || req.Email == "" || req.Message == "" {
		jsonError(w, "Name, email and message are required", http.StatusBadRequest)
		return
	}
	if !strings.Contains(req.Email, "@") {
		jsonError(w, "Invalid email address", http.StatusBadRequest)
		return
	}
	// WH-H7: reject CR/LF in fields that are placed into email headers, to
	// prevent SMTP header injection (e.g. adding Bcc: to relay spam).
	if strings.ContainsAny(req.Email, "\r\n") || strings.ContainsAny(req.Subject, "\r\n") ||
		strings.ContainsAny(req.Name, "\r\n") {
		jsonError(w, "Invalid characters in input", http.StatusBadRequest)
		return
	}
	// Bound each field independently of the body cap. A message within the
	// size limit can still carry a header line long enough to be mangled or
	// rejected downstream, and there is no legitimate 60 KB subject line.
	if len(req.Name) > maxContactName || len(req.Email) > maxContactEmail ||
		len(req.Subject) > maxContactSubject || len(req.Message) > maxContactMessage {
		jsonError(w, "Input too long", http.StatusBadRequest)
		return
	}

	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	if smtpUser == "" || smtpPass == "" {
		jsonError(w, "Contact form not configured", http.StatusServiceUnavailable)
		return
	}

	cfg := contactMailConfig()
	msg := buildContactMessage(cfg, req.Name, req.Email, req.Subject, req.Message)

	// The envelope sender is cfg.From, not smtpUser: with SES the username is
	// an IAM credential, and SES requires the envelope sender to be a verified
	// identity.
	auth := smtp.PlainAuth("", smtpUser, smtpPass, cfg.Host)
	if err := smtp.SendMail(cfg.Addr(), auth, cfg.From, []string{cfg.To}, msg); err != nil {
		jsonError(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"success": "true"})
}
