package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strings"
)

func SendContact(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	if smtpUser == "" || smtpPass == "" {
		jsonError(w, "Contact form not configured", http.StatusServiceUnavailable)
		return
	}

	to := "wonabru@gmail.com"
	subject := fmt.Sprintf("[QWID Contact] %s", req.Subject)
	if req.Subject == "" {
		subject = "[QWID Contact] New message"
	}
	body := fmt.Sprintf("From: %s <%s>\r\nSubject: %s\r\n\r\n%s", req.Name, req.Email, subject, req.Message)
	msg := []byte("To: " + to + "\r\n" +
		"From: " + smtpUser + "\r\n" +
		"Reply-To: " + req.Email + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body)

	auth := smtp.PlainAuth("", smtpUser, smtpPass, "smtp.gmail.com")
	if err := smtp.SendMail("smtp.gmail.com:587", auth, smtpUser, []string{to}, msg); err != nil {
		jsonError(w, "Failed to send message", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"success": "true"})
}
