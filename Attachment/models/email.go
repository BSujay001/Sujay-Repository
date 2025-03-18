package models

import (
	"time"
)

// Message represents an email message
type Message struct {
	ID          string       `json:"id"`
	Subject     string       `json:"subject"`
	To          string       `json:"to"`
	From        string       `json:"from"`
	FromName    string       `json:"from_name"` // Add sender's name
	Date        string       `json:"date"`
	Body        string       `json:"body"`
	Attachments []Attachment `json:"attachments"`
	//InlineImages []string     `json:"inline_images"`
}

// Attachment represents an email attachment
type Attachment struct {
	Filename string `json:"filename"`
	Path     string `json:"path"`
	MIMEType string `json:"mimeType"`
}

// EmailRecord represents a stored email
type EmailRecord struct {
	Email string `json:"email"`
	Name  string `json:"name"` // Added recipient name field
}

// OTP represents an OTP and its expiration
type OTP struct {
	Code       string    `json:"code"`
	Expiration time.Time `json:"expiration"`
}

// UserSession holds session information for logged-in users
type UserSession struct {
	Name      string    `json:"name"` // Add this field
	Email     string    `json:"email"`
	LoginTime time.Time `json:"login_time"`
}
