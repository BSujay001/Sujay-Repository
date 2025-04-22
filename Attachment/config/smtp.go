package config

import (
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

// SMTPConfig holds SMTP configuration
type SMTPConfig struct {
	From         string
	Password     string
	SMTPHost_ALT string
	SMTPHost     string
	SMTPPort     string
	SMTPSecurity string
	Domain       string
}

var (
	smtpConfig *SMTPConfig // Global SMTPConfig instance
	once       sync.Once   // Ensures config loads only once
)

// LoadSMTPConfig loads SMTP environment variables ONCE and caches them
func LoadSMTPConfig() (*SMTPConfig, error) {
	var err error
	once.Do(func() {
		startTime := time.Now() // ⏱ Start measuring time

		// ✅ Load environment variables once
		if err := godotenv.Load(); err != nil {
			log.Println("⚠️ Warning: .env file not found, using system environment variables")
		}

		// ✅ Assign values from environment
		smtpConfig = &SMTPConfig{
			From:         os.Getenv("SMTP_EMAIL"),
			Password:     os.Getenv("SMTP_PASSWORD"),
			SMTPHost_ALT: os.Getenv("SMTP_HOST_ALT"),
			SMTPHost:     os.Getenv("SMTP_HOST"),
			SMTPPort:     os.Getenv("SMTP_PORT"),
			SMTPSecurity: os.Getenv("SMTP_SECURITY"),
			Domain:       os.Getenv("DOMAIN"),
		}

		// ✅ Validate required fields
		missingFields := checkMissingFields(smtpConfig)
		if len(missingFields) > 0 {
			err = errors.New("❌ Missing required SMTP config fields: " + missingFields)
			smtpConfig = nil // Reset config
			return
		}

		// ⏱ Log execution time
		log.Printf("✅ SMTP Configuration Loaded Successfully in %v ms", time.Since(startTime).Milliseconds())
	})

	return smtpConfig, err
}

// checkMissingFields returns a comma-separated string of missing fields
func checkMissingFields(config *SMTPConfig) string {
	missing := []string{}
	if config.From == "" {
		missing = append(missing, "SMTP_EMAIL")
	}
	if config.Password == "" {
		missing = append(missing, "SMTP_PASSWORD")
	}
	if config.SMTPHost == "" {
		missing = append(missing, "SMTP_HOST")
	}
	if config.SMTPPort == "" {
		missing = append(missing, "SMTP_PORT")
	}

	if len(missing) == 0 {
		return ""
	}
	return "❌ " + strings.Join(missing, ", ")
}
