package services

import (
	"crypto/tls"
	"email-client/config"
	"fmt"
	"log"
	"strconv"
	"time"

	"gopkg.in/gomail.v2"
)

// SendEmail sends an OTP email and tracks execution time
const (
	SubjectTemplate = "Noreply: Vault access OTP"
	BodyTemplate    = `Dear %s,

OTP: %s

Please do not share this with anyone.

For any clarification, please feel free to call us at 9920130363.

Thanking You,
Vault Helpdesk.`
)

// SendEmail sends an OTP email using SMTP
// getSMTPTDialer initializes & reuses the SMTP dialer
func getSMTPDialer() (*gomail.Dialer, error) {
	smtpConfig, err := config.LoadSMTPConfig()
	if err != nil {
		return nil, fmt.Errorf("SMTP config error: %w", err)
	}

	smtpPort, err := strconv.Atoi(smtpConfig.SMTPPort)
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP port: %w", err)
	}

	dialer := gomail.NewDialer(smtpConfig.SMTPHost, smtpPort, smtpConfig.From, smtpConfig.Password)
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: smtpConfig.SMTPSecurity == "false"}

	return dialer, nil
}

func SendEmail(otp, recipient, fromName string) error {
	startTime := time.Now()

	dialer, err := getSMTPDialer()
	if err != nil {
		return fmt.Errorf("failed to initialize SMTP dialer: %w", err)
	}

	dialStart := time.Now()
	conn, err := dialer.Dial()
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	log.Printf("🔌 SMTP Dial time: %v ms", time.Since(dialStart).Milliseconds())
	defer conn.Close()

	smtpConfig, _ := config.LoadSMTPConfig()

	message := gomail.NewMessage()
	message.SetHeader("From", smtpConfig.From)
	message.SetHeader("To", recipient)
	message.SetHeader("Subject", SubjectTemplate)
	message.SetBody("text/plain", fmt.Sprintf(BodyTemplate, fromName, otp)) // 👈 Dear fromName

	sendStart := time.Now()
	if err := gomail.Send(conn, message); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	log.Printf("✅ Email sent to %s in %v ms", recipient, time.Since(sendStart).Milliseconds())
	log.Printf("📬 Total SendEmail time: %v ms", time.Since(startTime).Milliseconds())

	return nil
}
