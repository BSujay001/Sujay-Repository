package services

import (
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"email-client/config" // 🔁 Replace with your actual module path
	"email-client/models"
)

// SendEmailNewPatientRegistration sends email with new patient details using ALT SMTP

func SendEmailNewPatientRegistration(patientData models.PatientDataModel, recipientEmail, fromName string) error {
	start := time.Now()

	// Load SMTP configuration
	smtpConfig, err := config.LoadSMTPConfig()
	if err != nil {
		return fmt.Errorf("failed to load SMTP config: %w", err)
	}

	// ✅ Append domain if only mobile is passed
	if !strings.Contains(recipientEmail, "@") && len(recipientEmail) >= 10 {
		recipientEmail = recipientEmail + smtpConfig.Domain
	}

	// Format patient data
	patientDataFormatted := models.PatientDataModel{
		PatientName: strings.TrimSpace(patientData.PatientName),
		Email:       strings.TrimSpace(patientData.Email),
		Mobile:      strings.TrimSpace(patientData.Mobile),
		DOB:         strings.TrimSpace(patientData.DOB),
		Gender:      strings.TrimSpace(patientData.Gender),
		DoctorID:    strings.TrimSpace(patientData.DoctorID),
	}

	if fromName == "" {
		fromName = "Doctor"
	}

	// Prepare email body
	emailBody := fmt.Sprintf(`
        <html>
            <body>
                <p>Hello,</p>
                <p>We are pleased to inform you that your registration is complete.</p>
                <p><strong>Patient Information:</strong></p>
                <p>Name: %s</p>
                <p>Email: %s</p>
                <p>Mobile: %s</p>
                <p>DOB: %s</p>
                <p>Gender: %s</p>
            </body>
        </html>`,
		patientDataFormatted.PatientName,
		patientDataFormatted.Email,
		patientDataFormatted.Mobile,
		patientDataFormatted.DOB,
		patientDataFormatted.Gender,
	)

	// Build headers
	message := fmt.Sprintf("From: \"%s\" <%s>\r\n", fromName, patientDataFormatted.DoctorID) +
		fmt.Sprintf("To: %s\r\n", recipientEmail) +
		"Subject: New Patient Registration\r\n" +
		fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)) +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n\r\n" +
		emailBody

	// Send email
	auth := smtp.PlainAuth("", smtpConfig.From, smtpConfig.Password, smtpConfig.SMTPHost_ALT)

	err = smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpConfig.SMTPHost_ALT, smtpConfig.SMTPPort),
		auth,
		smtpConfig.From,
		[]string{recipientEmail},
		[]byte(message),
	)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("✅ Email sent to %s (From: %s <%s>)", recipientEmail, fromName, patientDataFormatted.DoctorID)
	log.Printf("⏱ Total Time: %v ms", time.Since(start).Milliseconds())
	return nil
}
