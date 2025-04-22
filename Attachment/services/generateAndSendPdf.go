package services

import (
	"bytes"
	"email-client/config"
	"email-client/models"

	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func GeneratePDFAndSendEmail(opdData models.OpdModel, recipientEmail, loggedInEmail, fromName string) error {
	// Step 1: Load Typst template
	templateData, err := os.ReadFile("templates/template.typ")
	if err != nil {
		return fmt.Errorf("failed to read template file: %w", err)
	}

	// Step 2: Skip if follow-up date is missing
	if strings.TrimSpace(opdData.FollowupDate) == "" {
		log.Println("Follow-up date/time is empty — skipping PDF generation")
		return nil
	}

	// Step 3: Replace placeholders in the template
	replacements := map[string]string{
		"#patientname":  opdData.PatientName,
		"#drname":       opdData.DoctorName,
		"#opddate":      opdData.OPDDate,
		"#opdnotes":     opdData.OPDNotes,
		"#prescription": opdData.Prescription,
		"#followupdate": opdData.FollowupDate,
		"#createdon":    opdData.CreatedOn,
	}
	typstContent := string(templateData)
	for key, value := range replacements {
		typstContent = strings.ReplaceAll(typstContent, key, value)
	}

	// Step 4: Write temporary Typst file
	safePatientName := strings.ReplaceAll(opdData.PatientName, " ", "_")
	tempTypFile := fmt.Sprintf("attachments/%s-opd.typ", safePatientName)
	if err := os.WriteFile(tempTypFile, []byte(typstContent), 0644); err != nil {
		return fmt.Errorf("failed to write Typst file: %w", err)
	}
	defer os.Remove(tempTypFile)

	// Step 5: Generate PDF using typst CLI
	pdfFileName := fmt.Sprintf("OPD_%s.pdf", safePatientName)
	pdfFilePath := filepath.Join("attachments", pdfFileName)
	cmd := exec.Command("typst", "compile", tempTypFile, pdfFilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("PDF generation failed: %v\nOutput: %s", err, output)
	}
	log.Println("✅ PDF generated:", pdfFilePath)

	// Step 6: Confirm PDF file exists
	info, err := os.Stat(pdfFilePath)
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("generated PDF file missing or empty at %s", pdfFilePath)
	}
	defer os.Remove(pdfFilePath)

	// Step 7: Read PDF content
	pdfContent, err := os.ReadFile(pdfFilePath)
	if err != nil {
		return fmt.Errorf("failed to read generated PDF: %w", err)
	}

	// Step 8: Send email with PDF attachment (just call the function directly)
	err = SendEmailWithAttachment(
		opdData.PatientName,
		opdData.DoctorName,
		opdData.OPDDate,
		opdData.OPDNotes,
		opdData.Prescription,
		opdData.FollowupDate,
		"", // followupTime (already combined)
		opdData.CreatedOn,
		fmt.Sprintf("OPD  %s", opdData.PatientName),
		recipientEmail,
		pdfFileName,
		pdfContent,
		loggedInEmail,
		fromName,
	)
	if err != nil {
		return fmt.Errorf("failed to send email with PDF: %w", err)
	}

	log.Println("✅ PDF created and email sent to:", recipientEmail, "from display name:", fromName)
	return nil
}

func parseOPDTemplate(templatePath string, data models.OpdModel) (string, error) {
	// Parse the HTML template file
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to parse template file (%s): %w", templatePath, err)
	}

	// Execute the template with provided OPD data
	var tpl bytes.Buffer
	if err := tmpl.Execute(&tpl, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return tpl.String(), nil
}
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func SendEmailWithAttachment(
	patientName, doctorName, opdDate, opdNotes, prescription, followupDate, followupTime, createdOn,
	subject, recipient, filename string, attachment []byte, loggedInEmail, fromName string,
) error {
	start := time.Now()

	// Load SMTP configuration
	smtpConfig, err := config.LoadSMTPConfig()
	if err != nil {
		return fmt.Errorf("failed to load SMTP config: %w", err)
	}

	// Prepare OPD data
	opdData := models.OpdModel{
		PatientName:  strings.TrimSpace(patientName),
		DoctorName:   strings.TrimSpace(doctorName),
		OPDDate:      strings.TrimSpace(opdDate),
		OPDNotes:     strings.TrimSpace(opdNotes),
		Prescription: strings.TrimSpace(prescription),
		FollowupDate: strings.TrimSpace(fmt.Sprintf("%s %s", followupDate, followupTime)),
		CreatedOn:    strings.TrimSpace(createdOn),
		GeneratedOn:  time.Now().Format("02 Jan 2006 03:04 PM"),
	}

	// Parse HTML email body
	emailBody, err := parseOPDTemplate("templates/opdmodal.html", opdData)
	if err != nil {
		return fmt.Errorf("failed to parse email body template: %v", err)
	}

	// Define boundary
	const boundary = "boundary-opd-email-12345"
	var sb strings.Builder

	// Build email headers
	sb.WriteString(fmt.Sprintf("From: \"%s\" <%s>\r\n", fromName, loggedInEmail))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", recipient))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", truncate(opdNotes, 30)))
	sb.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n", boundary))
	sb.WriteString("\r\n--" + boundary + "\r\n")

	// Add HTML body
	sb.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
	sb.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	sb.WriteString(emailBody + "\r\n")
	sb.WriteString("\r\n--" + boundary + "\r\n")

	// Add PDF attachment
	sb.WriteString(fmt.Sprintf("Content-Type: application/pdf; name=\"%s\"\r\n", filename))
	sb.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", filename))
	sb.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")

	encoded := base64.StdEncoding.EncodeToString(attachment)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end] + "\r\n")
	}
	sb.WriteString("--" + boundary + "--\r\n")

	// Send the email
	auth := smtp.PlainAuth("", smtpConfig.From, smtpConfig.Password, smtpConfig.SMTPHost_ALT)
	sendStart := time.Now()
	err = smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpConfig.SMTPHost_ALT, smtpConfig.SMTPPort),
		auth,
		smtpConfig.From,
		[]string{recipient},
		[]byte(sb.String()),
	)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("✅ Email sent to %s (display: %s <%s>)", recipient, fromName, loggedInEmail)
	log.Printf("⏱️ Send Time: %v ms | Total Time: %v ms", time.Since(sendStart).Milliseconds(), time.Since(start).Milliseconds())

	return nil
}
