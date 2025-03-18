package services

import (
	"context"
	"crypto/tls"
	"email-client/config"
	"email-client/models"
	"errors"
	"fmt"
	"html"
	"io"

	"log"
	"math/rand"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-message/mail"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// DateService provides current date functionality
type DateService struct{}

func NewDateService() *DateService {
	return &DateService{}
}

func (ds *DateService) GetCurrentDate() time.Time {
	return time.Now()
}

// OTPService handles OTP generation
type OTPService struct{}

func NewOTPService() *OTPService {
	return &OTPService{}
}

func (os *OTPService) GenerateOTP() string {
	rand.Seed(time.Now().UnixNano())
	otp := rand.Intn(1000000)
	formattedOTP := fmt.Sprintf("%06d", otp)
	fmt.Println("Generated OTP (from OTPService):", formattedOTP)
	return formattedOTP
}

// ✅ Struct to store recipient emails
type EmailRecord struct {
	Email string `json:"email"`
}

// FetchEmailIDs fetches unique email recipients
func FetchEmailIDs(loggedInEmail string) ([]string, error) {
	// ✅ Establish IMAP connection
	imapClient, err := config.ConnectIMAP()
	if err != nil {
		log.Printf("❌ IMAP Connection Error: %v", err)
		return nil, fmt.Errorf("failed to fetch emails: %w", err)
	}
	defer imapClient.Logout()

	// ✅ Select INBOX
	mbox, err := imapClient.Select("INBOX", false)
	if err != nil {
		log.Println("❌ Failed to select INBOX:", err)
		return nil, fmt.Errorf("failed to select INBOX: %v", err)
	}

	log.Println("📩 INBOX has", mbox.Messages, "messages")

	// ✅ If no messages exist, return
	if mbox.Messages == 0 {
		return nil, errors.New("📭 no messages in the mailbox")
	}

	// ✅ Fetch all emails
	seqSet := new(imap.SeqSet)
	seqSet.AddRange(1, mbox.Messages)
	//log.Println("🔍 Fetching all email IDs...")

	// ✅ Request only email headers
	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		done <- imapClient.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope}, messages)
	}()

	uniqueRecipients := make(map[string]bool)
	var recipientList []string

	// ✅ Process fetched emails
	for msg := range messages {
		// ✅ Debugging: Log raw email metadata
		// log.Printf("📩 Debug: Email Message ID: %v", msg.Envelope.MessageId)
		// log.Printf("📩 Debug: Email Subject: %v", msg.Envelope.Subject)
		// log.Printf("📩 Debug: From: %v", msg.Envelope.From)
		// log.Printf("📩 Debug: To: %v", msg.Envelope.To)

		if msg.Envelope == nil || len(msg.Envelope.From) == 0 || len(msg.Envelope.To) == 0 {
			//log.Println("⚠️ Skipping email: Missing envelope, sender, or recipient")
			continue
		}

		// ✅ Extract sender and recipient email
		fromEmail := fmt.Sprintf("%s@%s", msg.Envelope.From[0].MailboxName, msg.Envelope.From[0].HostName)
		toEmail := fmt.Sprintf("%s@%s", msg.Envelope.To[0].MailboxName, msg.Envelope.To[0].HostName)

		// ✅ Filter only emails sent by the logged-in user
		if !strings.EqualFold(fromEmail, loggedInEmail) {
			//log.Printf("⚠️ Skipping email: Sender %s does not match logged-in user %s", fromEmail, loggedInEmail)
			continue
		}

		// ✅ Store unique recipient email IDs
		if _, exists := uniqueRecipients[toEmail]; !exists {
			uniqueRecipients[toEmail] = true
			recipientList = append(recipientList, toEmail)
			//log.Printf("✅ Added recipient: %s", toEmail)
		}
	}

	// ✅ Check for fetch errors
	if err := <-done; err != nil {
		log.Println("❌ Failed to fetch email IDs:", err)
		return nil, fmt.Errorf("failed to fetch email IDs: %v", err)
	}

	//log.Println("✅ Fetched Unique Email IDs:", recipientList)
	return recipientList, nil
}

// CheckEmailExists checks if an email record (From, To pair) exists in MongoDB
func CheckEmailExists(fromEmail, toEmail string) bool {
	collection := config.GetReportCollection() // Ensure this gets 'RecordAccessRights'

	// Define filter based on the correct field names
	filter := bson.M{"DoctorId": fromEmail, "PatientId": toEmail}

	// Try to find a matching document
	var result bson.M
	err := collection.FindOne(context.TODO(), filter).Decode(&result)

	if err == mongo.ErrNoDocuments {
		// If no document is found, return false
		fmt.Println("❌ No matching record found")
		return false
	} else if err != nil {
		// If any error occurs other than 'no documents', print and return false
		fmt.Println("❌ Error checking email:", err)
		return false
	}

	// If a record is found, print success message and return true
	fmt.Println("✅ Record found in MongoDB")
	return true
}

// FetchEmails retrieves emails filtered by the recipient
func FetchEmails(toFilter string) ([]models.Message, error) {
	// ✅ Establish IMAP connection
	imapClient, err := config.ConnectIMAP()
	if err != nil {
		log.Printf("❌ IMAP Connection Error: %v", err)
		return nil, fmt.Errorf("failed to fetch emails: %w", err)
	}
	defer imapClient.Logout()

	// ✅ Select INBOX
	mbox, err := imapClient.Select("INBOX", false)
	if err != nil {
		log.Println("❌ Failed to select INBOX:", err)
		return nil, fmt.Errorf("failed to select INBOX: %w", err)
	}

	totalMessages := mbox.Messages
	log.Println("📩 INBOX contains", totalMessages, "messages")

	// ✅ Check if mailbox is empty
	if totalMessages == 0 {
		return nil, errors.New("📭 no messages in the mailbox")
	}

	// ✅ Fetch latest emails
	from := uint32(1)
	to := totalMessages
	seqSet := new(imap.SeqSet)
	seqSet.AddRange(from, to)
	log.Println("🔍 Fetching emails from", from, "to", to)

	// ✅ Request email headers
	section := imap.BodySectionName{}

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		// done <- imapClient.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope}, messages)
		done <- imapClient.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope, section.FetchItem()}, messages)

	}()

	var emailMessages []models.Message
	//log.Println("📥 Processing fetched emails...")

	// ✅ Iterate through fetched messages
	for msg := range messages {
		if msg.Envelope == nil || len(msg.Envelope.From) == 0 || len(msg.Envelope.To) == 0 {
			//log.Println("⚠️ Skipping email: Missing envelope, sender, or recipient")
			continue
		}

		//log.Println("📩 Processing email with subject:", msg.Envelope.Subject) // Move here

		// ✅ Extract "From" and "To" emails
		fromEmail := fmt.Sprintf("%s@%s", msg.Envelope.From[0].MailboxName, msg.Envelope.From[0].HostName)
		toEmail := fmt.Sprintf("%s@%s", msg.Envelope.To[0].MailboxName, msg.Envelope.To[0].HostName)
		fromName := msg.Envelope.From[0].PersonalName // Extract sender's name

		if toFilter != "" && !(strings.EqualFold(toEmail, toFilter) || strings.Contains(toEmail, toFilter)) {
			//log.Printf("🚫 Skipping: %s does not match filter %s", toEmail, toFilter)
			continue
		}
		// Read email body
		var bodyContent string
		var attachments []models.Attachment
		body := msg.GetBody(&section)

		if body == nil {
			log.Printf("No body found for message: %v", msg.Envelope.Subject)
			continue
		}

		mr, err := mail.CreateReader(body)
		if err != nil {
			log.Printf("Error creating mail reader: %v", err)
			continue
		}

		// Ensure "attachments" directory exists
		_ = os.Mkdir("attachments", os.ModePerm)

		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("Error reading mail part: %v", err)
				continue
			}

			switch header := part.Header.(type) {
			case *mail.InlineHeader:
				bodyBytes, err := io.ReadAll(part.Body)
				if err != nil {
					log.Printf("Error reading email body: %v", err)
					continue
				}

				mediaType, _, err := header.ContentType()
				if err != nil {
					log.Printf("Error parsing content type: %v", err)
					continue
				}

				decodedBody := string(bodyBytes)
				if strings.Contains(mediaType, "text/html") {
					bodyContent = decodedBody
				} else {
					bodyContent = html.EscapeString(decodedBody)
				}

			case *mail.AttachmentHeader:
				filename, _ := header.Filename()
				if filename == "" {
					continue
				}

				// Ensure 'attachments' directory exists
				os.MkdirAll("attachments", os.ModePerm)

				// Save the attachment in the attachment folder
				path := fmt.Sprintf("attachments/%s", filename)
				file, err := os.Create(path)
				if err != nil {
					log.Printf("Error creating file for attachment: %v", err)
					continue
				}
				if _, err := io.Copy(file, part.Body); err != nil {
					log.Printf("Error saving attachment: %v", err)
				}
				file.Close()

				// Store the attachment info
				attachments = append(attachments, models.Attachment{
					Filename: filename,
					Path:     fmt.Sprintf("attachments/%s", filename), // Serve via HTTP
				})

			}
		}

		// log.Printf("🔍 Filtering for recipient: %s", toFilter)
		// log.Printf("📧 Checking email: From %s, To %s", fromEmail, toEmail)

		// ✅ Add to result list
		emailMessages = append(emailMessages, models.Message{
			Subject:     msg.Envelope.Subject,
			From:        fromEmail,
			FromName:    fromName,
			To:          toEmail,
			Date:        msg.Envelope.Date.Format("Jan 02 2006 03:04 PM"),
			Body:        bodyContent,
			Attachments: attachments,
		})
	}

	// ✅ Check for fetch errors
	if err := <-done; err != nil {
		log.Printf("❌ Fetch error after processing %d emails: %v", len(emailMessages), err)
		return nil, fmt.Errorf("failed to fetch messages: %w", err)
	}

	//log.Println("✅ Successfully fetched", len(emailMessages), "emails for recipient:", toFilter)
	return emailMessages, nil
}

// SendEmail sends an email with the given subject, body, OTP, and recipient email.
func SendEmail(subject, body, otp, recipient string) error {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Could not load .env file, using system environment variables")
	}

	// Fetch SMTP credentials from environment
	from := os.Getenv("SMTP_EMAIL")
	password := os.Getenv("SMTP_PASSWORD")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpSecurity := os.Getenv("SMTP_SECURITY") // "true" or "false"

	// Validate credentials
	if from == "" || password == "" || smtpHost == "" || smtpPort == "" {
		return fmt.Errorf("SMTP credentials are missing")
	}

	// Construct the email message
	message := fmt.Sprintf("Subject: %s\r\n\r\n%s\r\n\r\nYour OTP code is: %s", subject, body, otp)

	// Set up authentication
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Handle SMTP security modes
	if smtpSecurity == "false" {
		// No TLS (INSECURE mode)
		log.Println("Warning: Sending email without TLS")
		err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{recipient}, []byte(message))
		if err != nil {
			return fmt.Errorf("failed to send email: %v", err)
		}
	} else {
		// Use TLS (Secure mode)
		log.Println("Using TLS for secure email transmission")

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // ⚠️ Disable only for testing
			ServerName:         smtpHost,
		}

		// Connect to SMTP server over TLS
		conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP over TLS: %v", err)
		}
		defer conn.Close()

		// Create SMTP client
		client, err := smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %v", err)
		}
		defer client.Close()

		// Authenticate
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate: %v", err)
		}

		// Set sender and recipient
		if err = client.Mail(from); err != nil {
			return fmt.Errorf("failed to set sender: %v", err)
		}
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient: %v", err)
		}

		// Send email body
		wc, err := client.Data()
		if err != nil {
			return fmt.Errorf("failed to open write connection: %v", err)
		}
		_, err = wc.Write([]byte(message))
		if err != nil {
			return fmt.Errorf("failed to write email body: %v", err)
		}
		err = wc.Close()
		if err != nil {
			return fmt.Errorf("failed to close write connection: %v", err)
		}

		// Close client
		client.Quit()
	}

	log.Println("Email successfully sent to:", recipient)
	return nil
}

func GetUniqueRecipients(fromEmail string) ([]string, error) {
	//log.Printf("📩 Fetching unique recipients for: %s", fromEmail)

	// ✅ Fetch only emails where "From" matches `fromEmail`
	emails, err := FetchEmails(fromEmail) // Pass `fromEmail` as a filter
	if err != nil {
		//log.Printf("❌ Error fetching emails for %s: %v", fromEmail, err)
		return nil, fmt.Errorf("failed to fetch emails: %w", err)
	}

	// ✅ Use a map to track unique recipients (avoid duplicates)
	emailSet := make(map[string]struct{})

	for _, email := range emails {
		recipients := strings.Split(email.To, ",")
		for _, recipient := range recipients {
			normalizedEmail := strings.ToLower(strings.TrimSpace(recipient))

			// Ensure it's a valid email and not the sender itself
			if normalizedEmail != "" && normalizedEmail != strings.ToLower(fromEmail) {
				if _, exists := emailSet[normalizedEmail]; !exists {
					log.Println("📨 Adding recipient:", normalizedEmail)
					emailSet[normalizedEmail] = struct{}{}
				}
			}
		}
	}

	// ✅ Convert map keys to a slice
	uniqueEmails := make([]string, 0, len(emailSet))
	for email := range emailSet {
		uniqueEmails = append(uniqueEmails, email)
	}

	//log.Printf("✅ %d Unique recipients found: %v", len(uniqueEmails), uniqueEmails)
	return uniqueEmails, nil
}
