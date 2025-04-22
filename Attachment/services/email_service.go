package services

import (
	"email-client/config"

	"fmt"
	"log"
	"math/rand"

	"strings"
	"time"

	"github.com/emersion/go-imap"
)

// DateService provides current date functionality
//type DateService struct{}

// func NewDateService() *DateService {
// 	return &DateService{}
// }

// func (ds *DateService) GetCurrentDate() time.Time {
// 	return time.Now()
// }

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

// FetchFromNameByEmail retrieves the sender's name from the email header.
func FetchFromNameByEmail(loggedInEmail string) (string, error) {
	startTime := time.Now()
	log.Println("🔄 [Service - Name] Checking if entered email exists and fetching name...")

	// ✅ Connect to IMAP
	imapStart := time.Now()
	imapClient, err := config.ConnectIMAP()
	if err != nil {
		log.Printf("❌ IMAP connection failed: %v", err)
		return "", fmt.Errorf("IMAP connection error: %w", err)
	}
	defer imapClient.Logout()
	log.Printf("✅ IMAP connected in %v ms", time.Since(imapStart).Milliseconds())

	// ✅ Select INBOX in read-only mode
	inboxStart := time.Now()
	_, err = imapClient.Select("INBOX", true)
	if err != nil {
		log.Printf("❌ Failed to select INBOX: %v", err)
		return "", fmt.Errorf("failed to select INBOX: %w", err)
	}
	log.Printf("📂 INBOX selected in %v ms", time.Since(inboxStart).Milliseconds())

	// ✅ Search for emails FROM loggedInEmail
	searchStart := time.Now()
	searchCriteria := imap.NewSearchCriteria()
	searchCriteria.Header.Add("FROM", loggedInEmail)

	seqNums, err := imapClient.Search(searchCriteria)
	if err != nil || len(seqNums) == 0 {
		log.Printf("⚠️ No matching emails found from: %s", loggedInEmail)
		log.Printf("🕒 Total execution time: %v ms", time.Since(startTime).Milliseconds())
		return "", nil // Only return empty string if not found
	}
	log.Printf("📊 Found %d matching emails in %v ms", len(seqNums), time.Since(searchStart).Milliseconds())

	// ✅ Fetch headers from latest 10 emails only
	if len(seqNums) > 10 {
		seqNums = seqNums[len(seqNums)-10:]
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(seqNums...)

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		done <- imapClient.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope}, messages)
	}()

	// ✅ Check for name in From field
	for msg := range messages {
		if msg.Envelope != nil {
			for _, from := range msg.Envelope.From {
				emailAddr := from.MailboxName + "@" + from.HostName
				if strings.EqualFold(emailAddr, loggedInEmail) && from.PersonalName != "" {
					senderName := strings.Title(strings.ToLower(from.PersonalName))
					log.Printf("✅ Found name: '%s' for %s", senderName, emailAddr)
					log.Printf("🕒 Total execution time: %v ms", time.Since(startTime).Milliseconds())
					return senderName, nil
				}
			}
		}
	}

	// ✅ Wait for fetch to complete
	if err := <-done; err != nil {
		log.Printf("❌ Error fetching headers: %v", err)
		return "", fmt.Errorf("fetch error: %w", err)
	}

	log.Printf("⚠️ Email found but name missing. Returning empty.")
	log.Printf("🕒 Total execution time: %v ms", time.Since(startTime).Milliseconds())
	return "", nil
}
