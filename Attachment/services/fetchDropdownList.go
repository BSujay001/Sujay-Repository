package services

import (
	"email-client/config"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap"
)

// ✅ Struct to store recipient emails and sender names FetchEmailIDs
type EmailRecord struct {
	Email    string `json:"email"`
	FromName string `json:"from_name"`
}

// EmailInfo stores email metadata
type EmailInfo struct {
	Date  time.Time
	Email string
}

// ExtractMobileNumber extracts mobile number from email (before the '@' symbol)
func ExtractMobileNumber(email string) (string, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid email format: %s", email)
	}
	mobileNumber := parts[0] // Extract only the mobile number part
	return mobileNumber, nil
}

// FetchEmailIDs retrieves unique recipient emails sorted by latest date first
func FetchEmailIDs(loggedInEmail string) ([]string, error) {
	imapClient, err := config.ConnectIMAP()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IMAP: %w", err)
	}
	defer imapClient.Logout()

	_, err = imapClient.Select("INBOX", true)
	if err != nil {
		return nil, fmt.Errorf("failed to select INBOX: %w", err)
	}

	// Search for emails sent by logged-in user
	searchCriteria := imap.NewSearchCriteria()
	searchCriteria.Header.Add("FROM", loggedInEmail)

	seqNums, err := imapClient.Search(searchCriteria)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	if len(seqNums) == 0 {
		return []string{}, nil
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(seqNums...)

	messages := make(chan *imap.Message, len(seqNums))
	go func() {
		_ = imapClient.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope}, messages)
	}()

	var emailList []EmailInfo
	uniqueRecipients := make(map[string]bool)

	// Process fetched emails
	for msg := range messages {
		if msg == nil || msg.Envelope == nil || len(msg.Envelope.To) == 0 {
			continue
		}

		for _, recipient := range msg.Envelope.To {
			toEmail := fmt.Sprintf("%s@%s", recipient.MailboxName, recipient.HostName)
			toEmail = strings.ToLower(strings.TrimSpace(toEmail))

			emailDate := msg.Envelope.Date.UTC() // Convert to UTC

			if toEmail != "" && !uniqueRecipients[toEmail] {
				uniqueRecipients[toEmail] = true
				emailList = append(emailList, EmailInfo{Date: emailDate, Email: toEmail})
			}
		}
	}

	// Sort emails by date (latest first)
	sort.Slice(emailList, func(i, j int) bool {
		return emailList[i].Date.After(emailList[j].Date)
	})

	// Convert to final slice
	var recipients []string
	for _, email := range emailList {
		recipients = append(recipients, email.Email)
	}

	return recipients, nil
}

func GetUniqueRecipients(loggedInEmail string) ([]string, error) {
	log.Printf("📩 Fetching unique recipients for logged-in email: %s", loggedInEmail)

	// ✅ Fetch recipients using logged-in email
	emails, err := FetchEmailIDs(loggedInEmail)
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to fetch emails: %w", err)
	}

	// ✅ Use a map to track unique recipients (avoid duplicates)
	emailSet := make(map[string]struct{})
	normalizedSender := strings.ToLower(strings.TrimSpace(loggedInEmail))

	for _, recipient := range emails {
		normalizedEmail := strings.ToLower(strings.TrimSpace(recipient))

		// Ensure it's a valid email and not the sender itself
		if normalizedEmail != "" && normalizedEmail != normalizedSender {
			// Strip the domain part and extract the mobile number
			mobileNumber, err := ExtractMobileNumber(normalizedEmail)
			if err != nil {
				log.Printf("❌ Invalid email format for %s: %v", normalizedEmail, err)
				continue
			}

			if _, exists := emailSet[mobileNumber]; !exists {
				log.Printf("📨 Adding recipient: %s", mobileNumber) // Log mobile number only
				emailSet[mobileNumber] = struct{}{}
			}
		}
	}

	// ✅ Convert map keys to a slice
	uniqueMobiles := make([]string, 0, len(emailSet))
	for mobile := range emailSet {
		uniqueMobiles = append(uniqueMobiles, mobile)
	}

	// ✅ Log results
	if len(uniqueMobiles) == 0 {
		log.Println("📭 No unique recipients found.")
	} else {
		log.Printf("✅ %d Unique recipients found: %v", len(uniqueMobiles), uniqueMobiles)
	}

	return uniqueMobiles, nil
}
