package services

import (
	"email-client/timeConfig"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-message"
)

type Attachment struct {
	Name string `json:"name"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

// FetchAttachment retrieves an email attachment by UID and attachment name
func FetchAttachment(emailUID uint32, attachmentName string) ([]byte, string, error) {
	startTime := time.Now()

	// ✅ Step 1: Reuse IMAP connection (No need to reconnect every time)
	imapClient, err := timeConfig.ConnectIMAP()
	if err != nil {
		log.Printf("❌ IMAP connection error: %v", err)
		return nil, "", fmt.Errorf("IMAP connection error: %v", err)
	}

	// ✅ Step 2: Select Mailbox (Avoid reselecting if already selected)
	_, err = imapClient.Select("INBOX", false)
	if err != nil {
		log.Printf("❌ Failed to select INBOX: %v", err)
		return nil, "", fmt.Errorf("failed to select INBOX: %v", err)
	}

	// ✅ Step 3: Setup Async Fetch for Faster Processing
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(emailUID)
	section := &imap.BodySectionName{}

	messages := make(chan *imap.Message, 1)
	errChan := make(chan error, 1)

	// ⚡ Concurrent Fetch
	go func() {
		errChan <- imapClient.UidFetch(seqSet, []imap.FetchItem{section.FetchItem()}, messages)
	}()

	msg := <-messages
	if fetchErr := <-errChan; fetchErr != nil {
		log.Printf("❌ Fetch error for UID %d: %v", emailUID, fetchErr)
		return nil, "", fmt.Errorf("fetch error: %v", fetchErr)
	}

	if msg == nil {
		log.Printf("❌ No email found with UID: %d", emailUID)
		return nil, "", fmt.Errorf("no message found with UID %d", emailUID)
	}

	// ✅ Step 4: Use Streaming to Read Email Faster
	r := msg.GetBody(section)
	if r == nil {
		log.Printf("❌ No body found for UID %d", emailUID)
		return nil, "", fmt.Errorf("failed to get body for UID %d", emailUID)
	}

	m, err := message.Read(r)
	if err != nil {
		log.Printf("❌ Failed to parse email UID %d: %v", emailUID, err)
		return nil, "", fmt.Errorf("failed to parse email: %v", err)
	}

	mr := m.MultipartReader()
	if mr == nil {
		log.Printf("❌ Email UID %d is not multipart; no attachments found", emailUID)
		return nil, "", fmt.Errorf("email is not multipart; no attachments found")
	}

	// ✅ Step 5: Extract Attachment (Fastest Processing)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("❌ Error reading multipart part: %v", err)
			return nil, "", fmt.Errorf("error reading multipart part: %v", err)
		}

		// Check attachment properties
		disposition, params, _ := p.Header.ContentDisposition()
		filename := params["filename"]

		if (disposition == "attachment" || disposition == "inline") && strings.EqualFold(filename, attachmentName) {
			data, err := io.ReadAll(p.Body)
			if err != nil {
				log.Printf("❌ Error reading attachment body: %v", err)
				return nil, "", fmt.Errorf("error reading attachment body: %v", err)
			}

			log.Printf("📎 Attachment '%s' fetched successfully in %v ms!", filename, time.Since(startTime).Milliseconds())
			return data, filename, nil
		}
	}

	log.Printf("❌ Attachment '%s' not found in email UID %d", attachmentName, emailUID)
	return nil, "", fmt.Errorf("attachment %s not found in email UID %d", attachmentName, emailUID)
}
