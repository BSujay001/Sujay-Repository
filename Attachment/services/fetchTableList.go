package services

import (
	"email-client/config"
	"email-client/models"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap"
)

func FetchEmails(loggedInEmail string, toFilter string) ([]models.Message, error) {
	startTime := time.Now()
	log.Println("⏳ FetchEmails started...")

	imapClient, err := config.ConnectIMAP()
	if err != nil {
		log.Printf("❌ IMAP Connection Error: %v", err)
		return nil, fmt.Errorf("failed to connect to IMAP: %w", err)
	}
	defer imapClient.Logout()
	log.Println("✅ IMAP connection established")

	mbox, err := imapClient.Select("INBOX", true)
	if err != nil {
		log.Println("❌ Failed to select INBOX:", err)
		return nil, fmt.Errorf("failed to select INBOX: %w", err)
	}
	log.Println("✅ INBOX selected")

	if mbox.Messages == 0 {
		log.Println("📭 No messages in the inbox.")
		return nil, errors.New("no messages found in mailbox")
	}

	seqSet := new(imap.SeqSet)
	criteria := imap.NewSearchCriteria()
	if loggedInEmail != "" {
		criteria.Header.Add("From", loggedInEmail)
	}
	if toFilter != "" {
		criteria.Header.Add("To", toFilter)
	}
	uids, err := imapClient.Search(criteria)
	if err != nil {
		log.Printf("❌ IMAP search error: %v", err)
		return nil, fmt.Errorf("error searching emails: %w", err)
	}
	if len(uids) == 0 {
		log.Println("📭 No emails found for the given filter(s).")
		return nil, nil
	}
	seqSet.AddNum(uids...)

	log.Println("✅ Email search completed")

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		done <- imapClient.Fetch(seqSet, []imap.FetchItem{
			imap.FetchEnvelope,
			imap.FetchBodyStructure,
			imap.FetchUid,
		}, messages)
	}()

	var wg sync.WaitGroup
	emailChannel := make(chan struct {
		msg       models.Message
		timestamp time.Time
	}, 10)

	for msg := range messages {
		wg.Add(1)
		go func(m *imap.Message) {
			defer wg.Done()
			if m.Envelope == nil || len(m.Envelope.From) == 0 || len(m.Envelope.To) == 0 {
				return
			}

			fromEmail := m.Envelope.From[0].Address()
			toEmail := m.Envelope.To[0].Address()
			fromName := m.Envelope.From[0].PersonalName

			var attachmentNames []string
			if m.BodyStructure != nil {
				attachmentNames = getAttachmentNames(m.BodyStructure)
			}

			emailChannel <- struct {
				msg       models.Message
				timestamp time.Time
			}{
				msg: models.Message{
					ID:              strconv.Itoa(int(m.Uid)),
					UID:             m.Uid,
					Subject:         m.Envelope.Subject,
					From:            fromEmail,
					FromName:        fromName,
					To:              toEmail,
					Date:            "",
					AttachmentNames: attachmentNames,
				},
				timestamp: m.Envelope.Date,
			}
		}(msg)
	}

	go func() {
		wg.Wait()
		close(emailChannel)
		close(done)
	}()

	var emailMessages []struct {
		msg       models.Message
		timestamp time.Time
	}
	for email := range emailChannel {
		emailMessages = append(emailMessages, email)
	}

	if err := <-done; err != nil {
		log.Printf("❌ Error while fetching emails: %v", err)
		return nil, fmt.Errorf("error while fetching emails: %w", err)
	}

	sort.Slice(emailMessages, func(i, j int) bool {
		return emailMessages[i].timestamp.After(emailMessages[j].timestamp)
	})

	var sortedMessages []models.Message
	for _, item := range emailMessages {
		item.msg.Date = item.timestamp.Format("Jan 02 2006 03:04 PM")
		sortedMessages = append(sortedMessages, item.msg)
	}

	log.Printf("✅ Total FetchEmails execution time: %v ms", time.Since(startTime).Milliseconds())
	return sortedMessages, nil
}

func FetchAllDoctorsOfPatient(toFilter string) ([]models.Message, error) {
	startTime := time.Now()
	log.Println("⏳ FetchEmails started...")

	imapClient, err := config.ConnectIMAP()
	if err != nil {
		log.Printf("❌ IMAP Connection Error: %v", err)
		return nil, fmt.Errorf("failed to connect to IMAP: %w", err)
	}
	defer imapClient.Logout()
	log.Println("✅ IMAP connection established")

	mbox, err := imapClient.Select("INBOX", true)
	if err != nil {
		log.Println("❌ Failed to select INBOX:", err)
		return nil, fmt.Errorf("failed to select INBOX: %w", err)
	}
	log.Println("✅ INBOX selected")

	if mbox.Messages == 0 {
		log.Println("📭 No messages in the inbox.")
		return nil, errors.New("no messages found in mailbox")
	}

	seqSet := new(imap.SeqSet)
	if toFilter != "" {
		criteria := imap.NewSearchCriteria()
		criteria.Header.Add("To", toFilter)
		uids, err := imapClient.Search(criteria)
		if err != nil {
			log.Printf("❌ IMAP search error: %v", err)
			return nil, fmt.Errorf("error searching emails: %w", err)
		}
		if len(uids) == 0 {
			log.Println("📭 No emails found for the given filter.")
			return nil, nil
		}
		seqSet.AddNum(uids...)
	} else {
		seqSet.AddRange(1, mbox.Messages)
	}
	log.Println("✅ Email search completed")

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		done <- imapClient.Fetch(seqSet, []imap.FetchItem{
			imap.FetchEnvelope,
			imap.FetchBodyStructure,
			imap.FetchUid,
		}, messages)
	}()

	var wg sync.WaitGroup
	emailChannel := make(chan struct {
		msg       models.Message
		timestamp time.Time
	}, 10)

	for msg := range messages {
		wg.Add(1)
		go func(m *imap.Message) {
			defer wg.Done()
			if m.Envelope == nil || len(m.Envelope.From) == 0 || len(m.Envelope.To) == 0 {
				return
			}

			fromEmail := m.Envelope.From[0].Address()
			toEmail := m.Envelope.To[0].Address()
			fromName := m.Envelope.From[0].PersonalName
			// log.Printf("📧 From: %s (%s), To: %s, Subject: %s, Date: %v",
			// 	fromName, fromEmail, toEmail, m.Envelope.Subject, m.Envelope.Date)

			var attachmentNames []string
			if m.BodyStructure != nil {
				attachmentNames = getAttachmentNames(m.BodyStructure)
			}

			emailChannel <- struct {
				msg       models.Message
				timestamp time.Time
			}{
				msg: models.Message{
					ID:              strconv.Itoa(int(m.Uid)),
					UID:             m.Uid,
					Subject:         m.Envelope.Subject,
					From:            fromEmail,
					FromName:        fromName,
					To:              toEmail,
					Date:            "", // Will be set later
					AttachmentNames: attachmentNames,
				},
				timestamp: m.Envelope.Date, // ✅ Use actual email timestamp
			}
		}(msg)
	}

	go func() {
		wg.Wait()
		close(emailChannel)
		close(done)
	}()

	var emailMessages []struct {
		msg       models.Message
		timestamp time.Time
	}
	for email := range emailChannel {
		emailMessages = append(emailMessages, email)
	}

	if err := <-done; err != nil {
		log.Printf("❌ Error while fetching emails: %v", err)
		return nil, fmt.Errorf("error while fetching emails: %w", err)
	}

	// ✅ Sort by real email date
	sort.Slice(emailMessages, func(i, j int) bool {
		return emailMessages[i].timestamp.After(emailMessages[j].timestamp)
	})

	var sortedMessages []models.Message
	for _, item := range emailMessages {
		item.msg.Date = item.timestamp.Format("Jan 02 2006 03:04 PM")
		sortedMessages = append(sortedMessages, item.msg)
	}
	log.Printf("📥 Total emails fetched: %d", len(sortedMessages))
	log.Printf("✅ Total FetchEmails execution time: %v ms", time.Since(startTime).Milliseconds())
	return sortedMessages, nil
}

func getAttachmentNames(part *imap.BodyStructure) []string {
	var attachments []string

	if part == nil {
		return attachments
	}

	// If part is attachment
	if part.Disposition != "" && strings.ToLower(part.Disposition) == "attachment" {
		filename := part.Params["filename"]
		if filename == "" {
			filename = part.Params["name"]
		}
		if filename != "" {
			attachments = append(attachments, filename)
		}
	}

	// Recursively check sub-parts
	for _, subPart := range part.Parts {
		attachments = append(attachments, getAttachmentNames(subPart)...)
	}

	return attachments
}
