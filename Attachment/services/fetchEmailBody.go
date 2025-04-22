package services

import (
	"bytes"
	"email-client/config"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
)

func FetchPlainTextEmailBody(imapClient *client.Client, emailUID uint32) (string, []map[string]string, error) {
	startTime := time.Now() // Track execution time

	// ✅ Skip re-selecting INBOX if already selected
	if imapClient.Mailbox() == nil || imapClient.Mailbox().Name != "INBOX" {
		_, err := imapClient.Select("INBOX", false)
		if err != nil {
			return "", nil, fmt.Errorf("failed to select mailbox: %w", err)
		}
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(emailUID)

	// ✅ Fetch only the required parts
	section := &imap.BodySectionName{}
	messages := make(chan *imap.Message, 1)

	if err := imapClient.UidFetch(seqSet, []imap.FetchItem{section.FetchItem()}, messages); err != nil {
		return "", nil, fmt.Errorf("fetch error: %w", err)
	}

	msg := <-messages
	if msg == nil {
		return "", nil, fmt.Errorf("email not found for UID %d", emailUID)
	}

	body := msg.GetBody(section)
	if body == nil {
		return "", nil, fmt.Errorf("email body empty for UID %d", emailUID)
	}

	rawBody, err := io.ReadAll(body)
	if err != nil {
		return "", nil, fmt.Errorf("error reading body: %w", err)
	}

	// ✅ Skip MIME processing if not needed
	if !bytes.Contains(rawBody, []byte("Content-Type:")) {
		log.Println("✅ No MIME structure found. Returning plain text body.")
		return string(rawBody), nil, nil
	}

	reader, err := mail.CreateReader(bytes.NewReader(rawBody))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse MIME email: %w", err)
	}

	var emailBody, plainTextBody string
	var attachments []map[string]string

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("⚠️ Error reading email part: %v", err)
			continue
		}

		contentType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		disp, dispParams, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))

		// ✅ Get filename from Content-Disposition OR Content-Type
		filename := dispParams["filename"]
		if filename == "" {
			_, cParams, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
			filename = cParams["name"]
		}

		// ✅ Prefer HTML if available
		if strings.HasPrefix(contentType, "text/html") {
			htmlBytes, err := io.ReadAll(part.Body)
			if err == nil {
				emailBody = string(htmlBytes)
			}
		} else if strings.HasPrefix(contentType, "text/plain") {
			textBytes, err := io.ReadAll(part.Body)
			if err == nil {
				plainTextBody = string(textBytes)
			}
		} else if (strings.EqualFold(disp, "attachment") || strings.EqualFold(disp, "inline")) && strings.Contains(contentType, "image") {
			data, err := io.ReadAll(part.Body)
			if err != nil {
				log.Printf("⚠️ Failed to read attachment %s: %v", filename, err)
				continue
			}
			if len(data) == 0 {
				log.Printf("⚠️ Attachment %s is empty", filename)
				continue
			}

			base64Img := base64.StdEncoding.EncodeToString(data)
			log.Printf("📎 Processed attachment: %s (size: %d bytes)", filename, len(data))

			attachments = append(attachments, map[string]string{
				"type":   "image",
				"name":   filename,
				"base64": fmt.Sprintf("data:%s;base64,%s", contentType, base64Img),
			})
		}
	}

	// ✅ Fallback to plain text if HTML not found
	if emailBody == "" && plainTextBody != "" {
		emailBody = plainTextBody
	}

	// ✅ Log missing content issues
	if emailBody == "" && len(attachments) == 0 {
		log.Println("⚠️ No email content or attachments found for UID:", emailUID)
		return "", nil, fmt.Errorf("no content available")
	}

	// ✅ Measure execution time
	log.Printf("✅ FetchPlainTextEmailBody completed in %d ms", time.Since(startTime).Milliseconds())

	return emailBody, attachments, nil
}

// CheckEmailExists checks if an email exists with doctorId as "From" and patientId as "To"
func CheckEmailExists(doctorId, patientId string) (bool, error) {
	start := time.Now()
	log.Println("📨 Checking emails From:", doctorId, "| To:", patientId)

	imapClient, err := config.ConnectIMAP()
	if err != nil {
		log.Println("❌ IMAP connection error:", err)
		return false, err
	}
	defer imapClient.Logout()

	_, err = imapClient.Select("INBOX", false)
	if err != nil {
		log.Println("❌ Failed to select INBOX:", err)
		return false, err
	}

	// Use IMAP header filtering
	criteria := imap.NewSearchCriteria()
	criteria.Header.Add("From", doctorId)
	criteria.Header.Add("To", patientId)

	uids, err := imapClient.Search(criteria)
	if err != nil {
		log.Println("❌ IMAP search failed:", err)
		return false, err
	}
	log.Printf("🔍 Matched UIDs: %d", len(uids))

	if len(uids) > 0 {
		log.Printf("✅ Matching email found (From: %s → To: %s)", doctorId, patientId)
		log.Printf("⏱️ Check completed in %v ms", time.Since(start).Milliseconds())
		return true, nil
	}

	log.Printf("❌ No matching email found for From = %s and To = %s", doctorId, patientId)
	log.Printf("⏱️ Check completed in %v ms", time.Since(start).Milliseconds())
	return false, nil
}
