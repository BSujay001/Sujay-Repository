package config

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap/client"
)

// ConnectIMAP establishes an IMAP connection and tracks execution time
func ConnectIMAP() (*client.Client, error) {
	startTime := time.Now()

	// ✅ Load IMAP configuration from environment variables
	imapServer := os.Getenv("IMAP_SERVER")
	username := os.Getenv("EMAIL_USERNAME")
	password := os.Getenv("EMAIL_PASSWORD")

	if imapServer == "" || username == "" || password == "" {
		return nil, fmt.Errorf("❌ Missing IMAP configuration. Check environment variables")
	}

	parts := strings.Split(imapServer, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("❌ Invalid IMAP_SERVER format. Expected format: hostname:port")
	}

	host, port := parts[0], parts[1]
	var imapClient *client.Client
	var err error

	// ✅ Connect to IMAP Server
	connectStart := time.Now()
	switch port {
	case "993":
		imapClient, err = client.DialTLS(imapServer, &tls.Config{ServerName: host})
	case "143":
		imapClient, err = client.Dial(imapServer)
		if err == nil {
			err = imapClient.StartTLS(&tls.Config{ServerName: host})
		}
	default:
		return nil, fmt.Errorf("❌ Unsupported IMAP port: %s", port)
	}

	if err != nil {
		return nil, fmt.Errorf("❌ Failed to connect to IMAP server: %w", err)
	}
	log.Printf("✅ IMAP server connection established in %v ms", time.Since(connectStart).Milliseconds())

	// ✅ Login to IMAP
	loginStart := time.Now()
	if err := imapClient.Login(username, password); err != nil {
		imapClient.Logout()
		return nil, fmt.Errorf("❌ IMAP login failed: %w", err)
	}
	log.Printf("✅ IMAP login successful in %v ms", time.Since(loginStart).Milliseconds())

	// ✅ Keep connection alive with NOOP
	go func() {
		for {
			time.Sleep(40 * time.Minute) // Run every 5 minutes
			if err := imapClient.Noop(); err != nil {
				log.Println("⚠️ IMAP NOOP failed, connection might be lost:", err)
			}
		}
	}()

	log.Printf("✅ Total IMAP connection time: %v ms", time.Since(startTime).Milliseconds())

	return imapClient, nil
}
