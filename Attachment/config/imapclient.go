package config

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/emersion/go-imap/client"
)

// ConnectIMAP establishes an IMAP connection using environment variables
func ConnectIMAP() (*client.Client, error) {
	// ✅ Load IMAP configuration from environment variables
	imapServer := os.Getenv("IMAP_SERVER")
	username := os.Getenv("EMAIL_USERNAME")
	password := os.Getenv("EMAIL_PASSWORD")

	// ✅ Validate environment variables
	if imapServer == "" || username == "" || password == "" {
		log.Println("❌ Missing IMAP configuration. Check environment variables.")
		return nil, fmt.Errorf("IMAP_SERVER, EMAIL_USERNAME, or EMAIL_PASSWORD is not set")
	}

	// ✅ Split IMAP server and port
	parts := strings.Split(imapServer, ":")
	if len(parts) != 2 {
		log.Println("❌ Invalid IMAP_SERVER format. Expected format: hostname:port")
		return nil, fmt.Errorf("invalid IMAP_SERVER format: %s", imapServer)
	}

	host := parts[0]
	port := parts[1]

	var c *client.Client
	var err error

	// ✅ Check port to determine connection type
	if port == "993" {
		// Secure TLS connection
		c, err = client.DialTLS(imapServer, &tls.Config{ServerName: host, InsecureSkipVerify: false})
		if err != nil {
			log.Println("❌ Failed to connect via TLS:", err)
			return nil, fmt.Errorf("failed to connect to IMAP server via TLS: %w", err)
		}
		log.Println("✅ Connected to IMAP server with SSL/TLS")
	} else if port == "143" {
		// Plain IMAP with STARTTLS
		c, err = client.Dial(imapServer)
		if err != nil {
			log.Println("❌ Failed to connect via IMAP:", err)
			return nil, fmt.Errorf("failed to connect to IMAP server: %w", err)
		}

		// ✅ Upgrade to secure connection using STARTTLS
		if err := c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: false}); err != nil {
			log.Println("❌ Failed to start TLS:", err)
			c.Logout()
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
		log.Println("✅ STARTTLS successful")
	} else {
		log.Println("❌ Unsupported IMAP port:", port)
		return nil, fmt.Errorf("unsupported IMAP port: %s", port)
	}

	// ✅ Ensure cleanup in case of error
	defer func() {
		if err != nil && c != nil {
			c.Logout()
		}
	}()

	// ✅ Login to IMAP
	if err := c.Login(username, password); err != nil {
		log.Println("❌ Failed to login:", err)
		c.Logout()
		return nil, fmt.Errorf("failed to login: %w", err)
	}

	log.Println("✅ IMAP connection successful")
	return c, nil
}
