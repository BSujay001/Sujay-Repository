package timeConfig

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap/client"
)

var imapClient *client.Client // Global IMAP client (optional)

// ConnectIMAP establishes an IMAP connection efficiently with a timeout.
func ConnectIMAP() (*client.Client, error) {
	startTime := time.Now() // Start tracking total time

	// ✅ Load IMAP configuration from environment variables
	imapServer := os.Getenv("IMAP_SERVER")
	username := os.Getenv("EMAIL_USERNAME")
	password := os.Getenv("EMAIL_PASSWORD")

	if imapServer == "" || username == "" || password == "" {
		log.Println("❌ Missing IMAP configuration. Check environment variables.")
		return nil, fmt.Errorf("IMAP_SERVER, EMAIL_USERNAME, or EMAIL_PASSWORD is not set")
	}

	parts := strings.Split(imapServer, ":")
	if len(parts) != 2 {
		log.Println("❌ Invalid IMAP_SERVER format. Expected format: hostname:port")
		return nil, fmt.Errorf("invalid IMAP_SERVER format: %s", imapServer)
	}

	host := parts[0]
	port := parts[1]

	// Check if an existing connection can be reused (optional)
	if imapClient != nil {
		log.Println("♻️ Reusing existing IMAP connection")
		return imapClient, nil
	}

	var c *client.Client
	var err error

	connectStart := time.Now() // Track connection start time
	timeout := 10 * time.Second

	// Dial with timeout
	dialer := &net.Dialer{Timeout: timeout}

	if port == "993" {
		// Secure TLS connection
		c, err = client.DialWithDialerTLS(dialer, imapServer, &tls.Config{ServerName: host})
	} else if port == "143" {
		// Plain IMAP with STARTTLS
		c, err = client.DialWithDialer(dialer, imapServer)
		if err == nil {
			if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
				log.Println("❌ Failed to start TLS:", err)
				c.Logout()
				return nil, fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	} else {
		log.Println("❌ Unsupported IMAP port:", port)
		return nil, fmt.Errorf("unsupported IMAP port: %s", port)
	}

	if err != nil {
		log.Println("❌ IMAP connection failed:", err)
		return nil, fmt.Errorf("failed to connect to IMAP server: %w", err)
	}

	log.Printf("✅ IMAP server connected in %v ms", time.Since(connectStart).Milliseconds())

	// Login
	loginStart := time.Now()
	if err := c.Login(username, password); err != nil {
		log.Println("❌ IMAP login failed:", err)
		c.Logout()
		return nil, fmt.Errorf("failed to login: %w", err)
	}

	log.Printf("✅ IMAP login successful in %v ms", time.Since(loginStart).Milliseconds())

	// Store client for reuse (optional)
	imapClient = c

	log.Printf("✅ Total IMAP setup time: %v ms", time.Since(startTime).Milliseconds())

	return c, nil
}
