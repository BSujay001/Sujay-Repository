package services

// import (
// 	"crypto/tls"
// 	"log"

// 	"gopkg.in/gomail.v2"
// )

// func smtp() {
// 	emailID := "your-email@example.com"
// 	emailPass := "your-password"
// 	smtpHost := "smtp.xvz.com"
// 	smtpPort := 587

// 	message := gomail.NewMessage()
// 	message.SetHeader("From", emailID)
// 	message.SetHeader("To", "recipient@example.com")
// 	message.SetHeader("Subject", "Test Email")
// 	message.SetBody("text/plain", "This is a test email from Golang.")

// 	dialer := gomail.NewDialer(smtpHost, smtpPort, emailID, emailPass)
// 	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true} // Ignore certificate validation

// 	if err := dialer.DialAndSend(message); err != nil {
// 		log.Fatal("Failed to send email:", err)
// 	}

// 	log.Println("Email sent successfully")
// }
