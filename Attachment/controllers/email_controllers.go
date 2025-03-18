package controllers

import (
	"context"
	"email-client/config"
	"email-client/models"
	"email-client/services"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	OTPSubject     = "Your OTP Code"
	SessionUserKey = "user" // Using consistently across controllers
)

var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
var otpStore = sync.Map{}

// IndexHandler serves the homepage
func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{"title": "Vault"})
}

// AboutHandler serves the about page
func AboutHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "about.html", gin.H{"title": "Vault"})
}

func DashboardHandler(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(SessionUserKey)

	if user == nil {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	log.Printf("Dashboard - Logged in User: %v", user)
	var senderName string

	// Pass logged-in email instead of FromName
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":    "Vault",
		"Email":    user.(string), // Directly pass the logged-in email
		"FromName": senderName,
	})
}

// GetRecipientsHandler fetches "To" emails filtered by logged-in user's email
func GetRecipientsHandler(c *gin.Context) {
	//log.Println("📩 GetRecipientsHandler triggered!")

	session := sessions.Default(c)
	userEmail := session.Get(SessionUserKey)

	if userEmail == nil {
		log.Println("❌ User not logged in")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not logged in"})
		return
	}

	log.Printf("✅ Fetching recipients for user: %s", userEmail)
	recipients, err := services.GetUniqueRecipients(userEmail.(string))
	if err != nil {
		log.Println("❌ Error fetching recipients:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch emails"}) // ✅ Show only this message
		return
	}

	//log.Println("📩 Recipients fetched successfully")
	c.JSON(http.StatusOK, recipients)
}

// LoginHandler handles login, OTP generation, and verification
func LoginHandler(c *gin.Context) {
	var data struct {
		Email        string
		ShowOTP      bool
		ErrorMessage string
	}

	if c.Request.Method == http.MethodPost {
		if err := c.Request.ParseForm(); err != nil {
			log.Printf("Error parsing form: %v", err)
			data.ErrorMessage = "Failed to process form data."
			c.HTML(http.StatusBadRequest, "login.html", data)
			return
		}

		action := c.PostForm("action")
		switch action {

		case "sendotp":
			email := c.PostForm("email")
			if email == "" || !emailRegex.MatchString(email) {
				data.ErrorMessage = "Invalid or empty email."
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			otpService := services.NewOTPService()
			otp := otpService.GenerateOTP()
			expiration := time.Now().Add(10 * time.Minute)

			otpStore.Store(email, struct {
				OTP        string
				Expiration time.Time
			}{otp, expiration})

			body := fmt.Sprintf("Your OTP is: %s", otp)
			err := services.SendEmail(OTPSubject, body, otp, email)
			if err != nil {
				data.ErrorMessage = fmt.Sprintf("Failed to send OTP: %v", err)
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			data.Email = email
			data.ShowOTP = true
			c.HTML(http.StatusOK, "login.html", data)

		case "verifyotp":
			email := c.PostForm("email")
			otp := c.PostForm("otp")

			value, ok := otpStore.Load(email)
			if !ok {
				data.ErrorMessage = "Invalid email or OTP session expired."
				data.Email = email
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			stored := value.(struct {
				OTP        string
				Expiration time.Time
			})

			if time.Now().After(stored.Expiration) {
				otpStore.Delete(email)
				data.ErrorMessage = "OTP has expired. Please request a new one."
				data.Email = email
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			if otp != stored.OTP {
				data.ErrorMessage = "Invalid OTP. Please try again."
				data.Email = email
				data.ShowOTP = true
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			otpStore.Delete(email)
			session := sessions.Default(c)
			session.Set(SessionUserKey, email)
			session.Options(sessions.Options{
				MaxAge:   3000, // 50 minutes
				HttpOnly: true, // Protect against XSS
				Secure:   false,
			})
			if err := session.Save(); err != nil {
				log.Println("Session Save Error:", err)
				data.ErrorMessage = "Failed to create session. Please try again."
				c.HTML(http.StatusOK, "login.html", data)
				return
			}
			log.Println("Session Set for:", email)
			c.Redirect(http.StatusSeeOther, "/dashboard")

		default:
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid action"})
		}
		return
	}

	c.HTML(http.StatusOK, "login.html", data)
}

// AppointmentListHandler serves the appointment list page
func AppointmentListHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "appointment_list.html", gin.H{"title": "Vault"})
}

func AttachmentHandler(c *gin.Context) {
	filename := c.Param("filename")
	cleanFilename := path.Clean(filename) // Prevent directory traversal
	filePath := filepath.Join("./attachments", cleanFilename)

	// Ensure file is within the expected directory
	absBase, _ := filepath.Abs("./attachments")
	absFile, _ := filepath.Abs(filePath)
	if len(absFile) < len(absBase) || absFile[:len(absBase)] != absBase {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Detect MIME type
	mimeType := mime.TypeByExtension(filepath.Ext(filename))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	log.Println("Serving file:", filePath, "with MIME type:", mimeType)

	// Set headers to force opening in a new tab
	c.Header("Content-Type", mimeType)
	c.Header("Content-Disposition", "inline")

	// Serve file
	c.File(filePath)
}

type EmailResponse struct {
	Email string `json:"email"`
}

// GetEmailIDs fetches email IDs filtered by logged-in user's email
func GetEmailIDs(c *gin.Context) {
	session := sessions.Default(c)
	userEmail := session.Get(SessionUserKey) // Get the logged-in user's email

	if userEmail == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not logged in"})
		return
	}

	loggedInEmail := userEmail.(string)
	log.Println("Fetching recipients for:", loggedInEmail) // Debugging log

	// Fetch unique "To" addresses from the emails sent by the logged-in user
	recipients, err := services.GetUniqueRecipients(loggedInEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Println("Fetched recipients:", recipients) // Debugging log
	c.JSON(http.StatusOK, recipients)
}

// EmailHandler handles email fetching and rendering
// EmailHandler processes email-related requests.
func EmailHandler(c *gin.Context) {
	log.Println("🚀 Entering EmailHandler function")

	// ✅ Get logged-in user from session
	session := sessions.Default(c)
	user := session.Get(SessionUserKey)

	if user == nil {
		log.Println("❌ No active session found, redirecting to login")
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	loggedInEmail, ok := user.(string)
	if !ok || loggedInEmail == "" {
		log.Println("❌ Invalid user session data, redirecting to login")
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	log.Printf("✅ Authenticated user: %s\n", loggedInEmail)

	// ✅ Fetch unique recipient email IDs
	recipientList, err := services.FetchEmailIDs(loggedInEmail)
	if err != nil {
		log.Printf("❌ Error fetching email IDs for %s: %v\n", loggedInEmail, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch email recipients"})
		return
	}

	// ✅ Get selected recipient from query parameter
	selectedRecipient := c.Query("to")

	// ✅ Handle AJAX request for fetching emails
	if c.Request.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		if selectedRecipient == "" {
			log.Println("⚠️ No recipient provided in AJAX request")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Recipient email is required"})
			return
		}

		log.Printf("📩 Fetching emails for recipient: %s\n", selectedRecipient)

		emailList, err := services.FetchEmails(selectedRecipient)
		if err != nil {
			log.Printf("❌ Error fetching emails for %s: %v\n", selectedRecipient, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch emails"})
			return
		}

		// ✅ Ensure `emailList` is never nil (returns an empty array if no emails exist)
		if emailList == nil {
			log.Println("⚠️ No emails found for recipient:", selectedRecipient)
			emailList = []models.Message{}
		}

		log.Printf("✅ %d emails fetched for %s\n", len(emailList), selectedRecipient)
		c.JSON(http.StatusOK, gin.H{"emails": emailList}) // ✅ Correct JSON format
		return
	}

	// ✅ Handle normal page rendering request
	log.Println("📤 Rendering document.html")

	c.HTML(http.StatusOK, "document.html", gin.H{
		"title":            "Vault",
		"Email":            loggedInEmail,
		"UniqueRecipients": recipientList,
		"Emails":           []models.Message{}, // ✅ Uses the correct struct from models

		"SelectedTo": selectedRecipient,
	})
}

// CheckEmailExistsHandler checks if the email pair exists in MongoDB
func CheckEmailExistsHandler(c *gin.Context) {
	toEmail := c.Query("to")     // PatientId in MongoDB
	fromEmail := c.Query("from") // DoctorId in MongoDB

	// log.Println("🔍 Received From (DoctorId):", fromEmail) // Debug log
	// log.Println("🔍 Received To (PatientId):", toEmail)    // Debug log

	// ✅ Get MongoDB collection for 'RecordAccessRights'
	emailCol := config.GetReportCollection()
	if emailCol == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ MongoDB not initialized"})
		return
	}

	// ✅ Use the correct field names: "DoctorId" and "PatientId"
	filter := bson.M{"DoctorId": fromEmail, "PatientId": toEmail}

	log.Println("🔍 MongoDB Query Filter:", filter) // Debug log

	// ✅ Check if the record exists
	count, err := emailCol.CountDocuments(context.Background(), filter)
	if err != nil {
		log.Println("❌ MongoDB Query Error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database query failed"})
		return
	}

	if count > 0 {
		log.Println("✅ Email exists in MongoDB")
		c.JSON(http.StatusOK, gin.H{"message": "✅ Email exists in database"})
	} else {
		log.Println("⚠️ Email not found in MongoDB")
		c.JSON(http.StatusOK, gin.H{"message": "⚠️ Email not found in database"})
	}
}

func LogoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	fmt.Println("Before logout:", session.Get("user"))

	session.Clear()
	session.Save()

	fmt.Println("After logout:", session.Get("user")) // Should print `nil`
	c.SetCookie("session_token", "", -1, "/", "", false, true)

	c.Redirect(http.StatusSeeOther, "/login")
}
