package controllers

import (
	"email-client/config"
	"email-client/models"
	"email-client/services"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func GeneratePDF(c *gin.Context) {
	var request struct {
		Mobile       string `json:"mobile"`
		DoctorName   string `json:"doctorName"`
		OpdNotes     string `json:"opdNotes"`
		Prescription string `json:"prescription"`
		FollowupDate string `json:"followupDate"`
		FollowupTime string `json:"followupTime"`
		CreatedOn    string `json:"createdOn"`
	}

	// ✅ Parse the incoming JSON body
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("❌ Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// ✅ Get the logged-in email from Gin context
	loggedInEmailValue, exists := c.Get("loggedInEmail")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: logged-in email not found"})
		return
	}
	loggedInEmail := loggedInEmailValue.(string)

	// ✅ Get "fromName" from context
	fromNameValue, exists := c.Get("fromName")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: fromName not found"})
		return
	}
	fromName := fromNameValue.(string)

	// ✅ Construct recipient email
	recipientEmail := fmt.Sprintf("%s@reportsofme.com", request.Mobile)

	// ✅ Construct OPD data model
	opdData := models.OpdModel{
		PatientName:  strings.TrimSpace(request.Mobile),
		DoctorName:   strings.TrimSpace(request.DoctorName),
		OPDNotes:     strings.TrimSpace(request.OpdNotes),
		Prescription: strings.TrimSpace(request.Prescription),
		FollowupDate: strings.TrimSpace(fmt.Sprintf("%s %s", request.FollowupDate, request.FollowupTime)),
		CreatedOn:    time.Now().Format("02 Jan 2006 03:04 PM"),
		GeneratedOn:  time.Now().Format("02 Jan 2006 03:04 PM"),
	}

	// ✅ Log email generation
	log.Printf("📧 Generating PDF and sending email from %s (name: %s) to %s", loggedInEmail, fromName, recipientEmail)

	// ✅ Pass "loggedInEmail" as the "From" email
	err := services.GeneratePDFAndSendEmail(opdData, recipientEmail, loggedInEmail, fromName)

	if err != nil {
		log.Println("❌ Error while generating PDF or sending email:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "✅ PDF generated and emailed successfully!"})
}

const (
	OTPSubject     = "Your OTP Code"
	SessionUserKey = "user" // Using consistently across controllers
)

var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
var otpStore = sync.Map{}

// IndexHandler serves the homepage
func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{})
}

// AboutHandler serves the about page
func AboutHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "about.html", gin.H{})
}

func DashboardHandler(c *gin.Context) {
	session := sessions.Default(c)

	// Get user email from session
	user := session.Get(SessionUserKey)
	// Get from_name (sender name) from session
	fromName := session.Get("from_name")

	// If no user is found in session, redirect to login
	if user == nil {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	// Log for debugging
	log.Printf("Dashboard - Logged in User: %v, FromName: %v", user, fromName)

	// Render dashboard with email and from_name
	c.HTML(http.StatusOK, "dashboard.html", gin.H{

		"Email":    user.(string),
		"FromName": fromName,
	})
}

// GetRecipientsHandler handles the request to fetch enriched recipients
func GetRecipientsHandler(c *gin.Context) {
	session := sessions.Default(c)
	userEmail := session.Get(SessionUserKey)

	if userEmail == nil {
		log.Println("❌ User not logged in")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not logged in"})
		return
	}

	log.Printf("✅ Fetching recipients for user: %s", userEmail)

	// Step 1: Get unique mobile@reportsofme.com list
	recipients, err := services.GetUniqueRecipients(userEmail.(string))
	if err != nil {
		log.Println("❌ Error fetching recipients:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch emails"})
		return
	}

	// Step 2: For each recipient, extract mobile and find name from MongoDB
	var enrichedList []map[string]string
	for _, email := range recipients {
		parts := strings.Split(email, "@")
		if len(parts) > 0 {
			mobile := parts[0] // Extract mobile number from email

			// Lookup name in MongoDB
			patient, err := services.GetPatientByMobile(mobile)
			displayName := mobile // Fallback to mobile if name is not found

			if err == nil && patient != nil && patient.PatientName != "" {
				displayName = patient.PatientName // Use patient's name if found
			}

			enrichedList = append(enrichedList, map[string]string{
				"mobile": mobile,
				"name":   displayName,
			})
		} else {
			log.Printf("❌ Invalid email format: %s", email)
		}
	}

	log.Printf("📋 Final recipient dropdown values: %+v", enrichedList)
	c.JSON(http.StatusOK, enrichedList)
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
			log.Printf("❌ Error parsing form: %v", err)
			data.ErrorMessage = "Failed to process form data."
			c.HTML(http.StatusBadRequest, "login.html", data)
			return
		}

		action := c.PostForm("action")
		switch action {
		case "sendotp":
			email := strings.TrimSpace(c.PostForm("email"))
			if email == "" || !emailRegex.MatchString(email) {
				data.ErrorMessage = "❌ Please enter a valid email address."
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			// 🔍 Check if email exists in FROM
			fromName, err := services.FetchFromNameByEmail(email)
			if err != nil || fromName == "" || fromName == email {
				data.ErrorMessage = fmt.Sprintf("⚠️ The email '%s' is not registered. Please try again with a registered one.", email)
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			// 🔑 Generate & store OTP with expiration
			otpService := services.NewOTPService()
			otp := otpService.GenerateOTP()
			otpStore.Store(email, struct {
				OTP        string
				Expiration time.Time
			}{
				OTP:        otp,
				Expiration: time.Now().Add(10 * time.Minute),
			})

			// 📤 Send OTP
			if err := services.SendEmail(otp, email, fromName); err != nil {
				log.Printf("❌ Failed to send OTP to %s: %v", email, err)
				data.ErrorMessage = "Failed to send OTP. Please try again."
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			// ✅ Show OTP field
			data.Email = email
			data.ShowOTP = true
			c.HTML(http.StatusOK, "login.html", data)

		case "verifyotp":
			email := strings.TrimSpace(c.PostForm("email"))
			otp := strings.TrimSpace(c.PostForm("otp"))

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

			// 🎉 OTP verified — create session
			fromName, err := services.FetchFromNameByEmail(email)
			if err != nil || fromName == "" {
				fromName = email
			}

			session := sessions.Default(c)
			session.Set(SessionUserKey, email)
			session.Set("from_name", fromName)
			session.Options(sessions.Options{
				MaxAge:   3000, // 50 min
				HttpOnly: true,
				Secure:   false,
			})
			if err := session.Save(); err != nil {
				log.Printf("❌ Session Save Error for %s: %v", email, err)
				data.ErrorMessage = "Failed to create session. Please try again."
				c.HTML(http.StatusOK, "login.html", data)
				return
			}

			// ✅ Clean up and redirect
			otpStore.Delete(email)
			log.Printf("✅ Session set for %s (FromName: %s)", email, fromName)
			c.Redirect(http.StatusSeeOther, "/dashboard")

		default:
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid action"})
		}
		return
	}

	// GET handler
	c.HTML(http.StatusOK, "login.html", data)
}

var cardOTPStore sync.Map // Put this at the top of the file

func GenerateOtpForAccess(c *gin.Context) {
	mobile := c.PostForm("mobile")

	if len(mobile) != 10 || !regexp.MustCompile(`^\d{10}$`).MatchString(mobile) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid mobile number"})
		return
	}

	otpService := services.NewOTPService()
	otp := otpService.GenerateOTP()
	expiration := time.Now().Add(10 * time.Minute)

	cardOTPStore.Store(mobile, struct {
		OTP        string
		Expiration time.Time
	}{
		OTP:        otp,
		Expiration: expiration,
	})

	fmt.Printf("🔐 OTP for %s is: %s\n", mobile, otp)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func VerifyOtpForAccess(c *gin.Context) {
	mobile := c.PostForm("mobile")
	otp := c.PostForm("otp")

	if mobile == "" || otp == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Mobile and OTP are required"})
		return
	}

	value, ok := cardOTPStore.Load(mobile)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Session expired or OTP not found"})
		return
	}

	stored := value.(struct {
		OTP        string
		Expiration time.Time
	})

	if time.Now().After(stored.Expiration) {
		cardOTPStore.Delete(mobile)
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "OTP has expired"})
		return
	}

	if otp != stored.OTP {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Incorrect OTP"})
		return
	}

	cardOTPStore.Delete(mobile)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "OTP verified successfully"})
}

func CheckSession(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get(SessionUserKey)

	if user == nil || user == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.Status(http.StatusOK)
}

// AppointmentListHandler serves the appointment list page
func AppointmentListHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "appointment_list.html", gin.H{})
}

func AttachmentHandler(c *gin.Context) {
	filename := c.Param("filename")
	filePath := fmt.Sprintf("./attachments/%s", filename)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Detect MIME type automatically
	mimeType := mime.TypeByExtension(filepath.Ext(filename))
	if mimeType == "" {
		mimeType = "application/octet-stream" // Default fallback
	}

	log.Println("Serving file:", filePath, "with MIME type:", mimeType)

	// Set headers to force opening in a new tab (not downloading)
	c.Header("Content-Type", mimeType)
	c.Header("Content-Disposition", "inline") // Forces browser to display file

	// Serve file
	c.File(filePath)
}

// GetEmailIDs fetches unique recipient email IDs filtered by the logged-in user's email
func GetEmailIDs(c *gin.Context) {
	session := sessions.Default(c)
	userEmail := session.Get(SessionUserKey) // Get the logged-in user's email from session

	if userEmail == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not logged in"})
		return
	}

	loggedInEmail := userEmail.(string)
	log.Printf("✅ Fetching recipients for logged-in email: %s", loggedInEmail)

	// Fetch unique recipients
	recipients, err := services.GetUniqueRecipients(loggedInEmail)
	if err != nil {
		log.Printf("❌ Failed to fetch recipients: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Handle empty results gracefully
	if len(recipients) == 0 {
		log.Println("⚠ No recipients found for this user.")
		c.JSON(http.StatusOK, gin.H{
			"message":    "No recipients found.",
			"recipients": []string{},
		})
		return
	}

	log.Printf("✅ Successfully fetched %d recipients: %v", len(recipients), recipients)

	// Return recipients in JSON
	c.JSON(http.StatusOK, gin.H{
		"recipients": recipients,
	})
}

// EmailHandler handles email fetching and rendering
// EmailHandler processes email-related requests.
func EmailHandler(c *gin.Context) {
	startTime := time.Now()
	log.Println("🚀 Entering EmailHandler")

	session := sessions.Default(c)
	loggedInEmail, ok := session.Get(SessionUserKey).(string)
	fromName := session.Get("from_name")

	if !ok || loggedInEmail == "" {
		log.Println("❌ No active session found, redirecting to login")
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	selectedRecipient := c.Query("to")

	// ✅ AJAX Request: JSON return
	if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
		if selectedRecipient == "" {
			log.Println("⚠️ No recipient provided in AJAX request")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Recipient email is required"})
			return
		}

		// 🔄 Check access using updated method
		access, err := services.CheckAccessValue(loggedInEmail, selectedRecipient)
		if err != nil {
			log.Printf("❌ Access check error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check access"})
			return
		}

		var emailList []models.Message

		if access == "Y" {
			log.Println("🔓 Access = Y: Fetching full doctor view")
			emailList, err = services.FetchAllDoctorsOfPatient(selectedRecipient)
		} else {
			log.Printf("🔒 Access not granted or not found (access=%s): Fetching limited view", access)
			emailList, err = services.FetchEmails(loggedInEmail, selectedRecipient)
		}

		if err != nil {
			log.Printf("❌ Error fetching emails: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch emails"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"emails": emailList})
		log.Printf("✅ AJAX EmailHandler completed in %v ms", time.Since(startTime).Milliseconds())
		return
	}

	// 🌐 Full page render
	recipientList, err := services.FetchEmailIDs(loggedInEmail)
	if err != nil {
		log.Printf("❌ Error fetching recipient list: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch recipients"})
		return
	}

	var emailList []models.Message
	if selectedRecipient != "" {
		access, err := services.CheckAccessValue(loggedInEmail, selectedRecipient)
		if err != nil {
			log.Printf("⚠️ Access check failed: %v", err)
			emailList = []models.Message{}
		} else if access == "Y" {
			log.Println("🔓 Full page access = Y")
			emailList, err = services.FetchAllDoctorsOfPatient(selectedRecipient)
		} else {
			log.Println("🔒 Full page access != Y")
			emailList, err = services.FetchEmails(loggedInEmail, selectedRecipient)
		}

		if err != nil {
			log.Printf("❌ Email fetch error: %v", err)
			emailList = []models.Message{}
		}
	}

	c.HTML(http.StatusOK, "document.html", gin.H{
		"Email":            loggedInEmail,
		"FromName":         fromName,
		"UniqueRecipients": recipientList,
		"Emails":           emailList,
		"SelectedTo":       selectedRecipient,
	})

	log.Printf("✅ Full Page EmailHandler completed in %v ms", time.Since(startTime).Milliseconds())
}

type EmailResponse struct {
	PlainTextBody string              `json:"plainTextBody"`
	Attachments   []map[string]string `json:"attachments"`
}

func GetPlainTextEmailBody(c *gin.Context) {
	startTime := time.Now()

	uid := c.Query("uid")
	if uid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UID is required"})
		return
	}

	uidInt, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid UID format: %v", err)})
		return
	}

	// ✅ Start IMAP connection and fetch email in one go
	log.Println("⏳ Connecting to IMAP server...")
	imapStart := time.Now()
	imapClient, err := config.ConnectIMAP()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to IMAP server"})
		return
	}
	defer imapClient.Logout()
	log.Printf("✅ IMAP connected in %v ms", time.Since(imapStart).Milliseconds())

	// ✅ Fetch email content (this depends on active IMAP connection)
	log.Println("📩 Fetching email content...")
	fetchStart := time.Now()
	plainTextBody, attachments, fetchErr := services.FetchPlainTextEmailBody(imapClient, uint32(uidInt))
	if fetchErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to fetch email content: %v", fetchErr)})
		return
	}
	log.Printf("✅ Email fetched in %v ms", time.Since(fetchStart).Milliseconds())

	// ✅ Send response
	c.JSON(http.StatusOK, EmailResponse{
		PlainTextBody: plainTextBody,
		Attachments:   attachments,
	})

	log.Printf("✅ GetPlainTextEmailBody executed in %v ms", time.Since(startTime).Milliseconds())
}

// GetAttachment handles attachment retrieval via API
func GetAttachment(c *gin.Context) {
	// ✅ Read query parameters
	emailIDStr := c.Query("email_id")
	attachmentName := c.Query("attachment_name")

	if emailIDStr == "" || attachmentName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
		return
	}

	// ✅ Convert email ID to uint32
	emailID, err := strconv.ParseUint(emailIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email ID format"})
		return
	}

	// ✅ Fetch the attachment
	attachmentData, filename, err := services.FetchAttachment(uint32(emailID), attachmentName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch attachment: " + err.Error()})
		return
	}

	// ✅ Return the file as a downloadable response
	c.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.Header("Content-Type", "application/octet-stream")
	c.Data(http.StatusOK, "application/octet-stream", attachmentData)
}

// DownloadAttachmentHandler serves attachments for viewing/downloading
func DownloadAttachmentHandler(c *gin.Context) {
	// ✅ Read query parameters
	emailIDStr := c.Query("uid")
	attachmentName := c.Query("attachmentName")

	if emailIDStr == "" || attachmentName == "" {
		c.Data(http.StatusBadRequest, "text/html", []byte("<h3>Missing required parameters: uid and attachmentName.</h3>"))
		return
	}

	// ✅ Convert email ID to uint32
	emailID, err := strconv.ParseUint(emailIDStr, 10, 32)
	if err != nil {
		c.Data(http.StatusBadRequest, "text/html", []byte("<h3>Invalid Email ID format.</h3>"))
		return
	}

	// ✅ Fetch the attachment
	attachmentData, filename, err := services.FetchAttachment(uint32(emailID), attachmentName)
	if err != nil {
		c.Data(http.StatusInternalServerError, "text/html", []byte(fmt.Sprintf(
			"<h3>Attachment not found or failed to load.</h3><p>Error: %v</p>", err)))
		return
	}

	// ✅ Determine MIME type
	ext := filepath.Ext(filename)
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		mimeType = http.DetectContentType(attachmentData)
	}

	// ✅ Set headers for inline display (view in browser)
	c.Header("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, filename))
	c.Data(http.StatusOK, mimeType, attachmentData)
}

// CheckEmailExistsHandler checks if the email pair exists in MongoDB
// func CheckEmailExistsHandler(c *gin.Context) {
// 	toEmail := c.Query("to")     // PatientId in MongoDB
// 	fromEmail := c.Query("from") // DoctorId in MongoDB

// 	// log.Println("🔍 Received From (DoctorId):", fromEmail) // Debug log
// 	// log.Println("🔍 Received To (PatientId):", toEmail)    // Debug log

// 	// ✅ Get MongoDB collection for 'RecordAccessRights'
// 	emailCol := config.GetReportCollection()
// 	if emailCol == nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ MongoDB not initialized"})
// 		return
// 	}

// 	// ✅ Use the correct field names: "DoctorId" and "PatientId"
// 	filter := bson.M{"DoctorId": fromEmail, "PatientId": toEmail}

// 	log.Println("🔍 MongoDB Query Filter:", filter) // Debug log

// 	// ✅ Check if the record exists
// 	count, err := emailCol.CountDocuments(context.Background(), filter)
// 	if err != nil {
// 		log.Println("❌ MongoDB Query Error:", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database query failed"})
// 		return
// 	}

// 	if count > 0 {
// 		log.Println("✅ Email exists in MongoDB")
// 		c.JSON(http.StatusOK, gin.H{"message": "✅ Email exists in database"})
// 	} else {
// 		log.Println("⚠️ Email not found in MongoDB")
// 		c.JSON(http.StatusOK, gin.H{"message": "⚠️ Email not found in database"})
// 	}
// }

func LogoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	fmt.Println("Before logout:", session.Get("user"))

	session.Clear()
	session.Save()

	fmt.Println("After logout:", session.Get("user")) // Should print `nil`
	c.SetCookie("session_token", "", -1, "/", "", false, true)

	c.Redirect(http.StatusSeeOther, "/login")
}
