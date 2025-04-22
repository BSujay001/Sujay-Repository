package routes

import (
	"email-client/controllers"
	"email-client/middleware"
	"html/template"
	"log"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

// InitializeRoutes sets up all routes and middleware
func InitializeRoutes() *gin.Engine {
	router := gin.Default()

	// ✅ Setup secure cookie-based session store
	store := cookie.NewStore([]byte("secret-key"))
	store.Options(sessions.Options{
		MaxAge:   3600,  // 1 hour
		HttpOnly: true,  // JS can't access
		Secure:   false, // set true in prod with HTTPS
	})
	router.Use(sessions.Sessions("email-session", store))

	// ✅ Load HTML templates

	// tmpl, err := template.ParseGlob("templates/*.html")
	// if err != nil {
	// 	log.Fatalf("❌ Error parsing templates: %v", err)
	// }
	// router.SetHTMLTemplate(template.Must(tmpl))
	router.SetHTMLTemplate(template.Must(template.ParseGlob("templates/*.html")))

	// ✅ Serve static files
	router.Static("/static", "./static")

	// ---------- Public Routes ----------
	router.GET("/", controllers.IndexHandler)
	router.GET("/about", controllers.AboutHandler)
	router.GET("/login", controllers.LoginHandler)
	router.POST("/login", controllers.LoginHandler)
	router.GET("/logout", controllers.LogoutHandler)
	router.GET("/check-session", controllers.CheckSession)

	// ---------- Protected Routes ----------
	authRoutes := router.Group("/")
	authRoutes.Use(authMiddleware())

	log.Println("✅ Registered protected routes: /dashboard, /emails, /document, /recipients, etc.")
	authRoutes.GET("/dashboard", controllers.DashboardHandler)
	authRoutes.GET("/appointment_list", controllers.AppointmentListHandler)
	authRoutes.GET("/document", controllers.EmailHandler)
	authRoutes.GET("/emails", controllers.EmailHandler)
	authRoutes.GET("/get-recipients", controllers.GetRecipientsHandler)

	authRoutes.GET("/get-email-body", controllers.GetPlainTextEmailBody)
	authRoutes.GET("/attachment", controllers.GetAttachment)
	authRoutes.GET("/get-attachment", controllers.DownloadAttachmentHandler)
	authRoutes.GET("/attachments/:filename", controllers.AttachmentHandler)

	// 🔐 PDF generation route with middleware
	router.POST("/generate-pdf", middleware.AuthMiddleware(), controllers.GeneratePDF)

	// 🔐 OTP & Access Management

	router.GET("/check-patient", controllers.CheckPatientHandler)
	router.GET("/check-access", controllers.CheckDoctorAccess)
	router.POST("/generate-otp-card", controllers.GenerateOtpForAccess)
	router.POST("/verify-otp-card", controllers.VerifyOtpForAccess)
	router.POST("/save-patient", middleware.AuthMiddleware(), controllers.SavePatientHandler)
	router.POST("/update-access", controllers.UpdateAccess)

	return router
}

// Middleware to enforce authentication
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")

		if user == nil {
			log.Println("⚠️ Unauthorized access attempt. Redirecting to login.")
			c.Redirect(302, "/login")
			c.Abort()
			return
		}

		log.Println("✅ Authenticated user:", user)
		c.Next()
	}
}
