package routes

import (
	"email-client/controllers"
	"html/template"
	"log"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

// InitializeRoutes sets up all routes and middleware
func InitializeRoutes() *gin.Engine {
	router := gin.Default()

	// Secure session store
	store := cookie.NewStore([]byte("secret-key"))
	store.Options(sessions.Options{
		MaxAge:   3600, // 1-hour session expiry
		HttpOnly: true, // Prevent JS access
		Secure:   true, // Only allow HTTPS (set false for dev mode)
	})

	router.Use(sessions.Sessions("email-session", store))

	// Load HTML templates
	// router.SetHTMLTemplate(template.Must(template.ParseGlob("templates/*.html")))
	t, err := template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Error parsing templates: %v", err)
	}

	router.SetHTMLTemplate(template.Must(t, err))
	// Serve static assets
	router.Static("/static", "./static")

	// --------- Public Routes ---------
	router.GET("/", controllers.IndexHandler)
	router.GET("/about", controllers.AboutHandler)
	router.GET("/login", controllers.LoginHandler)
	router.POST("/login", controllers.LoginHandler)
	router.GET("/logout", controllers.LogoutHandler)

	// --------- Authenticated Routes ---------
	authRoutes := router.Group("/")
	authRoutes.Use(authMiddleware()) // Apply middleware to all routes inside this group

	log.Println("✅ Routes registered: /dashboard, /appointment_list, /document, /recipients")
	authRoutes.GET("/dashboard", controllers.DashboardHandler)
	authRoutes.GET("/appointment_list", controllers.AppointmentListHandler)
	authRoutes.GET("/document", controllers.EmailHandler)
	authRoutes.GET("/emails", controllers.EmailHandler)
	authRoutes.GET("/recipients", controllers.GetRecipientsHandler)

	// Email & Attachments
	authRoutes.GET("/attachments/:filename", controllers.AttachmentHandler)
	authRoutes.GET("/api/check-email", controllers.CheckEmailExistsHandler)

	return router
}

///////////////////////
// AUTH MIDDLEWARE  //
///////////////////////

// authMiddleware restricts access to authenticated users only
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
