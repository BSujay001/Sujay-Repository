package main

import (
	"email-client/config"
	"email-client/routes"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
)

func init() {
	// Load .env at the start of the application
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Could not load .env file")
	}
	log.SetOutput(os.Stdout)                     // Ensures logs go to console
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Adds timestamp & file:line info
}

func main() {
	// ✅ Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ Warning: Could not load .env file, using system environment variables")
	}

	fmt.Println("Connected to IMAP server successfully (SSL verification disabled)")
	fmt.Println("Starting email service...")

	// Create the attachments directory if it doesn't exist
	if err := os.MkdirAll("./attachments", os.ModePerm); err != nil {
		log.Fatalf("Error creating attachments directory: %v", err)
	}
	// Initialize MongoDB
	config.InitMongoDB()
	defer config.CloseMongoDB() // Ensure it closes when the app exits

	// Initialize router
	router := routes.InitializeRoutes()

	//r := gin.Default()
	//r.GET("/attachments/:filename", AttachmentHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// Channel to listen for interrupt or terminate signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		fmt.Println("Server is running at http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start email service: %v", err)
		}
	}()

	//defer c.Logout()
	// Wait for interrupt signal
	<-quit
	fmt.Println("\nShutting down email service gracefully...")

	// Graceful shutdown
	if err := server.Close(); err != nil {
		log.Fatalf("Could not gracefully shut down the server: %v", err)
	}

	fmt.Println("Email service stopped.")
}
