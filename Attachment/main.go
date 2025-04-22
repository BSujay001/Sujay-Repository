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
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ Warning: Could not load .env file")
	}
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	fmt.Println("📦 Starting Email Client Service...")

	// ✅ Create attachments directory if not exists
	if err := os.MkdirAll("./attachments", os.ModePerm); err != nil {
		log.Fatalf("❌ Failed to create attachments directory: %v", err)
	}

	// ✅ Initialize MongoDB connection
	config.InitMongoClient()
	defer config.CloseMongoClient()

	// ✅ Setup Gin router
	router := routes.InitializeRoutes()

	// ✅ Configure HTTP server
	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// 📢 Listen for termination signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Println("🚀 Server is running at http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server failed: %v", err)
		}
	}()

	<-quit
	log.Println("🛑 Shutting down server...")

	if err := server.Close(); err != nil {
		log.Fatalf("❌ Server shutdown error: %v", err)
	}

	log.Println("✅ Server stopped gracefully.")
}
