package config

import (
	"context"
	"log"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoClient *mongo.Client
	dbName      = "reportDB"
	mongoOnce   sync.Once
)

// ✅ Call this in main.go
func InitMongoClient() {
	mongoOnce.Do(func() {
		uri := "mongodb://localhost:27017"
		clientOptions := options.Client().ApplyURI(uri)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := mongo.Connect(ctx, clientOptions)
		if err != nil {
			log.Fatalf("❌ MongoDB connection error: %v", err)
		}

		if err := client.Ping(ctx, nil); err != nil {
			log.Fatalf("❌ MongoDB ping error: %v", err)
		}

		log.Println("✅ Connected to MongoDB")
		mongoClient = client
	})
}

// Utility functions
func GetDatabase() *mongo.Database {
	if mongoClient == nil {
		InitMongoClient()
	}
	return mongoClient.Database(dbName)
}

func GetPatientCollection() *mongo.Collection {
	return GetDatabase().Collection("PatientData")
}

func GetDoctorPatientAccessCollection() *mongo.Collection {
	return GetDatabase().Collection("RecordAccessRights")
}

func CloseMongoClient() {
	if mongoClient != nil {
		if err := mongoClient.Disconnect(context.Background()); err != nil {
			log.Printf("❌ Error disconnecting MongoDB: %v", err)
		} else {
			log.Println("✅ MongoDB connection closed")
		}
	}
}
