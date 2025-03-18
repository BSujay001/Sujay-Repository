package config

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ✅ Global MongoDB client
var mongoClient *mongo.Client

// ✅ Initialize MongoDB Connection
func InitMongoDB() {
	uri := "mongodb://localhost:27017" // Change if needed
	clientOptions := options.Client().ApplyURI(uri)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("❌ MongoDB Connection Error:", err)
	}

	// ✅ Check the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("❌ MongoDB Ping Failed:", err)
	}

	log.Println("✅ Connected to MongoDB successfully!")
	mongoClient = client
}

// ✅ Get MongoDB Database
func GetDatabase() *mongo.Database {
	if mongoClient == nil {
		log.Println("❌ MongoDB Client is not initialized")
		return nil
	}
	return mongoClient.Database("reportDB") // ✅ Correct database name
}

// ✅ Get the "RecordAccessRights" Collection
func GetReportCollection() *mongo.Collection {
	db := GetDatabase()
	if db == nil {
		return nil
	}
	return db.Collection("RecordAccessRights") // ✅ Correct collection name
}

// ✅ Close MongoDB Connection (Call this on server shutdown)
func CloseMongoDB() {
	if mongoClient != nil {
		err := mongoClient.Disconnect(context.Background())
		if err != nil {
			log.Println("❌ Error disconnecting MongoDB:", err)
		} else {
			log.Println("✅ MongoDB connection closed successfully")
		}
	}
}
